#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <switch.h>

#include "swg/app_session.h"
#include "swg/compat_bridge.h"
#include "swg/client.h"
#include "swg/ipc_protocol.h"
#include "swg/moonlight.h"
#include "swg/session_socket.h"
#include "swg/wg_profile.h"

namespace {

constexpr int kAutoRefreshFrames = 30;
constexpr std::size_t kMaxPreviewBytes = 8;
constexpr std::uint64_t kReceivePollIntervalNs = 100 * 1000 * 1000ULL;
constexpr int kReceivePollAttempts = 20;

constexpr char kHarnessHttpSignature[] = "service=swg-integration-server";

struct ScreenModel {
  swg::Result<swg::VersionInfo> version;
  swg::Result<swg::ServiceStatus> status;
  swg::Result<swg::TunnelStats> stats;
  swg::Result<std::vector<swg::ProfileSummary>> profiles;
  swg::Result<swg::Config> config;
  swg::Result<swg::CompatibilityInfo> compatibility;
};

struct DiagnosticTarget {
  std::string host;
  bool is_hostname = false;
  bool is_numeric_ipv4 = false;
  bool is_numeric_ipv6 = false;
};

struct IntegrationServerTarget {
  DiagnosticTarget endpoint;
  std::string dns_hostname;
  std::uint16_t tcp_echo_port = 0;
  std::uint16_t http_port = 0;
  std::uint16_t udp_echo_port = 0;
  std::string http_path;
  bool uses_profile_endpoint = false;
};

struct IntegrationState {
  explicit IntegrationState(swg::Client client) : session(std::move(client)) {}

  swg::AppSession session;
  swg::AppTunnelRequest session_request{};
  std::optional<swg::SessionSocket> sample_socket;
  std::string last_action = "waiting for swg:ctl";
  std::string last_dns_result = "not run";
  std::vector<std::string> dns_lines;
  std::string last_socket_result = "not run";
  std::vector<std::string> socket_lines;
  std::string last_compat_result = "not run";
  std::vector<std::string> compat_lines;
  std::string last_send_result = "not run";
  std::string last_receive_result = "not run";
  std::string last_smoke_summary = "not run";
  std::vector<std::string> smoke_lines;
  std::string last_run_all_summary = "not run";
  std::vector<std::string> run_all_lines;
  std::uint8_t payload_nonce = 1;
  std::uint32_t run_all_nonce = 1;
};

bool IsSessionTunnelReady(const ScreenModel& model, const IntegrationState& state);

const char* BoolLabel(bool value) {
  return value ? "yes" : "no";
}

swg::RuntimeFlags ToggleFlag(swg::RuntimeFlags flags, swg::RuntimeFlag flag) {
  if (swg::HasFlag(flags, flag)) {
    return flags & ~swg::ToFlags(flag);
  }

  return flags | swg::ToFlags(flag);
}

void RefreshModel(const swg::Client& client, ScreenModel* model) {
  model->version = client.GetVersion();
  model->status = client.GetStatus();
  model->stats = client.GetStats();
  model->profiles = client.ListProfiles();
  model->config = client.GetConfig();
  model->compatibility = client.GetCompatibilityInfo();
}

int FindActiveProfileIndex(const ScreenModel& model) {
  if (!model.status.ok() || !model.profiles.ok()) {
    return -1;
  }

  for (std::size_t index = 0; index < model.profiles.value.size(); ++index) {
    if (model.profiles.value[index].name == model.status.value.active_profile) {
      return static_cast<int>(index);
    }
  }

  return model.profiles.value.empty() ? -1 : 0;
}

std::string CurrentProfileName(const ScreenModel& model) {
  if (model.status.ok() && !model.status.value.active_profile.empty()) {
    return model.status.value.active_profile;
  }

  if (model.profiles.ok() && !model.profiles.value.empty()) {
    return model.profiles.value.front().name;
  }

  return {};
}

swg::AppTunnelRequest MakeIntegrationSessionRequest(std::string desired_profile) {
  swg::AppTunnelRequest request{};
  request.app.client_name = "SWG Integration";
  request.app.integration_tag = "switch-integration";
  request.desired_profile = std::move(desired_profile);
  return request;
}

const char* CompatRouteLabel(swg::CompatSocketRoute route) {
  switch (route) {
    case swg::CompatSocketRoute::Direct:
      return "direct";
    case swg::CompatSocketRoute::Tunnel:
      return "tunnel";
    case swg::CompatSocketRoute::Failed:
    default:
      return "failed";
  }
}

std::string FormatResolvedCompatAddress(const sockaddr_storage& addr) {
  char buffer[64] = {};
  if (addr.ss_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&addr);
    if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer, sizeof(buffer)) != nullptr) {
      return std::string(buffer) + ":" + std::to_string(ntohs(ipv4->sin_port));
    }
  }

  return "<unprintable>";
}

swg::Result<DiagnosticTarget> GetDiagnosticTarget(const ScreenModel& model) {
  if (!model.config.ok()) {
    return swg::MakeFailure<DiagnosticTarget>(model.config.error.code,
                                              "config unavailable: " + model.config.error.message);
  }

  const std::string profile_name = CurrentProfileName(model);
  if (profile_name.empty()) {
    return swg::MakeFailure<DiagnosticTarget>(swg::ErrorCode::NotFound, "no active profile available");
  }

  const auto profile = model.config.value.profiles.find(profile_name);
  if (profile == model.config.value.profiles.end()) {
    return swg::MakeFailure<DiagnosticTarget>(swg::ErrorCode::NotFound,
                                              "active profile config unavailable: " + profile_name);
  }

  if (profile->second.endpoint_host.empty()) {
    return swg::MakeFailure<DiagnosticTarget>(swg::ErrorCode::ParseError,
                                              "active profile endpoint_host is empty");
  }

  DiagnosticTarget target{};
  target.host = profile->second.endpoint_host;

  const swg::Result<swg::ParsedIpAddress> parsed = swg::ParseIpAddress(target.host, "endpoint_host");
  if (!parsed.ok()) {
    target.is_hostname = true;
  } else if (parsed.value.family == swg::ParsedIpFamily::IPv4) {
    target.is_numeric_ipv4 = true;
  } else {
    target.is_numeric_ipv6 = true;
  }

  return swg::MakeSuccess(std::move(target));
}

swg::Result<DiagnosticTarget> ClassifyDiagnosticTarget(std::string host, std::string_view field_name) {
  if (host.empty()) {
    return swg::MakeFailure<DiagnosticTarget>(swg::ErrorCode::ParseError,
                                              std::string(field_name) + " must not be empty");
  }

  DiagnosticTarget target{};
  target.host = std::move(host);

  const swg::Result<swg::ParsedIpAddress> parsed = swg::ParseIpAddress(target.host, std::string(field_name));
  if (!parsed.ok()) {
    target.is_hostname = true;
  } else if (parsed.value.family == swg::ParsedIpFamily::IPv4) {
    target.is_numeric_ipv4 = true;
  } else {
    target.is_numeric_ipv6 = true;
  }

  return swg::MakeSuccess(std::move(target));
}

std::string DescribeDiagnosticTarget(const DiagnosticTarget& target) {
  if (target.is_hostname) {
    return target.host + " (hostname)";
  }

  if (target.is_numeric_ipv4) {
    return target.host + " (numeric IPv4)";
  }

  return target.host + " (numeric IPv6)";
}

swg::Result<IntegrationServerTarget> GetIntegrationServerTarget(const ScreenModel& model) {
  if (!model.config.ok()) {
    return swg::MakeFailure<IntegrationServerTarget>(model.config.error.code,
                                                     "config unavailable: " + model.config.error.message);
  }

  IntegrationServerTarget target{};
  target.tcp_echo_port = model.config.value.integration_test.tcp_echo_port;
  target.http_port = model.config.value.integration_test.http_port;
  target.udp_echo_port = model.config.value.integration_test.udp_echo_port;
  target.http_path = model.config.value.integration_test.http_path;

  if (!model.config.value.integration_test.target_host.empty()) {
    const swg::Result<DiagnosticTarget> classified =
        ClassifyDiagnosticTarget(model.config.value.integration_test.target_host, "integration_test.target_host");
    if (!classified.ok()) {
      return swg::MakeFailure<IntegrationServerTarget>(classified.error.code, classified.error.message);
    }
    target.endpoint = classified.value;
  } else {
    const swg::Result<DiagnosticTarget> fallback = GetDiagnosticTarget(model);
    if (!fallback.ok()) {
      return swg::MakeFailure<IntegrationServerTarget>(fallback.error.code, fallback.error.message);
    }
    target.endpoint = fallback.value;
    target.uses_profile_endpoint = true;
  }

  if (!model.config.value.integration_test.dns_hostname.empty()) {
    target.dns_hostname = model.config.value.integration_test.dns_hostname;
  } else if (target.endpoint.is_hostname) {
    target.dns_hostname = target.endpoint.host;
  }

  return swg::MakeSuccess(std::move(target));
}

std::string DescribeIntegrationServerTarget(const IntegrationServerTarget& target) {
  std::string description = DescribeDiagnosticTarget(target.endpoint);
  description += " tcp=" + std::to_string(target.tcp_echo_port);
  description += " http=" + std::to_string(target.http_port);
  description += " udp=" + std::to_string(target.udp_echo_port);
  if (target.uses_profile_endpoint) {
    description += " source=profile.endpoint_host";
  } else {
    description += " source=integration_test.target_host";
  }
  if (!target.dns_hostname.empty()) {
    description += " dns=" + target.dns_hostname;
  }
  return description;
}

void ClearSessionDiagnostics(IntegrationState* state) {
  state->sample_socket.reset();
  state->last_dns_result = "not run";
  state->dns_lines.clear();
  state->last_socket_result = "not run";
  state->socket_lines.clear();
  state->last_compat_result = "not run";
  state->compat_lines.clear();
  state->last_send_result = "not run";
  state->last_receive_result = "not run";
  state->last_smoke_summary = "not run";
  state->smoke_lines.clear();
  state->last_run_all_summary = "not run";
  state->run_all_lines.clear();
}

std::vector<std::uint8_t> ToByteVector(const std::string& value) {
  return std::vector<std::uint8_t>(value.begin(), value.end());
}

std::string ToString(const std::vector<std::uint8_t>& value) {
  return std::string(value.begin(), value.end());
}

void RecordRunAllStep(std::vector<std::string>* lines,
                      bool passed,
                      const char* label,
                      const std::string& detail) {
  lines->push_back(std::string(passed ? "PASS " : "FAIL ") + label + ": " + detail);
}

swg::Result<swg::TunnelDatagram> PollTunnelDatagramReceive(const swg::TunnelDatagramSocket& socket) {
  for (int attempt = 0; attempt < kReceivePollAttempts; ++attempt) {
    const auto result = socket.Receive();
    if (result.ok()) {
      return result;
    }
    if (result.error.code != swg::ErrorCode::NotFound) {
      return result;
    }
    svcSleepThread(kReceivePollIntervalNs);
  }

  return swg::MakeFailure<swg::TunnelDatagram>(swg::ErrorCode::NotFound,
                                               "timed out waiting for a tunnel datagram response");
}

swg::Result<swg::TunnelStreamReadResult> PollTunnelStreamReceive(const swg::TunnelStreamSocket& socket) {
  for (int attempt = 0; attempt < kReceivePollAttempts; ++attempt) {
    const auto result = socket.Receive();
    if (result.ok()) {
      if (!result.value.payload.empty() || result.value.peer_closed) {
        return result;
      }
    } else if (result.error.code != swg::ErrorCode::NotFound) {
      return result;
    }

    svcSleepThread(kReceivePollIntervalNs);
  }

  return swg::MakeFailure<swg::TunnelStreamReadResult>(swg::ErrorCode::NotFound,
                                                       "timed out waiting for a tunnel stream response");
}

bool EnsureConnectedSession(const swg::Client& client,
                            ScreenModel* model,
                            IntegrationState* state,
                            std::string* detail) {
  if (!model->status.ok()) {
    *detail = "status unavailable: " + model->status.error.message;
    return false;
  }

  if (model->status.value.state != swg::TunnelState::Connected) {
    const swg::Error error = client.Connect();
    if (error) {
      *detail = "connect failed: " + error.message;
      return false;
    }

    RefreshModel(client, model);
    if (!model->status.ok()) {
      *detail = "status unavailable after connect: " + model->status.error.message;
      return false;
    }
    if (model->status.value.state != swg::TunnelState::Connected) {
      *detail = "connect returned without reaching connected state";
      return false;
    }
  }

  const std::string profile_name = CurrentProfileName(*model);
  if (profile_name.empty()) {
    *detail = "no active profile available";
    return false;
  }

  if (state->session.is_open() && state->session.info().active_profile != profile_name) {
    const swg::Error error = state->session.Close();
    if (error) {
      *detail = "close stale session failed: " + error.message;
      return false;
    }
    state->session_request = {};
    ClearSessionDiagnostics(state);
  }

  if (!state->session.is_open()) {
    const swg::AppTunnelRequest request = MakeIntegrationSessionRequest(profile_name);
    const auto opened = state->session.Open(request);
    if (!opened.ok()) {
      *detail = "open session failed: " + opened.error.message;
      return false;
    }

    state->session_request = request;
    ClearSessionDiagnostics(state);
  }

  RefreshModel(client, model);
  if (!IsSessionTunnelReady(*model, *state)) {
    *detail = "session opened but tunnel is not ready for the active profile";
    return false;
  }

  *detail = "connected profile=" + state->session.info().active_profile +
            " session_id=" + std::to_string(state->session.info().session_id);
  return true;
}

std::string SelectSmokeTargetHost(const ScreenModel& model) {
  const swg::Result<IntegrationServerTarget> target = GetIntegrationServerTarget(model);
  if (!target.ok()) {
    return "vpn.example.test";
  }

  if (!target.value.dns_hostname.empty()) {
    return target.value.dns_hostname;
  }

  return target.value.endpoint.host;
}

bool IsSessionTunnelReady(const ScreenModel& model, const IntegrationState& state) {
  return state.session.is_open() && model.status.ok() &&
         model.status.value.state == swg::TunnelState::Connected &&
         state.session.info().active_profile == model.status.value.active_profile;
}

std::string FormatHexPreview(const std::vector<std::uint8_t>& bytes) {
  if (bytes.empty()) {
    return "<empty>";
  }

  std::ostringstream stream;
  stream << std::hex;
  const std::size_t preview_size = std::min(bytes.size(), kMaxPreviewBytes);
  for (std::size_t index = 0; index < preview_size; ++index) {
    if (index != 0) {
      stream << ' ';
    }

    stream.width(2);
    stream.fill('0');
    stream << static_cast<unsigned int>(bytes[index]);
  }

  if (bytes.size() > preview_size) {
    stream << " ...";
  }

  return stream.str();
}

std::string FormatJoined(const std::vector<std::string>& values) {
  if (values.empty()) {
    return "<none>";
  }

  std::ostringstream stream;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      stream << ", ";
    }
    stream << values[index];
  }
  return stream.str();
}

std::string ApplyRuntimeFlags(const swg::Client& client, swg::RuntimeFlags flags) {
  const swg::Error error = client.SetRuntimeFlags(flags);
  if (error) {
    return "set flags failed: " + error.message;
  }

  return "runtime flags updated to " + swg::RuntimeFlagsToString(flags);
}

std::string CycleProfile(const swg::Client& client, const ScreenModel& model, int direction) {
  if (!model.profiles.ok() || model.profiles.value.empty()) {
    return "no profiles available";
  }

  int index = FindActiveProfileIndex(model);
  if (index < 0) {
    index = 0;
  }

  const int profile_count = static_cast<int>(model.profiles.value.size());
  const int next_index = (index + direction + profile_count) % profile_count;
  const std::string& next_profile = model.profiles.value[static_cast<std::size_t>(next_index)].name;

  const swg::Error error = client.SetActiveProfile(next_profile);
  if (error) {
    return "set active profile failed: " + error.message;
  }

  return "active profile set to " + next_profile;
}

std::string ToggleConnection(const swg::Client& client, const ScreenModel& model) {
  if (!model.status.ok()) {
    return "status unavailable: " + model.status.error.message;
  }

  swg::Error error;
  if (model.status.value.state == swg::TunnelState::Connected ||
      model.status.value.state == swg::TunnelState::Connecting) {
    error = client.Disconnect();
    if (error) {
      return "disconnect failed: " + error.message;
    }
    return "disconnect requested";
  }

  error = client.Connect();
  if (error) {
    return "connect failed: " + error.message;
  }
  return "connect requested";
}

std::string ToggleSession(const ScreenModel& model, IntegrationState* state) {
  if (state->session.is_open()) {
    const swg::Error error = state->session.Close();
    if (error) {
      return "close session failed: " + error.message;
    }

    state->session_request = {};
    ClearSessionDiagnostics(state);
    return "app session closed";
  }

  const std::string profile_name = CurrentProfileName(model);
  if (profile_name.empty()) {
    return "cannot open session without an active profile";
  }

  swg::AppTunnelRequest request = MakeIntegrationSessionRequest(profile_name);

  const auto opened = state->session.Open(request);
  if (!opened.ok()) {
    return "open session failed: " + opened.error.message;
  }

  state->session_request = request;
  ClearSessionDiagnostics(state);
  return "app session opened: id=" + std::to_string(opened.value.session_id) +
         " profile=" + opened.value.active_profile;
}

std::string RunDnsResolve(const ScreenModel& model, IntegrationState* state) {
  if (!state->session.is_open()) {
    return "open app session before resolving dns";
  }

  state->dns_lines.clear();
  const swg::Result<IntegrationServerTarget> target = GetIntegrationServerTarget(model);
  if (!target.ok()) {
    state->last_dns_result = "skipped";
    state->dns_lines.push_back(target.error.message);
    return "dns resolve skipped";
  }

  state->dns_lines.push_back("target: " + DescribeIntegrationServerTarget(target.value));
  if (target.value.dns_hostname.empty()) {
    state->last_dns_result = "skipped";
    state->dns_lines.push_back(
        "configure integration_test.dns_hostname to exercise tunnel DNS when the target host is numeric");
    return "dns resolve skipped";
  }

  const auto dns = state->session.ResolveDns(target.value.dns_hostname);
  if (!dns.ok()) {
    state->last_dns_result = "failed";
    state->dns_lines.push_back(dns.error.message);
    return "dns resolve failed";
  }

  state->last_dns_result = std::string(swg::ToString(dns.value.action)) +
                           " resolved=" + BoolLabel(dns.value.resolved) +
                           " tunnel_dns=" + BoolLabel(dns.value.use_tunnel_dns);
  state->dns_lines.push_back("message: " + dns.value.message);
  state->dns_lines.push_back("addresses: " + FormatJoined(dns.value.addresses));
  state->dns_lines.push_back("dns servers: " + FormatJoined(dns.value.dns_servers));
  return "dns resolve refreshed";
}

void RecordSocketSummary(const char* label,
                         const swg::Result<swg::SessionSocket>& socket,
                         std::vector<std::string>* lines) {
  if (!socket.ok()) {
    lines->push_back(std::string("FAIL ") + label + ": " + socket.error.message);
    return;
  }

  const auto& info = socket.value.info();
  std::string line = std::string("PASS ") + label + ": kind=" + std::string(swg::ToString(info.kind)) +
                     " mode=" + std::string(swg::ToString(info.mode)) +
                     " transport=" + std::string(swg::ToString(info.transport));
  if (!info.remote_addresses.empty()) {
    line += " addrs=" + FormatJoined(info.remote_addresses);
  }
  lines->push_back(std::move(line));
  lines->push_back("  note: " + info.message);
  if (info.used_dns_helper) {
    lines->push_back("  dns: " + info.dns.message);
  }
}

std::string PrepareSocketSmoke(const ScreenModel& model, IntegrationState* state) {
  if (!state->session.is_open()) {
    return "open app session before opening socket wrappers";
  }

  state->socket_lines.clear();
  const swg::Result<IntegrationServerTarget> target = GetIntegrationServerTarget(model);
  if (!target.ok()) {
    state->sample_socket.reset();
    state->last_socket_result = "skipped";
    state->socket_lines.push_back(target.error.message);
    return "socket abstraction skipped";
  }

  state->socket_lines.push_back("target: " + DescribeIntegrationServerTarget(target.value));
  if (target.value.endpoint.is_numeric_ipv6) {
    state->sample_socket.reset();
    state->last_socket_result = "skipped";
    state->socket_lines.push_back(
        "numeric IPv6 endpoints are not yet supported by the session socket diagnostics; use a hostname or numeric IPv4 target");
    return "socket abstraction skipped";
  }

  const auto video_socket = swg::SessionSocket::OpenDatagram(
      state->session, swg::MakeMoonlightVideoSocketRequest(target.value.endpoint.host, target.value.udp_echo_port));
  RecordSocketSummary("video-datagram", video_socket, &state->socket_lines);

  const auto control_socket = swg::SessionSocket::OpenStream(
      state->session,
      swg::MakeMoonlightStreamControlSocketRequest(target.value.endpoint.host, target.value.tcp_echo_port));
  RecordSocketSummary("tcp-stream", control_socket, &state->socket_lines);

  if (video_socket.ok() && video_socket.value.uses_tunnel_packets()) {
    state->sample_socket = video_socket.value;
    state->last_socket_result = "video datagram socket is ready for tunnel packet I/O";
  } else {
    state->sample_socket.reset();
    state->last_socket_result = "no tunnel-packet datagram socket is ready";
  }

  return "socket abstraction refreshed";
}

std::string RunCompatResolveProbe(const ScreenModel& model, IntegrationState* state) {
  state->compat_lines.clear();

  const swg::Result<IntegrationServerTarget> target = GetIntegrationServerTarget(model);
  if (!target.ok()) {
    state->last_compat_result = "skipped";
    state->compat_lines.push_back(target.error.message);
    return "generic compat probe skipped";
  }

  constexpr char kCompatClientName[] = "SWG Integration Compat";
  constexpr char kCompatIntegrationTag[] = "switch-integration-compat";
  swg::ConfigureCompatBridgeIdentity(kCompatClientName, kCompatIntegrationTag, kCompatClientName);

  state->compat_lines.push_back("target: " + DescribeIntegrationServerTarget(target.value));
  state->compat_lines.push_back(std::string("identity: client=") + kCompatClientName +
                                " tag=" + kCompatIntegrationTag);

  sockaddr_storage resolved_addr{};
  socklen_t resolved_addr_len = 0;
  std::string error;
  const swg::CompatSocketRoute route = swg::CompatResolveStreamHost(target.value.endpoint.host,
                                                                    target.value.tcp_echo_port,
                                                                    &resolved_addr,
                                                                    &resolved_addr_len,
                                                                    &error);

  state->last_compat_result = std::string("route=") + CompatRouteLabel(route);
  if (route == swg::CompatSocketRoute::Direct) {
    state->compat_lines.push_back("result: compat layer selected native direct routing");
    return "generic compat probe refreshed";
  }

  if (route == swg::CompatSocketRoute::Tunnel) {
    state->compat_lines.push_back("result: compat layer selected tunnel routing");
    state->compat_lines.push_back("resolved address: " + FormatResolvedCompatAddress(resolved_addr));
    return "generic compat probe refreshed";
  }

  state->compat_lines.push_back("error: " + (error.empty() ? std::string("unknown compat failure") : error));
  return "generic compat probe failed";
}

bool RecordPlanCheck(const char* label,
                     const swg::Result<swg::NetworkPlan>& plan,
                     swg::RouteAction expected_action,
                     bool check_local_bypass,
                     bool expected_local_bypass,
                     bool expected_tunnel_dns,
                     const std::string& expected_profile,
                     std::vector<std::string>* lines) {
  bool ok = plan.ok();
  if (ok) {
    ok = plan.value.action == expected_action;
  }
  if (ok && check_local_bypass) {
    ok = plan.value.local_bypass == expected_local_bypass;
  }
  if (ok) {
    ok = plan.value.use_tunnel_dns == expected_tunnel_dns;
  }
  if (ok && !expected_profile.empty()) {
    ok = plan.value.profile_name == expected_profile;
  }

  if (!plan.ok()) {
    lines->push_back(std::string("FAIL ") + label + ": " + plan.error.message);
    return false;
  }

  std::string line = std::string(ok ? "PASS " : "FAIL ") + label + ": action=" +
                     std::string(swg::ToString(plan.value.action));
  if (check_local_bypass) {
    line += std::string(" local=") + BoolLabel(plan.value.local_bypass);
  }
  if (expected_tunnel_dns || plan.value.use_tunnel_dns) {
    line += std::string(" dns=") + BoolLabel(plan.value.use_tunnel_dns);
  }
  if (!ok) {
    line += " reason=" + plan.value.reason;
  }
  lines->push_back(std::move(line));
  return ok;
}

std::string RunSessionSmoke(const ScreenModel& model, IntegrationState* state) {
  if (!state->session.is_open()) {
    return "open app session before running smoke checks";
  }
  if (!model.status.ok()) {
    return "status unavailable: " + model.status.error.message;
  }

  const bool connected = IsSessionTunnelReady(model, *state);
  const bool dns_enabled = swg::HasFlag(model.status.value.runtime_flags, swg::RuntimeFlag::DnsThroughTunnel);
  const std::string smoke_target_host = SelectSmokeTargetHost(model);
  std::vector<std::string> lines;
  int passed = 0;

  passed += RecordPlanCheck(
      "discovery",
      state->session.PlanNetwork(swg::MakeMoonlightDiscoveryPlan()),
      swg::RouteAction::Direct,
      true,
      true,
      false,
      state->session.info().active_profile,
      &lines)
                ? 1
                : 0;
  passed += RecordPlanCheck(
      "wake-on-lan",
      state->session.PlanNetwork(swg::MakeMoonlightWakeOnLanPlan("192.168.1.20")),
      swg::RouteAction::Direct,
      true,
      true,
      false,
      state->session.info().active_profile,
      &lines)
                ? 1
                : 0;
  passed += RecordPlanCheck(
      "stun",
      state->session.PlanNetwork(swg::MakeMoonlightStunPlan()),
      swg::RouteAction::Direct,
      true,
      false,
      false,
      state->session.info().active_profile,
      &lines)
                ? 1
                : 0;

  swg::RouteAction expected_dns_action = swg::RouteAction::Direct;
  if (dns_enabled && connected) {
    expected_dns_action = swg::RouteAction::Tunnel;
  } else if (dns_enabled && !connected) {
    expected_dns_action = swg::RouteAction::Deny;
  }
  passed += RecordPlanCheck(
      "dns",
      state->session.PlanNetwork(swg::MakeMoonlightDnsPlan(smoke_target_host)),
      expected_dns_action,
      false,
      false,
      dns_enabled && connected,
      state->session.info().active_profile,
      &lines)
                ? 1
                : 0;

  const swg::RouteAction expected_stream_action = connected ? swg::RouteAction::Tunnel : swg::RouteAction::Deny;
  passed += RecordPlanCheck(
      "https-control",
      state->session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan(smoke_target_host, 47984)),
      expected_stream_action,
      false,
      false,
      false,
      state->session.info().active_profile,
      &lines)
                ? 1
                : 0;
  passed += RecordPlanCheck(
      "video",
      state->session.PlanNetwork(swg::MakeMoonlightVideoPlan(smoke_target_host, 47998)),
      expected_stream_action,
      false,
      false,
      false,
      state->session.info().active_profile,
      &lines)
                ? 1
                : 0;

  state->smoke_lines = std::move(lines);
  state->last_smoke_summary = std::string(passed == static_cast<int>(state->smoke_lines.size()) ? "pass " : "fail ") +
                              std::to_string(passed) + "/" + std::to_string(state->smoke_lines.size()) +
                              (connected ? " checks with tunnel connected" : " checks with tunnel disconnected");
  return state->last_smoke_summary;
}

std::string RunAllTunnelTests(const swg::Client& client, ScreenModel* model, IntegrationState* state) {
  std::vector<std::string> lines;
  int total_steps = 0;
  int passed_steps = 0;

  auto record = [&](bool passed, const char* label, const std::string& detail) {
    ++total_steps;
    if (passed) {
      ++passed_steps;
    }
    RecordRunAllStep(&lines, passed, label, detail);
  };

  std::string detail;
  if (!EnsureConnectedSession(client, model, state, &detail)) {
    record(false, "connect/session", detail);
    state->run_all_lines = std::move(lines);
    state->last_run_all_summary = "fail 0/1 steps";
    return state->last_run_all_summary;
  }
  record(true, "connect/session", detail);

  const std::string smoke_summary = RunSessionSmoke(*model, state);
  record(state->last_smoke_summary.rfind("pass ", 0) == 0, "route-smoke", smoke_summary);

  const swg::Result<IntegrationServerTarget> target = GetIntegrationServerTarget(*model);
  if (!target.ok()) {
    record(false, "target", target.error.message);
    state->run_all_lines = std::move(lines);
    state->last_run_all_summary = std::string(passed_steps == total_steps ? "pass " : "fail ") +
                                  std::to_string(passed_steps) + "/" + std::to_string(total_steps) + " steps";
    return state->last_run_all_summary;
  }

  const IntegrationServerTarget& server = target.value;
  if (server.endpoint.is_numeric_ipv6) {
    record(false, "target", "IPv6 targets are not supported by the current tunnel diagnostics");
    state->run_all_lines = std::move(lines);
    state->last_run_all_summary = std::string(passed_steps == total_steps ? "pass " : "fail ") +
                                  std::to_string(passed_steps) + "/" + std::to_string(total_steps) + " steps";
    return state->last_run_all_summary;
  }

  record(true, "target", DescribeIntegrationServerTarget(server));

  if (server.dns_hostname.empty()) {
    record(false, "dns", "configure integration_test.dns_hostname to exercise tunnel DNS for this target");
  } else {
    const auto dns = state->session.ResolveDns(server.dns_hostname);
    if (!dns.ok()) {
      record(false, "dns", dns.error.message);
    } else if (!dns.value.resolved || dns.value.addresses.empty()) {
      record(false, "dns", "resolve returned no IPv4 addresses");
    } else {
      record(true,
             "dns",
             std::string(swg::ToString(dns.value.action)) + " addrs=" + FormatJoined(dns.value.addresses));
    }
  }

  const auto session_datagram =
      swg::SessionSocket::OpenDatagram(state->session,
                                       swg::MakeMoonlightVideoSocketRequest(server.endpoint.host, server.udp_echo_port));
  const auto session_stream =
      swg::SessionSocket::OpenStream(state->session,
                                     swg::MakeMoonlightStreamControlSocketRequest(server.endpoint.host,
                                                                                  server.tcp_echo_port));

  bool socket_probe_ok = session_datagram.ok() && session_stream.ok();
  if (!socket_probe_ok) {
    const std::string socket_error = !session_datagram.ok() ? session_datagram.error.message
                                                            : session_stream.error.message;
    state->sample_socket.reset();
    record(false, "session-socket", socket_error);
  } else {
    const bool datagram_tunnel = session_datagram.value.uses_tunnel_packets();
    const bool stream_tunnel = session_stream.value.uses_tunnel_packets();
    socket_probe_ok = datagram_tunnel && stream_tunnel;
    if (datagram_tunnel) {
      state->sample_socket = session_datagram.value;
    } else {
      state->sample_socket.reset();
    }
    record(socket_probe_ok,
           "session-socket",
           std::string("udp=") + std::string(swg::ToString(session_datagram.value.info().mode)) +
               " tcp=" + std::string(swg::ToString(session_stream.value.info().mode)));
  }

  {
    const auto stream =
        swg::TunnelStreamSocket::Open(state->session,
                                      swg::MakeMoonlightStreamControlStreamRequest(server.endpoint.host,
                                                                                   server.tcp_echo_port));
    if (!stream.ok()) {
      record(false, "tcp-echo", stream.error.message);
    } else {
      const std::string payload_text = "SWG-TCP-ECHO-" + std::to_string(state->run_all_nonce++);
      const auto send_counter = stream.value.Send(ToByteVector(payload_text));
      if (!send_counter.ok()) {
        record(false, "tcp-echo", send_counter.error.message);
      } else {
        const auto received = PollTunnelStreamReceive(stream.value);
        if (!received.ok()) {
          record(false, "tcp-echo", received.error.message);
        } else {
          const std::string response = ToString(received.value.payload);
          record(response == payload_text,
                 "tcp-echo",
                 "send_counter=" + std::to_string(send_counter.value) +
                     " bytes=" + std::to_string(received.value.payload.size()));
        }
      }
    }
  }

  {
    swg::TunnelStreamOpenRequest http_request{};
    http_request.remote_host = server.endpoint.host;
    http_request.remote_port = server.http_port;
    http_request.transport = swg::TransportProtocol::Https;
    http_request.traffic_class = swg::AppTrafficClass::HttpsControl;
    http_request.route_preference = swg::RoutePreference::RequireTunnel;

    const auto stream = swg::TunnelStreamSocket::Open(state->session, http_request);
    if (!stream.ok()) {
      record(false, "http-probe", stream.error.message);
    } else {
      const std::string host_header = server.dns_hostname.empty() ? server.endpoint.host : server.dns_hostname;
      const std::string request_text = "GET " + server.http_path + " HTTP/1.1\r\nHost: " + host_header +
                                       "\r\nConnection: close\r\nUser-Agent: swg-integration/1\r\n\r\n";
      const auto send_counter = stream.value.Send(ToByteVector(request_text));
      if (!send_counter.ok()) {
        record(false, "http-probe", send_counter.error.message);
      } else {
        const auto received = PollTunnelStreamReceive(stream.value);
        if (!received.ok()) {
          record(false, "http-probe", received.error.message);
        } else {
          const std::string response = ToString(received.value.payload);
          const bool ok = response.find("HTTP/1.1 200 OK") != std::string::npos &&
                          response.find(kHarnessHttpSignature) != std::string::npos;
          record(ok,
                 "http-probe",
                 "send_counter=" + std::to_string(send_counter.value) +
                     " bytes=" + std::to_string(received.value.payload.size()));
        }
      }
    }
  }

  {
    const auto socket =
        swg::TunnelDatagramSocket::Open(state->session,
                                        swg::MakeMoonlightVideoDatagramRequest(server.endpoint.host,
                                                                               server.udp_echo_port));
    if (!socket.ok()) {
      record(false, "udp-echo", socket.error.message);
    } else {
      const std::string payload_text = "SWG-UDP-ECHO-" + std::to_string(state->run_all_nonce++);
      const auto send_counter = socket.value.Send(ToByteVector(payload_text));
      if (!send_counter.ok()) {
        record(false, "udp-echo", send_counter.error.message);
      } else {
        const auto received = PollTunnelDatagramReceive(socket.value);
        if (!received.ok()) {
          record(false, "udp-echo", received.error.message);
        } else {
          const std::string response = ToString(received.value.payload);
          record(response == payload_text,
                 "udp-echo",
                 "send_counter=" + std::to_string(send_counter.value) +
                     " bytes=" + std::to_string(received.value.payload.size()));
        }
      }
    }
  }

  state->run_all_lines = std::move(lines);
  state->last_run_all_summary = std::string(passed_steps == total_steps ? "pass " : "fail ") +
                                std::to_string(passed_steps) + "/" + std::to_string(total_steps) + " steps";
  RefreshModel(client, model);
  return state->last_run_all_summary;
}

std::string SendDiagnosticPayload(IntegrationState* state) {
  if (!state->session.is_open()) {
    return "open app session before sending a diagnostic payload";
  }

  const std::vector<std::uint8_t> payload = {
      0x53, 0x57, 0x47, 0x49, 0x4e, 0x54, state->payload_nonce++,
  };
  const auto counter = state->sample_socket.has_value() ? state->sample_socket->Send(payload)
                                                        : state->session.SendPacket(payload);
  if (!counter.ok()) {
    state->last_send_result = "failed: " + counter.error.message;
    return "diagnostic send failed";
  }

  state->last_send_result = "counter=" + std::to_string(counter.value) +
                            " size=" + std::to_string(payload.size()) +
                            " hex=" + FormatHexPreview(payload);
  return "diagnostic payload sent";
}

std::string ReceiveDiagnosticPayload(IntegrationState* state) {
  if (!state->session.is_open()) {
    return "open app session before reading queued payloads";
  }

  const auto packet = state->sample_socket.has_value() ? state->sample_socket->Receive()
                                                       : state->session.ReceivePacket();
  if (!packet.ok()) {
    state->last_receive_result = packet.error.message;
    return packet.error.code == swg::ErrorCode::NotFound ? "no queued payload" : "receive failed";
  }

  state->last_receive_result = "counter=" + std::to_string(packet.value.counter) +
                               " size=" + std::to_string(packet.value.payload.size()) +
                               " hex=" + FormatHexPreview(packet.value.payload);
  return "queued payload received";
}

void DrawScreen(const ScreenModel& model, const IntegrationState& state) {
  consoleClear();

  std::printf("Switch WireGuard Integration\n");
  if (model.version.ok()) {
    std::printf("version: %s  abi: %u\n", model.version.value.semantic_version.c_str(), model.version.value.abi_version);
  } else {
    std::printf("version: unavailable (%s)\n", model.version.error.message.c_str());
  }

  std::printf("\nservice:\n");
  if (model.status.ok()) {
    const auto& status = model.status.value;
    std::printf("  ready=%s state=%s profile=%s\n",
                BoolLabel(status.service_ready),
                std::string(swg::ToString(status.state)).c_str(),
                status.active_profile.empty() ? "<none>" : status.active_profile.c_str());
    std::printf("  flags=%s\n", swg::RuntimeFlagsToString(status.runtime_flags).c_str());
    std::printf("  last error=%s\n", status.last_error.empty() ? "<none>" : status.last_error.c_str());
  } else {
    std::printf("  unavailable (%s)\n", model.status.error.message.c_str());
  }

  std::printf("\nstats:\n");
  if (model.stats.ok()) {
    const auto& stats = model.stats.value;
    std::printf("  connect=%u handshakes=%u reconnects=%u\n",
                stats.connect_attempts,
                stats.successful_handshakes,
                stats.reconnects);
    std::printf("  packets in/out=%llu / %llu\n",
                static_cast<unsigned long long>(stats.packets_in),
                static_cast<unsigned long long>(stats.packets_out));
    std::printf("  bytes in/out=%llu / %llu\n",
                static_cast<unsigned long long>(stats.bytes_in),
                static_cast<unsigned long long>(stats.bytes_out));
  } else {
    std::printf("  unavailable (%s)\n", model.stats.error.message.c_str());
  }

  std::printf("\napp session:\n");
  if (state.session.is_open()) {
    const auto& info = state.session.info();
    std::printf("  open=yes id=%llu profile=%s\n",
                static_cast<unsigned long long>(info.session_id),
                info.active_profile.empty() ? "<none>" : info.active_profile.c_str());
    std::printf("  granted=%s tunnel_now=%s\n",
                swg::RuntimeFlagsToString(info.granted_flags).c_str(),
                BoolLabel(IsSessionTunnelReady(model, state)));
  } else {
    std::printf("  open=no\n");
  }

  std::printf("\nlast action: %s\n", state.last_action.c_str());
  std::printf("run all: %s\n", state.last_run_all_summary.c_str());
  for (const auto& line : state.run_all_lines) {
    std::printf("  %s\n", line.c_str());
  }

  std::printf("smoke: %s\n", state.last_smoke_summary.c_str());
  for (const auto& line : state.smoke_lines) {
    std::printf("  %s\n", line.c_str());
  }

  std::printf("\ndns resolve:\n");
  std::printf("  %s\n", state.last_dns_result.c_str());
  for (const auto& line : state.dns_lines) {
    std::printf("  %s\n", line.c_str());
  }

  std::printf("\nsocket abstraction:\n");
  std::printf("  %s\n", state.last_socket_result.c_str());
  for (const auto& line : state.socket_lines) {
    std::printf("  %s\n", line.c_str());
  }

  std::printf("\ngeneric compat probe:\n");
  std::printf("  %s\n", state.last_compat_result.c_str());
  for (const auto& line : state.compat_lines) {
    std::printf("  %s\n", line.c_str());
  }

  std::printf("\ndiagnostic payload:\n");
  std::printf("  send=%s\n", state.last_send_result.c_str());
  std::printf("  recv=%s\n", state.last_receive_result.c_str());
  std::printf("  send/recv uses the sample tunnel socket when available\n");

  std::printf("\ncontrols:\n");
  std::printf("  A connect/disconnect   B refresh   - compat probe   + exit\n");
  std::printf("  X open/close session   Y run all tunnel tests\n");
  std::printf("  Up resolve dns         Down open socket helpers\n");
  std::printf("  Left/Right change active profile\n");
  std::printf("  ZL toggle dns flag     ZR toggle transparent flag\n");
  std::printf("  L send diagnostic payload   R poll receive queue\n");
}

}  // namespace

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  consoleInit(nullptr);

  PadState pad;
  padConfigureInput(1, HidNpadStyleSet_NpadStandard);
  padInitializeDefault(&pad);

  swg::Client client;
  ScreenModel model{};
  IntegrationState state(client);
  int frame_counter = 0;
  bool refresh_requested = true;

  while (appletMainLoop()) {
    padUpdate(&pad);
    const u64 buttons_down = padGetButtonsDown(&pad);

    if ((buttons_down & HidNpadButton_Plus) != 0) {
      break;
    }

    if ((buttons_down & HidNpadButton_B) != 0) {
      state.last_action = "manual refresh";
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_Minus) != 0) {
      state.last_action = RunCompatResolveProbe(model, &state);
    }

    if (refresh_requested || frame_counter % kAutoRefreshFrames == 0) {
      RefreshModel(client, &model);
      refresh_requested = false;
    }

    if ((buttons_down & HidNpadButton_A) != 0) {
      state.last_action = ToggleConnection(client, model);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_X) != 0) {
      state.last_action = ToggleSession(model, &state);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_Y) != 0) {
      state.last_action = RunAllTunnelTests(client, &model, &state);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_Up) != 0) {
      state.last_action = RunDnsResolve(model, &state);
    }

    if ((buttons_down & HidNpadButton_Down) != 0) {
      state.last_action = PrepareSocketSmoke(model, &state);
    }

    if ((buttons_down & HidNpadButton_Left) != 0) {
      state.last_action = CycleProfile(client, model, -1);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_Right) != 0) {
      state.last_action = CycleProfile(client, model, 1);
      refresh_requested = true;
    }

    if (model.status.ok()) {
      if ((buttons_down & HidNpadButton_ZL) != 0) {
        state.last_action = ApplyRuntimeFlags(client, ToggleFlag(model.status.value.runtime_flags,
                                                                 swg::RuntimeFlag::DnsThroughTunnel));
        refresh_requested = true;
      }

      if ((buttons_down & HidNpadButton_ZR) != 0) {
        state.last_action = ApplyRuntimeFlags(client, ToggleFlag(model.status.value.runtime_flags,
                                                                 swg::RuntimeFlag::TransparentMode));
        refresh_requested = true;
      }
    }

    if ((buttons_down & HidNpadButton_L) != 0) {
      state.last_action = SendDiagnosticPayload(&state);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_R) != 0) {
      state.last_action = ReceiveDiagnosticPayload(&state);
      refresh_requested = true;
    }

    DrawScreen(model, state);
    consoleUpdate(nullptr);
    ++frame_counter;
  }

  if (state.session.is_open()) {
    static_cast<void>(state.session.Close());
  }

  consoleExit(nullptr);
  return 0;
}