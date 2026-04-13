#include "swg_sysmodule/local_service.h"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>

#include "swg/config.h"
#include "swg/hos_caps.h"
#include "swg/ipv4_tcp.h"
#include "swg/log.h"
#include "swg/state_machine.h"
#include "swg/tunnel_dns.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/wg_engine.h"

namespace swg::sysmodule {
namespace {

bool ProfileHasCompleteKeyMaterial(const ProfileConfig& profile) {
  return !profile.private_key.empty() && !profile.public_key.empty() && !profile.endpoint_host.empty() &&
         !profile.allowed_ips.empty() && !profile.addresses.empty();
}

struct AppSessionRecord {
  AppTunnelRequest request;
  std::string matched_policy_name;
  RuntimeFlags requested_flags = 0;
  bool allow_local_network_bypass = true;
  bool require_tunnel_for_default_traffic = false;
  bool prefer_tunnel_dns = true;
  bool allow_direct_internet_fallback = false;
  std::string selected_profile;
};

struct TunnelDatagramHandleRecord {
  std::uint64_t datagram_id = 0;
  std::uint64_t session_id = 0;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  std::string selected_profile;
  std::string remote_host;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string local_address;
  std::uint16_t local_port = 0;
  std::array<std::uint8_t, 4> remote_ipv4{};
  std::array<std::uint8_t, 4> local_ipv4{};
};

struct TunnelStreamHandleRecord {
  struct BufferedSegment {
    std::uint64_t counter = 0;
    Ipv4TcpPacket packet;
  };

  std::uint64_t stream_id = 0;
  std::uint64_t session_id = 0;
  TransportProtocol transport = TransportProtocol::Tcp;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  std::string selected_profile;
  std::string remote_host;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string local_address;
  std::uint16_t local_port = 0;
  std::array<std::uint8_t, 4> remote_ipv4{};
  std::array<std::uint8_t, 4> local_ipv4{};
  std::uint32_t next_send_sequence = 0;
  std::uint32_t next_expected_remote_sequence = 0;
  bool peer_closed = false;
  std::map<std::uint32_t, BufferedSegment> buffered_remote_segments;
};

struct TunnelDnsLookupResult {
  bool resolved = false;
  std::vector<std::string> addresses;
  std::string message;
  std::uint32_t fallback_count = 0;
};

enum class ClosedTunnelFlowTransport : std::uint8_t {
  Udp = 0,
  Tcp,
};

struct ClosedTunnelFlowRecord {
  ClosedTunnelFlowTransport transport = ClosedTunnelFlowTransport::Udp;
  std::array<std::uint8_t, 4> remote_ipv4{};
  std::array<std::uint8_t, 4> local_ipv4{};
  std::uint16_t remote_port = 0;
  std::uint16_t local_port = 0;
};

constexpr std::uint16_t kTunnelDnsSourcePortBase = 40000;
constexpr std::uint16_t kTunnelDnsSourcePortSpan = 20000;
constexpr std::uint16_t kTunnelDnsDestinationPort = 53;
constexpr std::uint16_t kTunnelDatagramSourcePortBase = 20000;
constexpr std::uint16_t kTunnelDatagramSourcePortSpan = 10000;
constexpr std::uint16_t kTunnelStreamSourcePortBase = 30000;
constexpr std::uint16_t kTunnelStreamSourcePortSpan = 10000;
constexpr std::uint32_t kTunnelStreamInitialSequenceBase = 0x53570000u;
constexpr std::chrono::milliseconds kTunnelDnsPollInterval(25);
constexpr int kTunnelDnsPollAttemptsPerServer = 40;
constexpr std::chrono::milliseconds kTunnelStreamConnectPollInterval(25);
constexpr std::chrono::milliseconds kTunnelStreamConnectTimeout(3000);
constexpr std::chrono::milliseconds kTunnelStreamConnectSynRetransmitInterval(250);
constexpr std::size_t kTunnelStreamBufferedSegmentLimit = 32;
constexpr std::size_t kClosedTunnelFlowRecordLimit = 64;

ClosedTunnelFlowRecord MakeClosedTunnelFlowRecord(const TunnelDatagramHandleRecord& datagram) {
  ClosedTunnelFlowRecord record{};
  record.transport = ClosedTunnelFlowTransport::Udp;
  record.remote_ipv4 = datagram.remote_ipv4;
  record.local_ipv4 = datagram.local_ipv4;
  record.remote_port = datagram.remote_port;
  record.local_port = datagram.local_port;
  return record;
}

ClosedTunnelFlowRecord MakeClosedTunnelFlowRecord(const TunnelStreamHandleRecord& stream) {
  ClosedTunnelFlowRecord record{};
  record.transport = ClosedTunnelFlowTransport::Tcp;
  record.remote_ipv4 = stream.remote_ipv4;
  record.local_ipv4 = stream.local_ipv4;
  record.remote_port = stream.remote_port;
  record.local_port = stream.local_port;
  return record;
}

bool MatchesClosedTunnelFlow(const ClosedTunnelFlowRecord& flow, const Ipv4UdpPacket& packet) {
  return flow.transport == ClosedTunnelFlowTransport::Udp && packet.endpoint.source_ipv4 == flow.remote_ipv4 &&
         packet.endpoint.destination_ipv4 == flow.local_ipv4 && packet.endpoint.source_port == flow.remote_port &&
         packet.endpoint.destination_port == flow.local_port;
}

bool MatchesClosedTunnelFlow(const ClosedTunnelFlowRecord& flow, const Ipv4TcpPacket& packet) {
  return flow.transport == ClosedTunnelFlowTransport::Tcp && packet.endpoint.source_ipv4 == flow.remote_ipv4 &&
         packet.endpoint.destination_ipv4 == flow.local_ipv4 && packet.endpoint.source_port == flow.remote_port &&
         packet.endpoint.destination_port == flow.local_port;
}

std::uint32_t MeasureTunnelStreamSequenceAdvance(const Ipv4TcpPacket& segment) {
  std::uint32_t advance = 0;
  if (HasFlag(segment.flags, TcpControlFlag::Syn)) {
    ++advance;
  }
  advance += static_cast<std::uint32_t>(segment.payload.size());
  if (HasFlag(segment.flags, TcpControlFlag::Fin)) {
    ++advance;
  }
  return advance;
}

std::uint32_t MeasureTunnelStreamEndSequence(const Ipv4TcpPacket& segment) {
  return segment.sequence_number + MeasureTunnelStreamSequenceAdvance(segment);
}

void TrimTunnelStreamSegmentPrefix(Ipv4TcpPacket* segment, std::uint32_t trim_bytes) {
  if (trim_bytes == 0) {
    return;
  }

  if (HasFlag(segment->flags, TcpControlFlag::Syn) && trim_bytes != 0) {
    segment->flags = static_cast<TcpControlFlags>(segment->flags & ~ToFlags(TcpControlFlag::Syn));
    ++segment->sequence_number;
    --trim_bytes;
  }

  if (trim_bytes != 0 && !segment->payload.empty()) {
    const std::size_t payload_trim = std::min<std::size_t>(trim_bytes, segment->payload.size());
    segment->payload.erase(segment->payload.begin(),
                           segment->payload.begin() + static_cast<std::ptrdiff_t>(payload_trim));
    segment->sequence_number += static_cast<std::uint32_t>(payload_trim);
    trim_bytes -= static_cast<std::uint32_t>(payload_trim);
  }

  if (trim_bytes != 0 && HasFlag(segment->flags, TcpControlFlag::Fin)) {
    segment->flags = static_cast<TcpControlFlags>(segment->flags & ~ToFlags(TcpControlFlag::Fin));
    ++segment->sequence_number;
    --trim_bytes;
  }
}

Result<std::vector<std::string>> ResolveIpv4HostAddrs(std::string_view hostname) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  addrinfo* results = nullptr;
  const int rc = getaddrinfo(std::string(hostname).c_str(), nullptr, &hints, &results);
  if (rc != 0 || results == nullptr) {
    if (results != nullptr) {
      freeaddrinfo(results);
    }

    const ErrorCode code = rc == EAI_NONAME ? ErrorCode::NotFound : ErrorCode::ServiceUnavailable;
    std::string message = "hostname '" + std::string(hostname) + "' did not resolve to IPv4";
    if (rc != 0) {
      message += ": ";
      message += gai_strerror(rc);
    }
    return MakeFailure<std::vector<std::string>>(code, std::move(message));
  }

  std::vector<std::string> addresses;
  for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
    if (current->ai_family != AF_INET || current->ai_addr == nullptr ||
        current->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      continue;
    }

    const auto& addr = *reinterpret_cast<const sockaddr_in*>(current->ai_addr);
    char buffer[16] = {};
    if (inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer)) == nullptr) {
      continue;
    }

    const std::string address(buffer);
    if (std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
      addresses.push_back(address);
    }
  }

  freeaddrinfo(results);
  if (addresses.empty()) {
    return MakeFailure<std::vector<std::string>>(ErrorCode::NotFound,
                                                 "hostname '" + std::string(hostname) +
                                                     "' returned no usable IPv4 addresses");
  }

  return MakeSuccess(std::move(addresses));
}

std::string DescribeDnsResponseCode(std::uint8_t rcode) {
  switch (rcode) {
    case 0:
      return "no_error";
    case 1:
      return "format_error";
    case 2:
      return "server_failure";
    case 3:
      return "name_error";
    case 4:
      return "not_implemented";
    case 5:
      return "refused";
    default:
      return "rcode=" + std::to_string(rcode);
  }
}

RuntimeFlags ResolveGrantedFlags(RuntimeFlags active_flags, RuntimeFlags requested_flags) {
  return requested_flags == 0 ? active_flags : (active_flags & requested_flags);
}

bool StartsWith(std::string_view value, std::string_view prefix) {
  return value.rfind(prefix, 0) == 0;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
  return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}

bool IsPrivateIpv4(std::string_view host) {
  if (StartsWith(host, "10.") || StartsWith(host, "127.") || StartsWith(host, "192.168.") ||
      StartsWith(host, "169.254.")) {
    return true;
  }

  if (!StartsWith(host, "172.")) {
    return false;
  }

  const std::size_t first_dot = host.find('.');
  if (first_dot == std::string_view::npos) {
    return false;
  }

  const std::size_t second_dot = host.find('.', first_dot + 1);
  const std::string second_octet = std::string(host.substr(first_dot + 1, second_dot - first_dot - 1));
  try {
    const int value = std::stoi(second_octet);
    return value >= 16 && value <= 31;
  } catch (const std::exception&) {
    return false;
  }
}

bool LooksLocalHost(std::string_view host) {
  if (host.empty()) {
    return false;
  }

  std::string normalized(host);
  for (char& ch : normalized) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  return normalized == "localhost" || normalized == "::1" || StartsWith(normalized, "fe80:") ||
         StartsWith(normalized, "fc") || StartsWith(normalized, "fd") || EndsWith(normalized, ".local") ||
         IsPrivateIpv4(normalized);
}

const AppPolicyConfig* FindMatchingAppPolicy(const Config& config,
                                             const AppIdentity& app,
                                             std::string* matched_policy_name) {
  const AppPolicyConfig* best_match = nullptr;
  int best_score = -1;

  for (const auto& [name, policy] : config.app_policies) {
    if (name == "default") {
      continue;
    }

    bool has_explicit_match_fields = false;
    int score = 0;

    if (!policy.client_name.empty()) {
      has_explicit_match_fields = true;
      if (policy.client_name != app.client_name) {
        continue;
      }
      score += 2;
    }

    if (!policy.integration_tag.empty()) {
      has_explicit_match_fields = true;
      if (policy.integration_tag != app.integration_tag) {
        continue;
      }
      score += 4;
    }

    if (!has_explicit_match_fields) {
      const bool name_matches = (!app.client_name.empty() && name == app.client_name) ||
                                (!app.integration_tag.empty() && name == app.integration_tag);
      if (!name_matches) {
        continue;
      }
      score = 1;
    }

    if (score > best_score) {
      best_match = &policy;
      best_score = score;
      if (matched_policy_name != nullptr) {
        *matched_policy_name = name;
      }
    }
  }

  if (best_match != nullptr) {
    return best_match;
  }

  const auto default_it = config.app_policies.find("default");
  if (default_it != config.app_policies.end()) {
    if (matched_policy_name != nullptr) {
      *matched_policy_name = default_it->first;
    }
    return &default_it->second;
  }

  return nullptr;
}

AppSessionRecord ResolveAppSessionRecord(const Config& config, const AppTunnelRequest& request) {
  AppSessionRecord session{};
  session.request = request;
  session.selected_profile = request.desired_profile.empty() ? config.active_profile : request.desired_profile;
  session.requested_flags = request.requested_flags;
  session.allow_local_network_bypass = request.allow_local_network_bypass;
  session.require_tunnel_for_default_traffic = request.require_tunnel_for_default_traffic;
  session.prefer_tunnel_dns = request.prefer_tunnel_dns;
  session.allow_direct_internet_fallback = request.allow_direct_internet_fallback;

  std::string matched_policy_name;
  const AppPolicyConfig* matched_policy = FindMatchingAppPolicy(config, request.app, &matched_policy_name);
  if (matched_policy == nullptr) {
    return session;
  }

  session.matched_policy_name = std::move(matched_policy_name);

  if (request.desired_profile.empty() && !matched_policy->desired_profile.empty()) {
    session.selected_profile = matched_policy->desired_profile;
  }

  if (request.requested_flags == 0) {
    session.requested_flags = matched_policy->requested_flags;
  }

  session.allow_local_network_bypass = matched_policy->allow_local_network_bypass;
  session.require_tunnel_for_default_traffic = matched_policy->require_tunnel_for_default_traffic;
  session.prefer_tunnel_dns = matched_policy->prefer_tunnel_dns;
  session.allow_direct_internet_fallback = matched_policy->allow_direct_internet_fallback;

  if (HasFlag(request.policy_overrides, AppPolicyOverrideFlag::AllowLocalNetworkBypass)) {
    session.allow_local_network_bypass = request.allow_local_network_bypass;
  }

  if (HasFlag(request.policy_overrides, AppPolicyOverrideFlag::RequireTunnelForDefaultTraffic)) {
    session.require_tunnel_for_default_traffic = request.require_tunnel_for_default_traffic;
  }

  if (HasFlag(request.policy_overrides, AppPolicyOverrideFlag::PreferTunnelDns)) {
    session.prefer_tunnel_dns = request.prefer_tunnel_dns;
  }

  if (HasFlag(request.policy_overrides, AppPolicyOverrideFlag::AllowDirectInternetFallback)) {
    session.allow_direct_internet_fallback = request.allow_direct_internet_fallback;
  }

  return session;
}

std::string BuildAppSessionNotes(const AppSessionRecord& session,
                                 const StateSnapshot& snapshot,
                                 RuntimeFlags granted_flags) {
  std::ostringstream stream;
  stream << "app=" << (session.request.app.client_name.empty() ? "unknown" : session.request.app.client_name)
         << ", profile=" << (session.selected_profile.empty() ? "<none>" : session.selected_profile)
         << ", runtime_flags=" << RuntimeFlagsToString(granted_flags)
         << ", state=" << ToString(snapshot.state);
  if (!session.matched_policy_name.empty()) {
    stream << ", app_policy=" << session.matched_policy_name;
  }
  if (session.require_tunnel_for_default_traffic) {
    stream << ", default_routes=require_tunnel";
  }
  if (session.allow_local_network_bypass) {
    stream << ", local_bypass=enabled";
  }
  if (session.prefer_tunnel_dns) {
    stream << ", dns=tunnel_preferred";
  }
  if (session.allow_direct_internet_fallback) {
    stream << ", direct_fallback=enabled";
  }
  return stream.str();
}

TunnelStats MergeEngineStats(const TunnelStats& base, const TunnelStats& engine) {
  TunnelStats merged = base;
  merged.bytes_in += engine.bytes_in;
  merged.bytes_out += engine.bytes_out;
  merged.packets_in += engine.packets_in;
  merged.packets_out += engine.packets_out;
  merged.successful_handshakes += engine.successful_handshakes;
  merged.reconnects += engine.reconnects;
  merged.dns_queries += engine.dns_queries;
  merged.dns_fallbacks += engine.dns_fallbacks;
  merged.leak_prevention_events += engine.leak_prevention_events;
  merged.last_handshake_age_seconds = engine.last_handshake_age_seconds;
  return merged;
}

NetworkPlan BuildNetworkPlan(const AppSessionRecord& session,
                             const StateSnapshot& snapshot,
                             RuntimeFlags granted_flags,
                             const NetworkPlanRequest& request) {
  const bool tunnel_ready = snapshot.state == TunnelState::Connected && !session.selected_profile.empty() &&
                            snapshot.active_profile == session.selected_profile;

  NetworkPlan plan{};
  plan.profile_name = session.selected_profile;
  plan.transparent_eligible = tunnel_ready && HasFlag(granted_flags, RuntimeFlag::TransparentMode);

  const bool explicit_bypass = request.route_preference == RoutePreference::BypassTunnel;
  const bool local_bypass = session.allow_local_network_bypass &&
                            (request.local_network_hint || request.traffic_class == AppTrafficClass::Discovery ||
                             request.traffic_class == AppTrafficClass::WakeOnLan ||
                             LooksLocalHost(request.remote_host));

  if (explicit_bypass || local_bypass) {
    plan.action = RouteAction::Direct;
    plan.local_bypass = local_bypass;
    plan.reason = explicit_bypass ? "caller requested direct routing"
                                 : "local discovery or local-network traffic bypasses the tunnel";
    return plan;
  }

  if (request.traffic_class == AppTrafficClass::Dns) {
    const bool wants_tunnel_dns = session.prefer_tunnel_dns && HasFlag(granted_flags, RuntimeFlag::DnsThroughTunnel);
    if (wants_tunnel_dns && tunnel_ready) {
      plan.action = RouteAction::Tunnel;
      plan.use_tunnel_dns = true;
      plan.reason = "DNS should resolve through the active tunnel for this app session";
      return plan;
    }

    if (wants_tunnel_dns && !session.allow_direct_internet_fallback) {
      plan.action = RouteAction::Deny;
      plan.reason = "tunnel DNS requested but the tunnel is not ready";
      return plan;
    }

    plan.action = RouteAction::Direct;
    plan.reason = wants_tunnel_dns ? "falling back to direct DNS because tunnel DNS is unavailable"
                                   : "app session does not require tunnel DNS";
    return plan;
  }

  bool wants_tunnel = false;
  switch (request.route_preference) {
    case RoutePreference::RequireTunnel:
    case RoutePreference::PreferTunnel:
      wants_tunnel = true;
      break;
    case RoutePreference::Default:
      wants_tunnel = session.require_tunnel_for_default_traffic;
      break;
    case RoutePreference::BypassTunnel:
      wants_tunnel = false;
      break;
  }

  if (wants_tunnel) {
    if (tunnel_ready) {
      plan.action = RouteAction::Tunnel;
      plan.reason = "policy selected the active tunnel for this traffic";
      return plan;
    }

    if (request.route_preference != RoutePreference::RequireTunnel && session.allow_direct_internet_fallback) {
      plan.action = RouteAction::Direct;
      plan.reason = "tunnel unavailable; app session allows direct fallback";
      return plan;
    }

    plan.action = RouteAction::Deny;
    plan.reason = "tunnel-required traffic cannot proceed until the selected profile is connected";
    return plan;
  }

  plan.action = RouteAction::Direct;
  plan.reason = "traffic class does not require the tunnel";
  return plan;
}

class LocalControlService final : public IControlService {
 public:
  explicit LocalControlService(std::filesystem::path runtime_root,
                               std::unique_ptr<IWgTunnelEngine> tunnel_engine = {})
      : paths_(DetectRuntimePaths(runtime_root)),
        tunnel_engine_(tunnel_engine ? std::move(tunnel_engine) : CreateWgTunnelEngine()) {
    const Error init_error = Initialize();
    if (init_error) {
      initialization_error_ = init_error;
    }
  }

  Result<VersionInfo> GetVersion() const override {
    return MakeSuccess(VersionInfo{});
  }

  Result<ServiceStatus> GetStatus() const override {
    std::scoped_lock lock(mutex_);

    const StateSnapshot snapshot = state_machine_.snapshot();
    ServiceStatus status{};
    status.service_ready = initialization_error_.ok();
    status.state = initialization_error_ ? TunnelState::Error : snapshot.state;
    status.runtime_flags = snapshot.runtime_flags;
    status.active_profile = snapshot.active_profile;
    status.last_error = initialization_error_ ? initialization_error_.message : snapshot.last_error;
    if (!initialization_error_ && snapshot.state == TunnelState::Connected && !tunnel_engine_->IsRunning()) {
      const std::string runtime_error = tunnel_engine_->GetLastError();
      if (!runtime_error.empty()) {
        status.state = TunnelState::Error;
        status.last_error = runtime_error;
      }
    }
    return MakeSuccess(std::move(status));
  }

  Result<std::string> GetLastError() const override {
    const Result<ServiceStatus> status = GetStatus();
    if (!status.ok()) {
      return MakeFailure<std::string>(status.error.code, status.error.message);
    }
    return MakeSuccess(status.value.last_error);
  }

  Result<std::vector<ProfileSummary>> ListProfiles() const override {
    std::scoped_lock lock(mutex_);

    std::vector<ProfileSummary> profiles;
    profiles.reserve(config_.profiles.size());
    for (const auto& [name, profile] : config_.profiles) {
      profiles.push_back(ProfileSummary{
          name,
          profile.autostart,
          profile.transparent_mode,
          ProfileHasCompleteKeyMaterial(profile),
      });
    }

    return MakeSuccess(std::move(profiles));
  }

  Result<Config> GetConfig() const override {
    std::scoped_lock lock(mutex_);
    return MakeSuccess(config_);
  }

  Error SaveConfig(const Config& config) override {
    std::scoped_lock lock(mutex_);

    if (!IsConfigMutationAllowed()) {
      return MakeError(ErrorCode::InvalidState, "cannot save config while tunnel is active");
    }

    const Error validation_error = ValidateConfig(config);
    if (validation_error) {
      return validation_error;
    }

    config_ = config;
    NormalizeActiveProfile();
    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      return save_error;
    }

    ApplyConfigToState();
    LogInfo("sysmodule", "config saved: " + DescribeConfig(config_));
    return Error::None();
  }

  Error SetActiveProfile(std::string_view profile_name) override {
    std::scoped_lock lock(mutex_);

    const std::string profile(profile_name);
    if (config_.profiles.find(profile) == config_.profiles.end()) {
      return MakeError(ErrorCode::NotFound, "profile not found: " + profile);
    }

    const Error state_error = state_machine_.SetActiveProfile(profile);
    if (state_error) {
      return state_error;
    }

    config_.active_profile = profile;
    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      return save_error;
    }

    LogInfo("sysmodule", "active profile set to " + profile);
    return Error::None();
  }

  Error Connect() override {
    std::scoped_lock lock(mutex_);

    if (initialization_error_) {
      return initialization_error_;
    }

    const auto profile_it = config_.profiles.find(config_.active_profile);
    if (profile_it == config_.profiles.end()) {
      return MakeError(ErrorCode::InvalidConfig, "active profile does not exist: " + config_.active_profile);
    }

    const Error connect_error = state_machine_.Connect();
    if (connect_error) {
      return connect_error;
    }

    TunnelStats stats = state_machine_.snapshot().stats;
    ++stats.connect_attempts;
    state_machine_.UpdateStats(stats);

    const Result<ValidatedWireGuardProfile> validated_profile =
        ValidateWireGuardProfileForConnect(profile_it->second);
    if (!validated_profile.ok()) {
      state_machine_.MarkConnectFailed(validated_profile.error.message);
      LogError("sysmodule", "connect validation failed for profile " + config_.active_profile + ": " +
                                 validated_profile.error.message);
      return validated_profile.error;
    }

    const Result<PreparedTunnelSession> prepared_session =
        PrepareTunnelSession(config_.active_profile, validated_profile.value, config_.runtime_flags);
    if (!prepared_session.ok()) {
      state_machine_.MarkConnectFailed(prepared_session.error.message);
      LogError("sysmodule", "connect session preparation failed for profile " + config_.active_profile + ": " +
                                 prepared_session.error.message);
      return prepared_session.error;
    }

    const Error engine_error = tunnel_engine_->Start(TunnelEngineStartRequest{prepared_session.value});
    if (engine_error) {
      state_machine_.MarkConnectFailed(engine_error.message);
      LogError("sysmodule", "WireGuard engine start failed for profile " + config_.active_profile + ": " +
                                 engine_error.message);
      return engine_error;
    }

    const Error mark_error = state_machine_.MarkConnected();
    if (mark_error) {
      tunnel_engine_->Stop();
      return mark_error;
    }

    LogInfo("sysmodule", "connect requested with prepared session: " +
                            DescribePreparedTunnelSession(prepared_session.value) +
                            " (WireGuard response validated)");
    return Error::None();
  }

  Error Disconnect() override {
    std::scoped_lock lock(mutex_);

    const Error disconnect_error = state_machine_.Disconnect();
    if (disconnect_error) {
      return disconnect_error;
    }

    const TunnelStats final_engine_stats = tunnel_engine_->GetStats();

    const Error engine_error = tunnel_engine_->Stop();
    if (engine_error) {
      state_machine_.MarkConnectFailed(engine_error.message);
      return engine_error;
    }

    InvalidateAllTunnelFlowsLocked();

    const Error mark_error = state_machine_.MarkDisconnected();
    if (mark_error) {
      return mark_error;
    }

    state_machine_.UpdateStats(MergeEngineStats(state_machine_.snapshot().stats, final_engine_stats));

    LogInfo("sysmodule", "disconnect requested");
    return Error::None();
  }

  Result<TunnelStats> GetStats() const override {
    std::scoped_lock lock(mutex_);

    TunnelStats stats = MergeEngineStats(state_machine_.snapshot().stats, tunnel_engine_->GetStats());

    return MakeSuccess(std::move(stats));
  }

  Error SetRuntimeFlags(RuntimeFlags flags) override {
    std::scoped_lock lock(mutex_);

    config_.runtime_flags = flags;
    const Error state_error = state_machine_.SetRuntimeFlags(flags);
    if (state_error) {
      return state_error;
    }

    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      return save_error;
    }

    LogInfo("sysmodule", "runtime flags set to " + RuntimeFlagsToString(flags));
    return Error::None();
  }

  Result<CompatibilityInfo> GetCompatibilityInfo() const override {
    const HosCapabilities capabilities = DetectHosCapabilities();
    CompatibilityInfo info{};
    info.switch_target = capabilities.switch_target;
    info.has_bsd_a = capabilities.has_bsd_a;
    info.has_dns_priv = capabilities.has_dns_priv;
    info.has_ifcfg = capabilities.has_ifcfg;
    info.has_bsd_nu = capabilities.has_bsd_nu;
    info.needs_new_tls_abi = capabilities.needs_new_tls_abi;
#if defined(SWG_PLATFORM_SWITCH)
    info.notes = DescribeHosCapabilities(capabilities) +
         "; probe mapping: has_dns_priv checks dns:priv then sfdnsres, has_ifcfg checks ifcfg then nifm:a/nifm:s; "
         "Phase A exposes the control plane through the registered swg:ctl service.";
#else
    info.notes = DescribeHosCapabilities(capabilities) + "; Phase A currently exercises the control plane through a local stub service.";
#endif
    return MakeSuccess(std::move(info));
  }

  Result<AppSessionInfo> OpenAppSession(const AppTunnelRequest& request) override {
    std::scoped_lock lock(mutex_);

    if (initialization_error_) {
      return Result<AppSessionInfo>::Failure(initialization_error_);
    }

    AppSessionRecord session = ResolveAppSessionRecord(config_, request);
    if (!session.selected_profile.empty() && config_.profiles.find(session.selected_profile) == config_.profiles.end()) {
      return MakeFailure<AppSessionInfo>(ErrorCode::NotFound,
                                         "requested profile not found: " + session.selected_profile);
    }

    const std::uint64_t session_id = next_session_id_++;
    app_sessions_[session_id] = session;

    const StateSnapshot snapshot = state_machine_.snapshot();
    const RuntimeFlags granted_flags = ResolveGrantedFlags(config_.runtime_flags, session.requested_flags);

    AppSessionInfo info{};
    info.session_id = session_id;
    info.service_ready = true;
    info.tunnel_ready = snapshot.state == TunnelState::Connected && !session.selected_profile.empty() &&
                        snapshot.active_profile == session.selected_profile;
    info.dns_ready = info.tunnel_ready && session.prefer_tunnel_dns && HasFlag(granted_flags, RuntimeFlag::DnsThroughTunnel);
    info.transparent_mode_ready = info.tunnel_ready && HasFlag(granted_flags, RuntimeFlag::TransparentMode);
    info.active_profile = session.selected_profile;
    info.granted_flags = granted_flags;
    info.notes = BuildAppSessionNotes(session, snapshot, granted_flags);

    LogInfo("sysmodule", "opened app session " + std::to_string(session_id) + " for " +
                            (request.app.client_name.empty() ? std::string("unknown_app") : request.app.client_name));
    return MakeSuccess(std::move(info));
  }

  Error CloseAppSession(std::uint64_t session_id) override {
    std::scoped_lock lock(mutex_);

    const auto it = app_sessions_.find(session_id);
    if (it == app_sessions_.end()) {
      return MakeError(ErrorCode::NotFound, "app session not found: " + std::to_string(session_id));
    }

    RemoveTunnelDatagramsForSessionLocked(session_id);
    RemoveTunnelStreamsForSessionLocked(session_id);
    app_sessions_.erase(it);
    LogInfo("sysmodule", "closed app session " + std::to_string(session_id));
    return Error::None();
  }

  Result<NetworkPlan> GetNetworkPlan(const NetworkPlanRequest& request) const override {
    std::scoped_lock lock(mutex_);

    const auto session_it = app_sessions_.find(request.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<NetworkPlan>(ErrorCode::NotFound,
                                      "app session not found: " + std::to_string(request.session_id));
    }

    const AppSessionRecord& session = session_it->second;
    const StateSnapshot snapshot = state_machine_.snapshot();
    const RuntimeFlags granted_flags = ResolveGrantedFlags(config_.runtime_flags, session.requested_flags);
    NetworkPlan plan = BuildNetworkPlan(session, snapshot, granted_flags, request);
    return MakeSuccess(std::move(plan));
  }

  Result<DnsResolveResult> ResolveDns(const DnsResolveRequest& request) const override {
    if (request.hostname.empty()) {
      return MakeFailure<DnsResolveResult>(ErrorCode::ParseError, "hostname must not be empty");
    }

    AppSessionRecord session{};
    StateSnapshot snapshot{};
    RuntimeFlags granted_flags = 0;
    RuntimeFlags active_runtime_flags = 0;
    std::vector<std::string> dns_servers;
    ProfileConfig selected_profile{};
    bool have_selected_profile = false;
    {
      std::scoped_lock lock(mutex_);
      const auto session_it = app_sessions_.find(request.session_id);
      if (session_it == app_sessions_.end()) {
        return MakeFailure<DnsResolveResult>(ErrorCode::NotFound,
                                             "app session not found: " + std::to_string(request.session_id));
      }

      session = session_it->second;
      snapshot = state_machine_.snapshot();
      granted_flags = ResolveGrantedFlags(config_.runtime_flags, session.requested_flags);
      active_runtime_flags = config_.runtime_flags;

      const auto profile_it = config_.profiles.find(session.selected_profile);
      if (profile_it != config_.profiles.end()) {
        selected_profile = profile_it->second;
        have_selected_profile = true;
        dns_servers = profile_it->second.dns_servers;
      }
    }

    NetworkPlanRequest plan_request{};
    plan_request.session_id = request.session_id;
    plan_request.remote_host = request.hostname;
    plan_request.traffic_class = AppTrafficClass::Dns;
    plan_request.route_preference = RoutePreference::PreferTunnel;

    const NetworkPlan plan = BuildNetworkPlan(session, snapshot, granted_flags, plan_request);

    DnsResolveResult result{};
    result.action = plan.action;
    result.use_tunnel_dns = plan.use_tunnel_dns;
    result.profile_name = plan.profile_name;
    result.dns_servers = dns_servers;
    result.message = plan.reason;

    const bool local_dns_bypass = session.allow_local_network_bypass && LooksLocalHost(request.hostname);
    const bool wants_tunnel_dns = session.prefer_tunnel_dns && HasFlag(granted_flags, RuntimeFlag::DnsThroughTunnel);
    std::uint32_t fallback_count_increment = 0;
    const bool used_direct_fallback = plan.action == RouteAction::Direct && wants_tunnel_dns && !local_dns_bypass;
    if (plan.action == RouteAction::Direct) {
      const Result<std::vector<std::string>> resolved = ResolveIpv4HostAddrs(request.hostname);
      if (resolved.ok()) {
        result.resolved = true;
        result.addresses = resolved.value;
        result.message = plan.reason + "; resolved " + std::to_string(result.addresses.size()) + " IPv4 address(es)";
      } else {
        result.message = resolved.error.message;
      }
    } else if (plan.action == RouteAction::Tunnel) {
      if (!have_selected_profile) {
        return MakeFailure<DnsResolveResult>(ErrorCode::NotFound,
                                             "selected profile not found for app session DNS resolve");
      }

      const Result<PreparedTunnelSession> prepared_session =
          PrepareSelectedTunnelSession(session.selected_profile, selected_profile, active_runtime_flags);
      if (!prepared_session.ok()) {
        return MakeFailure<DnsResolveResult>(prepared_session.error.code, prepared_session.error.message);
      }

      const Result<TunnelDnsLookupResult> resolved =
          ResolveTunnelDns(request.session_id, prepared_session.value, request.hostname);
      if (!resolved.ok()) {
        return MakeFailure<DnsResolveResult>(resolved.error.code, resolved.error.message);
      }

      result.resolved = resolved.value.resolved;
      result.addresses = resolved.value.addresses;
      result.message = resolved.value.message;
      fallback_count_increment = resolved.value.fallback_count;
    }

    {
      std::scoped_lock lock(mutex_);
      TunnelStats stats = state_machine_.snapshot().stats;
      ++stats.dns_queries;
      if (used_direct_fallback) {
        ++stats.dns_fallbacks;
      }
      stats.dns_fallbacks += fallback_count_increment;
      if (plan.action == RouteAction::Deny) {
        ++stats.leak_prevention_events;
      }
      state_machine_.UpdateStats(stats);
    }

    return MakeSuccess(std::move(result));
  }

  Result<TunnelDatagramInfo> OpenTunnelDatagram(const TunnelDatagramOpenRequest& request) override {
    if (request.remote_host.empty()) {
      return MakeFailure<TunnelDatagramInfo>(ErrorCode::ParseError, "remote_host must not be empty");
    }
    if (request.remote_port == 0) {
      return MakeFailure<TunnelDatagramInfo>(ErrorCode::ParseError, "remote_port must not be zero");
    }

    AppSessionRecord session{};
    StateSnapshot snapshot{};
    RuntimeFlags granted_flags = 0;
    RuntimeFlags active_runtime_flags = 0;
    ProfileConfig selected_profile{};
    bool have_selected_profile = false;
    {
      std::scoped_lock lock(mutex_);
      const auto session_it = app_sessions_.find(request.session_id);
      if (session_it == app_sessions_.end()) {
        return MakeFailure<TunnelDatagramInfo>(ErrorCode::NotFound,
                                               "app session not found: " + std::to_string(request.session_id));
      }

      session = session_it->second;
      snapshot = state_machine_.snapshot();
      granted_flags = ResolveGrantedFlags(config_.runtime_flags, session.requested_flags);
      active_runtime_flags = config_.runtime_flags;

      const auto profile_it = config_.profiles.find(session.selected_profile);
      if (profile_it != config_.profiles.end()) {
        selected_profile = profile_it->second;
        have_selected_profile = true;
      }
    }

    NetworkPlanRequest plan_request{};
    plan_request.session_id = request.session_id;
    plan_request.remote_host = request.remote_host;
    plan_request.remote_port = request.remote_port;
    plan_request.transport = TransportProtocol::Udp;
    plan_request.traffic_class = request.traffic_class;
    plan_request.route_preference = request.route_preference;
    plan_request.local_network_hint = request.local_network_hint;

    const NetworkPlan plan = BuildNetworkPlan(session, snapshot, granted_flags, plan_request);
    if (plan.action != RouteAction::Tunnel) {
      return MakeFailure<TunnelDatagramInfo>(ErrorCode::Unsupported,
                                             "tunnel UDP datagram requires a tunnel route: " + plan.reason);
    }

    if (!have_selected_profile) {
      return MakeFailure<TunnelDatagramInfo>(ErrorCode::NotFound,
                                             "selected profile not found for tunnel datagram open");
    }

    const Result<PreparedTunnelSession> prepared_session =
        PrepareSelectedTunnelSession(session.selected_profile, selected_profile, active_runtime_flags);
    if (!prepared_session.ok()) {
      return MakeFailure<TunnelDatagramInfo>(prepared_session.error.code, prepared_session.error.message);
    }

    const Result<std::array<std::uint8_t, 4>> remote_ipv4 =
        ResolveTunnelRemoteIpv4(request.session_id, prepared_session.value, request.remote_host);
    if (!remote_ipv4.ok()) {
      return MakeFailure<TunnelDatagramInfo>(remote_ipv4.error.code, remote_ipv4.error.message);
    }

    TunnelDatagramInfo info{};
    {
      std::scoped_lock lock(mutex_);
      const auto session_it = app_sessions_.find(request.session_id);
      if (session_it == app_sessions_.end()) {
        return MakeFailure<TunnelDatagramInfo>(ErrorCode::NotFound,
                                               "app session not found during tunnel datagram open");
      }

      const StateSnapshot live_snapshot = state_machine_.snapshot();
      if (!SessionUsesActiveTunnelLocked(session_it->second, live_snapshot)) {
        return MakeFailure<TunnelDatagramInfo>(ErrorCode::InvalidState,
                                               "tunnel is not connected for tunnel datagram open");
      }

      TunnelDatagramHandleRecord record{};
      record.datagram_id = next_tunnel_datagram_id_++;
      record.session_id = request.session_id;
      record.traffic_class = request.traffic_class;
      record.selected_profile = session_it->second.selected_profile;
      record.remote_host = request.remote_host;
      record.remote_address = FormatIpv4Address(remote_ipv4.value);
      record.remote_port = request.remote_port;
      record.local_address = FormatIpv4Address(prepared_session.value.interface_ipv4_addresses.front().address);
      record.local_port = ReserveTunnelDatagramSourcePortLocked();
      record.remote_ipv4 = remote_ipv4.value;
      record.local_ipv4 = prepared_session.value.interface_ipv4_addresses.front().address;

      info.datagram_id = record.datagram_id;
      info.session_id = record.session_id;
      info.traffic_class = record.traffic_class;
      info.profile_name = record.selected_profile;
      info.remote_host = record.remote_host;
      info.remote_address = record.remote_address;
      info.remote_port = record.remote_port;
      info.local_address = record.local_address;
      info.local_port = record.local_port;
      info.message = plan.reason + "; forward UDP payloads through this tunnel datagram handle";

      tunnel_datagrams_[record.datagram_id] = record;
    }

    return MakeSuccess(std::move(info));
  }

  Error CloseTunnelDatagram(std::uint64_t datagram_id) override {
    std::scoped_lock lock(mutex_);

    const auto it = tunnel_datagrams_.find(datagram_id);
    if (it == tunnel_datagrams_.end()) {
      return MakeError(ErrorCode::NotFound, "tunnel datagram not found: " + std::to_string(datagram_id));
    }

    RememberAndPurgeClosedTunnelFlowLocked(it->second);
    tunnel_datagrams_.erase(it);
    return Error::None();
  }

  Result<std::uint64_t> SendTunnelDatagram(const TunnelDatagramSendRequest& request) override {
    std::scoped_lock lock(mutex_);

    if (request.payload.empty()) {
      return MakeFailure<std::uint64_t>(ErrorCode::ParseError, "tunnel datagram payload must not be empty");
    }

    const auto datagram_it = tunnel_datagrams_.find(request.datagram_id);
    if (datagram_it == tunnel_datagrams_.end()) {
      return MakeFailure<std::uint64_t>(ErrorCode::NotFound,
                                        "tunnel datagram not found: " + std::to_string(request.datagram_id));
    }

    const auto session_it = app_sessions_.find(datagram_it->second.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<std::uint64_t>(ErrorCode::NotFound,
                                        "app session not found for tunnel datagram send");
    }

    const StateSnapshot snapshot = state_machine_.snapshot();
    if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "tunnel is not connected for tunnel datagram send");
    }

    Ipv4UdpPacketEndpoint endpoint{};
    endpoint.source_ipv4 = datagram_it->second.local_ipv4;
    endpoint.destination_ipv4 = datagram_it->second.remote_ipv4;
    endpoint.source_port = datagram_it->second.local_port;
    endpoint.destination_port = datagram_it->second.remote_port;

    const Result<std::vector<std::uint8_t>> packet = BuildIpv4UdpPacket(endpoint, request.payload);
    if (!packet.ok()) {
      return MakeFailure<std::uint64_t>(packet.error.code, packet.error.message);
    }

    return tunnel_engine_->SendPacket(packet.value);
  }

  Result<TunnelDatagram> RecvTunnelDatagram(std::uint64_t datagram_id) override {
    std::scoped_lock lock(mutex_);

    const auto datagram_it = tunnel_datagrams_.find(datagram_id);
    if (datagram_it == tunnel_datagrams_.end()) {
      return MakeFailure<TunnelDatagram>(ErrorCode::NotFound,
                                         "tunnel datagram not found: " + std::to_string(datagram_id));
    }

    const auto session_it = app_sessions_.find(datagram_it->second.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<TunnelDatagram>(ErrorCode::NotFound,
                                         "app session not found for tunnel datagram receive");
    }

    const StateSnapshot snapshot = state_machine_.snapshot();
    if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
      return MakeFailure<TunnelDatagram>(ErrorCode::InvalidState,
                                         "tunnel is not connected for tunnel datagram receive");
    }

    return PopTunnelDatagramLocked(datagram_it->second);
  }

  Result<TunnelStreamInfo> OpenTunnelStream(const TunnelStreamOpenRequest& request) override {
    if (request.remote_host.empty()) {
      return MakeFailure<TunnelStreamInfo>(ErrorCode::ParseError, "remote_host must not be empty");
    }
    if (request.remote_port == 0) {
      return MakeFailure<TunnelStreamInfo>(ErrorCode::ParseError, "remote_port must not be zero");
    }

    AppSessionRecord session{};
    StateSnapshot snapshot{};
    RuntimeFlags granted_flags = 0;
    RuntimeFlags active_runtime_flags = 0;
    ProfileConfig selected_profile{};
    bool have_selected_profile = false;
    {
      std::scoped_lock lock(mutex_);
      const auto session_it = app_sessions_.find(request.session_id);
      if (session_it == app_sessions_.end()) {
        return MakeFailure<TunnelStreamInfo>(ErrorCode::NotFound,
                                             "app session not found: " + std::to_string(request.session_id));
      }

      session = session_it->second;
      snapshot = state_machine_.snapshot();
      granted_flags = ResolveGrantedFlags(config_.runtime_flags, session.requested_flags);
      active_runtime_flags = config_.runtime_flags;

      const auto profile_it = config_.profiles.find(session.selected_profile);
      if (profile_it != config_.profiles.end()) {
        selected_profile = profile_it->second;
        have_selected_profile = true;
      }
    }

    NetworkPlanRequest plan_request{};
    plan_request.session_id = request.session_id;
    plan_request.remote_host = request.remote_host;
    plan_request.remote_port = request.remote_port;
    plan_request.transport = request.transport;
    plan_request.traffic_class = request.traffic_class;
    plan_request.route_preference = request.route_preference;
    plan_request.local_network_hint = request.local_network_hint;

    const NetworkPlan plan = BuildNetworkPlan(session, snapshot, granted_flags, plan_request);
    if (plan.action != RouteAction::Tunnel) {
      return MakeFailure<TunnelStreamInfo>(ErrorCode::Unsupported,
                                           "tunnel stream requires a tunnel route: " + plan.reason);
    }

    if (!have_selected_profile) {
      return MakeFailure<TunnelStreamInfo>(ErrorCode::NotFound,
                                           "selected profile not found for tunnel stream open");
    }

    const Result<PreparedTunnelSession> prepared_session =
        PrepareSelectedTunnelSession(session.selected_profile, selected_profile, active_runtime_flags);
    if (!prepared_session.ok()) {
      return MakeFailure<TunnelStreamInfo>(prepared_session.error.code, prepared_session.error.message);
    }

    const Result<std::array<std::uint8_t, 4>> remote_ipv4 =
        ResolveTunnelRemoteIpv4(request.session_id, prepared_session.value, request.remote_host);
    if (!remote_ipv4.ok()) {
      return MakeFailure<TunnelStreamInfo>(remote_ipv4.error.code, remote_ipv4.error.message);
    }

    TunnelStreamHandleRecord stream{};
    {
      std::scoped_lock lock(mutex_);
      const auto session_it = app_sessions_.find(request.session_id);
      if (session_it == app_sessions_.end()) {
        return MakeFailure<TunnelStreamInfo>(ErrorCode::NotFound,
                                             "app session not found during tunnel stream open");
      }

      const StateSnapshot live_snapshot = state_machine_.snapshot();
      if (!SessionUsesActiveTunnelLocked(session_it->second, live_snapshot)) {
        return MakeFailure<TunnelStreamInfo>(ErrorCode::InvalidState,
                                             "tunnel is not connected for tunnel stream open");
      }

      stream.stream_id = next_tunnel_stream_id_++;
      stream.session_id = request.session_id;
      stream.transport = request.transport;
      stream.traffic_class = request.traffic_class;
      stream.selected_profile = session_it->second.selected_profile;
      stream.remote_host = request.remote_host;
      stream.remote_address = FormatIpv4Address(remote_ipv4.value);
      stream.remote_port = request.remote_port;
      stream.local_address = FormatIpv4Address(prepared_session.value.interface_ipv4_addresses.front().address);
      stream.local_port = ReserveTunnelStreamSourcePortLocked();
      stream.remote_ipv4 = remote_ipv4.value;
      stream.local_ipv4 = prepared_session.value.interface_ipv4_addresses.front().address;
      stream.next_send_sequence = ReserveTunnelStreamInitialSequenceLocked();
      stream.next_expected_remote_sequence = 0;
    }

    const std::uint32_t initial_send_sequence = stream.next_send_sequence;
    bool connected = false;
    std::string connect_timeout_message;
    for (int connect_attempt = 0; connect_attempt < 2 && !connected; ++connect_attempt) {
      if (connect_attempt > 0) {
        const Error recovery_error = RecoverTransportForTunnelStreamOpen(request.session_id, connect_timeout_message);
        if (recovery_error) {
          return MakeFailure<TunnelStreamInfo>(recovery_error.code, recovery_error.message);
        }
      }

      stream.next_send_sequence = initial_send_sequence;
      stream.next_expected_remote_sequence = 0;
      stream.peer_closed = false;
      stream.buffered_remote_segments.clear();

      const Result<std::uint64_t> syn_counter = SendTunnelStreamPacket(stream, ToFlags(TcpControlFlag::Syn), {});
      if (!syn_counter.ok()) {
        return MakeFailure<TunnelStreamInfo>(syn_counter.error.code, syn_counter.error.message);
      }

      const auto connect_deadline = std::chrono::steady_clock::now() + kTunnelStreamConnectTimeout;
      auto next_syn_retransmit = std::chrono::steady_clock::now() + kTunnelStreamConnectSynRetransmitInterval;
      while (std::chrono::steady_clock::now() < connect_deadline) {
        Result<TunnelPacket> packet = MakeFailure<TunnelPacket>(ErrorCode::NotFound, "no packet available");
        {
          std::scoped_lock lock(mutex_);
          const auto session_it = app_sessions_.find(request.session_id);
          if (session_it == app_sessions_.end()) {
            return MakeFailure<TunnelStreamInfo>(ErrorCode::NotFound,
                                                 "app session not found during tunnel stream connect");
          }

          const StateSnapshot live_snapshot = state_machine_.snapshot();
          if (!SessionUsesActiveTunnelLocked(session_it->second, live_snapshot)) {
            return MakeFailure<TunnelStreamInfo>(ErrorCode::InvalidState,
                                                 "tunnel disconnected while opening tunnel stream");
          }

          packet = TakeDeferredPacketMatchingLocked([&](const TunnelPacket& deferred_packet) {
            Ipv4TcpPacket segment{};
            return TryMatchTunnelStreamPacket(stream, deferred_packet, &segment) &&
                   HasFlag(segment.flags, TcpControlFlag::Syn) &&
                   HasFlag(segment.flags, TcpControlFlag::Ack) &&
                   segment.acknowledgment_number == stream.next_send_sequence + 1u;
          });
          if (!packet.ok() && packet.error.code == ErrorCode::NotFound) {
            packet = PopEnginePacketLocked();
          }
        }

        if (!packet.ok()) {
          if (packet.error.code != ErrorCode::NotFound) {
            return MakeFailure<TunnelStreamInfo>(packet.error.code, packet.error.message);
          }

          const auto now = std::chrono::steady_clock::now();
          if (now >= next_syn_retransmit) {
            const Result<std::uint64_t> retransmitted_syn_counter =
                SendTunnelStreamPacket(stream, ToFlags(TcpControlFlag::Syn), {});
            if (!retransmitted_syn_counter.ok()) {
              return MakeFailure<TunnelStreamInfo>(retransmitted_syn_counter.error.code,
                                                   retransmitted_syn_counter.error.message);
            }
            next_syn_retransmit = now + kTunnelStreamConnectSynRetransmitInterval;
          }

          const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
              connect_deadline - std::chrono::steady_clock::now());
          if (remaining > std::chrono::milliseconds::zero()) {
            std::this_thread::sleep_for(std::min(kTunnelStreamConnectPollInterval, remaining));
          }
          continue;
        }

        Ipv4TcpPacket segment{};
        if (!TryMatchTunnelStreamPacket(stream, packet.value, &segment) ||
            !HasFlag(segment.flags, TcpControlFlag::Syn) ||
            !HasFlag(segment.flags, TcpControlFlag::Ack) ||
            segment.acknowledgment_number != stream.next_send_sequence + 1u) {
          std::scoped_lock lock(mutex_);
          DeferPacketLocked(std::move(packet.value));
          continue;
        }

        stream.next_send_sequence += 1u;
        stream.next_expected_remote_sequence = segment.sequence_number + 1u;
        connected = true;
        break;
      }

      if (!connected) {
        connect_timeout_message = "timed out waiting for tunnel stream SYN-ACK from " + stream.remote_host + ":" +
                                  std::to_string(stream.remote_port) + " after " +
                                  std::to_string(kTunnelStreamConnectTimeout.count()) + " ms";
      }
    }

    if (!connected) {
      return MakeFailure<TunnelStreamInfo>(ErrorCode::ServiceUnavailable, connect_timeout_message);
    }

    const Result<std::uint64_t> ack_counter = SendTunnelStreamPacket(stream, ToFlags(TcpControlFlag::Ack), {});
    if (!ack_counter.ok()) {
      return MakeFailure<TunnelStreamInfo>(ack_counter.error.code, ack_counter.error.message);
    }

    TunnelStreamInfo info{};
    {
      std::scoped_lock lock(mutex_);
      tunnel_streams_[stream.stream_id] = stream;

      info.stream_id = stream.stream_id;
      info.session_id = stream.session_id;
      info.transport = stream.transport;
      info.traffic_class = stream.traffic_class;
      info.profile_name = stream.selected_profile;
      info.remote_host = stream.remote_host;
      info.remote_address = stream.remote_address;
      info.remote_port = stream.remote_port;
      info.local_address = stream.local_address;
      info.local_port = stream.local_port;
      info.message = plan.reason + "; tunnel TCP stream handshake completed";
    }

    return MakeSuccess(std::move(info));
  }

  Error CloseTunnelStream(std::uint64_t stream_id) override {
    std::scoped_lock lock(mutex_);

    const auto it = tunnel_streams_.find(stream_id);
    if (it == tunnel_streams_.end()) {
      return MakeError(ErrorCode::NotFound, "tunnel stream not found: " + std::to_string(stream_id));
    }

    if (tunnel_engine_->IsRunning()) {
      static_cast<void>(SendTunnelStreamPacket(it->second, ToFlags(TcpControlFlag::Fin) | ToFlags(TcpControlFlag::Ack), {}));
    }

    RememberAndPurgeClosedTunnelFlowLocked(it->second);
    tunnel_streams_.erase(it);
    return Error::None();
  }

  Result<std::uint64_t> SendTunnelStream(const TunnelStreamSendRequest& request) override {
    std::scoped_lock lock(mutex_);

    if (request.payload.empty()) {
      return MakeFailure<std::uint64_t>(ErrorCode::ParseError, "tunnel stream payload must not be empty");
    }

    auto stream_it = tunnel_streams_.find(request.stream_id);
    if (stream_it == tunnel_streams_.end()) {
      return MakeFailure<std::uint64_t>(ErrorCode::NotFound,
                                        "tunnel stream not found: " + std::to_string(request.stream_id));
    }

    const auto session_it = app_sessions_.find(stream_it->second.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<std::uint64_t>(ErrorCode::NotFound,
                                        "app session not found for tunnel stream send");
    }

    const StateSnapshot snapshot = state_machine_.snapshot();
    if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "tunnel is not connected for tunnel stream send");
    }
    if (stream_it->second.peer_closed) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "tunnel stream peer has already closed the connection");
    }

    const Result<std::uint64_t> counter =
        SendTunnelStreamPacket(stream_it->second, ToFlags(TcpControlFlag::Ack) | ToFlags(TcpControlFlag::Psh), request.payload);
    if (!counter.ok()) {
      return MakeFailure<std::uint64_t>(counter.error.code, counter.error.message);
    }

    stream_it->second.next_send_sequence += static_cast<std::uint32_t>(request.payload.size());
    return counter;
  }

  Result<TunnelStreamReadResult> RecvTunnelStream(std::uint64_t stream_id) override {
    std::scoped_lock lock(mutex_);

    auto stream_it = tunnel_streams_.find(stream_id);
    if (stream_it == tunnel_streams_.end()) {
      return MakeFailure<TunnelStreamReadResult>(ErrorCode::NotFound,
                                                 "tunnel stream not found: " + std::to_string(stream_id));
    }

    const auto session_it = app_sessions_.find(stream_it->second.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<TunnelStreamReadResult>(ErrorCode::NotFound,
                                                 "app session not found for tunnel stream receive");
    }

    const StateSnapshot snapshot = state_machine_.snapshot();
    if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
      return MakeFailure<TunnelStreamReadResult>(ErrorCode::InvalidState,
                                                 "tunnel is not connected for tunnel stream receive");
    }

    return PopTunnelStreamReadLocked(&stream_it->second);
  }

  Result<std::uint64_t> SendPacket(const TunnelSendRequest& request) override {
    std::scoped_lock lock(mutex_);

    if (request.payload.empty()) {
      return MakeFailure<std::uint64_t>(ErrorCode::ParseError,
                                        "authenticated transport payload must not be empty");
    }

    const auto session_it = app_sessions_.find(request.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<std::uint64_t>(ErrorCode::NotFound,
                                        "app session not found: " + std::to_string(request.session_id));
    }

    const AppSessionRecord& session = session_it->second;
    const StateSnapshot snapshot = state_machine_.snapshot();
    if (snapshot.state != TunnelState::Connected || !tunnel_engine_->IsRunning()) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "tunnel is not connected for packet send");
    }

    if (session.selected_profile.empty() || snapshot.active_profile != session.selected_profile) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "app session profile is not active on the connected tunnel");
    }

    return tunnel_engine_->SendPacket(request.payload);
  }

  Result<TunnelPacket> RecvPacket(std::uint64_t session_id) override {
    std::scoped_lock lock(mutex_);

    const auto session_it = app_sessions_.find(session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<TunnelPacket>(ErrorCode::NotFound,
                                       "app session not found: " + std::to_string(session_id));
    }

    const AppSessionRecord& session = session_it->second;
    const StateSnapshot snapshot = state_machine_.snapshot();
    if (snapshot.state != TunnelState::Connected || !tunnel_engine_->IsRunning()) {
      return MakeFailure<TunnelPacket>(ErrorCode::InvalidState,
                                       "tunnel is not connected for packet receive");
    }

    if (session.selected_profile.empty() || snapshot.active_profile != session.selected_profile) {
      return MakeFailure<TunnelPacket>(ErrorCode::InvalidState,
                                       "app session profile is not active on the connected tunnel");
    }

    return PopQueuedOrEnginePacketLocked();
  }

 private:
  bool SessionUsesActiveTunnelLocked(const AppSessionRecord& session, const StateSnapshot& snapshot) const {
    return snapshot.state == TunnelState::Connected && tunnel_engine_->IsRunning() &&
           !session.selected_profile.empty() && snapshot.active_profile == session.selected_profile;
  }

  Result<TunnelPacket> PopQueuedOrEnginePacketLocked() const {
    if (!deferred_packets_.empty()) {
      TunnelPacket packet = std::move(deferred_packets_.front());
      deferred_packets_.pop_front();
      return MakeSuccess(std::move(packet));
    }

    return PopEnginePacketLocked();
  }

  template <typename Matcher>
  Result<TunnelPacket> TakeDeferredPacketMatchingLocked(Matcher&& matcher) const {
    std::deque<TunnelPacket> unmatched_deferred;
    while (!deferred_packets_.empty()) {
      TunnelPacket packet = std::move(deferred_packets_.front());
      deferred_packets_.pop_front();

      if (matcher(packet)) {
        for (TunnelPacket& deferred : unmatched_deferred) {
          deferred_packets_.push_back(std::move(deferred));
        }
        return MakeSuccess(std::move(packet));
      }

      unmatched_deferred.push_back(std::move(packet));
    }

    for (TunnelPacket& deferred : unmatched_deferred) {
      deferred_packets_.push_back(std::move(deferred));
    }

    return MakeFailure<TunnelPacket>(ErrorCode::NotFound, "no matching deferred packet available");
  }

  Result<TunnelPacket> PopEnginePacketLocked() const {
    const Result<WireGuardConsumedTransportPacket> packet = tunnel_engine_->ReceivePacket();
    if (!packet.ok()) {
      return MakeFailure<TunnelPacket>(packet.error.code, packet.error.message);
    }

    TunnelPacket received{};
    received.counter = packet.value.counter;
    received.payload = packet.value.payload;
    return MakeSuccess(std::move(received));
  }

  void RememberClosedTunnelFlowLocked(const ClosedTunnelFlowRecord& flow) const {
    closed_tunnel_flows_.push_back(flow);
    while (closed_tunnel_flows_.size() > kClosedTunnelFlowRecordLimit) {
      closed_tunnel_flows_.pop_front();
    }
  }

  bool ShouldDropClosedTunnelFlowPacketLocked(const TunnelPacket& packet) const {
    if (closed_tunnel_flows_.empty()) {
      return false;
    }

    const Result<Ipv4TcpPacket> tcp_packet = ParseIpv4TcpPacket(packet.payload);
    if (tcp_packet.ok()) {
      for (const ClosedTunnelFlowRecord& flow : closed_tunnel_flows_) {
        if (MatchesClosedTunnelFlow(flow, tcp_packet.value)) {
          return true;
        }
      }
      return false;
    }

    const Result<Ipv4UdpPacket> udp_packet = ParseIpv4UdpPacket(packet.payload);
    if (udp_packet.ok()) {
      for (const ClosedTunnelFlowRecord& flow : closed_tunnel_flows_) {
        if (MatchesClosedTunnelFlow(flow, udp_packet.value)) {
          return true;
        }
      }
    }

    return false;
  }

  void PurgeDeferredPacketsForClosedTunnelFlowLocked(const ClosedTunnelFlowRecord& flow) const {
    std::deque<TunnelPacket> surviving_packets;
    while (!deferred_packets_.empty()) {
      TunnelPacket packet = std::move(deferred_packets_.front());
      deferred_packets_.pop_front();
      bool drop_packet = false;

      const Result<Ipv4TcpPacket> tcp_packet = ParseIpv4TcpPacket(packet.payload);
      if (tcp_packet.ok()) {
        drop_packet = MatchesClosedTunnelFlow(flow, tcp_packet.value);
      } else {
        const Result<Ipv4UdpPacket> udp_packet = ParseIpv4UdpPacket(packet.payload);
        if (udp_packet.ok()) {
          drop_packet = MatchesClosedTunnelFlow(flow, udp_packet.value);
        }
      }

      if (!drop_packet) {
        surviving_packets.push_back(std::move(packet));
      }
    }

    deferred_packets_ = std::move(surviving_packets);
  }

  template <typename FlowRecord>
  void RememberAndPurgeClosedTunnelFlowLocked(const FlowRecord& flow_record) const {
    const ClosedTunnelFlowRecord flow = MakeClosedTunnelFlowRecord(flow_record);
    RememberClosedTunnelFlowLocked(flow);
    PurgeDeferredPacketsForClosedTunnelFlowLocked(flow);
  }

  void InvalidateAllTunnelFlowsLocked() const {
    for (const auto& [unused_id, datagram] : tunnel_datagrams_) {
      static_cast<void>(unused_id);
      RememberClosedTunnelFlowLocked(MakeClosedTunnelFlowRecord(datagram));
    }

    for (const auto& [unused_id, stream] : tunnel_streams_) {
      static_cast<void>(unused_id);
      RememberClosedTunnelFlowLocked(MakeClosedTunnelFlowRecord(stream));
    }

    tunnel_datagrams_.clear();
    tunnel_streams_.clear();
    deferred_packets_.clear();
  }

  void DeferPacketLocked(TunnelPacket packet) const {
    if (ShouldDropClosedTunnelFlowPacketLocked(packet)) {
      return;
    }

    deferred_packets_.push_back(std::move(packet));
  }

  Error RecoverTransportForTunnelStreamOpen(std::uint64_t session_id,
                                            std::string_view timeout_message) const {
    LogWarning("sysmodule", "tunnel stream open timed out; attempting bounded transport recovery: " +
                               std::string(timeout_message));

    const Error recovery_error = tunnel_engine_->RecoverTransport(timeout_message);
    if (recovery_error) {
      LogError("sysmodule", "tunnel stream transport recovery failed: " + recovery_error.message);
      return recovery_error;
    }

    std::scoped_lock lock(mutex_);
    const auto session_it = app_sessions_.find(session_id);
    if (session_it == app_sessions_.end()) {
      return MakeError(ErrorCode::NotFound,
                       "app session not found after tunnel stream transport recovery");
    }

    const StateSnapshot snapshot = state_machine_.snapshot();
    if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
      return MakeError(ErrorCode::InvalidState,
                       "tunnel is not connected after tunnel stream transport recovery");
    }

    InvalidateAllTunnelFlowsLocked();
    LogInfo("sysmodule", "tunnel stream transport recovery succeeded; retrying stream open");
    return Error::None();
  }

  std::uint16_t ReserveDnsQueryIdLocked() const {
    if (next_dns_query_id_ == 0) {
      next_dns_query_id_ = 1;
    }

    return next_dns_query_id_++;
  }

  std::uint16_t ReserveTunnelDatagramSourcePortLocked() const {
    if (next_tunnel_datagram_source_port_ < kTunnelDatagramSourcePortBase ||
        next_tunnel_datagram_source_port_ >= kTunnelDatagramSourcePortBase + kTunnelDatagramSourcePortSpan) {
      next_tunnel_datagram_source_port_ = kTunnelDatagramSourcePortBase;
    }

    return next_tunnel_datagram_source_port_++;
  }

  std::uint16_t ReserveTunnelStreamSourcePortLocked() const {
    if (next_tunnel_stream_source_port_ < kTunnelStreamSourcePortBase ||
        next_tunnel_stream_source_port_ >= kTunnelStreamSourcePortBase + kTunnelStreamSourcePortSpan) {
      next_tunnel_stream_source_port_ = kTunnelStreamSourcePortBase;
    }

    return next_tunnel_stream_source_port_++;
  }

  std::uint32_t ReserveTunnelStreamInitialSequenceLocked() const {
    if (next_tunnel_stream_initial_sequence_ < kTunnelStreamInitialSequenceBase) {
      next_tunnel_stream_initial_sequence_ = kTunnelStreamInitialSequenceBase;
    }

    const std::uint32_t sequence = next_tunnel_stream_initial_sequence_;
    next_tunnel_stream_initial_sequence_ += 0x1000u;
    return sequence;
  }

  void RemoveTunnelDatagramsForSessionLocked(std::uint64_t session_id) {
    for (auto it = tunnel_datagrams_.begin(); it != tunnel_datagrams_.end();) {
      if (it->second.session_id == session_id) {
        RememberAndPurgeClosedTunnelFlowLocked(it->second);
        it = tunnel_datagrams_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void RemoveTunnelStreamsForSessionLocked(std::uint64_t session_id) {
    for (auto it = tunnel_streams_.begin(); it != tunnel_streams_.end();) {
      if (it->second.session_id == session_id) {
        RememberAndPurgeClosedTunnelFlowLocked(it->second);
        it = tunnel_streams_.erase(it);
      } else {
        ++it;
      }
    }
  }

  Result<PreparedTunnelSession> PrepareSelectedTunnelSession(std::string_view profile_name,
                                                             const ProfileConfig& selected_profile,
                                                             RuntimeFlags active_runtime_flags) const {
    const Result<ValidatedWireGuardProfile> validated = ValidateWireGuardProfileForConnect(selected_profile);
    if (!validated.ok()) {
      return MakeFailure<PreparedTunnelSession>(validated.error.code, validated.error.message);
    }

    return PrepareTunnelSession(profile_name, validated.value, active_runtime_flags);
  }

  Result<std::array<std::uint8_t, 4>> ResolveTunnelRemoteIpv4(std::uint64_t session_id,
                                                              const PreparedTunnelSession& prepared_session,
                                                              std::string_view remote_host) const {
    const Result<ParsedIpAddress> parsed_remote = ParseIpAddress(remote_host, "remote_host");
    if (parsed_remote.ok()) {
      if (parsed_remote.value.family != ParsedIpFamily::IPv4) {
        return MakeFailure<std::array<std::uint8_t, 4>>(ErrorCode::Unsupported,
                                                        "tunnel datagram currently supports only IPv4 remote hosts");
      }

      std::array<std::uint8_t, 4> remote_ipv4{};
      std::copy_n(parsed_remote.value.bytes.begin(), 4, remote_ipv4.begin());
      return MakeSuccess(std::move(remote_ipv4));
    }

    const Result<TunnelDnsLookupResult> resolved = ResolveTunnelDns(session_id, prepared_session, remote_host);
    if (!resolved.ok()) {
      return MakeFailure<std::array<std::uint8_t, 4>>(resolved.error.code, resolved.error.message);
    }
    if (!resolved.value.resolved || resolved.value.addresses.empty()) {
      return MakeFailure<std::array<std::uint8_t, 4>>(
          ErrorCode::NotFound,
          resolved.value.message.empty() ? "hostname did not resolve to an IPv4 tunnel destination"
                                         : resolved.value.message);
    }

    const Result<ParsedIpAddress> resolved_address =
        ParseIpAddress(resolved.value.addresses.front(), "resolved_remote_host");
    if (!resolved_address.ok()) {
      return MakeFailure<std::array<std::uint8_t, 4>>(resolved_address.error.code, resolved_address.error.message);
    }
    if (resolved_address.value.family != ParsedIpFamily::IPv4) {
      return MakeFailure<std::array<std::uint8_t, 4>>(ErrorCode::Unsupported,
                                                      "tunnel datagram currently supports only IPv4 resolved hosts");
    }

    std::array<std::uint8_t, 4> remote_ipv4{};
    std::copy_n(resolved_address.value.bytes.begin(), 4, remote_ipv4.begin());
    return MakeSuccess(std::move(remote_ipv4));
  }

  Result<std::uint64_t> SendTunnelStreamPacket(const TunnelStreamHandleRecord& stream,
                                               TcpControlFlags flags,
                                               const std::vector<std::uint8_t>& payload) const {
    Ipv4TcpPacket packet{};
    packet.endpoint.source_ipv4 = stream.local_ipv4;
    packet.endpoint.destination_ipv4 = stream.remote_ipv4;
    packet.endpoint.source_port = stream.local_port;
    packet.endpoint.destination_port = stream.remote_port;
    packet.sequence_number = stream.next_send_sequence;
    packet.acknowledgment_number = HasFlag(flags, TcpControlFlag::Ack) ? stream.next_expected_remote_sequence : 0u;
    packet.flags = flags;
    packet.payload = payload;

    const Result<std::vector<std::uint8_t>> bytes = BuildIpv4TcpPacket(packet);
    if (!bytes.ok()) {
      return MakeFailure<std::uint64_t>(bytes.error.code, bytes.error.message);
    }

    return tunnel_engine_->SendPacket(bytes.value);
  }

  bool TryMatchTunnelStreamPacket(const TunnelStreamHandleRecord& stream,
                                  const TunnelPacket& packet,
                                  Ipv4TcpPacket* segment) const {
    const Result<Ipv4TcpPacket> parsed = ParseIpv4TcpPacket(packet.payload);
    if (!parsed.ok()) {
      return false;
    }

    if (parsed.value.endpoint.source_ipv4 != stream.remote_ipv4 ||
        parsed.value.endpoint.destination_ipv4 != stream.local_ipv4 ||
        parsed.value.endpoint.source_port != stream.remote_port ||
        parsed.value.endpoint.destination_port != stream.local_port) {
      return false;
    }

    *segment = parsed.value;
    return true;
  }

  bool TryMatchTunnelDatagramPacket(const TunnelDatagramHandleRecord& datagram,
                                    const TunnelPacket& packet,
                                    TunnelDatagram* matched) const {
    const Result<Ipv4UdpPacket> parsed = ParseIpv4UdpPacket(packet.payload);
    if (!parsed.ok()) {
      return false;
    }

    if (parsed.value.endpoint.source_ipv4 != datagram.remote_ipv4 ||
        parsed.value.endpoint.destination_ipv4 != datagram.local_ipv4 ||
        parsed.value.endpoint.source_port != datagram.remote_port ||
        parsed.value.endpoint.destination_port != datagram.local_port) {
      return false;
    }

    matched->datagram_id = datagram.datagram_id;
    matched->counter = packet.counter;
    matched->remote_address = FormatIpv4Address(parsed.value.endpoint.source_ipv4);
    matched->remote_port = parsed.value.endpoint.source_port;
    matched->payload = parsed.value.payload;
    return true;
  }

  Result<TunnelDatagram> PopTunnelDatagramLocked(const TunnelDatagramHandleRecord& datagram) const {
    std::deque<TunnelPacket> unmatched_deferred;
    while (!deferred_packets_.empty()) {
      TunnelPacket packet = std::move(deferred_packets_.front());
      deferred_packets_.pop_front();

      TunnelDatagram matched{};
      if (TryMatchTunnelDatagramPacket(datagram, packet, &matched)) {
        for (TunnelPacket& deferred : unmatched_deferred) {
          deferred_packets_.push_back(std::move(deferred));
        }
        return MakeSuccess(std::move(matched));
      }

      unmatched_deferred.push_back(std::move(packet));
    }

    for (TunnelPacket& deferred : unmatched_deferred) {
      deferred_packets_.push_back(std::move(deferred));
    }

    while (true) {
      const Result<TunnelPacket> packet = PopEnginePacketLocked();
      if (!packet.ok()) {
        return MakeFailure<TunnelDatagram>(packet.error.code, packet.error.message);
      }

      TunnelDatagram matched{};
      if (TryMatchTunnelDatagramPacket(datagram, packet.value, &matched)) {
        return MakeSuccess(std::move(matched));
      }

      DeferPacketLocked(packet.value);
    }
  }

  Result<TunnelStreamReadResult> PopTunnelStreamReadLocked(TunnelStreamHandleRecord* stream) const {
    std::deque<TunnelPacket> unmatched_deferred;
    while (!deferred_packets_.empty()) {
      TunnelPacket packet = std::move(deferred_packets_.front());
      deferred_packets_.pop_front();

      Ipv4TcpPacket segment{};
      if (TryMatchTunnelStreamPacket(*stream, packet, &segment)) {
        const Result<TunnelStreamReadResult> processed =
            ProcessTunnelStreamPacketLocked(stream, packet.counter, segment);
        for (TunnelPacket& deferred : unmatched_deferred) {
          deferred_packets_.push_back(std::move(deferred));
        }
        if (processed.ok()) {
          return processed;
        }
        if (processed.error.code != ErrorCode::NotFound) {
          return processed;
        }
        continue;
      }

      unmatched_deferred.push_back(std::move(packet));
    }

    for (TunnelPacket& deferred : unmatched_deferred) {
      deferred_packets_.push_back(std::move(deferred));
    }

    while (true) {
      const Result<TunnelPacket> packet = PopEnginePacketLocked();
      if (!packet.ok()) {
        return MakeFailure<TunnelStreamReadResult>(packet.error.code, packet.error.message);
      }

      Ipv4TcpPacket segment{};
      if (TryMatchTunnelStreamPacket(*stream, packet.value, &segment)) {
        const Result<TunnelStreamReadResult> processed =
            ProcessTunnelStreamPacketLocked(stream, packet.value.counter, segment);
        if (processed.ok()) {
          return processed;
        }
        if (processed.error.code != ErrorCode::NotFound) {
          return processed;
        }
        continue;
      }

      DeferPacketLocked(packet.value);
    }
  }

  Result<TunnelStreamReadResult> ProcessTunnelStreamPacketLocked(TunnelStreamHandleRecord* stream,
                                                                 std::uint64_t counter,
                                                                 const Ipv4TcpPacket& segment) const {
    auto send_ack = [&](std::uint32_t acknowledgment_number) -> Error {
      TunnelStreamHandleRecord ack_stream = *stream;
      ack_stream.next_expected_remote_sequence = acknowledgment_number;
      const Result<std::uint64_t> ack_counter = SendTunnelStreamPacket(ack_stream, ToFlags(TcpControlFlag::Ack), {});
      if (!ack_counter.ok()) {
        return MakeError(ack_counter.error.code, ack_counter.error.message);
      }
      return Error::None();
    };

    auto append_consumed_segment = [&](const Ipv4TcpPacket& consumed,
                                       TunnelStreamReadResult* read,
                                       bool* consumed_sequence) {
      if (HasFlag(consumed.flags, TcpControlFlag::Syn)) {
        stream->next_expected_remote_sequence += 1u;
      }
      if (!consumed.payload.empty()) {
        stream->next_expected_remote_sequence += static_cast<std::uint32_t>(consumed.payload.size());
        read->payload.insert(read->payload.end(), consumed.payload.begin(), consumed.payload.end());
      }
      if (HasFlag(consumed.flags, TcpControlFlag::Fin)) {
        stream->next_expected_remote_sequence += 1u;
        stream->peer_closed = true;
        read->peer_closed = true;
      }
      if (MeasureTunnelStreamSequenceAdvance(consumed) != 0) {
        *consumed_sequence = true;
      }
    };

    auto consume_buffered_segments = [&](TunnelStreamReadResult* read,
                                         bool* consumed_sequence) {
      while (!stream->buffered_remote_segments.empty()) {
        auto buffered_it = stream->buffered_remote_segments.begin();
        Ipv4TcpPacket buffered = buffered_it->second.packet;

        if (MeasureTunnelStreamEndSequence(buffered) <= stream->next_expected_remote_sequence) {
          stream->buffered_remote_segments.erase(buffered_it);
          continue;
        }

        if (buffered.sequence_number < stream->next_expected_remote_sequence) {
          TrimTunnelStreamSegmentPrefix(&buffered,
                                        stream->next_expected_remote_sequence - buffered.sequence_number);
        }

        if (MeasureTunnelStreamSequenceAdvance(buffered) == 0) {
          stream->buffered_remote_segments.erase(buffered_it);
          continue;
        }

        if (buffered.sequence_number != stream->next_expected_remote_sequence) {
          break;
        }

        stream->buffered_remote_segments.erase(buffered_it);
        append_consumed_segment(buffered, read, consumed_sequence);
      }
    };

    if (HasFlag(segment.flags, TcpControlFlag::Rst)) {
      stream->peer_closed = true;
      stream->buffered_remote_segments.clear();
      TunnelStreamReadResult reset{};
      reset.stream_id = stream->stream_id;
      reset.counter = counter;
      reset.peer_closed = true;
      return MakeSuccess(std::move(reset));
    }

    Ipv4TcpPacket working = segment;
    const bool has_sequence_advance = MeasureTunnelStreamSequenceAdvance(working) != 0;
    if (has_sequence_advance) {
      if (MeasureTunnelStreamEndSequence(working) <= stream->next_expected_remote_sequence) {
        const Error ack_error = send_ack(stream->next_expected_remote_sequence);
        if (ack_error) {
          return MakeFailure<TunnelStreamReadResult>(ack_error.code, ack_error.message);
        }
        return MakeFailure<TunnelStreamReadResult>(ErrorCode::NotFound,
                                                   "duplicate TCP stream segment already consumed");
      }

      if (working.sequence_number < stream->next_expected_remote_sequence) {
        TrimTunnelStreamSegmentPrefix(&working,
                                      stream->next_expected_remote_sequence - working.sequence_number);
      }

      if (MeasureTunnelStreamSequenceAdvance(working) == 0) {
        const Error ack_error = send_ack(stream->next_expected_remote_sequence);
        if (ack_error) {
          return MakeFailure<TunnelStreamReadResult>(ack_error.code, ack_error.message);
        }
        return MakeFailure<TunnelStreamReadResult>(ErrorCode::NotFound,
                                                   "duplicate TCP stream segment already consumed");
      }

      if (working.sequence_number > stream->next_expected_remote_sequence) {
        const auto existing = stream->buffered_remote_segments.find(working.sequence_number);
        if (existing == stream->buffered_remote_segments.end() &&
            stream->buffered_remote_segments.size() >= kTunnelStreamBufferedSegmentLimit) {
          return MakeFailure<TunnelStreamReadResult>(ErrorCode::Unsupported,
                                                     "too many out-of-order TCP segments are buffered");
        }

        auto& buffered = stream->buffered_remote_segments[working.sequence_number];
        if (buffered.counter == 0 ||
            MeasureTunnelStreamSequenceAdvance(buffered.packet) < MeasureTunnelStreamSequenceAdvance(working)) {
          buffered.counter = counter;
          buffered.packet = std::move(working);
        }

        const Error ack_error = send_ack(stream->next_expected_remote_sequence);
        if (ack_error) {
          return MakeFailure<TunnelStreamReadResult>(ack_error.code, ack_error.message);
        }
        return MakeFailure<TunnelStreamReadResult>(ErrorCode::NotFound,
                                                   "buffered out-of-order TCP stream segment");
      }
    }

    TunnelStreamReadResult read{};
    read.stream_id = stream->stream_id;
    read.counter = counter;
    bool consumed_sequence = false;

    if (has_sequence_advance) {
      append_consumed_segment(working, &read, &consumed_sequence);
      consume_buffered_segments(&read, &consumed_sequence);
    }

    if (consumed_sequence) {
      const Error ack_error = send_ack(stream->next_expected_remote_sequence);
      if (ack_error) {
        return MakeFailure<TunnelStreamReadResult>(ack_error.code, ack_error.message);
      }
    }

    if (read.payload.empty() && !read.peer_closed) {
      return MakeFailure<TunnelStreamReadResult>(ErrorCode::NotFound, "no stream payload available");
    }

    return MakeSuccess(std::move(read));
  }

  Result<TunnelDnsLookupResult> ResolveTunnelDns(std::uint64_t session_id,
                                                 const PreparedTunnelSession& prepared_session,
                                                 std::string_view hostname) const {
    if (prepared_session.interface_ipv4_addresses.empty()) {
      return MakeFailure<TunnelDnsLookupResult>(ErrorCode::InvalidConfig,
                                                "selected profile has no IPv4 interface address for tunnel DNS");
    }

    if (prepared_session.dns_servers.empty()) {
      TunnelDnsLookupResult lookup{};
      lookup.message = "tunnel DNS requested, but the selected profile has no configured DNS servers yet";
      return MakeSuccess(std::move(lookup));
    }

    TunnelDnsPacketEndpoint endpoint{};
    endpoint.source_ipv4 = prepared_session.interface_ipv4_addresses.front().address;
    endpoint.destination_port = kTunnelDnsDestinationPort;

    TunnelDnsLookupResult lookup{};
    for (std::size_t server_index = 0; server_index < prepared_session.dns_servers.size(); ++server_index) {
      endpoint.destination_ipv4 = prepared_session.dns_servers[server_index];

      std::uint16_t query_id = 0;
      {
        std::scoped_lock lock(mutex_);
        query_id = ReserveDnsQueryIdLocked();
      }
      endpoint.source_port = static_cast<std::uint16_t>(
          kTunnelDnsSourcePortBase + (query_id % kTunnelDnsSourcePortSpan));

      const Result<std::vector<std::uint8_t>> query_packet =
          BuildTunnelDnsQueryPacket(endpoint, hostname, query_id);
      if (!query_packet.ok()) {
        return MakeFailure<TunnelDnsLookupResult>(query_packet.error.code, query_packet.error.message);
      }

      {
        std::scoped_lock lock(mutex_);
        const auto session_it = app_sessions_.find(session_id);
        if (session_it == app_sessions_.end()) {
          return MakeFailure<TunnelDnsLookupResult>(ErrorCode::NotFound,
                                                    "app session not found during tunnel DNS lookup");
        }

        const StateSnapshot snapshot = state_machine_.snapshot();
        if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
          return MakeFailure<TunnelDnsLookupResult>(ErrorCode::InvalidState,
                                                    "tunnel is no longer connected for tunnel DNS lookup");
        }

        const Result<std::uint64_t> sent = tunnel_engine_->SendPacket(query_packet.value);
        if (!sent.ok()) {
          return MakeFailure<TunnelDnsLookupResult>(sent.error.code, sent.error.message);
        }
      }

      for (int attempt = 0; attempt < kTunnelDnsPollAttemptsPerServer; ++attempt) {
        Result<TunnelPacket> packet = MakeFailure<TunnelPacket>(ErrorCode::NotFound, "no packet available");
        {
          std::scoped_lock lock(mutex_);
          const auto session_it = app_sessions_.find(session_id);
          if (session_it == app_sessions_.end()) {
            return MakeFailure<TunnelDnsLookupResult>(ErrorCode::NotFound,
                                                      "app session not found during tunnel DNS receive");
          }

          const StateSnapshot snapshot = state_machine_.snapshot();
          if (!SessionUsesActiveTunnelLocked(session_it->second, snapshot)) {
            return MakeFailure<TunnelDnsLookupResult>(ErrorCode::InvalidState,
                                                      "tunnel disconnected while waiting for tunnel DNS response");
          }

          packet = TakeDeferredPacketMatchingLocked([&](const TunnelPacket& deferred_packet) {
            const Result<TunnelDnsResponse> response = ParseTunnelDnsResponsePacket(deferred_packet.payload);
            return response.ok() && response.value.query_id == query_id &&
                   response.value.source_port == endpoint.destination_port &&
                   response.value.destination_port == endpoint.source_port &&
                   response.value.source_ipv4 == endpoint.destination_ipv4 &&
                   response.value.destination_ipv4 == endpoint.source_ipv4;
          });
          if (!packet.ok() && packet.error.code == ErrorCode::NotFound) {
            packet = PopEnginePacketLocked();
          }
        }

        if (!packet.ok()) {
          if (packet.error.code != ErrorCode::NotFound) {
            return MakeFailure<TunnelDnsLookupResult>(packet.error.code, packet.error.message);
          }

          std::this_thread::sleep_for(kTunnelDnsPollInterval);
          continue;
        }

        const Result<TunnelDnsResponse> response = ParseTunnelDnsResponsePacket(packet.value.payload);
        if (!response.ok() || response.value.query_id != query_id ||
            response.value.source_port != endpoint.destination_port ||
            response.value.destination_port != endpoint.source_port ||
            response.value.source_ipv4 != endpoint.destination_ipv4 ||
            response.value.destination_ipv4 != endpoint.source_ipv4) {
          std::scoped_lock lock(mutex_);
          DeferPacketLocked(std::move(packet.value));
          continue;
        }

        if (response.value.rcode == 0 && !response.value.ipv4_addresses.empty()) {
          lookup.resolved = true;
          lookup.addresses = response.value.ipv4_addresses;
          lookup.message = "resolved " + std::to_string(lookup.addresses.size()) + " IPv4 address(es) through tunnel DNS server " +
                           FormatIpv4Address(endpoint.destination_ipv4);
          return MakeSuccess(std::move(lookup));
        }

        if (response.value.rcode == 3 || response.value.rcode == 0) {
          lookup.message = response.value.rcode == 3
                               ? "tunnel DNS server " + FormatIpv4Address(endpoint.destination_ipv4) +
                                     " reported name_error for '" + std::string(hostname) + "'"
                               : "tunnel DNS server " + FormatIpv4Address(endpoint.destination_ipv4) +
                                     " returned no IPv4 answers for '" + std::string(hostname) + "'";
          return MakeSuccess(std::move(lookup));
        }

        if (server_index + 1 < prepared_session.dns_servers.size()) {
          break;
        }

        lookup.message = "tunnel DNS server " + FormatIpv4Address(endpoint.destination_ipv4) +
                         " returned " + DescribeDnsResponseCode(response.value.rcode) +
                         " for '" + std::string(hostname) + "'";
        return MakeSuccess(std::move(lookup));
      }

      if (lookup.resolved) {
        return MakeSuccess(std::move(lookup));
      }
      if (!lookup.message.empty()) {
        return MakeSuccess(std::move(lookup));
      }
      if (server_index + 1 < prepared_session.dns_servers.size()) {
        ++lookup.fallback_count;
        continue;
      }
    }

    lookup.message = "tunnel DNS query for '" + std::string(hostname) + "' timed out against " +
                     std::to_string(prepared_session.dns_servers.size()) + " configured server(s)";
    return MakeSuccess(std::move(lookup));
  }

  Error Initialize() {
    const Error logger_error = Logger::Instance().Initialize(paths_.log_file);
    if (logger_error) {
      return logger_error;
    }

    LogInfo("sysmodule", "initializing control service");

    const Result<Config> loaded = LoadOrCreateConfigFile(paths_.config_file);
    if (!loaded.ok()) {
      LogError("sysmodule", "config load failed: " + loaded.error.message);
      return loaded.error;
    }

    config_ = loaded.value;
    NormalizeActiveProfile();

    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      LogError("sysmodule", "config save failed during init: " + save_error.message);
      return save_error;
    }

    ApplyConfigToState();
    LogInfo("sysmodule", "control service ready: " + DescribeConfig(config_));
    return Error::None();
  }

  void NormalizeActiveProfile() {
    if (config_.active_profile.empty() && config_.profiles.size() == 1) {
      config_.active_profile = config_.profiles.begin()->first;
    }
  }

  void ApplyConfigToState() {
    state_machine_.ApplyConfig(config_);
  }

  bool IsConfigMutationAllowed() const {
    const TunnelState state = state_machine_.snapshot().state;
    return state != TunnelState::Connecting && state != TunnelState::Connected &&
           state != TunnelState::Disconnecting;
  }

  RuntimePaths paths_{};
  mutable std::mutex mutex_;
  Config config_{};
  mutable ConnectionStateMachine state_machine_{};
  std::unique_ptr<IWgTunnelEngine> tunnel_engine_{};
  Error initialization_error_{};
  std::uint64_t next_session_id_ = 1;
  mutable std::uint64_t next_tunnel_datagram_id_ = 1;
  mutable std::uint64_t next_tunnel_stream_id_ = 1;
  mutable std::deque<TunnelPacket> deferred_packets_{};
  mutable std::deque<ClosedTunnelFlowRecord> closed_tunnel_flows_{};
  mutable std::uint16_t next_dns_query_id_ = 1;
  mutable std::uint16_t next_tunnel_datagram_source_port_ = kTunnelDatagramSourcePortBase;
  mutable std::uint16_t next_tunnel_stream_source_port_ = kTunnelStreamSourcePortBase;
  mutable std::uint32_t next_tunnel_stream_initial_sequence_ = kTunnelStreamInitialSequenceBase;
  mutable std::unordered_map<std::uint64_t, AppSessionRecord> app_sessions_{};
  mutable std::unordered_map<std::uint64_t, TunnelDatagramHandleRecord> tunnel_datagrams_{};
  mutable std::unordered_map<std::uint64_t, TunnelStreamHandleRecord> tunnel_streams_{};
};

}  // namespace

std::shared_ptr<IControlService> CreateLocalControlService(const std::filesystem::path& runtime_root) {
  return std::make_shared<LocalControlService>(runtime_root);
}

std::shared_ptr<IControlService> CreateLocalControlServiceForTest(std::unique_ptr<IWgTunnelEngine> tunnel_engine,
                                                                 const std::filesystem::path& runtime_root) {
  return std::make_shared<LocalControlService>(runtime_root, std::move(tunnel_engine));
}

}  // namespace swg::sysmodule
