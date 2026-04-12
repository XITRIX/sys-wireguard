#include <algorithm>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include <switch.h>

#include "swg/app_session.h"
#include "swg/client.h"
#include "swg/ipc_protocol.h"
#include "swg/moonlight.h"

namespace {

constexpr int kAutoRefreshFrames = 30;
constexpr std::size_t kMaxPreviewBytes = 8;

struct ScreenModel {
  swg::Result<swg::VersionInfo> version;
  swg::Result<swg::ServiceStatus> status;
  swg::Result<swg::TunnelStats> stats;
  swg::Result<std::vector<swg::ProfileSummary>> profiles;
  swg::Result<swg::CompatibilityInfo> compatibility;
};

struct IntegrationState {
  explicit IntegrationState(swg::Client client) : session(std::move(client)) {}

  swg::AppSession session;
  swg::AppTunnelRequest session_request{};
  std::string last_action = "waiting for swg:ctl";
  std::string last_send_result = "not run";
  std::string last_receive_result = "not run";
  std::string last_smoke_summary = "not run";
  std::vector<std::string> smoke_lines;
  std::uint8_t payload_nonce = 1;
};

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
    state->last_send_result = "not run";
    state->last_receive_result = "not run";
    state->last_smoke_summary = "not run";
    state->smoke_lines.clear();
    return "app session closed";
  }

  const std::string profile_name = CurrentProfileName(model);
  if (profile_name.empty()) {
    return "cannot open session without an active profile";
  }

  swg::AppTunnelRequest request = swg::MakeMoonlightSessionRequest(profile_name, true);
  request.app.client_name = "SWG Integration";
  request.app.integration_tag = "switch-integration";

  const auto opened = state->session.Open(request);
  if (!opened.ok()) {
    return "open session failed: " + opened.error.message;
  }

  state->session_request = request;
  return "app session opened: id=" + std::to_string(opened.value.session_id) +
         " profile=" + opened.value.active_profile;
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
      state->session.PlanNetwork(swg::MakeMoonlightDnsPlan("vpn.example.test")),
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
      state->session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984)),
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
      state->session.PlanNetwork(swg::MakeMoonlightVideoPlan("vpn.example.test", 47998)),
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

std::string SendDiagnosticPayload(IntegrationState* state) {
  if (!state->session.is_open()) {
    return "open app session before sending a diagnostic payload";
  }

  const std::vector<std::uint8_t> payload = {
      0x53, 0x57, 0x47, 0x49, 0x4e, 0x54, state->payload_nonce++,
  };
  const auto counter = state->session.SendPacket(payload);
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

  const auto packet = state->session.ReceivePacket();
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
  std::printf("smoke: %s\n", state.last_smoke_summary.c_str());
  for (const auto& line : state.smoke_lines) {
    std::printf("  %s\n", line.c_str());
  }

  std::printf("\ndiagnostic payload:\n");
  std::printf("  send=%s\n", state.last_send_result.c_str());
  std::printf("  recv=%s\n", state.last_receive_result.c_str());
  std::printf("  raw send/recv is diagnostic until socket helpers land\n");

  std::printf("\ncontrols:\n");
  std::printf("  A connect/disconnect   B refresh   + exit\n");
  std::printf("  X open/close session   Y run session smoke\n");
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
      state.last_action = RunSessionSmoke(model, &state);
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