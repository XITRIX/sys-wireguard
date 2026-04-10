#include <cstdio>
#include <string>
#include <vector>

#include <switch.h>

#include "swg/client.h"
#include "swg/ipc_protocol.h"

namespace {

constexpr int kAutoRefreshFrames = 30;

struct ScreenModel {
  swg::Result<swg::VersionInfo> version;
  swg::Result<swg::ServiceStatus> status;
  swg::Result<swg::TunnelStats> stats;
  swg::Result<std::vector<swg::ProfileSummary>> profiles;
  swg::Result<swg::CompatibilityInfo> compatibility;
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

void DrawScreen(const ScreenModel& model, const std::string& action_message) {
  consoleClear();

  std::printf("Switch WireGuard Manager\n");
  if (model.version.ok()) {
    std::printf("version: %s  abi: %u\n", model.version.value.semantic_version.c_str(), model.version.value.abi_version);
  } else {
    std::printf("version: unavailable (%s)\n", model.version.error.message.c_str());
  }

  std::printf("\n");
  if (model.status.ok()) {
    const auto& status = model.status.value;
    std::printf("service ready: %s\n", BoolLabel(status.service_ready));
    std::printf("state: %s\n", std::string(swg::ToString(status.state)).c_str());
    std::printf("active profile: %s\n", status.active_profile.empty() ? "<none>" : status.active_profile.c_str());
    std::printf("runtime flags: %s\n", swg::RuntimeFlagsToString(status.runtime_flags).c_str());
    std::printf("last error: %s\n", status.last_error.empty() ? "<none>" : status.last_error.c_str());
  } else {
    std::printf("status: unavailable (%s)\n", model.status.error.message.c_str());
  }

  std::printf("\n");
  if (model.stats.ok()) {
    const auto& stats = model.stats.value;
    std::printf("connect attempts: %u\n", stats.connect_attempts);
    std::printf("successful handshakes: %u\n", stats.successful_handshakes);
    std::printf("bytes in/out: %llu / %llu\n",
                static_cast<unsigned long long>(stats.bytes_in),
                static_cast<unsigned long long>(stats.bytes_out));
    std::printf("dns queries/fallbacks: %u / %u\n", stats.dns_queries, stats.dns_fallbacks);
  } else {
    std::printf("stats: unavailable (%s)\n", model.stats.error.message.c_str());
  }

  std::printf("\nprofiles:\n");
  if (model.profiles.ok()) {
    if (model.profiles.value.empty()) {
      std::printf("  <none>\n");
    }

    for (const auto& profile : model.profiles.value) {
      std::printf("  %c %s  autostart=%s complete=%s\n",
                  (model.status.ok() && profile.name == model.status.value.active_profile) ? '*' : ' ',
                  profile.name.c_str(),
                  BoolLabel(profile.autostart),
                  BoolLabel(profile.has_complete_key_material));
    }
  } else {
    std::printf("  unavailable (%s)\n", model.profiles.error.message.c_str());
  }

  std::printf("\ncompatibility:\n");
  if (model.compatibility.ok()) {
    const auto& compatibility = model.compatibility.value;
    std::printf("  switch target: %s  new tls abi: %s\n",
                BoolLabel(compatibility.switch_target),
                BoolLabel(compatibility.needs_new_tls_abi));
    std::printf("  bsd:a=%s dns:priv=%s ifcfg=%s bsd:nu=%s\n",
                BoolLabel(compatibility.has_bsd_a),
                BoolLabel(compatibility.has_dns_priv),
                BoolLabel(compatibility.has_ifcfg),
                BoolLabel(compatibility.has_bsd_nu));
  } else {
    std::printf("  unavailable (%s)\n", model.compatibility.error.message.c_str());
  }

  std::printf("\ncontrols:\n");
  std::printf("  A connect/disconnect   B refresh   + exit\n");
  std::printf("  Left/Right change active profile\n");
  std::printf("  X toggle dns-through-tunnel\n");
  std::printf("  Y toggle transparent-mode\n");
  std::printf("  R toggle kill-switch\n");
  std::printf("\nlast action: %s\n", action_message.c_str());
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
  std::string action_message = "waiting for swg:ctl";
  int frame_counter = 0;
  bool refresh_requested = true;

  while (appletMainLoop()) {
    padUpdate(&pad);
    const u64 buttons_down = padGetButtonsDown(&pad);

    if ((buttons_down & HidNpadButton_Plus) != 0) {
      break;
    }

    if ((buttons_down & HidNpadButton_B) != 0) {
      action_message = "manual refresh";
      refresh_requested = true;
    }

    if (refresh_requested || frame_counter % kAutoRefreshFrames == 0) {
      RefreshModel(client, &model);
      refresh_requested = false;
    }

    if ((buttons_down & HidNpadButton_A) != 0) {
      action_message = ToggleConnection(client, model);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_Left) != 0) {
      action_message = CycleProfile(client, model, -1);
      refresh_requested = true;
    }

    if ((buttons_down & HidNpadButton_Right) != 0) {
      action_message = CycleProfile(client, model, 1);
      refresh_requested = true;
    }

    if (model.status.ok()) {
      if ((buttons_down & HidNpadButton_X) != 0) {
        action_message = ApplyRuntimeFlags(client, ToggleFlag(model.status.value.runtime_flags,
                                                              swg::RuntimeFlag::DnsThroughTunnel));
        refresh_requested = true;
      }

      if ((buttons_down & HidNpadButton_Y) != 0) {
        action_message = ApplyRuntimeFlags(client, ToggleFlag(model.status.value.runtime_flags,
                                                              swg::RuntimeFlag::TransparentMode));
        refresh_requested = true;
      }

      if ((buttons_down & HidNpadButton_R) != 0) {
        action_message = ApplyRuntimeFlags(client, ToggleFlag(model.status.value.runtime_flags,
                                                              swg::RuntimeFlag::KillSwitch));
        refresh_requested = true;
      }
    }

    DrawScreen(model, action_message);
    consoleUpdate(nullptr);
    ++frame_counter;
  }

  consoleExit(nullptr);
  return 0;
}