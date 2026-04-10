#include <filesystem>
#include <iostream>
#include <string>

#include "swg/app_session.h"
#include "swg/client.h"
#include "swg/config.h"
#include "swg/moonlight.h"
#include "swg/state_machine.h"
#include "swg_sysmodule/local_service.h"

namespace {

bool Require(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "test failure: " << message << '\n';
    return false;
  }
  return true;
}

swg::Config MakeValidConfig() {
  swg::Config config = swg::DefaultConfig();
  swg::ProfileConfig profile{};
  profile.name = "default";
  profile.private_key = "private";
  profile.public_key = "public";
  profile.endpoint_host = "peer.example.test";
  profile.endpoint_port = 51820;
  profile.allowed_ips = {"0.0.0.0/0", "::/0"};
  profile.addresses = {"10.0.0.2/32"};
  profile.dns_servers = {"1.1.1.1", "1.0.0.1"};
  profile.autostart = false;
  config.profiles.emplace(profile.name, profile);
  config.active_profile = profile.name;
  config.runtime_flags = swg::ToFlags(swg::RuntimeFlag::DnsThroughTunnel);
  return config;
}

bool TestConfigRoundTrip() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const swg::RuntimePaths paths = swg::DetectRuntimePaths(runtime_root);
  const swg::Config expected = MakeValidConfig();
  const swg::Error save_error = swg::SaveConfigFile(expected, paths.config_file);
  if (!Require(save_error.ok(), "config save must succeed")) {
    return false;
  }

  const swg::Result<swg::Config> loaded = swg::LoadConfigFile(paths.config_file);
  if (!Require(loaded.ok(), "config load must succeed")) {
    return false;
  }

  bool ok = true;
  ok &= Require(loaded.value.active_profile == expected.active_profile, "active profile must round-trip");
  ok &= Require(loaded.value.profiles.size() == 1, "exactly one profile must round-trip");
  ok &= Require(loaded.value.runtime_flags == expected.runtime_flags, "runtime flags must round-trip");
  ok &= Require(loaded.value.profiles.at("default").endpoint_host == expected.profiles.at("default").endpoint_host,
                "endpoint_host must round-trip");
  return ok;
}

bool TestStateMachine() {
  swg::ConnectionStateMachine machine;
  const swg::Config config = MakeValidConfig();

  bool ok = true;
  ok &= Require(machine.ApplyConfig(config).ok(), "apply config must succeed");
  ok &= Require(machine.Connect().ok(), "connect transition must succeed");
  ok &= Require(machine.MarkConnected().ok(), "mark connected must succeed");

  const swg::StateSnapshot connected = machine.snapshot();
  ok &= Require(connected.state == swg::TunnelState::Connected, "state must be connected");

  ok &= Require(machine.Disconnect().ok(), "disconnect transition must succeed");
  ok &= Require(machine.MarkDisconnected().ok(), "mark disconnected must succeed");

  const swg::StateSnapshot ready = machine.snapshot();
  ok &= Require(ready.state == swg::TunnelState::ConfigReady, "state must return to config_ready");
  return ok;
}

bool TestClientHostBinding() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-client";
  swg::Client::AttachHostService(swg::sysmodule::CreateLocalControlService(runtime_root));

  swg::Client client;
  const auto version = client.GetVersion();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(version.ok(), "attached host service must provide version");
  ok &= Require(status.ok(), "attached host service must provide status");
  ok &= Require(status.value.service_ready, "attached host service must be ready");
  return ok;
}

bool TestMoonlightRoutePlanning() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-moonlight";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  swg::Client client(swg::sysmodule::CreateLocalControlService(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig()).ok(), "valid config must save before Moonlight planning")) {
    return false;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  if (!Require(opened.ok(), "Moonlight app session must open")) {
    return false;
  }

  bool ok = true;
  ok &= Require(!opened.value.tunnel_ready, "Moonlight session should start disconnected");
  ok &= Require(opened.value.active_profile == "default", "Moonlight session should bind to requested profile");

  const auto discovery = session.PlanNetwork(swg::MakeMoonlightDiscoveryPlan());
  ok &= Require(discovery.ok(), "discovery plan must succeed");
  ok &= Require(discovery.value.action == swg::RouteAction::Direct, "discovery must bypass the tunnel");
  ok &= Require(discovery.value.local_bypass, "discovery must be marked as local bypass");

  const auto wake = session.PlanNetwork(swg::MakeMoonlightWakeOnLanPlan("192.168.1.20"));
  ok &= Require(wake.ok(), "wake-on-lan plan must succeed");
  ok &= Require(wake.value.action == swg::RouteAction::Direct, "wake-on-lan must bypass the tunnel");

  const auto control_before_connect = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984));
  ok &= Require(control_before_connect.ok(), "control plan must succeed before connect");
  ok &= Require(control_before_connect.value.action == swg::RouteAction::Deny,
                "control traffic should be denied until the tunnel is connected");

  ok &= Require(client.Connect().ok(), "service connect must succeed for Moonlight planning");

  const auto dns = session.PlanNetwork(swg::MakeMoonlightDnsPlan("vpn.example.test"));
  ok &= Require(dns.ok(), "dns plan must succeed after connect");
  ok &= Require(dns.value.action == swg::RouteAction::Tunnel, "dns should use the tunnel after connect");
  ok &= Require(dns.value.use_tunnel_dns, "dns plan must mark tunnel dns usage");

  const auto control_after_connect = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984));
  ok &= Require(control_after_connect.ok(), "control plan must succeed after connect");
  ok &= Require(control_after_connect.value.action == swg::RouteAction::Tunnel,
                "control traffic should use the tunnel after connect");

  const auto video = session.PlanNetwork(swg::MakeMoonlightVideoPlan("vpn.example.test", 47998));
  ok &= Require(video.ok(), "video plan must succeed after connect");
  ok &= Require(video.value.action == swg::RouteAction::Tunnel, "video traffic should use the tunnel after connect");

  ok &= Require(session.Close().ok(), "Moonlight app session must close cleanly");
  return ok;
}

}  // namespace

int main() {
  const bool config_ok = TestConfigRoundTrip();
  const bool state_ok = TestStateMachine();
  const bool client_ok = TestClientHostBinding();
  const bool moonlight_ok = TestMoonlightRoutePlanning();
  return (config_ok && state_ok && client_ok && moonlight_ok) ? 0 : 1;
}
