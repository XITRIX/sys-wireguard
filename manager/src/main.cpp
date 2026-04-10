#include <iostream>
#include <string>

#include "swg/client.h"
#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg_sysmodule/local_service.h"

namespace {

void PrintUsage() {
  std::cout << "usage: swg_manager_stub [show-config|sample-profile|flags]\n";
}

swg::Config MakeSampleConfig() {
  swg::Config config = swg::DefaultConfig();
  swg::ProfileConfig profile{};
  profile.name = "default";
  profile.private_key = "REPLACE_PRIVATE_KEY";
  profile.public_key = "REPLACE_PUBLIC_KEY";
  profile.endpoint_host = "vpn.example.test";
  profile.endpoint_port = 51820;
  profile.allowed_ips = {"0.0.0.0/0", "::/0"};
  profile.addresses = {"10.0.0.2/32"};
  profile.dns_servers = {"1.1.1.1", "1.0.0.1"};
  profile.autostart = false;
  profile.transparent_mode = false;
  profile.kill_switch = false;
  config.profiles.emplace(profile.name, profile);
  config.active_profile = profile.name;
  config.runtime_flags = swg::ToFlags(swg::RuntimeFlag::DnsThroughTunnel);
  return config;
}

void ShowConfig(const swg::Client& client) {
  const auto config = client.GetConfig();
  if (!config.ok()) {
    std::cerr << config.error.message << '\n';
    return;
  }

  std::cout << "active_profile: " << (config.value.active_profile.empty() ? "<none>" : config.value.active_profile)
            << '\n';
  std::cout << "runtime_flags: " << swg::RuntimeFlagsToString(config.value.runtime_flags) << '\n';
  std::cout << "profile_count: " << config.value.profiles.size() << '\n';

  for (const auto& [name, profile] : config.value.profiles) {
    std::cout << "[profile." << name << "] endpoint=" << profile.endpoint_host << ':' << profile.endpoint_port
              << " autostart=" << (profile.autostart ? "true" : "false") << '\n';
  }
}

}  // namespace

int main(int argc, char** argv) {
  swg::Client::AttachHostService(swg::sysmodule::CreateLocalControlService());
  swg::Client client;

  if (argc < 2) {
    PrintUsage();
    return 0;
  }

  const std::string command = argv[1];

  if (command == "show-config") {
    ShowConfig(client);
    return 0;
  }

  if (command == "sample-profile") {
    const swg::Error error = client.SaveConfig(MakeSampleConfig());
    if (error) {
      std::cerr << error.message << '\n';
      return 1;
    }
    ShowConfig(client);
    return 0;
  }

  if (command == "flags") {
    const swg::Error error = client.SetRuntimeFlags(swg::ToFlags(swg::RuntimeFlag::DnsThroughTunnel) |
                                                    swg::ToFlags(swg::RuntimeFlag::TransparentMode));
    if (error) {
      std::cerr << error.message << '\n';
      return 1;
    }
    ShowConfig(client);
    return 0;
  }

  PrintUsage();
  return 1;
}
