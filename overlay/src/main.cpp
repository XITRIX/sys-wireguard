#include <iostream>
#include <string>

#include "swg/client.h"
#include "swg/ipc_protocol.h"
#include "swg_sysmodule/local_service.h"

namespace {

void PrintProfiles(const swg::Client& client) {
  const auto profiles = client.ListProfiles();
  if (!profiles.ok()) {
    std::cerr << profiles.error.message << '\n';
    return;
  }

  std::cout << "profiles:\n";
  for (const auto& profile : profiles.value) {
    std::cout << "- " << profile.name << " autostart=" << (profile.autostart ? "true" : "false")
              << " transparent_mode=" << (profile.transparent_mode ? "true" : "false")
              << " complete=" << (profile.has_complete_key_material ? "true" : "false") << '\n';
  }
}

void PrintStatus(const swg::Client& client) {
  const auto status = client.GetStatus();
  const auto stats = client.GetStats();

  if (!status.ok() || !stats.ok()) {
    std::cerr << "failed to query service state\n";
    return;
  }

  std::cout << "Switch WireGuard overlay stub\n";
  std::cout << "state: " << swg::ToString(status.value.state) << '\n';
  std::cout << "active profile: " << (status.value.active_profile.empty() ? "<none>" : status.value.active_profile)
            << '\n';
  std::cout << "flags: " << swg::RuntimeFlagsToString(status.value.runtime_flags) << '\n';
  std::cout << "last error: " << (status.value.last_error.empty() ? "<none>" : status.value.last_error) << '\n';
  std::cout << "connect attempts: " << stats.value.connect_attempts << '\n';
  std::cout << "successful handshakes: " << stats.value.successful_handshakes << '\n';
  PrintProfiles(client);
}

}  // namespace

int main(int argc, char** argv) {
  swg::Client::AttachHostService(swg::sysmodule::CreateLocalControlService());
  swg::Client client;

  const std::string command = argc > 1 ? argv[1] : "status";

  if (command == "status") {
    PrintStatus(client);
    return 0;
  }

  if (command == "connect") {
    const swg::Error error = client.Connect();
    if (error) {
      std::cerr << error.message << '\n';
      return 1;
    }
    PrintStatus(client);
    return 0;
  }

  if (command == "disconnect") {
    const swg::Error error = client.Disconnect();
    if (error) {
      std::cerr << error.message << '\n';
      return 1;
    }
    PrintStatus(client);
    return 0;
  }

  if (command == "profiles") {
    PrintProfiles(client);
    return 0;
  }

  std::cerr << "unknown command: " << command << '\n';
  return 1;
}
