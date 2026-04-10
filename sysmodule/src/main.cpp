#include <filesystem>
#include <iostream>
#include <string>

#include "swg/client.h"
#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg_sysmodule/host_transport.h"
#include "swg_sysmodule/local_service.h"

namespace {

void PrintStatus(const swg::Client& client) {
  const auto version = client.GetVersion();
  const auto status = client.GetStatus();
  const auto compatibility = client.GetCompatibilityInfo();

  if (!version.ok() || !status.ok() || !compatibility.ok()) {
    std::cerr << "service query failed\n";
    return;
  }

  std::cout << "Switch WireGuard sysmodule stub\n";
  std::cout << "version: " << version.value.semantic_version << " (abi " << version.value.abi_version << ")\n";
  std::cout << "state: " << swg::ToString(status.value.state) << "\n";
  std::cout << "service_ready: " << (status.value.service_ready ? "true" : "false") << "\n";
  std::cout << "active_profile: " << (status.value.active_profile.empty() ? "<none>" : status.value.active_profile) << "\n";
  std::cout << "runtime_flags: " << swg::RuntimeFlagsToString(status.value.runtime_flags) << "\n";
  std::cout << "compatibility: " << compatibility.value.notes << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path runtime_root = swg::DetectRuntimePaths().root_dir;
  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
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

  std::cerr << "unknown command: " << command << "\n";
  return 1;
}
