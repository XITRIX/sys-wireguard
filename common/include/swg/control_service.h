#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg/result.h"

namespace swg {

class IControlService {
 public:
  virtual ~IControlService() = default;

  virtual Result<VersionInfo> GetVersion() const = 0;
  virtual Result<ServiceStatus> GetStatus() const = 0;
  virtual Result<std::string> GetLastError() const = 0;
  virtual Result<std::vector<ProfileSummary>> ListProfiles() const = 0;
  virtual Result<Config> GetConfig() const = 0;
  virtual Error SaveConfig(const Config& config) = 0;
  virtual Error SetActiveProfile(std::string_view profile_name) = 0;
  virtual Error Connect() = 0;
  virtual Error Disconnect() = 0;
  virtual Result<TunnelStats> GetStats() const = 0;
  virtual Error SetRuntimeFlags(RuntimeFlags flags) = 0;
  virtual Result<CompatibilityInfo> GetCompatibilityInfo() const = 0;
  virtual Result<AppSessionInfo> OpenAppSession(const AppTunnelRequest& request) = 0;
  virtual Error CloseAppSession(std::uint64_t session_id) = 0;
  virtual Result<NetworkPlan> GetNetworkPlan(const NetworkPlanRequest& request) const = 0;
};

}  // namespace swg
