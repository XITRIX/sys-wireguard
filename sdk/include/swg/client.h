#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "swg/control_service.h"

namespace swg {

class Client {
 public:
  Client() = default;
  explicit Client(std::shared_ptr<IControlService> service);

  static void AttachHostService(const std::shared_ptr<IControlService>& service);

  Result<VersionInfo> GetVersion() const;
  Result<ServiceStatus> GetStatus() const;
  Result<std::string> GetLastError() const;
  Result<std::vector<ProfileSummary>> ListProfiles() const;
  Result<Config> GetConfig() const;
  Error SaveConfig(const Config& config) const;
  Error SetActiveProfile(std::string_view profile_name) const;
  Error Connect() const;
  Error Disconnect() const;
  Result<TunnelStats> GetStats() const;
  Error SetRuntimeFlags(RuntimeFlags flags) const;
  Result<CompatibilityInfo> GetCompatibilityInfo() const;
  Result<AppSessionInfo> OpenAppSession(const AppTunnelRequest& request) const;
  Error CloseAppSession(std::uint64_t session_id) const;
  Result<NetworkPlan> GetNetworkPlan(const NetworkPlanRequest& request) const;

 private:
  std::shared_ptr<IControlService> ResolveService() const;

  std::shared_ptr<IControlService> service_;
};

}  // namespace swg
