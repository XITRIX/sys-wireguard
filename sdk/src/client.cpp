#include "swg/client.h"

namespace swg {
namespace {

std::shared_ptr<IControlService> g_host_service;

Result<VersionInfo> ServiceUnavailableVersion() {
  return MakeFailure<VersionInfo>(ErrorCode::ServiceUnavailable, "control service unavailable");
}

template <typename T>
Result<T> ServiceUnavailableResult() {
  return MakeFailure<T>(ErrorCode::ServiceUnavailable, "control service unavailable");
}

Error ServiceUnavailableError() {
  return MakeError(ErrorCode::ServiceUnavailable, "control service unavailable");
}

}  // namespace

Client::Client(std::shared_ptr<IControlService> service) : service_(std::move(service)) {}

void Client::AttachHostService(const std::shared_ptr<IControlService>& service) {
  g_host_service = service;
}

std::shared_ptr<IControlService> Client::ResolveService() const {
  if (service_) {
    return service_;
  }

  return g_host_service;
}

Result<VersionInfo> Client::GetVersion() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetVersion() : ServiceUnavailableVersion();
}

Result<ServiceStatus> Client::GetStatus() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetStatus() : ServiceUnavailableResult<ServiceStatus>();
}

Result<std::string> Client::GetLastError() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetLastError() : ServiceUnavailableResult<std::string>();
}

Result<std::vector<ProfileSummary>> Client::ListProfiles() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->ListProfiles() : ServiceUnavailableResult<std::vector<ProfileSummary>>();
}

Result<Config> Client::GetConfig() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetConfig() : ServiceUnavailableResult<Config>();
}

Error Client::SaveConfig(const Config& config) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->SaveConfig(config) : ServiceUnavailableError();
}

Error Client::SetActiveProfile(std::string_view profile_name) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->SetActiveProfile(profile_name) : ServiceUnavailableError();
}

Error Client::Connect() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->Connect() : ServiceUnavailableError();
}

Error Client::Disconnect() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->Disconnect() : ServiceUnavailableError();
}

Result<TunnelStats> Client::GetStats() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetStats() : ServiceUnavailableResult<TunnelStats>();
}

Error Client::SetRuntimeFlags(RuntimeFlags flags) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->SetRuntimeFlags(flags) : ServiceUnavailableError();
}

Result<CompatibilityInfo> Client::GetCompatibilityInfo() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetCompatibilityInfo() : ServiceUnavailableResult<CompatibilityInfo>();
}

Result<AppSessionInfo> Client::OpenAppSession(const AppTunnelRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->OpenAppSession(request) : ServiceUnavailableResult<AppSessionInfo>();
}

Error Client::CloseAppSession(std::uint64_t session_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->CloseAppSession(session_id) : ServiceUnavailableError();
}

Result<NetworkPlan> Client::GetNetworkPlan(const NetworkPlanRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  return service ? service->GetNetworkPlan(request) : ServiceUnavailableResult<NetworkPlan>();
}

}  // namespace swg
