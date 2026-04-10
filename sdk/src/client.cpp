#include "swg/client.h"

#include "swg/switch_transport.h"

namespace swg {
namespace {

std::shared_ptr<IControlService> g_host_service;
std::shared_ptr<IClientTransport> g_host_transport;

Result<ByteBuffer> InvokeTransportRequest(const std::shared_ptr<IClientTransport>& transport,
                                         const IpcRequestMessage& request) {
  if (!transport) {
    return MakeFailure<ByteBuffer>(ErrorCode::ServiceUnavailable, "control transport unavailable");
  }

  const Result<ByteBuffer> request_bytes = EncodeRequestMessage(request);
  if (!request_bytes.ok()) {
    return request_bytes;
  }

  return transport->Invoke(request_bytes.value);
}

template <typename TResult>
Result<TResult> DecodeTransportResponse(const Result<ByteBuffer>& response_bytes,
                                        Result<TResult> (*decode_payload)(const ByteBuffer&)) {
  if (!response_bytes.ok()) {
    return MakeFailure<TResult>(response_bytes.error.code, response_bytes.error.message);
  }

  const Result<IpcResponseMessage> response = DecodeResponseMessage(response_bytes.value);
  if (!response.ok()) {
    return MakeFailure<TResult>(response.error.code, response.error.message);
  }

  if (response.value.error) {
    return MakeFailure<TResult>(response.value.error.code, response.value.error.message);
  }

  return decode_payload(response.value.payload);
}

Error DecodeTransportMutationResponse(const Result<ByteBuffer>& response_bytes) {
  if (!response_bytes.ok()) {
    return response_bytes.error;
  }

  const Result<IpcResponseMessage> response = DecodeResponseMessage(response_bytes.value);
  if (!response.ok()) {
    return response.error;
  }

  return response.value.error;
}

std::shared_ptr<IClientTransport> ResolvePlatformDefaultTransport() {
#if defined(SWG_PLATFORM_SWITCH)
  static std::shared_ptr<IClientTransport> transport = CreateSwitchControlTransport();
  return transport;
#else
  return {};
#endif
}

}  // namespace

Client::Client(std::shared_ptr<IControlService> service) : service_(std::move(service)) {}

Client::Client(std::shared_ptr<IClientTransport> transport) : transport_(std::move(transport)) {}

void Client::AttachHostService(const std::shared_ptr<IControlService>& service) {
  g_host_service = service;
}

void Client::AttachHostTransport(const std::shared_ptr<IClientTransport>& transport) {
  g_host_transport = transport;
}

std::shared_ptr<IControlService> Client::ResolveService() const {
  if (service_) {
    return service_;
  }

  return g_host_service;
}

std::shared_ptr<IClientTransport> Client::ResolveTransport() const {
  if (transport_) {
    return transport_;
  }

  if (g_host_transport) {
    return g_host_transport;
  }

  return ResolvePlatformDefaultTransport();
}

Result<VersionInfo> Client::GetVersion() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetVersion();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetVersion, {}}),
                                 DecodeVersionInfoPayload);
}

Result<ServiceStatus> Client::GetStatus() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetStatus();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetStatus, {}}),
                                 DecodeServiceStatusPayload);
}

Result<std::string> Client::GetLastError() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetLastError();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetLastError, {}}),
      DecodeStringPayload);
}

Result<std::vector<ProfileSummary>> Client::ListProfiles() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->ListProfiles();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::ListProfiles, {}}),
      DecodeProfileSummaryListPayload);
}

Result<Config> Client::GetConfig() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetConfig();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetConfig, {}}),
                                 DecodeConfigPayload);
}

Error Client::SaveConfig(const Config& config) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->SaveConfig(config);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(config);
  if (!payload.ok()) {
    return payload.error;
  }
  return DecodeTransportMutationResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::SaveConfig, payload.value}));
}

Error Client::SetActiveProfile(std::string_view profile_name) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->SetActiveProfile(profile_name);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(std::string(profile_name));
  if (!payload.ok()) {
    return payload.error;
  }
  return DecodeTransportMutationResponse(InvokeTransportRequest(
      transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::SetActiveProfile, payload.value}));
}

Error Client::Connect() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->Connect();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportMutationResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::Connect, {}}));
}

Error Client::Disconnect() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->Disconnect();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportMutationResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::Disconnect, {}}));
}

Result<TunnelStats> Client::GetStats() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetStats();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetStats, {}}),
                                 DecodeTunnelStatsPayload);
}

Error Client::SetRuntimeFlags(RuntimeFlags flags) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->SetRuntimeFlags(flags);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(flags);
  if (!payload.ok()) {
    return payload.error;
  }
  return DecodeTransportMutationResponse(InvokeTransportRequest(
      transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::SetRuntimeFlags, payload.value}));
}

Result<CompatibilityInfo> Client::GetCompatibilityInfo() const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetCompatibilityInfo();
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetCompatibilityInfo, {}}),
      DecodeCompatibilityInfoPayload);
}

Result<AppSessionInfo> Client::OpenAppSession(const AppTunnelRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->OpenAppSession(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<AppSessionInfo>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::OpenAppSession, payload.value}),
      DecodeAppSessionInfoPayload);
}

Error Client::CloseAppSession(std::uint64_t session_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->CloseAppSession(session_id);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(session_id);
  if (!payload.ok()) {
    return payload.error;
  }
  return DecodeTransportMutationResponse(InvokeTransportRequest(
      transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::CloseAppSession, payload.value}));
}

Result<NetworkPlan> Client::GetNetworkPlan(const NetworkPlanRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->GetNetworkPlan(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<NetworkPlan>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::GetNetworkPlan, payload.value}),
      DecodeNetworkPlanPayload);
}

}  // namespace swg
