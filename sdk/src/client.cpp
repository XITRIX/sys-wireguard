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

Result<DnsResolveResult> Client::ResolveDns(const DnsResolveRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->ResolveDns(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<DnsResolveResult>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::ResolveDns, payload.value}),
      DecodeDnsResolveResultPayload);
}

Result<std::uint64_t> Client::SendPacket(std::uint64_t session_id, const std::vector<std::uint8_t>& payload) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  const TunnelSendRequest request{kAbiVersion, session_id, payload};
  if (service) {
    return service->SendPacket(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> request_payload = EncodePayload(request);
  if (!request_payload.ok()) {
    return MakeFailure<std::uint64_t>(request_payload.error.code, request_payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::SendPacket, request_payload.value}),
      DecodeU64Payload);
}

Result<TunnelPacket> Client::RecvPacket(std::uint64_t session_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->RecvPacket(session_id);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(session_id);
  if (!payload.ok()) {
    return MakeFailure<TunnelPacket>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::RecvPacket, payload.value}),
      DecodeTunnelPacketPayload);
}

Result<TunnelDatagramInfo> Client::OpenTunnelDatagram(const TunnelDatagramOpenRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->OpenTunnelDatagram(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<TunnelDatagramInfo>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::OpenTunnelDatagram, payload.value}),
      DecodeTunnelDatagramInfoPayload);
}

Error Client::CloseTunnelDatagram(std::uint64_t datagram_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->CloseTunnelDatagram(datagram_id);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(datagram_id);
  if (!payload.ok()) {
    return payload.error;
  }
  return DecodeTransportMutationResponse(InvokeTransportRequest(
      transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::CloseTunnelDatagram, payload.value}));
}

Result<std::uint64_t> Client::SendTunnelDatagram(const TunnelDatagramSendRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->SendTunnelDatagram(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<std::uint64_t>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::SendTunnelDatagram, payload.value}),
      DecodeU64Payload);
}

Result<TunnelDatagram> Client::RecvTunnelDatagram(std::uint64_t datagram_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->RecvTunnelDatagram(datagram_id);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(datagram_id);
  if (!payload.ok()) {
    return MakeFailure<TunnelDatagram>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::RecvTunnelDatagram, payload.value}),
      DecodeTunnelDatagramPayload);
}

Result<TunnelStreamInfo> Client::OpenTunnelStream(const TunnelStreamOpenRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->OpenTunnelStream(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<TunnelStreamInfo>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::OpenTunnelStream, payload.value}),
      DecodeTunnelStreamInfoPayload);
}

Error Client::CloseTunnelStream(std::uint64_t stream_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->CloseTunnelStream(stream_id);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(stream_id);
  if (!payload.ok()) {
    return payload.error;
  }
  return DecodeTransportMutationResponse(InvokeTransportRequest(
      transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::CloseTunnelStream, payload.value}));
}

Result<std::uint64_t> Client::SendTunnelStream(const TunnelStreamSendRequest& request) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->SendTunnelStream(request);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(request);
  if (!payload.ok()) {
    return MakeFailure<std::uint64_t>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::SendTunnelStream, payload.value}),
      DecodeU64Payload);
}

Result<TunnelStreamReadResult> Client::RecvTunnelStream(std::uint64_t stream_id) const {
  const std::shared_ptr<IControlService> service = ResolveService();
  if (service) {
    return service->RecvTunnelStream(stream_id);
  }

  const std::shared_ptr<IClientTransport> transport = ResolveTransport();
  const Result<ByteBuffer> payload = EncodePayload(stream_id);
  if (!payload.ok()) {
    return MakeFailure<TunnelStreamReadResult>(payload.error.code, payload.error.message);
  }
  return DecodeTransportResponse(
      InvokeTransportRequest(transport, IpcRequestMessage{kAbiVersion, ServiceCommandId::RecvTunnelStream, payload.value}),
      DecodeTunnelStreamReadResultPayload);
}

}  // namespace swg
