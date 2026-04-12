#pragma once

#include <cstdint>
#include <vector>

#include "swg/control_service.h"

namespace swg {

using ByteBuffer = std::vector<std::uint8_t>;

struct IpcRequestMessage {
  std::uint16_t abi_version = kAbiVersion;
  ServiceCommandId command_id = ServiceCommandId::GetVersion;
  ByteBuffer payload;
};

struct IpcResponseMessage {
  std::uint16_t abi_version = kAbiVersion;
  Error error{};
  ByteBuffer payload;
};

ByteBuffer EncodeEmptyPayload();

Result<ByteBuffer> EncodePayload(const VersionInfo& value);
Result<ByteBuffer> EncodePayload(const ServiceStatus& value);
Result<ByteBuffer> EncodePayload(const std::string& value);
Result<ByteBuffer> EncodePayload(const std::vector<ProfileSummary>& value);
Result<ByteBuffer> EncodePayload(const Config& value);
Result<ByteBuffer> EncodePayload(const TunnelStats& value);
Result<ByteBuffer> EncodePayload(RuntimeFlags value);
Result<ByteBuffer> EncodePayload(const CompatibilityInfo& value);
Result<ByteBuffer> EncodePayload(const AppTunnelRequest& value);
Result<ByteBuffer> EncodePayload(const AppSessionInfo& value);
Result<ByteBuffer> EncodePayload(std::uint64_t value);
Result<ByteBuffer> EncodePayload(const NetworkPlanRequest& value);
Result<ByteBuffer> EncodePayload(const NetworkPlan& value);
Result<ByteBuffer> EncodePayload(const TunnelPacket& value);

Result<VersionInfo> DecodeVersionInfoPayload(const ByteBuffer& payload);
Result<ServiceStatus> DecodeServiceStatusPayload(const ByteBuffer& payload);
Result<std::string> DecodeStringPayload(const ByteBuffer& payload);
Result<std::vector<ProfileSummary>> DecodeProfileSummaryListPayload(const ByteBuffer& payload);
Result<Config> DecodeConfigPayload(const ByteBuffer& payload);
Result<TunnelStats> DecodeTunnelStatsPayload(const ByteBuffer& payload);
Result<RuntimeFlags> DecodeRuntimeFlagsPayload(const ByteBuffer& payload);
Result<CompatibilityInfo> DecodeCompatibilityInfoPayload(const ByteBuffer& payload);
Result<AppTunnelRequest> DecodeAppTunnelRequestPayload(const ByteBuffer& payload);
Result<AppSessionInfo> DecodeAppSessionInfoPayload(const ByteBuffer& payload);
Result<std::uint64_t> DecodeU64Payload(const ByteBuffer& payload);
Result<NetworkPlanRequest> DecodeNetworkPlanRequestPayload(const ByteBuffer& payload);
Result<NetworkPlan> DecodeNetworkPlanPayload(const ByteBuffer& payload);
Result<TunnelPacket> DecodeTunnelPacketPayload(const ByteBuffer& payload);

Result<ByteBuffer> EncodeRequestMessage(const IpcRequestMessage& request);
Result<IpcRequestMessage> DecodeRequestMessage(const ByteBuffer& bytes);
Result<ByteBuffer> EncodeResponseMessage(const IpcResponseMessage& response);
Result<IpcResponseMessage> DecodeResponseMessage(const ByteBuffer& bytes);

Result<ByteBuffer> DispatchIpcCommand(IControlService& service, const ByteBuffer& request_bytes);

}  // namespace swg
