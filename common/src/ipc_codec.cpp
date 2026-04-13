#include "swg/ipc_codec.h"

#include <cstring>
#include <limits>
#include <type_traits>

namespace swg {
namespace {

struct RequestHeaderWire {
  std::uint16_t abi_version;
  std::uint16_t reserved;
  std::uint32_t command_id;
  std::uint32_t payload_size;
};

struct ResponseHeaderWire {
  std::uint16_t abi_version;
  std::uint16_t reserved;
  std::uint32_t error_code;
  std::uint32_t payload_size;
};

class BufferWriter {
 public:
  template <typename T>
  void WritePod(const T& value) {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
    buffer_.insert(buffer_.end(), bytes, bytes + sizeof(T));
  }

  void WriteBool(bool value) {
    WritePod<std::uint8_t>(value ? 1u : 0u);
  }

  template <typename Enum>
  void WriteEnum(Enum value) {
    using Underlying = typename std::underlying_type<Enum>::type;
    WritePod<Underlying>(static_cast<Underlying>(value));
  }

  void WriteString(const std::string& value) {
    WritePod<std::uint32_t>(static_cast<std::uint32_t>(value.size()));
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
    buffer_.insert(buffer_.end(), bytes, bytes + value.size());
  }

  void WriteStringVector(const std::vector<std::string>& values) {
    WritePod<std::uint32_t>(static_cast<std::uint32_t>(values.size()));
    for (const std::string& value : values) {
      WriteString(value);
    }
  }

  void WriteByteVector(const std::vector<std::uint8_t>& value) {
    WritePod<std::uint32_t>(static_cast<std::uint32_t>(value.size()));
    buffer_.insert(buffer_.end(), value.begin(), value.end());
  }

  ByteBuffer Finish() && {
    return std::move(buffer_);
  }

 private:
  ByteBuffer buffer_{};
};

class BufferReader {
 public:
  explicit BufferReader(const ByteBuffer& buffer) : buffer_(buffer) {}

  template <typename T>
  Result<T> ReadPod() {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");
    if (Remaining() < sizeof(T)) {
      return MakeFailure<T>(ErrorCode::ParseError, "payload truncated");
    }

    T value{};
    std::memcpy(&value, buffer_.data() + offset_, sizeof(T));
    offset_ += sizeof(T);
    return MakeSuccess(value);
  }

  Result<bool> ReadBool() {
    const Result<std::uint8_t> value = ReadPod<std::uint8_t>();
    if (!value.ok()) {
      return MakeFailure<bool>(value.error.code, value.error.message);
    }
    return MakeSuccess(value.value != 0);
  }

  template <typename Enum>
  Result<Enum> ReadEnum() {
    using Underlying = typename std::underlying_type<Enum>::type;
    const Result<Underlying> value = ReadPod<Underlying>();
    if (!value.ok()) {
      return MakeFailure<Enum>(value.error.code, value.error.message);
    }
    return MakeSuccess(static_cast<Enum>(value.value));
  }

  Result<std::string> ReadString() {
    const Result<std::uint32_t> size = ReadPod<std::uint32_t>();
    if (!size.ok()) {
      return MakeFailure<std::string>(size.error.code, size.error.message);
    }

    if (Remaining() < size.value) {
      return MakeFailure<std::string>(ErrorCode::ParseError, "string payload truncated");
    }

    const auto* begin = reinterpret_cast<const char*>(buffer_.data() + offset_);
    std::string value(begin, begin + size.value);
    offset_ += size.value;
    return MakeSuccess(std::move(value));
  }

  Result<std::vector<std::string>> ReadStringVector() {
    const Result<std::uint32_t> count = ReadPod<std::uint32_t>();
    if (!count.ok()) {
      return MakeFailure<std::vector<std::string>>(count.error.code, count.error.message);
    }

    std::vector<std::string> values;
    values.reserve(count.value);
    for (std::uint32_t index = 0; index < count.value; ++index) {
      const Result<std::string> value = ReadString();
      if (!value.ok()) {
        return MakeFailure<std::vector<std::string>>(value.error.code, value.error.message);
      }
      values.push_back(value.value);
    }

    return MakeSuccess(std::move(values));
  }

  Result<std::vector<std::uint8_t>> ReadByteVector() {
    const Result<std::uint32_t> count = ReadPod<std::uint32_t>();
    if (!count.ok()) {
      return MakeFailure<std::vector<std::uint8_t>>(count.error.code, count.error.message);
    }

    if (Remaining() < count.value) {
      return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::ParseError, "byte vector payload truncated");
    }

    std::vector<std::uint8_t> value(buffer_.begin() + static_cast<std::ptrdiff_t>(offset_),
                                    buffer_.begin() + static_cast<std::ptrdiff_t>(offset_ + count.value));
    offset_ += count.value;
    return MakeSuccess(std::move(value));
  }

  [[nodiscard]] bool fully_consumed() const {
    return offset_ == buffer_.size();
  }

  [[nodiscard]] std::size_t Remaining() const {
    return buffer_.size() - offset_;
  }

 private:
  const ByteBuffer& buffer_;
  std::size_t offset_ = 0;
};

template <typename T>
Result<T> EnsureRead(Result<T> result) {
  return result;
}

Error EnsureFullyConsumed(const BufferReader& reader) {
  if (!reader.fully_consumed()) {
    return MakeError(ErrorCode::ParseError, "payload contains trailing data");
  }

  return Error::None();
}

void WriteProfileConfig(BufferWriter& writer, const ProfileConfig& value) {
  writer.WriteString(value.name);
  writer.WriteString(value.private_key);
  writer.WriteString(value.public_key);
  writer.WriteString(value.preshared_key);
  writer.WriteString(value.endpoint_host);
  writer.WritePod<std::uint16_t>(value.endpoint_port);
  writer.WriteStringVector(value.allowed_ips);
  writer.WriteStringVector(value.addresses);
  writer.WriteStringVector(value.dns_servers);
  writer.WritePod<std::uint16_t>(value.persistent_keepalive);
  writer.WriteBool(value.autostart);
  writer.WriteBool(value.transparent_mode);
  writer.WriteBool(value.kill_switch);
}

void WriteAppPolicyConfig(BufferWriter& writer, const AppPolicyConfig& value) {
  writer.WriteString(value.name);
  writer.WriteString(value.client_name);
  writer.WriteString(value.integration_tag);
  writer.WriteString(value.desired_profile);
  writer.WritePod<RuntimeFlags>(value.requested_flags);
  writer.WriteBool(value.allow_local_network_bypass);
  writer.WriteBool(value.require_tunnel_for_default_traffic);
  writer.WriteBool(value.prefer_tunnel_dns);
  writer.WriteBool(value.allow_direct_internet_fallback);
}

Result<ProfileConfig> ReadProfileConfig(BufferReader& reader) {
  ProfileConfig value{};

  const Result<std::string> name = reader.ReadString();
  if (!name.ok()) {
    return MakeFailure<ProfileConfig>(name.error.code, name.error.message);
  }
  value.name = name.value;

  const Result<std::string> private_key = reader.ReadString();
  if (!private_key.ok()) {
    return MakeFailure<ProfileConfig>(private_key.error.code, private_key.error.message);
  }
  value.private_key = private_key.value;

  const Result<std::string> public_key = reader.ReadString();
  if (!public_key.ok()) {
    return MakeFailure<ProfileConfig>(public_key.error.code, public_key.error.message);
  }
  value.public_key = public_key.value;

  const Result<std::string> preshared_key = reader.ReadString();
  if (!preshared_key.ok()) {
    return MakeFailure<ProfileConfig>(preshared_key.error.code, preshared_key.error.message);
  }
  value.preshared_key = preshared_key.value;

  const Result<std::string> endpoint_host = reader.ReadString();
  if (!endpoint_host.ok()) {
    return MakeFailure<ProfileConfig>(endpoint_host.error.code, endpoint_host.error.message);
  }
  value.endpoint_host = endpoint_host.value;

  const Result<std::uint16_t> endpoint_port = reader.ReadPod<std::uint16_t>();
  if (!endpoint_port.ok()) {
    return MakeFailure<ProfileConfig>(endpoint_port.error.code, endpoint_port.error.message);
  }
  value.endpoint_port = endpoint_port.value;

  const Result<std::vector<std::string>> allowed_ips = reader.ReadStringVector();
  if (!allowed_ips.ok()) {
    return MakeFailure<ProfileConfig>(allowed_ips.error.code, allowed_ips.error.message);
  }
  value.allowed_ips = allowed_ips.value;

  const Result<std::vector<std::string>> addresses = reader.ReadStringVector();
  if (!addresses.ok()) {
    return MakeFailure<ProfileConfig>(addresses.error.code, addresses.error.message);
  }
  value.addresses = addresses.value;

  const Result<std::vector<std::string>> dns_servers = reader.ReadStringVector();
  if (!dns_servers.ok()) {
    return MakeFailure<ProfileConfig>(dns_servers.error.code, dns_servers.error.message);
  }
  value.dns_servers = dns_servers.value;

  const Result<std::uint16_t> keepalive = reader.ReadPod<std::uint16_t>();
  if (!keepalive.ok()) {
    return MakeFailure<ProfileConfig>(keepalive.error.code, keepalive.error.message);
  }
  value.persistent_keepalive = keepalive.value;

  const Result<bool> autostart = reader.ReadBool();
  if (!autostart.ok()) {
    return MakeFailure<ProfileConfig>(autostart.error.code, autostart.error.message);
  }
  value.autostart = autostart.value;

  const Result<bool> transparent_mode = reader.ReadBool();
  if (!transparent_mode.ok()) {
    return MakeFailure<ProfileConfig>(transparent_mode.error.code, transparent_mode.error.message);
  }
  value.transparent_mode = transparent_mode.value;

  const Result<bool> kill_switch = reader.ReadBool();
  if (!kill_switch.ok()) {
    return MakeFailure<ProfileConfig>(kill_switch.error.code, kill_switch.error.message);
  }
  value.kill_switch = kill_switch.value;
  return MakeSuccess(std::move(value));
}

Result<AppPolicyConfig> ReadAppPolicyConfig(BufferReader& reader) {
  AppPolicyConfig value{};

  const Result<std::string> name = reader.ReadString();
  if (!name.ok()) {
    return MakeFailure<AppPolicyConfig>(name.error.code, name.error.message);
  }
  value.name = name.value;

  const Result<std::string> client_name = reader.ReadString();
  if (!client_name.ok()) {
    return MakeFailure<AppPolicyConfig>(client_name.error.code, client_name.error.message);
  }
  value.client_name = client_name.value;

  const Result<std::string> integration_tag = reader.ReadString();
  if (!integration_tag.ok()) {
    return MakeFailure<AppPolicyConfig>(integration_tag.error.code, integration_tag.error.message);
  }
  value.integration_tag = integration_tag.value;

  const Result<std::string> desired_profile = reader.ReadString();
  if (!desired_profile.ok()) {
    return MakeFailure<AppPolicyConfig>(desired_profile.error.code, desired_profile.error.message);
  }
  value.desired_profile = desired_profile.value;

  const Result<RuntimeFlags> requested_flags = reader.ReadPod<RuntimeFlags>();
  if (!requested_flags.ok()) {
    return MakeFailure<AppPolicyConfig>(requested_flags.error.code, requested_flags.error.message);
  }
  value.requested_flags = requested_flags.value;

  const Result<bool> allow_local_network_bypass = reader.ReadBool();
  if (!allow_local_network_bypass.ok()) {
    return MakeFailure<AppPolicyConfig>(allow_local_network_bypass.error.code,
                                        allow_local_network_bypass.error.message);
  }
  value.allow_local_network_bypass = allow_local_network_bypass.value;

  const Result<bool> require_tunnel_for_default_traffic = reader.ReadBool();
  if (!require_tunnel_for_default_traffic.ok()) {
    return MakeFailure<AppPolicyConfig>(require_tunnel_for_default_traffic.error.code,
                                        require_tunnel_for_default_traffic.error.message);
  }
  value.require_tunnel_for_default_traffic = require_tunnel_for_default_traffic.value;

  const Result<bool> prefer_tunnel_dns = reader.ReadBool();
  if (!prefer_tunnel_dns.ok()) {
    return MakeFailure<AppPolicyConfig>(prefer_tunnel_dns.error.code, prefer_tunnel_dns.error.message);
  }
  value.prefer_tunnel_dns = prefer_tunnel_dns.value;

  const Result<bool> allow_direct_internet_fallback = reader.ReadBool();
  if (!allow_direct_internet_fallback.ok()) {
    return MakeFailure<AppPolicyConfig>(allow_direct_internet_fallback.error.code,
                                        allow_direct_internet_fallback.error.message);
  }
  value.allow_direct_internet_fallback = allow_direct_internet_fallback.value;

  return MakeSuccess(std::move(value));
}

template <typename TResult>
Result<ByteBuffer> EncodeResponseFromResult(const Result<TResult>& result) {
  if (!result.ok()) {
    return EncodeResponseMessage(IpcResponseMessage{kAbiVersion, result.error, {}});
  }

  const Result<ByteBuffer> payload = EncodePayload(result.value);
  if (!payload.ok()) {
    return Result<ByteBuffer>::Failure(payload.error);
  }

  return EncodeResponseMessage(IpcResponseMessage{kAbiVersion, Error::None(), payload.value});
}

Result<ByteBuffer> EncodeResponseFromError(const Error& error) {
  return EncodeResponseMessage(IpcResponseMessage{kAbiVersion, error, {}});
}

Result<ByteBuffer> EncodeResponseFromConfigMutation(const Error& error) {
  return EncodeResponseMessage(IpcResponseMessage{kAbiVersion, error, {}});
}

Error ValidateRequestVersion(std::uint16_t abi_version) {
  if (abi_version != kAbiVersion) {
    return MakeError(ErrorCode::Unsupported, "unsupported ABI version");
  }

  return Error::None();
}

}  // namespace

ByteBuffer EncodeEmptyPayload() {
  return {};
}

Result<ByteBuffer> EncodePayload(const VersionInfo& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WriteString(value.semantic_version);
  return MakeSuccess(std::move(writer).Finish());
}

Result<VersionInfo> DecodeVersionInfoPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  VersionInfo value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<VersionInfo>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::string> semantic_version = reader.ReadString();
  if (!semantic_version.ok()) {
    return MakeFailure<VersionInfo>(semantic_version.error.code, semantic_version.error.message);
  }
  value.semantic_version = semantic_version.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<VersionInfo>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const ServiceStatus& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WriteBool(value.service_ready);
  writer.WriteEnum(value.state);
  writer.WritePod<RuntimeFlags>(value.runtime_flags);
  writer.WriteString(value.active_profile);
  writer.WriteString(value.last_error);
  return MakeSuccess(std::move(writer).Finish());
}

Result<ServiceStatus> DecodeServiceStatusPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  ServiceStatus value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<ServiceStatus>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<bool> service_ready = reader.ReadBool();
  if (!service_ready.ok()) {
    return MakeFailure<ServiceStatus>(service_ready.error.code, service_ready.error.message);
  }
  value.service_ready = service_ready.value;

  const Result<TunnelState> state = reader.ReadEnum<TunnelState>();
  if (!state.ok()) {
    return MakeFailure<ServiceStatus>(state.error.code, state.error.message);
  }
  value.state = state.value;

  const Result<RuntimeFlags> runtime_flags = reader.ReadPod<RuntimeFlags>();
  if (!runtime_flags.ok()) {
    return MakeFailure<ServiceStatus>(runtime_flags.error.code, runtime_flags.error.message);
  }
  value.runtime_flags = runtime_flags.value;

  const Result<std::string> active_profile = reader.ReadString();
  if (!active_profile.ok()) {
    return MakeFailure<ServiceStatus>(active_profile.error.code, active_profile.error.message);
  }
  value.active_profile = active_profile.value;

  const Result<std::string> last_error = reader.ReadString();
  if (!last_error.ok()) {
    return MakeFailure<ServiceStatus>(last_error.error.code, last_error.error.message);
  }
  value.last_error = last_error.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<ServiceStatus>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const std::string& value) {
  BufferWriter writer;
  writer.WriteString(value);
  return MakeSuccess(std::move(writer).Finish());
}

Result<std::string> DecodeStringPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  const Result<std::string> value = reader.ReadString();
  if (!value.ok()) {
    return value;
  }

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<std::string>(trailing.code, trailing.message);
  }
  return value;
}

Result<ByteBuffer> EncodePayload(const std::vector<ProfileSummary>& value) {
  BufferWriter writer;
  writer.WritePod<std::uint32_t>(static_cast<std::uint32_t>(value.size()));
  for (const ProfileSummary& profile : value) {
    writer.WriteString(profile.name);
    writer.WriteBool(profile.autostart);
    writer.WriteBool(profile.transparent_mode);
    writer.WriteBool(profile.has_complete_key_material);
  }
  return MakeSuccess(std::move(writer).Finish());
}

Result<std::vector<ProfileSummary>> DecodeProfileSummaryListPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  const Result<std::uint32_t> count = reader.ReadPod<std::uint32_t>();
  if (!count.ok()) {
    return MakeFailure<std::vector<ProfileSummary>>(count.error.code, count.error.message);
  }

  std::vector<ProfileSummary> value;
  value.reserve(count.value);
  for (std::uint32_t index = 0; index < count.value; ++index) {
    ProfileSummary profile{};

    const Result<std::string> name = reader.ReadString();
    if (!name.ok()) {
      return MakeFailure<std::vector<ProfileSummary>>(name.error.code, name.error.message);
    }
    profile.name = name.value;

    const Result<bool> autostart = reader.ReadBool();
    if (!autostart.ok()) {
      return MakeFailure<std::vector<ProfileSummary>>(autostart.error.code, autostart.error.message);
    }
    profile.autostart = autostart.value;

    const Result<bool> transparent_mode = reader.ReadBool();
    if (!transparent_mode.ok()) {
      return MakeFailure<std::vector<ProfileSummary>>(transparent_mode.error.code, transparent_mode.error.message);
    }
    profile.transparent_mode = transparent_mode.value;

    const Result<bool> complete = reader.ReadBool();
    if (!complete.ok()) {
      return MakeFailure<std::vector<ProfileSummary>>(complete.error.code, complete.error.message);
    }
    profile.has_complete_key_material = complete.value;
    value.push_back(std::move(profile));
  }

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<std::vector<ProfileSummary>>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const Config& value) {
  BufferWriter writer;
  writer.WriteString(value.active_profile);
  writer.WritePod<RuntimeFlags>(value.runtime_flags);
  writer.WritePod<std::uint32_t>(static_cast<std::uint32_t>(value.app_policies.size()));
  for (const auto& [name, policy] : value.app_policies) {
    (void)name;
    WriteAppPolicyConfig(writer, policy);
  }
  writer.WritePod<std::uint32_t>(static_cast<std::uint32_t>(value.profiles.size()));
  for (const auto& [name, profile] : value.profiles) {
    (void)name;
    WriteProfileConfig(writer, profile);
  }
  return MakeSuccess(std::move(writer).Finish());
}

Result<Config> DecodeConfigPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  Config value{};

  const Result<std::string> active_profile = reader.ReadString();
  if (!active_profile.ok()) {
    return MakeFailure<Config>(active_profile.error.code, active_profile.error.message);
  }
  value.active_profile = active_profile.value;

  const Result<RuntimeFlags> runtime_flags = reader.ReadPod<RuntimeFlags>();
  if (!runtime_flags.ok()) {
    return MakeFailure<Config>(runtime_flags.error.code, runtime_flags.error.message);
  }
  value.runtime_flags = runtime_flags.value;

  const Result<std::uint32_t> app_policy_count = reader.ReadPod<std::uint32_t>();
  if (!app_policy_count.ok()) {
    return MakeFailure<Config>(app_policy_count.error.code, app_policy_count.error.message);
  }

  for (std::uint32_t index = 0; index < app_policy_count.value; ++index) {
    const Result<AppPolicyConfig> app_policy = ReadAppPolicyConfig(reader);
    if (!app_policy.ok()) {
      return MakeFailure<Config>(app_policy.error.code, app_policy.error.message);
    }
    value.app_policies[app_policy.value.name] = app_policy.value;
  }

  const Result<std::uint32_t> count = reader.ReadPod<std::uint32_t>();
  if (!count.ok()) {
    return MakeFailure<Config>(count.error.code, count.error.message);
  }

  for (std::uint32_t index = 0; index < count.value; ++index) {
    const Result<ProfileConfig> profile = ReadProfileConfig(reader);
    if (!profile.ok()) {
      return MakeFailure<Config>(profile.error.code, profile.error.message);
    }
    value.profiles[profile.value.name] = profile.value;
  }

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<Config>(trailing.code, trailing.message);
  }

  const Error validation_error = ValidateConfig(value);
  if (validation_error) {
    return MakeFailure<Config>(validation_error.code, validation_error.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelStats& value) {
  BufferWriter writer;
  writer.WritePod<std::uint64_t>(value.bytes_in);
  writer.WritePod<std::uint64_t>(value.bytes_out);
  writer.WritePod<std::uint64_t>(value.packets_in);
  writer.WritePod<std::uint64_t>(value.packets_out);
  writer.WritePod<std::uint32_t>(value.connect_attempts);
  writer.WritePod<std::uint32_t>(value.successful_handshakes);
  writer.WritePod<std::uint32_t>(value.reconnects);
  writer.WritePod<std::uint32_t>(value.dns_queries);
  writer.WritePod<std::uint32_t>(value.dns_fallbacks);
  writer.WritePod<std::uint32_t>(value.leak_prevention_events);
  writer.WritePod<std::uint64_t>(value.last_handshake_age_seconds);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelStats> DecodeTunnelStatsPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelStats value{};

  const Result<std::uint64_t> bytes_in = reader.ReadPod<std::uint64_t>();
  if (!bytes_in.ok()) {
    return MakeFailure<TunnelStats>(bytes_in.error.code, bytes_in.error.message);
  }
  value.bytes_in = bytes_in.value;

  const Result<std::uint64_t> bytes_out = reader.ReadPod<std::uint64_t>();
  if (!bytes_out.ok()) {
    return MakeFailure<TunnelStats>(bytes_out.error.code, bytes_out.error.message);
  }
  value.bytes_out = bytes_out.value;

  const Result<std::uint64_t> packets_in = reader.ReadPod<std::uint64_t>();
  if (!packets_in.ok()) {
    return MakeFailure<TunnelStats>(packets_in.error.code, packets_in.error.message);
  }
  value.packets_in = packets_in.value;

  const Result<std::uint64_t> packets_out = reader.ReadPod<std::uint64_t>();
  if (!packets_out.ok()) {
    return MakeFailure<TunnelStats>(packets_out.error.code, packets_out.error.message);
  }
  value.packets_out = packets_out.value;

  const Result<std::uint32_t> connect_attempts = reader.ReadPod<std::uint32_t>();
  if (!connect_attempts.ok()) {
    return MakeFailure<TunnelStats>(connect_attempts.error.code, connect_attempts.error.message);
  }
  value.connect_attempts = connect_attempts.value;

  const Result<std::uint32_t> successful_handshakes = reader.ReadPod<std::uint32_t>();
  if (!successful_handshakes.ok()) {
    return MakeFailure<TunnelStats>(successful_handshakes.error.code, successful_handshakes.error.message);
  }
  value.successful_handshakes = successful_handshakes.value;

  const Result<std::uint32_t> reconnects = reader.ReadPod<std::uint32_t>();
  if (!reconnects.ok()) {
    return MakeFailure<TunnelStats>(reconnects.error.code, reconnects.error.message);
  }
  value.reconnects = reconnects.value;

  const Result<std::uint32_t> dns_queries = reader.ReadPod<std::uint32_t>();
  if (!dns_queries.ok()) {
    return MakeFailure<TunnelStats>(dns_queries.error.code, dns_queries.error.message);
  }
  value.dns_queries = dns_queries.value;

  const Result<std::uint32_t> dns_fallbacks = reader.ReadPod<std::uint32_t>();
  if (!dns_fallbacks.ok()) {
    return MakeFailure<TunnelStats>(dns_fallbacks.error.code, dns_fallbacks.error.message);
  }
  value.dns_fallbacks = dns_fallbacks.value;

  const Result<std::uint32_t> leak_prevention_events = reader.ReadPod<std::uint32_t>();
  if (!leak_prevention_events.ok()) {
    return MakeFailure<TunnelStats>(leak_prevention_events.error.code, leak_prevention_events.error.message);
  }
  value.leak_prevention_events = leak_prevention_events.value;

  const Result<std::uint64_t> last_handshake_age_seconds = reader.ReadPod<std::uint64_t>();
  if (!last_handshake_age_seconds.ok()) {
    return MakeFailure<TunnelStats>(last_handshake_age_seconds.error.code, last_handshake_age_seconds.error.message);
  }
  value.last_handshake_age_seconds = last_handshake_age_seconds.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelStats>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(RuntimeFlags value) {
  BufferWriter writer;
  writer.WritePod<RuntimeFlags>(value);
  return MakeSuccess(std::move(writer).Finish());
}

Result<RuntimeFlags> DecodeRuntimeFlagsPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  const Result<RuntimeFlags> value = reader.ReadPod<RuntimeFlags>();
  if (!value.ok()) {
    return value;
  }

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<RuntimeFlags>(trailing.code, trailing.message);
  }
  return value;
}

Result<ByteBuffer> EncodePayload(const CompatibilityInfo& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WriteBool(value.switch_target);
  writer.WriteBool(value.has_bsd_a);
  writer.WriteBool(value.has_dns_priv);
  writer.WriteBool(value.has_ifcfg);
  writer.WriteBool(value.has_bsd_nu);
  writer.WriteBool(value.needs_new_tls_abi);
  writer.WriteString(value.notes);
  return MakeSuccess(std::move(writer).Finish());
}

Result<CompatibilityInfo> DecodeCompatibilityInfoPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  CompatibilityInfo value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<CompatibilityInfo>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<bool> switch_target = reader.ReadBool();
  if (!switch_target.ok()) {
    return MakeFailure<CompatibilityInfo>(switch_target.error.code, switch_target.error.message);
  }
  value.switch_target = switch_target.value;

  const Result<bool> has_bsd_a = reader.ReadBool();
  if (!has_bsd_a.ok()) {
    return MakeFailure<CompatibilityInfo>(has_bsd_a.error.code, has_bsd_a.error.message);
  }
  value.has_bsd_a = has_bsd_a.value;

  const Result<bool> has_dns_priv = reader.ReadBool();
  if (!has_dns_priv.ok()) {
    return MakeFailure<CompatibilityInfo>(has_dns_priv.error.code, has_dns_priv.error.message);
  }
  value.has_dns_priv = has_dns_priv.value;

  const Result<bool> has_ifcfg = reader.ReadBool();
  if (!has_ifcfg.ok()) {
    return MakeFailure<CompatibilityInfo>(has_ifcfg.error.code, has_ifcfg.error.message);
  }
  value.has_ifcfg = has_ifcfg.value;

  const Result<bool> has_bsd_nu = reader.ReadBool();
  if (!has_bsd_nu.ok()) {
    return MakeFailure<CompatibilityInfo>(has_bsd_nu.error.code, has_bsd_nu.error.message);
  }
  value.has_bsd_nu = has_bsd_nu.value;

  const Result<bool> needs_new_tls_abi = reader.ReadBool();
  if (!needs_new_tls_abi.ok()) {
    return MakeFailure<CompatibilityInfo>(needs_new_tls_abi.error.code, needs_new_tls_abi.error.message);
  }
  value.needs_new_tls_abi = needs_new_tls_abi.value;

  const Result<std::string> notes = reader.ReadString();
  if (!notes.ok()) {
    return MakeFailure<CompatibilityInfo>(notes.error.code, notes.error.message);
  }
  value.notes = notes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<CompatibilityInfo>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const AppTunnelRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.app.title_id);
  writer.WriteString(value.app.client_name);
  writer.WriteString(value.app.integration_tag);
  writer.WriteString(value.desired_profile);
  writer.WritePod<RuntimeFlags>(value.requested_flags);
  if (value.policy_overrides != 0) {
    writer.WritePod<AppPolicyOverrideFlags>(value.policy_overrides);
  }
  writer.WriteBool(value.allow_local_network_bypass);
  writer.WriteBool(value.require_tunnel_for_default_traffic);
  writer.WriteBool(value.prefer_tunnel_dns);
  writer.WriteBool(value.allow_direct_internet_fallback);
  return MakeSuccess(std::move(writer).Finish());
}

Result<AppTunnelRequest> DecodeAppTunnelRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  AppTunnelRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<AppTunnelRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> title_id = reader.ReadPod<std::uint64_t>();
  if (!title_id.ok()) {
    return MakeFailure<AppTunnelRequest>(title_id.error.code, title_id.error.message);
  }
  value.app.title_id = title_id.value;

  const Result<std::string> client_name = reader.ReadString();
  if (!client_name.ok()) {
    return MakeFailure<AppTunnelRequest>(client_name.error.code, client_name.error.message);
  }
  value.app.client_name = client_name.value;

  const Result<std::string> integration_tag = reader.ReadString();
  if (!integration_tag.ok()) {
    return MakeFailure<AppTunnelRequest>(integration_tag.error.code, integration_tag.error.message);
  }
  value.app.integration_tag = integration_tag.value;

  const Result<std::string> desired_profile = reader.ReadString();
  if (!desired_profile.ok()) {
    return MakeFailure<AppTunnelRequest>(desired_profile.error.code, desired_profile.error.message);
  }
  value.desired_profile = desired_profile.value;

  const Result<RuntimeFlags> requested_flags = reader.ReadPod<RuntimeFlags>();
  if (!requested_flags.ok()) {
    return MakeFailure<AppTunnelRequest>(requested_flags.error.code, requested_flags.error.message);
  }
  value.requested_flags = requested_flags.value;

  constexpr std::size_t kAppTunnelRequestBoolFieldCount = 4;
  constexpr std::size_t kLegacyAppTunnelRequestTrailingBytes = kAppTunnelRequestBoolFieldCount * sizeof(std::uint8_t);
  constexpr std::size_t kCurrentAppTunnelRequestTrailingBytes =
      sizeof(AppPolicyOverrideFlags) + kLegacyAppTunnelRequestTrailingBytes;

  if (reader.Remaining() == kCurrentAppTunnelRequestTrailingBytes) {
    const Result<AppPolicyOverrideFlags> policy_overrides = reader.ReadPod<AppPolicyOverrideFlags>();
    if (!policy_overrides.ok()) {
      return MakeFailure<AppTunnelRequest>(policy_overrides.error.code, policy_overrides.error.message);
    }
    value.policy_overrides = policy_overrides.value;
  } else if (reader.Remaining() != kLegacyAppTunnelRequestTrailingBytes) {
    return MakeFailure<AppTunnelRequest>(ErrorCode::ParseError, "unexpected AppTunnelRequest payload size");
  }

  const Result<bool> allow_local_network_bypass = reader.ReadBool();
  if (!allow_local_network_bypass.ok()) {
    return MakeFailure<AppTunnelRequest>(allow_local_network_bypass.error.code, allow_local_network_bypass.error.message);
  }
  value.allow_local_network_bypass = allow_local_network_bypass.value;

  const Result<bool> require_tunnel_for_default_traffic = reader.ReadBool();
  if (!require_tunnel_for_default_traffic.ok()) {
    return MakeFailure<AppTunnelRequest>(require_tunnel_for_default_traffic.error.code,
                                         require_tunnel_for_default_traffic.error.message);
  }
  value.require_tunnel_for_default_traffic = require_tunnel_for_default_traffic.value;

  const Result<bool> prefer_tunnel_dns = reader.ReadBool();
  if (!prefer_tunnel_dns.ok()) {
    return MakeFailure<AppTunnelRequest>(prefer_tunnel_dns.error.code, prefer_tunnel_dns.error.message);
  }
  value.prefer_tunnel_dns = prefer_tunnel_dns.value;

  const Result<bool> allow_direct_internet_fallback = reader.ReadBool();
  if (!allow_direct_internet_fallback.ok()) {
    return MakeFailure<AppTunnelRequest>(allow_direct_internet_fallback.error.code,
                                         allow_direct_internet_fallback.error.message);
  }
  value.allow_direct_internet_fallback = allow_direct_internet_fallback.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<AppTunnelRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const AppSessionInfo& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteBool(value.service_ready);
  writer.WriteBool(value.tunnel_ready);
  writer.WriteBool(value.dns_ready);
  writer.WriteBool(value.transparent_mode_ready);
  writer.WriteString(value.active_profile);
  writer.WritePod<RuntimeFlags>(value.granted_flags);
  writer.WriteString(value.notes);
  return MakeSuccess(std::move(writer).Finish());
}

Result<AppSessionInfo> DecodeAppSessionInfoPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  AppSessionInfo value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<AppSessionInfo>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<AppSessionInfo>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<bool> service_ready = reader.ReadBool();
  if (!service_ready.ok()) {
    return MakeFailure<AppSessionInfo>(service_ready.error.code, service_ready.error.message);
  }
  value.service_ready = service_ready.value;

  const Result<bool> tunnel_ready = reader.ReadBool();
  if (!tunnel_ready.ok()) {
    return MakeFailure<AppSessionInfo>(tunnel_ready.error.code, tunnel_ready.error.message);
  }
  value.tunnel_ready = tunnel_ready.value;

  const Result<bool> dns_ready = reader.ReadBool();
  if (!dns_ready.ok()) {
    return MakeFailure<AppSessionInfo>(dns_ready.error.code, dns_ready.error.message);
  }
  value.dns_ready = dns_ready.value;

  const Result<bool> transparent_mode_ready = reader.ReadBool();
  if (!transparent_mode_ready.ok()) {
    return MakeFailure<AppSessionInfo>(transparent_mode_ready.error.code, transparent_mode_ready.error.message);
  }
  value.transparent_mode_ready = transparent_mode_ready.value;

  const Result<std::string> active_profile = reader.ReadString();
  if (!active_profile.ok()) {
    return MakeFailure<AppSessionInfo>(active_profile.error.code, active_profile.error.message);
  }
  value.active_profile = active_profile.value;

  const Result<RuntimeFlags> granted_flags = reader.ReadPod<RuntimeFlags>();
  if (!granted_flags.ok()) {
    return MakeFailure<AppSessionInfo>(granted_flags.error.code, granted_flags.error.message);
  }
  value.granted_flags = granted_flags.value;

  const Result<std::string> notes = reader.ReadString();
  if (!notes.ok()) {
    return MakeFailure<AppSessionInfo>(notes.error.code, notes.error.message);
  }
  value.notes = notes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<AppSessionInfo>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(std::uint64_t value) {
  BufferWriter writer;
  writer.WritePod<std::uint64_t>(value);
  return MakeSuccess(std::move(writer).Finish());
}

Result<std::uint64_t> DecodeU64Payload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  const Result<std::uint64_t> value = reader.ReadPod<std::uint64_t>();
  if (!value.ok()) {
    return value;
  }

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<std::uint64_t>(trailing.code, trailing.message);
  }
  return value;
}

Result<ByteBuffer> EncodePayload(const NetworkPlanRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteString(value.remote_host);
  writer.WritePod<std::uint16_t>(value.remote_port);
  writer.WriteEnum(value.transport);
  writer.WriteEnum(value.traffic_class);
  writer.WriteEnum(value.route_preference);
  writer.WriteBool(value.local_network_hint);
  return MakeSuccess(std::move(writer).Finish());
}

Result<NetworkPlanRequest> DecodeNetworkPlanRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  NetworkPlanRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<NetworkPlanRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<NetworkPlanRequest>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<std::string> remote_host = reader.ReadString();
  if (!remote_host.ok()) {
    return MakeFailure<NetworkPlanRequest>(remote_host.error.code, remote_host.error.message);
  }
  value.remote_host = remote_host.value;

  const Result<std::uint16_t> remote_port = reader.ReadPod<std::uint16_t>();
  if (!remote_port.ok()) {
    return MakeFailure<NetworkPlanRequest>(remote_port.error.code, remote_port.error.message);
  }
  value.remote_port = remote_port.value;

  const Result<TransportProtocol> transport = reader.ReadEnum<TransportProtocol>();
  if (!transport.ok()) {
    return MakeFailure<NetworkPlanRequest>(transport.error.code, transport.error.message);
  }
  value.transport = transport.value;

  const Result<AppTrafficClass> traffic_class = reader.ReadEnum<AppTrafficClass>();
  if (!traffic_class.ok()) {
    return MakeFailure<NetworkPlanRequest>(traffic_class.error.code, traffic_class.error.message);
  }
  value.traffic_class = traffic_class.value;

  const Result<RoutePreference> route_preference = reader.ReadEnum<RoutePreference>();
  if (!route_preference.ok()) {
    return MakeFailure<NetworkPlanRequest>(route_preference.error.code, route_preference.error.message);
  }
  value.route_preference = route_preference.value;

  const Result<bool> local_network_hint = reader.ReadBool();
  if (!local_network_hint.ok()) {
    return MakeFailure<NetworkPlanRequest>(local_network_hint.error.code, local_network_hint.error.message);
  }
  value.local_network_hint = local_network_hint.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<NetworkPlanRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const NetworkPlan& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WriteEnum(value.action);
  writer.WriteBool(value.use_tunnel_dns);
  writer.WriteBool(value.transparent_eligible);
  writer.WriteBool(value.local_bypass);
  writer.WriteString(value.profile_name);
  writer.WriteString(value.reason);
  return MakeSuccess(std::move(writer).Finish());
}

Result<NetworkPlan> DecodeNetworkPlanPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  NetworkPlan value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<NetworkPlan>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<RouteAction> action = reader.ReadEnum<RouteAction>();
  if (!action.ok()) {
    return MakeFailure<NetworkPlan>(action.error.code, action.error.message);
  }
  value.action = action.value;

  const Result<bool> use_tunnel_dns = reader.ReadBool();
  if (!use_tunnel_dns.ok()) {
    return MakeFailure<NetworkPlan>(use_tunnel_dns.error.code, use_tunnel_dns.error.message);
  }
  value.use_tunnel_dns = use_tunnel_dns.value;

  const Result<bool> transparent_eligible = reader.ReadBool();
  if (!transparent_eligible.ok()) {
    return MakeFailure<NetworkPlan>(transparent_eligible.error.code, transparent_eligible.error.message);
  }
  value.transparent_eligible = transparent_eligible.value;

  const Result<bool> local_bypass = reader.ReadBool();
  if (!local_bypass.ok()) {
    return MakeFailure<NetworkPlan>(local_bypass.error.code, local_bypass.error.message);
  }
  value.local_bypass = local_bypass.value;

  const Result<std::string> profile_name = reader.ReadString();
  if (!profile_name.ok()) {
    return MakeFailure<NetworkPlan>(profile_name.error.code, profile_name.error.message);
  }
  value.profile_name = profile_name.value;

  const Result<std::string> reason = reader.ReadString();
  if (!reason.ok()) {
    return MakeFailure<NetworkPlan>(reason.error.code, reason.error.message);
  }
  value.reason = reason.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<NetworkPlan>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelPacket& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.counter);
  writer.WriteByteVector(value.payload);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelPacket> DecodeTunnelPacketPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelPacket value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelPacket>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> counter = reader.ReadPod<std::uint64_t>();
  if (!counter.ok()) {
    return MakeFailure<TunnelPacket>(counter.error.code, counter.error.message);
  }
  value.counter = counter.value;

  const Result<std::vector<std::uint8_t>> bytes = reader.ReadByteVector();
  if (!bytes.ok()) {
    return MakeFailure<TunnelPacket>(bytes.error.code, bytes.error.message);
  }
  value.payload = bytes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelPacket>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelSendRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteByteVector(value.payload);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelSendRequest> DecodeTunnelSendRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelSendRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelSendRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<TunnelSendRequest>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<std::vector<std::uint8_t>> payload_bytes = reader.ReadByteVector();
  if (!payload_bytes.ok()) {
    return MakeFailure<TunnelSendRequest>(payload_bytes.error.code, payload_bytes.error.message);
  }
  value.payload = payload_bytes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelSendRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const DnsResolveRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteString(value.hostname);
  return MakeSuccess(std::move(writer).Finish());
}

Result<DnsResolveRequest> DecodeDnsResolveRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  DnsResolveRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<DnsResolveRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<DnsResolveRequest>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<std::string> hostname = reader.ReadString();
  if (!hostname.ok()) {
    return MakeFailure<DnsResolveRequest>(hostname.error.code, hostname.error.message);
  }
  value.hostname = hostname.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<DnsResolveRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const DnsResolveResult& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WriteEnum(value.action);
  writer.WriteBool(value.resolved);
  writer.WriteBool(value.use_tunnel_dns);
  writer.WriteString(value.profile_name);
  writer.WriteStringVector(value.addresses);
  writer.WriteStringVector(value.dns_servers);
  writer.WriteString(value.message);
  return MakeSuccess(std::move(writer).Finish());
}

Result<DnsResolveResult> DecodeDnsResolveResultPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  DnsResolveResult value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<DnsResolveResult>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<RouteAction> action = reader.ReadEnum<RouteAction>();
  if (!action.ok()) {
    return MakeFailure<DnsResolveResult>(action.error.code, action.error.message);
  }
  value.action = action.value;

  const Result<bool> resolved = reader.ReadBool();
  if (!resolved.ok()) {
    return MakeFailure<DnsResolveResult>(resolved.error.code, resolved.error.message);
  }
  value.resolved = resolved.value;

  const Result<bool> use_tunnel_dns = reader.ReadBool();
  if (!use_tunnel_dns.ok()) {
    return MakeFailure<DnsResolveResult>(use_tunnel_dns.error.code, use_tunnel_dns.error.message);
  }
  value.use_tunnel_dns = use_tunnel_dns.value;

  const Result<std::string> profile_name = reader.ReadString();
  if (!profile_name.ok()) {
    return MakeFailure<DnsResolveResult>(profile_name.error.code, profile_name.error.message);
  }
  value.profile_name = profile_name.value;

  const Result<std::vector<std::string>> addresses = reader.ReadStringVector();
  if (!addresses.ok()) {
    return MakeFailure<DnsResolveResult>(addresses.error.code, addresses.error.message);
  }
  value.addresses = addresses.value;

  const Result<std::vector<std::string>> dns_servers = reader.ReadStringVector();
  if (!dns_servers.ok()) {
    return MakeFailure<DnsResolveResult>(dns_servers.error.code, dns_servers.error.message);
  }
  value.dns_servers = dns_servers.value;

  const Result<std::string> message = reader.ReadString();
  if (!message.ok()) {
    return MakeFailure<DnsResolveResult>(message.error.code, message.error.message);
  }
  value.message = message.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<DnsResolveResult>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelDatagramOpenRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteString(value.remote_host);
  writer.WritePod<std::uint16_t>(value.remote_port);
  writer.WriteEnum(value.traffic_class);
  writer.WriteEnum(value.route_preference);
  writer.WriteBool(value.local_network_hint);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelDatagramOpenRequest> DecodeTunnelDatagramOpenRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelDatagramOpenRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<std::string> remote_host = reader.ReadString();
  if (!remote_host.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(remote_host.error.code, remote_host.error.message);
  }
  value.remote_host = remote_host.value;

  const Result<std::uint16_t> remote_port = reader.ReadPod<std::uint16_t>();
  if (!remote_port.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(remote_port.error.code, remote_port.error.message);
  }
  value.remote_port = remote_port.value;

  const Result<AppTrafficClass> traffic_class = reader.ReadEnum<AppTrafficClass>();
  if (!traffic_class.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(traffic_class.error.code, traffic_class.error.message);
  }
  value.traffic_class = traffic_class.value;

  const Result<RoutePreference> route_preference = reader.ReadEnum<RoutePreference>();
  if (!route_preference.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(route_preference.error.code, route_preference.error.message);
  }
  value.route_preference = route_preference.value;

  const Result<bool> local_network_hint = reader.ReadBool();
  if (!local_network_hint.ok()) {
    return MakeFailure<TunnelDatagramOpenRequest>(local_network_hint.error.code, local_network_hint.error.message);
  }
  value.local_network_hint = local_network_hint.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelDatagramOpenRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelDatagramInfo& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.datagram_id);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteEnum(value.traffic_class);
  writer.WriteString(value.profile_name);
  writer.WriteString(value.remote_host);
  writer.WriteString(value.remote_address);
  writer.WritePod<std::uint16_t>(value.remote_port);
  writer.WriteString(value.local_address);
  writer.WritePod<std::uint16_t>(value.local_port);
  writer.WriteString(value.message);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelDatagramInfo> DecodeTunnelDatagramInfoPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelDatagramInfo value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelDatagramInfo>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> datagram_id = reader.ReadPod<std::uint64_t>();
  if (!datagram_id.ok()) {
    return MakeFailure<TunnelDatagramInfo>(datagram_id.error.code, datagram_id.error.message);
  }
  value.datagram_id = datagram_id.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<TunnelDatagramInfo>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<AppTrafficClass> traffic_class = reader.ReadEnum<AppTrafficClass>();
  if (!traffic_class.ok()) {
    return MakeFailure<TunnelDatagramInfo>(traffic_class.error.code, traffic_class.error.message);
  }
  value.traffic_class = traffic_class.value;

  const Result<std::string> profile_name = reader.ReadString();
  if (!profile_name.ok()) {
    return MakeFailure<TunnelDatagramInfo>(profile_name.error.code, profile_name.error.message);
  }
  value.profile_name = profile_name.value;

  const Result<std::string> remote_host = reader.ReadString();
  if (!remote_host.ok()) {
    return MakeFailure<TunnelDatagramInfo>(remote_host.error.code, remote_host.error.message);
  }
  value.remote_host = remote_host.value;

  const Result<std::string> remote_address = reader.ReadString();
  if (!remote_address.ok()) {
    return MakeFailure<TunnelDatagramInfo>(remote_address.error.code, remote_address.error.message);
  }
  value.remote_address = remote_address.value;

  const Result<std::uint16_t> remote_port = reader.ReadPod<std::uint16_t>();
  if (!remote_port.ok()) {
    return MakeFailure<TunnelDatagramInfo>(remote_port.error.code, remote_port.error.message);
  }
  value.remote_port = remote_port.value;

  const Result<std::string> local_address = reader.ReadString();
  if (!local_address.ok()) {
    return MakeFailure<TunnelDatagramInfo>(local_address.error.code, local_address.error.message);
  }
  value.local_address = local_address.value;

  const Result<std::uint16_t> local_port = reader.ReadPod<std::uint16_t>();
  if (!local_port.ok()) {
    return MakeFailure<TunnelDatagramInfo>(local_port.error.code, local_port.error.message);
  }
  value.local_port = local_port.value;

  const Result<std::string> message = reader.ReadString();
  if (!message.ok()) {
    return MakeFailure<TunnelDatagramInfo>(message.error.code, message.error.message);
  }
  value.message = message.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelDatagramInfo>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelDatagramSendRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.datagram_id);
  writer.WriteByteVector(value.payload);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelDatagramSendRequest> DecodeTunnelDatagramSendRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelDatagramSendRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelDatagramSendRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> datagram_id = reader.ReadPod<std::uint64_t>();
  if (!datagram_id.ok()) {
    return MakeFailure<TunnelDatagramSendRequest>(datagram_id.error.code, datagram_id.error.message);
  }
  value.datagram_id = datagram_id.value;

  const Result<std::vector<std::uint8_t>> payload_bytes = reader.ReadByteVector();
  if (!payload_bytes.ok()) {
    return MakeFailure<TunnelDatagramSendRequest>(payload_bytes.error.code, payload_bytes.error.message);
  }
  value.payload = payload_bytes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelDatagramSendRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelDatagram& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.datagram_id);
  writer.WritePod<std::uint64_t>(value.counter);
  writer.WriteString(value.remote_address);
  writer.WritePod<std::uint16_t>(value.remote_port);
  writer.WriteByteVector(value.payload);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelDatagram> DecodeTunnelDatagramPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelDatagram value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelDatagram>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> datagram_id = reader.ReadPod<std::uint64_t>();
  if (!datagram_id.ok()) {
    return MakeFailure<TunnelDatagram>(datagram_id.error.code, datagram_id.error.message);
  }
  value.datagram_id = datagram_id.value;

  const Result<std::uint64_t> counter = reader.ReadPod<std::uint64_t>();
  if (!counter.ok()) {
    return MakeFailure<TunnelDatagram>(counter.error.code, counter.error.message);
  }
  value.counter = counter.value;

  const Result<std::string> remote_address = reader.ReadString();
  if (!remote_address.ok()) {
    return MakeFailure<TunnelDatagram>(remote_address.error.code, remote_address.error.message);
  }
  value.remote_address = remote_address.value;

  const Result<std::uint16_t> remote_port = reader.ReadPod<std::uint16_t>();
  if (!remote_port.ok()) {
    return MakeFailure<TunnelDatagram>(remote_port.error.code, remote_port.error.message);
  }
  value.remote_port = remote_port.value;

  const Result<std::vector<std::uint8_t>> payload_bytes = reader.ReadByteVector();
  if (!payload_bytes.ok()) {
    return MakeFailure<TunnelDatagram>(payload_bytes.error.code, payload_bytes.error.message);
  }
  value.payload = payload_bytes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelDatagram>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelStreamOpenRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteString(value.remote_host);
  writer.WritePod<std::uint16_t>(value.remote_port);
  writer.WriteEnum(value.transport);
  writer.WriteEnum(value.traffic_class);
  writer.WriteEnum(value.route_preference);
  writer.WriteBool(value.local_network_hint);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelStreamOpenRequest> DecodeTunnelStreamOpenRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelStreamOpenRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<std::string> remote_host = reader.ReadString();
  if (!remote_host.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(remote_host.error.code, remote_host.error.message);
  }
  value.remote_host = remote_host.value;

  const Result<std::uint16_t> remote_port = reader.ReadPod<std::uint16_t>();
  if (!remote_port.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(remote_port.error.code, remote_port.error.message);
  }
  value.remote_port = remote_port.value;

  const Result<TransportProtocol> transport = reader.ReadEnum<TransportProtocol>();
  if (!transport.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(transport.error.code, transport.error.message);
  }
  value.transport = transport.value;

  const Result<AppTrafficClass> traffic_class = reader.ReadEnum<AppTrafficClass>();
  if (!traffic_class.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(traffic_class.error.code, traffic_class.error.message);
  }
  value.traffic_class = traffic_class.value;

  const Result<RoutePreference> route_preference = reader.ReadEnum<RoutePreference>();
  if (!route_preference.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(route_preference.error.code, route_preference.error.message);
  }
  value.route_preference = route_preference.value;

  const Result<bool> local_network_hint = reader.ReadBool();
  if (!local_network_hint.ok()) {
    return MakeFailure<TunnelStreamOpenRequest>(local_network_hint.error.code, local_network_hint.error.message);
  }
  value.local_network_hint = local_network_hint.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelStreamOpenRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelStreamInfo& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.stream_id);
  writer.WritePod<std::uint64_t>(value.session_id);
  writer.WriteEnum(value.transport);
  writer.WriteEnum(value.traffic_class);
  writer.WriteString(value.profile_name);
  writer.WriteString(value.remote_host);
  writer.WriteString(value.remote_address);
  writer.WritePod<std::uint16_t>(value.remote_port);
  writer.WriteString(value.local_address);
  writer.WritePod<std::uint16_t>(value.local_port);
  writer.WriteString(value.message);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelStreamInfo> DecodeTunnelStreamInfoPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelStreamInfo value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelStreamInfo>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> stream_id = reader.ReadPod<std::uint64_t>();
  if (!stream_id.ok()) {
    return MakeFailure<TunnelStreamInfo>(stream_id.error.code, stream_id.error.message);
  }
  value.stream_id = stream_id.value;

  const Result<std::uint64_t> session_id = reader.ReadPod<std::uint64_t>();
  if (!session_id.ok()) {
    return MakeFailure<TunnelStreamInfo>(session_id.error.code, session_id.error.message);
  }
  value.session_id = session_id.value;

  const Result<TransportProtocol> transport = reader.ReadEnum<TransportProtocol>();
  if (!transport.ok()) {
    return MakeFailure<TunnelStreamInfo>(transport.error.code, transport.error.message);
  }
  value.transport = transport.value;

  const Result<AppTrafficClass> traffic_class = reader.ReadEnum<AppTrafficClass>();
  if (!traffic_class.ok()) {
    return MakeFailure<TunnelStreamInfo>(traffic_class.error.code, traffic_class.error.message);
  }
  value.traffic_class = traffic_class.value;

  const Result<std::string> profile_name = reader.ReadString();
  if (!profile_name.ok()) {
    return MakeFailure<TunnelStreamInfo>(profile_name.error.code, profile_name.error.message);
  }
  value.profile_name = profile_name.value;

  const Result<std::string> remote_host = reader.ReadString();
  if (!remote_host.ok()) {
    return MakeFailure<TunnelStreamInfo>(remote_host.error.code, remote_host.error.message);
  }
  value.remote_host = remote_host.value;

  const Result<std::string> remote_address = reader.ReadString();
  if (!remote_address.ok()) {
    return MakeFailure<TunnelStreamInfo>(remote_address.error.code, remote_address.error.message);
  }
  value.remote_address = remote_address.value;

  const Result<std::uint16_t> remote_port = reader.ReadPod<std::uint16_t>();
  if (!remote_port.ok()) {
    return MakeFailure<TunnelStreamInfo>(remote_port.error.code, remote_port.error.message);
  }
  value.remote_port = remote_port.value;

  const Result<std::string> local_address = reader.ReadString();
  if (!local_address.ok()) {
    return MakeFailure<TunnelStreamInfo>(local_address.error.code, local_address.error.message);
  }
  value.local_address = local_address.value;

  const Result<std::uint16_t> local_port = reader.ReadPod<std::uint16_t>();
  if (!local_port.ok()) {
    return MakeFailure<TunnelStreamInfo>(local_port.error.code, local_port.error.message);
  }
  value.local_port = local_port.value;

  const Result<std::string> message = reader.ReadString();
  if (!message.ok()) {
    return MakeFailure<TunnelStreamInfo>(message.error.code, message.error.message);
  }
  value.message = message.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelStreamInfo>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelStreamSendRequest& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.stream_id);
  writer.WriteByteVector(value.payload);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelStreamSendRequest> DecodeTunnelStreamSendRequestPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelStreamSendRequest value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelStreamSendRequest>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> stream_id = reader.ReadPod<std::uint64_t>();
  if (!stream_id.ok()) {
    return MakeFailure<TunnelStreamSendRequest>(stream_id.error.code, stream_id.error.message);
  }
  value.stream_id = stream_id.value;

  const Result<std::vector<std::uint8_t>> payload_bytes = reader.ReadByteVector();
  if (!payload_bytes.ok()) {
    return MakeFailure<TunnelStreamSendRequest>(payload_bytes.error.code, payload_bytes.error.message);
  }
  value.payload = payload_bytes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelStreamSendRequest>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodePayload(const TunnelStreamReadResult& value) {
  BufferWriter writer;
  writer.WritePod<std::uint16_t>(value.abi_version);
  writer.WritePod<std::uint64_t>(value.stream_id);
  writer.WritePod<std::uint64_t>(value.counter);
  writer.WriteBool(value.peer_closed);
  writer.WriteByteVector(value.payload);
  return MakeSuccess(std::move(writer).Finish());
}

Result<TunnelStreamReadResult> DecodeTunnelStreamReadResultPayload(const ByteBuffer& payload) {
  BufferReader reader(payload);
  TunnelStreamReadResult value{};

  const Result<std::uint16_t> abi_version = reader.ReadPod<std::uint16_t>();
  if (!abi_version.ok()) {
    return MakeFailure<TunnelStreamReadResult>(abi_version.error.code, abi_version.error.message);
  }
  value.abi_version = abi_version.value;

  const Result<std::uint64_t> stream_id = reader.ReadPod<std::uint64_t>();
  if (!stream_id.ok()) {
    return MakeFailure<TunnelStreamReadResult>(stream_id.error.code, stream_id.error.message);
  }
  value.stream_id = stream_id.value;

  const Result<std::uint64_t> counter = reader.ReadPod<std::uint64_t>();
  if (!counter.ok()) {
    return MakeFailure<TunnelStreamReadResult>(counter.error.code, counter.error.message);
  }
  value.counter = counter.value;

  const Result<bool> peer_closed = reader.ReadBool();
  if (!peer_closed.ok()) {
    return MakeFailure<TunnelStreamReadResult>(peer_closed.error.code, peer_closed.error.message);
  }
  value.peer_closed = peer_closed.value;

  const Result<std::vector<std::uint8_t>> payload_bytes = reader.ReadByteVector();
  if (!payload_bytes.ok()) {
    return MakeFailure<TunnelStreamReadResult>(payload_bytes.error.code, payload_bytes.error.message);
  }
  value.payload = payload_bytes.value;

  const Error trailing = EnsureFullyConsumed(reader);
  if (trailing) {
    return MakeFailure<TunnelStreamReadResult>(trailing.code, trailing.message);
  }

  return MakeSuccess(std::move(value));
}

Result<ByteBuffer> EncodeRequestMessage(const IpcRequestMessage& request) {
  RequestHeaderWire header{};
  header.abi_version = request.abi_version;
  header.command_id = static_cast<std::uint32_t>(request.command_id);
  header.payload_size = static_cast<std::uint32_t>(request.payload.size());

  ByteBuffer bytes(sizeof(header));
  std::memcpy(bytes.data(), &header, sizeof(header));
  bytes.insert(bytes.end(), request.payload.begin(), request.payload.end());
  return MakeSuccess(std::move(bytes));
}

Result<IpcRequestMessage> DecodeRequestMessage(const ByteBuffer& bytes) {
  if (bytes.size() < sizeof(RequestHeaderWire)) {
    return MakeFailure<IpcRequestMessage>(ErrorCode::ParseError, "request header truncated");
  }

  RequestHeaderWire header{};
  std::memcpy(&header, bytes.data(), sizeof(header));

  if (bytes.size() != sizeof(RequestHeaderWire) + header.payload_size) {
    return MakeFailure<IpcRequestMessage>(ErrorCode::ParseError, "request payload size mismatch");
  }

  IpcRequestMessage request{};
  request.abi_version = header.abi_version;
  request.command_id = static_cast<ServiceCommandId>(header.command_id);
  request.payload.assign(bytes.begin() + sizeof(header), bytes.end());
  return MakeSuccess(std::move(request));
}

Result<ByteBuffer> EncodeResponseMessage(const IpcResponseMessage& response) {
  const Result<ByteBuffer> error_message = EncodePayload(response.error.message);
  if (!error_message.ok()) {
    return Result<ByteBuffer>::Failure(error_message.error);
  }

  ByteBuffer payload = error_message.value;
  payload.insert(payload.end(), response.payload.begin(), response.payload.end());

  ResponseHeaderWire header{};
  header.abi_version = response.abi_version;
  header.error_code = static_cast<std::uint32_t>(response.error.code);
  header.payload_size = static_cast<std::uint32_t>(payload.size());

  ByteBuffer bytes(sizeof(header));
  std::memcpy(bytes.data(), &header, sizeof(header));
  bytes.insert(bytes.end(), payload.begin(), payload.end());
  return MakeSuccess(std::move(bytes));
}

Result<IpcResponseMessage> DecodeResponseMessage(const ByteBuffer& bytes) {
  if (bytes.size() < sizeof(ResponseHeaderWire)) {
    return MakeFailure<IpcResponseMessage>(ErrorCode::ParseError, "response header truncated");
  }

  ResponseHeaderWire header{};
  std::memcpy(&header, bytes.data(), sizeof(header));

  if (bytes.size() != sizeof(ResponseHeaderWire) + header.payload_size) {
    return MakeFailure<IpcResponseMessage>(ErrorCode::ParseError, "response payload size mismatch");
  }

  ByteBuffer payload(bytes.begin() + sizeof(header), bytes.end());
  BufferReader reader(payload);
  const Result<std::string> error_message = reader.ReadString();
  if (!error_message.ok()) {
    return MakeFailure<IpcResponseMessage>(error_message.error.code, error_message.error.message);
  }

  IpcResponseMessage response{};
  response.abi_version = header.abi_version;
  response.error.code = static_cast<ErrorCode>(header.error_code);
  response.error.message = error_message.value;
  response.payload.assign(payload.begin() + sizeof(std::uint32_t) + error_message.value.size(), payload.end());
  return MakeSuccess(std::move(response));
}

Result<ByteBuffer> DispatchIpcCommand(IControlService& service, const ByteBuffer& request_bytes) {
  const Result<IpcRequestMessage> request = DecodeRequestMessage(request_bytes);
  if (!request.ok()) {
    return EncodeResponseFromError(request.error);
  }

  const Error version_error = ValidateRequestVersion(request.value.abi_version);
  if (version_error) {
    return EncodeResponseFromError(version_error);
  }

  switch (request.value.command_id) {
    case ServiceCommandId::GetVersion:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "GetVersion does not accept a payload"));
      }
      return EncodeResponseFromResult(service.GetVersion());
    case ServiceCommandId::GetStatus:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "GetStatus does not accept a payload"));
      }
      return EncodeResponseFromResult(service.GetStatus());
    case ServiceCommandId::GetLastError:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "GetLastError does not accept a payload"));
      }
      return EncodeResponseFromResult(service.GetLastError());
    case ServiceCommandId::ListProfiles:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "ListProfiles does not accept a payload"));
      }
      return EncodeResponseFromResult(service.ListProfiles());
    case ServiceCommandId::GetConfig:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "GetConfig does not accept a payload"));
      }
      return EncodeResponseFromResult(service.GetConfig());
    case ServiceCommandId::SaveConfig: {
      const Result<Config> config = DecodeConfigPayload(request.value.payload);
      if (!config.ok()) {
        return EncodeResponseFromError(config.error);
      }
      return EncodeResponseFromConfigMutation(service.SaveConfig(config.value));
    }
    case ServiceCommandId::SetActiveProfile: {
      const Result<std::string> profile_name = DecodeStringPayload(request.value.payload);
      if (!profile_name.ok()) {
        return EncodeResponseFromError(profile_name.error);
      }
      return EncodeResponseFromConfigMutation(service.SetActiveProfile(profile_name.value));
    }
    case ServiceCommandId::Connect:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "Connect does not accept a payload"));
      }
      return EncodeResponseFromConfigMutation(service.Connect());
    case ServiceCommandId::Disconnect:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "Disconnect does not accept a payload"));
      }
      return EncodeResponseFromConfigMutation(service.Disconnect());
    case ServiceCommandId::GetStats:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "GetStats does not accept a payload"));
      }
      return EncodeResponseFromResult(service.GetStats());
    case ServiceCommandId::SetRuntimeFlags: {
      const Result<RuntimeFlags> flags = DecodeRuntimeFlagsPayload(request.value.payload);
      if (!flags.ok()) {
        return EncodeResponseFromError(flags.error);
      }
      return EncodeResponseFromConfigMutation(service.SetRuntimeFlags(flags.value));
    }
    case ServiceCommandId::GetCompatibilityInfo:
      if (!request.value.payload.empty()) {
        return EncodeResponseFromError(MakeError(ErrorCode::ParseError, "GetCompatibilityInfo does not accept a payload"));
      }
      return EncodeResponseFromResult(service.GetCompatibilityInfo());
    case ServiceCommandId::OpenAppSession: {
      const Result<AppTunnelRequest> app_request = DecodeAppTunnelRequestPayload(request.value.payload);
      if (!app_request.ok()) {
        return EncodeResponseFromError(app_request.error);
      }
      return EncodeResponseFromResult(service.OpenAppSession(app_request.value));
    }
    case ServiceCommandId::CloseAppSession: {
      const Result<std::uint64_t> session_id = DecodeU64Payload(request.value.payload);
      if (!session_id.ok()) {
        return EncodeResponseFromError(session_id.error);
      }
      return EncodeResponseFromConfigMutation(service.CloseAppSession(session_id.value));
    }
    case ServiceCommandId::GetNetworkPlan: {
      const Result<NetworkPlanRequest> plan_request = DecodeNetworkPlanRequestPayload(request.value.payload);
      if (!plan_request.ok()) {
        return EncodeResponseFromError(plan_request.error);
      }
      return EncodeResponseFromResult(service.GetNetworkPlan(plan_request.value));
    }
    case ServiceCommandId::ResolveDns: {
      const Result<DnsResolveRequest> dns_request = DecodeDnsResolveRequestPayload(request.value.payload);
      if (!dns_request.ok()) {
        return EncodeResponseFromError(dns_request.error);
      }
      return EncodeResponseFromResult(service.ResolveDns(dns_request.value));
    }
    case ServiceCommandId::RecvPacket: {
      const Result<std::uint64_t> session_id = DecodeU64Payload(request.value.payload);
      if (!session_id.ok()) {
        return EncodeResponseFromError(session_id.error);
      }
      return EncodeResponseFromResult(service.RecvPacket(session_id.value));
    }
    case ServiceCommandId::SendPacket: {
      const Result<TunnelSendRequest> send_request = DecodeTunnelSendRequestPayload(request.value.payload);
      if (!send_request.ok()) {
        return EncodeResponseFromError(send_request.error);
      }
      return EncodeResponseFromResult(service.SendPacket(send_request.value));
    }
    case ServiceCommandId::OpenTunnelDatagram: {
      const Result<TunnelDatagramOpenRequest> open_request =
          DecodeTunnelDatagramOpenRequestPayload(request.value.payload);
      if (!open_request.ok()) {
        return EncodeResponseFromError(open_request.error);
      }
      return EncodeResponseFromResult(service.OpenTunnelDatagram(open_request.value));
    }
    case ServiceCommandId::CloseTunnelDatagram: {
      const Result<std::uint64_t> datagram_id = DecodeU64Payload(request.value.payload);
      if (!datagram_id.ok()) {
        return EncodeResponseFromError(datagram_id.error);
      }
      return EncodeResponseFromConfigMutation(service.CloseTunnelDatagram(datagram_id.value));
    }
    case ServiceCommandId::RecvTunnelDatagram: {
      const Result<std::uint64_t> datagram_id = DecodeU64Payload(request.value.payload);
      if (!datagram_id.ok()) {
        return EncodeResponseFromError(datagram_id.error);
      }
      return EncodeResponseFromResult(service.RecvTunnelDatagram(datagram_id.value));
    }
    case ServiceCommandId::SendTunnelDatagram: {
      const Result<TunnelDatagramSendRequest> send_request =
          DecodeTunnelDatagramSendRequestPayload(request.value.payload);
      if (!send_request.ok()) {
        return EncodeResponseFromError(send_request.error);
      }
      return EncodeResponseFromResult(service.SendTunnelDatagram(send_request.value));
    }
    case ServiceCommandId::OpenTunnelStream: {
      const Result<TunnelStreamOpenRequest> open_request =
          DecodeTunnelStreamOpenRequestPayload(request.value.payload);
      if (!open_request.ok()) {
        return EncodeResponseFromError(open_request.error);
      }
      return EncodeResponseFromResult(service.OpenTunnelStream(open_request.value));
    }
    case ServiceCommandId::CloseTunnelStream: {
      const Result<std::uint64_t> stream_id = DecodeU64Payload(request.value.payload);
      if (!stream_id.ok()) {
        return EncodeResponseFromError(stream_id.error);
      }
      return EncodeResponseFromConfigMutation(service.CloseTunnelStream(stream_id.value));
    }
    case ServiceCommandId::RecvTunnelStream: {
      const Result<std::uint64_t> stream_id = DecodeU64Payload(request.value.payload);
      if (!stream_id.ok()) {
        return EncodeResponseFromError(stream_id.error);
      }
      return EncodeResponseFromResult(service.RecvTunnelStream(stream_id.value));
    }
    case ServiceCommandId::SendTunnelStream: {
      const Result<TunnelStreamSendRequest> send_request =
          DecodeTunnelStreamSendRequestPayload(request.value.payload);
      if (!send_request.ok()) {
        return EncodeResponseFromError(send_request.error);
      }
      return EncodeResponseFromResult(service.SendTunnelStream(send_request.value));
    }
  }

  return EncodeResponseFromError(MakeError(ErrorCode::Unsupported, "unsupported command"));
}

}  // namespace swg
