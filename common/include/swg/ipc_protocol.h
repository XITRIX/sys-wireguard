#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "swg/version.h"

namespace swg {

inline constexpr char kControlServiceName[] = "swg:ctl";
inline constexpr std::size_t kControlPortMaxEnvelopeSize = 128 * 1024;

enum class ControlPortCommandId : std::uint32_t {
  Invoke = 0,
};

struct ControlPortInvokeRequest {
  std::uint32_t input_size = 0;
};

struct ControlPortInvokeResponse {
  std::uint32_t output_size = 0;
};

enum class ServiceCommandId : std::uint32_t {
  GetVersion = 0,
  GetStatus,
  GetLastError,
  ListProfiles,
  GetConfig,
  SaveConfig,
  SetActiveProfile,
  Connect,
  Disconnect,
  GetStats,
  SetRuntimeFlags,
  GetCompatibilityInfo,
  OpenAppSession,
  CloseAppSession,
  GetNetworkPlan,
  RecvPacket,
  SendPacket,
  ResolveDns,
  OpenTunnelDatagram,
  CloseTunnelDatagram,
  RecvTunnelDatagram,
  SendTunnelDatagram,
  OpenTunnelStream,
  CloseTunnelStream,
  RecvTunnelStream,
  SendTunnelStream,
};

enum class TunnelState : std::uint32_t {
  Idle = 0,
  ConfigReady,
  Connecting,
  Connected,
  Disconnecting,
  Error,
};

enum class RuntimeFlag : std::uint32_t {
  None = 0,
  TransparentMode = 1u << 0,
  DnsThroughTunnel = 1u << 1,
  KillSwitch = 1u << 2,
};

enum class TransportProtocol : std::uint32_t {
  Unspecified = 0,
  Tcp,
  Udp,
  Http,
  Https,
};

enum class AppTrafficClass : std::uint32_t {
  Generic = 0,
  Discovery,
  WakeOnLan,
  Dns,
  HttpsControl,
  StreamControl,
  StreamVideo,
  StreamAudio,
  StreamInput,
  ExternalAddressProbe,
};

enum class RoutePreference : std::uint32_t {
  Default = 0,
  PreferTunnel,
  RequireTunnel,
  BypassTunnel,
};

enum class RouteAction : std::uint32_t {
  Direct = 0,
  Tunnel,
  Deny,
};

using RuntimeFlags = std::uint32_t;

inline constexpr RuntimeFlags ToFlags(RuntimeFlag flag) {
  return static_cast<RuntimeFlags>(flag);
}

inline constexpr bool HasFlag(RuntimeFlags flags, RuntimeFlag flag) {
  return (flags & ToFlags(flag)) != 0;
}

struct VersionInfo {
  std::uint16_t abi_version = kAbiVersion;
  std::string semantic_version = VersionString();
};

struct ProfileSummary {
  std::string name;
  bool autostart = false;
  bool transparent_mode = false;
  bool has_complete_key_material = false;
};

struct TunnelStats {
  std::uint64_t bytes_in = 0;
  std::uint64_t bytes_out = 0;
  std::uint64_t packets_in = 0;
  std::uint64_t packets_out = 0;
  std::uint32_t connect_attempts = 0;
  std::uint32_t successful_handshakes = 0;
  std::uint32_t reconnects = 0;
  std::uint32_t dns_queries = 0;
  std::uint32_t dns_fallbacks = 0;
  std::uint32_t leak_prevention_events = 0;
  std::uint64_t last_handshake_age_seconds = 0;
};

struct ServiceStatus {
  std::uint16_t abi_version = kAbiVersion;
  bool service_ready = false;
  TunnelState state = TunnelState::Idle;
  RuntimeFlags runtime_flags = 0;
  std::string active_profile;
  std::string last_error;
};

struct CompatibilityInfo {
  std::uint16_t abi_version = kAbiVersion;
  bool switch_target = false;
  bool has_bsd_a = false;
  bool has_dns_priv = false;
  bool has_ifcfg = false;
  bool has_bsd_nu = false;
  bool needs_new_tls_abi = false;
  std::string notes;
};

struct AppIdentity {
  std::uint64_t title_id = 0;
  std::string client_name;
  std::string integration_tag;
};

struct AppTunnelRequest {
  std::uint16_t abi_version = kAbiVersion;
  AppIdentity app;
  std::string desired_profile;
  RuntimeFlags requested_flags = 0;
  bool allow_local_network_bypass = true;
  bool require_tunnel_for_default_traffic = false;
  bool prefer_tunnel_dns = true;
  bool allow_direct_internet_fallback = false;
};

struct AppSessionInfo {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t session_id = 0;
  bool service_ready = false;
  bool tunnel_ready = false;
  bool dns_ready = false;
  bool transparent_mode_ready = false;
  std::string active_profile;
  RuntimeFlags granted_flags = 0;
  std::string notes;
};

struct NetworkPlanRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t session_id = 0;
  std::string remote_host;
  std::uint16_t remote_port = 0;
  TransportProtocol transport = TransportProtocol::Unspecified;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  RoutePreference route_preference = RoutePreference::Default;
  bool local_network_hint = false;
};

struct NetworkPlan {
  std::uint16_t abi_version = kAbiVersion;
  RouteAction action = RouteAction::Direct;
  bool use_tunnel_dns = false;
  bool transparent_eligible = false;
  bool local_bypass = false;
  std::string profile_name;
  std::string reason;
};

struct TunnelPacket {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t counter = 0;
  std::vector<std::uint8_t> payload;
};

struct TunnelSendRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t session_id = 0;
  std::vector<std::uint8_t> payload;
};

struct DnsResolveRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t session_id = 0;
  std::string hostname;
};

struct DnsResolveResult {
  std::uint16_t abi_version = kAbiVersion;
  RouteAction action = RouteAction::Direct;
  bool resolved = false;
  bool use_tunnel_dns = false;
  std::string profile_name;
  std::vector<std::string> addresses;
  std::vector<std::string> dns_servers;
  std::string message;
};

struct TunnelDatagramOpenRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t session_id = 0;
  std::string remote_host;
  std::uint16_t remote_port = 0;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  RoutePreference route_preference = RoutePreference::RequireTunnel;
  bool local_network_hint = false;
};

struct TunnelDatagramInfo {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t datagram_id = 0;
  std::uint64_t session_id = 0;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  std::string profile_name;
  std::string remote_host;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string local_address;
  std::uint16_t local_port = 0;
  std::string message;
};

struct TunnelDatagramSendRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t datagram_id = 0;
  std::vector<std::uint8_t> payload;
};

struct TunnelDatagram {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t datagram_id = 0;
  std::uint64_t counter = 0;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::vector<std::uint8_t> payload;
};

struct TunnelStreamOpenRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t session_id = 0;
  std::string remote_host;
  std::uint16_t remote_port = 0;
  TransportProtocol transport = TransportProtocol::Tcp;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  RoutePreference route_preference = RoutePreference::RequireTunnel;
  bool local_network_hint = false;
};

struct TunnelStreamInfo {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t stream_id = 0;
  std::uint64_t session_id = 0;
  TransportProtocol transport = TransportProtocol::Tcp;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  std::string profile_name;
  std::string remote_host;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string local_address;
  std::uint16_t local_port = 0;
  std::string message;
};

struct TunnelStreamSendRequest {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t stream_id = 0;
  std::vector<std::uint8_t> payload;
};

struct TunnelStreamReadResult {
  std::uint16_t abi_version = kAbiVersion;
  std::uint64_t stream_id = 0;
  std::uint64_t counter = 0;
  bool peer_closed = false;
  std::vector<std::uint8_t> payload;
};

inline std::string_view ToString(TunnelState state) {
  switch (state) {
    case TunnelState::Idle:
      return "idle";
    case TunnelState::ConfigReady:
      return "config_ready";
    case TunnelState::Connecting:
      return "connecting";
    case TunnelState::Connected:
      return "connected";
    case TunnelState::Disconnecting:
      return "disconnecting";
    case TunnelState::Error:
      return "error";
  }

  return "unknown";
}

inline std::string_view ToString(TransportProtocol protocol) {
  switch (protocol) {
    case TransportProtocol::Unspecified:
      return "unspecified";
    case TransportProtocol::Tcp:
      return "tcp";
    case TransportProtocol::Udp:
      return "udp";
    case TransportProtocol::Http:
      return "http";
    case TransportProtocol::Https:
      return "https";
  }

  return "unknown";
}

inline std::string_view ToString(AppTrafficClass traffic_class) {
  switch (traffic_class) {
    case AppTrafficClass::Generic:
      return "generic";
    case AppTrafficClass::Discovery:
      return "discovery";
    case AppTrafficClass::WakeOnLan:
      return "wake_on_lan";
    case AppTrafficClass::Dns:
      return "dns";
    case AppTrafficClass::HttpsControl:
      return "https_control";
    case AppTrafficClass::StreamControl:
      return "stream_control";
    case AppTrafficClass::StreamVideo:
      return "stream_video";
    case AppTrafficClass::StreamAudio:
      return "stream_audio";
    case AppTrafficClass::StreamInput:
      return "stream_input";
    case AppTrafficClass::ExternalAddressProbe:
      return "external_address_probe";
  }

  return "unknown";
}

inline std::string_view ToString(RoutePreference preference) {
  switch (preference) {
    case RoutePreference::Default:
      return "default";
    case RoutePreference::PreferTunnel:
      return "prefer_tunnel";
    case RoutePreference::RequireTunnel:
      return "require_tunnel";
    case RoutePreference::BypassTunnel:
      return "bypass_tunnel";
  }

  return "unknown";
}

inline std::string_view ToString(RouteAction action) {
  switch (action) {
    case RouteAction::Direct:
      return "direct";
    case RouteAction::Tunnel:
      return "tunnel";
    case RouteAction::Deny:
      return "deny";
  }

  return "unknown";
}

inline std::string RuntimeFlagsToString(RuntimeFlags flags) {
  std::string result;

  if (HasFlag(flags, RuntimeFlag::TransparentMode)) {
    result += "transparent_mode";
  }

  if (HasFlag(flags, RuntimeFlag::DnsThroughTunnel)) {
    if (!result.empty()) {
      result += ",";
    }
    result += "dns_through_tunnel";
  }

  if (HasFlag(flags, RuntimeFlag::KillSwitch)) {
    if (!result.empty()) {
      result += ",";
    }
    result += "kill_switch";
  }

  if (result.empty()) {
    result = "none";
  }

  return result;
}

}  // namespace swg
