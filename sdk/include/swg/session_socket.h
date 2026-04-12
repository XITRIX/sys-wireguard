#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "swg/app_session.h"

namespace swg {

enum class SessionSocketKind : std::uint32_t {
  Datagram = 0,
  Stream,
};

enum class SessionSocketMode : std::uint32_t {
  DirectSocket = 0,
  TunnelPacket,
  Denied,
};

struct SessionSocketRequest {
  std::string remote_host;
  std::uint16_t remote_port = 0;
  TransportProtocol transport = TransportProtocol::Unspecified;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  RoutePreference route_preference = RoutePreference::Default;
  bool local_network_hint = false;
};

struct SessionSocketInfo {
  SessionSocketKind kind = SessionSocketKind::Datagram;
  SessionSocketMode mode = SessionSocketMode::Denied;
  TransportProtocol transport = TransportProtocol::Unspecified;
  AppTrafficClass traffic_class = AppTrafficClass::Generic;
  std::string remote_host;
  std::uint16_t remote_port = 0;
  std::vector<std::string> remote_addresses;
  NetworkPlan plan{};
  DnsResolveResult dns{};
  bool used_dns_helper = false;
  std::string message;
};

inline std::string_view ToString(SessionSocketKind kind) {
  switch (kind) {
    case SessionSocketKind::Datagram:
      return "datagram";
    case SessionSocketKind::Stream:
      return "stream";
  }

  return "unknown";
}

inline std::string_view ToString(SessionSocketMode mode) {
  switch (mode) {
    case SessionSocketMode::DirectSocket:
      return "direct_socket";
    case SessionSocketMode::TunnelPacket:
      return "tunnel_packet";
    case SessionSocketMode::Denied:
      return "denied";
  }

  return "unknown";
}

class SessionSocket {
 public:
  SessionSocket() = default;

  static Result<SessionSocket> OpenDatagram(const AppSession& session, const SessionSocketRequest& request);
  static Result<SessionSocket> OpenStream(const AppSession& session, const SessionSocketRequest& request);

  [[nodiscard]] bool uses_direct_socket() const noexcept {
    return info_.mode == SessionSocketMode::DirectSocket;
  }

  [[nodiscard]] bool uses_tunnel_packets() const noexcept {
    return info_.mode == SessionSocketMode::TunnelPacket;
  }

  [[nodiscard]] bool denied() const noexcept {
    return info_.mode == SessionSocketMode::Denied;
  }

  [[nodiscard]] const SessionSocketInfo& info() const noexcept {
    return info_;
  }

  Result<std::uint64_t> Send(const std::vector<std::uint8_t>& payload) const;
  Result<TunnelPacket> Receive() const;

 private:
  SessionSocket(const AppSession* session, SessionSocketInfo info);
  static Result<SessionSocket> Open(const AppSession& session, SessionSocketRequest request, SessionSocketKind kind);

  const AppSession* session_ = nullptr;
  SessionSocketInfo info_{};
};

}  // namespace swg