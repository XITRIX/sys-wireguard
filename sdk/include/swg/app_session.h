#pragma once

#include <cstdint>

#include "swg/client.h"

namespace swg {

class AppSession {
 public:
  explicit AppSession(Client client = {});
  ~AppSession();

  Result<AppSessionInfo> Open(const AppTunnelRequest& request);
  Error Close();
  Result<NetworkPlan> PlanNetwork(const NetworkPlanRequest& request) const;
  Result<DnsResolveResult> ResolveDns(std::string_view hostname) const;
  Result<std::uint64_t> SendPacket(const std::vector<std::uint8_t>& payload) const;
  Result<TunnelPacket> ReceivePacket() const;
  Result<TunnelDatagramInfo> OpenTunnelDatagram(const TunnelDatagramOpenRequest& request) const;
  Error CloseTunnelDatagram(std::uint64_t datagram_id) const;
  Result<std::uint64_t> SendTunnelDatagram(std::uint64_t datagram_id, const std::vector<std::uint8_t>& payload) const;
  Result<TunnelDatagram> ReceiveTunnelDatagram(std::uint64_t datagram_id) const;

  [[nodiscard]] bool is_open() const noexcept {
    return session_id_ != 0;
  }

  [[nodiscard]] std::uint64_t session_id() const noexcept {
    return session_id_;
  }

  [[nodiscard]] const AppSessionInfo& info() const noexcept {
    return session_info_;
  }

 private:
  Client client_;
  std::uint64_t session_id_ = 0;
  AppSessionInfo session_info_{};
};

}  // namespace swg
