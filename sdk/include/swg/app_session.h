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
  Result<TunnelPacket> ReceivePacket() const;

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
