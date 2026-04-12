#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "swg/app_session.h"

namespace swg {

class TunnelDatagramSocket {
 public:
  TunnelDatagramSocket() = default;
  TunnelDatagramSocket(const TunnelDatagramSocket&) = delete;
  TunnelDatagramSocket& operator=(const TunnelDatagramSocket&) = delete;

  TunnelDatagramSocket(TunnelDatagramSocket&& other) noexcept;
  TunnelDatagramSocket& operator=(TunnelDatagramSocket&& other) noexcept;

  ~TunnelDatagramSocket();

  static Result<TunnelDatagramSocket> Open(const AppSession& session, TunnelDatagramOpenRequest request);

  [[nodiscard]] bool is_open() const noexcept {
    return session_ != nullptr && info_.datagram_id != 0;
  }

  [[nodiscard]] const TunnelDatagramInfo& info() const noexcept {
    return info_;
  }

  Error Close();
  Result<std::uint64_t> Send(const std::vector<std::uint8_t>& payload) const;
  Result<TunnelDatagram> Receive() const;

 private:
  TunnelDatagramSocket(const AppSession* session, TunnelDatagramInfo info);

  const AppSession* session_ = nullptr;
  TunnelDatagramInfo info_{};
};

}  // namespace swg