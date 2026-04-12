#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "swg/app_session.h"

namespace swg {

class TunnelStreamSocket {
 public:
  TunnelStreamSocket() = default;
  TunnelStreamSocket(const TunnelStreamSocket&) = delete;
  TunnelStreamSocket& operator=(const TunnelStreamSocket&) = delete;

  TunnelStreamSocket(TunnelStreamSocket&& other) noexcept;
  TunnelStreamSocket& operator=(TunnelStreamSocket&& other) noexcept;

  ~TunnelStreamSocket();

  static Result<TunnelStreamSocket> Open(const AppSession& session, TunnelStreamOpenRequest request);

  [[nodiscard]] bool is_open() const noexcept {
    return session_ != nullptr && info_.stream_id != 0;
  }

  [[nodiscard]] const TunnelStreamInfo& info() const noexcept {
    return info_;
  }

  Error Close();
  Result<std::uint64_t> Send(const std::vector<std::uint8_t>& payload) const;
  Result<TunnelStreamReadResult> Receive() const;

 private:
  TunnelStreamSocket(const AppSession* session, TunnelStreamInfo info);

  const AppSession* session_ = nullptr;
  TunnelStreamInfo info_{};
};

}  // namespace swg
