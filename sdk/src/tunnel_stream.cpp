#include "swg/tunnel_stream.h"

namespace swg {

TunnelStreamSocket::TunnelStreamSocket(const AppSession* session, TunnelStreamInfo info)
    : session_(session), info_(std::move(info)) {}

TunnelStreamSocket::TunnelStreamSocket(TunnelStreamSocket&& other) noexcept
    : session_(other.session_), info_(std::move(other.info_)) {
  other.session_ = nullptr;
  other.info_ = {};
}

TunnelStreamSocket& TunnelStreamSocket::operator=(TunnelStreamSocket&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  static_cast<void>(Close());
  session_ = other.session_;
  info_ = std::move(other.info_);
  other.session_ = nullptr;
  other.info_ = {};
  return *this;
}

TunnelStreamSocket::~TunnelStreamSocket() {
  static_cast<void>(Close());
}

Result<TunnelStreamSocket> TunnelStreamSocket::Open(const AppSession& session, TunnelStreamOpenRequest request) {
  const Result<TunnelStreamInfo> opened = session.OpenTunnelStream(request);
  if (!opened.ok()) {
    return MakeFailure<TunnelStreamSocket>(opened.error.code, opened.error.message);
  }

  return MakeSuccess(TunnelStreamSocket(&session, opened.value));
}

Error TunnelStreamSocket::Close() {
  if (!is_open()) {
    return Error::None();
  }

  const Error error = session_->CloseTunnelStream(info_.stream_id);
  if (error && error.code != ErrorCode::NotFound) {
    return error;
  }

  session_ = nullptr;
  info_ = {};
  return Error::None();
}

Result<std::uint64_t> TunnelStreamSocket::Send(const std::vector<std::uint8_t>& payload) const {
  if (!is_open()) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "tunnel stream socket is not open");
  }

  return session_->SendTunnelStream(info_.stream_id, payload);
}

Result<TunnelStreamReadResult> TunnelStreamSocket::Receive() const {
  if (!is_open()) {
    return MakeFailure<TunnelStreamReadResult>(ErrorCode::InvalidState, "tunnel stream socket is not open");
  }

  return session_->ReceiveTunnelStream(info_.stream_id);
}

}  // namespace swg
