#include "swg/tunnel_datagram.h"

namespace swg {

TunnelDatagramSocket::TunnelDatagramSocket(const AppSession* session, TunnelDatagramInfo info)
    : session_(session), info_(std::move(info)) {}

TunnelDatagramSocket::TunnelDatagramSocket(TunnelDatagramSocket&& other) noexcept
    : session_(other.session_), info_(std::move(other.info_)) {
  other.session_ = nullptr;
  other.info_ = {};
}

TunnelDatagramSocket& TunnelDatagramSocket::operator=(TunnelDatagramSocket&& other) noexcept {
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

TunnelDatagramSocket::~TunnelDatagramSocket() {
  static_cast<void>(Close());
}

Result<TunnelDatagramSocket> TunnelDatagramSocket::Open(const AppSession& session, TunnelDatagramOpenRequest request) {
  const Result<TunnelDatagramInfo> opened = session.OpenTunnelDatagram(request);
  if (!opened.ok()) {
    return MakeFailure<TunnelDatagramSocket>(opened.error.code, opened.error.message);
  }

  return MakeSuccess(TunnelDatagramSocket(&session, opened.value));
}

Error TunnelDatagramSocket::Close() {
  if (!is_open()) {
    return Error::None();
  }

  const Error error = session_->CloseTunnelDatagram(info_.datagram_id);
  if (error && error.code != ErrorCode::NotFound) {
    return error;
  }

  session_ = nullptr;
  info_ = {};
  return Error::None();
}

Result<std::uint64_t> TunnelDatagramSocket::Send(const std::vector<std::uint8_t>& payload) const {
  if (!is_open()) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "tunnel datagram socket is not open");
  }

  return session_->SendTunnelDatagram(info_.datagram_id, payload);
}

Result<TunnelDatagram> TunnelDatagramSocket::Receive() const {
  if (!is_open()) {
    return MakeFailure<TunnelDatagram>(ErrorCode::InvalidState, "tunnel datagram socket is not open");
  }

  return session_->ReceiveTunnelDatagram(info_.datagram_id);
}

}  // namespace swg