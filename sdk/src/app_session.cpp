#include "swg/app_session.h"

namespace swg {

AppSession::AppSession(Client client) : client_(std::move(client)) {}

AppSession::~AppSession() {
  static_cast<void>(Close());
}

Result<AppSessionInfo> AppSession::Open(const AppTunnelRequest& request) {
  if (is_open()) {
    return MakeFailure<AppSessionInfo>(ErrorCode::InvalidState, "app session is already open");
  }

  const Result<AppSessionInfo> opened = client_.OpenAppSession(request);
  if (!opened.ok()) {
    return opened;
  }

  session_id_ = opened.value.session_id;
  session_info_ = opened.value;
  return opened;
}

Error AppSession::Close() {
  if (!is_open()) {
    return Error::None();
  }

  const Error close_error = client_.CloseAppSession(session_id_);
  if (close_error && close_error.code != ErrorCode::NotFound) {
    return close_error;
  }

  session_id_ = 0;
  session_info_ = {};
  return Error::None();
}

Result<NetworkPlan> AppSession::PlanNetwork(const NetworkPlanRequest& request) const {
  if (!is_open()) {
    return MakeFailure<NetworkPlan>(ErrorCode::InvalidState, "app session is not open");
  }

  NetworkPlanRequest scoped_request = request;
  scoped_request.session_id = session_id_;
  return client_.GetNetworkPlan(scoped_request);
}

Result<DnsResolveResult> AppSession::ResolveDns(std::string_view hostname) const {
  if (!is_open()) {
    return MakeFailure<DnsResolveResult>(ErrorCode::InvalidState, "app session is not open");
  }

  DnsResolveRequest request{};
  request.session_id = session_id_;
  request.hostname = std::string(hostname);
  return client_.ResolveDns(request);
}

Result<std::uint64_t> AppSession::SendPacket(const std::vector<std::uint8_t>& payload) const {
  if (!is_open()) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "app session is not open");
  }

  return client_.SendPacket(session_id_, payload);
}

Result<TunnelPacket> AppSession::ReceivePacket() const {
  if (!is_open()) {
    return MakeFailure<TunnelPacket>(ErrorCode::InvalidState, "app session is not open");
  }

  return client_.RecvPacket(session_id_);
}

Result<TunnelDatagramInfo> AppSession::OpenTunnelDatagram(const TunnelDatagramOpenRequest& request) const {
  if (!is_open()) {
    return MakeFailure<TunnelDatagramInfo>(ErrorCode::InvalidState, "app session is not open");
  }

  TunnelDatagramOpenRequest scoped_request = request;
  scoped_request.session_id = session_id_;
  return client_.OpenTunnelDatagram(scoped_request);
}

Error AppSession::CloseTunnelDatagram(std::uint64_t datagram_id) const {
  if (!is_open()) {
    return MakeError(ErrorCode::InvalidState, "app session is not open");
  }

  return client_.CloseTunnelDatagram(datagram_id);
}

Result<std::uint64_t> AppSession::SendTunnelDatagram(std::uint64_t datagram_id,
                                                     const std::vector<std::uint8_t>& payload) const {
  if (!is_open()) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "app session is not open");
  }

  TunnelDatagramSendRequest request{};
  request.datagram_id = datagram_id;
  request.payload = payload;
  return client_.SendTunnelDatagram(request);
}

Result<TunnelDatagram> AppSession::ReceiveTunnelDatagram(std::uint64_t datagram_id) const {
  if (!is_open()) {
    return MakeFailure<TunnelDatagram>(ErrorCode::InvalidState, "app session is not open");
  }

  return client_.RecvTunnelDatagram(datagram_id);
}

Result<TunnelStreamInfo> AppSession::OpenTunnelStream(const TunnelStreamOpenRequest& request) const {
  if (!is_open()) {
    return MakeFailure<TunnelStreamInfo>(ErrorCode::InvalidState, "app session is not open");
  }

  TunnelStreamOpenRequest scoped_request = request;
  scoped_request.session_id = session_id_;
  return client_.OpenTunnelStream(scoped_request);
}

Error AppSession::CloseTunnelStream(std::uint64_t stream_id) const {
  if (!is_open()) {
    return MakeError(ErrorCode::InvalidState, "app session is not open");
  }

  return client_.CloseTunnelStream(stream_id);
}

Result<std::uint64_t> AppSession::SendTunnelStream(std::uint64_t stream_id,
                                                   const std::vector<std::uint8_t>& payload) const {
  if (!is_open()) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "app session is not open");
  }

  TunnelStreamSendRequest request{};
  request.stream_id = stream_id;
  request.payload = payload;
  return client_.SendTunnelStream(request);
}

Result<TunnelStreamReadResult> AppSession::ReceiveTunnelStream(std::uint64_t stream_id) const {
  if (!is_open()) {
    return MakeFailure<TunnelStreamReadResult>(ErrorCode::InvalidState, "app session is not open");
  }

  return client_.RecvTunnelStream(stream_id);
}

}  // namespace swg
