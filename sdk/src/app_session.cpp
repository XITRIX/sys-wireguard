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

}  // namespace swg
