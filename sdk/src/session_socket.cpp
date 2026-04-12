#include "swg/session_socket.h"

#include "swg/wg_profile.h"

namespace swg {
namespace {

TransportProtocol DefaultTransport(SessionSocketKind kind) {
  switch (kind) {
    case SessionSocketKind::Datagram:
      return TransportProtocol::Udp;
    case SessionSocketKind::Stream:
      return TransportProtocol::Tcp;
  }

  return TransportProtocol::Unspecified;
}

SessionSocketMode ModeForRouteAction(RouteAction action) {
  switch (action) {
    case RouteAction::Direct:
      return SessionSocketMode::DirectSocket;
    case RouteAction::Tunnel:
      return SessionSocketMode::TunnelPacket;
    case RouteAction::Deny:
      return SessionSocketMode::Denied;
  }

  return SessionSocketMode::Denied;
}

bool IsNumericIpv4(std::string_view host) {
  const Result<ParsedIpAddress> parsed = ParseIpAddress(host, "remote_host");
  return parsed.ok() && parsed.value.family == ParsedIpFamily::IPv4;
}

std::string DescribeDirectSocketUse(const SessionSocketInfo& info) {
  return "use the resolved address list to open the app's native " + std::string(ToString(info.kind)) +
         " socket directly";
}

std::string DescribeTunnelSocketUse(const SessionSocketInfo& info) {
  if (info.kind == SessionSocketKind::Datagram) {
    return "forward caller-managed datagram payloads through the current session packet channel";
  }

  return "forward framed stream payloads through the current session packet channel; this is not a native TCP socket";
}

}  // namespace

SessionSocket::SessionSocket(const AppSession* session, SessionSocketInfo info)
    : session_(session), info_(std::move(info)) {}

Result<SessionSocket> SessionSocket::OpenDatagram(const AppSession& session, const SessionSocketRequest& request) {
  return Open(session, request, SessionSocketKind::Datagram);
}

Result<SessionSocket> SessionSocket::OpenStream(const AppSession& session, const SessionSocketRequest& request) {
  return Open(session, request, SessionSocketKind::Stream);
}

Result<SessionSocket> SessionSocket::Open(const AppSession& session,
                                          SessionSocketRequest request,
                                          SessionSocketKind kind) {
  if (!session.is_open()) {
    return MakeFailure<SessionSocket>(ErrorCode::InvalidState, "app session is not open");
  }
  if (request.remote_host.empty()) {
    return MakeFailure<SessionSocket>(ErrorCode::ParseError, "remote_host must not be empty");
  }

  SessionSocketInfo info{};
  info.kind = kind;
  info.transport = request.transport == TransportProtocol::Unspecified ? DefaultTransport(kind) : request.transport;
  info.traffic_class = request.traffic_class;
  info.remote_host = request.remote_host;
  info.remote_port = request.remote_port;

  NetworkPlanRequest plan_request{};
  plan_request.remote_host = request.remote_host;
  plan_request.remote_port = request.remote_port;
  plan_request.transport = info.transport;
  plan_request.traffic_class = request.traffic_class;
  plan_request.route_preference = request.route_preference;
  plan_request.local_network_hint = request.local_network_hint;

  const Result<NetworkPlan> plan = session.PlanNetwork(plan_request);
  if (!plan.ok()) {
    return MakeFailure<SessionSocket>(plan.error.code, plan.error.message);
  }

  info.plan = plan.value;
  info.mode = ModeForRouteAction(plan.value.action);
  info.message = plan.value.reason;

  if (IsNumericIpv4(request.remote_host)) {
    info.remote_addresses.push_back(request.remote_host);
    info.dns.action = RouteAction::Direct;
    info.dns.resolved = true;
    info.dns.profile_name = plan.value.profile_name;
    info.dns.addresses = info.remote_addresses;
    info.dns.message = "numeric IPv4 host bypasses SDK DNS resolution";
  } else {
    const Result<DnsResolveResult> dns = session.ResolveDns(request.remote_host);
    if (!dns.ok()) {
      return MakeFailure<SessionSocket>(dns.error.code, dns.error.message);
    }

    info.used_dns_helper = true;
    info.dns = dns.value;
    if (dns.value.resolved) {
      info.remote_addresses = dns.value.addresses;
    }
  }

  if (info.mode == SessionSocketMode::DirectSocket && info.remote_addresses.empty()) {
    info.mode = SessionSocketMode::Denied;
    info.message = info.dns.message.empty() ? "direct route selected but no IPv4 addresses were resolved"
                                            : info.dns.message;
  }

  if (info.mode == SessionSocketMode::DirectSocket) {
    info.message += "; ";
    info.message += DescribeDirectSocketUse(info);
  } else if (info.mode == SessionSocketMode::TunnelPacket) {
    info.message += "; ";
    info.message += DescribeTunnelSocketUse(info);
  }

  return MakeSuccess(SessionSocket(&session, std::move(info)));
}

Result<std::uint64_t> SessionSocket::Send(const std::vector<std::uint8_t>& payload) const {
  if (session_ == nullptr) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "session socket is not initialized");
  }
  if (info_.mode != SessionSocketMode::TunnelPacket) {
    return MakeFailure<std::uint64_t>(ErrorCode::Unsupported,
                                      "packet send is only available when the session socket selected tunnel-packet mode");
  }

  return session_->SendPacket(payload);
}

Result<TunnelPacket> SessionSocket::Receive() const {
  if (session_ == nullptr) {
    return MakeFailure<TunnelPacket>(ErrorCode::InvalidState, "session socket is not initialized");
  }
  if (info_.mode != SessionSocketMode::TunnelPacket) {
    return MakeFailure<TunnelPacket>(ErrorCode::Unsupported,
                                     "packet receive is only available when the session socket selected tunnel-packet mode");
  }

  return session_->ReceivePacket();
}

}  // namespace swg