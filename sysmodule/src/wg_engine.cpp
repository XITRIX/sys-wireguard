#include "swg_sysmodule/wg_engine.h"

#include "swg_sysmodule/socket_runtime.h"

#include <algorithm>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>

namespace swg::sysmodule {
namespace {

std::array<std::uint8_t, 4> CopyIpv4Bytes(const ParsedIpAddress& address) {
  std::array<std::uint8_t, 4> bytes{};
  std::copy_n(address.bytes.begin(), bytes.size(), bytes.begin());
  return bytes;
}

PreparedIpv4Network PrepareIpv4Network(const ParsedIpNetwork& network) {
  PreparedIpv4Network prepared{};
  prepared.address = CopyIpv4Bytes(network.address);
  prepared.prefix_length = network.prefix_length;
  prepared.normalized = network.normalized;
  return prepared;
}

std::array<std::uint8_t, 4> CopyIpv4SockaddrBytes(const sockaddr_in& address) {
  std::array<std::uint8_t, 4> bytes{};
  std::copy_n(reinterpret_cast<const std::uint8_t*>(&address.sin_addr), bytes.size(), bytes.begin());
  return bytes;
}

Error MakeResolveError(int rc, std::string_view host) {
  ErrorCode code = ErrorCode::ServiceUnavailable;
  if (rc == EAI_NONAME) {
    code = ErrorCode::NotFound;
  }

  std::string message = "endpoint host '" + std::string(host) + "' could not be resolved to IPv4";
  if (rc != 0) {
    message += ": ";
    message += gai_strerror(rc);
  }
  return MakeError(code, std::move(message));
}

class StubWgTunnelEngine final : public IWgTunnelEngine {
 public:
  Error Start(const TunnelEngineStartRequest& request) override {
    if (running_) {
      return MakeError(ErrorCode::InvalidState, "WireGuard engine is already running");
    }

    const Error runtime_error = socket_runtime_.Start();
    if (runtime_error) {
      return runtime_error;
    }

    const Result<PreparedTunnelSession> resolved_session = ResolvePreparedTunnelSessionEndpoint(request.session);
    if (!resolved_session.ok()) {
      socket_runtime_.Stop();
      return resolved_session.error;
    }

    const Result<int> socket_result = socket_runtime_.OpenConnectedUdpSocket(resolved_session.value.endpoint);
    if (!socket_result.ok()) {
      socket_runtime_.Stop();
      return socket_result.error;
    }

    udp_socket_ = socket_result.value;
    active_profile_ = resolved_session.value.profile_name;
    prepared_session_ = resolved_session.value;
    stats_ = {};
    running_ = true;
    return Error::None();
  }

  Error Stop() override {
    if (!running_) {
      return Error::None();
    }

    socket_runtime_.CloseSocket(udp_socket_);
    socket_runtime_.Stop();
    udp_socket_ = -1;
    running_ = false;
    active_profile_.clear();
    prepared_session_ = {};
    stats_ = {};
    return Error::None();
  }

  TunnelStats GetStats() const override {
    return stats_;
  }

  bool IsRunning() const override {
    return running_;
  }

 private:
  BsdSocketRuntime socket_runtime_{};
  std::string active_profile_;
  PreparedTunnelSession prepared_session_{};
  TunnelStats stats_{};
  int udp_socket_ = -1;
  bool running_ = false;
};

}  // namespace

Result<PreparedTunnelSession> PrepareTunnelSession(std::string_view profile_name,
                                                   const ValidatedWireGuardProfile& profile,
                                                   RuntimeFlags runtime_flags) {
  PreparedTunnelSession session{};
  session.profile_name = std::string(profile_name);
  session.runtime_flags = runtime_flags;
  session.persistent_keepalive = profile.persistent_keepalive;
  session.has_preshared_key = profile.has_preshared_key;
  session.private_key = profile.private_key;
  session.local_public_key = profile.local_public_key;
  session.public_key = profile.public_key;
  session.static_shared_secret = profile.static_shared_secret;
  session.preshared_key = profile.preshared_key;
  session.endpoint.host = profile.endpoint.host;
  session.endpoint.port = profile.endpoint.port;

  switch (profile.endpoint.type) {
    case ParsedEndpointHostType::Hostname:
      session.endpoint.state = PreparedEndpointState::NeedsIpv4Resolution;
      break;
    case ParsedEndpointHostType::IPv4: {
      const Result<ParsedIpAddress> endpoint_address = ParseIpAddress(profile.endpoint.host, "endpoint_host");
      if (!endpoint_address.ok()) {
        return MakeFailure<PreparedTunnelSession>(endpoint_address.error.code,
                                                  "profile '" + session.profile_name +
                                                      "': endpoint_host could not be reparsed as IPv4");
      }

      session.endpoint.state = PreparedEndpointState::Ready;
      session.endpoint.ipv4 = CopyIpv4Bytes(endpoint_address.value);
      break;
    }
    case ParsedEndpointHostType::IPv6:
      return MakeFailure<PreparedTunnelSession>(ErrorCode::InvalidConfig,
                                                "profile '" + session.profile_name +
                                                    "': current Switch transport does not support IPv6 endpoints");
  }

  for (const ParsedIpNetwork& network : profile.allowed_ips) {
    if (network.address.family == ParsedIpFamily::IPv4) {
      session.allowed_ipv4_routes.push_back(PrepareIpv4Network(network));
    } else {
      ++session.ignored_ipv6_allowed_ips;
    }
  }
  if (session.allowed_ipv4_routes.empty()) {
    return MakeFailure<PreparedTunnelSession>(ErrorCode::InvalidConfig,
                                              "profile '" + session.profile_name +
                                                  "': current Switch transport requires at least one IPv4 allowed_ips entry");
  }

  for (const ParsedIpNetwork& network : profile.addresses) {
    if (network.address.family == ParsedIpFamily::IPv4) {
      session.interface_ipv4_addresses.push_back(PrepareIpv4Network(network));
    } else {
      ++session.ignored_ipv6_addresses;
    }
  }
  if (session.interface_ipv4_addresses.empty()) {
    return MakeFailure<PreparedTunnelSession>(ErrorCode::InvalidConfig,
                                              "profile '" + session.profile_name +
                                                  "': current Switch transport requires at least one IPv4 interface address");
  }

  for (const ParsedIpAddress& dns_server : profile.dns_servers) {
    if (dns_server.family == ParsedIpFamily::IPv4) {
      session.dns_servers.push_back(CopyIpv4Bytes(dns_server));
    } else {
      ++session.ignored_ipv6_dns_servers;
    }
  }

  return MakeSuccess(std::move(session));
}

Result<PreparedTunnelEndpoint> ResolvePreparedTunnelEndpoint(const PreparedTunnelEndpoint& endpoint) {
  if (endpoint.port == 0) {
    return MakeFailure<PreparedTunnelEndpoint>(ErrorCode::InvalidConfig,
                                               "prepared endpoint must not use port 0");
  }

  if (endpoint.state == PreparedEndpointState::Ready) {
    return MakeSuccess(endpoint);
  }

  if (endpoint.host.empty()) {
    return MakeFailure<PreparedTunnelEndpoint>(ErrorCode::InvalidConfig,
                                               "prepared endpoint hostname must not be empty");
  }

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  addrinfo* results = nullptr;
  const int rc = getaddrinfo(endpoint.host.c_str(), nullptr, &hints, &results);
  if (rc != 0 || results == nullptr) {
    if (results != nullptr) {
      freeaddrinfo(results);
    }
    const Error error = MakeResolveError(rc, endpoint.host);
    return Result<PreparedTunnelEndpoint>::Failure(error);
  }

  for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
    if (current->ai_family != AF_INET || current->ai_addr == nullptr ||
        current->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      continue;
    }

    PreparedTunnelEndpoint resolved = endpoint;
    resolved.state = PreparedEndpointState::Ready;
    resolved.ipv4 = CopyIpv4SockaddrBytes(*reinterpret_cast<const sockaddr_in*>(current->ai_addr));
    freeaddrinfo(results);
    return MakeSuccess(std::move(resolved));
  }

  freeaddrinfo(results);
  return MakeFailure<PreparedTunnelEndpoint>(ErrorCode::NotFound,
                                             "endpoint host '" + endpoint.host +
                                                 "' did not return an IPv4 address");
}

Result<PreparedTunnelSession> ResolvePreparedTunnelSessionEndpoint(const PreparedTunnelSession& session) {
  const Result<PreparedTunnelEndpoint> resolved_endpoint = ResolvePreparedTunnelEndpoint(session.endpoint);
  if (!resolved_endpoint.ok()) {
    return MakeFailure<PreparedTunnelSession>(resolved_endpoint.error.code, resolved_endpoint.error.message);
  }

  PreparedTunnelSession resolved = session;
  resolved.endpoint = resolved_endpoint.value;
  return MakeSuccess(std::move(resolved));
}

std::string DescribePreparedTunnelSession(const PreparedTunnelSession& session) {
  std::ostringstream stream;
  stream << "profile=" << session.profile_name << ", endpoint=" << session.endpoint.host << ':' << session.endpoint.port
         << ", endpoint_state="
         << (session.endpoint.state == PreparedEndpointState::Ready ? "ready" : "needs_ipv4_resolution")
         << ", ipv4_allowed=" << session.allowed_ipv4_routes.size()
         << ", ipv4_addresses=" << session.interface_ipv4_addresses.size() << ", dns=" << session.dns_servers.size();

  if (session.ignored_ipv6_allowed_ips != 0 || session.ignored_ipv6_addresses != 0 ||
      session.ignored_ipv6_dns_servers != 0) {
    stream << ", ignored_ipv6={allowed:" << session.ignored_ipv6_allowed_ips
           << ", address:" << session.ignored_ipv6_addresses << ", dns:" << session.ignored_ipv6_dns_servers
           << '}';
  }

  return stream.str();
}

std::unique_ptr<IWgTunnelEngine> CreateStubWgTunnelEngine() {
  return std::make_unique<StubWgTunnelEngine>();
}

}  // namespace swg::sysmodule