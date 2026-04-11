#include "swg_sysmodule/wg_engine.h"

#include <algorithm>
#include <sstream>

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

class StubWgTunnelEngine final : public IWgTunnelEngine {
 public:
  Error Start(const TunnelEngineStartRequest& request) override {
    if (running_) {
      return MakeError(ErrorCode::InvalidState, "WireGuard engine is already running");
    }

    active_profile_ = request.session.profile_name;
    prepared_session_ = request.session;
    stats_ = {};
    running_ = true;
    return Error::None();
  }

  Error Stop() override {
    if (!running_) {
      return Error::None();
    }

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
  std::string active_profile_;
  PreparedTunnelSession prepared_session_{};
  TunnelStats stats_{};
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
  session.public_key = profile.public_key;
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