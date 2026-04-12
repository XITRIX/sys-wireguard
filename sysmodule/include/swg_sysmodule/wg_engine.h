#pragma once

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "swg/ipc_protocol.h"
#include "swg/result.h"
#include "swg/wg_profile.h"

namespace swg::sysmodule {

enum class PreparedEndpointState : std::uint32_t {
  Ready = 0,
  NeedsIpv4Resolution,
};

struct PreparedIpv4Network {
  std::array<std::uint8_t, 4> address{};
  std::uint8_t prefix_length = 0;
  std::string normalized;
};

struct PreparedTunnelEndpoint {
  PreparedEndpointState state = PreparedEndpointState::NeedsIpv4Resolution;
  std::string host;
  std::array<std::uint8_t, 4> ipv4{};
  std::uint16_t port = 0;
};

struct PreparedTunnelSession {
  std::string profile_name;
  PreparedTunnelEndpoint endpoint;
  std::vector<PreparedIpv4Network> allowed_ipv4_routes;
  std::vector<PreparedIpv4Network> interface_ipv4_addresses;
  std::vector<std::array<std::uint8_t, 4>> dns_servers;
  std::uint32_t ignored_ipv6_allowed_ips = 0;
  std::uint32_t ignored_ipv6_addresses = 0;
  std::uint32_t ignored_ipv6_dns_servers = 0;
  std::uint16_t persistent_keepalive = 0;
  RuntimeFlags runtime_flags = 0;
  bool has_preshared_key = false;
  WireGuardKey private_key{};
  WireGuardKey local_public_key{};
  WireGuardKey public_key{};
  WireGuardKey static_shared_secret{};
  WireGuardKey preshared_key{};
};

struct TunnelEngineStartRequest {
  PreparedTunnelSession session;
};

Result<PreparedTunnelSession> PrepareTunnelSession(std::string_view profile_name,
                                                   const ValidatedWireGuardProfile& profile,
                                                   RuntimeFlags runtime_flags);
Result<PreparedTunnelEndpoint> ResolvePreparedTunnelEndpoint(const PreparedTunnelEndpoint& endpoint);
Result<PreparedTunnelSession> ResolvePreparedTunnelSessionEndpoint(const PreparedTunnelSession& session);
std::string DescribePreparedTunnelSession(const PreparedTunnelSession& session);

class IWgTunnelEngine {
 public:
  virtual ~IWgTunnelEngine() = default;

  virtual Error Start(const TunnelEngineStartRequest& request) = 0;
  virtual Error Stop() = 0;
  [[nodiscard]] virtual TunnelStats GetStats() const = 0;
  [[nodiscard]] virtual bool IsRunning() const = 0;
};

std::unique_ptr<IWgTunnelEngine> CreateWgTunnelEngine();

}  // namespace swg::sysmodule