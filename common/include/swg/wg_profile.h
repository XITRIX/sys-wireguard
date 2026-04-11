#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "swg/config.h"
#include "swg/result.h"

namespace swg {

inline constexpr std::size_t kWireGuardKeySize = 32;

struct WireGuardKey {
  std::array<std::uint8_t, kWireGuardKeySize> bytes{};
};

enum class ParsedIpFamily : std::uint32_t {
  IPv4 = 0,
  IPv6,
};

enum class ParsedEndpointHostType : std::uint32_t {
  Hostname = 0,
  IPv4,
  IPv6,
};

struct ParsedIpAddress {
  ParsedIpFamily family = ParsedIpFamily::IPv4;
  std::array<std::uint8_t, 16> bytes{};
  std::string normalized;
};

struct ParsedIpNetwork {
  ParsedIpAddress address;
  std::uint8_t prefix_length = 0;
  std::string normalized;
};

struct ParsedEndpoint {
  ParsedEndpointHostType type = ParsedEndpointHostType::Hostname;
  std::string host;
  std::uint16_t port = 0;
};

struct ValidatedWireGuardProfile {
  std::string name;
  ParsedEndpoint endpoint;
  std::vector<ParsedIpNetwork> allowed_ips;
  std::vector<ParsedIpNetwork> addresses;
  std::vector<ParsedIpAddress> dns_servers;
  std::uint16_t persistent_keepalive = 0;
  bool has_preshared_key = false;
  WireGuardKey private_key{};
  WireGuardKey public_key{};
  WireGuardKey preshared_key{};
};

Result<ParsedIpAddress> ParseIpAddress(std::string_view input, std::string_view field_name);
Result<ParsedIpNetwork> ParseIpNetwork(std::string_view input, std::string_view field_name);
Result<ParsedEndpoint> ParseEndpoint(std::string_view host, std::uint16_t port,
                                     std::string_view field_name = "endpoint_host");
Result<WireGuardKey> ParseWireGuardKey(std::string_view encoded, std::string_view field_name);
Result<ValidatedWireGuardProfile> ValidateWireGuardProfileForConnect(const ProfileConfig& profile);

}  // namespace swg