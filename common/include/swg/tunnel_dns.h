#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "swg/ipv4_udp.h"
#include "swg/result.h"

namespace swg {

struct TunnelDnsPacketEndpoint {
  std::array<std::uint8_t, 4> source_ipv4{};
  std::array<std::uint8_t, 4> destination_ipv4{};
  std::uint16_t source_port = 0;
  std::uint16_t destination_port = 53;
};

struct TunnelDnsResponse {
  std::uint16_t query_id = 0;
  std::array<std::uint8_t, 4> source_ipv4{};
  std::array<std::uint8_t, 4> destination_ipv4{};
  std::uint16_t source_port = 0;
  std::uint16_t destination_port = 0;
  bool truncated = false;
  std::uint8_t rcode = 0;
  std::vector<std::string> ipv4_addresses;
};

Result<std::vector<std::uint8_t>> BuildTunnelDnsQueryPacket(const TunnelDnsPacketEndpoint& endpoint,
                                                            std::string_view hostname,
                                                            std::uint16_t query_id);
Result<std::vector<std::uint8_t>> BuildTunnelDnsResponsePacket(const TunnelDnsPacketEndpoint& endpoint,
                                                               std::string_view hostname,
                                                               std::uint16_t query_id,
                                                               const std::vector<std::string>& ipv4_addresses,
                                                               std::uint8_t rcode = 0);
Result<TunnelDnsResponse> ParseTunnelDnsResponsePacket(const std::vector<std::uint8_t>& packet);

}  // namespace swg