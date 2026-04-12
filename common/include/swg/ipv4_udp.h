#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "swg/result.h"

namespace swg {

struct Ipv4UdpPacketEndpoint {
  std::array<std::uint8_t, 4> source_ipv4{};
  std::array<std::uint8_t, 4> destination_ipv4{};
  std::uint16_t source_port = 0;
  std::uint16_t destination_port = 0;
};

struct Ipv4UdpPacket {
  Ipv4UdpPacketEndpoint endpoint;
  std::vector<std::uint8_t> payload;
};

std::string FormatIpv4Address(const std::array<std::uint8_t, 4>& ipv4);
Result<std::vector<std::uint8_t>> BuildIpv4UdpPacket(const Ipv4UdpPacketEndpoint& endpoint,
                                                     const std::vector<std::uint8_t>& payload);
Result<Ipv4UdpPacket> ParseIpv4UdpPacket(const std::vector<std::uint8_t>& packet);

}  // namespace swg