#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "swg/result.h"

namespace swg {

enum class TcpControlFlag : std::uint16_t {
  Fin = 0x01,
  Syn = 0x02,
  Rst = 0x04,
  Psh = 0x08,
  Ack = 0x10,
};

using TcpControlFlags = std::uint16_t;

inline constexpr TcpControlFlags ToFlags(TcpControlFlag flag) {
  return static_cast<TcpControlFlags>(flag);
}

inline constexpr bool HasFlag(TcpControlFlags flags, TcpControlFlag flag) {
  return (flags & ToFlags(flag)) != 0;
}

struct Ipv4TcpPacketEndpoint {
  std::array<std::uint8_t, 4> source_ipv4{};
  std::array<std::uint8_t, 4> destination_ipv4{};
  std::uint16_t source_port = 0;
  std::uint16_t destination_port = 0;
};

struct Ipv4TcpPacket {
  Ipv4TcpPacketEndpoint endpoint;
  std::uint32_t sequence_number = 0;
  std::uint32_t acknowledgment_number = 0;
  TcpControlFlags flags = 0;
  std::uint16_t window_size = 0xffffu;
  std::vector<std::uint8_t> payload;
};

Result<std::vector<std::uint8_t>> BuildIpv4TcpPacket(const Ipv4TcpPacket& packet);
Result<Ipv4TcpPacket> ParseIpv4TcpPacket(const std::vector<std::uint8_t>& packet);

}  // namespace swg
