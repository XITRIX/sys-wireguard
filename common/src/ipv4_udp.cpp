#include "swg/ipv4_udp.h"

#include <algorithm>

namespace swg {
namespace {

constexpr std::size_t kIpv4HeaderSize = 20;
constexpr std::size_t kUdpHeaderSize = 8;

std::uint16_t Load16Be(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
}

std::uint16_t ComputeIpv4HeaderChecksum(const std::uint8_t* bytes, std::size_t size) {
  std::uint32_t sum = 0;
  for (std::size_t index = 0; index + 1 < size; index += 2) {
    sum += static_cast<std::uint32_t>((bytes[index] << 8) | bytes[index + 1]);
  }

  while ((sum >> 16) != 0) {
    sum = (sum & 0xffffu) + (sum >> 16);
  }

  return static_cast<std::uint16_t>(~sum & 0xffffu);
}

}  // namespace

std::string FormatIpv4Address(const std::array<std::uint8_t, 4>& ipv4) {
  return std::to_string(ipv4[0]) + '.' + std::to_string(ipv4[1]) + '.' + std::to_string(ipv4[2]) + '.' +
         std::to_string(ipv4[3]);
}

Result<std::vector<std::uint8_t>> BuildIpv4UdpPacket(const Ipv4UdpPacketEndpoint& endpoint,
                                                     const std::vector<std::uint8_t>& payload) {
  if (endpoint.source_port == 0 || endpoint.destination_port == 0) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::ParseError, "udp packet ports must not be zero");
  }

  if (payload.size() > 65507) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::Unsupported,
                                                  "udp payload exceeds the IPv4 maximum datagram size");
  }

  const std::uint16_t udp_length = static_cast<std::uint16_t>(kUdpHeaderSize + payload.size());
  const std::uint16_t total_length = static_cast<std::uint16_t>(kIpv4HeaderSize + udp_length);

  std::vector<std::uint8_t> packet(kIpv4HeaderSize + kUdpHeaderSize + payload.size(), 0);
  packet[0] = 0x45;
  packet[1] = 0;
  packet[2] = static_cast<std::uint8_t>((total_length >> 8) & 0xffu);
  packet[3] = static_cast<std::uint8_t>(total_length & 0xffu);
  packet[4] = static_cast<std::uint8_t>((endpoint.source_port >> 8) & 0xffu);
  packet[5] = static_cast<std::uint8_t>(endpoint.source_port & 0xffu);
  packet[6] = 0x40;
  packet[7] = 0x00;
  packet[8] = 64;
  packet[9] = 17;
  std::copy(endpoint.source_ipv4.begin(), endpoint.source_ipv4.end(), packet.begin() + static_cast<std::ptrdiff_t>(12));
  std::copy(endpoint.destination_ipv4.begin(), endpoint.destination_ipv4.end(),
            packet.begin() + static_cast<std::ptrdiff_t>(16));
  const std::uint16_t checksum = ComputeIpv4HeaderChecksum(packet.data(), kIpv4HeaderSize);
  packet[10] = static_cast<std::uint8_t>((checksum >> 8) & 0xffu);
  packet[11] = static_cast<std::uint8_t>(checksum & 0xffu);

  const std::size_t udp_offset = kIpv4HeaderSize;
  packet[udp_offset + 0] = static_cast<std::uint8_t>((endpoint.source_port >> 8) & 0xffu);
  packet[udp_offset + 1] = static_cast<std::uint8_t>(endpoint.source_port & 0xffu);
  packet[udp_offset + 2] = static_cast<std::uint8_t>((endpoint.destination_port >> 8) & 0xffu);
  packet[udp_offset + 3] = static_cast<std::uint8_t>(endpoint.destination_port & 0xffu);
  packet[udp_offset + 4] = static_cast<std::uint8_t>((udp_length >> 8) & 0xffu);
  packet[udp_offset + 5] = static_cast<std::uint8_t>(udp_length & 0xffu);
  packet[udp_offset + 6] = 0;
  packet[udp_offset + 7] = 0;
  std::copy(payload.begin(), payload.end(), packet.begin() + static_cast<std::ptrdiff_t>(udp_offset + kUdpHeaderSize));
  return MakeSuccess(std::move(packet));
}

Result<Ipv4UdpPacket> ParseIpv4UdpPacket(const std::vector<std::uint8_t>& packet) {
  if (packet.size() < kIpv4HeaderSize + kUdpHeaderSize) {
    return MakeFailure<Ipv4UdpPacket>(ErrorCode::ParseError, "udp packet is too short");
  }
  if ((packet[0] >> 4) != 4) {
    return MakeFailure<Ipv4UdpPacket>(ErrorCode::ParseError, "udp packet is not IPv4");
  }

  const std::size_t ipv4_header_size = static_cast<std::size_t>(packet[0] & 0x0fu) * 4;
  if (ipv4_header_size < kIpv4HeaderSize || packet.size() < ipv4_header_size + kUdpHeaderSize) {
    return MakeFailure<Ipv4UdpPacket>(ErrorCode::ParseError, "udp packet has an invalid IPv4 header size");
  }

  const std::uint16_t total_length = Load16Be(packet.data() + 2);
  if (total_length < ipv4_header_size + kUdpHeaderSize || total_length > packet.size()) {
    return MakeFailure<Ipv4UdpPacket>(ErrorCode::ParseError, "udp packet has an invalid IPv4 total length");
  }
  if (packet[9] != 17) {
    return MakeFailure<Ipv4UdpPacket>(ErrorCode::ParseError, "udp packet is not UDP");
  }

  const std::size_t udp_offset = ipv4_header_size;
  const std::uint16_t udp_length = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(udp_offset + 4));
  if (udp_length < kUdpHeaderSize || udp_offset + udp_length > total_length) {
    return MakeFailure<Ipv4UdpPacket>(ErrorCode::ParseError, "udp packet has an invalid UDP length");
  }

  Ipv4UdpPacket parsed{};
  parsed.endpoint.source_port = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(udp_offset));
  parsed.endpoint.destination_port = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(udp_offset + 2));
  std::copy(packet.begin() + static_cast<std::ptrdiff_t>(12),
            packet.begin() + static_cast<std::ptrdiff_t>(16), parsed.endpoint.source_ipv4.begin());
  std::copy(packet.begin() + static_cast<std::ptrdiff_t>(16),
            packet.begin() + static_cast<std::ptrdiff_t>(20), parsed.endpoint.destination_ipv4.begin());
  parsed.payload.assign(packet.begin() + static_cast<std::ptrdiff_t>(udp_offset + kUdpHeaderSize),
                        packet.begin() + static_cast<std::ptrdiff_t>(udp_offset + udp_length));
  return MakeSuccess(std::move(parsed));
}

}  // namespace swg