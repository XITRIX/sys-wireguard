#include "swg/ipv4_tcp.h"

#include <algorithm>

namespace swg {
namespace {

constexpr std::size_t kIpv4HeaderSize = 20;
constexpr std::size_t kTcpHeaderSize = 20;

void Store16Be(std::vector<std::uint8_t>* bytes, std::uint16_t value) {
  bytes->push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>(value & 0xffu));
}

void Store32Be(std::vector<std::uint8_t>* bytes, std::uint32_t value) {
  bytes->push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>(value & 0xffu));
}

std::uint16_t Load16Be(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
}

std::uint32_t Load32Be(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) |
         static_cast<std::uint32_t>(bytes[3]);
}

std::uint16_t ComputeChecksum(const std::uint8_t* bytes, std::size_t size) {
  std::uint32_t sum = 0;
  std::size_t index = 0;
  while (index + 1 < size) {
    sum += static_cast<std::uint32_t>((bytes[index] << 8) | bytes[index + 1]);
    index += 2;
  }
  if (index < size) {
    sum += static_cast<std::uint32_t>(bytes[index] << 8);
  }

  while ((sum >> 16) != 0) {
    sum = (sum & 0xffffu) + (sum >> 16);
  }

  return static_cast<std::uint16_t>(~sum & 0xffffu);
}

std::uint16_t ComputeTcpChecksum(const Ipv4TcpPacket& packet,
                                 const std::vector<std::uint8_t>& tcp_segment) {
  std::vector<std::uint8_t> pseudo_header;
  pseudo_header.reserve(12 + tcp_segment.size());
  pseudo_header.insert(pseudo_header.end(), packet.endpoint.source_ipv4.begin(), packet.endpoint.source_ipv4.end());
  pseudo_header.insert(pseudo_header.end(), packet.endpoint.destination_ipv4.begin(), packet.endpoint.destination_ipv4.end());
  pseudo_header.push_back(0);
  pseudo_header.push_back(6);
  Store16Be(&pseudo_header, static_cast<std::uint16_t>(tcp_segment.size()));
  pseudo_header.insert(pseudo_header.end(), tcp_segment.begin(), tcp_segment.end());
  return ComputeChecksum(pseudo_header.data(), pseudo_header.size());
}

}  // namespace

Result<std::vector<std::uint8_t>> BuildIpv4TcpPacket(const Ipv4TcpPacket& packet) {
  if (packet.endpoint.source_port == 0 || packet.endpoint.destination_port == 0) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::ParseError, "tcp packet ports must not be zero");
  }

  if (packet.payload.size() > 65515u) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::Unsupported,
                                                  "tcp payload exceeds the IPv4 maximum segment size");
  }

  const std::uint16_t tcp_length = static_cast<std::uint16_t>(kTcpHeaderSize + packet.payload.size());
  const std::uint16_t total_length = static_cast<std::uint16_t>(kIpv4HeaderSize + tcp_length);

  std::vector<std::uint8_t> bytes;
  bytes.reserve(total_length);
  bytes.resize(kIpv4HeaderSize, 0);
  bytes[0] = 0x45;
  bytes[2] = static_cast<std::uint8_t>((total_length >> 8) & 0xffu);
  bytes[3] = static_cast<std::uint8_t>(total_length & 0xffu);
  bytes[6] = 0x40;
  bytes[8] = 64;
  bytes[9] = 6;
  std::copy(packet.endpoint.source_ipv4.begin(), packet.endpoint.source_ipv4.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(12));
  std::copy(packet.endpoint.destination_ipv4.begin(), packet.endpoint.destination_ipv4.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(16));
  const std::uint16_t ipv4_checksum = ComputeChecksum(bytes.data(), kIpv4HeaderSize);
  bytes[10] = static_cast<std::uint8_t>((ipv4_checksum >> 8) & 0xffu);
  bytes[11] = static_cast<std::uint8_t>(ipv4_checksum & 0xffu);

  std::vector<std::uint8_t> tcp_segment;
  tcp_segment.reserve(tcp_length);
  Store16Be(&tcp_segment, packet.endpoint.source_port);
  Store16Be(&tcp_segment, packet.endpoint.destination_port);
  Store32Be(&tcp_segment, packet.sequence_number);
  Store32Be(&tcp_segment, packet.acknowledgment_number);
  tcp_segment.push_back(static_cast<std::uint8_t>((5u << 4) & 0xf0u));
  tcp_segment.push_back(static_cast<std::uint8_t>(packet.flags & 0x3fu));
  Store16Be(&tcp_segment, packet.window_size);
  Store16Be(&tcp_segment, 0);
  Store16Be(&tcp_segment, 0);
  tcp_segment.insert(tcp_segment.end(), packet.payload.begin(), packet.payload.end());
  const std::uint16_t tcp_checksum = ComputeTcpChecksum(packet, tcp_segment);
  tcp_segment[16] = static_cast<std::uint8_t>((tcp_checksum >> 8) & 0xffu);
  tcp_segment[17] = static_cast<std::uint8_t>(tcp_checksum & 0xffu);

  bytes.insert(bytes.end(), tcp_segment.begin(), tcp_segment.end());
  return MakeSuccess(std::move(bytes));
}

Result<Ipv4TcpPacket> ParseIpv4TcpPacket(const std::vector<std::uint8_t>& packet) {
  if (packet.size() < kIpv4HeaderSize + kTcpHeaderSize) {
    return MakeFailure<Ipv4TcpPacket>(ErrorCode::ParseError, "tcp packet is too short");
  }
  if ((packet[0] >> 4) != 4) {
    return MakeFailure<Ipv4TcpPacket>(ErrorCode::ParseError, "tcp packet is not IPv4");
  }

  const std::size_t ipv4_header_size = static_cast<std::size_t>(packet[0] & 0x0fu) * 4;
  if (ipv4_header_size < kIpv4HeaderSize || packet.size() < ipv4_header_size + kTcpHeaderSize) {
    return MakeFailure<Ipv4TcpPacket>(ErrorCode::ParseError, "tcp packet has an invalid IPv4 header size");
  }

  const std::uint16_t total_length = Load16Be(packet.data() + 2);
  if (total_length < ipv4_header_size + kTcpHeaderSize || total_length > packet.size()) {
    return MakeFailure<Ipv4TcpPacket>(ErrorCode::ParseError, "tcp packet has an invalid IPv4 total length");
  }
  if (packet[9] != 6) {
    return MakeFailure<Ipv4TcpPacket>(ErrorCode::ParseError, "tcp packet is not TCP");
  }

  const std::size_t tcp_offset = ipv4_header_size;
  const std::size_t tcp_header_size = static_cast<std::size_t>((packet[tcp_offset + 12] >> 4) & 0x0fu) * 4;
  if (tcp_header_size < kTcpHeaderSize || tcp_offset + tcp_header_size > total_length) {
    return MakeFailure<Ipv4TcpPacket>(ErrorCode::ParseError, "tcp packet has an invalid TCP header size");
  }

  Ipv4TcpPacket parsed{};
  std::copy(packet.begin() + static_cast<std::ptrdiff_t>(12),
            packet.begin() + static_cast<std::ptrdiff_t>(16), parsed.endpoint.source_ipv4.begin());
  std::copy(packet.begin() + static_cast<std::ptrdiff_t>(16),
            packet.begin() + static_cast<std::ptrdiff_t>(20), parsed.endpoint.destination_ipv4.begin());
  parsed.endpoint.source_port = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(tcp_offset));
  parsed.endpoint.destination_port = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(tcp_offset + 2));
  parsed.sequence_number = Load32Be(packet.data() + static_cast<std::ptrdiff_t>(tcp_offset + 4));
  parsed.acknowledgment_number = Load32Be(packet.data() + static_cast<std::ptrdiff_t>(tcp_offset + 8));
  parsed.flags = static_cast<TcpControlFlags>(packet[tcp_offset + 13] & 0x3fu);
  parsed.window_size = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(tcp_offset + 14));
  parsed.payload.assign(packet.begin() + static_cast<std::ptrdiff_t>(tcp_offset + tcp_header_size),
                        packet.begin() + static_cast<std::ptrdiff_t>(total_length));
  return MakeSuccess(std::move(parsed));
}

}  // namespace swg
