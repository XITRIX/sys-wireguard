#include "swg/tunnel_dns.h"

#include <algorithm>

#include "swg/wg_profile.h"

namespace swg {
namespace {

constexpr std::size_t kIpv4HeaderSize = 20;
constexpr std::size_t kUdpHeaderSize = 8;
constexpr std::size_t kDnsHeaderSize = 12;
constexpr std::uint16_t kDnsClassIn = 1;
constexpr std::uint16_t kDnsTypeA = 1;
constexpr std::uint16_t kDnsFlagsQueryRecursionDesired = 0x0100;
constexpr std::uint16_t kDnsFlagsResponse = 0x8000;
constexpr std::uint16_t kDnsFlagsRecursionAvailable = 0x0080;
constexpr std::uint16_t kDnsFlagsTruncated = 0x0200;

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

Error AppendDnsName(std::string_view hostname, std::vector<std::uint8_t>* output) {
  if (hostname.empty()) {
    return MakeError(ErrorCode::ParseError, "dns hostname must not be empty");
  }

  std::string normalized(hostname);
  if (!normalized.empty() && normalized.back() == '.') {
    normalized.pop_back();
  }
  if (normalized.empty()) {
    return MakeError(ErrorCode::ParseError, "dns hostname must not be empty");
  }

  std::size_t cursor = 0;
  while (cursor < normalized.size()) {
    const std::size_t dot = normalized.find('.', cursor);
    const std::size_t end = dot == std::string::npos ? normalized.size() : dot;
    const std::size_t length = end - cursor;
    if (length == 0 || length > 63) {
      return MakeError(ErrorCode::ParseError, "dns hostname contains an invalid label length");
    }

    output->push_back(static_cast<std::uint8_t>(length));
    output->insert(output->end(), normalized.begin() + static_cast<std::ptrdiff_t>(cursor),
                   normalized.begin() + static_cast<std::ptrdiff_t>(end));
    cursor = end == normalized.size() ? normalized.size() : end + 1;
  }

  output->push_back(0);
  return Error::None();
}

Result<std::vector<std::uint8_t>> BuildDnsQuestion(std::string_view hostname, std::uint16_t query_id) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(kDnsHeaderSize + hostname.size() + 8);

  Store16Be(&bytes, query_id);
  Store16Be(&bytes, kDnsFlagsQueryRecursionDesired);
  Store16Be(&bytes, 1);
  Store16Be(&bytes, 0);
  Store16Be(&bytes, 0);
  Store16Be(&bytes, 0);

  const Error name_error = AppendDnsName(hostname, &bytes);
  if (name_error) {
    return MakeFailure<std::vector<std::uint8_t>>(name_error.code, name_error.message);
  }

  Store16Be(&bytes, kDnsTypeA);
  Store16Be(&bytes, kDnsClassIn);
  return MakeSuccess(std::move(bytes));
}

Result<std::vector<std::uint8_t>> WrapIpv4UdpPayload(const TunnelDnsPacketEndpoint& endpoint,
                                                     const std::vector<std::uint8_t>& udp_payload,
                                                     bool reverse_flow) {
  if (endpoint.source_port == 0 || endpoint.destination_port == 0) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::ParseError,
                                                  "dns packet ports must not be zero");
  }

  const auto& source_ipv4 = reverse_flow ? endpoint.destination_ipv4 : endpoint.source_ipv4;
  const auto& destination_ipv4 = reverse_flow ? endpoint.source_ipv4 : endpoint.destination_ipv4;
  const std::uint16_t source_port = reverse_flow ? endpoint.destination_port : endpoint.source_port;
  const std::uint16_t destination_port = reverse_flow ? endpoint.source_port : endpoint.destination_port;
  const std::uint16_t udp_length = static_cast<std::uint16_t>(kUdpHeaderSize + udp_payload.size());
  const std::uint16_t total_length = static_cast<std::uint16_t>(kIpv4HeaderSize + udp_length);

  std::vector<std::uint8_t> packet(kIpv4HeaderSize + kUdpHeaderSize + udp_payload.size(), 0);
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
  std::copy(source_ipv4.begin(), source_ipv4.end(), packet.begin() + static_cast<std::ptrdiff_t>(12));
  std::copy(destination_ipv4.begin(), destination_ipv4.end(), packet.begin() + static_cast<std::ptrdiff_t>(16));
  const std::uint16_t checksum = ComputeIpv4HeaderChecksum(packet.data(), kIpv4HeaderSize);
  packet[10] = static_cast<std::uint8_t>((checksum >> 8) & 0xffu);
  packet[11] = static_cast<std::uint8_t>(checksum & 0xffu);

  const std::size_t udp_offset = kIpv4HeaderSize;
  packet[udp_offset + 0] = static_cast<std::uint8_t>((source_port >> 8) & 0xffu);
  packet[udp_offset + 1] = static_cast<std::uint8_t>(source_port & 0xffu);
  packet[udp_offset + 2] = static_cast<std::uint8_t>((destination_port >> 8) & 0xffu);
  packet[udp_offset + 3] = static_cast<std::uint8_t>(destination_port & 0xffu);
  packet[udp_offset + 4] = static_cast<std::uint8_t>((udp_length >> 8) & 0xffu);
  packet[udp_offset + 5] = static_cast<std::uint8_t>(udp_length & 0xffu);
  packet[udp_offset + 6] = 0;
  packet[udp_offset + 7] = 0;
  std::copy(udp_payload.begin(), udp_payload.end(), packet.begin() + static_cast<std::ptrdiff_t>(udp_offset + kUdpHeaderSize));
  return MakeSuccess(std::move(packet));
}

Result<std::size_t> SkipDnsName(const std::uint8_t* bytes, std::size_t size, std::size_t offset) {
  std::size_t cursor = offset;
  while (cursor < size) {
    const std::uint8_t length = bytes[cursor];
    if ((length & 0xc0u) == 0xc0u) {
      if (cursor + 1 >= size) {
        return MakeFailure<std::size_t>(ErrorCode::ParseError, "dns name pointer overruns the response");
      }
      return MakeSuccess(cursor + 2);
    }
    if ((length & 0xc0u) != 0) {
      return MakeFailure<std::size_t>(ErrorCode::ParseError, "dns name uses an unsupported label encoding");
    }

    ++cursor;
    if (length == 0) {
      return MakeSuccess(cursor);
    }
    if (cursor + length > size) {
      return MakeFailure<std::size_t>(ErrorCode::ParseError, "dns label overruns the response");
    }
    cursor += length;
  }

  return MakeFailure<std::size_t>(ErrorCode::ParseError, "dns name overruns the response");
}

}  // namespace

std::string FormatIpv4Address(const std::array<std::uint8_t, 4>& ipv4) {
  return std::to_string(ipv4[0]) + '.' + std::to_string(ipv4[1]) + '.' + std::to_string(ipv4[2]) + '.' +
         std::to_string(ipv4[3]);
}

Result<std::vector<std::uint8_t>> BuildTunnelDnsQueryPacket(const TunnelDnsPacketEndpoint& endpoint,
                                                            std::string_view hostname,
                                                            std::uint16_t query_id) {
  const Result<std::vector<std::uint8_t>> dns_question = BuildDnsQuestion(hostname, query_id);
  if (!dns_question.ok()) {
    return MakeFailure<std::vector<std::uint8_t>>(dns_question.error.code, dns_question.error.message);
  }

  return WrapIpv4UdpPayload(endpoint, dns_question.value, false);
}

Result<std::vector<std::uint8_t>> BuildTunnelDnsResponsePacket(const TunnelDnsPacketEndpoint& endpoint,
                                                               std::string_view hostname,
                                                               std::uint16_t query_id,
                                                               const std::vector<std::string>& ipv4_addresses,
                                                               std::uint8_t rcode) {
  std::vector<std::uint8_t> dns_payload;
  dns_payload.reserve(kDnsHeaderSize + hostname.size() + 8 + (ipv4_addresses.size() * 16));

  Store16Be(&dns_payload, query_id);
  Store16Be(&dns_payload, static_cast<std::uint16_t>(kDnsFlagsResponse | kDnsFlagsRecursionAvailable | (rcode & 0x0fu)));
  Store16Be(&dns_payload, 1);
  Store16Be(&dns_payload, rcode == 0 ? static_cast<std::uint16_t>(ipv4_addresses.size()) : 0);
  Store16Be(&dns_payload, 0);
  Store16Be(&dns_payload, 0);

  const Error name_error = AppendDnsName(hostname, &dns_payload);
  if (name_error) {
    return MakeFailure<std::vector<std::uint8_t>>(name_error.code, name_error.message);
  }
  Store16Be(&dns_payload, kDnsTypeA);
  Store16Be(&dns_payload, kDnsClassIn);

  if (rcode == 0) {
    for (const std::string& address_text : ipv4_addresses) {
      const Result<ParsedIpAddress> parsed = ParseIpAddress(address_text, "dns_answer");
      if (!parsed.ok()) {
        return MakeFailure<std::vector<std::uint8_t>>(parsed.error.code, parsed.error.message);
      }
      if (parsed.value.family != ParsedIpFamily::IPv4) {
        return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::ParseError,
                                                      "dns answers currently support only IPv4 literals");
      }

      Store16Be(&dns_payload, 0xc00c);
      Store16Be(&dns_payload, kDnsTypeA);
      Store16Be(&dns_payload, kDnsClassIn);
      Store32Be(&dns_payload, 60);
      Store16Be(&dns_payload, 4);
      dns_payload.insert(dns_payload.end(), parsed.value.bytes.begin(), parsed.value.bytes.begin() + 4);
    }
  }

  return WrapIpv4UdpPayload(endpoint, dns_payload, true);
}

Result<TunnelDnsResponse> ParseTunnelDnsResponsePacket(const std::vector<std::uint8_t>& packet) {
  if (packet.size() < kIpv4HeaderSize + kUdpHeaderSize + kDnsHeaderSize) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet is too short");
  }
  if ((packet[0] >> 4) != 4) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet is not IPv4");
  }

  const std::size_t ipv4_header_size = static_cast<std::size_t>(packet[0] & 0x0fu) * 4;
  if (ipv4_header_size < kIpv4HeaderSize || packet.size() < ipv4_header_size + kUdpHeaderSize + kDnsHeaderSize) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet has an invalid IPv4 header size");
  }

  const std::uint16_t total_length = Load16Be(packet.data() + 2);
  if (total_length < ipv4_header_size + kUdpHeaderSize + kDnsHeaderSize || total_length > packet.size()) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet has an invalid IPv4 total length");
  }
  if (packet[9] != 17) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet is not UDP");
  }

  const std::size_t udp_offset = ipv4_header_size;
  const std::uint16_t udp_length = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(udp_offset + 4));
  if (udp_length < kUdpHeaderSize + kDnsHeaderSize || udp_offset + udp_length > total_length) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet has an invalid UDP length");
  }

  const std::size_t dns_offset = udp_offset + kUdpHeaderSize;
  const std::size_t dns_size = udp_length - kUdpHeaderSize;
  const std::uint8_t* dns = packet.data() + static_cast<std::ptrdiff_t>(dns_offset);

  const std::uint16_t flags = Load16Be(dns + 2);
  if ((flags & kDnsFlagsResponse) == 0) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns packet is not a response");
  }

  TunnelDnsResponse response{};
  response.query_id = Load16Be(dns);
  response.source_port = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(udp_offset));
  response.destination_port = Load16Be(packet.data() + static_cast<std::ptrdiff_t>(udp_offset + 2));
  std::copy(packet.begin() + static_cast<std::ptrdiff_t>(12),
            packet.begin() + static_cast<std::ptrdiff_t>(16), response.source_ipv4.begin());
  std::copy(packet.begin() + static_cast<std::ptrdiff_t>(16),
            packet.begin() + static_cast<std::ptrdiff_t>(20), response.destination_ipv4.begin());
  response.truncated = (flags & kDnsFlagsTruncated) != 0;
  response.rcode = static_cast<std::uint8_t>(flags & 0x0fu);

  const std::uint16_t question_count = Load16Be(dns + 4);
  const std::uint16_t answer_count = Load16Be(dns + 6);
  std::size_t cursor = kDnsHeaderSize;

  for (std::uint16_t index = 0; index < question_count; ++index) {
    const Result<std::size_t> name_end = SkipDnsName(dns, dns_size, cursor);
    if (!name_end.ok()) {
      return MakeFailure<TunnelDnsResponse>(name_end.error.code, name_end.error.message);
    }
    cursor = name_end.value;
    if (cursor + 4 > dns_size) {
      return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns question overruns the response");
    }
    cursor += 4;
  }

  for (std::uint16_t index = 0; index < answer_count; ++index) {
    const Result<std::size_t> name_end = SkipDnsName(dns, dns_size, cursor);
    if (!name_end.ok()) {
      return MakeFailure<TunnelDnsResponse>(name_end.error.code, name_end.error.message);
    }
    cursor = name_end.value;
    if (cursor + 10 > dns_size) {
      return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns answer header overruns the response");
    }

    const std::uint16_t type = Load16Be(dns + cursor);
    const std::uint16_t klass = Load16Be(dns + cursor + 2);
    const std::uint16_t rdlength = Load16Be(dns + cursor + 8);
    cursor += 10;
    if (cursor + rdlength > dns_size) {
      return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns answer payload overruns the response");
    }

    if (type == kDnsTypeA && klass == kDnsClassIn && rdlength == 4) {
      std::array<std::uint8_t, 4> ipv4{};
      std::copy_n(dns + cursor, 4, ipv4.begin());
      response.ipv4_addresses.push_back(FormatIpv4Address(ipv4));
    }
    cursor += rdlength;
  }

  return MakeSuccess(std::move(response));
}

}  // namespace swg