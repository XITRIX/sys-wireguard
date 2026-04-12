#include "swg/tunnel_dns.h"

#include <algorithm>

#include "swg/wg_profile.h"

namespace swg {
namespace {

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

Result<std::vector<std::uint8_t>> BuildTunnelDnsQueryPacket(const TunnelDnsPacketEndpoint& endpoint,
                                                            std::string_view hostname,
                                                            std::uint16_t query_id) {
  const Result<std::vector<std::uint8_t>> dns_question = BuildDnsQuestion(hostname, query_id);
  if (!dns_question.ok()) {
    return MakeFailure<std::vector<std::uint8_t>>(dns_question.error.code, dns_question.error.message);
  }

  Ipv4UdpPacketEndpoint packet_endpoint{};
  packet_endpoint.source_ipv4 = endpoint.source_ipv4;
  packet_endpoint.destination_ipv4 = endpoint.destination_ipv4;
  packet_endpoint.source_port = endpoint.source_port;
  packet_endpoint.destination_port = endpoint.destination_port;
  return BuildIpv4UdpPacket(packet_endpoint, dns_question.value);
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

  Ipv4UdpPacketEndpoint packet_endpoint{};
  packet_endpoint.source_ipv4 = endpoint.destination_ipv4;
  packet_endpoint.destination_ipv4 = endpoint.source_ipv4;
  packet_endpoint.source_port = endpoint.destination_port;
  packet_endpoint.destination_port = endpoint.source_port;
  return BuildIpv4UdpPacket(packet_endpoint, dns_payload);
}

Result<TunnelDnsResponse> ParseTunnelDnsResponsePacket(const std::vector<std::uint8_t>& packet) {
  const Result<Ipv4UdpPacket> parsed = ParseIpv4UdpPacket(packet);
  if (!parsed.ok()) {
    return MakeFailure<TunnelDnsResponse>(parsed.error.code, parsed.error.message);
  }
  if (parsed.value.payload.size() < kDnsHeaderSize) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns response packet is too short");
  }

  const std::size_t dns_size = parsed.value.payload.size();
  const std::uint8_t* dns = parsed.value.payload.data();

  const std::uint16_t flags = Load16Be(dns + 2);
  if ((flags & kDnsFlagsResponse) == 0) {
    return MakeFailure<TunnelDnsResponse>(ErrorCode::ParseError, "dns packet is not a response");
  }

  TunnelDnsResponse response{};
  response.query_id = Load16Be(dns);
  response.source_port = parsed.value.endpoint.source_port;
  response.destination_port = parsed.value.endpoint.destination_port;
  response.source_ipv4 = parsed.value.endpoint.source_ipv4;
  response.destination_ipv4 = parsed.value.endpoint.destination_ipv4;
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