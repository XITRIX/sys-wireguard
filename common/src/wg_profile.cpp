#include "swg/wg_profile.h"

#include "swg/wg_crypto.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <cctype>
#include <vector>

namespace swg {
namespace {

constexpr std::size_t kIpStringBufferSize = 64;

int Base64Value(char ch) {
  if (ch >= 'A' && ch <= 'Z') {
    return ch - 'A';
  }
  if (ch >= 'a' && ch <= 'z') {
    return ch - 'a' + 26;
  }
  if (ch >= '0' && ch <= '9') {
    return ch - '0' + 52;
  }
  if (ch == '+') {
    return 62;
  }
  if (ch == '/') {
    return 63;
  }
  return -1;
}

std::string TrimCopy(std::string_view input) {
  std::size_t begin = 0;
  std::size_t end = input.size();

  while (begin < end && std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
    ++begin;
  }
  while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
    --end;
  }

  return std::string(input.substr(begin, end - begin));
}

Result<std::vector<std::uint8_t>> DecodeBase64(std::string_view encoded, std::string_view field_name) {
  const std::string compact = TrimCopy(encoded);
  if (compact.empty()) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::InvalidConfig,
                                                  std::string(field_name) + " must not be empty");
  }

  if (compact.size() % 4 != 0) {
    return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::InvalidConfig,
                                                  std::string(field_name) + " must be valid base64");
  }

  std::vector<std::uint8_t> output;
  output.reserve((compact.size() / 4) * 3);

  for (std::size_t index = 0; index < compact.size(); index += 4) {
    int values[4] = {0, 0, 0, 0};
    int padding = 0;

    for (int part = 0; part < 4; ++part) {
      const char current = compact[index + static_cast<std::size_t>(part)];
      if (current == '=') {
        if (part < 2) {
          return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::InvalidConfig,
                                                        std::string(field_name) + " must be valid base64");
        }
        ++padding;
        values[part] = 0;
        continue;
      }

      if (padding != 0) {
        return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::InvalidConfig,
                                                      std::string(field_name) + " must be valid base64");
      }

      values[part] = Base64Value(current);
      if (values[part] < 0) {
        return MakeFailure<std::vector<std::uint8_t>>(ErrorCode::InvalidConfig,
                                                      std::string(field_name) + " must be valid base64");
      }
    }

    output.push_back(static_cast<std::uint8_t>((values[0] << 2) | (values[1] >> 4)));
    if (compact[index + 2] != '=') {
      output.push_back(static_cast<std::uint8_t>(((values[1] & 0x0f) << 4) | (values[2] >> 2)));
    }
    if (compact[index + 3] != '=') {
      output.push_back(static_cast<std::uint8_t>(((values[2] & 0x03) << 6) | values[3]));
    }
  }

  return MakeSuccess(std::move(output));
}

bool ContainsWhitespace(std::string_view input) {
  return std::any_of(input.begin(), input.end(), [](char ch) {
    return std::isspace(static_cast<unsigned char>(ch)) != 0;
  });
}

std::string ToLowerAscii(std::string_view input) {
  std::string lowered(input);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](char ch) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  });
  return lowered;
}

Result<ParsedIpAddress> ParseIpAddressImpl(std::string_view input, std::string_view field_name) {
  const std::string trimmed = TrimCopy(input);
  if (trimmed.empty()) {
    return MakeFailure<ParsedIpAddress>(ErrorCode::InvalidConfig, std::string(field_name) + " must not be empty");
  }

  ParsedIpAddress address{};
  char buffer[kIpStringBufferSize] = {};

  std::array<std::uint8_t, 4> ipv4 = {};
  if (inet_pton(AF_INET, trimmed.c_str(), ipv4.data()) == 1) {
    address.family = ParsedIpFamily::IPv4;
    std::copy_n(ipv4.begin(), 4, address.bytes.begin());
    if (inet_ntop(AF_INET, ipv4.data(), buffer, sizeof(buffer)) == nullptr) {
      return MakeFailure<ParsedIpAddress>(ErrorCode::InvalidConfig,
                                          std::string(field_name) + " could not be normalized");
    }
    address.normalized = buffer;
    return MakeSuccess(std::move(address));
  }

  std::array<std::uint8_t, 16> ipv6 = {};
  if (inet_pton(AF_INET6, trimmed.c_str(), ipv6.data()) == 1) {
    address.family = ParsedIpFamily::IPv6;
    std::copy_n(ipv6.begin(), 16, address.bytes.begin());
    if (inet_ntop(AF_INET6, ipv6.data(), buffer, sizeof(buffer)) == nullptr) {
      return MakeFailure<ParsedIpAddress>(ErrorCode::InvalidConfig,
                                          std::string(field_name) + " could not be normalized");
    }
    address.normalized = buffer;
    return MakeSuccess(std::move(address));
  }

  return MakeFailure<ParsedIpAddress>(ErrorCode::InvalidConfig,
                                      std::string(field_name) + " must be a numeric IPv4 or IPv6 address");
}

std::string StripIpv6Brackets(std::string_view input) {
  if (input.size() >= 2 && input.front() == '[' && input.back() == ']') {
    return std::string(input.substr(1, input.size() - 2));
  }
  return std::string(input);
}

Result<std::uint8_t> ParsePrefixLength(std::string_view input, std::string_view field_name) {
  try {
    const unsigned long value = std::stoul(std::string(input));
    if (value > 255UL) {
      return MakeFailure<std::uint8_t>(ErrorCode::InvalidConfig,
                                       std::string(field_name) + " prefix length is out of range");
    }
    return MakeSuccess(static_cast<std::uint8_t>(value));
  } catch (const std::exception&) {
    return MakeFailure<std::uint8_t>(ErrorCode::InvalidConfig,
                                     std::string(field_name) + " prefix length is invalid");
  }
}

}  // namespace

Result<ParsedIpAddress> ParseIpAddress(std::string_view input, std::string_view field_name) {
  return ParseIpAddressImpl(input, field_name);
}

Result<ParsedIpNetwork> ParseIpNetwork(std::string_view input, std::string_view field_name) {
  const std::string trimmed = TrimCopy(input);
  const std::size_t separator = trimmed.find('/');
  if (separator == std::string::npos) {
    return MakeFailure<ParsedIpNetwork>(ErrorCode::InvalidConfig,
                                        std::string(field_name) + " must use CIDR notation");
  }

  const Result<ParsedIpAddress> address = ParseIpAddressImpl(trimmed.substr(0, separator), field_name);
  if (!address.ok()) {
    return MakeFailure<ParsedIpNetwork>(address.error.code, address.error.message);
  }

  const Result<std::uint8_t> prefix = ParsePrefixLength(trimmed.substr(separator + 1), field_name);
  if (!prefix.ok()) {
    return MakeFailure<ParsedIpNetwork>(prefix.error.code, prefix.error.message);
  }

  const std::uint8_t max_prefix = address.value.family == ParsedIpFamily::IPv4 ? 32 : 128;
  if (prefix.value > max_prefix) {
    return MakeFailure<ParsedIpNetwork>(ErrorCode::InvalidConfig,
                                        std::string(field_name) + " prefix length exceeds address size");
  }

  ParsedIpNetwork network{};
  network.address = address.value;
  network.prefix_length = prefix.value;
  network.normalized = address.value.normalized + "/" + std::to_string(prefix.value);
  return MakeSuccess(std::move(network));
}

Result<ParsedEndpoint> ParseEndpoint(std::string_view host, std::uint16_t port, std::string_view field_name) {
  const std::string trimmed = TrimCopy(host);
  if (trimmed.empty()) {
    return MakeFailure<ParsedEndpoint>(ErrorCode::InvalidConfig, std::string(field_name) + " must not be empty");
  }
  if (port == 0) {
    return MakeFailure<ParsedEndpoint>(ErrorCode::InvalidConfig, "endpoint_port must not be 0");
  }
  if (ContainsWhitespace(trimmed)) {
    return MakeFailure<ParsedEndpoint>(ErrorCode::InvalidConfig,
                                       std::string(field_name) + " must not contain whitespace");
  }

  const bool has_left_bracket = trimmed.front() == '[';
  const bool has_right_bracket = trimmed.back() == ']';
  if (has_left_bracket != has_right_bracket) {
    return MakeFailure<ParsedEndpoint>(ErrorCode::InvalidConfig,
                                       std::string(field_name) + " has mismatched IPv6 brackets");
  }

  const std::string candidate = StripIpv6Brackets(trimmed);
  const Result<ParsedIpAddress> numeric_address = ParseIpAddressImpl(candidate, field_name);

  ParsedEndpoint endpoint{};
  endpoint.port = port;
  if (numeric_address.ok()) {
    endpoint.type = numeric_address.value.family == ParsedIpFamily::IPv4 ? ParsedEndpointHostType::IPv4
                                                                         : ParsedEndpointHostType::IPv6;
    endpoint.host = numeric_address.value.normalized;
    return MakeSuccess(std::move(endpoint));
  }

  if (candidate.find('/') != std::string::npos || candidate.find('[') != std::string::npos ||
      candidate.find(']') != std::string::npos) {
    return MakeFailure<ParsedEndpoint>(ErrorCode::InvalidConfig,
                                       std::string(field_name) + " must be a hostname or IP literal");
  }

  endpoint.type = ParsedEndpointHostType::Hostname;
  endpoint.host = ToLowerAscii(candidate);
  return MakeSuccess(std::move(endpoint));
}

Result<WireGuardKey> ParseWireGuardKey(std::string_view encoded, std::string_view field_name) {
  const Result<std::vector<std::uint8_t>> decoded = DecodeBase64(encoded, field_name);
  if (!decoded.ok()) {
    return MakeFailure<WireGuardKey>(decoded.error.code, decoded.error.message);
  }

  if (decoded.value.size() != kWireGuardKeySize) {
    return MakeFailure<WireGuardKey>(ErrorCode::InvalidConfig,
                                     std::string(field_name) + " must decode to exactly 32 bytes");
  }

  WireGuardKey key{};
  std::copy(decoded.value.begin(), decoded.value.end(), key.bytes.begin());
  return MakeSuccess(std::move(key));
}

Result<ValidatedWireGuardProfile> ValidateWireGuardProfileForConnect(const ProfileConfig& profile) {
  if (profile.name.empty()) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig, "profile name must not be empty");
  }

  const Result<WireGuardKey> private_key = ParseWireGuardKey(profile.private_key, "private_key");
  if (!private_key.ok()) {
    return MakeFailure<ValidatedWireGuardProfile>(private_key.error.code,
                                                  "profile '" + profile.name + "': " + private_key.error.message);
  }

  const Result<WireGuardKey> public_key = ParseWireGuardKey(profile.public_key, "public_key");
  if (!public_key.ok()) {
    return MakeFailure<ValidatedWireGuardProfile>(public_key.error.code,
                                                  "profile '" + profile.name + "': " + public_key.error.message);
  }

  const Result<WireGuardKey> local_public_key = DeriveWireGuardPublicKey(private_key.value);
  if (!local_public_key.ok()) {
    return MakeFailure<ValidatedWireGuardProfile>(local_public_key.error.code,
                                                  "profile '" + profile.name +
                                                      "': failed to derive local public key: " +
                                                      local_public_key.error.message);
  }

  const Result<WireGuardKey> static_shared_secret =
      ComputeWireGuardSharedSecret(private_key.value, public_key.value);
  if (!static_shared_secret.ok()) {
    return MakeFailure<ValidatedWireGuardProfile>(static_shared_secret.error.code,
                                                  "profile '" + profile.name +
                                                      "': peer public_key is not usable for X25519: " +
                                                      static_shared_secret.error.message);
  }

  ValidatedWireGuardProfile validated{};
  validated.name = profile.name;
  validated.private_key = private_key.value;
  validated.local_public_key = local_public_key.value;
  validated.public_key = public_key.value;
  validated.static_shared_secret = static_shared_secret.value;
  validated.persistent_keepalive = profile.persistent_keepalive;

  if (!profile.preshared_key.empty()) {
    const Result<WireGuardKey> preshared_key = ParseWireGuardKey(profile.preshared_key, "preshared_key");
    if (!preshared_key.ok()) {
      return MakeFailure<ValidatedWireGuardProfile>(preshared_key.error.code,
                                                    "profile '" + profile.name + "': " + preshared_key.error.message);
    }

    validated.has_preshared_key = true;
    validated.preshared_key = preshared_key.value;
  }

  const Result<ParsedEndpoint> endpoint = ParseEndpoint(profile.endpoint_host, profile.endpoint_port);
  if (!endpoint.ok()) {
    return MakeFailure<ValidatedWireGuardProfile>(endpoint.error.code,
                                                  "profile '" + profile.name + "': " + endpoint.error.message);
  }
  validated.endpoint = endpoint.value;

  if (profile.allowed_ips.empty()) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': allowed_ips must not be empty");
  }
  validated.allowed_ips.reserve(profile.allowed_ips.size());
  for (const std::string& cidr : profile.allowed_ips) {
    const Result<ParsedIpNetwork> parsed = ParseIpNetwork(cidr, "allowed_ips");
    if (!parsed.ok()) {
      return MakeFailure<ValidatedWireGuardProfile>(parsed.error.code,
                                                    "profile '" + profile.name + "': " + parsed.error.message);
    }
    validated.allowed_ips.push_back(parsed.value);
  }

  if (profile.addresses.empty()) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': address list must not be empty");
  }
  validated.addresses.reserve(profile.addresses.size());
  for (const std::string& cidr : profile.addresses) {
    const Result<ParsedIpNetwork> parsed = ParseIpNetwork(cidr, "address");
    if (!parsed.ok()) {
      return MakeFailure<ValidatedWireGuardProfile>(parsed.error.code,
                                                    "profile '" + profile.name + "': " + parsed.error.message);
    }
    validated.addresses.push_back(parsed.value);
  }

  validated.dns_servers.reserve(profile.dns_servers.size());
  for (const std::string& dns_server : profile.dns_servers) {
    const Result<ParsedIpAddress> parsed = ParseIpAddress(dns_server, "dns");
    if (!parsed.ok()) {
      return MakeFailure<ValidatedWireGuardProfile>(parsed.error.code,
                                                    "profile '" + profile.name + "': " + parsed.error.message);
    }
    validated.dns_servers.push_back(parsed.value);
  }

  return MakeSuccess(std::move(validated));
}

}  // namespace swg