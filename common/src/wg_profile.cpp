#include "swg/wg_profile.h"

#include <algorithm>
#include <cctype>
#include <vector>

namespace swg {
namespace {

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

}  // namespace

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

  ValidatedWireGuardProfile validated{};
  validated.name = profile.name;
  validated.private_key = private_key.value;
  validated.public_key = public_key.value;

  if (!profile.preshared_key.empty()) {
    const Result<WireGuardKey> preshared_key = ParseWireGuardKey(profile.preshared_key, "preshared_key");
    if (!preshared_key.ok()) {
      return MakeFailure<ValidatedWireGuardProfile>(preshared_key.error.code,
                                                    "profile '" + profile.name + "': " + preshared_key.error.message);
    }

    validated.has_preshared_key = true;
    validated.preshared_key = preshared_key.value;
  }

  const std::string endpoint_host = TrimCopy(profile.endpoint_host);
  if (endpoint_host.empty()) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': endpoint_host must not be empty");
  }
  if (ContainsWhitespace(endpoint_host)) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': endpoint_host must not contain whitespace");
  }
  if (profile.endpoint_port == 0) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': endpoint_port must not be 0");
  }
  if (profile.allowed_ips.empty()) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': allowed_ips must not be empty");
  }
  if (profile.addresses.empty()) {
    return MakeFailure<ValidatedWireGuardProfile>(ErrorCode::InvalidConfig,
                                                  "profile '" + profile.name + "': address list must not be empty");
  }

  validated.endpoint_host = endpoint_host;
  validated.endpoint_port = profile.endpoint_port;
  validated.allowed_ip_count = profile.allowed_ips.size();
  validated.address_count = profile.addresses.size();
  return MakeSuccess(std::move(validated));
}

}  // namespace swg