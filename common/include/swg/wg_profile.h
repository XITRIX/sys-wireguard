#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "swg/config.h"
#include "swg/result.h"

namespace swg {

inline constexpr std::size_t kWireGuardKeySize = 32;

struct WireGuardKey {
  std::array<std::uint8_t, kWireGuardKeySize> bytes{};
};

struct ValidatedWireGuardProfile {
  std::string name;
  std::string endpoint_host;
  std::uint16_t endpoint_port = 0;
  std::size_t allowed_ip_count = 0;
  std::size_t address_count = 0;
  bool has_preshared_key = false;
  WireGuardKey private_key{};
  WireGuardKey public_key{};
  WireGuardKey preshared_key{};
};

Result<WireGuardKey> ParseWireGuardKey(std::string_view encoded, std::string_view field_name);
Result<ValidatedWireGuardProfile> ValidateWireGuardProfileForConnect(const ProfileConfig& profile);

}  // namespace swg