#pragma once

#include <cstdint>
#include <string>

namespace swg {

inline constexpr std::uint16_t kAbiVersion = 1;
inline constexpr std::uint16_t kVersionMajor = 0;
inline constexpr std::uint16_t kVersionMinor = 1;
inline constexpr std::uint16_t kVersionPatch = 0;

inline std::string VersionString() {
  return "0.1.0";
}

}  // namespace swg
