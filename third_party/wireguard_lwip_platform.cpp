#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include <psa/crypto.h>

#if defined(SWG_PLATFORM_SWITCH)
extern "C" {
#include <switch/services/time.h>
}
#endif

extern "C" {
#include "crypto.h"
#include "wireguard-platform.h"
}

namespace {

constexpr std::uint64_t kTai64Base = 0x400000000000000aULL;

std::once_flag g_psa_crypto_once;
psa_status_t g_psa_crypto_status = PSA_ERROR_BAD_STATE;
thread_local std::vector<std::uint8_t> g_random_override;
thread_local std::size_t g_random_override_offset = 0;
thread_local std::array<std::uint8_t, 12> g_tai64n_override{};
thread_local bool g_has_tai64n_override = false;

psa_status_t EnsurePsaCrypto() {
  std::call_once(g_psa_crypto_once, []() {
    g_psa_crypto_status = psa_crypto_init();
  });
  return g_psa_crypto_status;
}

std::uint64_t UnixSecondsNow() {
#if defined(SWG_PLATFORM_SWITCH)
  if (R_SUCCEEDED(timeInitialize())) {
    u64 switch_timestamp = 0;
    ::Result rc = timeGetCurrentTime(TimeType_LocalSystemClock, &switch_timestamp);
    if (R_FAILED(rc)) {
      rc = timeGetCurrentTime(TimeType_Default, &switch_timestamp);
    }
    timeExit();
    if (R_SUCCEEDED(rc)) {
      return static_cast<std::uint64_t>(switch_timestamp);
    }
  }
#endif

  const auto now = std::chrono::system_clock::now();
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
  return static_cast<std::uint64_t>(seconds.count());
}

std::uint32_t SteadyNanosecondComponent() {
  const auto now = std::chrono::steady_clock::now();
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
  return static_cast<std::uint32_t>(nanos.count() % 1000000000LL);
}

}  // namespace

extern "C" uint32_t wireguard_sys_now() {
  const auto now = std::chrono::steady_clock::now();
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
  return static_cast<std::uint32_t>(millis.count());
}

extern "C" void wireguard_random_bytes(void* bytes, size_t size) {
  if (bytes == nullptr || size == 0) {
    return;
  }

  if (g_random_override_offset + size <= g_random_override.size()) {
    std::memcpy(bytes, g_random_override.data() + g_random_override_offset, size);
    g_random_override_offset += size;
    return;
  }

  if (EnsurePsaCrypto() == PSA_SUCCESS && psa_generate_random(static_cast<std::uint8_t*>(bytes), size) == PSA_SUCCESS) {
    return;
  }

  std::memset(bytes, 0, size);
}

extern "C" void wireguard_tai64n_now(uint8_t* output) {
  if (output == nullptr) {
    return;
  }

  if (g_has_tai64n_override) {
    std::memcpy(output, g_tai64n_override.data(), g_tai64n_override.size());
    return;
  }

  const std::uint64_t seconds = kTai64Base + UnixSecondsNow();
  const std::uint32_t nanos = SteadyNanosecondComponent();
  U64TO8_BIG(output + 0, seconds);
  U32TO8_BIG(output + 8, nanos);
}

extern "C" bool wireguard_is_under_load() {
  return false;
}

extern "C" void swg_wireguard_lwip_set_random_override(const uint8_t* bytes, size_t size) {
  g_random_override.clear();
  g_random_override_offset = 0;
  if (bytes != nullptr && size != 0) {
    g_random_override.assign(bytes, bytes + size);
  }
}

extern "C" void swg_wireguard_lwip_set_tai64n_override(const uint8_t* bytes, size_t size) {
  g_tai64n_override = {};
  g_has_tai64n_override = false;
  if (bytes != nullptr && size == g_tai64n_override.size()) {
    std::copy_n(bytes, size, g_tai64n_override.begin());
    g_has_tai64n_override = true;
  }
}

extern "C" void swg_wireguard_lwip_clear_overrides() {
  g_random_override.clear();
  g_random_override_offset = 0;
  g_tai64n_override = {};
  g_has_tai64n_override = false;
}
