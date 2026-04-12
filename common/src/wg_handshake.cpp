#include "swg/wg_handshake.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>

#include <mbedtls/chachapoly.h>

#if defined(SWG_PLATFORM_SWITCH)
extern "C" {
#include <switch/services/time.h>
}
#endif

#include "swg/wg_crypto.h"

namespace swg {
namespace {

using Blake2sHash = std::array<std::uint8_t, 32>;
using Blake2sMac16 = std::array<std::uint8_t, 16>;

constexpr std::size_t kBlake2sBlockSize = 64;
constexpr std::size_t kWireGuardTimestampSize = 12;
constexpr std::size_t kAeadTagSize = 16;
constexpr std::size_t kInitiationSenderIndexOffset = 4;
constexpr std::size_t kInitiationEphemeralOffset = 8;
constexpr std::size_t kInitiationEncryptedStaticOffset = 40;
constexpr std::size_t kInitiationEncryptedStaticSize = kWireGuardKeySize + kAeadTagSize;
constexpr std::size_t kInitiationEncryptedTimestampOffset =
    kInitiationEncryptedStaticOffset + kInitiationEncryptedStaticSize;
constexpr std::size_t kInitiationEncryptedTimestampSize = kWireGuardTimestampSize + kAeadTagSize;
constexpr std::size_t kInitiationMac1Offset =
    kInitiationEncryptedTimestampOffset + kInitiationEncryptedTimestampSize;
constexpr std::size_t kResponseSenderIndexOffset = 4;
constexpr std::size_t kResponseReceiverIndexOffset = 8;
constexpr std::size_t kResponseEphemeralOffset = 12;
constexpr std::size_t kResponseEncryptedNothingOffset = 44;
constexpr std::size_t kResponseEncryptedNothingSize = kAeadTagSize;
constexpr std::size_t kResponseMac1Offset = kResponseEncryptedNothingOffset + kResponseEncryptedNothingSize;
constexpr std::uint64_t kTai64Base = 0x400000000000000aULL;
constexpr char kWireGuardConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
constexpr char kWireGuardIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
constexpr char kWireGuardMac1Label[] = "mac1----";

constexpr std::array<std::uint32_t, 8> kBlake2sIv = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

constexpr std::array<std::array<std::uint8_t, 16>, 10> kBlake2sSigma = {{
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
    {{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}},
    {{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}},
    {{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}},
    {{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}},
    {{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}},
    {{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}},
    {{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}},
    {{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}},
}};

struct ByteSlice {
  const std::uint8_t* data = nullptr;
  std::size_t size = 0;
};

struct Blake2sContext {
  std::array<std::uint32_t, 8> h{};
  std::array<std::uint32_t, 2> t{};
  std::array<std::uint32_t, 2> f{};
  std::array<std::uint8_t, kBlake2sBlockSize> buffer{};
  std::size_t buffer_size = 0;
  std::size_t output_size = 32;
};

struct ResponseState {
  std::uint32_t initiator_sender_index = 0;
  WireGuardKey initiator_ephemeral_public{};
  WireGuardKey initiator_static_public{};
  Blake2sHash chaining_key{};
  Blake2sHash hash{};
};

inline ByteSlice MakeSlice(const std::uint8_t* data, std::size_t size) {
  return ByteSlice{data, size};
}

template <std::size_t N>
ByteSlice MakeSlice(const std::array<std::uint8_t, N>& value) {
  return ByteSlice{value.data(), value.size()};
}

ByteSlice MakeSlice(const WireGuardKey& key) {
  return ByteSlice{key.bytes.data(), key.bytes.size()};
}

ByteSlice MakeSlice(const char* value) {
  return ByteSlice{reinterpret_cast<const std::uint8_t*>(value), std::strlen(value)};
}

std::uint32_t Load32Le(const std::uint8_t* input) {
  return static_cast<std::uint32_t>(input[0]) |
         (static_cast<std::uint32_t>(input[1]) << 8) |
         (static_cast<std::uint32_t>(input[2]) << 16) |
         (static_cast<std::uint32_t>(input[3]) << 24);
}

void Store32Le(std::uint8_t* output, std::uint32_t value) {
  output[0] = static_cast<std::uint8_t>(value & 0xFFu);
  output[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  output[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  output[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

void Store32Be(std::uint8_t* output, std::uint32_t value) {
  output[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  output[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  output[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  output[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

void Store64Be(std::uint8_t* output, std::uint64_t value) {
  for (int index = 7; index >= 0; --index) {
    output[7 - index] = static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFu);
  }
}

inline std::uint32_t RotateRight(std::uint32_t value, int bits) {
  return (value >> bits) | (value << (32 - bits));
}

void Blake2sMix(std::array<std::uint32_t, 16>& state,
                std::uint32_t a,
                std::uint32_t b,
                std::uint32_t c,
                std::uint32_t d,
                std::uint32_t x,
                std::uint32_t y) {
  state[a] = state[a] + state[b] + x;
  state[d] = RotateRight(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = RotateRight(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + y;
  state[d] = RotateRight(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = RotateRight(state[b] ^ state[c], 7);
}

void Blake2sIncrement(Blake2sContext& context, std::uint32_t increment) {
  context.t[0] += increment;
  if (context.t[0] < increment) {
    ++context.t[1];
  }
}

void Blake2sCompress(Blake2sContext& context, const std::uint8_t block[kBlake2sBlockSize]) {
  std::array<std::uint32_t, 16> message{};
  for (std::size_t index = 0; index < message.size(); ++index) {
    message[index] = Load32Le(block + (index * 4));
  }

  std::array<std::uint32_t, 16> state{};
  for (std::size_t index = 0; index < context.h.size(); ++index) {
    state[index] = context.h[index];
    state[index + 8] = kBlake2sIv[index];
  }
  state[12] ^= context.t[0];
  state[13] ^= context.t[1];
  state[14] ^= context.f[0];
  state[15] ^= context.f[1];

  for (const auto& sigma : kBlake2sSigma) {
    Blake2sMix(state, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
    Blake2sMix(state, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
    Blake2sMix(state, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
    Blake2sMix(state, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);
    Blake2sMix(state, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
    Blake2sMix(state, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
    Blake2sMix(state, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
    Blake2sMix(state, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
  }

  for (std::size_t index = 0; index < context.h.size(); ++index) {
    context.h[index] ^= state[index] ^ state[index + 8];
  }
}

void Blake2sInit(Blake2sContext& context, std::size_t output_size, const std::uint8_t* key, std::size_t key_size) {
  context.h = kBlake2sIv;
  context.t = {};
  context.f = {};
  context.buffer.fill(0);
  context.buffer_size = 0;
  context.output_size = output_size;
  context.h[0] ^= (0x01010000u ^ (static_cast<std::uint32_t>(key_size) << 8) ^
                   static_cast<std::uint32_t>(output_size));

  if (key_size != 0) {
    std::array<std::uint8_t, kBlake2sBlockSize> key_block{};
    std::copy_n(key, key_size, key_block.begin());

    context.buffer = key_block;
    context.buffer_size = kBlake2sBlockSize;
  }
}

void Blake2sUpdate(Blake2sContext& context, const std::uint8_t* data, std::size_t size) {
  if (size == 0) {
    return;
  }

  std::size_t offset = 0;
  if (context.buffer_size != 0) {
    const std::size_t fill = kBlake2sBlockSize - context.buffer_size;
    if (size > fill) {
      std::copy_n(data, fill, context.buffer.begin() + static_cast<std::ptrdiff_t>(context.buffer_size));
      Blake2sIncrement(context, static_cast<std::uint32_t>(kBlake2sBlockSize));
      Blake2sCompress(context, context.buffer.data());
      context.buffer_size = 0;
      offset += fill;
      size -= fill;
    }
  }

  while (size > kBlake2sBlockSize) {
    Blake2sIncrement(context, static_cast<std::uint32_t>(kBlake2sBlockSize));
    Blake2sCompress(context, data + offset);
    offset += kBlake2sBlockSize;
    size -= kBlake2sBlockSize;
  }

  std::copy_n(data + offset, size, context.buffer.begin() + static_cast<std::ptrdiff_t>(context.buffer_size));
  context.buffer_size += size;
}

template <std::size_t N>
std::array<std::uint8_t, N> Blake2sFinalize(Blake2sContext& context) {
  Blake2sIncrement(context, static_cast<std::uint32_t>(context.buffer_size));
  context.f[0] = 0xFFFFFFFFu;
  std::fill(context.buffer.begin() + static_cast<std::ptrdiff_t>(context.buffer_size), context.buffer.end(), 0);
  Blake2sCompress(context, context.buffer.data());

  std::array<std::uint8_t, N> output{};
  std::array<std::uint8_t, 32> full_output{};
  for (std::size_t index = 0; index < context.h.size(); ++index) {
    Store32Le(full_output.data() + (index * 4), context.h[index]);
  }
  std::copy_n(full_output.begin(), output.size(), output.begin());
  return output;
}

template <std::size_t N>
std::array<std::uint8_t, N> Blake2sDigest(std::initializer_list<ByteSlice> slices,
                                          const std::uint8_t* key = nullptr,
                                          std::size_t key_size = 0) {
  Blake2sContext context{};
  Blake2sInit(context, N, key, key_size);
  for (const ByteSlice slice : slices) {
    Blake2sUpdate(context, slice.data, slice.size);
  }
  return Blake2sFinalize<N>(context);
}

Blake2sHash HmacBlake2s(const std::uint8_t* key, std::size_t key_size, std::initializer_list<ByteSlice> slices) {
  std::array<std::uint8_t, kBlake2sBlockSize> normalized_key{};
  if (key_size > normalized_key.size()) {
    const Blake2sHash hashed_key = Blake2sDigest<32>({MakeSlice(key, key_size)});
    std::copy(hashed_key.begin(), hashed_key.end(), normalized_key.begin());
  } else if (key_size != 0) {
    std::copy_n(key, key_size, normalized_key.begin());
  }

  std::array<std::uint8_t, kBlake2sBlockSize> inner_pad{};
  std::array<std::uint8_t, kBlake2sBlockSize> outer_pad{};
  for (std::size_t index = 0; index < normalized_key.size(); ++index) {
    inner_pad[index] = static_cast<std::uint8_t>(normalized_key[index] ^ 0x36u);
    outer_pad[index] = static_cast<std::uint8_t>(normalized_key[index] ^ 0x5Cu);
  }

  Blake2sContext inner_context{};
  Blake2sInit(inner_context, 32, nullptr, 0);
  Blake2sUpdate(inner_context, inner_pad.data(), inner_pad.size());
  for (const ByteSlice slice : slices) {
    Blake2sUpdate(inner_context, slice.data, slice.size);
  }
  const Blake2sHash inner_hash = Blake2sFinalize<32>(inner_context);

  return Blake2sDigest<32>({MakeSlice(outer_pad), MakeSlice(inner_hash)});
}

template <std::size_t N>
std::array<std::uint8_t, N> KeyedBlake2s(const std::uint8_t* key,
                                         std::size_t key_size,
                                         std::initializer_list<ByteSlice> slices) {
  return Blake2sDigest<N>(slices, key, key_size);
}

template <std::size_t N>
std::array<std::uint8_t, N> KeyedBlake2s(const WireGuardKey& key, std::initializer_list<ByteSlice> slices) {
  return KeyedBlake2s<N>(key.bytes.data(), key.bytes.size(), slices);
}

template <std::size_t N>
std::array<std::uint8_t, N> KeyedBlake2s(const Blake2sHash& key, std::initializer_list<ByteSlice> slices) {
  return KeyedBlake2s<N>(key.data(), key.size(), slices);
}

Blake2sHash KdfTemp(const Blake2sHash& chaining_key, const ByteSlice input) {
  return HmacBlake2s(chaining_key.data(), chaining_key.size(), {input});
}

Blake2sHash KdfLabel(const Blake2sHash& key, std::uint8_t label) {
  return HmacBlake2s(key.data(), key.size(), {MakeSlice(&label, 1)});
}

Blake2sHash KdfLabelWithPrevious(const Blake2sHash& key, const Blake2sHash& previous, std::uint8_t label) {
  return HmacBlake2s(key.data(), key.size(), {MakeSlice(previous), MakeSlice(&label, 1)});
}

WireGuardKey ToWireGuardKey(const Blake2sHash& hash) {
  WireGuardKey key{};
  key.bytes = hash;
  return key;
}

Blake2sHash ToBlake2sHash(const WireGuardKey& key) {
  Blake2sHash hash{};
  hash = key.bytes;
  return hash;
}

Blake2sHash MakeEffectivePresharedKey(const WireGuardHandshakeConfig& config) {
  return config.has_preshared_key ? ToBlake2sHash(config.preshared_key) : Blake2sHash{};
}

Blake2sHash MakeEffectivePresharedKey(const WireGuardResponderConfig& config) {
  return config.has_preshared_key ? ToBlake2sHash(config.preshared_key) : Blake2sHash{};
}

std::array<std::uint8_t, 12> MakeAeadNonce(std::uint64_t counter) {
  std::array<std::uint8_t, 12> nonce{};
  for (std::size_t index = 0; index < 8; ++index) {
    nonce[4 + index] = static_cast<std::uint8_t>((counter >> (index * 8)) & 0xFFu);
  }
  return nonce;
}

Error MakeMbedTlsError(int rc, std::string_view operation) {
  std::ostringstream stream;
  stream << operation << " failed: mbedtls_rc=" << rc;
  return MakeError(ErrorCode::ServiceUnavailable, stream.str());
}

template <std::size_t PlaintextSize>
Result<std::array<std::uint8_t, PlaintextSize + kAeadTagSize>> EncryptAead(
    const WireGuardKey& key,
    std::uint64_t counter,
    const std::array<std::uint8_t, PlaintextSize>& plaintext,
    const Blake2sHash& aad) {
  std::array<std::uint8_t, PlaintextSize + kAeadTagSize> encrypted{};
  const std::array<std::uint8_t, 12> nonce = MakeAeadNonce(counter);

  mbedtls_chachapoly_context context;
  mbedtls_chachapoly_init(&context);

  int rc = mbedtls_chachapoly_setkey(&context, key.bytes.data());
  if (rc == 0) {
    rc = mbedtls_chachapoly_encrypt_and_tag(&context, plaintext.size(), nonce.data(), aad.data(), aad.size(),
                                            plaintext.data(), encrypted.data(),
                                            encrypted.data() + static_cast<std::ptrdiff_t>(plaintext.size()));
  }

  mbedtls_chachapoly_free(&context);
  if (rc != 0) {
    return Result<std::array<std::uint8_t, PlaintextSize + kAeadTagSize>>::Failure(
        MakeMbedTlsError(rc, "mbedtls_chachapoly_encrypt_and_tag"));
  }

  return MakeSuccess(encrypted);
}

template <std::size_t PlaintextSize>
Result<std::array<std::uint8_t, PlaintextSize>> DecryptAead(
    const WireGuardKey& key,
    std::uint64_t counter,
    const std::uint8_t* ciphertext,
    std::size_t ciphertext_size,
    const Blake2sHash& aad,
    std::string_view field_name) {
  if (ciphertext_size != PlaintextSize + kAeadTagSize) {
    return MakeFailure<std::array<std::uint8_t, PlaintextSize>>(ErrorCode::ParseError,
                                                                std::string(field_name) +
                                                                    " has an unexpected AEAD size");
  }

  std::array<std::uint8_t, PlaintextSize> plaintext{};
  const std::array<std::uint8_t, 12> nonce = MakeAeadNonce(counter);

  mbedtls_chachapoly_context context;
  mbedtls_chachapoly_init(&context);

  int rc = mbedtls_chachapoly_setkey(&context, key.bytes.data());
  if (rc == 0) {
    rc = mbedtls_chachapoly_auth_decrypt(&context, PlaintextSize, nonce.data(), aad.data(), aad.size(),
                                         ciphertext + static_cast<std::ptrdiff_t>(PlaintextSize), ciphertext,
                                         plaintext.data());
  }

  mbedtls_chachapoly_free(&context);
  if (rc != 0) {
    return MakeFailure<std::array<std::uint8_t, PlaintextSize>>(ErrorCode::ParseError,
                                                                std::string(field_name) +
                                                                    " AEAD verification failed");
  }

  return MakeSuccess(plaintext);
}

Blake2sHash ComputeInitialChainKey() {
  return Blake2sDigest<32>({MakeSlice(kWireGuardConstruction)});
}

Blake2sHash ComputeInitialHash(const WireGuardKey& peer_public_key) {
  const Blake2sHash chaining_key = ComputeInitialChainKey();
  const Blake2sHash identifier_hash = Blake2sDigest<32>({MakeSlice(chaining_key), MakeSlice(kWireGuardIdentifier)});
  return Blake2sDigest<32>({MakeSlice(identifier_hash), MakeSlice(peer_public_key)});
}

Blake2sHash MixHash(const Blake2sHash& current_hash, const ByteSlice slice) {
  return Blake2sDigest<32>({MakeSlice(current_hash), slice});
}

std::pair<Blake2sHash, WireGuardKey> MixKey(const Blake2sHash& chaining_key, const WireGuardKey& input) {
  const Blake2sHash temp = KdfTemp(chaining_key, MakeSlice(input));
  const Blake2sHash next_chaining_key = KdfLabel(temp, 0x1);
  const Blake2sHash key = KdfLabelWithPrevious(temp, next_chaining_key, 0x2);
  return {next_chaining_key, ToWireGuardKey(key)};
}

struct PresharedMixResult {
  Blake2sHash chaining_key{};
  Blake2sHash hash_mix{};
  WireGuardKey key{};
};

PresharedMixResult MixPresharedKey(const Blake2sHash& chaining_key, const Blake2sHash& preshared_key) {
  const Blake2sHash temp = HmacBlake2s(chaining_key.data(), chaining_key.size(), {MakeSlice(preshared_key)});
  const Blake2sHash next_chaining_key = KdfLabel(temp, 0x1);
  const Blake2sHash hash_mix = KdfLabelWithPrevious(temp, next_chaining_key, 0x2);
  const Blake2sHash key = KdfLabelWithPrevious(temp, hash_mix, 0x3);
  return PresharedMixResult{next_chaining_key, hash_mix, ToWireGuardKey(key)};
}

std::pair<WireGuardKey, WireGuardKey> DeriveSessionKeys(const Blake2sHash& chaining_key) {
  const Blake2sHash temp = HmacBlake2s(chaining_key.data(), chaining_key.size(), {});
  const Blake2sHash key_one = KdfLabel(temp, 0x1);
  const Blake2sHash key_two = KdfLabelWithPrevious(temp, key_one, 0x2);
  return {ToWireGuardKey(key_one), ToWireGuardKey(key_two)};
}

Blake2sMac16 ComputeMac1(const WireGuardKey& peer_public_key, const std::uint8_t* message, std::size_t message_size) {
  const Blake2sHash mac_key = Blake2sDigest<32>({MakeSlice(kWireGuardMac1Label), MakeSlice(peer_public_key)});
  return KeyedBlake2s<16>(mac_key, {MakeSlice(message, message_size)});
}

Error ValidateReservedZero(const std::uint8_t* packet, std::size_t size) {
  if (size < 4) {
    return MakeError(ErrorCode::ParseError, "WireGuard packet is too short");
  }
  if (packet[1] != 0 || packet[2] != 0 || packet[3] != 0) {
    return MakeError(ErrorCode::ParseError, "WireGuard packet reserved bytes must be zero");
  }
  return Error::None();
}

Result<std::uint32_t> RandomSenderIndex() {
  std::array<std::uint8_t, sizeof(std::uint32_t)> bytes{};
  const Error random_error = GenerateRandomBytes(bytes.data(), bytes.size());
  if (random_error) {
    return Result<std::uint32_t>::Failure(random_error);
  }
  return MakeSuccess(Load32Le(bytes.data()));
}

Result<std::array<std::uint8_t, 12>> CurrentTai64nTimestamp() {
  std::uint64_t seconds_since_epoch = 0;

#if defined(SWG_PLATFORM_SWITCH)
  bool has_switch_wall_clock = false;
  if (R_SUCCEEDED(timeInitialize())) {
    u64 switch_timestamp = 0;
    ::Result rc = timeGetCurrentTime(TimeType_LocalSystemClock, &switch_timestamp);
    if (R_FAILED(rc)) {
      rc = timeGetCurrentTime(TimeType_Default, &switch_timestamp);
    }
    if (R_SUCCEEDED(rc)) {
      seconds_since_epoch = static_cast<std::uint64_t>(switch_timestamp);
      has_switch_wall_clock = true;
    }
    timeExit();
  }

  if (!has_switch_wall_clock) {
    const auto now = std::chrono::system_clock::now();
    const auto duration = now.time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    seconds_since_epoch = static_cast<std::uint64_t>(seconds.count());
  }
#else
  const auto now = std::chrono::system_clock::now();
  const auto duration = now.time_since_epoch();
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
  seconds_since_epoch = static_cast<std::uint64_t>(seconds.count());
#endif

  const auto steady_duration = std::chrono::steady_clock::now().time_since_epoch();
  const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(steady_duration);
  const std::uint32_t nanoseconds_component =
      static_cast<std::uint32_t>(nanoseconds.count() % 1000000000LL);

  std::array<std::uint8_t, 12> timestamp{};
  Store64Be(timestamp.data(), kTai64Base + seconds_since_epoch);
  Store32Be(timestamp.data() + 8, nanoseconds_component);
  return MakeSuccess(timestamp);
}

Result<ResponseState> ParseInitiationForResponder(const WireGuardResponderConfig& config,
                                                  const std::uint8_t* packet,
                                                  std::size_t packet_size) {
  if (packet_size != kWireGuardHandshakeInitiationSize) {
    return MakeFailure<ResponseState>(ErrorCode::ParseError,
                                      "WireGuard initiation packet has an unexpected size");
  }
  if (packet[0] != static_cast<std::uint8_t>(WireGuardMessageType::HandshakeInitiation)) {
    return MakeFailure<ResponseState>(ErrorCode::ParseError,
                                      "WireGuard responder received a non-initiation packet");
  }

  const Error reserved_error = ValidateReservedZero(packet, packet_size);
  if (reserved_error) {
    return Result<ResponseState>::Failure(reserved_error);
  }

  const Blake2sMac16 expected_mac1 = ComputeMac1(config.local_public_key, packet, kInitiationMac1Offset);
  if (!std::equal(expected_mac1.begin(), expected_mac1.end(), packet + static_cast<std::ptrdiff_t>(kInitiationMac1Offset))) {
    return MakeFailure<ResponseState>(ErrorCode::ParseError, "WireGuard initiation packet MAC1 is invalid");
  }

  ResponseState state{};
  state.initiator_sender_index = Load32Le(packet + kInitiationSenderIndexOffset);
  std::copy_n(packet + kInitiationEphemeralOffset, kWireGuardKeySize, state.initiator_ephemeral_public.bytes.begin());
  state.chaining_key = ComputeInitialChainKey();
  state.hash = ComputeInitialHash(config.local_public_key);
  state.hash = MixHash(state.hash, MakeSlice(state.initiator_ephemeral_public));
  state.chaining_key = KdfLabel(KdfTemp(state.chaining_key, MakeSlice(state.initiator_ephemeral_public)), 0x1);

  const Result<WireGuardKey> shared_es =
      ComputeWireGuardSharedSecret(config.local_private_key, state.initiator_ephemeral_public);
  if (!shared_es.ok()) {
    return MakeFailure<ResponseState>(shared_es.error.code,
                                      "responder failed to derive ephemeral-static secret: " +
                                          shared_es.error.message);
  }

  auto [chaining_key_after_es, static_key] = MixKey(state.chaining_key, shared_es.value);
  const auto decrypted_static = DecryptAead<kWireGuardKeySize>(
      static_key, 0, packet + kInitiationEncryptedStaticOffset, kInitiationEncryptedStaticSize, state.hash,
      "encrypted_static");
  if (!decrypted_static.ok()) {
    return MakeFailure<ResponseState>(decrypted_static.error.code, decrypted_static.error.message);
  }

  std::copy(decrypted_static.value.begin(), decrypted_static.value.end(), state.initiator_static_public.bytes.begin());
  if (config.expected_peer_public_key.has_value() &&
      state.initiator_static_public.bytes != config.expected_peer_public_key->bytes) {
    return MakeFailure<ResponseState>(ErrorCode::ParseError,
                                      "WireGuard initiation static public key did not match the expected peer");
  }

  state.hash = MixHash(state.hash, MakeSlice(packet + kInitiationEncryptedStaticOffset, kInitiationEncryptedStaticSize));

  const Result<WireGuardKey> shared_ss =
      ComputeWireGuardSharedSecret(config.local_private_key, state.initiator_static_public);
  if (!shared_ss.ok()) {
    return MakeFailure<ResponseState>(shared_ss.error.code,
                                      "responder failed to derive static-static secret: " +
                                          shared_ss.error.message);
  }

  auto [chaining_key_after_ss, timestamp_key] = MixKey(chaining_key_after_es, shared_ss.value);
  const auto decrypted_timestamp = DecryptAead<kWireGuardTimestampSize>(
      timestamp_key, 0, packet + kInitiationEncryptedTimestampOffset, kInitiationEncryptedTimestampSize,
      state.hash, "encrypted_timestamp");
  if (!decrypted_timestamp.ok()) {
    return MakeFailure<ResponseState>(decrypted_timestamp.error.code, decrypted_timestamp.error.message);
  }

  state.hash = MixHash(state.hash,
                       MakeSlice(packet + kInitiationEncryptedTimestampOffset, kInitiationEncryptedTimestampSize));
  state.chaining_key = chaining_key_after_ss;
  return MakeSuccess(state);
}

}  // namespace

Result<WireGuardHandshakeInitiation> CreateHandshakeInitiation(const WireGuardHandshakeConfig& config,
                                                              const WireGuardHandshakeInitiationOptions& options) {
  WireGuardHandshakeInitiation initiation{};
  initiation.packet[0] = static_cast<std::uint8_t>(WireGuardMessageType::HandshakeInitiation);

  if (options.sender_index.has_value()) {
    initiation.state.sender_index = *options.sender_index;
  } else {
    const Result<std::uint32_t> random_sender_index = RandomSenderIndex();
    if (!random_sender_index.ok()) {
      return MakeFailure<WireGuardHandshakeInitiation>(random_sender_index.error.code,
                                                       random_sender_index.error.message);
    }
    initiation.state.sender_index = random_sender_index.value;
  }

  if (options.ephemeral_private_key.has_value()) {
    initiation.state.ephemeral_private_key = *options.ephemeral_private_key;
    const Result<WireGuardKey> public_key = DeriveWireGuardPublicKey(initiation.state.ephemeral_private_key);
    if (!public_key.ok()) {
      return MakeFailure<WireGuardHandshakeInitiation>(public_key.error.code,
                                                       "failed to derive WireGuard ephemeral public key: " +
                                                           public_key.error.message);
    }
    initiation.state.ephemeral_public_key = public_key.value;
  } else {
    const Result<WireGuardKeyPair> key_pair = GenerateWireGuardKeyPair();
    if (!key_pair.ok()) {
      return MakeFailure<WireGuardHandshakeInitiation>(key_pair.error.code, key_pair.error.message);
    }
    initiation.state.ephemeral_private_key = key_pair.value.private_key;
    initiation.state.ephemeral_public_key = key_pair.value.public_key;
  }

  const Result<std::array<std::uint8_t, 12>> timestamp =
      options.timestamp.has_value() ? MakeSuccess(*options.timestamp) : CurrentTai64nTimestamp();
  if (!timestamp.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(timestamp.error.code, timestamp.error.message);
  }

  initiation.state.chaining_key = ComputeInitialChainKey();
  initiation.state.hash = ComputeInitialHash(config.peer_public_key);

  Store32Le(initiation.packet.data() + kInitiationSenderIndexOffset, initiation.state.sender_index);
  std::copy(initiation.state.ephemeral_public_key.bytes.begin(), initiation.state.ephemeral_public_key.bytes.end(),
            initiation.packet.begin() + static_cast<std::ptrdiff_t>(kInitiationEphemeralOffset));
  initiation.state.hash = MixHash(initiation.state.hash, MakeSlice(initiation.state.ephemeral_public_key));
    initiation.state.chaining_key =
      KdfLabel(KdfTemp(initiation.state.chaining_key, MakeSlice(initiation.state.ephemeral_public_key)), 0x1);

    const Result<WireGuardKey> shared_es =
      ComputeWireGuardSharedSecret(initiation.state.ephemeral_private_key, config.peer_public_key);
    if (!shared_es.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(shared_es.error.code,
                             "failed to derive WireGuard ephemeral-static secret: " +
                               shared_es.error.message);
    }
    const auto [chaining_key_after_e, static_key] = MixKey(initiation.state.chaining_key, shared_es.value);
  initiation.state.chaining_key = chaining_key_after_e;

  const auto encrypted_static = EncryptAead<kWireGuardKeySize>(static_key, 0, config.local_public_key.bytes,
                                                               initiation.state.hash);
  if (!encrypted_static.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(encrypted_static.error.code,
                                                     encrypted_static.error.message);
  }
  std::copy(encrypted_static.value.begin(), encrypted_static.value.end(),
            initiation.packet.begin() + static_cast<std::ptrdiff_t>(kInitiationEncryptedStaticOffset));
  initiation.state.hash = MixHash(initiation.state.hash,
                                  MakeSlice(initiation.packet.data() + kInitiationEncryptedStaticOffset,
                                            kInitiationEncryptedStaticSize));

  const auto shared_ss = ComputeWireGuardSharedSecret(config.local_private_key, config.peer_public_key);
  if (!shared_ss.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(shared_ss.error.code,
                                                     "failed to derive WireGuard static shared secret: " +
                                                         shared_ss.error.message);
  }
  const auto [chaining_key_after_s, timestamp_key] = MixKey(initiation.state.chaining_key, shared_ss.value);
  initiation.state.chaining_key = chaining_key_after_s;

  const auto encrypted_timestamp = EncryptAead<kWireGuardTimestampSize>(timestamp_key, 0, timestamp.value,
                                                                        initiation.state.hash);
  if (!encrypted_timestamp.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(encrypted_timestamp.error.code,
                                                     encrypted_timestamp.error.message);
  }
  std::copy(encrypted_timestamp.value.begin(), encrypted_timestamp.value.end(),
            initiation.packet.begin() + static_cast<std::ptrdiff_t>(kInitiationEncryptedTimestampOffset));
  initiation.state.hash = MixHash(initiation.state.hash,
                                  MakeSlice(initiation.packet.data() + kInitiationEncryptedTimestampOffset,
                                            kInitiationEncryptedTimestampSize));

  const Blake2sMac16 mac1 = ComputeMac1(config.peer_public_key, initiation.packet.data(), kInitiationMac1Offset);
  std::copy(mac1.begin(), mac1.end(), initiation.packet.begin() + static_cast<std::ptrdiff_t>(kInitiationMac1Offset));
  return MakeSuccess(initiation);
}

Result<WireGuardHandshakeResponse> RespondToHandshakeInitiationForTest(
    const WireGuardResponderConfig& config,
    const std::uint8_t* packet,
    std::size_t packet_size,
    const WireGuardHandshakeResponseOptions& options) {
  const Result<ResponseState> parsed = ParseInitiationForResponder(config, packet, packet_size);
  if (!parsed.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(parsed.error.code, parsed.error.message);
  }

  WireGuardHandshakeResponse response{};
  response.packet[0] = static_cast<std::uint8_t>(WireGuardMessageType::HandshakeResponse);
  response.receiver_index = parsed.value.initiator_sender_index;

  WireGuardKeyPair key_pair{};
  if (options.ephemeral_private_key.has_value()) {
    key_pair.private_key = *options.ephemeral_private_key;
    const Result<WireGuardKey> public_key = DeriveWireGuardPublicKey(key_pair.private_key);
    if (!public_key.ok()) {
      return MakeFailure<WireGuardHandshakeResponse>(public_key.error.code,
                                                     "failed to derive responder ephemeral public key: " +
                                                         public_key.error.message);
    }
    key_pair.public_key = public_key.value;
  } else {
    const Result<WireGuardKeyPair> generated = GenerateWireGuardKeyPair();
    if (!generated.ok()) {
      return MakeFailure<WireGuardHandshakeResponse>(generated.error.code, generated.error.message);
    }
    key_pair = generated.value;
  }

  if (options.sender_index.has_value()) {
    response.sender_index = *options.sender_index;
  } else {
    const Result<std::uint32_t> random_sender_index = RandomSenderIndex();
    if (!random_sender_index.ok()) {
      return MakeFailure<WireGuardHandshakeResponse>(random_sender_index.error.code,
                                                     random_sender_index.error.message);
    }
    response.sender_index = random_sender_index.value;
  }

  Store32Le(response.packet.data() + kResponseSenderIndexOffset, response.sender_index);
  Store32Le(response.packet.data() + kResponseReceiverIndexOffset, response.receiver_index);
  std::copy(key_pair.public_key.bytes.begin(), key_pair.public_key.bytes.end(),
            response.packet.begin() + static_cast<std::ptrdiff_t>(kResponseEphemeralOffset));

  Blake2sHash chaining_key = parsed.value.chaining_key;
  Blake2sHash hash = parsed.value.hash;
  hash = MixHash(hash, MakeSlice(key_pair.public_key));

  const auto temp_chaining_key = KdfTemp(chaining_key, MakeSlice(key_pair.public_key));
  chaining_key = KdfLabel(temp_chaining_key, 0x1);

  const Result<WireGuardKey> shared_ee =
      ComputeWireGuardSharedSecret(key_pair.private_key, parsed.value.initiator_ephemeral_public);
  if (!shared_ee.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(shared_ee.error.code,
                                                   "failed to derive responder ee shared secret: " +
                                                       shared_ee.error.message);
  }
  chaining_key = MixKey(chaining_key, shared_ee.value).first;

  const Result<WireGuardKey> shared_se =
      ComputeWireGuardSharedSecret(key_pair.private_key, parsed.value.initiator_static_public);
  if (!shared_se.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(shared_se.error.code,
                                                   "failed to derive responder se shared secret: " +
                                                       shared_se.error.message);
  }
  chaining_key = MixKey(chaining_key, shared_se.value).first;

  const PresharedMixResult preshared_mix = MixPresharedKey(chaining_key, MakeEffectivePresharedKey(config));
  chaining_key = preshared_mix.chaining_key;
  hash = MixHash(hash, MakeSlice(preshared_mix.hash_mix));

  const std::array<std::uint8_t, 0> empty_plaintext{};
  const auto encrypted_nothing = EncryptAead<0>(preshared_mix.key, 0, empty_plaintext, hash);
  if (!encrypted_nothing.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(encrypted_nothing.error.code,
                                                   encrypted_nothing.error.message);
  }
  std::copy(encrypted_nothing.value.begin(), encrypted_nothing.value.end(),
            response.packet.begin() + static_cast<std::ptrdiff_t>(kResponseEncryptedNothingOffset));
  hash = MixHash(hash, MakeSlice(response.packet.data() + kResponseEncryptedNothingOffset,
                                 kResponseEncryptedNothingSize));

  const auto [receiving_key, sending_key] = DeriveSessionKeys(chaining_key);
  response.receiving_key = receiving_key;
  response.sending_key = sending_key;

  const Blake2sMac16 mac1 =
      ComputeMac1(parsed.value.initiator_static_public, response.packet.data(), kResponseMac1Offset);
  std::copy(mac1.begin(), mac1.end(), response.packet.begin() + static_cast<std::ptrdiff_t>(kResponseMac1Offset));
  return MakeSuccess(response);
}

Result<WireGuardValidatedHandshake> ConsumeHandshakeResponse(const WireGuardHandshakeConfig& config,
                                                            const WireGuardInitiationState& state,
                                                            const std::uint8_t* packet,
                                                            std::size_t packet_size) {
  if (packet_size != kWireGuardHandshakeResponseSize) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard response packet has an unexpected size");
  }
  if (packet[0] != static_cast<std::uint8_t>(WireGuardMessageType::HandshakeResponse)) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard initiator received a non-response packet");
  }

  const Error reserved_error = ValidateReservedZero(packet, packet_size);
  if (reserved_error) {
    return Result<WireGuardValidatedHandshake>::Failure(reserved_error);
  }

  const std::uint32_t response_sender_index = Load32Le(packet + kResponseSenderIndexOffset);
  const std::uint32_t response_receiver_index = Load32Le(packet + kResponseReceiverIndexOffset);
  if (response_receiver_index != state.sender_index) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard response receiver index did not match the initiator");
  }

  const Blake2sMac16 expected_mac1 = ComputeMac1(config.local_public_key, packet, kResponseMac1Offset);
  if (!std::equal(expected_mac1.begin(), expected_mac1.end(), packet + static_cast<std::ptrdiff_t>(kResponseMac1Offset))) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard response MAC1 is invalid");
  }

  WireGuardKey responder_ephemeral_public{};
  std::copy_n(packet + kResponseEphemeralOffset, kWireGuardKeySize, responder_ephemeral_public.bytes.begin());

  Blake2sHash chaining_key = state.chaining_key;
  Blake2sHash hash = state.hash;
  hash = MixHash(hash, MakeSlice(responder_ephemeral_public));

  const auto temp_chaining_key = KdfTemp(chaining_key, MakeSlice(responder_ephemeral_public));
  chaining_key = KdfLabel(temp_chaining_key, 0x1);

  const Result<WireGuardKey> shared_ee =
      ComputeWireGuardSharedSecret(state.ephemeral_private_key, responder_ephemeral_public);
  if (!shared_ee.ok()) {
    return MakeFailure<WireGuardValidatedHandshake>(shared_ee.error.code,
                                                    "failed to derive initiator ee shared secret: " +
                                                        shared_ee.error.message);
  }
  chaining_key = MixKey(chaining_key, shared_ee.value).first;

  const Result<WireGuardKey> shared_se =
      ComputeWireGuardSharedSecret(config.local_private_key, responder_ephemeral_public);
  if (!shared_se.ok()) {
    return MakeFailure<WireGuardValidatedHandshake>(shared_se.error.code,
                                                    "failed to derive initiator se shared secret: " +
                                                        shared_se.error.message);
  }
  chaining_key = MixKey(chaining_key, shared_se.value).first;

  const PresharedMixResult preshared_mix = MixPresharedKey(chaining_key, MakeEffectivePresharedKey(config));
  chaining_key = preshared_mix.chaining_key;
  hash = MixHash(hash, MakeSlice(preshared_mix.hash_mix));

  const auto decrypted_nothing = DecryptAead<0>(preshared_mix.key, 0,
                                                packet + kResponseEncryptedNothingOffset,
                                                kResponseEncryptedNothingSize, hash,
                                                "encrypted_nothing");
  if (!decrypted_nothing.ok()) {
    return MakeFailure<WireGuardValidatedHandshake>(decrypted_nothing.error.code,
                                                    decrypted_nothing.error.message);
  }

  hash = MixHash(hash, MakeSlice(packet + kResponseEncryptedNothingOffset, kResponseEncryptedNothingSize));
  const auto [sending_key, receiving_key] = DeriveSessionKeys(chaining_key);

  WireGuardValidatedHandshake handshake{};
  handshake.local_sender_index = state.sender_index;
  handshake.peer_sender_index = response_sender_index;
  handshake.sending_key = sending_key;
  handshake.receiving_key = receiving_key;
  return MakeSuccess(handshake);
}

}  // namespace swg