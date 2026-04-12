#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "swg/result.h"
#include "swg/wg_profile.h"

namespace swg {

inline constexpr std::size_t kWireGuardHandshakeInitiationSize = 148;
inline constexpr std::size_t kWireGuardHandshakeResponseSize = 92;
inline constexpr std::size_t kWireGuardCookieReplySize = 64;
inline constexpr std::size_t kWireGuardTransportHeaderSize = 16;
inline constexpr std::size_t kWireGuardTransportKeepaliveSize = 32;

enum class WireGuardMessageType : std::uint8_t {
  HandshakeInitiation = 1,
  HandshakeResponse = 2,
  CookieReply = 3,
  Data = 4,
};

struct WireGuardHandshakeConfig {
  WireGuardKey local_private_key{};
  WireGuardKey local_public_key{};
  WireGuardKey peer_public_key{};
  WireGuardKey preshared_key{};
  bool has_preshared_key = false;
};

struct WireGuardHandshakeInitiationOptions {
  std::optional<WireGuardKey> ephemeral_private_key;
  std::optional<std::uint32_t> sender_index;
  std::optional<std::array<std::uint8_t, 12>> timestamp;
};

struct WireGuardInitiationState {
  std::uint32_t sender_index = 0;
  WireGuardKey ephemeral_private_key{};
  WireGuardKey ephemeral_public_key{};
  std::array<std::uint8_t, 32> chaining_key{};
  std::array<std::uint8_t, 32> hash{};
};

struct WireGuardHandshakeInitiation {
  std::array<std::uint8_t, kWireGuardHandshakeInitiationSize> packet{};
  WireGuardInitiationState state{};
};

struct WireGuardResponderConfig {
  WireGuardKey local_private_key{};
  WireGuardKey local_public_key{};
  std::optional<WireGuardKey> expected_peer_public_key;
  WireGuardKey preshared_key{};
  bool has_preshared_key = false;
};

struct WireGuardHandshakeResponseOptions {
  std::optional<WireGuardKey> ephemeral_private_key;
  std::optional<std::uint32_t> sender_index;
};

struct WireGuardHandshakeResponse {
  std::array<std::uint8_t, kWireGuardHandshakeResponseSize> packet{};
  std::uint32_t sender_index = 0;
  std::uint32_t receiver_index = 0;
  WireGuardKey sending_key{};
  WireGuardKey receiving_key{};
};

struct WireGuardValidatedHandshake {
  std::uint32_t local_sender_index = 0;
  std::uint32_t peer_sender_index = 0;
  WireGuardKey sending_key{};
  WireGuardKey receiving_key{};
};

struct WireGuardTransportKeepalive {
  std::array<std::uint8_t, kWireGuardTransportKeepaliveSize> packet{};
  std::uint32_t receiver_index = 0;
  std::uint64_t counter = 0;
};

Result<WireGuardHandshakeInitiation> CreateHandshakeInitiation(
    const WireGuardHandshakeConfig& config,
    const WireGuardHandshakeInitiationOptions& options = {});
Result<WireGuardHandshakeResponse> RespondToHandshakeInitiationForTest(
    const WireGuardResponderConfig& config,
    const std::uint8_t* packet,
    std::size_t packet_size,
    const WireGuardHandshakeResponseOptions& options = {});
Result<WireGuardValidatedHandshake> ConsumeHandshakeResponse(const WireGuardHandshakeConfig& config,
                                                             const WireGuardInitiationState& state,
                                                             const std::uint8_t* packet,
                                                             std::size_t packet_size);
Result<WireGuardTransportKeepalive> CreateTransportKeepalivePacket(const WireGuardKey& sending_key,
                                                                   std::uint32_t receiver_index,
                                                                   std::uint64_t counter = 0);
Result<std::uint64_t> ConsumeTransportKeepaliveForTest(const WireGuardKey& receiving_key,
                                                       std::uint32_t expected_receiver_index,
                                                       const std::uint8_t* packet,
                                                       std::size_t packet_size);

}  // namespace swg