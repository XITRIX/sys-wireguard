#include "swg/wg_handshake.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "swg/wg_crypto.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
extern "C" {
#include "wireguard.h"
}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

extern "C" void swg_wireguard_lwip_set_random_override(const uint8_t* bytes, size_t size);
extern "C" void swg_wireguard_lwip_set_tai64n_override(const uint8_t* bytes, size_t size);
extern "C" void swg_wireguard_lwip_clear_overrides();

namespace swg {
namespace {

constexpr std::size_t kMessageReservedOffset = 1;
constexpr std::size_t kMessageReservedSize = 3;
constexpr std::size_t kTransportReceiverIndexOffset = 4;
constexpr std::size_t kTransportCounterOffset = 8;
constexpr std::size_t kTransportEncryptedPayloadOffset = kWireGuardTransportHeaderSize;
constexpr std::size_t kAeadTagSize = WIREGUARD_AUTHTAG_LEN;

static_assert(sizeof(message_handshake_initiation) == kWireGuardHandshakeInitiationSize);
static_assert(sizeof(message_handshake_response) == kWireGuardHandshakeResponseSize);
static_assert(sizeof(message_cookie_reply) == kWireGuardCookieReplySize);
static_assert(sizeof(message_transport_data) == kWireGuardTransportHeaderSize);
static_assert(WIREGUARD_PUBLIC_KEY_LEN == kWireGuardKeySize);
static_assert(WIREGUARD_PRIVATE_KEY_LEN == kWireGuardKeySize);
static_assert(WIREGUARD_SESSION_KEY_LEN == kWireGuardKeySize);

std::once_flag g_wireguard_init_once;

void EnsureWireGuardInit() {
  std::call_once(g_wireguard_init_once, []() {
    wireguard_init();
  });
}

std::uint32_t Load32Le(const std::uint8_t* input) {
  return static_cast<std::uint32_t>(input[0]) |
         (static_cast<std::uint32_t>(input[1]) << 8) |
         (static_cast<std::uint32_t>(input[2]) << 16) |
         (static_cast<std::uint32_t>(input[3]) << 24);
}

std::uint64_t Load64Le(const std::uint8_t* input) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(input[index]) << (index * 8);
  }
  return value;
}

void Store32Le(std::uint8_t* output, std::uint32_t value) {
  output[0] = static_cast<std::uint8_t>(value & 0xFFu);
  output[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  output[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  output[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

void Store64Le(std::uint8_t* output, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    output[index] = static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFu);
  }
}

void AppendSenderIndex(std::vector<std::uint8_t>* output, std::uint32_t sender_index) {
  const std::size_t offset = output->size();
  output->resize(offset + sizeof(std::uint32_t));
  Store32Le(output->data() + static_cast<std::ptrdiff_t>(offset), sender_index);
}

Error ValidateReservedZero(const std::uint8_t* packet, std::size_t packet_size) {
  if (packet_size < kMessageReservedOffset + kMessageReservedSize) {
    return MakeError(ErrorCode::ParseError, "WireGuard packet is too small to contain reserved bytes");
  }

  for (std::size_t index = 0; index < kMessageReservedSize; ++index) {
    if (packet[kMessageReservedOffset + index] != 0) {
      return MakeError(ErrorCode::ParseError, "WireGuard packet reserved bytes must be zero");
    }
  }

  return Error::None();
}

WireGuardKey CopyWireGuardKey(const std::uint8_t* input) {
  WireGuardKey key{};
  std::copy_n(input, key.bytes.size(), key.bytes.begin());
  return key;
}

void CopyWireGuardKeyTo(std::uint8_t* output, const WireGuardKey& key) {
  std::copy_n(key.bytes.begin(), key.bytes.size(), output);
}

bool KeysEqual(const std::uint8_t* lhs, const WireGuardKey& rhs) {
  return std::equal(rhs.bytes.begin(), rhs.bytes.end(), lhs);
}

struct UpstreamContext {
  wireguard_device device{};

  wireguard_peer& peer() {
    return device.peers[0];
  }

  const wireguard_peer& peer() const {
    return device.peers[0];
  }
};

Result<UpstreamContext> MakeInitiatorContext(const WireGuardHandshakeConfig& config) {
  EnsureWireGuardInit();

  UpstreamContext context{};
  if (!wireguard_device_init(&context.device, config.local_private_key.bytes.data())) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "wireguard-lwip rejected the local private key");
  }

  if (!KeysEqual(context.device.public_key, config.local_public_key)) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "local private key does not match the configured local public key");
  }

  const std::uint8_t* preshared_key = config.has_preshared_key ? config.preshared_key.bytes.data() : nullptr;
  if (!wireguard_peer_init(&context.device, &context.peer(), config.peer_public_key.bytes.data(), preshared_key)) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "wireguard-lwip rejected the configured peer");
  }

  return MakeSuccess(std::move(context));
}

Result<UpstreamContext> MakeResponderContext(const WireGuardResponderConfig& config) {
  EnsureWireGuardInit();

  if (!config.expected_peer_public_key.has_value()) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "test responder requires an expected peer public key");
  }

  UpstreamContext context{};
  if (!wireguard_device_init(&context.device, config.local_private_key.bytes.data())) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "wireguard-lwip rejected the responder private key");
  }

  if (!KeysEqual(context.device.public_key, config.local_public_key)) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "responder private key does not match the configured responder public key");
  }

  const std::uint8_t* preshared_key = config.has_preshared_key ? config.preshared_key.bytes.data() : nullptr;
  if (!wireguard_peer_init(&context.device, &context.peer(), config.expected_peer_public_key->bytes.data(),
                           preshared_key)) {
    return MakeFailure<UpstreamContext>(ErrorCode::InvalidConfig,
                                        "wireguard-lwip rejected the expected responder peer");
  }

  return MakeSuccess(std::move(context));
}

void CopyInitiationStateFromPeer(const wireguard_peer& peer, WireGuardInitiationState* state) {
  state->sender_index = peer.handshake.local_index;
  state->ephemeral_private_key = CopyWireGuardKey(peer.handshake.ephemeral_private);
  state->ephemeral_public_key = CopyWireGuardKey(peer.handshake.remote_ephemeral);
  std::copy_n(peer.handshake.chaining_key, state->chaining_key.size(), state->chaining_key.begin());
  std::copy_n(peer.handshake.hash, state->hash.size(), state->hash.begin());
}

void CopyInitiationStateToPeer(const WireGuardInitiationState& state, wireguard_peer* peer) {
  std::memset(&peer->handshake, 0, sizeof(peer->handshake));
  peer->handshake.valid = true;
  peer->handshake.initiator = true;
  peer->handshake.local_index = state.sender_index;
  CopyWireGuardKeyTo(peer->handshake.ephemeral_private, state.ephemeral_private_key);
  CopyWireGuardKeyTo(peer->handshake.remote_ephemeral, state.ephemeral_public_key);
  std::copy_n(state.chaining_key.begin(), state.chaining_key.size(), peer->handshake.chaining_key);
  std::copy_n(state.hash.begin(), state.hash.size(), peer->handshake.hash);
}

const wireguard_keypair* FindKeypairForLocalIndex(const wireguard_peer& peer, std::uint32_t local_index) {
  if (peer.curr_keypair.valid && peer.curr_keypair.local_index == local_index) {
    return &peer.curr_keypair;
  }
  if (peer.next_keypair.valid && peer.next_keypair.local_index == local_index) {
    return &peer.next_keypair;
  }
  if (peer.prev_keypair.valid && peer.prev_keypair.local_index == local_index) {
    return &peer.prev_keypair;
  }
  return nullptr;
}

Result<const wireguard_keypair*> RequireKeypairForLocalIndex(const wireguard_peer& peer,
                                                            std::uint32_t local_index) {
  const wireguard_keypair* keypair = FindKeypairForLocalIndex(peer, local_index);
  if (keypair == nullptr) {
    return MakeFailure<const wireguard_keypair*>(ErrorCode::InvalidState,
                                                 "wireguard-lwip did not publish a session keypair");
  }
  return MakeSuccess(keypair);
}

bool ValidateMac1(wireguard_device* device,
                  const std::uint8_t* packet,
                  std::size_t checked_size,
                  const std::uint8_t* mac1) {
  return wireguard_check_mac1(device, packet, checked_size, mac1);
}

struct ScopedUpstreamOverrides {
  explicit ScopedUpstreamOverrides(const std::vector<std::uint8_t>& random_bytes,
                                   const std::array<std::uint8_t, 12>* timestamp = nullptr) {
    swg_wireguard_lwip_set_random_override(random_bytes.data(), random_bytes.size());
    if (timestamp != nullptr) {
      swg_wireguard_lwip_set_tai64n_override(timestamp->data(), timestamp->size());
    }
  }

  ~ScopedUpstreamOverrides() {
    swg_wireguard_lwip_clear_overrides();
  }

  ScopedUpstreamOverrides(const ScopedUpstreamOverrides&) = delete;
  ScopedUpstreamOverrides& operator=(const ScopedUpstreamOverrides&) = delete;
};

Result<std::vector<std::uint8_t>> BuildInitiationRandomScript(
    const WireGuardHandshakeInitiationOptions& options) {
  std::vector<std::uint8_t> random_bytes;
  if (options.ephemeral_private_key.has_value()) {
    random_bytes.insert(random_bytes.end(), options.ephemeral_private_key->bytes.begin(),
                        options.ephemeral_private_key->bytes.end());
  } else if (options.sender_index.has_value()) {
    random_bytes.resize(kWireGuardKeySize);
    const Error random_error = GenerateRandomBytes(random_bytes.data(), random_bytes.size());
    if (random_error) {
      return MakeFailure<std::vector<std::uint8_t>>(random_error.code, random_error.message);
    }
  }

  if (options.sender_index.has_value()) {
    AppendSenderIndex(&random_bytes, *options.sender_index);
  }

  return MakeSuccess(std::move(random_bytes));
}

Result<std::vector<std::uint8_t>> BuildResponseRandomScript(
    const WireGuardHandshakeResponseOptions& options) {
  std::vector<std::uint8_t> random_bytes;
  if (options.ephemeral_private_key.has_value()) {
    random_bytes.insert(random_bytes.end(), options.ephemeral_private_key->bytes.begin(),
                        options.ephemeral_private_key->bytes.end());
  } else if (options.sender_index.has_value()) {
    random_bytes.resize(kWireGuardKeySize);
    const Error random_error = GenerateRandomBytes(random_bytes.data(), random_bytes.size());
    if (random_error) {
      return MakeFailure<std::vector<std::uint8_t>>(random_error.code, random_error.message);
    }
  }

  if (options.sender_index.has_value()) {
    AppendSenderIndex(&random_bytes, *options.sender_index);
  }

  return MakeSuccess(std::move(random_bytes));
}

}  // namespace

Result<WireGuardHandshakeInitiation> CreateHandshakeInitiation(
    const WireGuardHandshakeConfig& config,
    const WireGuardHandshakeInitiationOptions& options) {
  Result<UpstreamContext> context = MakeInitiatorContext(config);
  if (!context.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(context.error.code, context.error.message);
  }

  const Result<std::vector<std::uint8_t>> random_script = BuildInitiationRandomScript(options);
  if (!random_script.ok()) {
    return MakeFailure<WireGuardHandshakeInitiation>(random_script.error.code, random_script.error.message);
  }

  const ScopedUpstreamOverrides upstream_overrides(
      random_script.value, options.timestamp.has_value() ? &*options.timestamp : nullptr);

  message_handshake_initiation message{};
  if (!wireguard_create_handshake_initiation(&context.value.device, &context.value.peer(), &message)) {
    return MakeFailure<WireGuardHandshakeInitiation>(ErrorCode::InvalidState,
                                                    "wireguard-lwip failed to build a handshake initiation");
  }

  WireGuardHandshakeInitiation initiation{};
  std::memcpy(initiation.packet.data(), &message, sizeof(message));
  CopyInitiationStateFromPeer(context.value.peer(), &initiation.state);
  initiation.state.ephemeral_public_key = CopyWireGuardKey(message.ephemeral);
  return MakeSuccess(initiation);
}

Result<WireGuardHandshakeResponse> RespondToHandshakeInitiationForTest(
    const WireGuardResponderConfig& config,
    const std::uint8_t* packet,
    std::size_t packet_size,
    const WireGuardHandshakeResponseOptions& options) {
  if (packet == nullptr) {
    return MakeFailure<WireGuardHandshakeResponse>(ErrorCode::ParseError,
                                                   "WireGuard initiation packet pointer must not be null");
  }
  if (packet_size != kWireGuardHandshakeInitiationSize ||
      wireguard_get_message_type(packet, packet_size) != MESSAGE_HANDSHAKE_INITIATION) {
    return MakeFailure<WireGuardHandshakeResponse>(ErrorCode::ParseError,
                                                   "WireGuard responder received a non-initiation packet");
  }

  const Error reserved_error = ValidateReservedZero(packet, packet_size);
  if (reserved_error) {
    return Result<WireGuardHandshakeResponse>::Failure(reserved_error);
  }

  Result<UpstreamContext> context = MakeResponderContext(config);
  if (!context.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(context.error.code, context.error.message);
  }

  const auto* initiation = reinterpret_cast<const message_handshake_initiation*>(packet);
  if (!ValidateMac1(&context.value.device, packet, sizeof(message_handshake_initiation) - (2 * WIREGUARD_COOKIE_LEN),
                    initiation->mac1)) {
    return MakeFailure<WireGuardHandshakeResponse>(ErrorCode::ParseError,
                                                   "WireGuard initiation MAC1 is invalid");
  }

  message_handshake_initiation initiation_copy{};
  std::memcpy(&initiation_copy, packet, sizeof(initiation_copy));
  wireguard_peer* peer = wireguard_process_initiation_message(&context.value.device, &initiation_copy);
  if (peer == nullptr) {
    return MakeFailure<WireGuardHandshakeResponse>(ErrorCode::ParseError,
                                                   "wireguard-lwip rejected the handshake initiation");
  }

  const Result<std::vector<std::uint8_t>> random_script = BuildResponseRandomScript(options);
  if (!random_script.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(random_script.error.code, random_script.error.message);
  }

  const ScopedUpstreamOverrides upstream_overrides(random_script.value);

  message_handshake_response response_message{};
  if (!wireguard_create_handshake_response(&context.value.device, peer, &response_message)) {
    return MakeFailure<WireGuardHandshakeResponse>(ErrorCode::InvalidState,
                                                   "wireguard-lwip failed to build a handshake response");
  }

  const std::uint32_t local_sender_index = response_message.sender;
  const std::uint32_t peer_sender_index = response_message.receiver;
  wireguard_start_session(peer, false);

  const Result<const wireguard_keypair*> keypair = RequireKeypairForLocalIndex(*peer, local_sender_index);
  if (!keypair.ok()) {
    return MakeFailure<WireGuardHandshakeResponse>(keypair.error.code, keypair.error.message);
  }

  WireGuardHandshakeResponse response{};
  std::memcpy(response.packet.data(), &response_message, sizeof(response_message));
  response.sender_index = local_sender_index;
  response.receiver_index = peer_sender_index;
  response.sending_key = CopyWireGuardKey(keypair.value->sending_key);
  response.receiving_key = CopyWireGuardKey(keypair.value->receiving_key);
  return MakeSuccess(response);
}

Result<WireGuardValidatedHandshake> ConsumeHandshakeResponse(const WireGuardHandshakeConfig& config,
                                                             const WireGuardInitiationState& state,
                                                             const std::uint8_t* packet,
                                                             std::size_t packet_size) {
  if (packet == nullptr) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard response packet pointer must not be null");
  }
  if (packet_size != kWireGuardHandshakeResponseSize ||
      wireguard_get_message_type(packet, packet_size) != MESSAGE_HANDSHAKE_RESPONSE) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard initiator received a non-response packet");
  }

  const Error reserved_error = ValidateReservedZero(packet, packet_size);
  if (reserved_error) {
    return Result<WireGuardValidatedHandshake>::Failure(reserved_error);
  }

  const std::uint32_t response_sender_index = Load32Le(packet + 4);
  const std::uint32_t response_receiver_index = Load32Le(packet + 8);
  if (response_receiver_index != state.sender_index) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard response receiver index did not match the initiator");
  }

  Result<UpstreamContext> context = MakeInitiatorContext(config);
  if (!context.ok()) {
    return MakeFailure<WireGuardValidatedHandshake>(context.error.code, context.error.message);
  }

  const auto* response = reinterpret_cast<const message_handshake_response*>(packet);
  if (!ValidateMac1(&context.value.device, packet, sizeof(message_handshake_response) - (2 * WIREGUARD_COOKIE_LEN),
                    response->mac1)) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "WireGuard response MAC1 is invalid");
  }

  CopyInitiationStateToPeer(state, &context.value.peer());

  message_handshake_response response_copy{};
  std::memcpy(&response_copy, packet, sizeof(response_copy));
  if (!wireguard_process_handshake_response(&context.value.device, &context.value.peer(), &response_copy)) {
    return MakeFailure<WireGuardValidatedHandshake>(ErrorCode::ParseError,
                                                    "wireguard-lwip rejected the handshake response");
  }

  wireguard_start_session(&context.value.peer(), true);
  const Result<const wireguard_keypair*> keypair =
      RequireKeypairForLocalIndex(context.value.peer(), state.sender_index);
  if (!keypair.ok()) {
    return MakeFailure<WireGuardValidatedHandshake>(keypair.error.code, keypair.error.message);
  }

  WireGuardValidatedHandshake handshake{};
  handshake.local_sender_index = state.sender_index;
  handshake.peer_sender_index = response_sender_index;
  handshake.sending_key = CopyWireGuardKey(keypair.value->sending_key);
  handshake.receiving_key = CopyWireGuardKey(keypair.value->receiving_key);
  return MakeSuccess(handshake);
}

Result<WireGuardTransportKeepalive> CreateTransportKeepalivePacket(const WireGuardKey& sending_key,
                                                                   std::uint32_t receiver_index,
                                                                   std::uint64_t counter) {
  const Result<WireGuardTransportPacket> transport = CreateTransportPacket(sending_key, receiver_index, {}, counter);
  if (!transport.ok()) {
    return MakeFailure<WireGuardTransportKeepalive>(transport.error.code, transport.error.message);
  }
  if (transport.value.packet.size() != kWireGuardTransportKeepaliveSize) {
    return MakeFailure<WireGuardTransportKeepalive>(ErrorCode::ParseError,
                                                    "WireGuard transport keepalive produced an unexpected size");
  }

  WireGuardTransportKeepalive keepalive{};
  keepalive.receiver_index = receiver_index;
  keepalive.counter = counter;
  std::copy(transport.value.packet.begin(), transport.value.packet.end(), keepalive.packet.begin());
  return MakeSuccess(keepalive);
}

Result<WireGuardTransportPacket> CreateTransportPacket(const WireGuardKey& sending_key,
                                                       std::uint32_t receiver_index,
                                                       const std::vector<std::uint8_t>& payload,
                                                       std::uint64_t counter) {
  EnsureWireGuardInit();

  WireGuardTransportPacket transport{};
  transport.receiver_index = receiver_index;
  transport.counter = counter;
  transport.packet.resize(kWireGuardTransportHeaderSize + payload.size() + kAeadTagSize);
  transport.packet[0] = static_cast<std::uint8_t>(WireGuardMessageType::Data);
  Store32Le(transport.packet.data() + kTransportReceiverIndexOffset, receiver_index);
  Store64Le(transport.packet.data() + kTransportCounterOffset, counter);

  std::uint8_t* encrypted_payload = transport.packet.data() + kTransportEncryptedPayloadOffset;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), encrypted_payload);
  }

  wireguard_keypair keypair{};
  keypair.valid = true;
  keypair.sending_valid = true;
  keypair.sending_counter = counter;
  keypair.remote_index = receiver_index;
  CopyWireGuardKeyTo(keypair.sending_key, sending_key);

  wireguard_encrypt_packet(encrypted_payload, encrypted_payload, payload.size(), &keypair);
  return MakeSuccess(std::move(transport));
}

Result<WireGuardConsumedTransportPacket> ConsumeTransportPacket(const WireGuardKey& receiving_key,
                                                                std::uint32_t expected_receiver_index,
                                                                const std::uint8_t* packet,
                                                                std::size_t packet_size) {
  EnsureWireGuardInit();

  if (packet == nullptr) {
    return MakeFailure<WireGuardConsumedTransportPacket>(ErrorCode::ParseError,
                                                         "WireGuard transport packet pointer must not be null");
  }
  if (packet_size < kWireGuardTransportHeaderSize + kAeadTagSize ||
      wireguard_get_message_type(packet, packet_size) != MESSAGE_TRANSPORT_DATA) {
    return MakeFailure<WireGuardConsumedTransportPacket>(ErrorCode::ParseError,
                                                         "WireGuard transport packet has an unexpected size or type");
  }

  const Error reserved_error = ValidateReservedZero(packet, packet_size);
  if (reserved_error) {
    return Result<WireGuardConsumedTransportPacket>::Failure(reserved_error);
  }

  const std::uint32_t receiver_index = Load32Le(packet + kTransportReceiverIndexOffset);
  if (receiver_index != expected_receiver_index) {
    return MakeFailure<WireGuardConsumedTransportPacket>(
        ErrorCode::ParseError,
        "WireGuard transport packet receiver index did not match the expected peer index");
  }

  const std::size_t encrypted_size = packet_size - kTransportEncryptedPayloadOffset;
  const std::size_t plaintext_size = encrypted_size - kAeadTagSize;
  std::vector<std::uint8_t> plaintext(plaintext_size);
  std::array<std::uint8_t, 1> empty_plaintext{};
  std::uint8_t* plaintext_data = plaintext.empty() ? empty_plaintext.data() : plaintext.data();

  wireguard_keypair keypair{};
  keypair.valid = true;
  keypair.receiving_valid = true;
  keypair.local_index = expected_receiver_index;
  CopyWireGuardKeyTo(keypair.receiving_key, receiving_key);

  const std::uint64_t counter = Load64Le(packet + kTransportCounterOffset);
  if (!wireguard_decrypt_packet(plaintext_data, packet + kTransportEncryptedPayloadOffset, encrypted_size, counter,
                                &keypair)) {
    return MakeFailure<WireGuardConsumedTransportPacket>(ErrorCode::ParseError,
                                                         "wireguard-lwip rejected the transport packet");
  }

  WireGuardConsumedTransportPacket transport{};
  transport.counter = counter;
  transport.payload = std::move(plaintext);
  return MakeSuccess(std::move(transport));
}

Result<std::uint64_t> ConsumeTransportKeepalivePacket(const WireGuardKey& receiving_key,
                                                      std::uint32_t expected_receiver_index,
                                                      const std::uint8_t* packet,
                                                      std::size_t packet_size) {
  const Result<WireGuardConsumedTransportPacket> transport =
      ConsumeTransportPacket(receiving_key, expected_receiver_index, packet, packet_size);
  if (!transport.ok()) {
    return MakeFailure<std::uint64_t>(transport.error.code, transport.error.message);
  }
  if (!transport.value.payload.empty()) {
    return MakeFailure<std::uint64_t>(ErrorCode::ParseError,
                                      "WireGuard transport keepalive unexpectedly carried payload bytes");
  }

  return MakeSuccess(transport.value.counter);
}

Result<std::uint64_t> ConsumeTransportKeepaliveForTest(const WireGuardKey& receiving_key,
                                                       std::uint32_t expected_receiver_index,
                                                       const std::uint8_t* packet,
                                                       std::size_t packet_size) {
  return ConsumeTransportKeepalivePacket(receiving_key, expected_receiver_index, packet, packet_size);
}

}  // namespace swg
