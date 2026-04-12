#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "swg/app_session.h"
#include "swg/client.h"
#include "swg/config.h"
#include "swg/ipc_codec.h"
#include "swg/ipv4_tcp.h"
#include "swg/moonlight.h"
#include "swg/session_socket.h"
#include "swg/state_machine.h"
#include "swg/tunnel_datagram.h"
#include "swg/tunnel_stream.h"
#include "swg/tunnel_dns.h"
#include "swg/wg_crypto.h"
#include "swg/wg_handshake.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/wg_engine.h"
#include "swg_sysmodule/host_transport.h"
#include "swg_sysmodule/local_service.h"
#include "swg_sysmodule/socket_runtime.h"

namespace {

bool Require(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "test failure: " << message << '\n';
    return false;
  }
  return true;
}

constexpr const char* kSamplePrivateKey = "oP1+wj0r1k+4bqyOp9QKF77GZaPGTzlvzCm/44vR63E=";
constexpr const char* kSamplePublicKey = "Kx666j8fvAMhWmqVQsmtmXeljBNvf0vB1SEHaUa2iAI=";
constexpr const char* kSamplePeerPrivateKey = "mJTpfsnklx/WSF8AEbdbvB8pimF17uoRX69FYVxs2F4=";
constexpr const char* kSampleLocalPublicKey = "qsqG0CFCWMI/D34HIRhM9ZdXpmhvrKJK/FNQ5Q1egRo=";
constexpr const char* kSamplePresharedKey = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";

std::string DescribeSocketError(const char* operation) {
  return std::string(operation) + " failed: " + std::strerror(errno);
}

swg::Result<swg::WireGuardHandshakeConfig> MakeHandshakeInitiatorConfig() {
  const auto local_private = swg::ParseWireGuardKey(kSamplePrivateKey, "private_key");
  if (!local_private.ok()) {
    return swg::MakeFailure<swg::WireGuardHandshakeConfig>(local_private.error.code, local_private.error.message);
  }

  const auto local_public = swg::ParseWireGuardKey(kSampleLocalPublicKey, "local_public_key");
  if (!local_public.ok()) {
    return swg::MakeFailure<swg::WireGuardHandshakeConfig>(local_public.error.code, local_public.error.message);
  }

  const auto peer_public = swg::ParseWireGuardKey(kSamplePublicKey, "public_key");
  if (!peer_public.ok()) {
    return swg::MakeFailure<swg::WireGuardHandshakeConfig>(peer_public.error.code, peer_public.error.message);
  }

  const auto preshared = swg::ParseWireGuardKey(kSamplePresharedKey, "preshared_key");
  if (!preshared.ok()) {
    return swg::MakeFailure<swg::WireGuardHandshakeConfig>(preshared.error.code, preshared.error.message);
  }

  swg::WireGuardHandshakeConfig config{};
  config.local_private_key = local_private.value;
  config.local_public_key = local_public.value;
  config.peer_public_key = peer_public.value;
  config.preshared_key = preshared.value;
  config.has_preshared_key = true;
  return swg::MakeSuccess(config);
}

swg::Result<swg::WireGuardResponderConfig> MakeHandshakeResponderConfig() {
  const auto responder_private = swg::ParseWireGuardKey(kSamplePeerPrivateKey, "responder_private_key");
  if (!responder_private.ok()) {
    return swg::MakeFailure<swg::WireGuardResponderConfig>(responder_private.error.code,
                                                           responder_private.error.message);
  }

  const auto responder_public = swg::ParseWireGuardKey(kSamplePublicKey, "responder_public_key");
  if (!responder_public.ok()) {
    return swg::MakeFailure<swg::WireGuardResponderConfig>(responder_public.error.code,
                                                           responder_public.error.message);
  }

  const auto expected_peer = swg::ParseWireGuardKey(kSampleLocalPublicKey, "expected_peer_public_key");
  if (!expected_peer.ok()) {
    return swg::MakeFailure<swg::WireGuardResponderConfig>(expected_peer.error.code,
                                                           expected_peer.error.message);
  }

  const auto preshared = swg::ParseWireGuardKey(kSamplePresharedKey, "preshared_key");
  if (!preshared.ok()) {
    return swg::MakeFailure<swg::WireGuardResponderConfig>(preshared.error.code, preshared.error.message);
  }

  swg::WireGuardResponderConfig config{};
  config.local_private_key = responder_private.value;
  config.local_public_key = responder_public.value;
  config.expected_peer_public_key = expected_peer.value;
  config.preshared_key = preshared.value;
  config.has_preshared_key = true;
  return swg::MakeSuccess(config);
}

std::vector<std::vector<std::uint8_t>> MakePayloadSequence(std::vector<std::uint8_t> payload) {
  std::vector<std::vector<std::uint8_t>> payloads;
  if (!payload.empty()) {
    payloads.push_back(std::move(payload));
  }
  return payloads;
}

class LocalHandshakeResponder {
 public:
  explicit LocalHandshakeResponder(std::uint32_t expected_additional_keepalives = 0,
                                   std::uint32_t inbound_keepalives_to_send = 0,
                                   std::vector<std::uint8_t> inbound_transport_payload = {},
                                   std::vector<std::uint8_t> expected_outbound_transport_payload = {})
      : LocalHandshakeResponder(expected_additional_keepalives, inbound_keepalives_to_send,
                                MakePayloadSequence(std::move(inbound_transport_payload)),
                                MakePayloadSequence(std::move(expected_outbound_transport_payload))) {}

  LocalHandshakeResponder(std::uint32_t expected_additional_keepalives,
                          std::uint32_t inbound_keepalives_to_send,
                          std::vector<std::vector<std::uint8_t>> inbound_transport_payloads,
                          std::vector<std::vector<std::uint8_t>> expected_outbound_transport_payloads)
      : expected_additional_keepalives_(expected_additional_keepalives),
        inbound_keepalives_to_send_(inbound_keepalives_to_send),
        inbound_transport_payloads_(std::move(inbound_transport_payloads)),
        expected_outbound_transport_payloads_(std::move(expected_outbound_transport_payloads)) {
    socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
      error_ = DescribeSocketError("socket");
      return;
    }

    timeval timeout{};
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    if (::setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
      error_ = DescribeSocketError("setsockopt");
      return;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(socket_fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      error_ = DescribeSocketError("bind");
      return;
    }

    socklen_t address_length = sizeof(address);
    if (::getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&address), &address_length) != 0) {
      error_ = DescribeSocketError("getsockname");
      return;
    }

    port_ = ntohs(address.sin_port);
    worker_ = std::thread([this]() {
      Run();
    });
  }

  LocalHandshakeResponder(const LocalHandshakeResponder&) = delete;
  LocalHandshakeResponder& operator=(const LocalHandshakeResponder&) = delete;

  ~LocalHandshakeResponder() {
    Join();
    if (socket_fd_ >= 0) {
      ::close(socket_fd_);
    }
  }

  bool ready() const {
    return error_.empty() && socket_fd_ >= 0 && port_ != 0;
  }

  std::uint16_t port() const {
    return port_;
  }

  bool Join() {
    if (worker_.joinable()) {
      worker_.join();
    }
    return error_.empty() && responded_ && keepalive_validated_ &&
           validated_additional_keepalives_ == expected_additional_keepalives_ &&
           validated_outbound_transport_packets_ == expected_outbound_transport_payloads_.size();
  }

  const std::string& error() const {
    return error_;
  }

 private:
  void Run() {
    const auto responder_config = MakeHandshakeResponderConfig();
    if (!responder_config.ok()) {
      error_ = responder_config.error.message;
      return;
    }

    std::array<std::uint8_t, 256> buffer{};
    sockaddr_in client_address{};
    socklen_t client_length = sizeof(client_address);
    const ssize_t received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                        reinterpret_cast<sockaddr*>(&client_address), &client_length);
    if (received < 0) {
      error_ = DescribeSocketError("recvfrom");
      return;
    }

    const auto response = swg::RespondToHandshakeInitiationForTest(
        responder_config.value, buffer.data(), static_cast<std::size_t>(received));
    if (!response.ok()) {
      error_ = response.error.message;
      return;
    }

    const ssize_t sent = ::sendto(socket_fd_, response.value.packet.data(), response.value.packet.size(), 0,
                                  reinterpret_cast<const sockaddr*>(&client_address), client_length);
    if (sent < 0) {
      error_ = DescribeSocketError("sendto");
      return;
    }
    if (static_cast<std::size_t>(sent) != response.value.packet.size()) {
      error_ = "sendto returned a short WireGuard response";
      return;
    }

    responded_ = true;

    client_length = sizeof(client_address);
    const ssize_t keepalive_received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                                  reinterpret_cast<sockaddr*>(&client_address), &client_length);
    if (keepalive_received < 0) {
      error_ = DescribeSocketError("recvfrom");
      return;
    }

    const auto keepalive = swg::ConsumeTransportKeepaliveForTest(
        response.value.receiving_key, response.value.sender_index, buffer.data(),
        static_cast<std::size_t>(keepalive_received));
    if (!keepalive.ok()) {
      error_ = keepalive.error.message;
      return;
    }

    if (keepalive.value != 0) {
      error_ = "post-handshake keepalive used an unexpected transport counter";
      return;
    }

    keepalive_validated_ = true;

    for (std::uint32_t inbound_counter = 0; inbound_counter < inbound_keepalives_to_send_; ++inbound_counter) {
      const auto inbound_keepalive = swg::CreateTransportKeepalivePacket(
          response.value.sending_key, response.value.receiver_index, inbound_counter);
      if (!inbound_keepalive.ok()) {
        error_ = inbound_keepalive.error.message;
        return;
      }

      const ssize_t inbound_sent = ::sendto(socket_fd_, inbound_keepalive.value.packet.data(),
                                            inbound_keepalive.value.packet.size(), 0,
                                            reinterpret_cast<const sockaddr*>(&client_address), client_length);
      if (inbound_sent < 0) {
        error_ = DescribeSocketError("sendto");
        return;
      }
      if (static_cast<std::size_t>(inbound_sent) != inbound_keepalive.value.packet.size()) {
        error_ = "sendto returned a short authenticated keepalive";
        return;
      }
    }

    std::uint64_t inbound_transport_counter = inbound_keepalives_to_send_;
    for (const auto& inbound_transport_payload : inbound_transport_payloads_) {
      const auto inbound_transport = swg::CreateTransportPacket(
          response.value.sending_key, response.value.receiver_index,
          inbound_transport_payload, inbound_transport_counter);
      if (!inbound_transport.ok()) {
        error_ = inbound_transport.error.message;
        return;
      }

      const ssize_t inbound_sent = ::sendto(socket_fd_, inbound_transport.value.packet.data(),
                                            inbound_transport.value.packet.size(), 0,
                                            reinterpret_cast<const sockaddr*>(&client_address), client_length);
      if (inbound_sent < 0) {
        error_ = DescribeSocketError("sendto");
        return;
      }
      if (static_cast<std::size_t>(inbound_sent) != inbound_transport.value.packet.size()) {
        error_ = "sendto returned a short authenticated transport payload";
        return;
      }

      ++inbound_transport_counter;
    }

    std::uint64_t expected_outbound_counter = 1;
    for (const auto& expected_outbound_transport_payload : expected_outbound_transport_payloads_) {
      client_length = sizeof(client_address);
      const ssize_t outbound_received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                                   reinterpret_cast<sockaddr*>(&client_address), &client_length);
      if (outbound_received < 0) {
        error_ = DescribeSocketError("recvfrom");
        return;
      }

      const auto outbound_transport = swg::ConsumeTransportPacket(
          response.value.receiving_key, response.value.sender_index, buffer.data(),
          static_cast<std::size_t>(outbound_received));
      if (!outbound_transport.ok()) {
        error_ = outbound_transport.error.message;
        return;
      }

      if (outbound_transport.value.counter != expected_outbound_counter) {
        error_ = "outbound transport payload used an unexpected transport counter";
        return;
      }
      if (outbound_transport.value.payload != expected_outbound_transport_payload) {
        error_ = "outbound transport payload bytes did not match the expected authenticated payload";
        return;
      }

      ++validated_outbound_transport_packets_;
      ++expected_outbound_counter;
    }

    for (std::uint32_t expected_counter = 1; expected_counter <= expected_additional_keepalives_; ++expected_counter) {
      client_length = sizeof(client_address);
      const ssize_t periodic_received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                                   reinterpret_cast<sockaddr*>(&client_address), &client_length);
      if (periodic_received < 0) {
        error_ = DescribeSocketError("recvfrom");
        return;
      }

      const auto periodic_keepalive = swg::ConsumeTransportKeepaliveForTest(
          response.value.receiving_key, response.value.sender_index, buffer.data(),
          static_cast<std::size_t>(periodic_received));
      if (!periodic_keepalive.ok()) {
        error_ = periodic_keepalive.error.message;
        return;
      }

      if (periodic_keepalive.value != expected_counter) {
        error_ = "periodic keepalive used an unexpected transport counter";
        return;
      }

      ++validated_additional_keepalives_;
    }
  }

  int socket_fd_ = -1;
  std::uint16_t port_ = 0;
  std::thread worker_{};
  bool responded_ = false;
  bool keepalive_validated_ = false;
  std::uint32_t expected_additional_keepalives_ = 0;
  std::uint32_t validated_additional_keepalives_ = 0;
  std::uint32_t inbound_keepalives_to_send_ = 0;
  std::vector<std::vector<std::uint8_t>> inbound_transport_payloads_{};
  std::vector<std::vector<std::uint8_t>> expected_outbound_transport_payloads_{};
  std::size_t validated_outbound_transport_packets_ = 0;
  std::string error_{};
};

class DelayedTunnelStreamSynAckResponder {
 public:
  DelayedTunnelStreamSynAckResponder(std::vector<std::uint8_t> expected_syn_payload,
                                     std::vector<std::uint8_t> inbound_synack_payload,
                                     std::vector<std::uint8_t> expected_ack_payload,
                                     std::chrono::milliseconds synack_delay)
      : expected_syn_payload_(std::move(expected_syn_payload)),
        inbound_synack_payload_(std::move(inbound_synack_payload)),
        expected_ack_payload_(std::move(expected_ack_payload)),
        synack_delay_(synack_delay) {
    socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
      error_ = DescribeSocketError("socket");
      return;
    }

    timeval timeout{};
    timeout.tv_sec = 4;
    timeout.tv_usec = 0;
    if (::setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
      error_ = DescribeSocketError("setsockopt");
      return;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(socket_fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      error_ = DescribeSocketError("bind");
      return;
    }

    socklen_t address_length = sizeof(address);
    if (::getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&address), &address_length) != 0) {
      error_ = DescribeSocketError("getsockname");
      return;
    }

    port_ = ntohs(address.sin_port);
    worker_ = std::thread([this]() {
      Run();
    });
  }

  DelayedTunnelStreamSynAckResponder(const DelayedTunnelStreamSynAckResponder&) = delete;
  DelayedTunnelStreamSynAckResponder& operator=(const DelayedTunnelStreamSynAckResponder&) = delete;

  ~DelayedTunnelStreamSynAckResponder() {
    Join();
    if (socket_fd_ >= 0) {
      ::close(socket_fd_);
    }
  }

  bool ready() const {
    return error_.empty() && socket_fd_ >= 0 && port_ != 0;
  }

  std::uint16_t port() const {
    return port_;
  }

  bool Join() {
    if (worker_.joinable()) {
      worker_.join();
    }
    return error_.empty() && responded_ && keepalive_validated_ && saw_syn_ && saw_ack_;
  }

  const std::string& error() const {
    return error_;
  }

 private:
  void Run() {
    const auto responder_config = MakeHandshakeResponderConfig();
    if (!responder_config.ok()) {
      error_ = responder_config.error.message;
      return;
    }

    std::array<std::uint8_t, 256> buffer{};
    sockaddr_in client_address{};
    socklen_t client_length = sizeof(client_address);
    const ssize_t received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                        reinterpret_cast<sockaddr*>(&client_address), &client_length);
    if (received < 0) {
      error_ = DescribeSocketError("recvfrom");
      return;
    }

    const auto response = swg::RespondToHandshakeInitiationForTest(
        responder_config.value, buffer.data(), static_cast<std::size_t>(received));
    if (!response.ok()) {
      error_ = response.error.message;
      return;
    }

    const ssize_t sent = ::sendto(socket_fd_, response.value.packet.data(), response.value.packet.size(), 0,
                                  reinterpret_cast<const sockaddr*>(&client_address), client_length);
    if (sent < 0) {
      error_ = DescribeSocketError("sendto");
      return;
    }
    if (static_cast<std::size_t>(sent) != response.value.packet.size()) {
      error_ = "sendto returned a short WireGuard response";
      return;
    }

    responded_ = true;

    client_length = sizeof(client_address);
    const ssize_t keepalive_received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                                  reinterpret_cast<sockaddr*>(&client_address), &client_length);
    if (keepalive_received < 0) {
      error_ = DescribeSocketError("recvfrom");
      return;
    }

    const auto keepalive = swg::ConsumeTransportKeepaliveForTest(
        response.value.receiving_key, response.value.sender_index, buffer.data(),
        static_cast<std::size_t>(keepalive_received));
    if (!keepalive.ok()) {
      error_ = keepalive.error.message;
      return;
    }

    if (keepalive.value != 0) {
      error_ = "post-handshake keepalive used an unexpected transport counter";
      return;
    }

    keepalive_validated_ = true;

    client_length = sizeof(client_address);
    const ssize_t syn_received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                            reinterpret_cast<sockaddr*>(&client_address), &client_length);
    if (syn_received < 0) {
      error_ = DescribeSocketError("recvfrom");
      return;
    }

    const auto outbound_syn = swg::ConsumeTransportPacket(
        response.value.receiving_key, response.value.sender_index, buffer.data(),
        static_cast<std::size_t>(syn_received));
    if (!outbound_syn.ok()) {
      error_ = outbound_syn.error.message;
      return;
    }
    if (outbound_syn.value.payload != expected_syn_payload_) {
      error_ = "first outbound tunnel stream packet was not the expected SYN";
      return;
    }

    saw_syn_ = true;
    std::this_thread::sleep_for(synack_delay_);

    const auto inbound_synack = swg::CreateTransportPacket(
        response.value.sending_key, response.value.receiver_index, inbound_synack_payload_, 0);
    if (!inbound_synack.ok()) {
      error_ = inbound_synack.error.message;
      return;
    }

    const ssize_t synack_sent = ::sendto(socket_fd_, inbound_synack.value.packet.data(), inbound_synack.value.packet.size(),
                                         0, reinterpret_cast<const sockaddr*>(&client_address), client_length);
    if (synack_sent < 0) {
      error_ = DescribeSocketError("sendto");
      return;
    }
    if (static_cast<std::size_t>(synack_sent) != inbound_synack.value.packet.size()) {
      error_ = "sendto returned a short authenticated SYN-ACK payload";
      return;
    }

    for (;;) {
      client_length = sizeof(client_address);
      const ssize_t outbound_received = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                                   reinterpret_cast<sockaddr*>(&client_address), &client_length);
      if (outbound_received < 0) {
        error_ = DescribeSocketError("recvfrom");
        return;
      }

      const auto outbound_transport = swg::ConsumeTransportPacket(
          response.value.receiving_key, response.value.sender_index, buffer.data(),
          static_cast<std::size_t>(outbound_received));
      if (!outbound_transport.ok()) {
        error_ = outbound_transport.error.message;
        return;
      }

      if (outbound_transport.value.payload == expected_syn_payload_) {
        continue;
      }

      if (outbound_transport.value.payload != expected_ack_payload_) {
        error_ = "outbound tunnel stream packet after delayed SYN-ACK was not the expected ACK";
        return;
      }

      saw_ack_ = true;
      return;
    }
  }

  int socket_fd_ = -1;
  std::uint16_t port_ = 0;
  std::thread worker_{};
  std::vector<std::uint8_t> expected_syn_payload_{};
  std::vector<std::uint8_t> inbound_synack_payload_{};
  std::vector<std::uint8_t> expected_ack_payload_{};
  std::chrono::milliseconds synack_delay_{};
  bool responded_ = false;
  bool keepalive_validated_ = false;
  bool saw_syn_ = false;
  bool saw_ack_ = false;
  std::string error_{};
};

class ScriptedReconnectSocketRuntime final : public swg::sysmodule::IUdpSocketRuntime {
 public:
  enum class FailureMode : std::uint32_t {
    OutboundSendOnce = 0,
    ReceiveOnceAfterHandshake,
    KeepaliveSendOnce,
  };

  explicit ScriptedReconnectSocketRuntime(swg::sysmodule::PreparedTunnelEndpoint endpoint,
                                          std::vector<std::uint8_t> expected_payload,
                                          FailureMode failure_mode = FailureMode::OutboundSendOnce)
      : endpoint_(std::move(endpoint)), expected_payload_(std::move(expected_payload)), failure_mode_(failure_mode) {
    responder_config_result_ = MakeHandshakeResponderConfig();
  }

  swg::Error Start() override {
    if (!responder_config_result_.ok()) {
      return responder_config_result_.error;
    }

    started_ = true;
    return swg::Error::None();
  }

  void Stop() override {
    std::scoped_lock lock(mutex_);
    started_ = false;
    pending_response_.clear();
    current_response_.reset();
    active_socket_ = -1;
    awaiting_post_handshake_keepalive_ = false;
    pending_receive_failure_ = false;
  }

  [[nodiscard]] bool IsStarted() const override {
    std::scoped_lock lock(mutex_);
    return started_;
  }

  swg::Result<int> OpenUdpSocket() const override {
    std::scoped_lock lock(mutex_);
    if (!started_) {
      return swg::MakeFailure<int>(swg::ErrorCode::InvalidState, "scripted runtime is not initialized");
    }

    return swg::MakeSuccess(next_socket_++);
  }

  swg::Result<std::size_t> SendTo(int socket_fd,
                                  const swg::sysmodule::PreparedTunnelEndpoint& endpoint,
                                  const std::uint8_t* buffer,
                                  std::size_t size) const override {
    std::scoped_lock lock(mutex_);
    if (!started_) {
      return swg::MakeFailure<std::size_t>(swg::ErrorCode::InvalidState, "scripted runtime is not initialized");
    }
    if (endpoint.port != endpoint_.port || endpoint.ipv4 != endpoint_.ipv4) {
      return swg::MakeFailure<std::size_t>(swg::ErrorCode::IoError, "scripted runtime received an unexpected endpoint");
    }
    if (!responder_config_result_.ok()) {
      return swg::MakeFailure<std::size_t>(responder_config_result_.error.code, responder_config_result_.error.message);
    }
    if (size == 0) {
      return swg::MakeFailure<std::size_t>(swg::ErrorCode::ParseError, "scripted runtime received an empty datagram");
    }

    const auto message_type = static_cast<swg::WireGuardMessageType>(buffer[0]);
    switch (message_type) {
      case swg::WireGuardMessageType::HandshakeInitiation: {
        const auto response = swg::RespondToHandshakeInitiationForTest(
            responder_config_result_.value, buffer, size,
            swg::WireGuardHandshakeResponseOptions{.sender_index = static_cast<std::uint32_t>(0x4000u + handshake_count_)});
        if (!response.ok()) {
          return swg::MakeFailure<std::size_t>(response.error.code, response.error.message);
        }

        pending_response_ = std::vector<std::uint8_t>(response.value.packet.begin(), response.value.packet.end());
        current_response_ = response.value;
        active_socket_ = socket_fd;
        awaiting_post_handshake_keepalive_ = true;
        pending_receive_failure_ = false;
        ++handshake_count_;
        return swg::MakeSuccess(size);
      }
      case swg::WireGuardMessageType::Data: {
        if (!current_response_.has_value()) {
          return swg::MakeFailure<std::size_t>(swg::ErrorCode::ParseError,
                                               "scripted runtime received transport data before a handshake response");
        }

        const auto packet = swg::ConsumeTransportPacket(current_response_->receiving_key, current_response_->sender_index,
                                                        buffer, size);
        if (!packet.ok()) {
          return swg::MakeFailure<std::size_t>(packet.error.code, packet.error.message);
        }

        if (awaiting_post_handshake_keepalive_) {
          if (packet.value.counter != 0 || !packet.value.payload.empty()) {
            return swg::MakeFailure<std::size_t>(swg::ErrorCode::ParseError,
                                                 "scripted runtime expected the post-handshake keepalive first");
          }
          awaiting_post_handshake_keepalive_ = false;
          if (failure_mode_ == FailureMode::ReceiveOnceAfterHandshake && !receive_failure_triggered_) {
            pending_receive_failure_ = true;
          }
          return swg::MakeSuccess(size);
        }

        if (failure_mode_ == FailureMode::KeepaliveSendOnce && packet.value.payload.empty() &&
            !keepalive_send_failure_triggered_) {
          keepalive_send_failure_triggered_ = true;
          return swg::MakeFailure<std::size_t>(swg::ErrorCode::IoError,
                                               "scripted periodic keepalive failure to trigger reconnect");
        }

        if (failure_mode_ == FailureMode::OutboundSendOnce && !outbound_send_failure_triggered_) {
          outbound_send_failure_triggered_ = true;
          failed_send_once_ = true;
          return swg::MakeFailure<std::size_t>(swg::ErrorCode::IoError,
                                               "scripted outbound transport failure to trigger reconnect");
        }

        if (packet.value.counter != 1) {
          return swg::MakeFailure<std::size_t>(swg::ErrorCode::ParseError,
                                               "scripted runtime observed an unexpected outbound transport counter");
        }
        if (packet.value.payload != expected_payload_) {
          return swg::MakeFailure<std::size_t>(swg::ErrorCode::ParseError,
                                               "scripted runtime observed unexpected outbound transport payload bytes");
        }

        outbound_payload_validated_ = true;
        return swg::MakeSuccess(size);
      }
      default:
        return swg::MakeFailure<std::size_t>(swg::ErrorCode::Unsupported,
                                             "scripted runtime observed an unsupported WireGuard message type");
    }
  }

  swg::Result<swg::sysmodule::ReceivedUdpDatagram> ReceiveFrom(int socket_fd,
                                                               std::uint8_t* buffer,
                                                               std::size_t size,
                                                               std::uint32_t timeout_ms) const override {
    std::scoped_lock lock(mutex_);
    if (!started_) {
      return swg::MakeFailure<swg::sysmodule::ReceivedUdpDatagram>(swg::ErrorCode::InvalidState,
                                                                   "scripted runtime is not initialized");
    }
    if (socket_fd != active_socket_) {
      return swg::MakeFailure<swg::sysmodule::ReceivedUdpDatagram>(swg::ErrorCode::IoError,
                                                                   "scripted runtime received from an unexpected socket");
    }
    if (failure_mode_ == FailureMode::ReceiveOnceAfterHandshake && pending_receive_failure_ &&
        !receive_failure_triggered_) {
      receive_failure_triggered_ = true;
      pending_receive_failure_ = false;
      return swg::MakeFailure<swg::sysmodule::ReceivedUdpDatagram>(
          swg::ErrorCode::IoError,
          "scripted receive failure to trigger reconnect");
    }
    if (pending_response_.empty()) {
      return swg::MakeFailure<swg::sysmodule::ReceivedUdpDatagram>(swg::ErrorCode::IoError,
                                                                   "recv timed out after " + std::to_string(timeout_ms) + "ms");
    }
    if (size < pending_response_.size()) {
      return swg::MakeFailure<swg::sysmodule::ReceivedUdpDatagram>(swg::ErrorCode::ParseError,
                                                                   "scripted runtime receive buffer was too small");
    }

    std::copy(pending_response_.begin(), pending_response_.end(), buffer);
    swg::sysmodule::ReceivedUdpDatagram datagram{};
    datagram.size = pending_response_.size();
    datagram.source_ipv4 = endpoint_.ipv4;
    datagram.source_port = endpoint_.port;
    pending_response_.clear();
    return swg::MakeSuccess(std::move(datagram));
  }

  void CloseSocket(int socket_fd) const override {
    std::scoped_lock lock(mutex_);
    if (active_socket_ == socket_fd) {
      active_socket_ = -1;
    }
  }

  [[nodiscard]] bool outbound_payload_validated() const {
    std::scoped_lock lock(mutex_);
    return outbound_payload_validated_;
  }

  [[nodiscard]] bool receive_failure_triggered() const {
    std::scoped_lock lock(mutex_);
    return receive_failure_triggered_;
  }

  [[nodiscard]] bool keepalive_send_failure_triggered() const {
    std::scoped_lock lock(mutex_);
    return keepalive_send_failure_triggered_;
  }

  [[nodiscard]] std::uint32_t handshake_count() const {
    std::scoped_lock lock(mutex_);
    return handshake_count_;
  }

 private:
  swg::sysmodule::PreparedTunnelEndpoint endpoint_{};
  std::vector<std::uint8_t> expected_payload_{};
  FailureMode failure_mode_ = FailureMode::OutboundSendOnce;
  swg::Result<swg::WireGuardResponderConfig> responder_config_result_ =
      swg::MakeFailure<swg::WireGuardResponderConfig>(swg::ErrorCode::InvalidState, "not initialized");
  mutable std::mutex mutex_{};
  mutable bool started_ = false;
  mutable int next_socket_ = 100;
  mutable int active_socket_ = -1;
  mutable std::optional<swg::WireGuardHandshakeResponse> current_response_{};
  mutable std::vector<std::uint8_t> pending_response_{};
  mutable std::uint32_t handshake_count_ = 0;
  mutable bool awaiting_post_handshake_keepalive_ = false;
  mutable bool pending_receive_failure_ = false;
  mutable bool failed_send_once_ = false;
  mutable bool outbound_send_failure_triggered_ = false;
  mutable bool receive_failure_triggered_ = false;
  mutable bool keepalive_send_failure_triggered_ = false;
  mutable bool outbound_payload_validated_ = false;
};

class RecoveringTunnelStreamEngine final : public swg::sysmodule::IWgTunnelEngine {
 public:
  swg::Error Start(const swg::sysmodule::TunnelEngineStartRequest& request) override {
    std::scoped_lock lock(mutex_);
    running_ = true;
    prepared_session_ = request.session;
    queued_packets_.clear();
    stats_ = {};
    stats_.successful_handshakes = 1;
    next_send_counter_ = 1;
    next_receive_counter_ = 1;
    recovery_count_ = 0;
    saw_blackholed_syn_ = false;
    saw_post_recovery_syn_ = false;
    saw_post_recovery_ack_ = false;
    queued_post_recovery_synack_ = false;
    last_error_.clear();
    last_recovery_reason_.clear();
    return swg::Error::None();
  }

  swg::Error Stop() override {
    std::scoped_lock lock(mutex_);
    running_ = false;
    queued_packets_.clear();
    return swg::Error::None();
  }

  swg::Error RecoverTransport(std::string_view reason) override {
    std::scoped_lock lock(mutex_);
    if (!running_) {
      last_error_ = "recover requested while the scripted tunnel engine is stopped";
      return swg::MakeError(swg::ErrorCode::InvalidState, last_error_);
    }

    ++recovery_count_;
    ++stats_.reconnects;
    ++stats_.successful_handshakes;
    next_send_counter_ = 1;
    queued_packets_.clear();
    queued_post_recovery_synack_ = false;
    last_recovery_reason_ = std::string(reason);
    last_error_.clear();
    return swg::Error::None();
  }

  swg::Result<std::uint64_t> SendPacket(const std::vector<std::uint8_t>& payload) override {
    std::scoped_lock lock(mutex_);
    if (!running_) {
      return swg::MakeFailure<std::uint64_t>(swg::ErrorCode::InvalidState,
                                             "scripted tunnel engine is not running");
    }

    const auto parsed = swg::ParseIpv4TcpPacket(payload);
    if (!parsed.ok()) {
      return swg::MakeFailure<std::uint64_t>(parsed.error.code, parsed.error.message);
    }

    const std::uint64_t counter = next_send_counter_++;
    stats_.bytes_out += payload.size();
    ++stats_.packets_out;

    const swg::Ipv4TcpPacket& segment = parsed.value;
    if (swg::HasFlag(segment.flags, swg::TcpControlFlag::Syn) &&
        !swg::HasFlag(segment.flags, swg::TcpControlFlag::Ack)) {
      if (recovery_count_ == 0) {
        saw_blackholed_syn_ = true;
        return swg::MakeSuccess(counter);
      }

      saw_post_recovery_syn_ = true;
      if (!queued_post_recovery_synack_) {
        const auto synack_payload = BuildSynAck(segment);
        if (!synack_payload.ok()) {
          return swg::MakeFailure<std::uint64_t>(synack_payload.error.code, synack_payload.error.message);
        }

        queued_packets_.push_back(swg::WireGuardConsumedTransportPacket{next_receive_counter_++, synack_payload.value});
        stats_.bytes_in += synack_payload.value.size();
        ++stats_.packets_in;
        queued_post_recovery_synack_ = true;
      }
      return swg::MakeSuccess(counter);
    }

    if (recovery_count_ != 0 && queued_post_recovery_synack_ &&
        swg::HasFlag(segment.flags, swg::TcpControlFlag::Ack) &&
        !swg::HasFlag(segment.flags, swg::TcpControlFlag::Syn) && segment.payload.empty() &&
        segment.acknowledgment_number == kRemoteInitialSequence + 1u) {
      saw_post_recovery_ack_ = true;
    }

    return swg::MakeSuccess(counter);
  }

  swg::Result<swg::WireGuardConsumedTransportPacket> ReceivePacket() override {
    std::scoped_lock lock(mutex_);
    if (!running_) {
      return swg::MakeFailure<swg::WireGuardConsumedTransportPacket>(swg::ErrorCode::InvalidState,
                                                                     "scripted tunnel engine is not running");
    }

    if (queued_packets_.empty()) {
      return swg::MakeFailure<swg::WireGuardConsumedTransportPacket>(swg::ErrorCode::NotFound,
                                                                     "no scripted transport packets are queued");
    }

    swg::WireGuardConsumedTransportPacket packet = std::move(queued_packets_.front());
    queued_packets_.pop_front();
    return swg::MakeSuccess(std::move(packet));
  }

  swg::TunnelStats GetStats() const override {
    std::scoped_lock lock(mutex_);
    return stats_;
  }

  std::string GetLastError() const override {
    std::scoped_lock lock(mutex_);
    return last_error_;
  }

  bool IsRunning() const override {
    std::scoped_lock lock(mutex_);
    return running_;
  }

  [[nodiscard]] std::uint32_t recovery_count() const {
    std::scoped_lock lock(mutex_);
    return recovery_count_;
  }

  [[nodiscard]] bool saw_blackholed_syn() const {
    std::scoped_lock lock(mutex_);
    return saw_blackholed_syn_;
  }

  [[nodiscard]] bool saw_post_recovery_syn() const {
    std::scoped_lock lock(mutex_);
    return saw_post_recovery_syn_;
  }

  [[nodiscard]] bool saw_post_recovery_ack() const {
    std::scoped_lock lock(mutex_);
    return saw_post_recovery_ack_;
  }

  [[nodiscard]] std::string last_recovery_reason() const {
    std::scoped_lock lock(mutex_);
    return last_recovery_reason_;
  }

 private:
  swg::Result<std::vector<std::uint8_t>> BuildSynAck(const swg::Ipv4TcpPacket& syn) const {
    swg::Ipv4TcpPacket synack{};
    synack.endpoint.source_ipv4 = syn.endpoint.destination_ipv4;
    synack.endpoint.destination_ipv4 = syn.endpoint.source_ipv4;
    synack.endpoint.source_port = syn.endpoint.destination_port;
    synack.endpoint.destination_port = syn.endpoint.source_port;
    synack.sequence_number = kRemoteInitialSequence;
    synack.acknowledgment_number = syn.sequence_number + 1u;
    synack.flags = swg::ToFlags(swg::TcpControlFlag::Syn) | swg::ToFlags(swg::TcpControlFlag::Ack);
    return swg::BuildIpv4TcpPacket(synack);
  }

  static constexpr std::uint32_t kRemoteInitialSequence = 0x45000000u;

  mutable std::mutex mutex_{};
  bool running_ = false;
  swg::sysmodule::PreparedTunnelSession prepared_session_{};
  std::deque<swg::WireGuardConsumedTransportPacket> queued_packets_{};
  swg::TunnelStats stats_{};
  std::uint64_t next_send_counter_ = 1;
  std::uint64_t next_receive_counter_ = 1;
  std::uint32_t recovery_count_ = 0;
  bool saw_blackholed_syn_ = false;
  bool saw_post_recovery_syn_ = false;
  bool saw_post_recovery_ack_ = false;
  bool queued_post_recovery_synack_ = false;
  std::string last_error_{};
  std::string last_recovery_reason_{};
};

bool TestWireGuardCrypto() {
  bool ok = true;

  const auto local_private = swg::ParseWireGuardKey(kSamplePrivateKey, "private_key");
  const auto peer_private = swg::ParseWireGuardKey(kSamplePeerPrivateKey, "private_key");
  const auto peer_public = swg::ParseWireGuardKey(kSamplePublicKey, "public_key");
  const auto expected_local_public = swg::ParseWireGuardKey(kSampleLocalPublicKey, "local_public_key");

  ok &= Require(local_private.ok(), "sample local private key must parse");
  ok &= Require(peer_private.ok(), "sample peer private key must parse");
  ok &= Require(peer_public.ok(), "sample peer public key must parse");
  ok &= Require(expected_local_public.ok(), "expected local public key must parse");
  if (!local_private.ok() || !peer_private.ok() || !peer_public.ok() || !expected_local_public.ok()) {
    return false;
  }

  const auto derived_local_public = swg::DeriveWireGuardPublicKey(local_private.value);
  ok &= Require(derived_local_public.ok(), "derived local public key must succeed");
  if (derived_local_public.ok()) {
    ok &= Require(derived_local_public.value.bytes == expected_local_public.value.bytes,
                  "derived local public key must match the expected X25519 public key");
  }

  const auto derived_peer_public = swg::DeriveWireGuardPublicKey(peer_private.value);
  ok &= Require(derived_peer_public.ok(), "derived peer public key must succeed");

  const auto shared_a = swg::ComputeWireGuardSharedSecret(local_private.value, peer_public.value);
  ok &= Require(shared_a.ok(), "static shared secret must derive for the sample peer public key");

  if (derived_peer_public.ok()) {
    const auto shared_b = swg::ComputeWireGuardSharedSecret(peer_private.value, expected_local_public.value);
    ok &= Require(shared_b.ok(), "static shared secret must be symmetric across both peers");
    if (shared_a.ok() && shared_b.ok()) {
      ok &= Require(shared_a.value.bytes == shared_b.value.bytes,
                    "static shared secret must match across both peers");
    }
  }

  swg::WireGuardKey zero_public_key{};
  const auto invalid_shared = swg::ComputeWireGuardSharedSecret(local_private.value, zero_public_key);
  ok &= Require(!invalid_shared.ok(), "zero peer public key must be rejected for shared secret derivation");
  return ok;
}

bool TestWireGuardHandshakeRoundTrip() {
  const auto initiator_config = MakeHandshakeInitiatorConfig();
  const auto responder_config = MakeHandshakeResponderConfig();

  bool ok = true;
  ok &= Require(initiator_config.ok(), "sample initiator handshake config must parse");
  ok &= Require(responder_config.ok(), "sample responder handshake config must parse");
  if (!initiator_config.ok() || !responder_config.ok()) {
    return false;
  }

  const auto initiation = swg::CreateHandshakeInitiation(initiator_config.value);
  ok &= Require(initiation.ok(), "handshake initiation packet must build");
  if (!initiation.ok()) {
    return false;
  }

  const auto response = swg::RespondToHandshakeInitiationForTest(
      responder_config.value, initiation.value.packet.data(), initiation.value.packet.size());
  ok &= Require(response.ok(), "responder must build a valid handshake response");
  if (!response.ok()) {
    return false;
  }

  const auto validated = swg::ConsumeHandshakeResponse(
      initiator_config.value, initiation.value.state, response.value.packet.data(), response.value.packet.size());
  ok &= Require(validated.ok(), "initiator must validate the responder handshake response");
  if (!validated.ok()) {
    return false;
  }

  ok &= Require(validated.value.local_sender_index == initiation.value.state.sender_index,
                "validated handshake must preserve the initiator sender index");
  ok &= Require(validated.value.peer_sender_index == response.value.sender_index,
                "validated handshake must preserve the responder sender index");
  ok &= Require(validated.value.sending_key.bytes == response.value.receiving_key.bytes,
                "initiator sending key must match responder receiving key");
  ok &= Require(validated.value.receiving_key.bytes == response.value.sending_key.bytes,
                "initiator receiving key must match responder sending key");

  const auto keepalive =
      swg::CreateTransportKeepalivePacket(validated.value.sending_key, validated.value.peer_sender_index, 0);
  ok &= Require(keepalive.ok(), "initiator must build a post-handshake keepalive packet");
  if (keepalive.ok()) {
    const auto consumed = swg::ConsumeTransportKeepaliveForTest(
        response.value.receiving_key, response.value.sender_index, keepalive.value.packet.data(),
        keepalive.value.packet.size());
    ok &= Require(consumed.ok(), "responder must validate the initiator post-handshake keepalive");
    if (consumed.ok()) {
      ok &= Require(consumed.value == 0, "first post-handshake keepalive must use transport counter zero");
    }
  }

  const std::vector<std::uint8_t> payload = {0x53, 0x57, 0x47, 0x01};
  const auto transport =
      swg::CreateTransportPacket(validated.value.sending_key, validated.value.peer_sender_index, payload, 1);
  ok &= Require(transport.ok(), "initiator must build an authenticated transport payload packet");
  if (transport.ok()) {
    const auto consumed = swg::ConsumeTransportPacket(response.value.receiving_key, response.value.sender_index,
                                                      transport.value.packet.data(), transport.value.packet.size());
    ok &= Require(consumed.ok(), "responder must validate the initiator transport payload packet");
    if (consumed.ok()) {
      ok &= Require(consumed.value.counter == 1,
                    "transport payload packet must preserve the transport counter");
      ok &= Require(consumed.value.payload == payload,
                    "transport payload packet must round-trip the authenticated payload bytes");
    }
  }
  return ok;
}

bool TestEndpointAndNetworkParsing() {
  bool ok = true;

  const auto ipv4_network = swg::ParseIpNetwork("10.0.0.2/32", "address");
  ok &= Require(ipv4_network.ok(), "ipv4 network must parse");
  if (ipv4_network.ok()) {
    ok &= Require(ipv4_network.value.address.family == swg::ParsedIpFamily::IPv4,
                  "ipv4 network must preserve address family");
    ok &= Require(ipv4_network.value.normalized == "10.0.0.2/32", "ipv4 network must normalize");
  }

  const auto ipv6_network = swg::ParseIpNetwork("fd00::2/128", "address");
  ok &= Require(ipv6_network.ok(), "ipv6 network must parse");
  if (ipv6_network.ok()) {
    ok &= Require(ipv6_network.value.address.family == swg::ParsedIpFamily::IPv6,
                  "ipv6 network must preserve address family");
  }

  const auto dns_server = swg::ParseIpAddress("2606:4700:4700::1111", "dns");
  ok &= Require(dns_server.ok(), "ipv6 dns address must parse");

  const auto endpoint = swg::ParseEndpoint("[2001:db8::1]", 51820);
  ok &= Require(endpoint.ok(), "ipv6 endpoint literal must parse");
  if (endpoint.ok()) {
    ok &= Require(endpoint.value.type == swg::ParsedEndpointHostType::IPv6,
                  "ipv6 endpoint must be classified correctly");
    ok &= Require(endpoint.value.host == "2001:db8::1", "ipv6 endpoint must normalize brackets away");
  }

  const auto invalid_network = swg::ParseIpNetwork("10.0.0.2", "allowed_ips");
  ok &= Require(!invalid_network.ok(), "cidr parser must reject missing prefix length");

  const auto invalid_dns = swg::ParseIpAddress("dns.example.test", "dns");
  ok &= Require(!invalid_dns.ok(), "dns parser must currently reject hostnames");
  return ok;
}

swg::Config MakeValidConfig(std::string endpoint_host = "localhost", std::uint16_t endpoint_port = 51820) {
  swg::Config config = swg::DefaultConfig();
  swg::ProfileConfig profile{};
  profile.name = "default";
  profile.private_key = kSamplePrivateKey;
  profile.public_key = kSamplePublicKey;
  profile.preshared_key = kSamplePresharedKey;
  profile.endpoint_host = std::move(endpoint_host);
  profile.endpoint_port = endpoint_port;
  profile.allowed_ips = {"0.0.0.0/0", "::/0"};
  profile.addresses = {"10.0.0.2/32"};
  profile.dns_servers = {"1.1.1.1", "1.0.0.1"};
  profile.autostart = false;
  config.profiles.emplace(profile.name, profile);
  config.active_profile = profile.name;
  config.runtime_flags = swg::ToFlags(swg::RuntimeFlag::DnsThroughTunnel);
  return config;
}

bool TestWireGuardProfileValidation() {
  const swg::Config valid_config = MakeValidConfig();
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));
  const auto expected_local_public = swg::ParseWireGuardKey(kSampleLocalPublicKey, "local_public_key");

  bool ok = true;
  ok &= Require(validated.ok(), "valid WireGuard profile must pass connect validation");
  ok &= Require(expected_local_public.ok(), "expected local public key must parse");
  if (!validated.ok()) {
    return false;
  }

  ok &= Require(validated.value.has_preshared_key, "validated profile must preserve preshared key presence");
  ok &= Require(validated.value.endpoint.port == 51820, "validated profile must preserve endpoint port");
  ok &= Require(validated.value.endpoint.type == swg::ParsedEndpointHostType::Hostname,
                "validated profile must preserve endpoint host type");
  ok &= Require(validated.value.allowed_ips.size() == 2, "validated profile must parse allowed ip networks");
  ok &= Require(validated.value.addresses.size() == 1, "validated profile must parse interface addresses");
  ok &= Require(validated.value.dns_servers.size() == 2, "validated profile must parse dns servers");
  if (expected_local_public.ok()) {
    ok &= Require(validated.value.local_public_key.bytes == expected_local_public.value.bytes,
                  "validated profile must derive the local X25519 public key");
  }
  ok &= Require(validated.value.static_shared_secret.bytes != swg::WireGuardKey{}.bytes,
                "validated profile must compute a non-zero static shared secret");
  ok &= Require(validated.value.persistent_keepalive == 25,
                "validated profile must preserve keepalive interval");

  swg::Config invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").private_key = "not-base64";
  const auto invalid = swg::ValidateWireGuardProfileForConnect(invalid_config.profiles.at("default"));
  ok &= Require(!invalid.ok(), "invalid WireGuard key must fail connect validation");

  invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").allowed_ips = {"not-a-cidr"};
  const auto invalid_cidr = swg::ValidateWireGuardProfileForConnect(invalid_config.profiles.at("default"));
  ok &= Require(!invalid_cidr.ok(), "invalid allowed_ips entry must fail connect validation");

  invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").public_key = kSampleLocalPublicKey;
  const auto self_peer = swg::ValidateWireGuardProfileForConnect(invalid_config.profiles.at("default"));
  ok &= Require(!self_peer.ok(), "peer public key must not match the local derived public key");
  if (!self_peer.ok()) {
    ok &= Require(self_peer.error.message.find("must not match the local public key") != std::string::npos,
                  "self-peer validation failure must explain the remote peer key requirement");
  }
  return ok;
}

bool TestTunnelSessionPreparation() {
  const swg::Config valid_config = MakeValidConfig();
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for tunnel session prep");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared = swg::sysmodule::PrepareTunnelSession(
      valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "hostname-based IPv4-ready profile must prepare a tunnel session");
  if (!prepared.ok()) {
    return false;
  }

  ok &= Require(prepared.value.endpoint.state == swg::sysmodule::PreparedEndpointState::NeedsIpv4Resolution,
                "hostname endpoint must remain resolution-pending");
  ok &= Require(prepared.value.allowed_ipv4_routes.size() == 1,
                "only IPv4 allowed_ips entries should be kept for the current transport");
  ok &= Require(prepared.value.ignored_ipv6_allowed_ips == 1,
                "IPv6 allowed_ips entries should be recorded as ignored for the current transport");
  ok &= Require(prepared.value.local_public_key.bytes != swg::WireGuardKey{}.bytes,
                "prepared session must carry the derived local public key");
  ok &= Require(prepared.value.static_shared_secret.bytes != swg::WireGuardKey{}.bytes,
                "prepared session must carry the static peer shared secret");
  ok &= Require(prepared.value.interface_ipv4_addresses.size() == 1,
                "IPv4 interface addresses should be retained for the current transport");
  ok &= Require(prepared.value.dns_servers.size() == 2,
                "IPv4 DNS servers should be retained for the current transport");

  swg::Config ipv6_endpoint_config = MakeValidConfig();
  ipv6_endpoint_config.profiles.at("default").endpoint_host = "[2001:db8::1]";
  const auto validated_ipv6_endpoint =
      swg::ValidateWireGuardProfileForConnect(ipv6_endpoint_config.profiles.at("default"));
  ok &= Require(validated_ipv6_endpoint.ok(), "IPv6 endpoint should still parse at shared validation layer");
  if (validated_ipv6_endpoint.ok()) {
    const auto unsupported_endpoint = swg::sysmodule::PrepareTunnelSession(
        ipv6_endpoint_config.active_profile, validated_ipv6_endpoint.value, ipv6_endpoint_config.runtime_flags);
    ok &= Require(!unsupported_endpoint.ok(), "IPv6 transport endpoint should be rejected by Switch session prep");
  }

  swg::Config ipv6_address_config = MakeValidConfig();
  ipv6_address_config.profiles.at("default").addresses = {"fd00::2/128"};
  const auto validated_ipv6_address =
      swg::ValidateWireGuardProfileForConnect(ipv6_address_config.profiles.at("default"));
  ok &= Require(validated_ipv6_address.ok(), "IPv6 interface address should still parse at shared validation layer");
  if (validated_ipv6_address.ok()) {
    const auto unsupported_address = swg::sysmodule::PrepareTunnelSession(
        ipv6_address_config.active_profile, validated_ipv6_address.value, ipv6_address_config.runtime_flags);
    ok &= Require(!unsupported_address.ok(), "Switch session prep should require an IPv4 interface address");
  }

  return ok;
}

bool TestTunnelEndpointResolution() {
  bool ok = true;

  swg::Config literal_config = MakeValidConfig();
  literal_config.profiles.at("default").endpoint_host = "127.0.0.1";
  const auto validated_literal = swg::ValidateWireGuardProfileForConnect(literal_config.profiles.at("default"));
  ok &= Require(validated_literal.ok(), "IPv4 literal endpoint must validate before resolution");
  if (!validated_literal.ok()) {
    return false;
  }

  const auto prepared_literal =
      swg::sysmodule::PrepareTunnelSession(literal_config.active_profile, validated_literal.value,
                                           literal_config.runtime_flags);
  ok &= Require(prepared_literal.ok(), "IPv4 literal endpoint must prepare a session");
  if (!prepared_literal.ok()) {
    return false;
  }

  const auto resolved_literal = swg::sysmodule::ResolvePreparedTunnelSessionEndpoint(prepared_literal.value);
  ok &= Require(resolved_literal.ok(), "ready IPv4 literal endpoint must resolve without DNS");
  if (resolved_literal.ok()) {
    ok &= Require(resolved_literal.value.endpoint.state == swg::sysmodule::PreparedEndpointState::Ready,
                  "IPv4 literal endpoint must stay ready after resolution");
    ok &= Require(resolved_literal.value.endpoint.ipv4[0] == 127 && resolved_literal.value.endpoint.ipv4[3] == 1,
                  "IPv4 literal endpoint must preserve its numeric address bytes");
  }

  swg::Config hostname_config = MakeValidConfig();
  hostname_config.profiles.at("default").endpoint_host = "LOCALHOST";
  const auto validated_hostname = swg::ValidateWireGuardProfileForConnect(hostname_config.profiles.at("default"));
  ok &= Require(validated_hostname.ok(), "localhost endpoint must validate before resolution");
  if (!validated_hostname.ok()) {
    return false;
  }

  const auto prepared_hostname =
      swg::sysmodule::PrepareTunnelSession(hostname_config.active_profile, validated_hostname.value,
                                           hostname_config.runtime_flags);
  ok &= Require(prepared_hostname.ok(), "localhost endpoint must prepare a session");
  if (!prepared_hostname.ok()) {
    return false;
  }

  ok &= Require(prepared_hostname.value.endpoint.state == swg::sysmodule::PreparedEndpointState::NeedsIpv4Resolution,
                "hostname endpoint must require IPv4 resolution before transport");

  const auto resolved_hostname = swg::sysmodule::ResolvePreparedTunnelSessionEndpoint(prepared_hostname.value);
  ok &= Require(resolved_hostname.ok(), "localhost endpoint must resolve to an IPv4 address on host tests");
  if (resolved_hostname.ok()) {
    ok &= Require(resolved_hostname.value.endpoint.state == swg::sysmodule::PreparedEndpointState::Ready,
                  "resolved hostname endpoint must become ready");
    ok &= Require(resolved_hostname.value.endpoint.ipv4[0] == 127,
                  "localhost endpoint must resolve to the IPv4 loopback range");
    ok &= Require(resolved_hostname.value.endpoint.port == 51820,
                  "hostname resolution must preserve the endpoint port");
  }

  return ok;
}

bool TestTunnelEngineHandshake() {
  LocalHandshakeResponder responder;
  if (!Require(responder.ready(), "local handshake responder must start for engine handshake test")) {
    return false;
  }

  const swg::Config valid_config = MakeValidConfig("127.0.0.1", responder.port());
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for engine start");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared =
      swg::sysmodule::PrepareTunnelSession(valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "prepared session must be available for engine start");
  if (!prepared.ok()) {
    return false;
  }

  auto engine = swg::sysmodule::CreateWgTunnelEngine();
  const swg::Error start_error = engine->Start(swg::sysmodule::TunnelEngineStartRequest{prepared.value});
  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must answer the initiation"
                                                            : responder.error());
  ok &= Require(start_error.ok(), "engine start must complete a WireGuard handshake against the local responder");
  ok &= Require(engine->IsRunning(), "engine must report running after handshake success");
  if (start_error.ok()) {
    const swg::TunnelStats stats = engine->GetStats();
    ok &= Require(stats.successful_handshakes == 1,
                  "engine handshake must record one successful handshake");
    ok &= Require(stats.bytes_out ==
                      swg::kWireGuardHandshakeInitiationSize + swg::kWireGuardTransportKeepaliveSize,
                  "engine handshake must send the initiation plus one keepalive packet");
    ok &= Require(stats.bytes_in == swg::kWireGuardHandshakeResponseSize,
                  "engine handshake must receive one response packet");
    ok &= Require(stats.packets_out == 2,
                  "engine handshake must send one initiation packet and one keepalive packet");
  }
  ok &= Require(engine->Stop().ok(), "engine stop must close the handshake socket cleanly");
  ok &= Require(!engine->IsRunning(), "engine must report stopped after shutdown");
  return ok;
}

bool TestConfigRoundTrip() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const swg::RuntimePaths paths = swg::DetectRuntimePaths(runtime_root);
  const swg::Config expected = MakeValidConfig();
  const swg::Error save_error = swg::SaveConfigFile(expected, paths.config_file);
  if (!Require(save_error.ok(), "config save must succeed")) {
    return false;
  }

  const swg::Result<swg::Config> loaded = swg::LoadConfigFile(paths.config_file);
  if (!Require(loaded.ok(), "config load must succeed")) {
    return false;
  }

  bool ok = true;
  ok &= Require(loaded.value.active_profile == expected.active_profile, "active profile must round-trip");
  ok &= Require(loaded.value.profiles.size() == 1, "exactly one profile must round-trip");
  ok &= Require(loaded.value.runtime_flags == expected.runtime_flags, "runtime flags must round-trip");
  ok &= Require(loaded.value.profiles.at("default").endpoint_host == expected.profiles.at("default").endpoint_host,
                "endpoint_host must round-trip");
  return ok;
}

bool TestStateMachine() {
  swg::ConnectionStateMachine machine;
  const swg::Config config = MakeValidConfig();

  bool ok = true;
  ok &= Require(machine.ApplyConfig(config).ok(), "apply config must succeed");
  ok &= Require(machine.Connect().ok(), "connect transition must succeed");
  ok &= Require(machine.MarkConnected().ok(), "mark connected must succeed");

  const swg::StateSnapshot connected = machine.snapshot();
  ok &= Require(connected.state == swg::TunnelState::Connected, "state must be connected");

  ok &= Require(machine.Disconnect().ok(), "disconnect transition must succeed");
  ok &= Require(machine.MarkDisconnected().ok(), "mark disconnected must succeed");

  const swg::StateSnapshot ready = machine.snapshot();
  ok &= Require(ready.state == swg::TunnelState::ConfigReady, "state must return to config_ready");
  return ok;
}

bool TestClientHostBinding() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-client";
  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  const auto version = client.GetVersion();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(version.ok(), "attached host service must provide version");
  ok &= Require(status.ok(), "attached host service must provide status");
  ok &= Require(status.value.service_ready, "attached host service must be ready");
  return ok;
}

bool TestConnectHandshakeStats() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-connect";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  LocalHandshakeResponder responder;
  if (!Require(responder.ready(), "local handshake responder must start for service connect test")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before connect handshake test")) {
    return false;
  }
  if (!Require(client.Connect().ok(), "connect must succeed after receiving a WireGuard handshake response")) {
    return false;
  }
  if (!Require(responder.Join(), responder.error().empty() ? "local responder must complete the service handshake"
                                                           : responder.error())) {
    return false;
  }

  const auto stats = client.GetStats();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(stats.ok(), "stats query must succeed after connect");
  ok &= Require(status.ok(), "status query must succeed after connect");
  if (!stats.ok() || !status.ok()) {
    return false;
  }

  ok &= Require(stats.value.connect_attempts == 1, "connect must increment connect_attempts");
  ok &= Require(stats.value.successful_handshakes == 1,
                "connect must record a successful WireGuard handshake after response validation");
  ok &= Require(stats.value.bytes_out ==
                    swg::kWireGuardHandshakeInitiationSize + swg::kWireGuardTransportKeepaliveSize,
                "connect must send the initiation plus one keepalive packet");
  ok &= Require(stats.value.packets_out == 2,
                "connect must record the post-handshake keepalive packet");
  ok &= Require(status.value.state == swg::TunnelState::Connected,
                "validated handshake should move the control service into connected state");
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after connect-handshake stats test");
  return ok;
}

bool TestPeriodicKeepaliveStats() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-periodic-keepalive";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  LocalHandshakeResponder responder(1);
  if (!Require(responder.ready(), "local handshake responder must start for periodic keepalive test")) {
    return false;
  }

  swg::Config config = MakeValidConfig("127.0.0.1", responder.port());
  config.profiles.at("default").persistent_keepalive = 1;

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(config).ok(),
               "periodic keepalive config must save before connect")) {
    return false;
  }
  if (!Require(client.Connect().ok(), "connect must succeed before periodic keepalive stats are sampled")) {
    return false;
  }
  if (!Require(responder.Join(), responder.error().empty() ? "local responder must receive one periodic keepalive"
                                                           : responder.error())) {
    return false;
  }

  const auto stats = client.GetStats();

  bool ok = true;
  ok &= Require(stats.ok(), "stats query must succeed after periodic keepalive send");
  if (!stats.ok()) {
    return false;
  }

  ok &= Require(stats.value.successful_handshakes == 1,
                "periodic keepalive stats must preserve the successful handshake count");
  ok &= Require(stats.value.bytes_out >=
                    swg::kWireGuardHandshakeInitiationSize + (2 * swg::kWireGuardTransportKeepaliveSize),
                "periodic keepalive stats must include the extra authenticated keepalive packet");
  ok &= Require(stats.value.packets_out >= 3,
                "periodic keepalive stats must report at least three outbound packets");
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after periodic keepalive stats test");
  return ok;
}

bool TestInboundKeepaliveStats() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-inbound-keepalive";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  LocalHandshakeResponder responder(0, 1);
  if (!Require(responder.ready(), "local handshake responder must start for inbound keepalive test")) {
    return false;
  }

  swg::Config config = MakeValidConfig("127.0.0.1", responder.port());
  config.profiles.at("default").persistent_keepalive = 0;

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(config).ok(),
               "inbound keepalive config must save before connect")) {
    return false;
  }
  if (!Require(client.Connect().ok(), "connect must succeed before inbound keepalive stats are sampled")) {
    return false;
  }
  if (!Require(responder.Join(), responder.error().empty() ? "local responder must send one inbound keepalive"
                                                           : responder.error())) {
    return false;
  }

  swg::TunnelStats observed_stats{};
  bool inbound_observed = false;
  for (int attempt = 0; attempt < 20; ++attempt) {
    const auto stats = client.GetStats();
    if (stats.ok() &&
        stats.value.bytes_in >= swg::kWireGuardHandshakeResponseSize + swg::kWireGuardTransportKeepaliveSize &&
        stats.value.packets_in >= 2) {
      observed_stats = stats.value;
      inbound_observed = true;
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  bool ok = true;
  ok &= Require(inbound_observed, "live stats must include one inbound authenticated keepalive");
  if (inbound_observed) {
    ok &= Require(observed_stats.successful_handshakes == 1,
                  "inbound keepalive stats must preserve the successful handshake count");
    ok &= Require(observed_stats.bytes_out ==
                      swg::kWireGuardHandshakeInitiationSize + swg::kWireGuardTransportKeepaliveSize,
                  "inbound keepalive stats must not require extra outbound packets when keepalives are disabled");
  }
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after inbound keepalive stats test");
  return ok;
}

bool TestInboundPayloadStats() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-inbound-payload";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const std::vector<std::uint8_t> payload = {0x53, 0x57, 0x47, 0x42};
  LocalHandshakeResponder responder(0, 0, payload);
  if (!Require(responder.ready(), "local handshake responder must start for inbound payload test")) {
    return false;
  }

  swg::Config config = MakeValidConfig("127.0.0.1", responder.port());
  config.profiles.at("default").persistent_keepalive = 0;

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(config).ok(),
               "inbound payload config must save before connect")) {
    return false;
  }
  if (!Require(client.Connect().ok(), "connect must succeed before inbound payload stats are sampled")) {
    return false;
  }
  if (!Require(responder.Join(), responder.error().empty() ? "local responder must send one inbound payload packet"
                                                           : responder.error())) {
    return false;
  }

  swg::TunnelStats observed_stats{};
  bool payload_observed = false;
  for (int attempt = 0; attempt < 20; ++attempt) {
    const auto stats = client.GetStats();
    if (stats.ok() && stats.value.bytes_in >
                          swg::kWireGuardHandshakeResponseSize + swg::kWireGuardTransportKeepaliveSize &&
        stats.value.packets_in >= 2) {
      observed_stats = stats.value;
      payload_observed = true;
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  bool ok = true;
  ok &= Require(payload_observed, "live stats must include one inbound authenticated transport payload packet");
  if (payload_observed) {
    ok &= Require(observed_stats.successful_handshakes == 1,
                  "inbound payload stats must preserve the successful handshake count");
    ok &= Require(observed_stats.bytes_out ==
                      swg::kWireGuardHandshakeInitiationSize + swg::kWireGuardTransportKeepaliveSize,
                  "inbound payload stats must not require extra outbound packets when keepalives are disabled");
  }
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after inbound payload stats test");
  return ok;
}

bool TestEngineInboundPayloadQueue() {
  const std::vector<std::uint8_t> payload = {0x51, 0x55, 0x45, 0x55, 0x45};
  LocalHandshakeResponder responder(0, 0, payload);
  if (!Require(responder.ready(), "local handshake responder must start for engine payload queue test")) {
    return false;
  }

  const swg::Config valid_config = MakeValidConfig("127.0.0.1", responder.port());
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for engine payload queue test");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared =
      swg::sysmodule::PrepareTunnelSession(valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "prepared session must be available for engine payload queue test");
  if (!prepared.ok()) {
    return false;
  }

  auto engine = swg::sysmodule::CreateWgTunnelEngine();
  const swg::Error start_error = engine->Start(swg::sysmodule::TunnelEngineStartRequest{prepared.value});
  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must send one inbound payload packet"
                                                            : responder.error());
  ok &= Require(start_error.ok(), "engine start must complete the payload queue handshake");
  if (!start_error.ok()) {
    return false;
  }

  swg::Result<swg::WireGuardConsumedTransportPacket> packet =
      swg::MakeFailure<swg::WireGuardConsumedTransportPacket>(swg::ErrorCode::NotFound, "not queued yet");
  for (int attempt = 0; attempt < 20; ++attempt) {
    packet = engine->ReceivePacket();
    if (packet.ok()) {
      break;
    }
    if (packet.error.code != swg::ErrorCode::NotFound) {
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  ok &= Require(packet.ok(), "engine must queue one validated inbound transport payload packet");
  if (packet.ok()) {
    ok &= Require(packet.value.payload == payload,
                  "engine receive queue must preserve the authenticated payload bytes");
    ok &= Require(packet.value.counter == 0,
                  "first queued inbound transport payload packet must preserve counter zero");
  }

  const auto empty = engine->ReceivePacket();
  ok &= Require(!empty.ok() && empty.error.code == swg::ErrorCode::NotFound,
                "engine receive queue must report empty after the queued packet is drained");

  ok &= Require(engine->Stop().ok(), "engine stop must succeed after payload queue test");
  return ok;
}

bool TestInvalidWireGuardConnectFails() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-invalid-connect";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  swg::Config invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").public_key = "invalid-key";

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(invalid_config).ok(), "invalid-format profile should still save at config layer")) {
    return false;
  }

  const swg::Error connect_error = client.Connect();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(connect_error.code == swg::ErrorCode::InvalidConfig,
                "connect must fail with InvalidConfig when WireGuard keys are malformed");
  ok &= Require(status.ok(), "status query must succeed after failed connect");
  if (!status.ok()) {
    return false;
  }

  ok &= Require(status.value.state == swg::TunnelState::Error,
                "failed WireGuard preflight must move the service into error state");
  ok &= Require(status.value.last_error.find("public_key") != std::string::npos,
                "failed connect must surface the WireGuard validation error");
  return ok;
}

bool TestIpcCodecRoundTrip() {
  const swg::VersionInfo expected_version{};
  const swg::Result<swg::ByteBuffer> version_payload = swg::EncodePayload(expected_version);
  if (!Require(version_payload.ok(), "version payload encoding must succeed")) {
    return false;
  }

  const swg::Result<swg::VersionInfo> decoded_version = swg::DecodeVersionInfoPayload(version_payload.value);
  if (!Require(decoded_version.ok(), "version payload decoding must succeed")) {
    return false;
  }

  bool ok = true;
  ok &= Require(decoded_version.value.abi_version == expected_version.abi_version,
                "version payload must preserve abi version");
  ok &= Require(decoded_version.value.semantic_version == expected_version.semantic_version,
                "version payload must preserve semantic version");

  const swg::Config expected_config = MakeValidConfig();
  const swg::Result<swg::ByteBuffer> config_payload = swg::EncodePayload(expected_config);
  ok &= Require(config_payload.ok(), "config payload encoding must succeed");
  if (!config_payload.ok()) {
    return false;
  }

  const swg::Result<swg::Config> decoded_config = swg::DecodeConfigPayload(config_payload.value);
  ok &= Require(decoded_config.ok(), "config payload decoding must succeed");
  if (!decoded_config.ok()) {
    return false;
  }

  ok &= Require(decoded_config.value.active_profile == expected_config.active_profile,
                "config payload must preserve active profile");
  ok &= Require(decoded_config.value.profiles.at("default").endpoint_host ==
                    expected_config.profiles.at("default").endpoint_host,
                "config payload must preserve endpoint host");

  const swg::TunnelPacket expected_packet{swg::kAbiVersion, 7, {0x41, 0x42, 0x43}};
  const swg::Result<swg::ByteBuffer> packet_payload = swg::EncodePayload(expected_packet);
  ok &= Require(packet_payload.ok(), "tunnel packet payload encoding must succeed");
  if (!packet_payload.ok()) {
    return false;
  }

  const swg::Result<swg::TunnelPacket> decoded_packet = swg::DecodeTunnelPacketPayload(packet_payload.value);
  ok &= Require(decoded_packet.ok(), "tunnel packet payload decoding must succeed");
  if (!decoded_packet.ok()) {
    return false;
  }

  ok &= Require(decoded_packet.value.abi_version == expected_packet.abi_version,
                "tunnel packet payload must preserve abi version");
  ok &= Require(decoded_packet.value.counter == expected_packet.counter,
                "tunnel packet payload must preserve the transport counter");
  ok &= Require(decoded_packet.value.payload == expected_packet.payload,
                "tunnel packet payload must preserve the authenticated payload bytes");
  return ok;
}

bool TestAppSessionReceivePacket() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-app-session-recv";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const std::vector<std::uint8_t> payload = {0x50, 0x4b, 0x54, 0x01};
  LocalHandshakeResponder responder(0, 0, payload);
  if (!Require(responder.ready(), "local handshake responder must start for app-session receive test")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before app-session receive test")) {
    return false;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  if (!Require(opened.ok(), "app session must open before receiving tunnel packets")) {
    return false;
  }

  if (!Require(client.Connect().ok(), "connect must succeed before app-session packet receive")) {
    return false;
  }
  if (!Require(responder.Join(), responder.error().empty() ? "local responder must send one queued payload packet"
                                                           : responder.error())) {
    return false;
  }

  swg::Result<swg::TunnelPacket> packet =
      swg::MakeFailure<swg::TunnelPacket>(swg::ErrorCode::NotFound, "not queued yet");
  for (int attempt = 0; attempt < 20; ++attempt) {
    packet = session.ReceivePacket();
    if (packet.ok()) {
      break;
    }
    if (packet.error.code != swg::ErrorCode::NotFound) {
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  bool ok = true;
  ok &= Require(packet.ok(), "app session must receive one queued authenticated tunnel packet through IPC");
  if (packet.ok()) {
    ok &= Require(packet.value.counter == 0,
                  "app session receive must preserve the first inbound transport counter");
    ok &= Require(packet.value.payload == payload,
                  "app session receive must preserve the queued authenticated payload bytes");
  }

  const auto empty = session.ReceivePacket();
  ok &= Require(!empty.ok() && empty.error.code == swg::ErrorCode::NotFound,
                "app session receive must report empty after draining the queued packet");

  ok &= Require(session.Close().ok(), "app session must close cleanly after packet receive test");
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after app-session receive test");
  return ok;
}

bool TestAppSessionSendPacket() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-app-session-send";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const std::vector<std::uint8_t> payload = {0x53, 0x45, 0x4e, 0x44, 0x01};
  LocalHandshakeResponder responder(0, 0, {}, payload);
  if (!Require(responder.ready(), "local handshake responder must start for app-session send test")) {
    return false;
  }

  swg::Config config = MakeValidConfig("127.0.0.1", responder.port());
  config.profiles.at("default").persistent_keepalive = 0;

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(config).ok(),
               "valid config must save before app-session send test")) {
    return false;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  if (!Require(opened.ok(), "app session must open before sending tunnel packets")) {
    return false;
  }

  if (!Require(client.Connect().ok(), "connect must succeed before app-session packet send")) {
    return false;
  }

  const auto counter = session.SendPacket(payload);
  if (!Require(counter.ok(), "app session must send one authenticated tunnel packet through IPC")) {
    return false;
  }
  if (!Require(counter.value == 1, "first app-session transport payload send must use counter one")) {
    return false;
  }

  if (!Require(responder.Join(), responder.error().empty() ? "local responder must validate the outbound payload packet"
                                                           : responder.error())) {
    return false;
  }

  const auto stats = client.GetStats();
  bool ok = true;
  ok &= Require(stats.ok(), "stats query must succeed after app-session packet send");
  if (stats.ok()) {
    ok &= Require(stats.value.packets_out >= 3,
                  "app-session packet send must increase outbound packet counters beyond handshake and keepalive");
    ok &= Require(stats.value.bytes_out >
                      swg::kWireGuardHandshakeInitiationSize + swg::kWireGuardTransportKeepaliveSize,
                  "app-session packet send must increase outbound byte counters beyond handshake and keepalive");
  }

  ok &= Require(session.Close().ok(), "app session must close cleanly after packet send test");
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after app-session send test");
  return ok;
}

bool TestAppSessionSustainedTraffic() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-app-session-sustained";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const std::vector<std::vector<std::uint8_t>> inbound_payloads = {
      {0x49, 0x4e, 0x30, 0x31},
      {0x49, 0x4e, 0x30, 0x32, 0x41},
      {0x49, 0x4e, 0x30, 0x33, 0x42, 0x43},
  };
  const std::vector<std::vector<std::uint8_t>> outbound_payloads = {
      {0x4f, 0x55, 0x54, 0x30, 0x31},
      {0x4f, 0x55, 0x54, 0x30, 0x32, 0x44},
      {0x4f, 0x55, 0x54, 0x30, 0x33, 0x45, 0x46},
  };

  LocalHandshakeResponder responder(0, 0, inbound_payloads, outbound_payloads);
  if (!Require(responder.ready(), "local handshake responder must start for sustained app-session traffic test")) {
    return false;
  }

  swg::Config config = MakeValidConfig("127.0.0.1", responder.port());
  config.profiles.at("default").persistent_keepalive = 0;

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(config).ok(),
               "valid config must save before sustained app-session traffic test")) {
    return false;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  if (!Require(opened.ok(), "app session must open before sustained packet traffic")) {
    return false;
  }

  if (!Require(client.Connect().ok(), "connect must succeed before sustained app-session traffic")) {
    return false;
  }

  bool ok = true;
  for (std::size_t index = 0; index < outbound_payloads.size(); ++index) {
    const auto counter = session.SendPacket(outbound_payloads[index]);
    ok &= Require(counter.ok(), "app session must send each sustained outbound payload packet");
    if (counter.ok()) {
      ok &= Require(counter.value == index + 1,
                    "sustained outbound payload packets must preserve consecutive transport counters");
    }
  }

  ok &= Require(responder.Join(), responder.error().empty()
                                      ? "local responder must validate the sustained outbound payload sequence"
                                      : responder.error());

  for (std::size_t index = 0; index < inbound_payloads.size(); ++index) {
    swg::Result<swg::TunnelPacket> packet =
        swg::MakeFailure<swg::TunnelPacket>(swg::ErrorCode::NotFound, "not queued yet");
    for (int attempt = 0; attempt < 20; ++attempt) {
      packet = session.ReceivePacket();
      if (packet.ok()) {
        break;
      }
      if (packet.error.code != swg::ErrorCode::NotFound) {
        break;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ok &= Require(packet.ok(), "app session must receive each sustained inbound payload packet");
    if (packet.ok()) {
      ok &= Require(packet.value.counter == index,
                    "sustained inbound payload packets must preserve consecutive transport counters");
      ok &= Require(packet.value.payload == inbound_payloads[index],
                    "sustained inbound payload packets must preserve the authenticated payload bytes");
    }
  }

  const auto empty = session.ReceivePacket();
  ok &= Require(!empty.ok() && empty.error.code == swg::ErrorCode::NotFound,
                "sustained app-session receive must report empty after draining the queued packets");

  const auto stats = client.GetStats();
  ok &= Require(stats.ok(), "stats query must succeed after sustained app-session traffic");
  if (stats.ok()) {
    ok &= Require(stats.value.successful_handshakes == 1,
                  "sustained app-session traffic must preserve a single successful handshake");
    ok &= Require(stats.value.packets_out >= 2 + outbound_payloads.size(),
                  "sustained app-session traffic must increase outbound packet counters across multiple payloads");
    ok &= Require(stats.value.packets_in >= 1 + inbound_payloads.size(),
                  "sustained app-session traffic must increase inbound packet counters across multiple payloads");
    ok &= Require(stats.value.bytes_out >
                      swg::kWireGuardHandshakeInitiationSize + swg::kWireGuardTransportKeepaliveSize,
                  "sustained app-session traffic must increase outbound bytes beyond handshake traffic");
    ok &= Require(stats.value.bytes_in > swg::kWireGuardHandshakeResponseSize,
                  "sustained app-session traffic must increase inbound bytes beyond the handshake response");
  }

  ok &= Require(session.Close().ok(), "app session must close cleanly after sustained traffic test");
  ok &= Require(client.Disconnect().ok(), "disconnect must succeed after sustained app-session traffic test");
  return ok;
}

bool TestEngineReconnectAfterSendFailure() {
  const swg::Config valid_config = MakeValidConfig("127.0.0.1", 51820);
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for reconnect test");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared =
      swg::sysmodule::PrepareTunnelSession(valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "prepared session must be available for reconnect test");
  if (!prepared.ok()) {
    return false;
  }

  const std::vector<std::uint8_t> payload = {0x52, 0x45, 0x43, 0x4f, 0x4e};
  auto runtime = std::make_unique<ScriptedReconnectSocketRuntime>(prepared.value.endpoint, payload);
  ScriptedReconnectSocketRuntime* runtime_ptr = runtime.get();
  auto engine = swg::sysmodule::CreateWgTunnelEngine(std::move(runtime));

  const swg::Error start_error = engine->Start(swg::sysmodule::TunnelEngineStartRequest{prepared.value});
  ok &= Require(start_error.ok(), "engine start must succeed before reconnect testing");
  if (!start_error.ok()) {
    return false;
  }

  const auto counter = engine->SendPacket(payload);
  ok &= Require(counter.ok(), "engine send must succeed after one bounded reconnect");
  if (counter.ok()) {
    ok &= Require(counter.value == 1,
                  "engine reconnect should resend the payload as the first post-reconnect transport packet");
  }

  const swg::TunnelStats stats = engine->GetStats();
  ok &= Require(stats.reconnects == 1, "engine stats must record one successful bounded reconnect");
  ok &= Require(stats.successful_handshakes == 2,
                "engine stats must record the initial handshake plus the reconnect handshake");
  ok &= Require(stats.packets_out >= 5,
                "engine reconnect test must account for initial and reconnect handshake traffic plus the payload send");
  ok &= Require(runtime_ptr->handshake_count() == 2,
                "scripted runtime must observe two handshake exchanges across reconnect");
  ok &= Require(runtime_ptr->outbound_payload_validated(),
                "scripted runtime must validate the resent authenticated payload after reconnect");
  ok &= Require(engine->Stop().ok(), "engine stop must succeed after reconnect test");
  return ok;
}

bool TestEngineReconnectAfterReceiveFailure() {
  const swg::Config valid_config = MakeValidConfig("127.0.0.1", 51820);
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for receive reconnect test");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared =
      swg::sysmodule::PrepareTunnelSession(valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "prepared session must be available for receive reconnect test");
  if (!prepared.ok()) {
    return false;
  }

  const std::vector<std::uint8_t> payload = {0x52, 0x45, 0x43, 0x56, 0x01};
  auto runtime = std::make_unique<ScriptedReconnectSocketRuntime>(
      prepared.value.endpoint, payload, ScriptedReconnectSocketRuntime::FailureMode::ReceiveOnceAfterHandshake);
  ScriptedReconnectSocketRuntime* runtime_ptr = runtime.get();
  auto engine = swg::sysmodule::CreateWgTunnelEngine(std::move(runtime));

  const swg::Error start_error = engine->Start(swg::sysmodule::TunnelEngineStartRequest{prepared.value});
  ok &= Require(start_error.ok(), "engine start must succeed before receive reconnect testing");
  if (!start_error.ok()) {
    return false;
  }

  bool reconnect_observed = false;
  swg::TunnelStats reconnect_stats{};
  for (int attempt = 0; attempt < 40; ++attempt) {
    reconnect_stats = engine->GetStats();
    if (reconnect_stats.reconnects == 1 && reconnect_stats.successful_handshakes == 2) {
      reconnect_observed = true;
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  ok &= Require(reconnect_observed, "engine must reconnect after a receive-side transport failure");
  ok &= Require(runtime_ptr->receive_failure_triggered(),
                "scripted runtime must trigger the receive-side reconnect failure path");
  ok &= Require(runtime_ptr->handshake_count() == 2,
                "scripted runtime must observe a second handshake after receive-side reconnect");

  const auto counter = engine->SendPacket(payload);
  ok &= Require(counter.ok(), "engine must send successfully after receive-side reconnect");
  if (counter.ok()) {
    ok &= Require(counter.value == 1,
                  "first payload send after a receive-side reconnect must restart the transport counter");
  }
  ok &= Require(runtime_ptr->outbound_payload_validated(),
                "scripted runtime must validate the outbound payload after receive-side reconnect");
  ok &= Require(engine->IsRunning(), "engine must still report running after receive-side reconnect");
  ok &= Require(engine->Stop().ok(), "engine stop must succeed after receive reconnect test");
  return ok;
}

bool TestEngineReconnectAfterKeepaliveFailure() {
  swg::Config valid_config = MakeValidConfig("127.0.0.1", 51820);
  valid_config.profiles.at("default").persistent_keepalive = 1;
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for keepalive reconnect test");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared =
      swg::sysmodule::PrepareTunnelSession(valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "prepared session must be available for keepalive reconnect test");
  if (!prepared.ok()) {
    return false;
  }

  const std::vector<std::uint8_t> payload = {0x4b, 0x45, 0x45, 0x50, 0x01};
  auto runtime = std::make_unique<ScriptedReconnectSocketRuntime>(
      prepared.value.endpoint, payload, ScriptedReconnectSocketRuntime::FailureMode::KeepaliveSendOnce);
  ScriptedReconnectSocketRuntime* runtime_ptr = runtime.get();
  auto engine = swg::sysmodule::CreateWgTunnelEngine(std::move(runtime));

  const swg::Error start_error = engine->Start(swg::sysmodule::TunnelEngineStartRequest{prepared.value});
  ok &= Require(start_error.ok(), "engine start must succeed before keepalive reconnect testing");
  if (!start_error.ok()) {
    return false;
  }

  bool reconnect_observed = false;
  swg::TunnelStats reconnect_stats{};
  for (int attempt = 0; attempt < 60; ++attempt) {
    reconnect_stats = engine->GetStats();
    if (reconnect_stats.reconnects == 1 && reconnect_stats.successful_handshakes == 2) {
      reconnect_observed = true;
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  ok &= Require(reconnect_observed, "engine must reconnect after a periodic keepalive send failure");
  ok &= Require(runtime_ptr->keepalive_send_failure_triggered(),
                "scripted runtime must trigger the keepalive reconnect failure path");
  ok &= Require(runtime_ptr->handshake_count() == 2,
                "scripted runtime must observe a second handshake after keepalive reconnect");

  const auto counter = engine->SendPacket(payload);
  ok &= Require(counter.ok(), "engine must send successfully after keepalive reconnect");
  if (counter.ok()) {
    ok &= Require(counter.value == 1,
                  "first payload send after a keepalive reconnect must restart the transport counter");
  }
  ok &= Require(runtime_ptr->outbound_payload_validated(),
                "scripted runtime must validate the outbound payload after keepalive reconnect");
  ok &= Require(engine->IsRunning(), "engine must still report running after keepalive reconnect");
  ok &= Require(engine->Stop().ok(), "engine stop must succeed after keepalive reconnect test");
  return ok;
}

bool TestMoonlightRoutePlanning() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-moonlight";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  LocalHandshakeResponder responder;
  if (!Require(responder.ready(), "local handshake responder must start for Moonlight planning")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before Moonlight planning")) {
    return false;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  if (!Require(opened.ok(), "Moonlight app session must open")) {
    return false;
  }

  bool ok = true;
  ok &= Require(!opened.value.tunnel_ready, "Moonlight session should start disconnected");
  ok &= Require(opened.value.active_profile == "default", "Moonlight session should bind to requested profile");

  const auto discovery = session.PlanNetwork(swg::MakeMoonlightDiscoveryPlan());
  ok &= Require(discovery.ok(), "discovery plan must succeed");
  ok &= Require(discovery.value.action == swg::RouteAction::Direct, "discovery must bypass the tunnel");
  ok &= Require(discovery.value.local_bypass, "discovery must be marked as local bypass");

  const auto wake = session.PlanNetwork(swg::MakeMoonlightWakeOnLanPlan("192.168.1.20"));
  ok &= Require(wake.ok(), "wake-on-lan plan must succeed");
  ok &= Require(wake.value.action == swg::RouteAction::Direct, "wake-on-lan must bypass the tunnel");
  ok &= Require(wake.value.local_bypass, "wake-on-lan must be marked as local bypass");

  const auto stun = session.PlanNetwork(swg::MakeMoonlightStunPlan());
  ok &= Require(stun.ok(), "stun plan must succeed");
  ok &= Require(stun.value.action == swg::RouteAction::Direct, "stun must bypass the tunnel");
  ok &= Require(!stun.value.local_bypass,
                "stun bypass must remain explicit and must not be mislabeled as local bypass");

  const auto control_before_connect = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984));
  ok &= Require(control_before_connect.ok(), "control plan must succeed before connect");
  ok &= Require(control_before_connect.value.action == swg::RouteAction::Deny,
                "control traffic should be denied until the tunnel is connected");

  ok &= Require(client.Connect().ok(), "service connect must succeed for Moonlight planning");
  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must complete the Moonlight handshake"
                                                            : responder.error());

  const auto dns = session.PlanNetwork(swg::MakeMoonlightDnsPlan("vpn.example.test"));
  ok &= Require(dns.ok(), "dns plan must succeed after connect");
  ok &= Require(dns.value.action == swg::RouteAction::Tunnel, "dns should use the tunnel after connect");
  ok &= Require(dns.value.use_tunnel_dns, "dns plan must mark tunnel dns usage");

  const auto control_after_connect = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984));
  ok &= Require(control_after_connect.ok(), "control plan must succeed after connect");
  ok &= Require(control_after_connect.value.action == swg::RouteAction::Tunnel,
                "control traffic should use the tunnel after connect");

  const auto video = session.PlanNetwork(swg::MakeMoonlightVideoPlan("vpn.example.test", 47998));
  ok &= Require(video.ok(), "video plan must succeed after connect");
  ok &= Require(video.value.action == swg::RouteAction::Tunnel, "video traffic should use the tunnel after connect");

  ok &= Require(session.Close().ok(), "Moonlight app session must close cleanly");
  return ok;
}

bool TestTunnelDnsPacketCodec() {
  swg::TunnelDnsPacketEndpoint endpoint{};
  endpoint.source_ipv4 = {10, 0, 0, 2};
  endpoint.destination_ipv4 = {1, 1, 1, 1};
  endpoint.source_port = 40001;
  endpoint.destination_port = 53;

  const auto query_packet = swg::BuildTunnelDnsQueryPacket(endpoint, "vpn.example.test", 0x1234);
  const auto response_packet = swg::BuildTunnelDnsResponsePacket(
      endpoint, "vpn.example.test", 0x1234, {"203.0.113.44", "203.0.113.45"});

  bool ok = true;
  ok &= Require(query_packet.ok(), "tunnel DNS query packet must build");
  ok &= Require(response_packet.ok(), "tunnel DNS response packet must build");
  if (!query_packet.ok() || !response_packet.ok()) {
    return false;
  }

  ok &= Require(!query_packet.value.empty(), "tunnel DNS query packet must not be empty");

  const auto parsed = swg::ParseTunnelDnsResponsePacket(response_packet.value);
  ok &= Require(parsed.ok(), "tunnel DNS response packet must parse");
  if (parsed.ok()) {
    ok &= Require(parsed.value.query_id == 0x1234, "parsed tunnel DNS response must preserve the query id");
    ok &= Require(parsed.value.source_ipv4 == endpoint.destination_ipv4,
                  "parsed tunnel DNS response must reverse the source IPv4");
    ok &= Require(parsed.value.destination_ipv4 == endpoint.source_ipv4,
                  "parsed tunnel DNS response must reverse the destination IPv4");
    ok &= Require(parsed.value.source_port == endpoint.destination_port,
                  "parsed tunnel DNS response must reverse the source port");
    ok &= Require(parsed.value.destination_port == endpoint.source_port,
                  "parsed tunnel DNS response must reverse the destination port");
    ok &= Require(parsed.value.ipv4_addresses.size() == 2,
                  "parsed tunnel DNS response must preserve both IPv4 answers");
  }

  return ok;
}

bool TestAppSessionDnsResolution() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-dns";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  swg::TunnelDnsPacketEndpoint dns_endpoint{};
  dns_endpoint.source_ipv4 = {10, 0, 0, 2};
  dns_endpoint.destination_ipv4 = {1, 1, 1, 1};
  dns_endpoint.source_port = 40001;
  dns_endpoint.destination_port = 53;

  const auto expected_query = swg::BuildTunnelDnsQueryPacket(dns_endpoint, "vpn.example.test", 1);
  const auto inbound_response =
      swg::BuildTunnelDnsResponsePacket(dns_endpoint, "vpn.example.test", 1, {"203.0.113.44"});
  if (!Require(expected_query.ok(), "expected tunnel DNS query packet must build for DNS resolution tests") ||
      !Require(inbound_response.ok(), "expected tunnel DNS response packet must build for DNS resolution tests")) {
    return false;
  }

  LocalHandshakeResponder responder(0, 0, inbound_response.value, expected_query.value);
  if (!Require(responder.ready(), "local handshake responder must start for DNS resolution tests")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before DNS resolution tests")) {
    return false;
  }

  bool ok = true;

  swg::AppSession direct_session(client);
  const auto direct_opened = direct_session.Open(swg::MakeMoonlightSessionRequest("default", false));
  ok &= Require(direct_opened.ok(), "direct-fallback DNS app session must open");
  if (!direct_opened.ok()) {
    return false;
  }

  const auto direct_dns = direct_session.ResolveDns("1.1.1.1");
  ok &= Require(direct_dns.ok(), "direct-fallback DNS resolve must succeed");
  if (direct_dns.ok()) {
    ok &= Require(direct_dns.value.action == swg::RouteAction::Direct,
                  "direct-fallback DNS resolve must stay on the direct path");
    ok &= Require(direct_dns.value.resolved, "direct-fallback DNS resolve must return addresses");
    ok &= Require(std::find(direct_dns.value.addresses.begin(), direct_dns.value.addresses.end(), "1.1.1.1") !=
                      direct_dns.value.addresses.end(),
            "direct-fallback DNS resolve must include the requested IPv4 literal");
  }

  const auto stats_after_direct = client.GetStats();
  ok &= Require(stats_after_direct.ok(), "stats must load after direct DNS resolve");
  if (stats_after_direct.ok()) {
    ok &= Require(stats_after_direct.value.dns_queries == 1,
                  "direct DNS resolve must increment the DNS query counter");
    ok &= Require(stats_after_direct.value.dns_fallbacks == 1,
                  "direct fallback DNS resolve must increment the fallback counter");
    ok &= Require(stats_after_direct.value.leak_prevention_events == 0,
                  "direct fallback DNS resolve must not record a leak-prevention event");
  }

  ok &= Require(direct_session.Close().ok(), "direct-fallback DNS app session must close cleanly");

  swg::AppSession tunnel_session(client);
  const auto tunnel_opened = tunnel_session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(tunnel_opened.ok(), "tunnel DNS app session must open");
  if (!tunnel_opened.ok()) {
    return false;
  }

  const auto denied_dns = tunnel_session.ResolveDns("vpn.example.test");
  ok &= Require(denied_dns.ok(), "denied DNS resolve must return a policy result");
  if (denied_dns.ok()) {
    ok &= Require(denied_dns.value.action == swg::RouteAction::Deny,
                  "tunnel-required DNS must fail closed before the tunnel is connected");
    ok &= Require(!denied_dns.value.resolved,
                  "tunnel-required DNS must not resolve directly before the tunnel is connected");
    ok &= Require(denied_dns.value.message.find("not ready") != std::string::npos,
                  "denied DNS result must explain that tunnel DNS is not ready");
  }

  const auto stats_after_deny = client.GetStats();
  ok &= Require(stats_after_deny.ok(), "stats must load after denied DNS resolve");
  if (stats_after_deny.ok()) {
    ok &= Require(stats_after_deny.value.dns_queries == 2,
                  "denied DNS resolve must increment the DNS query counter");
    ok &= Require(stats_after_deny.value.dns_fallbacks == 1,
                  "denied DNS resolve must not increment the fallback counter");
    ok &= Require(stats_after_deny.value.leak_prevention_events == 1,
                  "denied DNS resolve must record a leak-prevention event");
  }

  ok &= Require(client.Connect().ok(), "service connect must succeed before tunnel DNS resolution test");

  const auto tunnel_dns = tunnel_session.ResolveDns("vpn.example.test");
  ok &= Require(tunnel_dns.ok(), "tunnel DNS resolve must succeed after connect");
  if (tunnel_dns.ok()) {
    ok &= Require(tunnel_dns.value.action == swg::RouteAction::Tunnel,
                  "connected tunnel DNS resolve must stay on the tunnel path");
    ok &= Require(tunnel_dns.value.use_tunnel_dns,
                  "connected tunnel DNS resolve must mark tunnel DNS usage");
    ok &= Require(tunnel_dns.value.resolved,
                  "connected tunnel DNS resolve must return an IPv4 answer when the tunnel DNS response is queued");
    ok &= Require(tunnel_dns.value.dns_servers.size() == 2,
                  "connected tunnel DNS resolve must expose the selected profile DNS servers");
    ok &= Require(std::find(tunnel_dns.value.addresses.begin(), tunnel_dns.value.addresses.end(), "203.0.113.44") !=
                      tunnel_dns.value.addresses.end(),
                  "connected tunnel DNS resolve must return the queued IPv4 DNS answer");
    ok &= Require(tunnel_dns.value.message.find("1.1.1.1") != std::string::npos,
                  "connected tunnel DNS resolve must report the DNS server that answered the query");
  }

  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must complete the tunnel DNS handshake"
                                                            : responder.error());

  const auto stats_after_tunnel = client.GetStats();
  ok &= Require(stats_after_tunnel.ok(), "stats must load after tunnel DNS resolution");
  if (stats_after_tunnel.ok()) {
    ok &= Require(stats_after_tunnel.value.dns_queries == 3,
                  "tunnel DNS resolution must increment the DNS query counter");
    ok &= Require(stats_after_tunnel.value.dns_fallbacks == 1,
                  "successful tunnel DNS resolution must not increment the fallback counter");
    ok &= Require(stats_after_tunnel.value.leak_prevention_events == 1,
                  "successful tunnel DNS resolution must preserve the prior leak-prevention count");
  }

  ok &= Require(tunnel_session.Close().ok(), "tunnel DNS app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after DNS resolution tests");
  return ok;
}

bool TestSessionSocketAbstraction() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-session-socket";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const std::vector<std::uint8_t> inbound_payload = {0x44, 0x4e, 0x53, 0x52, 0x45, 0x43, 0x56};
  const std::vector<std::uint8_t> outbound_payload = {0x53, 0x4f, 0x43, 0x4b, 0x45, 0x54, 0x01};
  swg::TunnelDnsPacketEndpoint dns_endpoint{};
  dns_endpoint.source_ipv4 = {10, 0, 0, 2};
  dns_endpoint.destination_ipv4 = {1, 1, 1, 1};
  dns_endpoint.source_port = 40001;
  dns_endpoint.destination_port = 53;

  const auto dns_query = swg::BuildTunnelDnsQueryPacket(dns_endpoint, "vpn.example.test", 1);
  const auto dns_response =
      swg::BuildTunnelDnsResponsePacket(dns_endpoint, "vpn.example.test", 1, {"203.0.113.44"});
  if (!Require(dns_query.ok(), "expected tunnel DNS query packet must build for session socket tests") ||
      !Require(dns_response.ok(), "expected tunnel DNS response packet must build for session socket tests")) {
    return false;
  }

  LocalHandshakeResponder responder(0, 0,
                                    std::vector<std::vector<std::uint8_t>>{inbound_payload, dns_response.value},
                                    std::vector<std::vector<std::uint8_t>>{outbound_payload, dns_query.value});
  if (!Require(responder.ready(), "local handshake responder must start for session socket tests")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before session socket tests")) {
    return false;
  }

  bool ok = true;

  swg::AppSession direct_session(client);
  const auto direct_opened = direct_session.Open(swg::MakeMoonlightSessionRequest("default", false));
  ok &= Require(direct_opened.ok(), "direct-fallback app session must open for session socket tests");
  if (!direct_opened.ok()) {
    return false;
  }

  swg::SessionSocketRequest direct_request{};
  direct_request.remote_host = "1.1.1.1";
  direct_request.remote_port = 47998;
  direct_request.transport = swg::TransportProtocol::Udp;
  direct_request.traffic_class = swg::AppTrafficClass::StreamVideo;
  direct_request.route_preference = swg::RoutePreference::PreferTunnel;

  const auto direct_socket = swg::SessionSocket::OpenDatagram(direct_session, direct_request);
  ok &= Require(direct_socket.ok(), "direct datagram socket must open");
  if (direct_socket.ok()) {
    ok &= Require(direct_socket.value.uses_direct_socket(),
                  "direct datagram socket must select direct-socket mode");
    ok &= Require(!direct_socket.value.uses_tunnel_packets(),
                  "direct datagram socket must not expose tunnel-packet mode");
    ok &= Require(direct_socket.value.info().remote_addresses.size() == 1 &&
                      direct_socket.value.info().remote_addresses.front() == "1.1.1.1",
                  "direct datagram socket must preserve the requested IPv4 address");

    const auto direct_send = direct_socket.value.Send(outbound_payload);
    ok &= Require(!direct_send.ok() && direct_send.error.code == swg::ErrorCode::Unsupported,
                  "direct datagram socket must reject tunnel packet send calls");
  }

  ok &= Require(direct_session.Close().ok(), "direct-fallback app session must close after session socket tests");

  swg::AppSession tunnel_session(client);
  const auto tunnel_opened = tunnel_session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(tunnel_opened.ok(), "tunnel app session must open for session socket tests");
  if (!tunnel_opened.ok()) {
    return false;
  }

  const auto denied_socket = swg::SessionSocket::OpenDatagram(
      tunnel_session, swg::MakeMoonlightVideoSocketRequest("203.0.113.8", 47998));
  ok &= Require(denied_socket.ok(), "denied datagram socket must still return a structured result");
  if (denied_socket.ok()) {
    ok &= Require(denied_socket.value.denied(),
                  "tunnel-required datagram socket must deny before connect");
  }

  ok &= Require(client.Connect().ok(), "service connect must succeed before tunnel session socket tests");

  const auto tunnel_socket = swg::SessionSocket::OpenDatagram(
      tunnel_session, swg::MakeMoonlightVideoSocketRequest("203.0.113.8", 47998));
  ok &= Require(tunnel_socket.ok(), "connected datagram socket must open");
  if (tunnel_socket.ok()) {
    ok &= Require(tunnel_socket.value.uses_tunnel_packets(),
                  "connected datagram socket must select tunnel-packet mode");
    ok &= Require(tunnel_socket.value.info().mode == swg::SessionSocketMode::TunnelPacket,
                  "connected datagram socket must report tunnel-packet mode");

    const auto counter = tunnel_socket.value.Send(outbound_payload);
    ok &= Require(counter.ok(), "connected datagram socket must send through the tunnel packet path");
    if (counter.ok()) {
      ok &= Require(counter.value == 1,
                    "first datagram socket tunnel send must use transport counter one");
    }

    bool received_payload = false;
    for (int attempt = 0; attempt < 20; ++attempt) {
      const auto packet = tunnel_socket.value.Receive();
      if (packet.ok()) {
        received_payload = true;
        ok &= Require(packet.value.payload == inbound_payload,
                      "connected datagram socket must receive the queued inbound payload");
        break;
      }

      if (packet.error.code != swg::ErrorCode::NotFound) {
        ok &= Require(false, "connected datagram socket receive must only retry on an empty queue");
        break;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ok &= Require(received_payload,
                  "connected datagram socket must eventually receive the queued inbound payload");
  }

  const auto stream_socket = swg::SessionSocket::OpenStream(
      tunnel_session, swg::MakeMoonlightHttpsControlSocketRequest("vpn.example.test", 47984));
  ok &= Require(stream_socket.ok(), "connected stream socket must open");
  if (stream_socket.ok()) {
    ok &= Require(stream_socket.value.uses_tunnel_packets(),
                  "connected stream socket must surface tunnel-packet mode for framed stream payloads");
    ok &= Require(stream_socket.value.info().used_dns_helper,
                  "connected stream socket must consult the DNS helper for hostname targets");
    ok &= Require(stream_socket.value.info().dns.action == swg::RouteAction::Tunnel,
                  "connected stream socket must preserve tunnel DNS guidance for hostname targets");
    ok &= Require(stream_socket.value.info().dns.resolved,
                  "connected stream socket must resolve hostname targets through tunnel DNS when a response is queued");
    ok &= Require(std::find(stream_socket.value.info().remote_addresses.begin(),
                           stream_socket.value.info().remote_addresses.end(), "203.0.113.44") !=
                      stream_socket.value.info().remote_addresses.end(),
                  "connected stream socket must expose the resolved tunnel DNS IPv4 answer");
  }

  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must complete the session socket handshake"
                                                            : responder.error());
  ok &= Require(tunnel_session.Close().ok(), "tunnel app session must close after session socket tests");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after session socket tests");
  return ok;
}

bool TestTunnelDatagramSocket() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-tunnel-datagram";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  constexpr std::uint16_t kExpectedFirstTunnelDatagramSourcePort = 20000;
  constexpr std::uint16_t kMoonlightVideoPort = 47998;
  const std::vector<std::uint8_t> outbound_payload = {0x56, 0x49, 0x44, 0x45, 0x4f, 0x01};
  const std::vector<std::uint8_t> inbound_payload = {0x56, 0x49, 0x44, 0x45, 0x4f, 0x52, 0x45, 0x43, 0x56};

  const auto local_address = swg::ParseIpAddress("10.0.0.2", "local_address");
  const auto remote_address = swg::ParseIpAddress("203.0.113.8", "remote_address");
  if (!Require(local_address.ok(), "tunnel datagram local IPv4 address must parse") ||
      !Require(remote_address.ok(), "tunnel datagram remote IPv4 address must parse")) {
    return false;
  }

  swg::Ipv4UdpPacketEndpoint outbound_endpoint{};
  std::copy_n(local_address.value.bytes.begin(), 4, outbound_endpoint.source_ipv4.begin());
  std::copy_n(remote_address.value.bytes.begin(), 4, outbound_endpoint.destination_ipv4.begin());
  outbound_endpoint.source_port = kExpectedFirstTunnelDatagramSourcePort;
  outbound_endpoint.destination_port = kMoonlightVideoPort;

  swg::Ipv4UdpPacketEndpoint inbound_endpoint{};
  inbound_endpoint.source_ipv4 = outbound_endpoint.destination_ipv4;
  inbound_endpoint.destination_ipv4 = outbound_endpoint.source_ipv4;
  inbound_endpoint.source_port = outbound_endpoint.destination_port;
  inbound_endpoint.destination_port = outbound_endpoint.source_port;

  const auto expected_outbound_packet = swg::BuildIpv4UdpPacket(outbound_endpoint, outbound_payload);
  const auto inbound_packet = swg::BuildIpv4UdpPacket(inbound_endpoint, inbound_payload);
  if (!Require(expected_outbound_packet.ok(), "expected tunnel datagram packet must build") ||
      !Require(inbound_packet.ok(), "inbound tunnel datagram packet must build")) {
    return false;
  }

  LocalHandshakeResponder responder(0, 0, inbound_packet.value, expected_outbound_packet.value);
  if (!Require(responder.ready(), "local handshake responder must start for tunnel datagram tests")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before tunnel datagram tests")) {
    return false;
  }

  bool ok = true;
  ok &= Require(client.Connect().ok(), "service connect must succeed before tunnel datagram tests");

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(opened.ok(), "tunnel datagram app session must open");
  if (!opened.ok()) {
    return false;
  }

  const auto local_bypass = session.OpenTunnelDatagram(swg::MakeMoonlightVideoDatagramRequest("192.168.1.50", kMoonlightVideoPort));
  ok &= Require(!local_bypass.ok(), "local-network video traffic should not open a tunnel datagram handle");

  const auto video_socket = swg::TunnelDatagramSocket::Open(
      session, swg::MakeMoonlightVideoDatagramRequest("203.0.113.8", kMoonlightVideoPort));
  ok &= Require(video_socket.ok(), "Moonlight video tunnel datagram socket must open");
  if (!video_socket.ok()) {
    return false;
  }

  ok &= Require(video_socket.value.info().local_port == kExpectedFirstTunnelDatagramSourcePort,
                "first tunnel datagram handle must use the expected deterministic local UDP source port");
  ok &= Require(video_socket.value.info().remote_address == "203.0.113.8",
                "tunnel datagram info must report the resolved remote IPv4 address");

  const auto send_counter = video_socket.value.Send(outbound_payload);
  ok &= Require(send_counter.ok(), "tunnel datagram send must succeed");
  if (send_counter.ok()) {
    ok &= Require(send_counter.value == 1,
                  "first outbound tunnel datagram must use the first post-keepalive transport counter");
  }

  const auto received = video_socket.value.Receive();
  ok &= Require(received.ok(), "tunnel datagram receive must return the queued inbound UDP payload");
  if (received.ok()) {
    ok &= Require(received.value.remote_address == "203.0.113.8",
                  "tunnel datagram receive must preserve the remote IPv4 address");
    ok &= Require(received.value.remote_port == kMoonlightVideoPort,
                  "tunnel datagram receive must preserve the remote UDP port");
    ok &= Require(received.value.payload == inbound_payload,
                  "tunnel datagram receive must return the inner UDP payload bytes");
  }

  const auto empty = video_socket.value.Receive();
  ok &= Require(!empty.ok() && empty.error.code == swg::ErrorCode::NotFound,
                "tunnel datagram receive must report an empty queue after consuming the queued payload");

  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must validate the tunnel datagram exchange"
                                                            : responder.error());
  ok &= Require(session.Close().ok(), "tunnel datagram app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after tunnel datagram tests");
  return ok;
}

bool TestTunnelStreamSocket() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-tunnel-stream";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  constexpr std::uint16_t kExpectedFirstTunnelStreamSourcePort = 30000;
  constexpr std::uint16_t kMoonlightHttpsPort = 47984;
  constexpr std::uint32_t kExpectedFirstTunnelStreamInitialSequence = 0x53570000u;
  constexpr std::uint32_t kRemoteInitialSequence = 0x40000000u;

  const std::vector<std::uint8_t> request_payload = {'G', 'E', 'T', ' ', '/', 's', 'e', 'r', 'v', 'e', 'r'};
  const std::vector<std::uint8_t> response_payload = {'O', 'K', ' ', 'M', 'O', 'O', 'N', 'L', 'I', 'G', 'H', 'T'};

  const auto local_address = swg::ParseIpAddress("10.0.0.2", "local_address");
  const auto remote_address = swg::ParseIpAddress("203.0.113.44", "remote_address");
  if (!Require(local_address.ok(), "tunnel stream local IPv4 address must parse") ||
      !Require(remote_address.ok(), "tunnel stream remote IPv4 address must parse")) {
    return false;
  }

  swg::Ipv4TcpPacketEndpoint endpoint{};
  std::copy_n(local_address.value.bytes.begin(), 4, endpoint.source_ipv4.begin());
  std::copy_n(remote_address.value.bytes.begin(), 4, endpoint.destination_ipv4.begin());
  endpoint.source_port = kExpectedFirstTunnelStreamSourcePort;
  endpoint.destination_port = kMoonlightHttpsPort;

  swg::Ipv4TcpPacket syn{};
  syn.endpoint = endpoint;
  syn.sequence_number = kExpectedFirstTunnelStreamInitialSequence;
  syn.flags = swg::ToFlags(swg::TcpControlFlag::Syn);

  swg::Ipv4TcpPacket synack{};
  synack.endpoint.source_ipv4 = endpoint.destination_ipv4;
  synack.endpoint.destination_ipv4 = endpoint.source_ipv4;
  synack.endpoint.source_port = endpoint.destination_port;
  synack.endpoint.destination_port = endpoint.source_port;
  synack.sequence_number = kRemoteInitialSequence;
  synack.acknowledgment_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  synack.flags = swg::ToFlags(swg::TcpControlFlag::Syn) | swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket ack{};
  ack.endpoint = endpoint;
  ack.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  ack.acknowledgment_number = kRemoteInitialSequence + 1u;
  ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket request{};
  request.endpoint = endpoint;
  request.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  request.acknowledgment_number = kRemoteInitialSequence + 1u;
  request.flags = swg::ToFlags(swg::TcpControlFlag::Ack) | swg::ToFlags(swg::TcpControlFlag::Psh);
  request.payload = request_payload;

  swg::Ipv4TcpPacket response{};
  response.endpoint = synack.endpoint;
  response.sequence_number = kRemoteInitialSequence + 1u;
  response.acknowledgment_number = kExpectedFirstTunnelStreamInitialSequence + 1u +
                                   static_cast<std::uint32_t>(request_payload.size());
  response.flags = swg::ToFlags(swg::TcpControlFlag::Ack) | swg::ToFlags(swg::TcpControlFlag::Psh);
  response.payload = response_payload;

  swg::Ipv4TcpPacket response_ack{};
  response_ack.endpoint = endpoint;
  response_ack.sequence_number = response.acknowledgment_number;
  response_ack.acknowledgment_number = kRemoteInitialSequence + 1u + static_cast<std::uint32_t>(response_payload.size());
  response_ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  const auto syn_packet = swg::BuildIpv4TcpPacket(syn);
  const auto synack_packet = swg::BuildIpv4TcpPacket(synack);
  const auto ack_packet = swg::BuildIpv4TcpPacket(ack);
  const auto request_packet = swg::BuildIpv4TcpPacket(request);
  const auto response_packet = swg::BuildIpv4TcpPacket(response);
  const auto response_ack_packet = swg::BuildIpv4TcpPacket(response_ack);
  if (!Require(syn_packet.ok(), "tunnel stream SYN packet must build") ||
      !Require(synack_packet.ok(), "tunnel stream SYN-ACK packet must build") ||
      !Require(ack_packet.ok(), "tunnel stream ACK packet must build") ||
      !Require(request_packet.ok(), "tunnel stream request packet must build") ||
      !Require(response_packet.ok(), "tunnel stream response packet must build") ||
      !Require(response_ack_packet.ok(), "tunnel stream response ACK packet must build")) {
    return false;
  }

  LocalHandshakeResponder responder(0, 0,
                                    std::vector<std::vector<std::uint8_t>>{synack_packet.value, response_packet.value},
                                    std::vector<std::vector<std::uint8_t>>{syn_packet.value, ack_packet.value,
                                                                           request_packet.value, response_ack_packet.value});
  if (!Require(responder.ready(), "local handshake responder must start for tunnel stream tests")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before tunnel stream tests")) {
    return false;
  }

  bool ok = true;
  ok &= Require(client.Connect().ok(), "service connect must succeed before tunnel stream tests");

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(opened.ok(), "tunnel stream app session must open");
  if (!opened.ok()) {
    return false;
  }

  const auto local_bypass = session.OpenTunnelStream(
      swg::MakeMoonlightHttpsControlStreamRequest("192.168.1.50", kMoonlightHttpsPort));
  ok &= Require(!local_bypass.ok(), "local-network HTTPS control traffic should not open a tunnel stream");

  const auto control_stream = swg::TunnelStreamSocket::Open(
      session, swg::MakeMoonlightHttpsControlStreamRequest("203.0.113.44", kMoonlightHttpsPort));
  ok &= Require(control_stream.ok(), "Moonlight HTTPS control tunnel stream must open");
  if (!control_stream.ok()) {
    return false;
  }

  ok &= Require(control_stream.value.info().local_port == kExpectedFirstTunnelStreamSourcePort,
                "first tunnel stream handle must use the expected deterministic local TCP source port");
  ok &= Require(control_stream.value.info().remote_address == "203.0.113.44",
                "tunnel stream info must report the resolved remote IPv4 address");

  const auto send_counter = control_stream.value.Send(request_payload);
  ok &= Require(send_counter.ok(), "tunnel stream send must succeed");
  if (send_counter.ok()) {
    ok &= Require(send_counter.value == 3,
                  "first outbound stream payload must follow the SYN and ACK transport packets");
  }

  const auto received = control_stream.value.Receive();
  ok &= Require(received.ok(), "tunnel stream receive must return the queued response payload");
  if (received.ok()) {
    ok &= Require(!received.value.peer_closed,
                  "tunnel stream response should keep the peer connection open in the happy path");
    ok &= Require(received.value.payload == response_payload,
                  "tunnel stream receive must return the inner TCP payload bytes");
  }

  const auto empty = control_stream.value.Receive();
  ok &= Require(!empty.ok() && empty.error.code == swg::ErrorCode::NotFound,
                "tunnel stream receive must report an empty queue after consuming the response payload");

  ok &= Require(responder.Join(), responder.error().empty() ? "local responder must validate the tunnel stream exchange"
                                                            : responder.error());
  ok &= Require(session.Close().ok(), "tunnel stream app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after tunnel stream tests");
  return ok;
}

bool TestTunnelStreamSocketOutOfOrder() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-tunnel-stream-out-of-order";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  constexpr std::uint16_t kExpectedFirstTunnelStreamSourcePort = 30000;
  constexpr std::uint16_t kMoonlightHttpsPort = 47984;
  constexpr std::uint32_t kExpectedFirstTunnelStreamInitialSequence = 0x53570000u;
  constexpr std::uint32_t kRemoteInitialSequence = 0x40000000u;

  const std::vector<std::uint8_t> request_payload = {'G', 'E', 'T', ' ', '/', 'a', 'p', 'p', 's'};
  const std::vector<std::uint8_t> response_payload = {'G', 'A', 'M', 'E', 'S', ':', 'A', ',', 'B', ',', 'C'};
  const std::vector<std::uint8_t> response_payload_a(response_payload.begin(), response_payload.begin() + 5);
  const std::vector<std::uint8_t> response_payload_b(response_payload.begin() + 5, response_payload.end());

  const auto local_address = swg::ParseIpAddress("10.0.0.2", "local_address");
  const auto remote_address = swg::ParseIpAddress("203.0.113.44", "remote_address");
  if (!Require(local_address.ok(), "out-of-order tunnel stream local IPv4 address must parse") ||
      !Require(remote_address.ok(), "out-of-order tunnel stream remote IPv4 address must parse")) {
    return false;
  }

  swg::Ipv4TcpPacketEndpoint endpoint{};
  std::copy_n(local_address.value.bytes.begin(), 4, endpoint.source_ipv4.begin());
  std::copy_n(remote_address.value.bytes.begin(), 4, endpoint.destination_ipv4.begin());
  endpoint.source_port = kExpectedFirstTunnelStreamSourcePort;
  endpoint.destination_port = kMoonlightHttpsPort;

  swg::Ipv4TcpPacket syn{};
  syn.endpoint = endpoint;
  syn.sequence_number = kExpectedFirstTunnelStreamInitialSequence;
  syn.flags = swg::ToFlags(swg::TcpControlFlag::Syn);

  swg::Ipv4TcpPacket synack{};
  synack.endpoint.source_ipv4 = endpoint.destination_ipv4;
  synack.endpoint.destination_ipv4 = endpoint.source_ipv4;
  synack.endpoint.source_port = endpoint.destination_port;
  synack.endpoint.destination_port = endpoint.source_port;
  synack.sequence_number = kRemoteInitialSequence;
  synack.acknowledgment_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  synack.flags = swg::ToFlags(swg::TcpControlFlag::Syn) | swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket ack{};
  ack.endpoint = endpoint;
  ack.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  ack.acknowledgment_number = kRemoteInitialSequence + 1u;
  ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket request{};
  request.endpoint = endpoint;
  request.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  request.acknowledgment_number = kRemoteInitialSequence + 1u;
  request.flags = swg::ToFlags(swg::TcpControlFlag::Ack) | swg::ToFlags(swg::TcpControlFlag::Psh);
  request.payload = request_payload;

  swg::Ipv4TcpPacket response_a{};
  response_a.endpoint = synack.endpoint;
  response_a.sequence_number = kRemoteInitialSequence + 1u;
  response_a.acknowledgment_number = kExpectedFirstTunnelStreamInitialSequence + 1u +
                                     static_cast<std::uint32_t>(request_payload.size());
  response_a.flags = swg::ToFlags(swg::TcpControlFlag::Ack) | swg::ToFlags(swg::TcpControlFlag::Psh);
  response_a.payload = response_payload_a;

  swg::Ipv4TcpPacket response_b{};
  response_b.endpoint = synack.endpoint;
  response_b.sequence_number = response_a.sequence_number + static_cast<std::uint32_t>(response_payload_a.size());
  response_b.acknowledgment_number = response_a.acknowledgment_number;
  response_b.flags = swg::ToFlags(swg::TcpControlFlag::Ack) | swg::ToFlags(swg::TcpControlFlag::Psh);
  response_b.payload = response_payload_b;

  swg::Ipv4TcpPacket duplicate_ack{};
  duplicate_ack.endpoint = endpoint;
  duplicate_ack.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u +
                                  static_cast<std::uint32_t>(request_payload.size());
  duplicate_ack.acknowledgment_number = kRemoteInitialSequence + 1u;
  duplicate_ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket response_ack{};
  response_ack.endpoint = endpoint;
  response_ack.sequence_number = duplicate_ack.sequence_number;
  response_ack.acknowledgment_number = kRemoteInitialSequence + 1u +
                                       static_cast<std::uint32_t>(response_payload.size());
  response_ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  const auto syn_packet = swg::BuildIpv4TcpPacket(syn);
  const auto synack_packet = swg::BuildIpv4TcpPacket(synack);
  const auto ack_packet = swg::BuildIpv4TcpPacket(ack);
  const auto request_packet = swg::BuildIpv4TcpPacket(request);
  const auto response_a_packet = swg::BuildIpv4TcpPacket(response_a);
  const auto response_b_packet = swg::BuildIpv4TcpPacket(response_b);
  const auto duplicate_ack_packet = swg::BuildIpv4TcpPacket(duplicate_ack);
  const auto response_ack_packet = swg::BuildIpv4TcpPacket(response_ack);
  if (!Require(syn_packet.ok(), "out-of-order tunnel stream SYN packet must build") ||
      !Require(synack_packet.ok(), "out-of-order tunnel stream SYN-ACK packet must build") ||
      !Require(ack_packet.ok(), "out-of-order tunnel stream ACK packet must build") ||
      !Require(request_packet.ok(), "out-of-order tunnel stream request packet must build") ||
      !Require(response_a_packet.ok(), "out-of-order tunnel stream response A packet must build") ||
      !Require(response_b_packet.ok(), "out-of-order tunnel stream response B packet must build") ||
      !Require(duplicate_ack_packet.ok(), "out-of-order tunnel stream duplicate ACK packet must build") ||
      !Require(response_ack_packet.ok(), "out-of-order tunnel stream response ACK packet must build")) {
    return false;
  }

  LocalHandshakeResponder responder(
      0, 0,
      std::vector<std::vector<std::uint8_t>>{synack_packet.value, response_b_packet.value, response_a_packet.value},
      std::vector<std::vector<std::uint8_t>>{syn_packet.value, ack_packet.value, request_packet.value,
                                             duplicate_ack_packet.value, response_ack_packet.value});
  if (!Require(responder.ready(), "out-of-order tunnel stream responder must start")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before out-of-order tunnel stream tests")) {
    return false;
  }

  bool ok = true;
  ok &= Require(client.Connect().ok(), "service connect must succeed before out-of-order tunnel stream tests");

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(opened.ok(), "out-of-order tunnel stream app session must open");
  if (!opened.ok()) {
    return false;
  }

  const auto control_stream = swg::TunnelStreamSocket::Open(
      session, swg::MakeMoonlightHttpsControlStreamRequest("203.0.113.44", kMoonlightHttpsPort));
  ok &= Require(control_stream.ok(), "out-of-order Moonlight HTTPS control tunnel stream must open");
  if (!control_stream.ok()) {
    return false;
  }

  ok &= Require(control_stream.value.info().local_port == kExpectedFirstTunnelStreamSourcePort,
                "out-of-order tunnel stream must use the expected deterministic local TCP source port");

  const auto send_counter = control_stream.value.Send(request_payload);
  ok &= Require(send_counter.ok(), "out-of-order tunnel stream send must succeed");
  if (send_counter.ok()) {
    ok &= Require(send_counter.value == 3,
                  "out-of-order stream payload must still follow the SYN and ACK transport packets");
  }

  const auto received = control_stream.value.Receive();
  ok &= Require(received.ok(), "out-of-order tunnel stream receive must succeed");
  if (received.ok()) {
    ok &= Require(received.value.payload == response_payload,
                  "out-of-order tunnel stream receive must reassemble contiguous buffered TCP payload");
    ok &= Require(!received.value.peer_closed,
                  "out-of-order tunnel stream response should keep the peer connection open");
  }

  const auto empty = control_stream.value.Receive();
  ok &= Require(!empty.ok() && empty.error.code == swg::ErrorCode::NotFound,
                "out-of-order tunnel stream receive must drain the buffered response payload completely");

  ok &= Require(responder.Join(), responder.error().empty() ? "out-of-order responder must validate the tunnel stream exchange"
                                                            : responder.error());
  ok &= Require(session.Close().ok(), "out-of-order tunnel stream app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after out-of-order tunnel stream tests");
  return ok;
}

bool TestTunnelStreamSocketDelayedSynAck() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-tunnel-stream-delayed-synack";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  constexpr std::uint16_t kExpectedFirstTunnelStreamSourcePort = 30000;
  constexpr std::uint16_t kMoonlightRtspPort = 48010;
  constexpr std::uint32_t kExpectedFirstTunnelStreamInitialSequence = 0x53570000u;
  constexpr std::uint32_t kRemoteInitialSequence = 0x40000000u;

  const auto local_address = swg::ParseIpAddress("10.0.0.2", "local_address");
  const auto remote_address = swg::ParseIpAddress("203.0.113.44", "remote_address");
  if (!Require(local_address.ok(), "delayed SYN-ACK tunnel stream local IPv4 address must parse") ||
      !Require(remote_address.ok(), "delayed SYN-ACK tunnel stream remote IPv4 address must parse")) {
    return false;
  }

  swg::Ipv4TcpPacketEndpoint endpoint{};
  std::copy_n(local_address.value.bytes.begin(), 4, endpoint.source_ipv4.begin());
  std::copy_n(remote_address.value.bytes.begin(), 4, endpoint.destination_ipv4.begin());
  endpoint.source_port = kExpectedFirstTunnelStreamSourcePort;
  endpoint.destination_port = kMoonlightRtspPort;

  swg::Ipv4TcpPacket syn{};
  syn.endpoint = endpoint;
  syn.sequence_number = kExpectedFirstTunnelStreamInitialSequence;
  syn.flags = swg::ToFlags(swg::TcpControlFlag::Syn);

  swg::Ipv4TcpPacket synack{};
  synack.endpoint.source_ipv4 = endpoint.destination_ipv4;
  synack.endpoint.destination_ipv4 = endpoint.source_ipv4;
  synack.endpoint.source_port = endpoint.destination_port;
  synack.endpoint.destination_port = endpoint.source_port;
  synack.sequence_number = kRemoteInitialSequence;
  synack.acknowledgment_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  synack.flags = swg::ToFlags(swg::TcpControlFlag::Syn) | swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket ack{};
  ack.endpoint = endpoint;
  ack.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  ack.acknowledgment_number = kRemoteInitialSequence + 1u;
  ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  const auto syn_packet = swg::BuildIpv4TcpPacket(syn);
  const auto synack_packet = swg::BuildIpv4TcpPacket(synack);
  const auto ack_packet = swg::BuildIpv4TcpPacket(ack);
  if (!Require(syn_packet.ok(), "delayed SYN-ACK tunnel stream SYN packet must build") ||
      !Require(synack_packet.ok(), "delayed SYN-ACK tunnel stream SYN-ACK packet must build") ||
      !Require(ack_packet.ok(), "delayed SYN-ACK tunnel stream ACK packet must build")) {
    return false;
  }

  DelayedTunnelStreamSynAckResponder responder(
      syn_packet.value, synack_packet.value, ack_packet.value, std::chrono::milliseconds(1100));
  if (!Require(responder.ready(), "delayed SYN-ACK responder must start for tunnel stream tests")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before delayed SYN-ACK tunnel stream tests")) {
    return false;
  }

  bool ok = true;
  ok &= Require(client.Connect().ok(), "service connect must succeed before delayed SYN-ACK tunnel stream tests");

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(opened.ok(), "delayed SYN-ACK tunnel stream app session must open");
  if (!opened.ok()) {
    return false;
  }

  const auto control_stream = swg::TunnelStreamSocket::Open(
      session, swg::MakeMoonlightStreamControlStreamRequest("203.0.113.44", kMoonlightRtspPort));
  ok &= Require(control_stream.ok(), "tunnel stream open must survive a delayed SYN-ACK with retransmission");

  ok &= Require(responder.Join(), responder.error().empty() ? "delayed SYN-ACK responder must validate the tunnel stream exchange"
                                                            : responder.error());
  ok &= Require(session.Close().ok(), "delayed SYN-ACK tunnel stream app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after delayed SYN-ACK tunnel stream tests");
  return ok;
}

bool TestTunnelStreamSocketUsesDeferredSynAck() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-tunnel-stream-deferred-synack";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  constexpr std::uint16_t kExpectedFirstTunnelStreamSourcePort = 30000;
  constexpr std::uint16_t kMoonlightHttpsPort = 47984;
  constexpr std::uint32_t kExpectedFirstTunnelStreamInitialSequence = 0x53570000u;
  constexpr std::uint32_t kRemoteInitialSequence = 0x40000000u;

  swg::TunnelDnsPacketEndpoint dns_endpoint{};
  dns_endpoint.source_ipv4 = {10, 0, 0, 2};
  dns_endpoint.destination_ipv4 = {1, 1, 1, 1};
  dns_endpoint.source_port = 40001;
  dns_endpoint.destination_port = 53;

  const auto expected_dns_query = swg::BuildTunnelDnsQueryPacket(dns_endpoint, "vpn.example.test", 1);
  const auto inbound_dns_response =
      swg::BuildTunnelDnsResponsePacket(dns_endpoint, "vpn.example.test", 1, {"203.0.113.44"});

  const auto local_address = swg::ParseIpAddress("10.0.0.2", "local_address");
  const auto remote_address = swg::ParseIpAddress("203.0.113.44", "remote_address");
  if (!Require(expected_dns_query.ok(), "expected tunnel DNS query packet must build for deferred SYN-ACK tests") ||
      !Require(inbound_dns_response.ok(), "expected tunnel DNS response packet must build for deferred SYN-ACK tests") ||
      !Require(local_address.ok(), "deferred SYN-ACK tunnel stream local IPv4 address must parse") ||
      !Require(remote_address.ok(), "deferred SYN-ACK tunnel stream remote IPv4 address must parse")) {
    return false;
  }

  swg::Ipv4TcpPacketEndpoint endpoint{};
  std::copy_n(local_address.value.bytes.begin(), 4, endpoint.source_ipv4.begin());
  std::copy_n(remote_address.value.bytes.begin(), 4, endpoint.destination_ipv4.begin());
  endpoint.source_port = kExpectedFirstTunnelStreamSourcePort;
  endpoint.destination_port = kMoonlightHttpsPort;

  swg::Ipv4TcpPacket syn{};
  syn.endpoint = endpoint;
  syn.sequence_number = kExpectedFirstTunnelStreamInitialSequence;
  syn.flags = swg::ToFlags(swg::TcpControlFlag::Syn);

  swg::Ipv4TcpPacket synack{};
  synack.endpoint.source_ipv4 = endpoint.destination_ipv4;
  synack.endpoint.destination_ipv4 = endpoint.source_ipv4;
  synack.endpoint.source_port = endpoint.destination_port;
  synack.endpoint.destination_port = endpoint.source_port;
  synack.sequence_number = kRemoteInitialSequence;
  synack.acknowledgment_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  synack.flags = swg::ToFlags(swg::TcpControlFlag::Syn) | swg::ToFlags(swg::TcpControlFlag::Ack);

  swg::Ipv4TcpPacket ack{};
  ack.endpoint = endpoint;
  ack.sequence_number = kExpectedFirstTunnelStreamInitialSequence + 1u;
  ack.acknowledgment_number = kRemoteInitialSequence + 1u;
  ack.flags = swg::ToFlags(swg::TcpControlFlag::Ack);

  const auto syn_packet = swg::BuildIpv4TcpPacket(syn);
  const auto synack_packet = swg::BuildIpv4TcpPacket(synack);
  const auto ack_packet = swg::BuildIpv4TcpPacket(ack);
  if (!Require(syn_packet.ok(), "deferred SYN-ACK tunnel stream SYN packet must build") ||
      !Require(synack_packet.ok(), "deferred SYN-ACK tunnel stream SYN-ACK packet must build") ||
      !Require(ack_packet.ok(), "deferred SYN-ACK tunnel stream ACK packet must build")) {
    return false;
  }

  LocalHandshakeResponder responder(
      0,
      0,
      std::vector<std::vector<std::uint8_t>>{synack_packet.value, inbound_dns_response.value},
      std::vector<std::vector<std::uint8_t>>{expected_dns_query.value, syn_packet.value, ack_packet.value});
  if (!Require(responder.ready(), "deferred SYN-ACK responder must start for tunnel stream tests")) {
    return false;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig("127.0.0.1", responder.port())).ok(),
               "valid config must save before deferred SYN-ACK tunnel stream tests")) {
    return false;
  }

  bool ok = true;
  ok &= Require(client.Connect().ok(), "service connect must succeed before deferred SYN-ACK tunnel stream tests");

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(opened.ok(), "deferred SYN-ACK tunnel stream app session must open");
  if (!opened.ok()) {
    return false;
  }

  const auto resolved = session.ResolveDns("vpn.example.test");
  ok &= Require(resolved.ok(), "tunnel DNS resolve must succeed before deferred SYN-ACK stream open");
  if (resolved.ok()) {
    ok &= Require(resolved.value.resolved,
                  "tunnel DNS resolve must produce an address while deferring the future stream SYN-ACK");
  }

  const auto control_stream = swg::TunnelStreamSocket::Open(
      session, swg::MakeMoonlightHttpsControlStreamRequest("203.0.113.44", kMoonlightHttpsPort));
  ok &= Require(control_stream.ok(), "tunnel stream open must consume a matching SYN-ACK already queued in deferred packets");

  ok &= Require(responder.Join(), responder.error().empty() ? "deferred SYN-ACK responder must validate the tunnel DNS plus stream exchange"
                                                            : responder.error());
  ok &= Require(session.Close().ok(), "deferred SYN-ACK tunnel stream app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after deferred SYN-ACK tunnel stream tests");
  return ok;
}

bool TestTunnelStreamSocketRecoversAfterIdleTimeout() {
  const std::filesystem::path runtime_root =
      std::filesystem::current_path() / "test-runtime-tunnel-stream-idle-recovery";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  auto engine = std::make_unique<RecoveringTunnelStreamEngine>();
  RecoveringTunnelStreamEngine* engine_ptr = engine.get();
  const auto service = swg::sysmodule::CreateLocalControlServiceForTest(std::move(engine), runtime_root);
  swg::Client client(swg::sysmodule::CreateHostInProcessTransport(service));

  bool ok = true;
  ok &= Require(client.SaveConfig(MakeValidConfig("127.0.0.1", 51820)).ok(),
                "valid config must save before tunnel stream idle-recovery test");
  ok &= Require(client.Connect().ok(), "service connect must succeed before tunnel stream idle-recovery test");

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  ok &= Require(opened.ok(), "tunnel stream idle-recovery app session must open");
  if (!opened.ok()) {
    return false;
  }

  const auto control_stream =
      session.OpenTunnelStream(swg::MakeMoonlightHttpsControlStreamRequest("203.0.113.44", 47984));
  ok &= Require(control_stream.ok(), "tunnel stream open must recover once after an idle timeout");
  if (control_stream.ok()) {
    ok &= Require(control_stream.value.local_port == 30000,
                  "idle-recovery tunnel stream must preserve the deterministic first local TCP source port");
    ok &= Require(control_stream.value.remote_address == "203.0.113.44",
                  "idle-recovery tunnel stream must report the resolved remote IPv4 address");
  }

  const auto stats = client.GetStats();
  ok &= Require(stats.ok(), "idle-recovery tunnel stream test must read stats after open");
  if (stats.ok()) {
    ok &= Require(stats.value.reconnects == 1,
                  "idle-recovery tunnel stream open must record one transport reconnect");
    ok &= Require(stats.value.successful_handshakes == 2,
                  "idle-recovery tunnel stream open must preserve the initial and recovered transport handshakes");
  }

  ok &= Require(engine_ptr->recovery_count() == 1,
                "scripted tunnel engine must observe one bounded recovery request");
  ok &= Require(engine_ptr->saw_blackholed_syn(),
                "scripted tunnel engine must observe the pre-recovery SYN being blackholed");
  ok &= Require(engine_ptr->saw_post_recovery_syn(),
                "scripted tunnel engine must observe the retried SYN after recovery");
  ok &= Require(engine_ptr->saw_post_recovery_ack(),
                "scripted tunnel engine must observe the post-recovery ACK completion");
  ok &= Require(engine_ptr->last_recovery_reason().find("timed out waiting for tunnel stream SYN-ACK") !=
                    std::string::npos,
                "scripted tunnel engine must receive the SYN-ACK timeout reason for recovery");

  ok &= Require(session.Close().ok(), "tunnel stream idle-recovery app session must close cleanly");
  ok &= Require(client.Disconnect().ok(), "service disconnect must succeed after idle-recovery test");
  return ok;
}

}  // namespace

int main() {
  const bool endpoint_parser_ok = TestEndpointAndNetworkParsing();
  const bool config_ok = TestConfigRoundTrip();
  const bool wg_crypto_ok = TestWireGuardCrypto();
  const bool wg_handshake_ok = TestWireGuardHandshakeRoundTrip();
  const bool wg_validation_ok = TestWireGuardProfileValidation();
  const bool tunnel_session_ok = TestTunnelSessionPreparation();
  const bool endpoint_resolution_ok = TestTunnelEndpointResolution();
  const bool engine_handshake_ok = TestTunnelEngineHandshake();
  const bool engine_payload_queue_ok = TestEngineInboundPayloadQueue();
  const bool state_ok = TestStateMachine();
  const bool client_ok = TestClientHostBinding();
  const bool connect_handshake_ok = TestConnectHandshakeStats();
  const bool periodic_keepalive_ok = TestPeriodicKeepaliveStats();
  const bool inbound_keepalive_ok = TestInboundKeepaliveStats();
  const bool inbound_payload_ok = TestInboundPayloadStats();
  const bool invalid_connect_ok = TestInvalidWireGuardConnectFails();
  const bool codec_ok = TestIpcCodecRoundTrip();
  const bool app_session_send_ok = TestAppSessionSendPacket();
  const bool app_session_recv_ok = TestAppSessionReceivePacket();
  const bool sustained_app_session_ok = TestAppSessionSustainedTraffic();
  const bool reconnect_ok = TestEngineReconnectAfterSendFailure();
  const bool receive_reconnect_ok = TestEngineReconnectAfterReceiveFailure();
  const bool keepalive_reconnect_ok = TestEngineReconnectAfterKeepaliveFailure();
  const bool moonlight_ok = TestMoonlightRoutePlanning();
  const bool tunnel_dns_codec_ok = TestTunnelDnsPacketCodec();
  const bool dns_resolution_ok = TestAppSessionDnsResolution();
  const bool session_socket_ok = TestSessionSocketAbstraction();
  const bool tunnel_datagram_ok = TestTunnelDatagramSocket();
  const bool tunnel_stream_ok = TestTunnelStreamSocket();
  const bool tunnel_stream_out_of_order_ok = TestTunnelStreamSocketOutOfOrder();
  const bool tunnel_stream_delayed_synack_ok = TestTunnelStreamSocketDelayedSynAck();
  const bool tunnel_stream_deferred_synack_ok = TestTunnelStreamSocketUsesDeferredSynAck();
  const bool tunnel_stream_idle_recovery_ok = TestTunnelStreamSocketRecoversAfterIdleTimeout();
  return (endpoint_parser_ok && config_ok && wg_crypto_ok && wg_handshake_ok && wg_validation_ok &&
      tunnel_session_ok && endpoint_resolution_ok && engine_handshake_ok && engine_payload_queue_ok &&
      state_ok && client_ok &&
          connect_handshake_ok && periodic_keepalive_ok && inbound_keepalive_ok && inbound_payload_ok &&
          invalid_connect_ok &&
          codec_ok && app_session_send_ok && app_session_recv_ok && sustained_app_session_ok && reconnect_ok &&
          receive_reconnect_ok && keepalive_reconnect_ok && moonlight_ok && tunnel_dns_codec_ok && dns_resolution_ok &&
          session_socket_ok && tunnel_datagram_ok && tunnel_stream_ok && tunnel_stream_out_of_order_ok &&
          tunnel_stream_delayed_synack_ok && tunnel_stream_deferred_synack_ok &&
          tunnel_stream_idle_recovery_ok)
             ? 0
             : 1;
}
