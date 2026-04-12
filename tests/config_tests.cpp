#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iostream>
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
#include "swg/moonlight.h"
#include "swg/state_machine.h"
#include "swg/wg_crypto.h"
#include "swg/wg_handshake.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/wg_engine.h"
#include "swg_sysmodule/host_transport.h"
#include "swg_sysmodule/local_service.h"

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

class LocalHandshakeResponder {
 public:
  explicit LocalHandshakeResponder(std::uint32_t expected_additional_keepalives = 0,
                                   std::uint32_t inbound_keepalives_to_send = 0)
      : expected_additional_keepalives_(expected_additional_keepalives),
        inbound_keepalives_to_send_(inbound_keepalives_to_send) {
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
           validated_additional_keepalives_ == expected_additional_keepalives_;
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
  std::string error_{};
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
  const bool state_ok = TestStateMachine();
  const bool client_ok = TestClientHostBinding();
  const bool connect_handshake_ok = TestConnectHandshakeStats();
  const bool periodic_keepalive_ok = TestPeriodicKeepaliveStats();
  const bool inbound_keepalive_ok = TestInboundKeepaliveStats();
  const bool invalid_connect_ok = TestInvalidWireGuardConnectFails();
  const bool codec_ok = TestIpcCodecRoundTrip();
  const bool moonlight_ok = TestMoonlightRoutePlanning();
  return (endpoint_parser_ok && config_ok && wg_crypto_ok && wg_handshake_ok && wg_validation_ok &&
          tunnel_session_ok && endpoint_resolution_ok && engine_handshake_ok && state_ok && client_ok &&
          connect_handshake_ok && periodic_keepalive_ok && inbound_keepalive_ok && invalid_connect_ok &&
          codec_ok && moonlight_ok)
             ? 0
             : 1;
}
