#include "swg_sysmodule/wg_engine.h"

#include <chrono>
#include "swg_sysmodule/socket_runtime.h"

#include <algorithm>
#include <array>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>

#include "swg/log.h"
#include "swg/wg_handshake.h"

namespace swg::sysmodule {
namespace {

constexpr std::uint32_t kHandshakeResponseTimeoutMs = 5000;
constexpr std::uint32_t kHandshakeRetryCount = 2;
constexpr std::size_t kMaxHandshakeDatagramSize = 256;
constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<std::uint8_t, 4> CopyIpv4Bytes(const ParsedIpAddress& address) {
  std::array<std::uint8_t, 4> bytes{};
  std::copy_n(address.bytes.begin(), bytes.size(), bytes.begin());
  return bytes;
}

PreparedIpv4Network PrepareIpv4Network(const ParsedIpNetwork& network) {
  PreparedIpv4Network prepared{};
  prepared.address = CopyIpv4Bytes(network.address);
  prepared.prefix_length = network.prefix_length;
  prepared.normalized = network.normalized;
  return prepared;
}

std::array<std::uint8_t, 4> CopyIpv4SockaddrBytes(const sockaddr_in& address) {
  std::array<std::uint8_t, 4> bytes{};
  std::copy_n(reinterpret_cast<const std::uint8_t*>(&address.sin_addr), bytes.size(), bytes.begin());
  return bytes;
}

std::string FormatIpv4(const std::array<std::uint8_t, 4>& ipv4) {
  return std::to_string(ipv4[0]) + '.' + std::to_string(ipv4[1]) + '.' + std::to_string(ipv4[2]) + '.' +
         std::to_string(ipv4[3]);
}

std::string EncodeBase64(const WireGuardKey& key) {
  std::string output;
  output.reserve(((key.bytes.size() + 2) / 3) * 4);

  for (std::size_t index = 0; index < key.bytes.size(); index += 3) {
    const std::uint32_t a = key.bytes[index];
    const std::uint32_t b = index + 1 < key.bytes.size() ? key.bytes[index + 1] : 0;
    const std::uint32_t c = index + 2 < key.bytes.size() ? key.bytes[index + 2] : 0;
    const std::uint32_t chunk = (a << 16) | (b << 8) | c;

    output.push_back(kBase64Alphabet[(chunk >> 18) & 0x3F]);
    output.push_back(kBase64Alphabet[(chunk >> 12) & 0x3F]);
    output.push_back(index + 1 < key.bytes.size() ? kBase64Alphabet[(chunk >> 6) & 0x3F] : '=');
    output.push_back(index + 2 < key.bytes.size() ? kBase64Alphabet[chunk & 0x3F] : '=');
  }

  return output;
}

std::string DescribeResolvedEndpoint(const PreparedTunnelEndpoint& endpoint) {
  if (endpoint.state != PreparedEndpointState::Ready) {
    return endpoint.host + ':' + std::to_string(endpoint.port);
  }

  return FormatIpv4(endpoint.ipv4) + ':' + std::to_string(endpoint.port);
}

std::string DescribeReplySource(const ReceivedUdpDatagram& datagram) {
  return FormatIpv4(datagram.source_ipv4) + ':' + std::to_string(datagram.source_port);
}

Error MakeResolveError(int rc, std::string_view host) {
  ErrorCode code = ErrorCode::ServiceUnavailable;
  if (rc == EAI_NONAME) {
    code = ErrorCode::NotFound;
  }

  std::string message = "endpoint host '" + std::string(host) + "' could not be resolved to IPv4";
  if (rc != 0) {
    message += ": ";
    message += gai_strerror(rc);
  }
  return MakeError(code, std::move(message));
}

class WgTunnelEngine final : public IWgTunnelEngine {
 public:
  Error Start(const TunnelEngineStartRequest& request) override {
    if (running_) {
      return MakeError(ErrorCode::InvalidState, "WireGuard engine is already running");
    }

    const Error runtime_error = socket_runtime_.Start();
    if (runtime_error) {
      return runtime_error;
    }

    const Result<PreparedTunnelSession> resolved_session = ResolvePreparedTunnelSessionEndpoint(request.session);
    if (!resolved_session.ok()) {
      socket_runtime_.Stop();
      return resolved_session.error;
    }

    const Result<int> socket_result = socket_runtime_.OpenUdpSocket();
    if (!socket_result.ok()) {
      socket_runtime_.Stop();
      return socket_result.error;
    }

    const WireGuardHandshakeConfig handshake_config = {
        resolved_session.value.private_key,
        resolved_session.value.local_public_key,
        resolved_session.value.public_key,
        resolved_session.value.preshared_key,
        resolved_session.value.has_preshared_key,
    };

    const std::string endpoint_description = DescribeResolvedEndpoint(resolved_session.value.endpoint);
    const std::string local_public_key_b64 = EncodeBase64(resolved_session.value.local_public_key);
    const std::string peer_public_key_b64 = EncodeBase64(resolved_session.value.public_key);
    LogInfo("wg_engine", "starting handshake for profile " + resolved_session.value.profile_name +
                              ": endpoint=" + endpoint_description +
                              ", local_public_key=" + local_public_key_b64 +
                              ", peer_public_key=" + peer_public_key_b64 +
                              ", preshared_key=" + (resolved_session.value.has_preshared_key ? "enabled" : "disabled"));

    std::size_t total_bytes_sent = 0;
    std::size_t total_packets_sent = 0;
    Error last_timeout_error = MakeError(ErrorCode::IoError, "WireGuard response did not arrive");
    Result<WireGuardValidatedHandshake> validated =
        Result<WireGuardValidatedHandshake>::Failure(MakeError(ErrorCode::IoError, "WireGuard response missing"));
    std::size_t final_bytes_received = 0;

    for (std::uint32_t attempt = 1; attempt <= kHandshakeRetryCount; ++attempt) {
      const Result<WireGuardHandshakeInitiation> initiation = CreateHandshakeInitiation(handshake_config);
      if (!initiation.ok()) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(initiation.error.code,
                         "WireGuard initiation build failed: " + initiation.error.message);
      }

      LogInfo("wg_engine", "sending WireGuard initiation attempt " + std::to_string(attempt) + "/" +
                                std::to_string(kHandshakeRetryCount) +
                                ": sender_index=" + std::to_string(initiation.value.state.sender_index) +
                                ", endpoint=" + endpoint_description);

      const Result<std::size_t> bytes_sent = socket_runtime_.SendTo(socket_result.value, resolved_session.value.endpoint,
                                                                    initiation.value.packet.data(), initiation.value.packet.size());
      if (!bytes_sent.ok()) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(bytes_sent.error.code,
                         "WireGuard initiation send failed: " + bytes_sent.error.message);
      }
      if (bytes_sent.value != initiation.value.packet.size()) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(ErrorCode::IoError,
                         "WireGuard initiation send returned a short datagram for endpoint " +
                             endpoint_description);
      }

      total_bytes_sent += bytes_sent.value;
      ++total_packets_sent;

      std::array<std::uint8_t, kMaxHandshakeDatagramSize> response_buffer{};
      const Result<ReceivedUdpDatagram> received =
          socket_runtime_.ReceiveFrom(socket_result.value, response_buffer.data(), response_buffer.size(),
                                      kHandshakeResponseTimeoutMs);
      if (!received.ok()) {
        last_timeout_error = MakeError(received.error.code,
                                       "waiting for WireGuard response failed for endpoint " + endpoint_description +
                                           ": " + received.error.message +
                                           "; verify the server has peer public key " + local_public_key_b64 +
                                           " configured and that the endpoint/port is correct");
        if (attempt < kHandshakeRetryCount) {
          LogWarning("wg_engine", "WireGuard initiation attempt " + std::to_string(attempt) + " timed out: " +
                                      received.error.message + "; retrying");
          continue;
        }
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return last_timeout_error;
      }

      if (received.value.size == 0) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(ErrorCode::IoError, "received an empty WireGuard UDP datagram from " + endpoint_description);
      }

      const std::string reply_source = DescribeReplySource(received.value);
      if (reply_source != endpoint_description) {
        LogInfo("wg_engine", "received WireGuard UDP reply from " + reply_source +
                                 " while probing configured endpoint " + endpoint_description);
      }

      final_bytes_received = received.value.size;
      const auto message_type = static_cast<WireGuardMessageType>(response_buffer[0]);
      if (message_type == WireGuardMessageType::CookieReply) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(ErrorCode::Unsupported,
                         "received a WireGuard cookie reply from " + reply_source +
                             "; cookie handling is not implemented yet");
      }
      if (message_type != WireGuardMessageType::HandshakeResponse) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(ErrorCode::ParseError,
                         "received an unexpected WireGuard message type during handshake from " + reply_source);
      }

      validated = ConsumeHandshakeResponse(handshake_config, initiation.value.state, response_buffer.data(),
                                           received.value.size);
      if (!validated.ok()) {
        socket_runtime_.CloseSocket(socket_result.value);
        socket_runtime_.Stop();
        return MakeError(validated.error.code,
                         "WireGuard handshake response validation failed from " + reply_source + ": " +
                             validated.error.message);
      }

      resolved_response_endpoint_ = resolved_session.value.endpoint;
      resolved_response_endpoint_.ipv4 = received.value.source_ipv4;
      resolved_response_endpoint_.port = received.value.source_port;

      break;
    }

    if (!validated.ok()) {
      socket_runtime_.CloseSocket(socket_result.value);
      socket_runtime_.Stop();
      return last_timeout_error;
    }

    const PreparedTunnelEndpoint authenticated_endpoint =
        resolved_response_endpoint_.state == PreparedEndpointState::Ready ? resolved_response_endpoint_
                                                                          : resolved_session.value.endpoint;
    const Result<WireGuardTransportKeepalive> keepalive =
        CreateTransportKeepalivePacket(validated.value.sending_key, validated.value.peer_sender_index,
                                       next_send_counter_);
    if (!keepalive.ok()) {
      socket_runtime_.CloseSocket(socket_result.value);
      socket_runtime_.Stop();
      return MakeError(keepalive.error.code,
                       "failed to build post-handshake keepalive packet: " + keepalive.error.message);
    }

    LogInfo("wg_engine", "sending post-handshake keepalive: receiver_index=" +
                              std::to_string(validated.value.peer_sender_index) +
                              ", counter=" + std::to_string(next_send_counter_) +
                              ", endpoint=" + DescribeResolvedEndpoint(authenticated_endpoint));

    const Result<std::size_t> keepalive_bytes_sent =
        socket_runtime_.SendTo(socket_result.value, authenticated_endpoint,
                               keepalive.value.packet.data(), keepalive.value.packet.size());
    if (!keepalive_bytes_sent.ok()) {
      socket_runtime_.CloseSocket(socket_result.value);
      socket_runtime_.Stop();
      return MakeError(keepalive_bytes_sent.error.code,
                       "failed to send post-handshake keepalive packet: " + keepalive_bytes_sent.error.message);
    }
    if (keepalive_bytes_sent.value != keepalive.value.packet.size()) {
      socket_runtime_.CloseSocket(socket_result.value);
      socket_runtime_.Stop();
      return MakeError(ErrorCode::IoError,
                       "post-handshake keepalive send returned a short datagram for endpoint " +
                           DescribeResolvedEndpoint(authenticated_endpoint));
    }

    total_bytes_sent += keepalive_bytes_sent.value;
    ++total_packets_sent;
    ++next_send_counter_;

    udp_socket_ = socket_result.value;
    active_profile_ = resolved_session.value.profile_name;
    prepared_session_ = resolved_session.value;
    if (resolved_response_endpoint_.state == PreparedEndpointState::Ready) {
      prepared_session_.endpoint = resolved_response_endpoint_;
    }
    local_sender_index_ = validated.value.local_sender_index;
    peer_sender_index_ = validated.value.peer_sender_index;
    sending_key_ = validated.value.sending_key;
    receiving_key_ = validated.value.receiving_key;
    stats_ = {};
    stats_.bytes_out = total_bytes_sent;
    stats_.bytes_in = final_bytes_received;
    stats_.packets_out = total_packets_sent;
    stats_.packets_in = 1;
    stats_.successful_handshakes = 1;
    last_handshake_at_ = std::chrono::steady_clock::now();
    running_ = true;
    LogInfo("wg_engine", "validated WireGuard handshake for profile " + active_profile_ +
                              ": local_index=" + std::to_string(local_sender_index_) +
                              ", peer_index=" + std::to_string(peer_sender_index_) +
                              ", endpoint=" + DescribeResolvedEndpoint(prepared_session_.endpoint));
    return Error::None();
  }

  Error Stop() override {
    if (!running_) {
      return Error::None();
    }

    socket_runtime_.CloseSocket(udp_socket_);
    socket_runtime_.Stop();
    udp_socket_ = -1;
    running_ = false;
    active_profile_.clear();
    prepared_session_ = {};
    resolved_response_endpoint_ = {};
    stats_ = {};
    local_sender_index_ = 0;
    peer_sender_index_ = 0;
    sending_key_ = {};
    receiving_key_ = {};
    next_send_counter_ = 0;
    last_handshake_at_ = {};
    return Error::None();
  }

  TunnelStats GetStats() const override {
    TunnelStats stats = stats_;
    if (running_ && stats.successful_handshakes != 0) {
      stats.last_handshake_age_seconds = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - last_handshake_at_)
              .count());
    }
    return stats;
  }

  bool IsRunning() const override {
    return running_;
  }

 private:
  BsdSocketRuntime socket_runtime_{};
  std::string active_profile_;
  PreparedTunnelSession prepared_session_{};
  PreparedTunnelEndpoint resolved_response_endpoint_{};
  TunnelStats stats_{};
  int udp_socket_ = -1;
  std::uint32_t local_sender_index_ = 0;
  std::uint32_t peer_sender_index_ = 0;
  WireGuardKey sending_key_{};
  WireGuardKey receiving_key_{};
  std::uint64_t next_send_counter_ = 0;
  std::chrono::steady_clock::time_point last_handshake_at_{};
  bool running_ = false;
};

}  // namespace

Result<PreparedTunnelSession> PrepareTunnelSession(std::string_view profile_name,
                                                   const ValidatedWireGuardProfile& profile,
                                                   RuntimeFlags runtime_flags) {
  PreparedTunnelSession session{};
  session.profile_name = std::string(profile_name);
  session.runtime_flags = runtime_flags;
  session.persistent_keepalive = profile.persistent_keepalive;
  session.has_preshared_key = profile.has_preshared_key;
  session.private_key = profile.private_key;
  session.local_public_key = profile.local_public_key;
  session.public_key = profile.public_key;
  session.static_shared_secret = profile.static_shared_secret;
  session.preshared_key = profile.preshared_key;
  session.endpoint.host = profile.endpoint.host;
  session.endpoint.port = profile.endpoint.port;

  switch (profile.endpoint.type) {
    case ParsedEndpointHostType::Hostname:
      session.endpoint.state = PreparedEndpointState::NeedsIpv4Resolution;
      break;
    case ParsedEndpointHostType::IPv4: {
      const Result<ParsedIpAddress> endpoint_address = ParseIpAddress(profile.endpoint.host, "endpoint_host");
      if (!endpoint_address.ok()) {
        return MakeFailure<PreparedTunnelSession>(endpoint_address.error.code,
                                                  "profile '" + session.profile_name +
                                                      "': endpoint_host could not be reparsed as IPv4");
      }

      session.endpoint.state = PreparedEndpointState::Ready;
      session.endpoint.ipv4 = CopyIpv4Bytes(endpoint_address.value);
      break;
    }
    case ParsedEndpointHostType::IPv6:
      return MakeFailure<PreparedTunnelSession>(ErrorCode::InvalidConfig,
                                                "profile '" + session.profile_name +
                                                    "': current Switch transport does not support IPv6 endpoints");
  }

  for (const ParsedIpNetwork& network : profile.allowed_ips) {
    if (network.address.family == ParsedIpFamily::IPv4) {
      session.allowed_ipv4_routes.push_back(PrepareIpv4Network(network));
    } else {
      ++session.ignored_ipv6_allowed_ips;
    }
  }
  if (session.allowed_ipv4_routes.empty()) {
    return MakeFailure<PreparedTunnelSession>(ErrorCode::InvalidConfig,
                                              "profile '" + session.profile_name +
                                                  "': current Switch transport requires at least one IPv4 allowed_ips entry");
  }

  for (const ParsedIpNetwork& network : profile.addresses) {
    if (network.address.family == ParsedIpFamily::IPv4) {
      session.interface_ipv4_addresses.push_back(PrepareIpv4Network(network));
    } else {
      ++session.ignored_ipv6_addresses;
    }
  }
  if (session.interface_ipv4_addresses.empty()) {
    return MakeFailure<PreparedTunnelSession>(ErrorCode::InvalidConfig,
                                              "profile '" + session.profile_name +
                                                  "': current Switch transport requires at least one IPv4 interface address");
  }

  for (const ParsedIpAddress& dns_server : profile.dns_servers) {
    if (dns_server.family == ParsedIpFamily::IPv4) {
      session.dns_servers.push_back(CopyIpv4Bytes(dns_server));
    } else {
      ++session.ignored_ipv6_dns_servers;
    }
  }

  return MakeSuccess(std::move(session));
}

Result<PreparedTunnelEndpoint> ResolvePreparedTunnelEndpoint(const PreparedTunnelEndpoint& endpoint) {
  if (endpoint.port == 0) {
    return MakeFailure<PreparedTunnelEndpoint>(ErrorCode::InvalidConfig,
                                               "prepared endpoint must not use port 0");
  }

  if (endpoint.state == PreparedEndpointState::Ready) {
    return MakeSuccess(endpoint);
  }

  if (endpoint.host.empty()) {
    return MakeFailure<PreparedTunnelEndpoint>(ErrorCode::InvalidConfig,
                                               "prepared endpoint hostname must not be empty");
  }

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  addrinfo* results = nullptr;
  const int rc = getaddrinfo(endpoint.host.c_str(), nullptr, &hints, &results);
  if (rc != 0 || results == nullptr) {
    if (results != nullptr) {
      freeaddrinfo(results);
    }
    const Error error = MakeResolveError(rc, endpoint.host);
    return Result<PreparedTunnelEndpoint>::Failure(error);
  }

  for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
    if (current->ai_family != AF_INET || current->ai_addr == nullptr ||
        current->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      continue;
    }

    PreparedTunnelEndpoint resolved = endpoint;
    resolved.state = PreparedEndpointState::Ready;
    resolved.ipv4 = CopyIpv4SockaddrBytes(*reinterpret_cast<const sockaddr_in*>(current->ai_addr));
    freeaddrinfo(results);
    return MakeSuccess(std::move(resolved));
  }

  freeaddrinfo(results);
  return MakeFailure<PreparedTunnelEndpoint>(ErrorCode::NotFound,
                                             "endpoint host '" + endpoint.host +
                                                 "' did not return an IPv4 address");
}

Result<PreparedTunnelSession> ResolvePreparedTunnelSessionEndpoint(const PreparedTunnelSession& session) {
  const Result<PreparedTunnelEndpoint> resolved_endpoint = ResolvePreparedTunnelEndpoint(session.endpoint);
  if (!resolved_endpoint.ok()) {
    return MakeFailure<PreparedTunnelSession>(resolved_endpoint.error.code, resolved_endpoint.error.message);
  }

  PreparedTunnelSession resolved = session;
  resolved.endpoint = resolved_endpoint.value;
  return MakeSuccess(std::move(resolved));
}

std::string DescribePreparedTunnelSession(const PreparedTunnelSession& session) {
  std::ostringstream stream;
  stream << "profile=" << session.profile_name << ", endpoint=" << session.endpoint.host << ':' << session.endpoint.port
         << ", endpoint_state="
         << (session.endpoint.state == PreparedEndpointState::Ready ? "ready" : "needs_ipv4_resolution")
         << ", ipv4_allowed=" << session.allowed_ipv4_routes.size()
         << ", ipv4_addresses=" << session.interface_ipv4_addresses.size() << ", dns=" << session.dns_servers.size();

  if (session.ignored_ipv6_allowed_ips != 0 || session.ignored_ipv6_addresses != 0 ||
      session.ignored_ipv6_dns_servers != 0) {
    stream << ", ignored_ipv6={allowed:" << session.ignored_ipv6_allowed_ips
           << ", address:" << session.ignored_ipv6_addresses << ", dns:" << session.ignored_ipv6_dns_servers
           << '}';
  }

  return stream.str();
}

std::unique_ptr<IWgTunnelEngine> CreateWgTunnelEngine() {
  return std::make_unique<WgTunnelEngine>();
}

}  // namespace swg::sysmodule