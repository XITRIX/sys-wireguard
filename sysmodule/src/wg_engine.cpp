#include "swg_sysmodule/wg_engine.h"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

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
constexpr std::uint32_t kReconnectRetryCount = 3;
constexpr std::uint32_t kReconnectInitialBackoffMs = 100;
constexpr std::uint32_t kReconnectMaxBackoffMs = 1000;
constexpr std::uint32_t kTransportReceiveTimeoutMs = 250;
constexpr std::size_t kMaxQueuedTransportPackets = 8;
constexpr std::size_t kMaxQueuedTransportPayloadBytes = 8 * 1024;
constexpr std::size_t kMaxHandshakeDatagramSize = 256;
constexpr std::size_t kMaxTransportDatagramSize = 2048;
constexpr std::size_t kWireGuardTransportAeadOverhead = 16;
constexpr std::size_t kMaxOutboundTransportPayloadBytes =
  kMaxTransportDatagramSize - kWireGuardTransportHeaderSize - kWireGuardTransportAeadOverhead;
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

bool IsReceiveTimeout(const Error& error) {
  return error.code == ErrorCode::IoError && error.message.find("timed out") != std::string::npos;
}

bool MatchesEndpoint(const PreparedTunnelEndpoint& endpoint, const ReceivedUdpDatagram& datagram) {
  return endpoint.state == PreparedEndpointState::Ready && endpoint.ipv4 == datagram.source_ipv4 &&
         endpoint.port == datagram.source_port;
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

struct ReservedTransportSend {
  PreparedTunnelEndpoint endpoint{};
  WireGuardKey sending_key{};
  std::uint32_t peer_sender_index = 0;
  std::uint64_t counter = 0;
  int socket_fd = -1;
};

struct EstablishedTransportSession {
  PreparedTunnelSession session;
  int udp_socket = -1;
  std::uint32_t local_sender_index = 0;
  std::uint32_t peer_sender_index = 0;
  WireGuardKey sending_key{};
  WireGuardKey receiving_key{};
  TunnelStats stats{};
};

enum class ReconnectTrigger : std::uint32_t {
  External = 0,
  ReceiveLoop,
  KeepaliveLoop,
};

class WgTunnelEngine final : public IWgTunnelEngine {
 public:
  explicit WgTunnelEngine(std::unique_ptr<IUdpSocketRuntime> socket_runtime)
      : socket_runtime_(std::move(socket_runtime)) {}

  ~WgTunnelEngine() override {
    if (running_ || keepalive_thread_.joinable() || receive_thread_.joinable() || socket_runtime_->IsStarted()) {
      Stop();
    }
  }

  Error Start(const TunnelEngineStartRequest& request) override {
    if (running_) {
      return MakeError(ErrorCode::InvalidState, "WireGuard engine is already running");
    }

    const Error runtime_error = socket_runtime_->Start();
    if (runtime_error) {
      return runtime_error;
    }

    const Result<EstablishedTransportSession> established = EstablishTransportSession(request.session);
    if (!established.ok()) {
      socket_runtime_->Stop();
      return established.error;
    }

    {
      std::scoped_lock lock(engine_mutex_);
      udp_socket_ = established.value.udp_socket;
      active_profile_ = established.value.session.profile_name;
      prepared_session_ = established.value.session;
      resolved_response_endpoint_ = established.value.session.endpoint;
      local_sender_index_ = established.value.local_sender_index;
      peer_sender_index_ = established.value.peer_sender_index;
      sending_key_ = established.value.sending_key;
      receiving_key_ = established.value.receiving_key;
      stats_ = established.value.stats;
      next_send_counter_ = 1;
      next_receive_counter_ = 0;
      last_handshake_at_ = std::chrono::steady_clock::now();
      running_ = true;
      stop_requested_ = false;
      last_error_.clear();
    }

    receive_thread_ = std::thread([this]() {
      ReceiveLoop();
    });
    if (prepared_session_.persistent_keepalive != 0) {
      keepalive_thread_ = std::thread([this]() {
        KeepaliveLoop();
      });
    }
    LogInfo("wg_engine", "validated WireGuard handshake for profile " + active_profile_ +
                              ": local_index=" + std::to_string(local_sender_index_) +
                              ", peer_index=" + std::to_string(peer_sender_index_) +
                              ", endpoint=" + DescribeResolvedEndpoint(prepared_session_.endpoint));
    return Error::None();
  }

  Error Stop() override {
    std::scoped_lock reconnect_lock(reconnect_mutex_);

    {
      std::scoped_lock lock(engine_mutex_);
      if (!running_ && !keepalive_thread_.joinable() && !receive_thread_.joinable() && !socket_runtime_->IsStarted() &&
          udp_socket_ < 0) {
        return Error::None();
      }

      stop_requested_ = true;
      running_ = false;
    }

    keepalive_cv_.notify_all();
    if (receive_thread_.joinable()) {
      receive_thread_.join();
    }
    if (keepalive_thread_.joinable()) {
      keepalive_thread_.join();
    }

    {
      std::scoped_lock send_lock(transport_send_mutex_);
      socket_runtime_->CloseSocket(udp_socket_);
    }
    socket_runtime_->Stop();

    {
      std::scoped_lock lock(engine_mutex_);
      udp_socket_ = -1;
      active_profile_.clear();
      prepared_session_ = {};
      resolved_response_endpoint_ = {};
      stats_ = {};
      local_sender_index_ = 0;
      peer_sender_index_ = 0;
      sending_key_ = {};
      receiving_key_ = {};
      next_send_counter_ = 0;
      next_receive_counter_ = 0;
      queued_transport_packets_.clear();
      queued_transport_payload_bytes_ = 0;
      receive_queue_overflow_logged_ = false;
      stop_requested_ = false;
      last_handshake_at_ = {};
      last_error_.clear();
    }

    return Error::None();
  }

  Result<std::uint64_t> SendPacket(const std::vector<std::uint8_t>& payload) override {
    if (payload.empty()) {
      return MakeFailure<std::uint64_t>(ErrorCode::ParseError, "authenticated transport payload must not be empty");
    }
    if (payload.size() > kMaxOutboundTransportPayloadBytes) {
      return MakeFailure<std::uint64_t>(
          ErrorCode::Unsupported,
          "authenticated transport payload exceeds the current bounded send limit of " +
              std::to_string(kMaxOutboundTransportPayloadBytes) + " bytes");
    }

    const Result<ReservedTransportSend> reserved = ReserveTransportSend();
    if (!reserved.ok()) {
      return MakeFailure<std::uint64_t>(reserved.error.code, reserved.error.message);
    }

    const Result<WireGuardTransportPacket> packet =
        CreateTransportPacket(reserved.value.sending_key, reserved.value.peer_sender_index, payload, reserved.value.counter);
    if (!packet.ok()) {
      return MakeFailure<std::uint64_t>(packet.error.code, packet.error.message);
    }
    if (packet.value.packet.size() > kMaxTransportDatagramSize) {
      return MakeFailure<std::uint64_t>(ErrorCode::Unsupported,
                                        "authenticated transport datagram exceeds the current bounded send limit");
    }

    const Result<std::size_t> bytes_sent = SendReservedTransportDatagram(reserved.value, packet.value.packet.data(),
                                                                         packet.value.packet.size());
    if (!bytes_sent.ok()) {
      if (bytes_sent.error.code != ErrorCode::IoError) {
        return MakeFailure<std::uint64_t>(bytes_sent.error.code, bytes_sent.error.message);
      }

      const Error reconnect_error = ReconnectWithBackoff("authenticated transport send failed: " +
                                                         bytes_sent.error.message,
                                                         ReconnectTrigger::External);
      if (reconnect_error) {
        return MakeFailure<std::uint64_t>(reconnect_error.code, reconnect_error.message);
      }

      const Result<ReservedTransportSend> retry_reserved = ReserveTransportSend();
      if (!retry_reserved.ok()) {
        return MakeFailure<std::uint64_t>(retry_reserved.error.code, retry_reserved.error.message);
      }

      const Result<WireGuardTransportPacket> retry_packet = CreateTransportPacket(
          retry_reserved.value.sending_key, retry_reserved.value.peer_sender_index, payload, retry_reserved.value.counter);
      if (!retry_packet.ok()) {
        return MakeFailure<std::uint64_t>(retry_packet.error.code, retry_packet.error.message);
      }
      if (retry_packet.value.packet.size() > kMaxTransportDatagramSize) {
        return MakeFailure<std::uint64_t>(ErrorCode::Unsupported,
                                          "authenticated transport datagram exceeds the current bounded send limit");
      }

      const Result<std::size_t> retry_bytes_sent = SendReservedTransportDatagram(
          retry_reserved.value, retry_packet.value.packet.data(), retry_packet.value.packet.size());
      if (!retry_bytes_sent.ok()) {
        return MakeFailure<std::uint64_t>(retry_bytes_sent.error.code, retry_bytes_sent.error.message);
      }

      RecordSuccessfulOutboundDatagram(retry_bytes_sent.value);
      return MakeSuccess(retry_reserved.value.counter);
    }

    RecordSuccessfulOutboundDatagram(bytes_sent.value);
    return MakeSuccess(reserved.value.counter);
  }

  Result<WireGuardConsumedTransportPacket> ReceivePacket() override {
    std::scoped_lock lock(engine_mutex_);
    if (queued_transport_packets_.empty()) {
      return MakeFailure<WireGuardConsumedTransportPacket>(ErrorCode::NotFound,
                                                           "no authenticated transport packets are queued");
    }

    WireGuardConsumedTransportPacket packet = std::move(queued_transport_packets_.front());
    queued_transport_packets_.pop_front();
    queued_transport_payload_bytes_ -= packet.payload.size();
    if (queued_transport_packets_.empty()) {
      receive_queue_overflow_logged_ = false;
    }
    return MakeSuccess(std::move(packet));
  }

  TunnelStats GetStats() const override {
    std::scoped_lock lock(engine_mutex_);
    TunnelStats stats = stats_;
    if (stats.successful_handshakes != 0 && last_handshake_at_ != std::chrono::steady_clock::time_point{}) {
      stats.last_handshake_age_seconds = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - last_handshake_at_)
              .count());
    }
    return stats;
  }

  std::string GetLastError() const override {
    std::scoped_lock lock(engine_mutex_);
    return last_error_;
  }

  bool IsRunning() const override {
    std::scoped_lock lock(engine_mutex_);
    return running_;
  }

 private:
  Result<EstablishedTransportSession> EstablishTransportSession(const PreparedTunnelSession& requested_session) {
    const Result<PreparedTunnelSession> resolved_session = ResolvePreparedTunnelSessionEndpoint(requested_session);
    if (!resolved_session.ok()) {
      return MakeFailure<EstablishedTransportSession>(resolved_session.error.code, resolved_session.error.message);
    }

    const Result<int> socket_result = socket_runtime_->OpenUdpSocket();
    if (!socket_result.ok()) {
      return MakeFailure<EstablishedTransportSession>(socket_result.error.code, socket_result.error.message);
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
    PreparedTunnelEndpoint authenticated_endpoint = resolved_session.value.endpoint;

    for (std::uint32_t attempt = 1; attempt <= kHandshakeRetryCount; ++attempt) {
      const Result<WireGuardHandshakeInitiation> initiation = CreateHandshakeInitiation(handshake_config);
      if (!initiation.ok()) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(initiation.error.code,
                                                        "WireGuard initiation build failed: " + initiation.error.message);
      }

      LogInfo("wg_engine", "sending WireGuard initiation attempt " + std::to_string(attempt) + "/" +
                                std::to_string(kHandshakeRetryCount) +
                                ": sender_index=" + std::to_string(initiation.value.state.sender_index) +
                                ", endpoint=" + endpoint_description);

      const Result<std::size_t> bytes_sent = socket_runtime_->SendTo(socket_result.value, resolved_session.value.endpoint,
                                                                     initiation.value.packet.data(), initiation.value.packet.size());
      if (!bytes_sent.ok()) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(bytes_sent.error.code,
                                                        "WireGuard initiation send failed: " + bytes_sent.error.message);
      }
      if (bytes_sent.value != initiation.value.packet.size()) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(ErrorCode::IoError,
                                                        "WireGuard initiation send returned a short datagram for endpoint " +
                                                            endpoint_description);
      }

      total_bytes_sent += bytes_sent.value;
      ++total_packets_sent;

      std::array<std::uint8_t, kMaxHandshakeDatagramSize> response_buffer{};
      const Result<ReceivedUdpDatagram> received =
          socket_runtime_->ReceiveFrom(socket_result.value, response_buffer.data(), response_buffer.size(),
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
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(last_timeout_error.code, last_timeout_error.message);
      }

      if (received.value.size == 0) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(ErrorCode::IoError,
                                                        "received an empty WireGuard UDP datagram from " + endpoint_description);
      }

      const std::string reply_source = DescribeReplySource(received.value);
      if (reply_source != endpoint_description) {
        LogInfo("wg_engine", "received WireGuard UDP reply from " + reply_source +
                                 " while probing configured endpoint " + endpoint_description);
      }

      final_bytes_received = received.value.size;
      const auto message_type = static_cast<WireGuardMessageType>(response_buffer[0]);
      if (message_type == WireGuardMessageType::CookieReply) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(ErrorCode::Unsupported,
                                                        "received a WireGuard cookie reply from " + reply_source +
                                                            "; cookie handling is not implemented yet");
      }
      if (message_type != WireGuardMessageType::HandshakeResponse) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(ErrorCode::ParseError,
                                                        "received an unexpected WireGuard message type during handshake from " +
                                                            reply_source);
      }

      validated = ConsumeHandshakeResponse(handshake_config, initiation.value.state, response_buffer.data(),
                                           received.value.size);
      if (!validated.ok()) {
        socket_runtime_->CloseSocket(socket_result.value);
        return MakeFailure<EstablishedTransportSession>(validated.error.code,
                                                        "WireGuard handshake response validation failed from " +
                                                            reply_source + ": " + validated.error.message);
      }

      authenticated_endpoint = resolved_session.value.endpoint;
      authenticated_endpoint.ipv4 = received.value.source_ipv4;
      authenticated_endpoint.port = received.value.source_port;
      break;
    }

    if (!validated.ok()) {
      socket_runtime_->CloseSocket(socket_result.value);
      return MakeFailure<EstablishedTransportSession>(last_timeout_error.code, last_timeout_error.message);
    }

    const Result<WireGuardTransportKeepalive> keepalive =
        CreateTransportKeepalivePacket(validated.value.sending_key, validated.value.peer_sender_index, 0);
    if (!keepalive.ok()) {
      socket_runtime_->CloseSocket(socket_result.value);
      return MakeFailure<EstablishedTransportSession>(keepalive.error.code,
                                                      "failed to build post-handshake keepalive packet: " + keepalive.error.message);
    }

    LogInfo("wg_engine", "sending post-handshake keepalive: receiver_index=" +
                              std::to_string(validated.value.peer_sender_index) +
                              ", counter=0, endpoint=" + DescribeResolvedEndpoint(authenticated_endpoint));

    const Result<std::size_t> keepalive_bytes_sent =
        socket_runtime_->SendTo(socket_result.value, authenticated_endpoint,
                                keepalive.value.packet.data(), keepalive.value.packet.size());
    if (!keepalive_bytes_sent.ok()) {
      socket_runtime_->CloseSocket(socket_result.value);
      return MakeFailure<EstablishedTransportSession>(keepalive_bytes_sent.error.code,
                                                      "failed to send post-handshake keepalive packet: " +
                                                          keepalive_bytes_sent.error.message);
    }
    if (keepalive_bytes_sent.value != keepalive.value.packet.size()) {
      socket_runtime_->CloseSocket(socket_result.value);
      return MakeFailure<EstablishedTransportSession>(ErrorCode::IoError,
                                                      "post-handshake keepalive send returned a short datagram for endpoint " +
                                                          DescribeResolvedEndpoint(authenticated_endpoint));
    }

    total_bytes_sent += keepalive_bytes_sent.value;
    ++total_packets_sent;

    EstablishedTransportSession established{};
    established.session = resolved_session.value;
    established.session.endpoint = authenticated_endpoint;
    established.udp_socket = socket_result.value;
    established.local_sender_index = validated.value.local_sender_index;
    established.peer_sender_index = validated.value.peer_sender_index;
    established.sending_key = validated.value.sending_key;
    established.receiving_key = validated.value.receiving_key;
    established.stats.bytes_out = total_bytes_sent;
    established.stats.bytes_in = final_bytes_received;
    established.stats.packets_out = total_packets_sent;
    established.stats.packets_in = 1;
    established.stats.successful_handshakes = 1;
    return MakeSuccess(std::move(established));
  }

  Result<ReservedTransportSend> ReserveTransportSend() {
    std::scoped_lock lock(engine_mutex_);
    if (!running_ || stop_requested_ || udp_socket_ < 0) {
      const std::string message = last_error_.empty() ? "WireGuard transport is not running" : last_error_;
      return MakeFailure<ReservedTransportSend>(ErrorCode::InvalidState, message);
    }

    ReservedTransportSend reserved{};
    reserved.endpoint = prepared_session_.endpoint;
    reserved.sending_key = sending_key_;
    reserved.peer_sender_index = peer_sender_index_;
    reserved.counter = next_send_counter_++;
    reserved.socket_fd = udp_socket_;
    return MakeSuccess(std::move(reserved));
  }

  Result<std::size_t> SendReservedTransportDatagram(const ReservedTransportSend& reserved,
                                                    const std::uint8_t* data,
                                                    std::size_t size) {
    std::scoped_lock send_lock(transport_send_mutex_);
    const Result<std::size_t> bytes_sent =
        socket_runtime_->SendTo(reserved.socket_fd, reserved.endpoint, data, size);
    if (!bytes_sent.ok()) {
      return MakeFailure<std::size_t>(bytes_sent.error.code, bytes_sent.error.message);
    }
    if (bytes_sent.value != size) {
      return MakeFailure<std::size_t>(ErrorCode::IoError,
                                      "authenticated transport send returned a short datagram for endpoint " +
                                          DescribeResolvedEndpoint(reserved.endpoint));
    }

    return bytes_sent;
  }

  void RecordSuccessfulOutboundDatagram(std::size_t bytes_sent) {
    std::scoped_lock lock(engine_mutex_);
    stats_.bytes_out += bytes_sent;
    ++stats_.packets_out;
  }

  bool IsCurrentThread(const std::thread& thread) const {
    return thread.joinable() && thread.get_id() == std::this_thread::get_id();
  }

  void PrepareReconnectCallerThread(ReconnectTrigger trigger) {
    switch (trigger) {
      case ReconnectTrigger::ReceiveLoop:
        if (IsCurrentThread(receive_thread_)) {
          receive_thread_.detach();
        }
        break;
      case ReconnectTrigger::KeepaliveLoop:
        if (IsCurrentThread(keepalive_thread_)) {
          keepalive_thread_.detach();
        }
        break;
      case ReconnectTrigger::External:
        break;
    }
  }

  void JoinReconnectPeerThreads(ReconnectTrigger trigger) {
    if (trigger != ReconnectTrigger::ReceiveLoop && receive_thread_.joinable()) {
      receive_thread_.join();
    }
    if (trigger != ReconnectTrigger::KeepaliveLoop && keepalive_thread_.joinable()) {
      keepalive_thread_.join();
    }
  }

  Error ReconnectWithBackoff(const std::string& reason, ReconnectTrigger trigger) {
    std::scoped_lock reconnect_lock(reconnect_mutex_);

    PreparedTunnelSession session{};
    {
      std::scoped_lock lock(engine_mutex_);
      if (!running_) {
        return MakeError(ErrorCode::InvalidState,
                         last_error_.empty() ? "WireGuard transport is not running" : last_error_);
      }

      session = prepared_session_;
      running_ = false;
      last_error_ = reason;
    }

    keepalive_cv_.notify_all();
    PrepareReconnectCallerThread(trigger);
    JoinReconnectPeerThreads(trigger);

    {
      std::scoped_lock send_lock(transport_send_mutex_);
      socket_runtime_->CloseSocket(udp_socket_);
    }
    {
      std::scoped_lock lock(engine_mutex_);
      udp_socket_ = -1;
    }

    Error last_error = MakeError(ErrorCode::IoError, reason);
    std::uint32_t backoff_ms = kReconnectInitialBackoffMs;
    for (std::uint32_t attempt = 1; attempt <= kReconnectRetryCount; ++attempt) {
      if (attempt > 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
        backoff_ms = std::min(backoff_ms * 2, kReconnectMaxBackoffMs);
      }

      if (!socket_runtime_->IsStarted()) {
        const Error runtime_error = socket_runtime_->Start();
        if (runtime_error) {
          last_error = runtime_error;
          continue;
        }
      }

      const Result<EstablishedTransportSession> established = EstablishTransportSession(session);
      if (!established.ok()) {
        last_error = established.error;
        LogWarning("wg_engine", "bounded reconnect attempt " + std::to_string(attempt) + "/" +
                                    std::to_string(kReconnectRetryCount) + " failed: " + established.error.message);
        continue;
      }

      {
        std::scoped_lock lock(engine_mutex_);
        udp_socket_ = established.value.udp_socket;
        active_profile_ = established.value.session.profile_name;
        prepared_session_ = established.value.session;
        resolved_response_endpoint_ = established.value.session.endpoint;
        local_sender_index_ = established.value.local_sender_index;
        peer_sender_index_ = established.value.peer_sender_index;
        sending_key_ = established.value.sending_key;
        receiving_key_ = established.value.receiving_key;
        stats_.bytes_in += established.value.stats.bytes_in;
        stats_.bytes_out += established.value.stats.bytes_out;
        stats_.packets_in += established.value.stats.packets_in;
        stats_.packets_out += established.value.stats.packets_out;
        stats_.successful_handshakes += established.value.stats.successful_handshakes;
        ++stats_.reconnects;
        next_send_counter_ = 1;
        next_receive_counter_ = 0;
        queued_transport_packets_.clear();
        queued_transport_payload_bytes_ = 0;
        receive_queue_overflow_logged_ = false;
        last_handshake_at_ = std::chrono::steady_clock::now();
        running_ = true;
        last_error_.clear();
      }

      receive_thread_ = std::thread([this]() {
        ReceiveLoop();
      });
      if (prepared_session_.persistent_keepalive != 0) {
        keepalive_thread_ = std::thread([this]() {
          KeepaliveLoop();
        });
      }

      LogInfo("wg_engine", "bounded reconnect succeeded after transport failure: attempt " +
                                std::to_string(attempt) + "/" + std::to_string(kReconnectRetryCount));
      return Error::None();
    }

    {
      std::scoped_lock lock(engine_mutex_);
      last_error_ = "bounded reconnect failed: " + last_error.message;
    }
    return MakeError(last_error.code, "bounded reconnect failed: " + last_error.message);
  }

  void HandleWorkerTransportFailure(std::string_view reason, ReconnectTrigger trigger) {
    const Error reconnect_error = ReconnectWithBackoff(std::string(reason), trigger);
    if (reconnect_error) {
      LogWarning("wg_engine", reconnect_error.message);
      return;
    }

    LogInfo("wg_engine", "worker-triggered bounded reconnect completed: " + std::string(reason));
  }

  void ReceiveLoop() {
    std::array<std::uint8_t, kMaxTransportDatagramSize> buffer{};

    while (true) {
      PreparedTunnelEndpoint endpoint{};
      WireGuardKey receiving_key{};
      std::uint32_t local_sender_index = 0;
      int socket_fd = -1;

      {
        std::scoped_lock lock(engine_mutex_);
        if (stop_requested_ || !running_) {
          return;
        }

        endpoint = prepared_session_.endpoint;
        receiving_key = receiving_key_;
        local_sender_index = local_sender_index_;
        socket_fd = udp_socket_;
      }

      const Result<ReceivedUdpDatagram> received =
          socket_runtime_->ReceiveFrom(socket_fd, buffer.data(), buffer.size(), kTransportReceiveTimeoutMs);
      if (!received.ok()) {
        if (IsReceiveTimeout(received.error)) {
          continue;
        }

        std::scoped_lock lock(engine_mutex_);
        if (stop_requested_ || !running_) {
          return;
        }
      }

      if (!received.ok()) {
        HandleWorkerTransportFailure("post-handshake transport receive failed: " + received.error.message,
                                     ReconnectTrigger::ReceiveLoop);
        return;
      }

      if (!MatchesEndpoint(endpoint, received.value)) {
        LogWarning("wg_engine", "ignoring authenticated transport candidate from unexpected endpoint " +
                                    DescribeReplySource(received.value) + "; expected " +
                                    DescribeResolvedEndpoint(endpoint));
        continue;
      }

      if (received.value.size == 0) {
        LogWarning("wg_engine", "ignoring empty post-handshake transport datagram from " +
                                    DescribeReplySource(received.value));
        continue;
      }

      const auto message_type = static_cast<WireGuardMessageType>(buffer[0]);
      if (message_type != WireGuardMessageType::Data) {
        LogWarning("wg_engine", "ignoring unsupported post-handshake WireGuard message type from " +
                                    DescribeReplySource(received.value));
        continue;
      }

        auto transport = ConsumeTransportPacket(receiving_key, local_sender_index, buffer.data(), received.value.size);
      if (!transport.ok()) {
        LogWarning("wg_engine", "failed to validate inbound authenticated transport packet from " +
                                    DescribeReplySource(received.value) + ": " + transport.error.message);
        continue;
      }

      {
        std::scoped_lock lock(engine_mutex_);
        if (transport.value.counter < next_receive_counter_) {
          LogWarning("wg_engine", "ignoring replayed authenticated transport packet with counter " +
                                      std::to_string(transport.value.counter));
          continue;
        }

        next_receive_counter_ = transport.value.counter + 1;
        stats_.bytes_in += received.value.size;
        ++stats_.packets_in;

        if (!transport.value.payload.empty()) {
          const std::size_t payload_size = transport.value.payload.size();
          if (payload_size > kMaxQueuedTransportPayloadBytes ||
              queued_transport_packets_.size() >= kMaxQueuedTransportPackets ||
              queued_transport_payload_bytes_ + payload_size > kMaxQueuedTransportPayloadBytes) {
            if (!receive_queue_overflow_logged_) {
              LogWarning("wg_engine", "dropping authenticated transport payload because the bounded receive queue is full");
              receive_queue_overflow_logged_ = true;
            }
          } else {
            queued_transport_payload_bytes_ += payload_size;
            queued_transport_packets_.push_back(std::move(transport.value));
            receive_queue_overflow_logged_ = false;
          }
        }
      }
    }
  }

  void KeepaliveLoop() {
    while (true) {
      std::uint16_t interval_seconds = 0;

      {
        std::unique_lock lock(engine_mutex_);
        interval_seconds = prepared_session_.persistent_keepalive;
        if (keepalive_cv_.wait_for(lock, std::chrono::seconds(interval_seconds), [this]() {
              return stop_requested_ || !running_;
            })) {
          return;
        }

        if (stop_requested_ || !running_) {
          return;
        }
      }

      const Result<ReservedTransportSend> reserved = ReserveTransportSend();
      if (!reserved.ok()) {
        if (reserved.error.code == ErrorCode::InvalidState) {
          return;
        }

        LogWarning("wg_engine", "failed to reserve periodic keepalive transport state: " + reserved.error.message);
        continue;
      }

      const Result<WireGuardTransportKeepalive> keepalive =
          CreateTransportKeepalivePacket(reserved.value.sending_key, reserved.value.peer_sender_index,
                                         reserved.value.counter);
      if (!keepalive.ok()) {
        LogWarning("wg_engine", "failed to build periodic keepalive packet: " + keepalive.error.message);
        continue;
      }

      const Result<std::size_t> bytes_sent = SendReservedTransportDatagram(
          reserved.value, keepalive.value.packet.data(), keepalive.value.packet.size());
      if (!bytes_sent.ok()) {
        if (bytes_sent.error.code == ErrorCode::IoError || bytes_sent.error.code == ErrorCode::InvalidState) {
          HandleWorkerTransportFailure("periodic keepalive send failed after " + std::to_string(interval_seconds) +
                                           "s: " + bytes_sent.error.message,
                                       ReconnectTrigger::KeepaliveLoop);
          return;
        }

        LogWarning("wg_engine", "failed to send periodic keepalive after " + std::to_string(interval_seconds) +
                                    "s: " + bytes_sent.error.message);
        continue;
      }

      RecordSuccessfulOutboundDatagram(bytes_sent.value);
    }
  }

  std::unique_ptr<IUdpSocketRuntime> socket_runtime_;
  mutable std::mutex engine_mutex_{};
  std::mutex transport_send_mutex_{};
  std::mutex reconnect_mutex_{};
  std::condition_variable keepalive_cv_{};
  std::thread keepalive_thread_{};
  std::thread receive_thread_{};
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
  std::uint64_t next_receive_counter_ = 0;
  std::deque<WireGuardConsumedTransportPacket> queued_transport_packets_{};
  std::size_t queued_transport_payload_bytes_ = 0;
  bool receive_queue_overflow_logged_ = false;
  bool stop_requested_ = false;
  std::chrono::steady_clock::time_point last_handshake_at_{};
  std::string last_error_;
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
  return std::make_unique<WgTunnelEngine>(std::make_unique<BsdSocketRuntime>());
}

std::unique_ptr<IWgTunnelEngine> CreateWgTunnelEngine(std::unique_ptr<IUdpSocketRuntime> socket_runtime) {
  return std::make_unique<WgTunnelEngine>(std::move(socket_runtime));
}

}  // namespace swg::sysmodule