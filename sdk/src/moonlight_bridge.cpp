#include "swg/moonlight_bridge.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "swg/app_session.h"
#include "swg/client.h"
#include "swg/log.h"
#include "swg/moonlight_bridge_c.h"
#include "swg/switch_transport.h"
#include "swg/tunnel_datagram.h"
#include "swg/tunnel_stream.h"

#if defined(SWG_PLATFORM_SWITCH)
#include <arpa/inet.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <sys/socket.h>
#endif

namespace {

#if defined(SWG_PLATFORM_SWITCH)

using namespace std::chrono_literals;

constexpr std::string_view kLogComponent = "compat-bridge";

template <typename... Args>
std::string BuildMessage(Args&&... args) {
  std::ostringstream stream;
  (stream << ... << std::forward<Args>(args));
  return stream.str();
}

void LogInfoMessage(const std::string& message) {
  swg::LogInfo(kLogComponent, message);
}

void LogWarningMessage(const std::string& message) {
  swg::LogWarning(kLogComponent, message);
}

enum class RouteKind {
  Direct = 0,
  Tunnel,
  Deny,
};

struct RouteDecision {
  RouteKind kind = RouteKind::Direct;
  std::string message;
};

struct ParsedUrl {
  std::string scheme;
  std::string host;
  std::uint16_t port = 0;
  std::string target;
  bool use_tls = false;
};

std::string ToLower(std::string_view text) {
  std::string lowered(text);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return lowered;
}

std::string Trim(std::string_view text) {
  std::size_t begin = 0;
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) {
    ++begin;
  }

  std::size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
    --end;
  }

  return std::string(text.substr(begin, end - begin));
}

bool TryParseUrl(const std::string& url, ParsedUrl* parsed, std::string* error) {
  const std::size_t scheme_separator = url.find("://");
  if (scheme_separator == std::string::npos) {
    if (error) {
      *error = "unsupported URL: missing scheme";
    }
    return false;
  }

  parsed->scheme = ToLower(std::string_view(url).substr(0, scheme_separator));
  if (parsed->scheme == "https") {
    parsed->use_tls = true;
    parsed->port = 443;
  } else if (parsed->scheme == "http") {
    parsed->use_tls = false;
    parsed->port = 80;
  } else {
    if (error) {
      *error = "unsupported URL scheme: " + parsed->scheme;
    }
    return false;
  }

  std::string_view remainder(url);
  remainder.remove_prefix(scheme_separator + 3);
  const std::size_t path_separator = remainder.find('/');
  std::string_view authority = remainder.substr(0, path_separator);
  parsed->target =
      path_separator == std::string::npos ? "/" : std::string(remainder.substr(path_separator));

  if (authority.empty()) {
    if (error) {
      *error = "unsupported URL: missing host";
    }
    return false;
  }

  if (authority.front() == '[') {
    const std::size_t closing = authority.find(']');
    if (closing == std::string::npos) {
      if (error) {
        *error = "unsupported URL: unterminated IPv6 host";
      }
      return false;
    }

    parsed->host = std::string(authority.substr(1, closing - 1));
    if (closing + 1 < authority.size()) {
      if (authority[closing + 1] != ':') {
        if (error) {
          *error = "unsupported URL: invalid authority";
        }
        return false;
      }

      const std::string port_text(authority.substr(closing + 2));
      const unsigned long raw_port = std::stoul(port_text);
      if (raw_port == 0 || raw_port > 65535) {
        if (error) {
          *error = "unsupported URL: invalid port";
        }
        return false;
      }
      parsed->port = static_cast<std::uint16_t>(raw_port);
    }
  } else {
    const std::size_t port_separator = authority.rfind(':');
    if (port_separator != std::string::npos && authority.find(':') == port_separator) {
      parsed->host = std::string(authority.substr(0, port_separator));
      const std::string port_text(authority.substr(port_separator + 1));
      const unsigned long raw_port = std::stoul(port_text);
      if (raw_port == 0 || raw_port > 65535) {
        if (error) {
          *error = "unsupported URL: invalid port";
        }
        return false;
      }
      parsed->port = static_cast<std::uint16_t>(raw_port);
    } else {
      parsed->host = std::string(authority);
    }
  }

  if (parsed->host.empty()) {
    if (error) {
      *error = "unsupported URL: missing host";
    }
    return false;
  }

  return true;
}

bool TryParseIpv4(std::string_view host, struct sockaddr_storage* addr, socklen_t* addr_len) {
  sockaddr_in ipv4{};
  ipv4.sin_family = AF_INET;
  if (inet_pton(AF_INET, std::string(host).c_str(), &ipv4.sin_addr) != 1) {
    return false;
  }

  std::memset(addr, 0, sizeof(*addr));
  std::memcpy(addr, &ipv4, sizeof(ipv4));
  *addr_len = sizeof(sockaddr_in);
  return true;
}

std::string FormatSocketAddress(const sockaddr_storage& addr) {
  char buffer[64] = {};
  if (addr.ss_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&addr);
    if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer, sizeof(buffer)) != nullptr) {
      return buffer;
    }
  }

  return {};
}

struct HttpResponse {
  int status_code = 0;
  std::vector<std::uint8_t> body;
};

bool DecodeChunkedBody(const std::vector<std::uint8_t>& encoded,
                       std::vector<std::uint8_t>* decoded,
                       std::string* error) {
  decoded->clear();
  std::size_t offset = 0;
  while (offset < encoded.size()) {
    const std::size_t line_end =
        std::search(encoded.begin() + static_cast<std::ptrdiff_t>(offset), encoded.end(),
                    "\r\n", "\r\n" + 2) -
        encoded.begin();
    if (line_end >= encoded.size()) {
      if (error) {
        *error = "chunked HTTP response is truncated";
      }
      return false;
    }

    const std::string size_text(reinterpret_cast<const char*>(encoded.data() + offset),
                                line_end - offset);
    const std::size_t extensions = size_text.find(';');
    const std::string raw_size =
        extensions == std::string::npos ? size_text : size_text.substr(0, extensions);
    const std::size_t chunk_size = std::stoul(raw_size, nullptr, 16);
    offset = line_end + 2;

    if (chunk_size == 0) {
      return true;
    }

    if (offset + chunk_size + 2 > encoded.size()) {
      if (error) {
        *error = "chunked HTTP response body is truncated";
      }
      return false;
    }

    decoded->insert(decoded->end(), encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                    encoded.begin() + static_cast<std::ptrdiff_t>(offset + chunk_size));
    offset += chunk_size;
    if (encoded[offset] != '\r' || encoded[offset + 1] != '\n') {
      if (error) {
        *error = "chunked HTTP response is malformed";
      }
      return false;
    }
    offset += 2;
  }

  if (error) {
    *error = "chunked HTTP response is incomplete";
  }
  return false;
}

bool ParseHttpResponse(const std::vector<std::uint8_t>& raw,
                       HttpResponse* response,
                       std::string* error) {
  const auto header_it = std::search(raw.begin(), raw.end(), "\r\n\r\n", "\r\n\r\n" + 4);
  if (header_it == raw.end()) {
    if (error) {
      *error = "HTTP response is missing headers";
    }
    return false;
  }

  const std::size_t header_size = static_cast<std::size_t>(header_it - raw.begin());
  const std::string header_block(reinterpret_cast<const char*>(raw.data()), header_size);

  const std::size_t line_end = header_block.find("\r\n");
  const std::string status_line =
      line_end == std::string::npos ? header_block : header_block.substr(0, line_end);
  const std::size_t first_space = status_line.find(' ');
  const std::size_t second_space =
      first_space == std::string::npos ? std::string::npos : status_line.find(' ', first_space + 1);
  if (first_space == std::string::npos) {
    if (error) {
      *error = "HTTP response has an invalid status line";
    }
    return false;
  }

  response->status_code =
      std::stoi(status_line.substr(first_space + 1, second_space - first_space - 1));

  const std::vector<std::uint8_t> encoded_body(header_it + 4, raw.end());
  std::vector<std::uint8_t> decoded_body;
  const std::string lowered_headers = ToLower(header_block);
  if (lowered_headers.find("transfer-encoding: chunked") != std::string::npos) {
    if (!DecodeChunkedBody(encoded_body, &decoded_body, error)) {
      return false;
    }
  } else {
    decoded_body = encoded_body;
    const std::size_t content_length_pos = lowered_headers.find("content-length:");
    if (content_length_pos != std::string::npos) {
      const std::size_t value_begin = content_length_pos + std::strlen("content-length:");
      const std::size_t value_end = lowered_headers.find("\r\n", value_begin);
      const std::size_t expected_length = static_cast<std::size_t>(std::stoul(
          Trim(std::string_view(lowered_headers).substr(value_begin, value_end - value_begin))));
      if (decoded_body.size() < expected_length) {
        if (error) {
          *error = "HTTP response body is truncated";
        }
        return false;
      }
      decoded_body.resize(expected_length);
    }
  }

  response->body = std::move(decoded_body);
  return true;
}

class TunnelStreamIo {
 public:
  TunnelStreamIo(swg::TunnelStreamSocket socket, int timeout_ms)
      : socket_(std::move(socket)), timeout_ms_(timeout_ms) {}

  bool SendAll(const std::string& request, std::string* error) {
    std::vector<std::uint8_t> payload(request.begin(), request.end());
    const auto sent = socket_.Send(payload);
    if (!sent.ok()) {
      if (error) {
        *error = sent.error.message;
      }
      return false;
    }
    return true;
  }

  int Read(unsigned char* buffer, std::size_t length, bool* peer_closed, std::string* error) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms_);
    while (pending_offset_ >= pending_.size()) {
      pending_.clear();
      pending_offset_ = 0;

      const auto received = socket_.Receive();
      if (received.ok()) {
        pending_ = std::move(received.value.payload);
        peer_closed_seen_ = received.value.peer_closed;
        if (pending_.empty()) {
          if (received.value.peer_closed) {
            *peer_closed = true;
            return 0;
          }
          continue;
        }
        break;
      }

      if (received.error.code != swg::ErrorCode::NotFound) {
        if (error) {
          *error = received.error.message;
        }
        return -1;
      }

      if (std::chrono::steady_clock::now() >= deadline) {
        if (peer_closed_seen_) {
          *peer_closed = true;
          return 0;
        }

        if (error) {
          *error = "timed out waiting for tunnel stream data";
        }
        return 0;
      }

      std::this_thread::sleep_for(10ms);
    }

    const std::size_t available = pending_.size() - pending_offset_;
    const std::size_t copy_length = std::min(length, available);
    std::memcpy(buffer, pending_.data() + pending_offset_, copy_length);
    pending_offset_ += copy_length;
    *peer_closed = peer_closed_seen_ && pending_offset_ >= pending_.size();
    return static_cast<int>(copy_length);
  }

  bool ReadUntilClose(std::vector<std::uint8_t>* bytes, std::string* error) {
    bytes->clear();
    bool peer_closed = false;
    std::array<unsigned char, 4096> buffer{};
    for (;;) {
      const int received = Read(buffer.data(), buffer.size(), &peer_closed, error);
      if (received < 0) {
        return false;
      }
      if (received == 0) {
        return peer_closed;
      }

      bytes->insert(bytes->end(), buffer.begin(), buffer.begin() + received);
      if (peer_closed) {
        return true;
      }
    }
  }

  static int BioSend(void* context, const unsigned char* buffer, std::size_t length) {
    auto* io = static_cast<TunnelStreamIo*>(context);
    std::string error;
    std::string request(reinterpret_cast<const char*>(buffer), length);
    if (!io->SendAll(request, &error)) {
      io->last_error_ = error;
      return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return static_cast<int>(length);
  }

  static int BioRecv(void* context, unsigned char* buffer, std::size_t length) {
    auto* io = static_cast<TunnelStreamIo*>(context);
    bool peer_closed = false;
    std::string error;
    const int received = io->Read(buffer, length, &peer_closed, &error);
    if (received > 0) {
      return received;
    }
    if (peer_closed) {
      return 0;
    }
    io->last_error_ = error;
    return error.empty() ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_RECV_FAILED;
  }

  const std::string& last_error() const {
    return last_error_;
  }

 private:
  swg::TunnelStreamSocket socket_{};
  int timeout_ms_ = 0;
  std::vector<std::uint8_t> pending_{};
  std::size_t pending_offset_ = 0;
  bool peer_closed_seen_ = false;
  std::string last_error_{};
};

enum class BridgeSocketKind {
  Stream = 0,
  Datagram,
};

enum class ReceiveOutcome {
  Ready = 0,
  Timeout,
  Error,
};

struct BridgeSocketEntry {
  explicit BridgeSocketEntry(int socket_fd_value, std::shared_ptr<swg::AppSession> app_session)
      : socket_fd(socket_fd_value), session(std::move(app_session)) {}

  int socket_fd = -1;
  BridgeSocketKind kind = BridgeSocketKind::Stream;
  std::shared_ptr<swg::AppSession> session{};
  swg::TunnelStreamSocket stream_socket{};
  swg::TunnelDatagramSocket datagram_socket{};
  int recv_timeout_ms = -1;
  bool peer_closed = false;
  sockaddr_storage remote_addr{};
  socklen_t remote_addr_len = 0;
  std::deque<std::uint8_t> stream_buffer{};
  std::optional<swg::TunnelDatagram> pending_datagram{};
  std::string last_error{};
  std::mutex mutex{};
};

int ToErrno(swg::ErrorCode code) {
  switch (code) {
    case swg::ErrorCode::Ok:
      return 0;
    case swg::ErrorCode::NotFound:
      return EWOULDBLOCK;
    case swg::ErrorCode::IoError:
      return EIO;
    case swg::ErrorCode::InvalidConfig:
    case swg::ErrorCode::ParseError:
      return EINVAL;
    case swg::ErrorCode::InvalidState:
      return ENOTCONN;
    case swg::ErrorCode::ServiceUnavailable:
      return ENETDOWN;
    case swg::ErrorCode::Unsupported:
      return EHOSTUNREACH;
    case swg::ErrorCode::AlreadyExists:
      return EALREADY;
  }

  return EIO;
}

swg::AppTrafficClass ToTrafficClass(int traffic_class) {
  switch (traffic_class) {
    case SWG_COMPAT_TRAFFIC_STREAM_VIDEO:
      return swg::AppTrafficClass::StreamVideo;
    case SWG_COMPAT_TRAFFIC_STREAM_AUDIO:
      return swg::AppTrafficClass::StreamAudio;
    case SWG_COMPAT_TRAFFIC_STREAM_INPUT:
      return swg::AppTrafficClass::StreamInput;
    case SWG_COMPAT_TRAFFIC_STREAM_CONTROL:
    default:
      return swg::AppTrafficClass::StreamControl;
  }
}

std::string DefaultCompatHttpUserAgent(std::string_view client_name) {
  if (client_name == "Moonlight-Switch") {
    return "Moonlight-Switch/1.4.1";
  }
  if (client_name.empty()) {
    return "SWG-Compat/1.0";
  }

  return std::string(client_name);
}

swg::AppTunnelRequest MakeCompatBridgeSessionRequest(std::string_view client_name,
                                                     std::string_view integration_tag) {
  swg::AppTunnelRequest request{};
  request.app.client_name = std::string(client_name);
  request.app.integration_tag = std::string(integration_tag);
  request.allow_local_network_bypass = false;
  return request;
}

ReceiveOutcome FillStreamBuffer(BridgeSocketEntry* entry, int timeout_ms) {
  if (!entry->stream_buffer.empty() || entry->peer_closed) {
    return ReceiveOutcome::Ready;
  }

  const auto deadline = timeout_ms < 0 ? std::optional<std::chrono::steady_clock::time_point>{}
                                       : std::optional<std::chrono::steady_clock::time_point>{
                                             std::chrono::steady_clock::now() +
                                             std::chrono::milliseconds(timeout_ms)};

  while (entry->stream_buffer.empty() && !entry->peer_closed) {
    const auto received = entry->stream_socket.Receive();
    if (received.ok()) {
      entry->peer_closed = entry->peer_closed || received.value.peer_closed;
      entry->stream_buffer.insert(entry->stream_buffer.end(),
                                  received.value.payload.begin(),
                                  received.value.payload.end());
      if (!entry->stream_buffer.empty() || entry->peer_closed) {
        return ReceiveOutcome::Ready;
      }
      continue;
    }

    if (received.error.code != swg::ErrorCode::NotFound) {
      entry->last_error = received.error.message;
      errno = ToErrno(received.error.code);
      return ReceiveOutcome::Error;
    }

    if (deadline.has_value() && std::chrono::steady_clock::now() >= *deadline) {
      return ReceiveOutcome::Timeout;
    }

    std::this_thread::sleep_for(10ms);
  }

  return ReceiveOutcome::Ready;
}

ReceiveOutcome FillDatagram(BridgeSocketEntry* entry, int timeout_ms) {
  if (entry->pending_datagram.has_value()) {
    return ReceiveOutcome::Ready;
  }

  const auto deadline = timeout_ms < 0 ? std::optional<std::chrono::steady_clock::time_point>{}
                                       : std::optional<std::chrono::steady_clock::time_point>{
                                             std::chrono::steady_clock::now() +
                                             std::chrono::milliseconds(timeout_ms)};

  while (!entry->pending_datagram.has_value()) {
    const auto received = entry->datagram_socket.Receive();
    if (received.ok()) {
      entry->pending_datagram = std::move(received.value);
      return ReceiveOutcome::Ready;
    }

    if (received.error.code != swg::ErrorCode::NotFound) {
      entry->last_error = received.error.message;
      errno = ToErrno(received.error.code);
      return ReceiveOutcome::Error;
    }

    if (deadline.has_value() && std::chrono::steady_clock::now() >= *deadline) {
      return ReceiveOutcome::Timeout;
    }

    std::this_thread::sleep_for(10ms);
  }

  return ReceiveOutcome::Ready;
}

class MoonlightBridgeState {
 public:
  static MoonlightBridgeState& Instance() {
    static MoonlightBridgeState instance;
    return instance;
  }

  void ConfigureIdentity(std::string client_name,
                         std::string integration_tag,
                         std::string http_user_agent) {
    std::scoped_lock lock(mutex_);

    if (client_name.empty()) {
      client_name = "Moonlight-Switch";
    }
    if (integration_tag.empty()) {
      integration_tag = "moonlight-switch";
    }
    if (http_user_agent.empty()) {
      http_user_agent = DefaultCompatHttpUserAgent(client_name);
    }

    if (client_name_ == client_name && integration_tag_ == integration_tag &&
        http_user_agent_ == http_user_agent) {
      return;
    }

    client_name_ = std::move(client_name);
    integration_tag_ = std::move(integration_tag);
    http_user_agent_ = std::move(http_user_agent);
    InvalidateSessionLocked();
  }

  void ConfigureHttpCredentials(std::string certificate_path, std::string key_path) {
    std::scoped_lock lock(mutex_);
    certificate_path_ = std::move(certificate_path);
    key_path_ = std::move(key_path);
  }

  int AttachStreamSocket(int socket_fd,
                         const struct sockaddr_storage* remote_addr,
                         socklen_t remote_addr_len,
                         unsigned short remote_port,
                         int traffic_class) {
    if (socket_fd < 0 || remote_addr == nullptr || remote_addr_len <= 0 || remote_port == 0) {
      errno = EINVAL;
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    const std::string remote_host = FormatSocketAddress(*remote_addr);
    if (remote_host.empty()) {
      errno = EAFNOSUPPORT;
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    const swg::AppTrafficClass app_traffic_class = ToTrafficClass(traffic_class);
    const RouteDecision plan = Plan(remote_host, remote_port, swg::TransportProtocol::Tcp,
                                    app_traffic_class);
    if (plan.kind == RouteKind::Direct) {
      LogInfoMessage(BuildMessage("using direct stream socket for ", remote_host, ":",
                                  remote_port, ": ",
                                  plan.message.empty() ? std::string("no tunnel route available")
                                                       : plan.message));
      return SWG_MOONLIGHT_ROUTE_DIRECT;
    }
    if (plan.kind == RouteKind::Deny) {
      errno = EHOSTUNREACH;
      LogWarningMessage(BuildMessage("denying tunnel stream attach for socket ", socket_fd,
                                     " to ", remote_host, ":", remote_port, ": ",
                                     plan.message));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    auto entry = CreateSocketEntry(socket_fd);
    if (!entry.ok()) {
      errno = ToErrno(entry.error.code);
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    entry.value->kind = BridgeSocketKind::Stream;
    std::memcpy(&entry.value->remote_addr, remote_addr, static_cast<std::size_t>(remote_addr_len));
    entry.value->remote_addr_len = remote_addr_len;

    swg::TunnelStreamOpenRequest request{};
    request.remote_host = remote_host;
    request.remote_port = remote_port;
    request.transport = swg::TransportProtocol::Tcp;
    request.traffic_class = app_traffic_class;
    request.route_preference = swg::RoutePreference::RequireTunnel;

    auto opened = swg::TunnelStreamSocket::Open(*entry.value->session, request);
    if (!opened.ok()) {
      errno = ToErrno(opened.error.code);
      LogWarningMessage(BuildMessage("failed to open tunnel stream for ", remote_host, ":",
                                     remote_port, ": ", opened.error.message));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    entry.value->stream_socket = std::move(opened.value);
    RegisterSocket(entry.value);
    return SWG_MOONLIGHT_ROUTE_TUNNEL;
  }

  int AttachDatagramSocket(int socket_fd,
                           const struct sockaddr_storage* remote_addr,
                           socklen_t remote_addr_len,
                           unsigned short remote_port,
                           int traffic_class) {
    if (socket_fd < 0 || remote_addr == nullptr || remote_addr_len <= 0 || remote_port == 0) {
      errno = EINVAL;
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    const std::string remote_host = FormatSocketAddress(*remote_addr);
    if (remote_host.empty()) {
      errno = EAFNOSUPPORT;
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    const swg::AppTrafficClass app_traffic_class = ToTrafficClass(traffic_class);
    const RouteDecision plan = Plan(remote_host, remote_port, swg::TransportProtocol::Udp,
                                    app_traffic_class);
    if (plan.kind == RouteKind::Direct) {
      LogInfoMessage(BuildMessage("using direct datagram socket for ", remote_host, ":",
                                  remote_port, ": ",
                                  plan.message.empty() ? std::string("no tunnel route available")
                                                       : plan.message));
      return SWG_MOONLIGHT_ROUTE_DIRECT;
    }
    if (plan.kind == RouteKind::Deny) {
      errno = EHOSTUNREACH;
      LogWarningMessage(BuildMessage("denying tunnel datagram attach for socket ", socket_fd,
                                     " to ", remote_host, ":", remote_port, ": ",
                                     plan.message));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    auto entry = CreateSocketEntry(socket_fd);
    if (!entry.ok()) {
      errno = ToErrno(entry.error.code);
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    entry.value->kind = BridgeSocketKind::Datagram;
    std::memcpy(&entry.value->remote_addr, remote_addr, static_cast<std::size_t>(remote_addr_len));
    entry.value->remote_addr_len = remote_addr_len;

    swg::TunnelDatagramOpenRequest request{};
    request.remote_host = remote_host;
    request.remote_port = remote_port;
    request.traffic_class = app_traffic_class;
    request.route_preference = swg::RoutePreference::RequireTunnel;

    auto opened = swg::TunnelDatagramSocket::Open(*entry.value->session, request);
    if (!opened.ok()) {
      errno = ToErrno(opened.error.code);
      LogWarningMessage(BuildMessage("failed to open tunnel datagram for ", remote_host, ":",
                                     remote_port, ": ", opened.error.message));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    entry.value->datagram_socket = std::move(opened.value);
    RegisterSocket(entry.value);
    return SWG_MOONLIGHT_ROUTE_TUNNEL;
  }

  bool IsTunnelSocket(int socket_fd) const {
    std::scoped_lock lock(socket_mutex_);
    return sockets_.find(socket_fd) != sockets_.end();
  }

  int StreamSend(int socket_fd, const void* buffer, std::size_t size) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }

    std::scoped_lock lock(entry->mutex);
    if (entry->kind != BridgeSocketKind::Stream) {
      errno = EINVAL;
      return -1;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(buffer);
    std::vector<std::uint8_t> payload(bytes, bytes + size);
    const auto sent = entry->stream_socket.Send(payload);
    if (!sent.ok()) {
      entry->last_error = sent.error.message;
      errno = ToErrno(sent.error.code);
      return -1;
    }

    return static_cast<int>(size);
  }

  int StreamRecv(int socket_fd, void* buffer, std::size_t size) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }

    std::scoped_lock lock(entry->mutex);
    if (entry->kind != BridgeSocketKind::Stream) {
      errno = EINVAL;
      return -1;
    }

    const ReceiveOutcome outcome = FillStreamBuffer(entry.get(), entry->recv_timeout_ms);
    if (outcome == ReceiveOutcome::Error) {
      return -1;
    }
    if (entry->stream_buffer.empty()) {
      if (outcome == ReceiveOutcome::Timeout) {
        errno = EWOULDBLOCK;
        return -1;
      }
      return 0;
    }

    const std::size_t copy_size = std::min(size, entry->stream_buffer.size());
    auto* bytes = static_cast<std::uint8_t*>(buffer);
    for (std::size_t index = 0; index < copy_size; ++index) {
      bytes[index] = entry->stream_buffer.front();
      entry->stream_buffer.pop_front();
    }

    return static_cast<int>(copy_size);
  }

  int DatagramSend(int socket_fd,
                   const void* buffer,
                   std::size_t size,
                   const struct sockaddr* remote_addr,
                   socklen_t remote_addr_len) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }

    std::scoped_lock lock(entry->mutex);
    if (entry->kind != BridgeSocketKind::Datagram) {
      errno = EINVAL;
      return -1;
    }

    if (remote_addr != nullptr && remote_addr_len > 0 && remote_addr->sa_family != AF_INET) {
      errno = EAFNOSUPPORT;
      return -1;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(buffer);
    std::vector<std::uint8_t> payload(bytes, bytes + size);
    const auto sent = entry->datagram_socket.Send(payload);
    if (!sent.ok()) {
      entry->last_error = sent.error.message;
      errno = ToErrno(sent.error.code);
      return -1;
    }

    return static_cast<int>(size);
  }

  int DatagramRecv(int socket_fd, void* buffer, std::size_t size, int timeout_ms) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }

    std::scoped_lock lock(entry->mutex);
    if (entry->kind != BridgeSocketKind::Datagram) {
      errno = EINVAL;
      return -1;
    }

    const int effective_timeout = timeout_ms >= 0 ? timeout_ms : entry->recv_timeout_ms;
    const ReceiveOutcome outcome = FillDatagram(entry.get(), effective_timeout);
    if (outcome == ReceiveOutcome::Error) {
      return -1;
    }
    if (!entry->pending_datagram.has_value()) {
      errno = EWOULDBLOCK;
      return -1;
    }

    swg::TunnelDatagram datagram = std::move(*entry->pending_datagram);
    entry->pending_datagram.reset();

    const std::size_t copy_size = std::min(size, datagram.payload.size());
    if (copy_size != 0) {
      std::memcpy(buffer, datagram.payload.data(), copy_size);
    }
    return static_cast<int>(copy_size);
  }

  int CopyRemoteAddr(int socket_fd, struct sockaddr_storage* remote_addr, socklen_t* remote_addr_len) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }
    if (remote_addr == nullptr || remote_addr_len == nullptr) {
      errno = EINVAL;
      return -1;
    }

    std::scoped_lock lock(entry->mutex);
    std::memcpy(remote_addr, &entry->remote_addr, static_cast<std::size_t>(entry->remote_addr_len));
    *remote_addr_len = entry->remote_addr_len;
    return 1;
  }

  int SocketWait(int socket_fd,
                 int want_read,
                 int want_write,
                 int timeout_ms,
                 int* can_read,
                 int* can_write) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }

    std::scoped_lock lock(entry->mutex);
    if (can_read) {
      *can_read = 0;
    }
    if (can_write) {
      *can_write = 0;
    }

    if (want_write && can_write) {
      *can_write = 1;
    }

    if (want_read) {
      ReceiveOutcome outcome = ReceiveOutcome::Ready;
      if (entry->kind == BridgeSocketKind::Stream) {
        outcome = FillStreamBuffer(entry.get(), timeout_ms);
        if (outcome == ReceiveOutcome::Error) {
          return -1;
        }
        if ((!entry->stream_buffer.empty() || entry->peer_closed) && can_read) {
          *can_read = 1;
        }
      } else {
        outcome = FillDatagram(entry.get(), timeout_ms);
        if (outcome == ReceiveOutcome::Error) {
          return -1;
        }
        if (entry->pending_datagram.has_value() && can_read) {
          *can_read = 1;
        }
      }
    }

    return 1;
  }

  int CloseSocket(int socket_fd) {
    std::shared_ptr<BridgeSocketEntry> removed;
    {
      std::scoped_lock lock(socket_mutex_);
      const auto entry = sockets_.find(socket_fd);
      if (entry == sockets_.end()) {
        return 0;
      }
      removed = std::move(entry->second);
      sockets_.erase(entry);
    }
    return removed ? 1 : 0;
  }

  int ShutdownSocket(int socket_fd) {
    return IsTunnelSocket(socket_fd) ? 1 : 0;
  }

  int SetRecvTimeout(int socket_fd, int timeout_ms) {
    auto entry = FindSocket(socket_fd);
    if (!entry) {
      return 0;
    }

    std::scoped_lock lock(entry->mutex);
    entry->recv_timeout_ms = timeout_ms;
    return 1;
  }

  int EnableNoDelay(int socket_fd) {
    return IsTunnelSocket(socket_fd) ? 1 : 0;
  }

  RouteDecision Plan(std::string_view host,
                     std::uint16_t port,
                     swg::TransportProtocol transport,
                     swg::AppTrafficClass traffic_class) {
    std::scoped_lock lock(mutex_);
    if (!EnsureTransportLocked()) {
      return RouteDecision{RouteKind::Direct, transport_error_};
    }
    if (!EnsureSessionLocked()) {
      return RouteDecision{RouteKind::Deny, session_error_};
    }

    swg::NetworkPlanRequest request{};
    request.remote_host = std::string(host);
    request.remote_port = port;
    request.transport = transport;
    request.traffic_class = traffic_class;
    request.route_preference = swg::RoutePreference::RequireTunnel;

    const auto plan = session_->PlanNetwork(request);
    if (!plan.ok()) {
      return RouteDecision{RouteKind::Deny, plan.error.message};
    }

    switch (plan.value.action) {
      case swg::RouteAction::Direct:
        return RouteDecision{RouteKind::Direct, plan.value.reason};
      case swg::RouteAction::Tunnel:
        return RouteDecision{RouteKind::Tunnel, plan.value.reason};
      case swg::RouteAction::Deny:
        return RouteDecision{RouteKind::Deny, plan.value.reason};
    }

    return RouteDecision{RouteKind::Direct, {}};
  }

  int ResolveStreamHost(const char* host,
                        unsigned short port,
                        struct sockaddr_storage* addr,
                        socklen_t* addr_len,
                        std::string* error = nullptr) {
    if (host == nullptr || addr == nullptr || addr_len == nullptr) {
      if (error) {
        *error = "host and address outputs must not be null";
      }
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    if (error) {
      error->clear();
    }

    const RouteDecision plan =
        Plan(host, port, swg::TransportProtocol::Tcp, swg::AppTrafficClass::StreamControl);
    if (plan.kind == RouteKind::Direct) {
      LogInfoMessage(BuildMessage("using direct hostname resolution for ", host, ":", port, ": ",
                                  plan.message.empty() ? std::string("no tunnel route available")
                                                       : plan.message));
      return SWG_MOONLIGHT_ROUTE_DIRECT;
    }
    if (plan.kind == RouteKind::Deny) {
      if (error) {
        *error = plan.message.empty() ? "swg tunnel route denied stream resolution" : plan.message;
      }
      LogWarningMessage(BuildMessage("denying stream hostname resolution for ", host, ":",
                                     port, ": ", plan.message));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    if (TryParseIpv4(host, addr, addr_len)) {
      reinterpret_cast<sockaddr_in*>(addr)->sin_port = htons(port);
      return SWG_MOONLIGHT_ROUTE_TUNNEL;
    }

    std::scoped_lock lock(mutex_);
    if (!EnsureSessionLocked()) {
      if (error) {
        *error = session_error_;
      }
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    const auto resolved = session_->ResolveDns(host);
    if (!resolved.ok() || !resolved.value.resolved || resolved.value.addresses.empty()) {
      if (error) {
        *error = resolved.ok() ? resolved.value.message : resolved.error.message;
      }
      LogWarningMessage(BuildMessage("failed to resolve ", host, " through swg tunnel DNS: ",
                                     resolved.ok() ? resolved.value.message
                                                   : resolved.error.message));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    if (!TryParseIpv4(resolved.value.addresses.front(), addr, addr_len)) {
      if (error) {
        *error = "unsupported resolved address: " + resolved.value.addresses.front();
      }
      LogWarningMessage(BuildMessage("unsupported resolved address for ", host, ": ",
                                     resolved.value.addresses.front()));
      return SWG_MOONLIGHT_ROUTE_ERROR;
    }

    reinterpret_cast<sockaddr_in*>(addr)->sin_port = htons(port);
    return SWG_MOONLIGHT_ROUTE_TUNNEL;
  }

  swg::CompatHttpRoute HttpRequest(const std::string& url,
                                   std::vector<std::uint8_t>* response_body,
                                   long timeout_seconds,
                                   std::string* error) {
    if (response_body == nullptr) {
      if (error) {
        *error = "response_body must not be null";
      }
      return swg::CompatHttpRoute::Failed;
    }

    ParsedUrl parsed{};
    if (!TryParseUrl(url, &parsed, error)) {
      return swg::CompatHttpRoute::Failed;
    }

    const RouteDecision plan =
        Plan(parsed.host, parsed.port,
             parsed.use_tls ? swg::TransportProtocol::Https : swg::TransportProtocol::Http,
             swg::AppTrafficClass::HttpsControl);
    if (plan.kind == RouteKind::Direct) {
      LogInfoMessage(BuildMessage("using direct HTTP control for ", parsed.host, ":", parsed.port,
                                  ": ",
                                  plan.message.empty() ? std::string("no tunnel route available")
                                                       : plan.message));
      return swg::CompatHttpRoute::Direct;
    }
    if (plan.kind == RouteKind::Deny) {
      if (error) {
        *error = plan.message.empty() ? "swg tunnel route denied control request" : plan.message;
      }
      return swg::CompatHttpRoute::Failed;
    }

    std::string cert_path;
    std::string key_path;
    std::string http_user_agent;
    std::shared_ptr<swg::AppSession> session;
    {
      std::scoped_lock lock(mutex_);
      if (!EnsureSessionLocked()) {
        if (error) {
          *error = session_error_;
        }
        return swg::CompatHttpRoute::Failed;
      }
      cert_path = certificate_path_;
      key_path = key_path_;
      http_user_agent = http_user_agent_;
      session = session_;
    }

    swg::TunnelStreamOpenRequest request{};
    request.remote_host = parsed.host;
    request.remote_port = parsed.port;
    request.transport = parsed.use_tls ? swg::TransportProtocol::Https : swg::TransportProtocol::Http;
    request.traffic_class = swg::AppTrafficClass::HttpsControl;
    request.route_preference = swg::RoutePreference::RequireTunnel;

    auto stream = swg::TunnelStreamSocket::Open(*session, request);
    if (!stream.ok()) {
      if (error) {
        *error = stream.error.message;
      }
      return swg::CompatHttpRoute::Failed;
    }

    TunnelStreamIo io(std::move(stream.value), static_cast<int>(timeout_seconds * 1000));
    const std::string request_text =
        "GET " + parsed.target + " HTTP/1.1\r\nHost: " + parsed.host +
        "\r\nConnection: close\r\nUser-Agent: " + http_user_agent + "\r\n\r\n";

    std::vector<std::uint8_t> raw_response;
    if (parsed.use_tls) {
      if (!PerformTlsRequest(io, parsed.host, cert_path, key_path, request_text, &raw_response,
                             error)) {
        return swg::CompatHttpRoute::Failed;
      }
    } else {
      if (!io.SendAll(request_text, error) || !io.ReadUntilClose(&raw_response, error)) {
        if (error && error->empty()) {
          *error = "failed to read HTTP response over swg tunnel stream";
        }
        return swg::CompatHttpRoute::Failed;
      }
    }

    HttpResponse response{};
    if (!ParseHttpResponse(raw_response, &response, error)) {
      return swg::CompatHttpRoute::Failed;
    }
    if (response.status_code >= 400) {
      if (error) {
        *error = "HTTP control request failed with status " + std::to_string(response.status_code);
      }
      return swg::CompatHttpRoute::Failed;
    }

    *response_body = std::move(response.body);
    return swg::CompatHttpRoute::Success;
  }

 private:
  MoonlightBridgeState() = default;

  bool EnsureTransportLocked() {
    if (transport_checked_) {
      return transport_available_;
    }

    transport_ = swg::CreateSwitchControlTransport();
    if (!transport_) {
      transport_available_ = false;
      transport_checked_ = true;
      transport_error_ = "swg transport is unavailable";
      LogWarningMessage(transport_error_);
      return false;
    }

    swg::Client probe(transport_);
    const auto version = probe.GetVersion();
    if (!version.ok()) {
      transport_available_ = false;
      transport_checked_ = true;
      transport_error_ = version.error.message;
      LogWarningMessage(BuildMessage("control transport probe failed: ", transport_error_));
      return false;
    }

    client_ = std::make_unique<swg::Client>(transport_);
    transport_available_ = true;
    transport_checked_ = true;
    return true;
  }

  bool EnsureSessionLocked() {
    if (session_ && session_->is_open()) {
      return true;
    }
    if (!transport_available_ || !client_) {
      session_error_ = transport_error_;
      return false;
    }

    auto session = std::make_shared<swg::AppSession>(*client_);
    const auto opened = session->Open(MakeCompatBridgeSessionRequest(client_name_, integration_tag_));
    if (!opened.ok()) {
      session_error_ = opened.error.message;
      LogWarningMessage(BuildMessage("failed to open app session: ", session_error_));
      return false;
    }

    session_error_.clear();
    session_ = std::move(session);
    return true;
  }

  swg::Result<std::shared_ptr<BridgeSocketEntry>> CreateSocketEntry(int socket_fd) {
    std::scoped_lock lock(mutex_);
    if (!EnsureTransportLocked()) {
      return swg::MakeFailure<std::shared_ptr<BridgeSocketEntry>>(swg::ErrorCode::ServiceUnavailable,
                                                                  transport_error_);
    }
    if (!EnsureSessionLocked()) {
      return swg::MakeFailure<std::shared_ptr<BridgeSocketEntry>>(swg::ErrorCode::InvalidState,
                                                                  session_error_);
    }

    return swg::MakeSuccess(std::make_shared<BridgeSocketEntry>(socket_fd, session_));
  }

  std::shared_ptr<BridgeSocketEntry> FindSocket(int socket_fd) const {
    std::scoped_lock lock(socket_mutex_);
    const auto entry = sockets_.find(socket_fd);
    return entry == sockets_.end() ? nullptr : entry->second;
  }

  void RegisterSocket(const std::shared_ptr<BridgeSocketEntry>& entry) {
    std::scoped_lock lock(socket_mutex_);
    sockets_[entry->socket_fd] = entry;
  }

  static bool PerformTlsRequest(TunnelStreamIo& io,
                                const std::string& host,
                                const std::string& cert_path,
                                const std::string& key_path,
                                const std::string& request_text,
                                std::vector<std::uint8_t>* raw_response,
                                std::string* error) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt certificate;
    mbedtls_pk_context private_key;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_x509_crt_init(&certificate);
    mbedtls_pk_init(&private_key);

    const auto cleanup = [&]() {
      mbedtls_pk_free(&private_key);
      mbedtls_x509_crt_free(&certificate);
      mbedtls_ssl_free(&ssl);
      mbedtls_ssl_config_free(&config);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
    };

    const char* personalization = "swg-compat-http";
    int rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   reinterpret_cast<const unsigned char*>(personalization),
                                   std::strlen(personalization));
    if (rc != 0) {
      if (error) {
        *error = FormatTlsError("mbedtls_ctr_drbg_seed", rc);
      }
      cleanup();
      return false;
    }

    rc = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
      if (error) {
        *error = FormatTlsError("mbedtls_ssl_config_defaults", rc);
      }
      cleanup();
      return false;
    }

    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (!cert_path.empty() && !key_path.empty()) {
      rc = mbedtls_x509_crt_parse_file(&certificate, cert_path.c_str());
      if (rc == 0) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
        rc = mbedtls_pk_parse_keyfile(&private_key, key_path.c_str(), nullptr,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
#else
        rc = mbedtls_pk_parse_keyfile(&private_key, key_path.c_str(), nullptr);
#endif
      }
      if (rc == 0) {
        rc = mbedtls_ssl_conf_own_cert(&config, &certificate, &private_key);
      }
      if (rc != 0) {
        if (error) {
          *error = FormatTlsError("loading TLS client credentials", rc);
        }
        cleanup();
        return false;
      }
    }

    rc = mbedtls_ssl_setup(&ssl, &config);
    if (rc != 0) {
      if (error) {
        *error = FormatTlsError("mbedtls_ssl_setup", rc);
      }
      cleanup();
      return false;
    }

    rc = mbedtls_ssl_set_hostname(&ssl, host.c_str());
    if (rc != 0) {
      if (error) {
        *error = FormatTlsError("mbedtls_ssl_set_hostname", rc);
      }
      cleanup();
      return false;
    }

    mbedtls_ssl_set_bio(&ssl, &io, TunnelStreamIo::BioSend, TunnelStreamIo::BioRecv, nullptr);
    while ((rc = mbedtls_ssl_handshake(&ssl)) != 0) {
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }

      if (error) {
        *error = io.last_error().empty() ? FormatTlsError("mbedtls_ssl_handshake", rc)
                                         : io.last_error();
      }
      cleanup();
      return false;
    }

    std::size_t written = 0;
    while (written < request_text.size()) {
      rc = mbedtls_ssl_write(&ssl,
                             reinterpret_cast<const unsigned char*>(request_text.data() + written),
                             request_text.size() - written);
      if (rc > 0) {
        written += static_cast<std::size_t>(rc);
        continue;
      }
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }

      if (error) {
        *error = io.last_error().empty() ? FormatTlsError("mbedtls_ssl_write", rc)
                                         : io.last_error();
      }
      cleanup();
      return false;
    }

    raw_response->clear();
    std::array<unsigned char, 4096> buffer{};
    for (;;) {
      rc = mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
      if (rc > 0) {
        raw_response->insert(raw_response->end(), buffer.begin(), buffer.begin() + rc);
        continue;
      }
      if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        break;
      }
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }

      if (error) {
        *error = io.last_error().empty() ? FormatTlsError("mbedtls_ssl_read", rc)
                                         : io.last_error();
      }
      cleanup();
      return false;
    }

    cleanup();
    return true;
  }

  static std::string FormatTlsError(std::string_view operation, int rc) {
    char buffer[256] = {};
    mbedtls_strerror(rc, buffer, sizeof(buffer));
    std::ostringstream stream;
    stream << operation << " failed: " << buffer << " (" << rc << ")";
    return stream.str();
  }

  void InvalidateSessionLocked() {
    std::unordered_map<int, std::shared_ptr<BridgeSocketEntry>> stale_sockets;
    {
      std::scoped_lock socket_lock(socket_mutex_);
      stale_sockets.swap(sockets_);
    }

    for (auto& [socket_fd, entry] : stale_sockets) {
      (void)socket_fd;
      if (!entry) {
        continue;
      }

      std::scoped_lock entry_lock(entry->mutex);
      if (entry->kind == BridgeSocketKind::Stream) {
        static_cast<void>(entry->stream_socket.Close());
      } else {
        static_cast<void>(entry->datagram_socket.Close());
      }
    }

    if (session_) {
      static_cast<void>(session_->Close());
      session_.reset();
    }
    session_error_.clear();
  }

  std::mutex mutex_{};
  bool transport_checked_ = false;
  bool transport_available_ = false;
  std::string transport_error_{};
  std::shared_ptr<swg::IClientTransport> transport_{};
  std::unique_ptr<swg::Client> client_{};
  std::shared_ptr<swg::AppSession> session_{};
  std::string session_error_{};
  std::string client_name_ = "Moonlight-Switch";
  std::string integration_tag_ = "moonlight-switch";
  std::string http_user_agent_ = DefaultCompatHttpUserAgent(client_name_);
  std::string certificate_path_{};
  std::string key_path_{};
  mutable std::mutex socket_mutex_{};
  std::unordered_map<int, std::shared_ptr<BridgeSocketEntry>> sockets_{};
};

#endif

}  // namespace

namespace swg {

void ConfigureCompatBridgeIdentity(std::string client_name,
                                   std::string integration_tag,
                                   std::string http_user_agent) {
#if defined(SWG_PLATFORM_SWITCH)
  MoonlightBridgeState::Instance().ConfigureIdentity(std::move(client_name),
                                                     std::move(integration_tag),
                                                     std::move(http_user_agent));
#else
  (void)client_name;
  (void)integration_tag;
  (void)http_user_agent;
#endif
}

void ConfigureCompatHttpCredentials(std::string certificate_path, std::string key_path) {
#if defined(SWG_PLATFORM_SWITCH)
  MoonlightBridgeState::Instance().ConfigureHttpCredentials(std::move(certificate_path),
                                                            std::move(key_path));
#else
  (void)certificate_path;
  (void)key_path;
#endif
}

CompatHttpRoute CompatHttpRequest(const std::string& url,
                                  std::vector<std::uint8_t>* response_body,
                                  long timeout_seconds,
                                  std::string* error) {
#if defined(SWG_PLATFORM_SWITCH)
  return MoonlightBridgeState::Instance().HttpRequest(url, response_body, timeout_seconds, error);
#else
  (void)url;
  (void)response_body;
  (void)timeout_seconds;
  (void)error;
  return CompatHttpRoute::Direct;
#endif
}

#if defined(SWG_PLATFORM_SWITCH)
CompatSocketRoute CompatResolveStreamHost(const std::string& host,
                                          std::uint16_t port,
                                          struct sockaddr_storage* addr,
                                          socklen_t* addr_len,
                                          std::string* error) {
  return static_cast<CompatSocketRoute>(
      MoonlightBridgeState::Instance().ResolveStreamHost(host.c_str(), port, addr, addr_len, error));
}
#endif

void ConfigureMoonlightHttpCredentials(std::string certificate_path, std::string key_path) {
  ConfigureCompatHttpCredentials(std::move(certificate_path), std::move(key_path));
}

MoonlightHttpRoute MoonlightHttpRequest(const std::string& url,
                                        std::vector<std::uint8_t>* response_body,
                                        long timeout_seconds,
                                        std::string* error) {
  return CompatHttpRequest(url, response_body, timeout_seconds, error);
}

}  // namespace swg

#if defined(SWG_PLATFORM_SWITCH)
extern "C" void swg_compat_configure_identity(const char* client_name,
                                               const char* integration_tag,
                                               const char* http_user_agent) {
  swg::ConfigureCompatBridgeIdentity(client_name == nullptr ? std::string{} : std::string(client_name),
                                     integration_tag == nullptr ? std::string{} : std::string(integration_tag),
                                     http_user_agent == nullptr ? std::string{} : std::string(http_user_agent));
}

extern "C" int swg_compat_resolve_stream_host(const char* host,
                                               unsigned short port,
                                               struct sockaddr_storage* addr,
                                               socklen_t* addr_len) {
  return MoonlightBridgeState::Instance().ResolveStreamHost(host, port, addr, addr_len);
}

extern "C" int swg_compat_attach_stream_socket(int socket_fd,
                                                const struct sockaddr_storage* remote_addr,
                                                socklen_t remote_addr_len,
                                                unsigned short remote_port,
                                                int traffic_class) {
  return MoonlightBridgeState::Instance().AttachStreamSocket(socket_fd, remote_addr,
                                                             remote_addr_len, remote_port,
                                                             traffic_class);
}

extern "C" int swg_compat_attach_datagram_socket(int socket_fd,
                                                  const struct sockaddr_storage* remote_addr,
                                                  socklen_t remote_addr_len,
                                                  unsigned short remote_port,
                                                  int traffic_class) {
  return MoonlightBridgeState::Instance().AttachDatagramSocket(socket_fd, remote_addr,
                                                               remote_addr_len, remote_port,
                                                               traffic_class);
}

extern "C" int swg_compat_is_tunnel_socket(int socket_fd) {
  return MoonlightBridgeState::Instance().IsTunnelSocket(socket_fd) ? 1 : 0;
}

extern "C" int swg_compat_stream_send(int socket_fd, const void* buffer, size_t size) {
  return MoonlightBridgeState::Instance().StreamSend(socket_fd, buffer, size);
}

extern "C" int swg_compat_stream_recv(int socket_fd, void* buffer, size_t size) {
  return MoonlightBridgeState::Instance().StreamRecv(socket_fd, buffer, size);
}

extern "C" int swg_compat_datagram_send(int socket_fd,
                                         const void* buffer,
                                         size_t size,
                                         const struct sockaddr* remote_addr,
                                         socklen_t remote_addr_len) {
  return MoonlightBridgeState::Instance().DatagramSend(socket_fd, buffer, size, remote_addr,
                                                       remote_addr_len);
}

extern "C" int swg_compat_datagram_recv(int socket_fd,
                                         void* buffer,
                                         size_t size,
                                         int timeout_ms) {
  return MoonlightBridgeState::Instance().DatagramRecv(socket_fd, buffer, size, timeout_ms);
}

extern "C" int swg_compat_copy_remote_addr(int socket_fd,
                                            struct sockaddr_storage* remote_addr,
                                            socklen_t* remote_addr_len) {
  return MoonlightBridgeState::Instance().CopyRemoteAddr(socket_fd, remote_addr, remote_addr_len);
}

extern "C" int swg_compat_socket_wait(int socket_fd,
                                       int want_read,
                                       int want_write,
                                       int timeout_ms,
                                       int* can_read,
                                       int* can_write) {
  return MoonlightBridgeState::Instance().SocketWait(socket_fd, want_read, want_write,
                                                     timeout_ms, can_read, can_write);
}

extern "C" int swg_compat_close_socket(int socket_fd) {
  return MoonlightBridgeState::Instance().CloseSocket(socket_fd);
}

extern "C" int swg_compat_shutdown_socket(int socket_fd) {
  return MoonlightBridgeState::Instance().ShutdownSocket(socket_fd);
}

extern "C" int swg_compat_set_recv_timeout(int socket_fd, int timeout_ms) {
  return MoonlightBridgeState::Instance().SetRecvTimeout(socket_fd, timeout_ms);
}

extern "C" int swg_compat_enable_no_delay(int socket_fd) {
  return MoonlightBridgeState::Instance().EnableNoDelay(socket_fd);
}

extern "C" int swg_moonlight_resolve_stream_host(const char* host,
                                                 unsigned short port,
                                                 struct sockaddr_storage* addr,
                                                 socklen_t* addr_len) {
  return swg_compat_resolve_stream_host(host, port, addr, addr_len);
}

extern "C" int swg_moonlight_attach_stream_socket(int socket_fd,
                                                   const struct sockaddr_storage* remote_addr,
                                                   socklen_t remote_addr_len,
                                                   unsigned short remote_port,
                                                   int traffic_class) {
  return swg_compat_attach_stream_socket(socket_fd, remote_addr, remote_addr_len, remote_port,
                                         traffic_class);
}

extern "C" int swg_moonlight_attach_datagram_socket(int socket_fd,
                                                     const struct sockaddr_storage* remote_addr,
                                                     socklen_t remote_addr_len,
                                                     unsigned short remote_port,
                                                     int traffic_class) {
  return swg_compat_attach_datagram_socket(socket_fd, remote_addr, remote_addr_len, remote_port,
                                           traffic_class);
}

extern "C" int swg_moonlight_is_tunnel_socket(int socket_fd) {
  return swg_compat_is_tunnel_socket(socket_fd);
}

extern "C" int swg_moonlight_stream_send(int socket_fd, const void* buffer, size_t size) {
  return swg_compat_stream_send(socket_fd, buffer, size);
}

extern "C" int swg_moonlight_stream_recv(int socket_fd, void* buffer, size_t size) {
  return swg_compat_stream_recv(socket_fd, buffer, size);
}

extern "C" int swg_moonlight_datagram_send(int socket_fd,
                                            const void* buffer,
                                            size_t size,
                                            const struct sockaddr* remote_addr,
                                            socklen_t remote_addr_len) {
  return swg_compat_datagram_send(socket_fd, buffer, size, remote_addr, remote_addr_len);
}

extern "C" int swg_moonlight_datagram_recv(int socket_fd,
                                            void* buffer,
                                            size_t size,
                                            int timeout_ms) {
  return swg_compat_datagram_recv(socket_fd, buffer, size, timeout_ms);
}

extern "C" int swg_moonlight_copy_remote_addr(int socket_fd,
                                               struct sockaddr_storage* remote_addr,
                                               socklen_t* remote_addr_len) {
  return swg_compat_copy_remote_addr(socket_fd, remote_addr, remote_addr_len);
}

extern "C" int swg_moonlight_socket_wait(int socket_fd,
                                          int want_read,
                                          int want_write,
                                          int timeout_ms,
                                          int* can_read,
                                          int* can_write) {
  return swg_compat_socket_wait(socket_fd, want_read, want_write, timeout_ms, can_read,
                                can_write);
}

extern "C" int swg_moonlight_close_socket(int socket_fd) {
  return swg_compat_close_socket(socket_fd);
}

extern "C" int swg_moonlight_shutdown_socket(int socket_fd) {
  return swg_compat_shutdown_socket(socket_fd);
}

extern "C" int swg_moonlight_set_recv_timeout(int socket_fd, int timeout_ms) {
  return swg_compat_set_recv_timeout(socket_fd, timeout_ms);
}

extern "C" int swg_moonlight_enable_no_delay(int socket_fd) {
  return swg_compat_enable_no_delay(socket_fd);
}
#endif