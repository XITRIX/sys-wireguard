#include <atomic>
#include <cerrno>
#include <cstdint>
#include <csignal>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace {

constexpr std::uint16_t kDefaultTcpEchoPort = 28080;
constexpr std::uint16_t kDefaultHttpPort = 28081;
constexpr std::uint16_t kDefaultUdpEchoPort = 28082;
constexpr char kDefaultBindHost[] = "0.0.0.0";
constexpr char kDefaultHttpPath[] = "/swg/health";
constexpr int kSocketTimeoutMs = 1000;
constexpr int kListenBacklog = 8;
constexpr std::size_t kMaxReadBytes = 4096;

#if defined(_WIN32)
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

struct ServerOptions {
  std::string bind_host = kDefaultBindHost;
  std::uint16_t tcp_echo_port = kDefaultTcpEchoPort;
  std::uint16_t http_port = kDefaultHttpPort;
  std::uint16_t udp_echo_port = kDefaultUdpEchoPort;
  std::string http_path = kDefaultHttpPath;
};

std::mutex g_log_mutex;
std::atomic<bool>* g_running = nullptr;

void LogLine(const std::string& line) {
  const std::lock_guard<std::mutex> lock(g_log_mutex);
  std::cout << line << std::endl;
}

void PrintUsage(const char* program_name) {
  std::cout << "Usage: " << program_name << " [options]\n"
            << "\n"
            << "Passive SWG integration harness server with three listeners:\n"
            << "  TCP echo    exact payload echo\n"
            << "  UDP echo    exact datagram echo\n"
            << "  HTTP probe  plain HTTP 200 response with client details\n"
            << "\n"
            << "Options:\n"
            << "  --bind <host>       Bind IPv4 host (default: " << kDefaultBindHost << ")\n"
            << "  --tcp <port>        TCP echo port (default: " << kDefaultTcpEchoPort << ")\n"
            << "  --http <port>       HTTP probe port (default: " << kDefaultHttpPort << ")\n"
            << "  --udp <port>        UDP echo port (default: " << kDefaultUdpEchoPort << ")\n"
            << "  --http-path <path>  HTTP probe path (default: " << kDefaultHttpPath << ")\n"
            << "  --help              Show this message\n";
}

bool ParseU16(const std::string& value, std::uint16_t* parsed) {
  try {
    const unsigned long port = std::stoul(value);
    if (port > 65535UL) {
      return false;
    }
    *parsed = static_cast<std::uint16_t>(port);
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

bool ParseArgs(int argc, char** argv, ServerOptions* options) {
  for (int index = 1; index < argc; ++index) {
    const std::string arg = argv[index];
    if (arg == "--help") {
      PrintUsage(argv[0]);
      return false;
    }

    auto require_value = [&](const char* name) -> const char* {
      if (index + 1 >= argc) {
        std::cerr << "missing value for " << name << '\n';
        return nullptr;
      }
      return argv[++index];
    };

    if (arg == "--bind") {
      const char* value = require_value("--bind");
      if (value == nullptr) {
        return false;
      }
      options->bind_host = value;
      continue;
    }

    if (arg == "--tcp") {
      const char* value = require_value("--tcp");
      if (value == nullptr || !ParseU16(value, &options->tcp_echo_port)) {
        std::cerr << "invalid TCP echo port\n";
        return false;
      }
      continue;
    }

    if (arg == "--http") {
      const char* value = require_value("--http");
      if (value == nullptr || !ParseU16(value, &options->http_port)) {
        std::cerr << "invalid HTTP probe port\n";
        return false;
      }
      continue;
    }

    if (arg == "--udp") {
      const char* value = require_value("--udp");
      if (value == nullptr || !ParseU16(value, &options->udp_echo_port)) {
        std::cerr << "invalid UDP echo port\n";
        return false;
      }
      continue;
    }

    if (arg == "--http-path") {
      const char* value = require_value("--http-path");
      if (value == nullptr || value[0] != '/') {
        std::cerr << "HTTP path must start with '/'\n";
        return false;
      }
      options->http_path = value;
      continue;
    }

    std::cerr << "unknown option: " << arg << '\n';
    return false;
  }

  return true;
}

#if defined(_WIN32)
void CloseSocket(SocketHandle socket_handle) {
  if (socket_handle != kInvalidSocket) {
    closesocket(socket_handle);
  }
}

int LastSocketErrorCode() {
  return WSAGetLastError();
}

std::string SocketErrorString(int error_code) {
  std::ostringstream stream;
  stream << "WSA error " << error_code;
  return stream.str();
}

bool SetSocketTimeout(SocketHandle socket_handle) {
  const DWORD timeout_ms = kSocketTimeoutMs;
  return setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) == 0;
}

bool SetReuseAddr(SocketHandle socket_handle) {
  const BOOL enabled = TRUE;
  return setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR,
                    reinterpret_cast<const char*>(&enabled), sizeof(enabled)) == 0;
}

class SocketRuntime {
 public:
  SocketRuntime() {
    WSADATA data{};
    ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }

  ~SocketRuntime() {
    if (ok_) {
      WSACleanup();
    }
  }

  bool ok() const {
    return ok_;
  }

 private:
  bool ok_ = false;
};
#else
void CloseSocket(SocketHandle socket_handle) {
  if (socket_handle != kInvalidSocket) {
    close(socket_handle);
  }
}

int LastSocketErrorCode() {
  return errno;
}

std::string SocketErrorString(int error_code) {
  return std::strerror(error_code);
}

bool SetSocketTimeout(SocketHandle socket_handle) {
  timeval timeout{};
  timeout.tv_sec = kSocketTimeoutMs / 1000;
  timeout.tv_usec = (kSocketTimeoutMs % 1000) * 1000;
  return setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0;
}

bool SetReuseAddr(SocketHandle socket_handle) {
  const int enabled = 1;
  return setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0;
}

class SocketRuntime {
 public:
  bool ok() const {
    return true;
  }
};
#endif

std::string DescribeSocketFailure(const char* operation) {
  return std::string(operation) + " failed: " + SocketErrorString(LastSocketErrorCode());
}

std::string DescribePeer(const sockaddr_storage& address, socklen_t address_length) {
  char host_buffer[NI_MAXHOST] = {};
  char service_buffer[NI_MAXSERV] = {};
  const int result = getnameinfo(reinterpret_cast<const sockaddr*>(&address), address_length,
                                 host_buffer, sizeof(host_buffer), service_buffer, sizeof(service_buffer),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  if (result != 0) {
    return "<unknown-peer>";
  }

  return std::string(host_buffer) + ":" + service_buffer;
}

SocketHandle CreateBoundSocket(const std::string& bind_host,
                               std::uint16_t port,
                               int socket_type,
                               int protocol,
                               bool needs_listen,
                               std::string* error) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = socket_type;
  hints.ai_protocol = protocol;
  hints.ai_flags = AI_PASSIVE;

  addrinfo* addresses = nullptr;
  const std::string port_string = std::to_string(port);
  const char* host_arg = bind_host.empty() ? nullptr : bind_host.c_str();
  const int resolve_result = getaddrinfo(host_arg, port_string.c_str(), &hints, &addresses);
  if (resolve_result != 0) {
#if defined(_WIN32)
    *error = std::string("getaddrinfo failed: ") + std::to_string(resolve_result);
#else
    *error = std::string("getaddrinfo failed: ") + gai_strerror(resolve_result);
#endif
    return kInvalidSocket;
  }

  SocketHandle socket_handle = kInvalidSocket;
  for (addrinfo* address = addresses; address != nullptr; address = address->ai_next) {
    socket_handle = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (socket_handle == kInvalidSocket) {
      continue;
    }

    static_cast<void>(SetReuseAddr(socket_handle));
    if (!SetSocketTimeout(socket_handle)) {
      *error = DescribeSocketFailure("setsockopt(SO_RCVTIMEO)");
      CloseSocket(socket_handle);
      socket_handle = kInvalidSocket;
      continue;
    }

    if (bind(socket_handle, address->ai_addr, static_cast<socklen_t>(address->ai_addrlen)) != 0) {
      *error = DescribeSocketFailure("bind");
      CloseSocket(socket_handle);
      socket_handle = kInvalidSocket;
      continue;
    }

    if (needs_listen && listen(socket_handle, kListenBacklog) != 0) {
      *error = DescribeSocketFailure("listen");
      CloseSocket(socket_handle);
      socket_handle = kInvalidSocket;
      continue;
    }

    break;
  }

  freeaddrinfo(addresses);
  if (socket_handle == kInvalidSocket && error->empty()) {
    *error = "no usable IPv4 bind address found";
  }
  return socket_handle;
}

std::string ReadPayload(SocketHandle socket_handle, bool stop_at_http_headers) {
  std::string payload;
  payload.reserve(kMaxReadBytes);
  char buffer[1024] = {};

  while (payload.size() < kMaxReadBytes) {
    const int received = recv(socket_handle, buffer, sizeof(buffer), 0);
    if (received <= 0) {
      break;
    }

    payload.append(buffer, buffer + received);
    if (stop_at_http_headers && payload.find("\r\n\r\n") != std::string::npos) {
      break;
    }

    if (!stop_at_http_headers) {
      break;
    }
  }

  return payload;
}

struct HttpRequestLine {
  std::string method;
  std::string path;
  std::string version;
};

HttpRequestLine ParseHttpRequestLine(const std::string& request) {
  HttpRequestLine line{};
  const std::size_t end = request.find("\r\n");
  const std::string first_line = request.substr(0, end);

  std::istringstream stream(first_line);
  stream >> line.method >> line.path >> line.version;
  return line;
}

void HandleTcpEchoClient(SocketHandle client_socket, const std::string& peer) {
  static_cast<void>(SetSocketTimeout(client_socket));
  const std::string payload = ReadPayload(client_socket, false);
  if (!payload.empty()) {
    const int sent = send(client_socket, payload.data(), static_cast<int>(payload.size()), 0);
    if (sent != static_cast<int>(payload.size())) {
      LogLine("[tcp] short echo to " + peer);
    } else {
      LogLine("[tcp] echoed " + std::to_string(payload.size()) + " bytes to " + peer);
    }
  } else {
    LogLine("[tcp] empty payload from " + peer);
  }

  CloseSocket(client_socket);
}

void HandleHttpClient(SocketHandle client_socket, const std::string& peer, const ServerOptions& options) {
  static_cast<void>(SetSocketTimeout(client_socket));
  const std::string request = ReadPayload(client_socket, true);
  const HttpRequestLine request_line = ParseHttpRequestLine(request);
  const bool path_match = request_line.path == options.http_path;
  const std::string body =
      std::string("service=swg-integration-server\nkind=http\nclient=") + peer +
      "\nmethod=" + request_line.method + "\npath=" + request_line.path + "\n";

  std::ostringstream response;
  response << (path_match ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 404 Not Found\r\n");
  response << "Content-Type: text/plain\r\n";
  response << "Content-Length: " << body.size() << "\r\n";
  response << "Connection: close\r\n\r\n";
  response << body;

  const std::string bytes = response.str();
  const int sent = send(client_socket, bytes.data(), static_cast<int>(bytes.size()), 0);
  if (sent != static_cast<int>(bytes.size())) {
    LogLine("[http] short response to " + peer + " path=" + request_line.path);
  } else {
    LogLine(std::string("[http] ") + (path_match ? "200" : "404") + " to " + peer +
            " path=" + request_line.path);
  }

  CloseSocket(client_socket);
}

void RunTcpEchoServer(const ServerOptions& options, std::atomic<bool>* running) {
  std::string error;
  SocketHandle listener = CreateBoundSocket(options.bind_host, options.tcp_echo_port, SOCK_STREAM, IPPROTO_TCP,
                                            true, &error);
  if (listener == kInvalidSocket) {
    LogLine("[tcp] startup failed: " + error);
    running->store(false);
    return;
  }

  LogLine("[tcp] listening on " + options.bind_host + ":" + std::to_string(options.tcp_echo_port));
  while (running->load()) {
    sockaddr_storage address{};
    socklen_t address_length = sizeof(address);
    SocketHandle client_socket = accept(listener, reinterpret_cast<sockaddr*>(&address), &address_length);
    if (client_socket == kInvalidSocket) {
      const int error_code = LastSocketErrorCode();
#if defined(_WIN32)
      if (error_code == WSAETIMEDOUT || error_code == WSAEWOULDBLOCK) {
#else
      if (error_code == EAGAIN || error_code == EWOULDBLOCK) {
#endif
        continue;
      }
      LogLine("[tcp] accept failed: " + SocketErrorString(error_code));
      continue;
    }

    HandleTcpEchoClient(client_socket, DescribePeer(address, address_length));
  }

  CloseSocket(listener);
}

void RunHttpServer(const ServerOptions& options, std::atomic<bool>* running) {
  std::string error;
  SocketHandle listener = CreateBoundSocket(options.bind_host, options.http_port, SOCK_STREAM, IPPROTO_TCP,
                                            true, &error);
  if (listener == kInvalidSocket) {
    LogLine("[http] startup failed: " + error);
    running->store(false);
    return;
  }

  LogLine("[http] listening on " + options.bind_host + ":" + std::to_string(options.http_port) +
          " path=" + options.http_path);
  while (running->load()) {
    sockaddr_storage address{};
    socklen_t address_length = sizeof(address);
    SocketHandle client_socket = accept(listener, reinterpret_cast<sockaddr*>(&address), &address_length);
    if (client_socket == kInvalidSocket) {
      const int error_code = LastSocketErrorCode();
#if defined(_WIN32)
      if (error_code == WSAETIMEDOUT || error_code == WSAEWOULDBLOCK) {
#else
      if (error_code == EAGAIN || error_code == EWOULDBLOCK) {
#endif
        continue;
      }
      LogLine("[http] accept failed: " + SocketErrorString(error_code));
      continue;
    }

    HandleHttpClient(client_socket, DescribePeer(address, address_length), options);
  }

  CloseSocket(listener);
}

void RunUdpEchoServer(const ServerOptions& options, std::atomic<bool>* running) {
  std::string error;
  SocketHandle socket_handle =
      CreateBoundSocket(options.bind_host, options.udp_echo_port, SOCK_DGRAM, IPPROTO_UDP, false, &error);
  if (socket_handle == kInvalidSocket) {
    LogLine("[udp] startup failed: " + error);
    running->store(false);
    return;
  }

  LogLine("[udp] listening on " + options.bind_host + ":" + std::to_string(options.udp_echo_port));
  std::vector<char> buffer(2048);
  while (running->load()) {
    sockaddr_storage address{};
    socklen_t address_length = sizeof(address);
    const int received = recvfrom(socket_handle, buffer.data(), static_cast<int>(buffer.size()), 0,
                                  reinterpret_cast<sockaddr*>(&address), &address_length);
    if (received < 0) {
      const int error_code = LastSocketErrorCode();
#if defined(_WIN32)
      if (error_code == WSAETIMEDOUT || error_code == WSAEWOULDBLOCK) {
#else
      if (error_code == EAGAIN || error_code == EWOULDBLOCK) {
#endif
        continue;
      }
      LogLine("[udp] recvfrom failed: " + SocketErrorString(error_code));
      continue;
    }

    const int sent = sendto(socket_handle, buffer.data(), received, 0,
                            reinterpret_cast<const sockaddr*>(&address), address_length);
    const std::string peer = DescribePeer(address, address_length);
    if (sent != received) {
      LogLine("[udp] short echo to " + peer);
    } else {
      LogLine("[udp] echoed " + std::to_string(received) + " bytes to " + peer);
    }
  }

  CloseSocket(socket_handle);
}

void SignalHandler(int signal_number) {
  if (g_running != nullptr) {
    g_running->store(false);
  }

  std::ostringstream stream;
  stream << "signal " << signal_number << " received, shutting down";
  LogLine(stream.str());
}

}  // namespace

int main(int argc, char** argv) {
  ServerOptions options{};
  if (!ParseArgs(argc, argv, &options)) {
    return argc == 2 && std::string(argv[1]) == "--help" ? 0 : 1;
  }

  SocketRuntime runtime;
  if (!runtime.ok()) {
    std::cerr << "failed to initialize socket runtime" << std::endl;
    return 1;
  }

  std::atomic<bool> running{true};
  g_running = &running;
  std::signal(SIGINT, SignalHandler);
#if defined(SIGTERM)
  std::signal(SIGTERM, SignalHandler);
#endif

  LogLine("Switch WireGuard integration server");
  LogLine("bind=" + options.bind_host + " tcp=" + std::to_string(options.tcp_echo_port) +
          " http=" + std::to_string(options.http_port) + " udp=" + std::to_string(options.udp_echo_port) +
          " path=" + options.http_path);
  LogLine("IPv4 only: matches the current SWG tunnel transport coverage");

  std::thread tcp_thread([&options, &running]() {
    RunTcpEchoServer(options, &running);
  });
  std::thread http_thread([&options, &running]() {
    RunHttpServer(options, &running);
  });
  std::thread udp_thread([&options, &running]() {
    RunUdpEchoServer(options, &running);
  });

  tcp_thread.join();
  http_thread.join();
  udp_thread.join();
  LogLine("integration server stopped");
  return 0;
}