#include "swg/compat_bridge.h"

#include <string>
#include <utility>
#include <vector>

#include "compat_bridge_internal.h"
#include "swg/compat_bridge_c.h"
#include "swg/moonlight_bridge_c.h"

namespace swg {

void ConfigureCompatBridgeIdentity(std::string client_name,
                                   std::string integration_tag,
                                   std::string http_user_agent) {
#if defined(SWG_PLATFORM_SWITCH)
  internal::CompatBridgeConfigureIdentity(std::move(client_name),
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
  internal::CompatBridgeConfigureHttpCredentials(std::move(certificate_path), std::move(key_path));
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
  return internal::CompatBridgeHttpRequest(url, response_body, timeout_seconds, error);
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
  return internal::CompatBridgeResolveStreamHost(host, port, addr, addr_len, error);
}
#endif

}  // namespace swg

#if defined(SWG_PLATFORM_SWITCH)
extern "C" void swg_compat_configure_identity(const char* client_name,
                                               const char* integration_tag,
                                               const char* http_user_agent) {
  swg::internal::CompatBridgeConfigureIdentity(client_name == nullptr ? std::string{} : std::string(client_name),
                                               integration_tag == nullptr ? std::string{} : std::string(integration_tag),
                                               http_user_agent == nullptr ? std::string{} : std::string(http_user_agent));
}

extern "C" int swg_compat_resolve_stream_host(const char* host,
                                               unsigned short port,
                                               struct sockaddr_storage* addr,
                                               socklen_t* addr_len) {
  std::string ignored_error;
  return static_cast<int>(swg::internal::CompatBridgeResolveStreamHost(
      host == nullptr ? std::string{} : std::string(host), port, addr, addr_len, &ignored_error));
}

extern "C" int swg_compat_attach_stream_socket(int socket_fd,
                                                const struct sockaddr_storage* remote_addr,
                                                socklen_t remote_addr_len,
                                                unsigned short remote_port,
                                                int traffic_class) {
  return swg::internal::CompatBridgeAttachStreamSocket(socket_fd, remote_addr, remote_addr_len,
                                                       remote_port, traffic_class);
}

extern "C" int swg_compat_attach_datagram_socket(int socket_fd,
                                                  const struct sockaddr_storage* remote_addr,
                                                  socklen_t remote_addr_len,
                                                  unsigned short remote_port,
                                                  int traffic_class) {
  return swg::internal::CompatBridgeAttachDatagramSocket(socket_fd, remote_addr, remote_addr_len,
                                                         remote_port, traffic_class);
}

extern "C" int swg_compat_is_tunnel_socket(int socket_fd) {
  return swg::internal::CompatBridgeIsTunnelSocket(socket_fd);
}

extern "C" int swg_compat_stream_send(int socket_fd, const void* buffer, size_t size) {
  return swg::internal::CompatBridgeStreamSend(socket_fd, buffer, size);
}

extern "C" int swg_compat_stream_recv(int socket_fd, void* buffer, size_t size) {
  return swg::internal::CompatBridgeStreamRecv(socket_fd, buffer, size);
}

extern "C" int swg_compat_datagram_send(int socket_fd,
                                         const void* buffer,
                                         size_t size,
                                         const struct sockaddr* remote_addr,
                                         socklen_t remote_addr_len) {
  return swg::internal::CompatBridgeDatagramSend(socket_fd, buffer, size, remote_addr,
                                                 remote_addr_len);
}

extern "C" int swg_compat_datagram_recv(int socket_fd,
                                         void* buffer,
                                         size_t size,
                                         int timeout_ms) {
  return swg::internal::CompatBridgeDatagramRecv(socket_fd, buffer, size, timeout_ms);
}

extern "C" int swg_compat_copy_remote_addr(int socket_fd,
                                            struct sockaddr_storage* remote_addr,
                                            socklen_t* remote_addr_len) {
  return swg::internal::CompatBridgeCopyRemoteAddr(socket_fd, remote_addr, remote_addr_len);
}

extern "C" int swg_compat_socket_wait(int socket_fd,
                                       int want_read,
                                       int want_write,
                                       int timeout_ms,
                                       int* can_read,
                                       int* can_write) {
  return swg::internal::CompatBridgeSocketWait(socket_fd, want_read, want_write, timeout_ms,
                                               can_read, can_write);
}

extern "C" int swg_compat_close_socket(int socket_fd) {
  return swg::internal::CompatBridgeCloseSocket(socket_fd);
}

extern "C" int swg_compat_shutdown_socket(int socket_fd) {
  return swg::internal::CompatBridgeShutdownSocket(socket_fd);
}

extern "C" int swg_compat_set_recv_timeout(int socket_fd, int timeout_ms) {
  return swg::internal::CompatBridgeSetRecvTimeout(socket_fd, timeout_ms);
}

extern "C" int swg_compat_enable_no_delay(int socket_fd) {
  return swg::internal::CompatBridgeEnableNoDelay(socket_fd);
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