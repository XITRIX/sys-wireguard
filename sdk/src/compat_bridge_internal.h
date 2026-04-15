#pragma once

#include <cstdint>
#include <string>
#include <vector>

#if defined(SWG_PLATFORM_SWITCH)
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "swg/compat_bridge.h"

namespace swg::internal {

#if defined(SWG_PLATFORM_SWITCH)
void CompatBridgeConfigureIdentity(std::string client_name,
                                   std::string integration_tag,
                                   std::string http_user_agent);

void CompatBridgeConfigureHttpCredentials(std::string certificate_path,
                                          std::string key_path);

CompatHttpRoute CompatBridgeHttpRequest(const std::string& url,
                                        std::vector<std::uint8_t>* response_body,
                                        long timeout_seconds,
                                        std::string* error);

CompatSocketRoute CompatBridgeResolveStreamHost(const std::string& host,
                                                std::uint16_t port,
                                                struct sockaddr_storage* addr,
                                                socklen_t* addr_len,
                                                std::string* error);

int CompatBridgeAttachStreamSocket(int socket_fd,
                                   const struct sockaddr_storage* remote_addr,
                                   socklen_t remote_addr_len,
                                   unsigned short remote_port,
                                   int traffic_class);

int CompatBridgeAttachDatagramSocket(int socket_fd,
                                     const struct sockaddr_storage* remote_addr,
                                     socklen_t remote_addr_len,
                                     unsigned short remote_port,
                                     int traffic_class);

int CompatBridgeIsTunnelSocket(int socket_fd);
int CompatBridgeStreamSend(int socket_fd, const void* buffer, size_t size);
int CompatBridgeStreamRecv(int socket_fd, void* buffer, size_t size);
int CompatBridgeDatagramSend(int socket_fd,
                             const void* buffer,
                             size_t size,
                             const struct sockaddr* remote_addr,
                             socklen_t remote_addr_len);
int CompatBridgeDatagramRecv(int socket_fd, void* buffer, size_t size, int timeout_ms);
int CompatBridgeCopyRemoteAddr(int socket_fd,
                               struct sockaddr_storage* remote_addr,
                               socklen_t* remote_addr_len);
int CompatBridgeSocketWait(int socket_fd,
                           int want_read,
                           int want_write,
                           int timeout_ms,
                           int* can_read,
                           int* can_write);
int CompatBridgeCloseSocket(int socket_fd);
int CompatBridgeShutdownSocket(int socket_fd);
int CompatBridgeSetRecvTimeout(int socket_fd, int timeout_ms);
int CompatBridgeEnableNoDelay(int socket_fd);
#endif

}  // namespace swg::internal