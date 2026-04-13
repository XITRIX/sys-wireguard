#pragma once

#if defined(__SWITCH__) || defined(SWG_PLATFORM_SWITCH)

#include "swg/compat_bridge_c.h"

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SWG_MOONLIGHT_ROUTE_ERROR = SWG_COMPAT_ROUTE_ERROR,
    SWG_MOONLIGHT_ROUTE_DIRECT = SWG_COMPAT_ROUTE_DIRECT,
    SWG_MOONLIGHT_ROUTE_TUNNEL = SWG_COMPAT_ROUTE_TUNNEL,
};

enum {
    SWG_MOONLIGHT_TRAFFIC_STREAM_CONTROL = SWG_COMPAT_TRAFFIC_STREAM_CONTROL,
    SWG_MOONLIGHT_TRAFFIC_STREAM_VIDEO = SWG_COMPAT_TRAFFIC_STREAM_VIDEO,
    SWG_MOONLIGHT_TRAFFIC_STREAM_AUDIO = SWG_COMPAT_TRAFFIC_STREAM_AUDIO,
    SWG_MOONLIGHT_TRAFFIC_STREAM_INPUT = SWG_COMPAT_TRAFFIC_STREAM_INPUT,
};

int swg_moonlight_resolve_stream_host(const char* host,
                                      unsigned short port,
                                      struct sockaddr_storage* addr,
                                      socklen_t* addr_len);
int swg_moonlight_attach_stream_socket(int socket_fd,
                                       const struct sockaddr_storage* remote_addr,
                                       socklen_t remote_addr_len,
                                       unsigned short remote_port,
                                       int traffic_class);
int swg_moonlight_attach_datagram_socket(int socket_fd,
                                         const struct sockaddr_storage* remote_addr,
                                         socklen_t remote_addr_len,
                                         unsigned short remote_port,
                                         int traffic_class);
int swg_moonlight_is_tunnel_socket(int socket_fd);
int swg_moonlight_stream_send(int socket_fd, const void* buffer, size_t size);
int swg_moonlight_stream_recv(int socket_fd, void* buffer, size_t size);
int swg_moonlight_datagram_send(int socket_fd,
                                const void* buffer,
                                size_t size,
                                const struct sockaddr* remote_addr,
                                socklen_t remote_addr_len);
int swg_moonlight_datagram_recv(int socket_fd, void* buffer, size_t size, int timeout_ms);
int swg_moonlight_copy_remote_addr(int socket_fd,
                                   struct sockaddr_storage* remote_addr,
                                   socklen_t* remote_addr_len);
int swg_moonlight_socket_wait(int socket_fd,
                              int want_read,
                              int want_write,
                              int timeout_ms,
                              int* can_read,
                              int* can_write);
int swg_moonlight_close_socket(int socket_fd);
int swg_moonlight_shutdown_socket(int socket_fd);
int swg_moonlight_set_recv_timeout(int socket_fd, int timeout_ms);
int swg_moonlight_enable_no_delay(int socket_fd);

#ifdef __cplusplus
}
#endif

#endif