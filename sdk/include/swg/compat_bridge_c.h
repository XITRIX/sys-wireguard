#pragma once

#if defined(__SWITCH__) || defined(SWG_PLATFORM_SWITCH)

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SWG_COMPAT_ROUTE_ERROR = -1,
    SWG_COMPAT_ROUTE_DIRECT = 0,
    SWG_COMPAT_ROUTE_TUNNEL = 1,
};

enum {
    SWG_COMPAT_TRAFFIC_STREAM_CONTROL = 1,
    SWG_COMPAT_TRAFFIC_STREAM_VIDEO = 2,
    SWG_COMPAT_TRAFFIC_STREAM_AUDIO = 3,
    SWG_COMPAT_TRAFFIC_STREAM_INPUT = 4,
};

void swg_compat_configure_identity(const char* client_name,
                                   const char* integration_tag,
                                   const char* http_user_agent);

int swg_compat_resolve_stream_host(const char* host,
                                   unsigned short port,
                                   struct sockaddr_storage* addr,
                                   socklen_t* addr_len);
int swg_compat_attach_stream_socket(int socket_fd,
                                    const struct sockaddr_storage* remote_addr,
                                    socklen_t remote_addr_len,
                                    unsigned short remote_port,
                                    int traffic_class);
int swg_compat_attach_datagram_socket(int socket_fd,
                                      const struct sockaddr_storage* remote_addr,
                                      socklen_t remote_addr_len,
                                      unsigned short remote_port,
                                      int traffic_class);
int swg_compat_is_tunnel_socket(int socket_fd);
int swg_compat_stream_send(int socket_fd, const void* buffer, size_t size);
int swg_compat_stream_recv(int socket_fd, void* buffer, size_t size);
int swg_compat_datagram_send(int socket_fd,
                             const void* buffer,
                             size_t size,
                             const struct sockaddr* remote_addr,
                             socklen_t remote_addr_len);
int swg_compat_datagram_recv(int socket_fd, void* buffer, size_t size, int timeout_ms);
int swg_compat_copy_remote_addr(int socket_fd,
                                struct sockaddr_storage* remote_addr,
                                socklen_t* remote_addr_len);
int swg_compat_socket_wait(int socket_fd,
                           int want_read,
                           int want_write,
                           int timeout_ms,
                           int* can_read,
                           int* can_write);
int swg_compat_close_socket(int socket_fd);
int swg_compat_shutdown_socket(int socket_fd);
int swg_compat_set_recv_timeout(int socket_fd, int timeout_ms);
int swg_compat_enable_no_delay(int socket_fd);

#ifdef __cplusplus
}
#endif

#endif