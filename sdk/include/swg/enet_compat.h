#pragma once

#if defined(__SWITCH__) || defined(SWG_PLATFORM_SWITCH)

#include <enet/enet.h>

#ifdef __cplusplus
extern "C" {
#endif

int swg_enet_try_set_option(ENetSocket socket,
                            ENetSocketOption option,
                            int value,
                            int* result);
int swg_enet_try_get_option(ENetSocket socket,
                            ENetSocketOption option,
                            int* value,
                            int* result);
int swg_enet_try_connect(ENetSocket socket,
                         const ENetAddress* address,
                         int* result);
void swg_enet_cleanup_socket(ENetSocket socket);
int swg_enet_try_send(ENetSocket socket,
                      const ENetAddress* peer_address,
                      const ENetBuffer* buffers,
                      size_t buffer_count,
                      int* sent_length);
int swg_enet_try_receive(ENetSocket socket,
                         ENetAddress* peer_address,
                         ENetAddress* local_address,
                         ENetBuffer* buffers,
                         size_t buffer_count,
                         int* recv_length);
int swg_enet_try_wait(ENetSocket socket,
                      enet_uint32* condition,
                      enet_uint32 timeout,
                      int* result);

#ifdef __cplusplus
}
#endif

#endif