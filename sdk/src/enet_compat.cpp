#include "swg/enet_compat.h"

#if defined(__SWITCH__) || defined(SWG_PLATFORM_SWITCH)

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <netinet/in.h>

#include "swg/compat_bridge_c.h"

namespace {

unsigned short GetRemotePort(const ENetAddress* address) {
    if (address == nullptr) {
        return 0;
    }

    if (address->address.ss_family == AF_INET) {
        return ENET_NET_TO_HOST_16(
            reinterpret_cast<const sockaddr_in*>(&address->address)->sin_port);
    }

#ifdef AF_INET6
    if (address->address.ss_family == AF_INET6) {
        return ENET_NET_TO_HOST_16(
            reinterpret_cast<const sockaddr_in6*>(&address->address)->sin6_port);
    }
#endif

    return 0;
}

size_t CopyBuffersToLinear(unsigned char* output,
                          const ENetBuffer* buffers,
                          size_t bufferCount) {
    size_t copied = 0;

    for (size_t index = 0; index < bufferCount; ++index) {
        std::memcpy(output + copied, buffers[index].data, buffers[index].dataLength);
        copied += buffers[index].dataLength;
    }

    return copied;
}

}  // namespace

extern "C" {

int swg_enet_try_set_option(ENetSocket socket,
                            ENetSocketOption option,
                            int value,
                            int* result) {
    if (swg_compat_is_tunnel_socket(socket) <= 0) {
        return 0;
    }

    switch (option) {
    case ENET_SOCKOPT_RCVTIMEO:
        *result = swg_compat_set_recv_timeout(socket, value) >= 0 ? 0 : -1;
        break;
    default:
        *result = 0;
        break;
    }

    return 1;
}

int swg_enet_try_get_option(ENetSocket socket,
                            ENetSocketOption option,
                            int* value,
                            int* result) {
    if (swg_compat_is_tunnel_socket(socket) <= 0) {
        return 0;
    }

    switch (option) {
    case ENET_SOCKOPT_ERROR:
        *value = 0;
        *result = 0;
        break;
    case ENET_SOCKOPT_TTL:
        *value = 64;
        *result = 0;
        break;
    default:
        *result = 0;
        break;
    }

    return 1;
}

int swg_enet_try_connect(ENetSocket socket,
                         const ENetAddress* address,
                         int* result) {
    const unsigned short port = GetRemotePort(address);

    if (port == 0) {
        return 0;
    }

    const int attachResult = swg_compat_attach_datagram_socket(
        socket,
        reinterpret_cast<const sockaddr_storage*>(&address->address),
        address->addressLength,
        port,
        SWG_COMPAT_TRAFFIC_STREAM_CONTROL);
    if (attachResult == SWG_COMPAT_ROUTE_TUNNEL) {
        *result = 0;
        return 1;
    }
    if (attachResult == SWG_COMPAT_ROUTE_ERROR) {
        *result = -1;
        return 1;
    }

    return 0;
}

void swg_enet_cleanup_socket(ENetSocket socket) {
    if (swg_compat_is_tunnel_socket(socket) > 0) {
        swg_compat_close_socket(socket);
    }
}

int swg_enet_try_send(ENetSocket socket,
                      const ENetAddress* peerAddress,
                      const ENetBuffer* buffers,
                      size_t bufferCount,
                      int* sentLength) {
    if (swg_compat_is_tunnel_socket(socket) <= 0) {
        return 0;
    }

    unsigned char* sendBuffer = nullptr;
    size_t sendLength = 0;

    for (size_t index = 0; index < bufferCount; ++index) {
        sendLength += buffers[index].dataLength;
    }

    if (bufferCount == 1) {
        sendBuffer = static_cast<unsigned char*>(buffers[0].data);
    } else {
        sendBuffer = static_cast<unsigned char*>(std::malloc(sendLength));
        if (sendBuffer == nullptr) {
            *sentLength = -1;
            return 1;
        }

        sendLength = CopyBuffersToLinear(sendBuffer, buffers, bufferCount);
    }

    *sentLength = swg_compat_datagram_send(
        socket,
        sendBuffer,
        sendLength,
        peerAddress != nullptr ? reinterpret_cast<const sockaddr*>(&peerAddress->address)
                               : nullptr,
        peerAddress != nullptr ? peerAddress->addressLength : 0);

    if (bufferCount > 1) {
        std::free(sendBuffer);
    }

    return 1;
}

int swg_enet_try_receive(ENetSocket socket,
                         ENetAddress* peerAddress,
                         ENetAddress* localAddress,
                         ENetBuffer* buffers,
                         size_t bufferCount,
                         int* recvLength) {
    if (swg_compat_is_tunnel_socket(socket) <= 0) {
        return 0;
    }

    unsigned char* recvBuffer = nullptr;
    size_t recvCapacity = 0;

    for (size_t index = 0; index < bufferCount; ++index) {
        recvCapacity += buffers[index].dataLength;
    }

    if (bufferCount == 1) {
        recvBuffer = static_cast<unsigned char*>(buffers[0].data);
    } else {
        recvBuffer = static_cast<unsigned char*>(std::malloc(recvCapacity));
        if (recvBuffer == nullptr) {
            *recvLength = -1;
            return 1;
        }
    }

    *recvLength = swg_compat_datagram_recv(socket, recvBuffer, recvCapacity, 0);
    if (*recvLength > 0) {
        if (bufferCount > 1) {
            size_t copied = 0;

            for (size_t index = 0;
                 index < bufferCount && copied < static_cast<size_t>(*recvLength);
                 ++index) {
                size_t toCopy = buffers[index].dataLength;
                if (toCopy > static_cast<size_t>(*recvLength) - copied) {
                    toCopy = static_cast<size_t>(*recvLength) - copied;
                }

                std::memcpy(buffers[index].data, recvBuffer + copied, toCopy);
                copied += toCopy;
            }

            std::free(recvBuffer);
        }

        if (peerAddress != nullptr) {
            sockaddr_storage remoteAddr;
            socklen_t remoteAddrLen = sizeof(remoteAddr);
            if (swg_compat_copy_remote_addr(socket, &remoteAddr, &remoteAddrLen) > 0) {
                std::memcpy(&peerAddress->address, &remoteAddr, remoteAddrLen);
                peerAddress->addressLength = remoteAddrLen;
            }
        }
        if (localAddress != nullptr) {
            std::memset(localAddress, 0, sizeof(*localAddress));
        }

        return 1;
    }

    if (bufferCount > 1) {
        std::free(recvBuffer);
    }

    if (*recvLength < 0 && errno == EWOULDBLOCK) {
        *recvLength = 0;
    }

    return 1;
}

int swg_enet_try_wait(ENetSocket socket,
                      enet_uint32* condition,
                      enet_uint32 timeout,
                      int* result) {
    if (swg_compat_is_tunnel_socket(socket) <= 0) {
        return 0;
    }

    int canRead = 0;
    int canWrite = 0;
    const int waitResult = swg_compat_socket_wait(
        socket,
        (*condition & ENET_SOCKET_WAIT_RECEIVE) != 0,
        (*condition & ENET_SOCKET_WAIT_SEND) != 0,
        timeout,
        &canRead,
        &canWrite);
    if (waitResult < 0) {
        *result = -1;
        return 1;
    }

    *condition = ENET_SOCKET_WAIT_NONE;
    if (canRead) {
        *condition |= ENET_SOCKET_WAIT_RECEIVE;
    }
    if (canWrite) {
        *condition |= ENET_SOCKET_WAIT_SEND;
    }

    *result = 0;
    return 1;
}

}  // extern "C"

#endif