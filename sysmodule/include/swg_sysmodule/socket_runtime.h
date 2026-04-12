#pragma once

#include <cstddef>
#include <cstdint>

#include "swg/result.h"
#include "swg_sysmodule/wg_engine.h"

namespace swg::sysmodule {

struct ReceivedUdpDatagram {
  std::size_t size = 0;
  std::array<std::uint8_t, 4> source_ipv4{};
  std::uint16_t source_port = 0;
};

class BsdSocketRuntime {
 public:
  Error Start();
  void Stop();
  [[nodiscard]] bool IsStarted() const;

  Result<int> OpenUdpSocket() const;
  Result<int> OpenConnectedUdpSocket(const PreparedTunnelEndpoint& endpoint) const;
  Result<std::size_t> SendTo(int socket_fd,
                             const PreparedTunnelEndpoint& endpoint,
                             const std::uint8_t* buffer,
                             std::size_t size) const;
  Result<std::size_t> Send(int socket_fd, const std::uint8_t* buffer, std::size_t size) const;
  Result<ReceivedUdpDatagram> ReceiveFrom(int socket_fd,
                                          std::uint8_t* buffer,
                                          std::size_t size,
                                          std::uint32_t timeout_ms) const;
  Result<std::size_t> Receive(int socket_fd,
                              std::uint8_t* buffer,
                              std::size_t size,
                              std::uint32_t timeout_ms) const;
  void CloseSocket(int socket_fd) const;

 private:
  bool started_ = false;
};

}  // namespace swg::sysmodule