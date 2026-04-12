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

class IUdpSocketRuntime {
 public:
  virtual ~IUdpSocketRuntime() = default;

  virtual Error Start() = 0;
  virtual void Stop() = 0;
  [[nodiscard]] virtual bool IsStarted() const = 0;
  [[nodiscard]] virtual Result<int> OpenUdpSocket() const = 0;
  [[nodiscard]] virtual Result<std::size_t> SendTo(int socket_fd,
                                                   const PreparedTunnelEndpoint& endpoint,
                                                   const std::uint8_t* buffer,
                                                   std::size_t size) const = 0;
  [[nodiscard]] virtual Result<ReceivedUdpDatagram> ReceiveFrom(int socket_fd,
                                                                std::uint8_t* buffer,
                                                                std::size_t size,
                                                                std::uint32_t timeout_ms) const = 0;
  virtual void CloseSocket(int socket_fd) const = 0;
};

class BsdSocketRuntime final : public IUdpSocketRuntime {
 public:
  Error Start() override;
  void Stop() override;
  [[nodiscard]] bool IsStarted() const override;

  Result<int> OpenUdpSocket() const override;
  Result<int> OpenConnectedUdpSocket(const PreparedTunnelEndpoint& endpoint) const;
  Result<std::size_t> SendTo(int socket_fd,
                             const PreparedTunnelEndpoint& endpoint,
                             const std::uint8_t* buffer,
                             std::size_t size) const override;
  Result<std::size_t> Send(int socket_fd, const std::uint8_t* buffer, std::size_t size) const;
  Result<ReceivedUdpDatagram> ReceiveFrom(int socket_fd,
                                          std::uint8_t* buffer,
                                          std::size_t size,
                                          std::uint32_t timeout_ms) const override;
  Result<std::size_t> Receive(int socket_fd,
                              std::uint8_t* buffer,
                              std::size_t size,
                              std::uint32_t timeout_ms) const;
  void CloseSocket(int socket_fd) const override;

 private:
  bool started_ = false;
};

}  // namespace swg::sysmodule