#pragma once

#include "swg/result.h"
#include "swg_sysmodule/wg_engine.h"

namespace swg::sysmodule {

class BsdSocketRuntime {
 public:
  Error Start();
  void Stop();
  [[nodiscard]] bool IsStarted() const;

  Result<int> OpenConnectedUdpSocket(const PreparedTunnelEndpoint& endpoint) const;
  void CloseSocket(int socket_fd) const;

 private:
  bool started_ = false;
};

}  // namespace swg::sysmodule