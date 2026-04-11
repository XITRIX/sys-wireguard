#pragma once

#include <memory>
#include <string>

#include "swg/ipc_protocol.h"
#include "swg/result.h"
#include "swg/wg_profile.h"

namespace swg::sysmodule {

struct TunnelEngineStartRequest {
  std::string profile_name;
  ValidatedWireGuardProfile profile;
  RuntimeFlags runtime_flags = 0;
};

class IWgTunnelEngine {
 public:
  virtual ~IWgTunnelEngine() = default;

  virtual Error Start(const TunnelEngineStartRequest& request) = 0;
  virtual Error Stop() = 0;
  [[nodiscard]] virtual TunnelStats GetStats() const = 0;
  [[nodiscard]] virtual bool IsRunning() const = 0;
};

std::unique_ptr<IWgTunnelEngine> CreateStubWgTunnelEngine();

}  // namespace swg::sysmodule