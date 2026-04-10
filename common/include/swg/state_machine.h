#pragma once

#include <string>

#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg/result.h"

namespace swg {

struct StateSnapshot {
  TunnelState state = TunnelState::Idle;
  std::string active_profile;
  std::string last_error;
  RuntimeFlags runtime_flags = 0;
  TunnelStats stats{};
};

class ConnectionStateMachine {
 public:
  Error ApplyConfig(const Config& config);
  Error SetActiveProfile(const std::string& profile_name);
  Error SetRuntimeFlags(RuntimeFlags runtime_flags);
  Error Connect();
  Error MarkConnected();
  Error MarkConnectFailed(const std::string& message);
  Error Disconnect();
  Error MarkDisconnected();
  void UpdateStats(const TunnelStats& stats);
  [[nodiscard]] StateSnapshot snapshot() const;

 private:
  StateSnapshot snapshot_{};
};

}  // namespace swg
