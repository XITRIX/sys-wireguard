#include "swg/state_machine.h"

namespace swg {

Error ConnectionStateMachine::ApplyConfig(const Config& config) {
  snapshot_.active_profile = config.active_profile;
  snapshot_.runtime_flags = config.runtime_flags;
  snapshot_.last_error.clear();
  snapshot_.state = config.profiles.empty() ? TunnelState::Idle : TunnelState::ConfigReady;
  return Error::None();
}

Error ConnectionStateMachine::SetActiveProfile(const std::string& profile_name) {
  if (profile_name.empty()) {
    return MakeError(ErrorCode::InvalidConfig, "active profile name must not be empty");
  }

  if (snapshot_.state == TunnelState::Connected || snapshot_.state == TunnelState::Connecting ||
      snapshot_.state == TunnelState::Disconnecting) {
    return MakeError(ErrorCode::InvalidState, "cannot change active profile while tunnel is busy");
  }

  snapshot_.active_profile = profile_name;
  snapshot_.state = TunnelState::ConfigReady;
  snapshot_.last_error.clear();
  return Error::None();
}

Error ConnectionStateMachine::SetRuntimeFlags(RuntimeFlags runtime_flags) {
  snapshot_.runtime_flags = runtime_flags;
  return Error::None();
}

Error ConnectionStateMachine::Connect() {
  if (snapshot_.active_profile.empty()) {
    return MakeError(ErrorCode::InvalidState, "cannot connect without an active profile");
  }

  if (snapshot_.state == TunnelState::Connecting || snapshot_.state == TunnelState::Connected) {
    return MakeError(ErrorCode::InvalidState, "connection is already active");
  }

  if (snapshot_.state == TunnelState::Disconnecting) {
    return MakeError(ErrorCode::InvalidState, "disconnect is already in progress");
  }

  snapshot_.state = TunnelState::Connecting;
  snapshot_.last_error.clear();
  return Error::None();
}

Error ConnectionStateMachine::MarkConnected() {
  if (snapshot_.state != TunnelState::Connecting) {
    return MakeError(ErrorCode::InvalidState, "cannot mark connected outside connecting state");
  }

  snapshot_.state = TunnelState::Connected;
  return Error::None();
}

Error ConnectionStateMachine::MarkConnectFailed(const std::string& message) {
  snapshot_.state = TunnelState::Error;
  snapshot_.last_error = message;
  return Error::None();
}

Error ConnectionStateMachine::Disconnect() {
  if (snapshot_.state != TunnelState::Connected && snapshot_.state != TunnelState::Connecting &&
      snapshot_.state != TunnelState::Error) {
    return MakeError(ErrorCode::InvalidState, "no active connection to disconnect");
  }

  snapshot_.state = TunnelState::Disconnecting;
  return Error::None();
}

Error ConnectionStateMachine::MarkDisconnected() {
  if (snapshot_.state != TunnelState::Disconnecting) {
    return MakeError(ErrorCode::InvalidState, "cannot complete disconnect outside disconnecting state");
  }

  snapshot_.state = snapshot_.active_profile.empty() ? TunnelState::Idle : TunnelState::ConfigReady;
  snapshot_.last_error.clear();
  return Error::None();
}

void ConnectionStateMachine::UpdateStats(const TunnelStats& stats) {
  snapshot_.stats = stats;
}

StateSnapshot ConnectionStateMachine::snapshot() const {
  return snapshot_;
}

}  // namespace swg
