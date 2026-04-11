#include "swg_sysmodule/wg_engine.h"

namespace swg::sysmodule {
namespace {

class StubWgTunnelEngine final : public IWgTunnelEngine {
 public:
  Error Start(const TunnelEngineStartRequest& request) override {
    if (running_) {
      return MakeError(ErrorCode::InvalidState, "WireGuard engine is already running");
    }

    (void)request.profile;
    (void)request.runtime_flags;
    active_profile_ = request.profile_name;
  prepared_profile_ = request.profile;
    stats_ = {};
    running_ = true;
    return Error::None();
  }

  Error Stop() override {
    if (!running_) {
      return Error::None();
    }

    running_ = false;
    active_profile_.clear();
    prepared_profile_ = {};
    stats_ = {};
    return Error::None();
  }

  TunnelStats GetStats() const override {
    return stats_;
  }

  bool IsRunning() const override {
    return running_;
  }

 private:
  std::string active_profile_;
  ValidatedWireGuardProfile prepared_profile_{};
  TunnelStats stats_{};
  bool running_ = false;
};

}  // namespace

std::unique_ptr<IWgTunnelEngine> CreateStubWgTunnelEngine() {
  return std::make_unique<StubWgTunnelEngine>();
}

}  // namespace swg::sysmodule