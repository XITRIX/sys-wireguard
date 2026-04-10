#include "swg_sysmodule/host_transport.h"

#include "swg/ipc_codec.h"
#include "swg_sysmodule/local_service.h"

namespace swg::sysmodule {
namespace {

class HostInProcessTransport final : public IClientTransport {
 public:
  explicit HostInProcessTransport(std::shared_ptr<IControlService> service) : service_(std::move(service)) {}

  Result<ByteBuffer> Invoke(const ByteBuffer& request_bytes) const override {
    if (!service_) {
      return MakeFailure<ByteBuffer>(ErrorCode::ServiceUnavailable, "control service unavailable");
    }

    return DispatchIpcCommand(*service_, request_bytes);
  }

 private:
  std::shared_ptr<IControlService> service_;
};

}  // namespace

std::shared_ptr<IClientTransport> CreateHostInProcessTransport(const std::shared_ptr<IControlService>& service) {
  return std::make_shared<HostInProcessTransport>(service);
}

std::shared_ptr<IClientTransport> CreateLocalControlTransport(const std::filesystem::path& runtime_root) {
  return CreateHostInProcessTransport(CreateLocalControlService(runtime_root));
}

}  // namespace swg::sysmodule
