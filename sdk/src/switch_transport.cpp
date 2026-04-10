#include "swg/switch_transport.h"

#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "swg/ipc_protocol.h"
#include "swg/result.h"

#if defined(SWG_PLATFORM_SWITCH)
#include <switch.h>
#endif

namespace swg {
namespace {

#if defined(SWG_PLATFORM_SWITCH)

std::string FormatLibnxResult(::Result rc) {
  std::ostringstream stream;
  stream << "0x" << std::hex << rc << std::dec << " (module=" << R_MODULE(rc)
         << ", description=" << R_DESCRIPTION(rc) << ")";
  return stream.str();
}

Error MakeTransportError(ErrorCode code, std::string_view action, ::Result rc) {
  return MakeError(code, std::string(action) + ": " + FormatLibnxResult(rc));
}

class SwitchControlTransport final : public IClientTransport {
 public:
  ~SwitchControlTransport() override {
    std::scoped_lock lock(mutex_);
    if (serviceIsActive(&service_)) {
      serviceClose(&service_);
    }
  }

  Result<ByteBuffer> Invoke(const ByteBuffer& request_bytes) const override {
    if (request_bytes.size() > kControlPortMaxEnvelopeSize) {
      return MakeFailure<ByteBuffer>(ErrorCode::InvalidConfig,
                                     "control request exceeds transport envelope limit");
    }

    const Error connect_error = EnsureServiceConnected();
    if (connect_error) {
      return Result<ByteBuffer>::Failure(connect_error);
    }

    std::vector<std::uint8_t> response_bytes(kControlPortMaxEnvelopeSize);
    ControlPortInvokeRequest in{static_cast<std::uint32_t>(request_bytes.size())};
    ControlPortInvokeResponse out{};

    SfDispatchParams dispatch{};
    dispatch.buffer_attrs.attr0 = SfBufferAttr_HipcMapAlias | SfBufferAttr_In;
    dispatch.buffer_attrs.attr1 = SfBufferAttr_HipcMapAlias | SfBufferAttr_Out;
    dispatch.buffers[0] = {
        request_bytes.empty() ? nullptr : request_bytes.data(),
        request_bytes.size(),
    };
    dispatch.buffers[1] = {
        response_bytes.data(),
        response_bytes.size(),
    };

    std::scoped_lock lock(mutex_);
    const ::Result rc = serviceDispatchImpl(&service_, static_cast<std::uint32_t>(ControlPortCommandId::Invoke),
                                            &in, sizeof(in), &out, sizeof(out), dispatch);
    if (R_FAILED(rc)) {
      serviceClose(&service_);
      return Result<ByteBuffer>::Failure(MakeTransportError(ErrorCode::ServiceUnavailable,
                                                            "swg:ctl invoke failed", rc));
    }

    if (out.output_size > response_bytes.size()) {
      return MakeFailure<ByteBuffer>(ErrorCode::ParseError,
                                     "swg:ctl returned an oversized response envelope");
    }

    response_bytes.resize(out.output_size);
    return MakeSuccess(std::move(response_bytes));
  }

 private:
  Error EnsureServiceConnected() const {
    std::scoped_lock lock(mutex_);
    if (serviceIsActive(&service_)) {
      return Error::None();
    }

    const ::Result rc = smGetService(&service_, kControlServiceName);
    if (R_FAILED(rc)) {
      return MakeTransportError(ErrorCode::ServiceUnavailable, "failed to open swg:ctl", rc);
    }

    return Error::None();
  }

  mutable std::mutex mutex_;
  mutable Service service_{};
};

#endif

}  // namespace

std::shared_ptr<IClientTransport> CreateSwitchControlTransport() {
#if defined(SWG_PLATFORM_SWITCH)
  return std::make_shared<SwitchControlTransport>();
#else
  return {};
#endif
}

}  // namespace swg