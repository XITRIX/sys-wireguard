#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include <switch.h>

#include "swg/control_service.h"
#include "swg/ipc_codec.h"
#include "swg/ipc_protocol.h"
#include "swg/log.h"
#include "swg_sysmodule/local_service.h"

namespace {

constexpr std::size_t kInnerHeapSize = 0x80000;
constexpr std::size_t kMaxSessionCount = 8;
constexpr std::uint16_t kServerPointerBufferSize = 0;

constexpr const char* kBootMarkerDir = "sdmc:/atmosphere/logs/swg";
constexpr const char* kBootMarkerPath = "sdmc:/atmosphere/logs/swg/boot_marker.log";

bool g_fs_initialized = false;
bool g_sdmc_mounted = false;

std::string FormatLibnxResult(::Result rc) {
  std::ostringstream stream;
  stream << "0x" << std::hex << rc << std::dec << " (module=" << R_MODULE(rc)
         << ", description=" << R_DESCRIPTION(rc) << ")";
  return stream.str();
}

::Result MakeLibnxBadInput() {
  return MAKERESULT(Module_Libnx, LibnxError_BadInput);
}

::Result MakeLibnxNoMemory() {
  return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
}

void EnsureBootMarkerDir() {
  mkdir("sdmc:/atmosphere", 0777);
  mkdir("sdmc:/atmosphere/logs", 0777);
  mkdir(kBootMarkerDir, 0777);
}

void WriteBootMarker(const char* stage) {
  EnsureBootMarkerDir();

  FILE* output = std::fopen(kBootMarkerPath, "a");
  if (output == nullptr) {
    return;
  }

  std::fprintf(output, "%s\n", stage);
  std::fclose(output);
}

void InitializeOptionalRuntimeServices() {
  ::Result rc = setsysInitialize();
  if (R_SUCCEEDED(rc)) {
    SetSysFirmwareVersion firmware{};
    rc = setsysGetFirmwareVersion(&firmware);
    if (R_SUCCEEDED(rc)) {
      hosversionSet(MAKEHOSVERSION(firmware.major, firmware.minor, firmware.micro));
    }
    setsysExit();
  }

  rc = fsInitialize();
  if (R_FAILED(rc)) {
    return;
  }
  g_fs_initialized = true;

  rc = fsdevMountSdmc();
  if (R_FAILED(rc)) {
    return;
  }
  g_sdmc_mounted = true;

  WriteBootMarker("main: sdmc mounted");
}

void PrepareCmifResponse(::Result rc, const void* payload, std::size_t payload_size) {
  auto* base = armGetTls();
  const auto data_words = static_cast<std::uint32_t>((0x10 + sizeof(CmifOutHeader) + payload_size + 3) / 4);
  HipcMetadata metadata{};
  metadata.num_data_words = data_words;
  HipcRequest hipc = hipcMakeRequest(base, metadata);

  auto* header = static_cast<CmifOutHeader*>(cmifGetAlignedDataStart(hipc.data_words, base));
  header->magic = CMIF_OUT_HEADER_MAGIC;
  header->version = 0;
  header->result = rc;
  header->token = 0;

  if (payload_size > 0) {
    std::memcpy(header + 1, payload, payload_size);
  }
}

void PrepareBlankHipcMessage() {
  hipcMakeRequestInline(armGetTls());
}

struct InvokeBuffers {
  const std::uint8_t* request_data = nullptr;
  std::size_t request_size = 0;
  std::uint8_t* response_data = nullptr;
  std::size_t response_capacity = 0;
};

::Result ParseInvokeBuffers(const HipcParsedRequest& request, InvokeBuffers* out_buffers) {
  if (request.meta.num_send_buffers < 1 || request.meta.num_recv_buffers < 1) {
    return MakeLibnxBadInput();
  }

  auto* base = armGetTls();
  const auto* header = static_cast<const CmifInHeader*>(cmifGetAlignedDataStart(request.data.data_words, base));
  const std::size_t data_size = static_cast<std::size_t>(request.meta.num_data_words) * sizeof(std::uint32_t);
  if (data_size < sizeof(CmifInHeader) + sizeof(swg::ControlPortInvokeRequest)) {
    return MakeLibnxBadInput();
  }

  if (header->magic != CMIF_IN_HEADER_MAGIC ||
      header->command_id != static_cast<std::uint32_t>(swg::ControlPortCommandId::Invoke)) {
    return MakeLibnxBadInput();
  }

  const auto* invoke = reinterpret_cast<const swg::ControlPortInvokeRequest*>(header + 1);
  const auto request_size = hipcGetBufferSize(&request.data.send_buffers[0]);
  if (invoke->input_size != request_size || request_size > swg::kControlPortMaxEnvelopeSize) {
    return MakeLibnxBadInput();
  }

  out_buffers->request_data = static_cast<const std::uint8_t*>(hipcGetBufferAddress(&request.data.send_buffers[0]));
  out_buffers->request_size = request_size;
  out_buffers->response_data = static_cast<std::uint8_t*>(hipcGetBufferAddress(&request.data.recv_buffers[0]));
  out_buffers->response_capacity = hipcGetBufferSize(&request.data.recv_buffers[0]);

  if ((out_buffers->request_size > 0 && out_buffers->request_data == nullptr) ||
      out_buffers->response_data == nullptr || out_buffers->response_capacity == 0) {
    return MakeLibnxBadInput();
  }

  return 0;
}

::Result DispatchEnvelopeRequest(swg::IControlService& service, const InvokeBuffers& buffers,
                                 swg::ControlPortInvokeResponse* out_response) {
  swg::ByteBuffer request_bytes(buffers.request_size);
  if (buffers.request_size > 0) {
    std::memcpy(request_bytes.data(), buffers.request_data, buffers.request_size);
  }

  swg::Result<swg::ByteBuffer> dispatch_result = swg::DispatchIpcCommand(service, request_bytes);
  swg::ByteBuffer response_bytes;
  if (!dispatch_result.ok()) {
    const auto fallback = swg::EncodeResponseMessage(
        swg::IpcResponseMessage{swg::kAbiVersion, dispatch_result.error, swg::EncodeEmptyPayload()});
    if (!fallback.ok()) {
      swg::LogError("sysmodule", "failed to encode fallback response: " + fallback.error.message);
      return MakeLibnxBadInput();
    }
    response_bytes = fallback.value;
  } else {
    response_bytes = std::move(dispatch_result.value);
  }

  if (response_bytes.size() > buffers.response_capacity ||
      response_bytes.size() > swg::kControlPortMaxEnvelopeSize) {
    swg::LogWarning("sysmodule", "control response exceeded the client buffer capacity");
    return MakeLibnxNoMemory();
  }

  if (!response_bytes.empty()) {
    std::memcpy(buffers.response_data, response_bytes.data(), response_bytes.size());
  }

  out_response->output_size = static_cast<std::uint32_t>(response_bytes.size());
  return 0;
}

::Result HandleControlRequest(const HipcParsedRequest& request) {
  auto* base = armGetTls();
  const auto* header = static_cast<const CmifInHeader*>(cmifGetAlignedDataStart(request.data.data_words, base));
  const std::size_t data_size = static_cast<std::size_t>(request.meta.num_data_words) * sizeof(std::uint32_t);
  if (data_size < sizeof(CmifInHeader) || header->magic != CMIF_IN_HEADER_MAGIC) {
    return MakeLibnxBadInput();
  }

  switch (header->command_id) {
    case 3:
      PrepareCmifResponse(0, &kServerPointerBufferSize, sizeof(kServerPointerBufferSize));
      return 0;
    default:
      return MakeLibnxBadInput();
  }
}

class SwitchControlServer {
 public:
  explicit SwitchControlServer(std::shared_ptr<swg::IControlService> service) : service_(std::move(service)) {
    handles_.fill(INVALID_HANDLE);
  }

  ~SwitchControlServer() {
    Shutdown();
  }

  ::Result Initialize() {
    if (!service_) {
      return MakeLibnxBadInput();
    }

    const ::Result rc = smRegisterService(&handles_[0], smEncodeName(swg::kControlServiceName), false,
                                          static_cast<s32>(kMaxSessionCount));
    if (R_SUCCEEDED(rc)) {
      handle_count_ = 1;
      swg::LogInfo("sysmodule", "registered swg:ctl service port");
    }

    return rc;
  }

  ::Result Run() {
    while (true) {
      const ::Result rc = ProcessNextHandle();
      if (R_FAILED(rc)) {
        if (rc == KERNELRESULT(ConnectionClosed)) {
          continue;
        }
        return rc;
      }
    }
  }

 private:
  void Shutdown() {
    if (handle_count_ == 0) {
      return;
    }

    for (std::size_t index = 0; index < handle_count_; ++index) {
      if (handles_[index] != INVALID_HANDLE) {
        svcCloseHandle(handles_[index]);
        handles_[index] = INVALID_HANDLE;
      }
    }

    handle_count_ = 0;
    smUnregisterService(smEncodeName(swg::kControlServiceName));
  }

  ::Result ProcessNextHandle() {
    s32 signaled_index = -1;
    const ::Result wait_result = svcWaitSynchronization(&signaled_index, handles_.data(), handle_count_, UINT64_MAX);
    if (R_FAILED(wait_result)) {
      return wait_result;
    }

    if (signaled_index < 0 || static_cast<std::size_t>(signaled_index) >= handle_count_) {
      return MakeLibnxBadInput();
    }

    if (signaled_index == 0) {
      return AcceptSession();
    }

    return ProcessSession(static_cast<std::size_t>(signaled_index));
  }

  ::Result AcceptSession() {
    Handle session = INVALID_HANDLE;
    const ::Result rc = svcAcceptSession(&session, handles_[0]);
    if (R_FAILED(rc)) {
      return rc;
    }

    if (handle_count_ >= handles_.size()) {
      svcCloseHandle(session);
      swg::LogWarning("sysmodule", "rejected swg:ctl session because the server is at capacity");
      return 0;
    }

    handles_[handle_count_] = session;
    ++handle_count_;
    swg::LogInfo("sysmodule", "accepted swg:ctl client session");
    return 0;
  }

  void CloseSession(std::size_t handle_index) {
    if (handle_index == 0 || handle_index >= handle_count_) {
      return;
    }

    svcCloseHandle(handles_[handle_index]);
    for (std::size_t index = handle_index; index + 1 < handle_count_; ++index) {
      handles_[index] = handles_[index + 1];
    }
    handles_[handle_count_ - 1] = INVALID_HANDLE;
    --handle_count_;
    swg::LogInfo("sysmodule", "closed swg:ctl client session");
  }

  ::Result ProcessSession(std::size_t handle_index) {
    s32 unused_index = -1;
    PrepareBlankHipcMessage();
    const ::Result receive_result = svcReplyAndReceive(&unused_index, &handles_[handle_index], 1, INVALID_HANDLE,
                                                       UINT64_MAX);
    if (R_FAILED(receive_result)) {
      swg::LogWarning("sysmodule", "failed to receive swg:ctl request: " + FormatLibnxResult(receive_result));
      CloseSession(handle_index);
      return receive_result;
    }

    const HipcParsedRequest request = hipcParseRequest(armGetTls());
    bool close_session = false;
    switch (request.meta.type) {
      case CmifCommandType_Request: {
        swg::ControlPortInvokeResponse response{};
        const ::Result handler_result = HandleInvokeRequest(request, &response);
        if (R_SUCCEEDED(handler_result)) {
          PrepareCmifResponse(handler_result, &response, sizeof(response));
        } else {
          swg::LogWarning("sysmodule", "rejected malformed swg:ctl request: " + FormatLibnxResult(handler_result));
          PrepareCmifResponse(handler_result, nullptr, 0);
        }
        break;
      }
      case CmifCommandType_Control: {
        const ::Result control_result = HandleControlRequest(request);
        if (R_SUCCEEDED(control_result)) {
          break;
        }

        swg::LogWarning("sysmodule", "rejected unsupported swg:ctl control request: " +
                                        FormatLibnxResult(control_result));
        PrepareCmifResponse(control_result, nullptr, 0);
        break;
      }
      case CmifCommandType_Close:
        close_session = true;
        PrepareCmifResponse(0, nullptr, 0);
        break;
      default:
        PrepareCmifResponse(MakeLibnxBadInput(), nullptr, 0);
        break;
    }

    const ::Result reply_result = svcReplyAndReceive(&unused_index, &handles_[handle_index], 0,
                                                     handles_[handle_index], 0);
    if (reply_result == KERNELRESULT(TimedOut)) {
      return 0;
    }

    if (R_FAILED(reply_result) || close_session) {
      if (R_FAILED(reply_result)) {
        swg::LogWarning("sysmodule", "failed to reply to swg:ctl client: " + FormatLibnxResult(reply_result));
      }
      CloseSession(handle_index);
    }

    return reply_result;
  }

  ::Result HandleInvokeRequest(const HipcParsedRequest& request,
                               swg::ControlPortInvokeResponse* out_response) const {
    InvokeBuffers buffers{};
    const ::Result parse_result = ParseInvokeBuffers(request, &buffers);
    if (R_FAILED(parse_result)) {
      return parse_result;
    }

    return DispatchEnvelopeRequest(*service_, buffers, out_response);
  }

  std::shared_ptr<swg::IControlService> service_;
  std::array<Handle, kMaxSessionCount + 1> handles_{};
  std::size_t handle_count_ = 0;
};

}  // namespace

extern "C" {

u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;

void __libnx_initheap(void) {
  static std::uint8_t inner_heap[kInnerHeapSize];
  extern void* fake_heap_start;
  extern void* fake_heap_end;

  fake_heap_start = inner_heap;
  fake_heap_end = inner_heap + sizeof(inner_heap);
}

void __appInit(void) {
  ::Result rc = smInitialize();
  if (R_FAILED(rc)) {
    diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));
  }
}

void __appExit(void) {
  if (g_sdmc_mounted) {
    fsdevUnmountAll();
  }
  if (g_fs_initialized) {
    fsExit();
  }
  smExit();
}

}  // extern "C"

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  InitializeOptionalRuntimeServices();

  WriteBootMarker("main: entered");

  std::shared_ptr<swg::IControlService> service = swg::sysmodule::CreateLocalControlService();
  WriteBootMarker("main: service created");
  SwitchControlServer server(std::move(service));

  const ::Result init_result = server.Initialize();
  if (R_FAILED(init_result)) {
    WriteBootMarker("main: service registration failed");
    swg::LogError("sysmodule", "failed to register swg:ctl: " + FormatLibnxResult(init_result));
    return 1;
  }

  WriteBootMarker("main: service registered");
  swg::LogInfo("sysmodule", "starting swg:ctl service loop");
  const ::Result run_result = server.Run();
  if (R_FAILED(run_result)) {
    WriteBootMarker("main: service loop exited");
    swg::LogError("sysmodule", "swg:ctl service loop exited: " + FormatLibnxResult(run_result));
    return 1;
  }

  return 0;
}