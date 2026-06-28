#if defined(SWG_PLATFORM_SWITCH)

#include "swg_sysmodule/mitm_observer_switch.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "swg/config.h"
#include "swg/hos_caps.h"
#include "swg/log.h"
#include "swg_sysmodule/experimental_mitm.h"

namespace swg::sysmodule {

bool IsExperimentalMitmObserverBuildEnabled() {
#if defined(SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER)
  return true;
#else
  return false;
#endif
}

#if defined(SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER)
namespace {

constexpr std::size_t kObserverStackSize = 0x8000;
constexpr std::size_t kQueryResponderStackSize = 0x8000;
constexpr std::uint64_t kObserverRetryDelayNs = 1'000'000'000ULL;
constexpr std::uint64_t kQueryResponderReadyPollNs = 1'000'000ULL;
constexpr std::uint32_t kQueryResponderReadyPolls = 3000;
constexpr std::uint32_t kShouldMitmCommandId = 65000;

struct AtmosphereMitmProcessInfo {
  std::uint64_t process_id;
  std::uint64_t program_id;
  std::uint64_t override_keys_held;
  std::uint64_t override_flags;
};
static_assert(sizeof(AtmosphereMitmProcessInfo) == 0x20);

struct ObservedService {
  MitmServiceTarget target = MitmServiceTarget::DnsResolver;
  const char* service_name = "";
  bool requested = false;
  bool installed = false;
  bool blocked = false;
  Handle mitm_port = INVALID_HANDLE;
  Handle query_session = INVALID_HANDLE;
};

struct QueryResponderContext {
  std::array<ObservedService, 2> services{};
  MitmRuntimeSettings settings{};
};

struct QueryCounters {
  std::atomic<std::uint64_t> total{0};
  std::atomic<std::uint64_t> unsupported{0};
  std::atomic<std::uint64_t> reply_failures{0};
  std::atomic<std::uint64_t> last_process_id{0};
  std::atomic<std::uint64_t> last_program_id{0};
  std::atomic<std::uint64_t> last_override_flags{0};
};

struct ObserverRuntime {
  Thread thread{};
  Thread query_thread{};
  QueryResponderContext query_context{};
  bool started = false;
  bool query_thread_started = false;
};

ObserverRuntime g_observer_runtime{};
std::array<QueryCounters, 2> g_query_counters{};
std::atomic<bool> g_query_responder_ready{false};
std::atomic<std::uint64_t> g_query_wait_failures{0};
std::atomic<std::uint64_t> g_query_invalid_signals{0};

::Result FormatLibnxResult(::Result rc, char* output, std::size_t output_size) {
  if (output == nullptr || output_size == 0) {
    return MAKERESULT(Module_Libnx, LibnxError_BadInput);
  }

  std::snprintf(output, output_size, "0x%x (module=%u, description=%u)", rc, R_MODULE(rc), R_DESCRIPTION(rc));
  return 0;
}

std::string FormatLibnxResult(::Result rc) {
  char buffer[96]{};
  FormatLibnxResult(rc, buffer, sizeof(buffer));
  return buffer;
}

bool IsSmResult(::Result rc, std::uint32_t description) {
  return R_MODULE(rc) == 21 && R_DESCRIPTION(rc) == description;
}

bool IsSmAlreadyRegistered(::Result rc) {
  return IsSmResult(rc, 4);
}

bool IsSmNotAllowed(::Result rc) {
  return IsSmResult(rc, 8);
}

std::string FormatHex(std::uint64_t value, int width) {
  char buffer[32]{};
  std::snprintf(buffer, sizeof(buffer), "%0*llx", width, static_cast<unsigned long long>(value));
  return buffer;
}

::Result OpenAtmosphereSession(TipcService* out) {
  Handle sm_handle = INVALID_HANDLE;
  ::Result rc = svcConnectToNamedPort(&sm_handle, "sm:");
  while (R_VALUE(rc) == KERNELRESULT(NotFound)) {
    svcSleepThread(50'000'000ULL);
    rc = svcConnectToNamedPort(&sm_handle, "sm:");
  }

  if (R_SUCCEEDED(rc)) {
    tipcCreate(out, sm_handle);
    TipcDispatchParams params{};
    params.in_send_pid = true;
    rc = tipcDispatchImpl(out, 0, nullptr, 0, nullptr, 0, params);
  }

  return rc;
}

::Result InstallAtmosphereMitm(TipcService* sm_session,
                               const char* service_name,
                               Handle* out_mitm_port,
                               Handle* out_query_session) {
  Handle handles[2] = {INVALID_HANDLE, INVALID_HANDLE};
  const SmServiceName name = smEncodeName(service_name);
  TipcDispatchParams params{};
  params.out_handle_attrs.attr0 = SfOutHandleAttr_HipcMove;
  params.out_handle_attrs.attr1 = SfOutHandleAttr_HipcMove;
  params.out_handles = handles;
  const ::Result rc = tipcDispatchImpl(sm_session, 65000, &name, sizeof(name), nullptr, 0, params);
  if (R_SUCCEEDED(rc)) {
    *out_mitm_port = handles[0];
    *out_query_session = handles[1];
  }
  return rc;
}

::Result ClearFutureMitm(TipcService* sm_session, const char* service_name) {
  const SmServiceName name = smEncodeName(service_name);
  TipcDispatchParams params{};
  return tipcDispatchImpl(sm_session, 65007, &name, sizeof(name), nullptr, 0, params);
}

void PrepareMitmQueryResponse(::Result rc, bool should_mitm) {
  auto* base = armGetTls();
  const std::uint32_t data_words =
      static_cast<std::uint32_t>((0x10 + sizeof(CmifOutHeader) + sizeof(should_mitm) + 3) / 4);
  HipcMetadata metadata{};
  metadata.num_data_words = data_words;
  HipcRequest hipc = hipcMakeRequest(base, metadata);

  auto* header = static_cast<CmifOutHeader*>(cmifGetAlignedDataStart(hipc.data_words, base));
  header->magic = CMIF_OUT_HEADER_MAGIC;
  header->version = 0;
  header->result = rc;
  header->token = 0;

  std::memcpy(header + 1, &should_mitm, sizeof(should_mitm));
}

bool ParseMitmQueryRequest(const HipcParsedRequest& request, AtmosphereMitmProcessInfo* out_info) {
  if (request.meta.type != CmifCommandType_Request &&
      request.meta.type != CmifCommandType_RequestWithContext) {
    return false;
  }

  auto* base = armGetTls();
  const auto* header = static_cast<const CmifInHeader*>(cmifGetAlignedDataStart(request.data.data_words, base));
  const std::size_t data_size = static_cast<std::size_t>(request.meta.num_data_words) * sizeof(std::uint32_t);
  if (data_size < sizeof(CmifInHeader) + sizeof(AtmosphereMitmProcessInfo)) {
    return false;
  }
  if (header->magic != CMIF_IN_HEADER_MAGIC || header->command_id != kShouldMitmCommandId) {
    return false;
  }

  std::memcpy(out_info, header + 1, sizeof(*out_info));
  return true;
}

::Result ReplyToQuerySession(Handle query_session) {
  s32 unused = -1;
  return svcReplyAndReceive(&unused, &query_session, 0, query_session, 0);
}

void ProcessQuerySession(std::size_t service_index, ObservedService& service) {
  AtmosphereMitmProcessInfo raw_info{};
  const HipcParsedRequest request = hipcParseRequest(armGetTls());
  const bool parsed = ParseMitmQueryRequest(request, &raw_info);

  PrepareMitmQueryResponse(0, false);
  const ::Result reply_result = ReplyToQuerySession(service.query_session);

  QueryCounters& counters = g_query_counters[service_index];
  counters.total.fetch_add(1, std::memory_order_relaxed);
  if (parsed) {
    counters.last_process_id.store(raw_info.process_id, std::memory_order_relaxed);
    counters.last_program_id.store(raw_info.program_id, std::memory_order_relaxed);
    counters.last_override_flags.store(raw_info.override_flags, std::memory_order_relaxed);
  } else {
    counters.unsupported.fetch_add(1, std::memory_order_relaxed);
  }
  if (reply_result != KERNELRESULT(TimedOut) && R_FAILED(reply_result)) {
    counters.reply_failures.fetch_add(1, std::memory_order_relaxed);
  }
}

void TryInstallObservedService(TipcService* sm_session, ObservedService& service) {
  if (!service.requested || service.installed || service.blocked) {
    return;
  }

  const ::Result install_result =
      InstallAtmosphereMitm(sm_session, service.service_name, &service.mitm_port, &service.query_session);
  if (R_FAILED(install_result)) {
    if (IsSmAlreadyRegistered(install_result)) {
      service.blocked = true;
      LogWarning("mitm-observer", std::string("MitM service-open observer disabled for ") +
                                      service.service_name +
                                      " because another MITM is already registered: " +
                                      FormatLibnxResult(install_result));
      return;
    }
    if (IsSmNotAllowed(install_result)) {
      service.blocked = true;
      LogWarning("mitm-observer", std::string("MitM service-open observer disabled for ") +
                                      service.service_name +
                                      " because SM denied host access: " +
                                      FormatLibnxResult(install_result));
      return;
    }
    LogWarning("mitm-observer", std::string("MitM service-open observer install pending for ") +
                                    service.service_name + ": " + FormatLibnxResult(install_result));
    return;
  }

  service.installed = true;
  LogInfo("mitm-observer", std::string("installed observe-only MitM query handles for ") + service.service_name);
}

std::array<ObservedService, 2> BuildObservedServices(const MitmRuntimeSettings& settings) {
  bool bsd_user_requested = false;
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_OBSERVER)
  bsd_user_requested = settings.enable_bsd_user_mitm;
#else
  if (settings.enable_bsd_user_mitm) {
    LogWarning("mitm-observer", "bsd:u MitM observer disabled in this build");
  }
#endif
  return {{
      {MitmServiceTarget::DnsResolver, "sfdnsres", settings.enable_dns_mitm},
      {MitmServiceTarget::BsdUser, "bsd:u", bsd_user_requested},
  }};
}

bool AnyServiceRequested(const std::array<ObservedService, 2>& services) {
  for (const ObservedService& service : services) {
    if (service.requested) {
      return true;
    }
  }
  return false;
}

bool AllRequestedServicesInstalled(const std::array<ObservedService, 2>& services) {
  for (const ObservedService& service : services) {
    if (service.requested && !service.installed && !service.blocked) {
      return false;
    }
  }
  return true;
}

bool AnyRequestedServiceInstalled(const std::array<ObservedService, 2>& services) {
  for (const ObservedService& service : services) {
    if (service.requested && service.installed) {
      return true;
    }
  }
  return false;
}

std::size_t BuildQueryWaitSet(const std::array<ObservedService, 2>& services,
                              std::array<Handle, 2>* out_handles,
                              std::array<std::size_t, 2>* out_service_indices) {
  std::size_t handle_count = 0;
  for (std::size_t index = 0; index < services.size(); ++index) {
    if (services[index].installed && services[index].query_session != INVALID_HANDLE) {
      (*out_handles)[handle_count] = services[index].query_session;
      (*out_service_indices)[handle_count] = index;
      ++handle_count;
    }
  }
  return handle_count;
}

void MitmQueryResponderThreadMain(void* arg) {
  auto* context = static_cast<QueryResponderContext*>(arg);
  g_query_responder_ready.store(true, std::memory_order_release);

  while (true) {
    std::array<Handle, 2> query_handles{};
    std::array<std::size_t, 2> service_indices{};
    const std::size_t handle_count = BuildQueryWaitSet(context->services, &query_handles, &service_indices);

    if (handle_count == 0) {
      svcSleepThread(kObserverRetryDelayNs);
      continue;
    }

    s32 signaled_index = -1;
    hipcMakeRequestInline(armGetTls());
    const ::Result wait_result =
        svcReplyAndReceive(&signaled_index, query_handles.data(), static_cast<s32>(handle_count), INVALID_HANDLE,
                           UINT64_MAX);
    if (R_FAILED(wait_result)) {
      g_query_wait_failures.fetch_add(1, std::memory_order_relaxed);
      svcSleepThread(kObserverRetryDelayNs);
      continue;
    }
    if (signaled_index < 0 || static_cast<std::size_t>(signaled_index) >= handle_count) {
      g_query_invalid_signals.fetch_add(1, std::memory_order_relaxed);
      continue;
    }

    const std::size_t service_index = service_indices[static_cast<std::size_t>(signaled_index)];
    ProcessQuerySession(service_index, context->services[service_index]);
  }
}

::Result StartMitmQueryResponderThread(const std::array<ObservedService, 2>& services,
                                       const MitmRuntimeSettings& settings) {
  if (g_observer_runtime.query_thread_started) {
    return 0;
  }

  g_observer_runtime.query_context.services = services;
  g_observer_runtime.query_context.settings = settings;
  g_query_responder_ready.store(false, std::memory_order_release);

  const int priority = 44;
  const int core_id = -2;
  const ::Result create_result =
      threadCreate(&g_observer_runtime.query_thread, MitmQueryResponderThreadMain,
                   &g_observer_runtime.query_context, nullptr, kQueryResponderStackSize, priority, core_id);
  if (R_FAILED(create_result)) {
    return create_result;
  }

  const ::Result start_result = threadStart(&g_observer_runtime.query_thread);
  if (R_FAILED(start_result)) {
    threadClose(&g_observer_runtime.query_thread);
    return start_result;
  }

  for (std::uint32_t attempt = 0; attempt < kQueryResponderReadyPolls; ++attempt) {
    if (g_query_responder_ready.load(std::memory_order_acquire)) {
      g_observer_runtime.query_thread_started = true;
      return 0;
    }
    svcSleepThread(kQueryResponderReadyPollNs);
  }

  threadClose(&g_observer_runtime.query_thread);
  return MAKERESULT(Module_Libnx, LibnxError_Timeout);
}

void LogQueryCounterSnapshots(const std::array<ObservedService, 2>& services,
                              std::array<std::uint64_t, 2>* last_totals) {
  for (std::size_t index = 0; index < services.size(); ++index) {
    const ObservedService& service = services[index];
    if (!service.requested || !service.installed) {
      continue;
    }

    const QueryCounters& counters = g_query_counters[index];
    const std::uint64_t total = counters.total.load(std::memory_order_relaxed);
    if (total == (*last_totals)[index]) {
      continue;
    }
    (*last_totals)[index] = total;

    LogInfo("mitm-observer", std::string("observe-only MitM query stats service=") + service.service_name +
                                  " total=" + std::to_string(total) +
                                  " unsupported=" +
                                  std::to_string(counters.unsupported.load(std::memory_order_relaxed)) +
                                  " reply_failures=" +
                                  std::to_string(counters.reply_failures.load(std::memory_order_relaxed)) +
                                  " last_pid=0x" +
                                  FormatHex(counters.last_process_id.load(std::memory_order_relaxed), 16) +
                                  " last_program=0x" +
                                  FormatHex(counters.last_program_id.load(std::memory_order_relaxed), 16) +
                                  " last_override_flags=0x" +
                                  FormatHex(counters.last_override_flags.load(std::memory_order_relaxed), 16));
  }

  const std::uint64_t wait_failures = g_query_wait_failures.load(std::memory_order_relaxed);
  const std::uint64_t invalid_signals = g_query_invalid_signals.load(std::memory_order_relaxed);
  if (wait_failures != 0 || invalid_signals != 0) {
    LogWarning("mitm-observer", "observe-only MitM responder anomalies: wait_failures=" +
                                    std::to_string(wait_failures) +
                                    " invalid_signals=" + std::to_string(invalid_signals));
  }
}

void ClearFutureMitmDeclarations(TipcService* sm_session, const std::array<ObservedService, 2>& services) {
  for (const ObservedService& service : services) {
    if (!service.requested || !service.installed) {
      continue;
    }

    const ::Result clear_result = ClearFutureMitm(sm_session, service.service_name);
    if (R_FAILED(clear_result)) {
      LogWarning("mitm-observer", std::string("failed to clear future MitM declaration for ") +
                                      service.service_name + ": " + FormatLibnxResult(clear_result));
      continue;
    }

    LogInfo("mitm-observer", std::string("activated observe-only MitM query hook for ") + service.service_name);
  }
}

void MitmObserverThreadMain(void*) {
  LogInfo("mitm-observer", "starting experimental MitM service-open observer thread");

  const RuntimePaths paths = DetectRuntimePaths();
  const Result<Config> config = LoadConfigFile(paths.config_file);
  if (!config.ok()) {
    LogWarning("mitm-observer", "MitM observer disabled because config could not be loaded: " +
                                    config.error.message);
    return;
  }

  MitmRuntimeSettings settings = BuildDefaultMitmRuntimeSettings(config.value);
  settings.observe_service_opens_only = true;
  settings.session_mode = MitmSessionMode::ObserveOnly;

  auto services = BuildObservedServices(settings);
  if (!AnyServiceRequested(services)) {
    LogInfo("mitm-observer", "MitM observer disabled because transparent mode is not requested");
    return;
  }

  HosCapabilities caps = DetectHosCapabilities();
  if (!caps.switch_target || !caps.atmosphere) {
    LogWarning("mitm-observer", "MitM observer disabled because Atmosphere extensions are unavailable");
    return;
  }

  TipcService sm_session{};
  const ::Result open_result = OpenAtmosphereSession(&sm_session);
  if (R_FAILED(open_result)) {
    LogWarning("mitm-observer", "failed to open Atmosphere SM session: " + FormatLibnxResult(open_result));
    return;
  }

  while (!AllRequestedServicesInstalled(services)) {
    for (ObservedService& service : services) {
      TryInstallObservedService(&sm_session, service);
    }
    if (!AllRequestedServicesInstalled(services)) {
      svcSleepThread(kObserverRetryDelayNs);
    }
  }

  if (!AnyRequestedServiceInstalled(services)) {
    LogWarning("mitm-observer", "MitM observer disabled because all requested hooks are unavailable");
    return;
  }

  const ::Result query_thread_result = StartMitmQueryResponderThread(services, settings);
  if (R_FAILED(query_thread_result)) {
    LogWarning("mitm-observer", "failed to start MitM query responder thread: " +
                                    FormatLibnxResult(query_thread_result));
    return;
  }

  ClearFutureMitmDeclarations(&sm_session, services);

  std::array<std::uint64_t, 2> last_query_totals{};
  while (true) {
    LogQueryCounterSnapshots(services, &last_query_totals);
    svcSleepThread(kObserverRetryDelayNs);
  }
}

}  // namespace

::Result StartExperimentalMitmObserverThread() {
  if (g_observer_runtime.started) {
    return 0;
  }

  const int priority = 45;
  const int core_id = -2;
  const ::Result create_result =
      threadCreate(&g_observer_runtime.thread, MitmObserverThreadMain, nullptr, nullptr, kObserverStackSize,
                   priority, core_id);
  if (R_FAILED(create_result)) {
    return create_result;
  }

  const ::Result start_result = threadStart(&g_observer_runtime.thread);
  if (R_FAILED(start_result)) {
    threadClose(&g_observer_runtime.thread);
    return start_result;
  }

  g_observer_runtime.started = true;
  return 0;
}

#else

::Result StartExperimentalMitmObserverThread() {
  LogWarning("mitm-observer", "experimental MitM service-open observer is disabled in this build");
  return 0;
}

#endif

}  // namespace swg::sysmodule

#endif
