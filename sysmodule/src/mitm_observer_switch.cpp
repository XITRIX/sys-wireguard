#if defined(SWG_PLATFORM_SWITCH)

#include "swg_sysmodule/mitm_observer_switch.h"

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <new>
#include <poll.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utility>
#include <vector>

#include "swg/config.h"
#include "swg/control_service.h"
#include "swg/hos_caps.h"
#include "swg/ipc_protocol.h"
#include "swg/log.h"
#include "swg_sysmodule/experimental_dns_mitm.h"
#include "swg_sysmodule/experimental_mitm.h"
#include "swg_sysmodule/socket_runtime.h"

extern "C" {
#include <switch/services/bsd.h>
}

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
constexpr std::size_t kDnsMitmStackSize = 0x10000;
constexpr std::size_t kDnsMitmMaxSessions = 8;
constexpr std::size_t kDnsMitmMaxHostsFileSize = 0x8000;
constexpr const char* kDnsMitmStartupLogPath = "sdmc:/atmosphere/logs/dns_mitm_startup.log";
constexpr const char* kDnsMitmDebugLogPath = "sdmc:/atmosphere/logs/dns_mitm_debug.log";
constexpr std::size_t kBsdMitmMaxVirtualSockets = 16;
constexpr std::size_t kBsdMitmMaxRemoteDatagramsPerSocket = 8;
constexpr std::size_t kBsdMitmMaxPendingDatagramsPerSocket = 32;
constexpr std::size_t kBsdMitmMaxPendingSocketOptions = 8;
constexpr std::size_t kBsdMitmMaxPendingSocketOptionBytes = 32;
constexpr std::uint16_t kBsdMitmPointerBufferSize = 0x1000;
constexpr std::size_t kBsdMitmMaxHipcBufferBytes = 256 * 1024;
constexpr std::uint32_t kBsdMitmDatagramBurstMaxDatagrams = 8;
constexpr std::uint32_t kBsdMitmDatagramBurstMaxPayloadBytes = 32 * 1024;
constexpr std::size_t kBsdMitmForwardedResponseSnapshotBytes = 0x100;
constexpr std::int32_t kBsdMitmFirstVirtualFd = 4;
constexpr std::int32_t kBsdMitmInvalidNativeFd = -1;
constexpr std::int32_t kBsdSocketCreateCloseOnExec = 0x10000000;
constexpr std::int32_t kBsdSocketCreateNonBlock = 0x20000000;
constexpr std::int32_t kBsdFcntlNxNonBlock = 0x800;
constexpr std::uintptr_t kLikelyHosUserAddressLimit = 0x0000008000000000ULL;
constexpr std::int32_t kLinuxErrnoBadFileDescriptor = 9;
constexpr std::int32_t kLinuxErrnoBadAddress = 14;
constexpr std::int32_t kLinuxErrnoInvalidArgument = 22;
constexpr std::int32_t kLinuxErrnoTooManyOpenFiles = 24;
constexpr std::int32_t kLinuxErrnoWouldBlock = 11;
constexpr std::int32_t kLinuxErrnoAddressFamilyNotSupported = 97;
constexpr std::int32_t kLinuxErrnoOperationNotSupported = 95;
constexpr std::int32_t kLinuxErrnoNetworkUnreachable = 101;
constexpr std::int32_t kLinuxErrnoNotConnected = 107;
constexpr std::int32_t kLinuxErrnoAlready = 114;
constexpr std::int32_t kLinuxErrnoInProgress = 115;
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
constexpr std::size_t kBsdMitmStackSize = 0x10000;
constexpr std::size_t kBsdMitmMaxSessions = 18;
constexpr std::uint64_t kOverrideStatusFlagHbl = 1ULL << 0;
constexpr std::uint64_t kOverrideStatusFlagProgramSpecific = 1ULL << 1;
#endif

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
  std::vector<std::uint64_t> bsd_mitm_title_ids;
};

struct DnsMitmRuntimeState {
  std::optional<bool> atmosphere_builtin_dns_mitm_enabled;
  bool add_defaults = true;
  bool debug_log = false;
  bool emummc_active = false;
  std::uint32_t emummc_id = 0;
  std::string environment_identifier = "lp1";
  std::string selected_hosts_path;
  AtmosphereDnsMitmRules rules;
};

struct DnsMitmClientSession {
  Handle client_session = INVALID_HANDLE;
  Handle forward_session = INVALID_HANDLE;
  AtmosphereMitmProcessInfo client_info{};
};

struct DnsMitmServerContext {
  ObservedService service{};
  DnsMitmRuntimeState runtime{};
};

struct BsdMitmPendingDatagram {
  TunnelDatagram datagram{};
  sockaddr_storage remote_address{};
  socklen_t remote_address_length = 0;
};

struct BsdMitmRemoteDatagram {
  sockaddr_storage remote_address{};
  socklen_t remote_address_length = 0;
  std::string remote_host;
  std::uint16_t remote_port = 0;
  std::uint64_t datagram_id = 0;
};

enum class BsdMitmSocketBackend : std::uint8_t {
  Undecided = 0,
  DirectNative,
  TunnelDatagram,
};

struct BsdMitmPendingSocketOption {
  bool used = false;
  std::int32_t level = 0;
  std::int32_t optname = 0;
  socklen_t length = 0;
  std::array<std::uint8_t, kBsdMitmMaxPendingSocketOptionBytes> value{};
};

struct BsdMitmVirtualSocket {
  bool used = false;
  std::int32_t fd = 0;
  std::int32_t native_fd = kBsdMitmInvalidNativeFd;
  std::int32_t domain = 0;
  std::int32_t type = 0;
  std::int32_t protocol = 0;
  std::int32_t descriptor_flags = 0;
  std::int32_t status_flags = 0;
  BsdMitmSocketBackend backend = BsdMitmSocketBackend::Undecided;
  bool original_bsd_fd = false;
  bool bound = false;
  bool connected = false;
  sockaddr_storage local_address{};
  socklen_t local_address_length = 0;
  sockaddr_storage connected_remote_address{};
  socklen_t connected_remote_address_length = 0;
  std::array<BsdMitmPendingSocketOption, kBsdMitmMaxPendingSocketOptions> pending_options{};
  std::array<BsdMitmRemoteDatagram, kBsdMitmMaxRemoteDatagramsPerSocket> remote_datagrams{};
  std::deque<BsdMitmPendingDatagram> pending_datagrams;
  std::uint64_t send_calls = 0;
  std::uint64_t recv_calls = 0;
  std::uint64_t poll_calls = 0;
};

struct BsdMitmClientState {
  AtmosphereMitmProcessInfo client_info{};
  std::array<BsdMitmVirtualSocket, kBsdMitmMaxVirtualSockets> virtual_sockets{};
  std::int32_t next_virtual_fd = kBsdMitmFirstVirtualFd;
  std::uint64_t app_session_id = 0;
  Handle registered_tmem_handle = INVALID_HANDLE;
  bool registered = false;
  bool monitoring_started = false;
  bool original_registered = false;
  bool original_monitoring_started = false;
};

struct BsdMitmClientSession {
  Handle client_session = INVALID_HANDLE;
  Handle forward_session = INVALID_HANDLE;
  Handle preserved_request_handle = INVALID_HANDLE;
  std::int32_t reserved_original_socket_zero_fd = -1;
  std::string post_reply_log;
  AtmosphereMitmProcessInfo client_info{};
  std::shared_ptr<BsdMitmClientState> state;
  std::uint64_t request_count = 0;
  std::uint64_t handled_count = 0;
  std::uint64_t unsupported_count = 0;
};

struct BsdMitmServerContext {
  ObservedService service{};
  std::shared_ptr<IControlService> control_service;
};

struct QueryCounters {
  std::atomic<std::uint64_t> total{0};
  std::atomic<std::uint64_t> selected{0};
  std::atomic<std::uint64_t> unsupported{0};
  std::atomic<std::uint64_t> reply_failures{0};
  std::atomic<std::uint64_t> last_process_id{0};
  std::atomic<std::uint64_t> last_program_id{0};
  std::atomic<std::uint64_t> last_override_flags{0};
};

struct ObserverRuntime {
  Thread thread{};
  Thread query_thread{};
  Thread dns_thread{};
  Thread bsd_thread{};
  std::shared_ptr<IControlService> control_service;
  QueryResponderContext query_context{};
  DnsMitmServerContext dns_context{};
  BsdMitmServerContext bsd_context{};
  std::array<ObservedService, 2> installed_services{};
  bool started = false;
  bool query_thread_started = false;
  bool dns_thread_started = false;
  bool bsd_thread_started = false;
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

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
[[maybe_unused]] bool HasOverrideFlag(const AtmosphereMitmProcessInfo& info, std::uint64_t flag) {
  return (info.override_flags & flag) != 0;
}
#endif

std::vector<std::uint64_t> BuildBsdMitmTitleAllowlist(const Config& config) {
  std::vector<std::uint64_t> title_ids;
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
  for (const auto& [name, policy] : config.app_policies) {
    (void)name;
    if (policy.title_id != 0 && HasFlag(policy.requested_flags, RuntimeFlag::TransparentMode)) {
      title_ids.push_back(policy.title_id);
    }
  }
#else
  (void)config;
#endif
  return title_ids;
}

bool ShouldSelectBsdMitmClient(const AtmosphereMitmProcessInfo& info,
                               const QueryResponderContext& context) {
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
  if (std::find(context.bsd_mitm_title_ids.begin(),
                context.bsd_mitm_title_ids.end(),
                info.program_id) != context.bsd_mitm_title_ids.end()) {
    return true;
  }
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_HBL_HOST_LAB)
  return HasOverrideFlag(info, kOverrideStatusFlagHbl) ||
         HasOverrideFlag(info, kOverrideStatusFlagProgramSpecific);
#else
  return false;
#endif
#else
  (void)info;
  (void)context;
  return false;
#endif
}

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
bool ShouldLogSparseCount(std::uint64_t count) {
  return count <= 8 || (count & (count - 1)) == 0;
}

bool ShouldTraceBsdRequest(std::uint64_t count) {
  return count <= 32 || (count & (count - 1)) == 0;
}
#endif

const char* DescribeBsdMitmMode() {
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
  return "adapter lab";
#else
  return "query-only";
#endif
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

::Result UninstallAtmosphereMitm(TipcService* sm_session, const char* service_name) {
  const SmServiceName name = smEncodeName(service_name);
  TipcDispatchParams params{};
  return tipcDispatchImpl(sm_session, 65001, &name, sizeof(name), nullptr, 0, params);
}

::Result AcknowledgeAtmosphereMitmSession(TipcService* sm_session,
                                          const char* service_name,
                                          AtmosphereMitmProcessInfo* out_info,
                                          Handle* out_forward_session) {
  const SmServiceName name = smEncodeName(service_name);
  Handle forward_session = INVALID_HANDLE;
  TipcDispatchParams params{};
  params.out_handle_attrs.attr0 = SfOutHandleAttr_HipcMove;
  params.out_handles = &forward_session;
  const ::Result rc = tipcDispatchImpl(sm_session, 65003, &name, sizeof(name), out_info, sizeof(*out_info), params);
  if (R_SUCCEEDED(rc)) {
    *out_forward_session = forward_session;
  }
  return rc;
}

::Result MakeLibnxBadInput() {
  return MAKERESULT(Module_Libnx, LibnxError_BadInput);
}

std::string SdmcPath(std::string_view atmosphere_path) {
  if (atmosphere_path.rfind("sdmc:/", 0) == 0) {
    return std::string(atmosphere_path);
  }
  if (!atmosphere_path.empty() && atmosphere_path.front() == '/') {
    return "sdmc:" + std::string(atmosphere_path);
  }
  return "sdmc:/" + std::string(atmosphere_path);
}

bool FileExists(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  return input.good();
}

std::string ReadTextFileLimited(const std::string& path, std::size_t max_size) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return {};
  }

  std::ostringstream stream;
  stream << input.rdbuf();
  std::string contents = stream.str();
  if (contents.size() > max_size) {
    contents.resize(max_size);
  }
  return contents;
}

void EnsureAtmosphereDnsDirectories() {
  mkdir("sdmc:/atmosphere", 0777);
  mkdir("sdmc:/atmosphere/logs", 0777);
  mkdir("sdmc:/atmosphere/hosts", 0777);
}

void WriteTextFile(const std::string& path, const std::string& contents) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return;
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

void AppendTextFile(const std::string& path, const std::string& text) {
  std::ofstream output(path, std::ios::binary | std::ios::app);
  if (!output.is_open()) {
    return;
  }
  output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

std::optional<bool> ReadAtmosphereBoolSetting(const char* item_key) {
  std::uint8_t value = 0;
  std::uint64_t size = 0;
  const ::Result init_result = setsysInitialize();
  if (R_FAILED(init_result)) {
    return std::nullopt;
  }
  const ::Result read_result =
      setsysGetSettingsItemValue("atmosphere", item_key, &value, sizeof(value), &size);
  setsysExit();
  if (R_FAILED(read_result) || size != sizeof(value)) {
    return std::nullopt;
  }
  return value != 0;
}

std::string ReadEnvironmentIdentifier() {
  char value[0x40]{};
  std::uint64_t size = 0;
  const ::Result init_result = setsysInitialize();
  if (R_FAILED(init_result)) {
    return "lp1";
  }
  const ::Result read_result =
      setsysGetSettingsItemValue("nsd", "environment_identifier", value, sizeof(value) - 1, &size);
  setsysExit();
  if (R_FAILED(read_result) || size == 0) {
    return "lp1";
  }
  value[sizeof(value) - 1] = '\0';
  return value[0] == '\0' ? "lp1" : std::string(value);
}

void DetectEmummcFromIni(bool* out_active, std::uint32_t* out_id) {
  *out_active = false;
  *out_id = 0;

  const std::string contents = ReadTextFileLimited("sdmc:/emuMMC/emummc.ini", 4096);
  if (contents.empty()) {
    return;
  }

  std::istringstream stream(contents);
  std::string line;
  while (std::getline(stream, line)) {
    const auto comment = line.find_first_of("#;");
    if (comment != std::string::npos) {
      line.resize(comment);
    }
    const auto equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }

    std::string key = line.substr(0, equals);
    std::string value = line.substr(equals + 1);
    auto trim = [](std::string* text) {
      while (!text->empty() && std::isspace(static_cast<unsigned char>(text->front())) != 0) {
        text->erase(text->begin());
      }
      while (!text->empty() && std::isspace(static_cast<unsigned char>(text->back())) != 0) {
        text->pop_back();
      }
    };
    trim(&key);
    trim(&value);

    if (key == "enabled" || key == "emummc_enabled") {
      *out_active = value == "1" || value == "true";
    } else if (key == "id" || key == "emummc_id") {
      try {
        *out_id = static_cast<std::uint32_t>(std::stoul(value, nullptr, 0));
      } catch (const std::exception&) {
        *out_id = 0;
      }
    }
  }
}

DnsMitmRuntimeState LoadDnsMitmRuntimeState() {
  EnsureAtmosphereDnsDirectories();

  DnsMitmRuntimeState state{};
  state.atmosphere_builtin_dns_mitm_enabled = ReadAtmosphereBoolSetting("enable_dns_mitm");
  state.add_defaults = ReadAtmosphereBoolSetting("add_defaults_to_dns_hosts").value_or(true);
  state.debug_log = ReadAtmosphereBoolSetting("enable_dns_mitm_debug_log").value_or(false);
  state.environment_identifier = ReadEnvironmentIdentifier();
  DetectEmummcFromIni(&state.emummc_active, &state.emummc_id);

  WriteTextFile(kDnsMitmStartupLogPath, "SWG DNS MitM:\n");
  AppendTextFile(kDnsMitmStartupLogPath, "SWG replacement enabled by build configuration.\n");
  if (state.atmosphere_builtin_dns_mitm_enabled.has_value()) {
    AppendTextFile(kDnsMitmStartupLogPath,
                   "atmosphere!enable_dns_mitm=" +
                       (*state.atmosphere_builtin_dns_mitm_enabled ? std::string("true") : std::string("false")) +
                       " (false is expected when SWG replaces Atmosphere DNS MITM)\n");
  } else {
    AppendTextFile(kDnsMitmStartupLogPath,
                   "atmosphere!enable_dns_mitm unavailable; continuing with SWG replacement enabled.\n");
  }

  const std::string default_hosts_path = SdmcPath(AtmosphereDnsDefaultHostsPath());
  if (!FileExists(default_hosts_path)) {
    WriteTextFile(default_hosts_path, DefaultAtmosphereDnsHostsFile());
    AppendTextFile(kDnsMitmStartupLogPath, "Created /atmosphere/hosts/default.txt.\n");
  }

  const std::vector<std::string> candidates =
      AtmosphereDnsHostsFileSearchOrder(state.emummc_active, state.emummc_id);
  for (const std::string& candidate : candidates) {
    const std::string sdmc_candidate = SdmcPath(candidate);
    if (FileExists(sdmc_candidate)) {
      state.selected_hosts_path = candidate;
      break;
    }
  }
  if (state.selected_hosts_path.empty()) {
    state.selected_hosts_path = AtmosphereDnsDefaultHostsPath();
  }

  const std::string hosts_text = ReadTextFileLimited(SdmcPath(state.selected_hosts_path), kDnsMitmMaxHostsFileSize);
  state.rules = BuildAtmosphereDnsMitmRules(hosts_text, state.environment_identifier, state.add_defaults);

  AppendTextFile(kDnsMitmStartupLogPath,
                 "Selected " + state.selected_hosts_path + "\n" +
                     "environment_identifier=" + state.environment_identifier + "\n" +
                     "add_defaults=" + (state.add_defaults ? std::string("true") : std::string("false")) + "\n" +
                     "rules=" + std::to_string(state.rules.rules().size()) + "\n");
  for (const AtmosphereDnsRedirectRule& rule : state.rules.rules()) {
    AppendTextFile(kDnsMitmStartupLogPath,
                   "    `" + rule.host_pattern + "` -> " +
                       FormatAtmosphereDnsIpv4(rule.ipv4_address) + "\n");
  }

  return state;
}

void PrepareCmifResponseWithToken(::Result rc,
                                  std::uint32_t token,
                                  const void* payload,
                                  std::size_t payload_size) {
  auto* base = armGetTls();
  const std::uint32_t data_words =
      static_cast<std::uint32_t>((0x10 + sizeof(CmifOutHeader) + payload_size + 3) / 4);
  HipcMetadata metadata{};
  metadata.num_data_words = data_words;
  HipcRequest hipc = hipcMakeRequest(base, metadata);

  auto* header = static_cast<CmifOutHeader*>(cmifGetAlignedDataStart(hipc.data_words, base));
  header->magic = CMIF_OUT_HEADER_MAGIC;
  header->version = 0;
  header->result = rc;
  header->token = token;

  if (payload_size > 0) {
    std::memcpy(header + 1, payload, payload_size);
  }
}

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
void PrepareCmifResponseWithMoveHandle(::Result rc, std::uint32_t token, Handle move_handle) {
  auto* base = armGetTls();
  const std::uint32_t data_words = static_cast<std::uint32_t>((0x10 + sizeof(CmifOutHeader) + 3) / 4);
  HipcMetadata metadata{};
  metadata.num_data_words = data_words;
  metadata.num_move_handles = R_SUCCEEDED(rc) && move_handle != INVALID_HANDLE ? 1 : 0;
  HipcRequest hipc = hipcMakeRequest(base, metadata);
  if (metadata.num_move_handles != 0) {
    hipc.move_handles[0] = move_handle;
  }

  auto* header = static_cast<CmifOutHeader*>(cmifGetAlignedDataStart(hipc.data_words, base));
  header->magic = CMIF_OUT_HEADER_MAGIC;
  header->version = 0;
  header->result = rc;
  header->token = token;
}
#endif

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

struct HipcBufferView {
  void* address = nullptr;
  std::size_t size = 0;
};

void* GetRecvListAddress(const HipcRecvListEntry& entry) {
  return reinterpret_cast<void*>(static_cast<std::uintptr_t>(entry.address_low) |
                                 ((static_cast<std::uintptr_t>(entry.address_high) & 0xffffULL) << 32));
}

HipcBufferView GetSendBuffer(const HipcParsedRequest& request, std::size_t index) {
  if (index >= request.meta.num_send_buffers) {
    return {};
  }
  const auto& descriptor = request.data.send_buffers[index];
  return {hipcGetBufferAddress(&descriptor), hipcGetBufferSize(&descriptor)};
}

HipcBufferView GetRecvBuffer(const HipcParsedRequest& request, std::size_t index) {
  if (index >= request.meta.num_recv_buffers) {
    return {};
  }
  const auto& descriptor = request.data.recv_buffers[index];
  return {hipcGetBufferAddress(&descriptor), hipcGetBufferSize(&descriptor)};
}

HipcBufferView GetSendStatic(const HipcParsedRequest& request, std::size_t index) {
  if (index >= request.meta.num_send_statics) {
    return {};
  }
  const auto& descriptor = request.data.send_statics[index];
  return {hipcGetStaticAddress(&descriptor), hipcGetStaticSize(&descriptor)};
}

HipcBufferView GetRecvList(const HipcParsedRequest& request, std::size_t index) {
  if (request.data.recv_list == nullptr || index >= request.meta.num_recv_statics) {
    return {};
  }
  const auto& entry = request.data.recv_list[index];
  return {GetRecvListAddress(entry), entry.size};
}

HipcBufferView GetAutoSendBuffer(const HipcParsedRequest& request, std::size_t index) {
  const HipcBufferView mapped = GetSendBuffer(request, index);
  if (mapped.address != nullptr && mapped.size != 0) {
    return mapped;
  }
  return GetSendStatic(request, index);
}

HipcBufferView GetAutoRecvBuffer(const HipcParsedRequest& request, std::size_t index) {
  const HipcBufferView mapped = GetRecvBuffer(request, index);
  if (mapped.address != nullptr && mapped.size != 0) {
    return mapped;
  }
  return GetRecvList(request, index);
}

bool IsLikelyHipcBuffer(const HipcBufferView& buffer, std::size_t bytes) {
  const auto address = reinterpret_cast<std::uintptr_t>(buffer.address);
  return buffer.address != nullptr && bytes <= buffer.size && address != 0 &&
         address < kLikelyHosUserAddressLimit && bytes <= kBsdMitmMaxHipcBufferBytes;
}

[[maybe_unused]] bool CopyFromHipcBuffer(void* destination, const HipcBufferView& buffer, std::size_t bytes) {
  if (bytes == 0) {
    return true;
  }
  if (!IsLikelyHipcBuffer(buffer, bytes)) {
    return false;
  }
  std::memcpy(destination, buffer.address, bytes);
  return true;
}

[[maybe_unused]] bool CopyToHipcBuffer(const HipcBufferView& buffer, const void* source, std::size_t bytes) {
  if (bytes == 0) {
    return true;
  }
  if (!IsLikelyHipcBuffer(buffer, bytes)) {
    return false;
  }
  std::memcpy(buffer.address, source, bytes);
  return true;
}

std::optional<std::string> ReadNullTerminatedString(const HipcBufferView& buffer) {
  if (buffer.address == nullptr || buffer.size == 0) {
    return std::nullopt;
  }

  const auto* text = static_cast<const char*>(buffer.address);
  for (std::size_t index = 0; index < buffer.size; ++index) {
    if (text[index] == '\0') {
      return std::string(text, index);
    }
  }
  return std::nullopt;
}

std::optional<std::uint16_t> ParseServicePort(const HipcBufferView& buffer) {
  const auto service = ReadNullTerminatedString(buffer);
  if (!service.has_value() || service->empty()) {
    return static_cast<std::uint16_t>(0);
  }

  std::uint32_t value = 0;
  for (char c : *service) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return std::nullopt;
    }
    value = value * 10u + static_cast<std::uint32_t>(c - '0');
    if (value > 65535u) {
      return std::nullopt;
    }
  }
  return static_cast<std::uint16_t>(value);
}

const CmifInHeader* GetCmifHeader(const HipcParsedRequest& request) {
  if (request.meta.type != CmifCommandType_Request &&
      request.meta.type != CmifCommandType_RequestWithContext &&
      request.meta.type != CmifCommandType_Control &&
      request.meta.type != CmifCommandType_ControlWithContext) {
    return nullptr;
  }

  auto* base = armGetTls();
  const auto* header = static_cast<const CmifInHeader*>(cmifGetAlignedDataStart(request.data.data_words, base));
  const std::size_t data_size = static_cast<std::size_t>(request.meta.num_data_words) * sizeof(std::uint32_t);
  if (data_size < sizeof(CmifInHeader) || header->magic != CMIF_IN_HEADER_MAGIC) {
    return nullptr;
  }
  return header;
}

void DebugLogDnsQuery(const DnsMitmRuntimeState& runtime,
                      std::uint64_t program_id,
                      const char* command,
                      const std::string& hostname,
                      bool redirected,
                      std::uint32_t address = 0) {
  if (!runtime.debug_log) {
    return;
  }

  std::string line = "[" + FormatHex(program_id, 16) + "]: ";
  line += command;
  line += "(" + hostname + ")";
  if (redirected) {
    line += " -> " + FormatAtmosphereDnsIpv4(address);
  }
  line += "\n";
  AppendTextFile(kDnsMitmDebugLogPath, line);
}

bool TrySerializeHostEntRedirect(const DnsMitmRuntimeState& runtime,
                                 const AtmosphereMitmProcessInfo& client_info,
                                 const char* command,
                                 const HipcBufferView& name_buffer,
                                 const HipcBufferView& output_buffer,
                                 std::uint32_t* out_size) {
  const auto hostname = ReadNullTerminatedString(name_buffer);
  if (!hostname.has_value()) {
    return false;
  }

  const auto redirect = runtime.rules.ResolveRedirect(*hostname);
  if (!redirect.has_value()) {
    DebugLogDnsQuery(runtime, client_info.program_id, command, *hostname, false);
    return false;
  }

  const auto serialized_size = SerializeAtmosphereDnsHostEnt(output_buffer.address, output_buffer.size,
                                                             *hostname, *redirect);
  if (!serialized_size.has_value()) {
    return false;
  }

  *out_size = static_cast<std::uint32_t>(*serialized_size);
  DebugLogDnsQuery(runtime, client_info.program_id, command, *hostname, true, *redirect);
  return true;
}

bool TrySerializeAddrInfoRedirect(const DnsMitmRuntimeState& runtime,
                                  const AtmosphereMitmProcessInfo& client_info,
                                  const char* command,
                                  const HipcBufferView& node_buffer,
                                  const HipcBufferView& service_buffer,
                                  const HipcBufferView& hint_buffer,
                                  const HipcBufferView& output_buffer,
                                  std::uint32_t* out_size) {
  const auto hostname = ReadNullTerminatedString(node_buffer);
  if (!hostname.has_value()) {
    return false;
  }

  const auto redirect = runtime.rules.ResolveRedirect(*hostname);
  if (!redirect.has_value()) {
    DebugLogDnsQuery(runtime, client_info.program_id, command, *hostname, false);
    return false;
  }

  const auto port = ParseServicePort(service_buffer);
  if (!port.has_value()) {
    return false;
  }

  std::optional<AtmosphereDnsAddrInfoHint> hint;
  if (hint_buffer.address != nullptr && hint_buffer.size != 0) {
    hint = ParseAtmosphereDnsSerializedAddrInfoHint(hint_buffer.address, hint_buffer.size);
    if (!hint.has_value() || hint->unsupported_family) {
      return false;
    }
  }

  const auto serialized_size = SerializeAtmosphereDnsAddrInfo(output_buffer.address, output_buffer.size,
                                                             *hostname, *redirect, *port,
                                                             hint.has_value() ? &*hint : nullptr);
  if (!serialized_size.has_value()) {
    return false;
  }

  *out_size = static_cast<std::uint32_t>(*serialized_size);
  DebugLogDnsQuery(runtime, client_info.program_id, command, *hostname, true, *redirect);
  return true;
}

::Result ReplyToQuerySession(Handle query_session) {
  s32 unused = -1;
  return svcReplyAndReceive(&unused, &query_session, 0, query_session, 0);
}

void ProcessQuerySession(std::size_t service_index,
                         ObservedService& service,
                         const QueryResponderContext& context) {
  AtmosphereMitmProcessInfo raw_info{};
  const HipcParsedRequest request = hipcParseRequest(armGetTls());
  const bool parsed = ParseMitmQueryRequest(request, &raw_info);

  bool should_mitm = false;
  if (parsed) {
    if (service.target == MitmServiceTarget::DnsResolver) {
      should_mitm = true;
    } else if (service.target == MitmServiceTarget::BsdUser) {
      should_mitm = ShouldSelectBsdMitmClient(raw_info, context);
    }
  }
  PrepareMitmQueryResponse(0, should_mitm);
  const ::Result reply_result = ReplyToQuerySession(service.query_session);

  QueryCounters& counters = g_query_counters[service_index];
  counters.total.fetch_add(1, std::memory_order_relaxed);
  if (should_mitm) {
    counters.selected.fetch_add(1, std::memory_order_relaxed);
  }
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

bool HandleDnsMitmRequest(DnsMitmRuntimeState& runtime,
                          const AtmosphereMitmProcessInfo& client_info,
                          const HipcParsedRequest& request) {
  const CmifInHeader* header = GetCmifHeader(request);
  if (header == nullptr) {
    return false;
  }

  switch (header->command_id) {
    case 2: {
      struct DnsHostByNameOut {
        std::uint32_t host_error = 0;
        std::uint32_t error = 0;
        std::uint32_t size = 0;
      } out{};
      if (!TrySerializeHostEntRedirect(runtime, client_info, "GetHostByNameRequest",
                                       GetSendBuffer(request, 0), GetRecvBuffer(request, 0), &out.size)) {
        return false;
      }
      PrepareCmifResponseWithToken(0, header->token, &out, sizeof(out));
      return true;
    }
    case 6: {
      struct DnsAddrInfoOut {
        std::uint32_t error = 0;
        std::int32_t retval = 0;
        std::uint32_t size = 0;
      } out{};
      if (!TrySerializeAddrInfoRedirect(runtime, client_info, "GetAddrInfoRequest",
                                        GetSendBuffer(request, 0), GetSendBuffer(request, 1),
                                        GetSendBuffer(request, 2), GetRecvBuffer(request, 0), &out.size)) {
        return false;
      }
      PrepareCmifResponseWithToken(0, header->token, &out, sizeof(out));
      return true;
    }
    case 10: {
      struct DnsHostByNameOptionsOut {
        std::uint32_t size = 0;
        std::int32_t host_error = 0;
        std::int32_t error = 0;
      } out{};
      if (!TrySerializeHostEntRedirect(runtime, client_info, "GetHostByNameRequestWithOptions",
                                       GetAutoSendBuffer(request, 0), GetAutoRecvBuffer(request, 0),
                                       &out.size)) {
        return false;
      }
      PrepareCmifResponseWithToken(0, header->token, &out, sizeof(out));
      return true;
    }
    case 12: {
      struct DnsAddrInfoOptionsOut {
        std::uint32_t size = 0;
        std::int32_t retval = 0;
        std::int32_t host_error = 0;
        std::int32_t error = 0;
      } out{};
      if (!TrySerializeAddrInfoRedirect(runtime, client_info, "GetAddrInfoRequestWithOptions",
                                        GetSendBuffer(request, 0), GetSendBuffer(request, 1),
                                        GetSendBuffer(request, 2), GetAutoRecvBuffer(request, 0), &out.size)) {
        return false;
      }
      PrepareCmifResponseWithToken(0, header->token, &out, sizeof(out));
      return true;
    }
    case 65000:
      runtime = LoadDnsMitmRuntimeState();
      PrepareCmifResponseWithToken(0, header->token, nullptr, 0);
      return true;
    default:
      return false;
  }
}

::Result ForwardCurrentMitmRequest(Handle forward_session) {
  return svcSendSyncRequest(forward_session);
}

class DnsMitmServer {
 public:
  explicit DnsMitmServer(DnsMitmServerContext* context) : context_(context) {
    sessions_.fill({});
  }

  ::Result Initialize() {
    return OpenAtmosphereSession(&sm_session_);
  }

  [[noreturn]] void Run() {
    while (true) {
      ProcessNext();
    }
  }

 private:
  void ProcessNext() {
    std::array<Handle, kDnsMitmMaxSessions + 1> handles{};
    handles[0] = context_->service.mitm_port;
    std::size_t handle_count = 1;
    std::array<std::size_t, kDnsMitmMaxSessions> session_indices{};
    for (std::size_t index = 0; index < sessions_.size(); ++index) {
      if (sessions_[index].client_session != INVALID_HANDLE) {
        handles[handle_count] = sessions_[index].client_session;
        session_indices[handle_count - 1] = index;
        ++handle_count;
      }
    }

    s32 signaled_index = -1;
    const ::Result wait_result =
        svcWaitSynchronization(&signaled_index, handles.data(), static_cast<s32>(handle_count), UINT64_MAX);
    if (R_FAILED(wait_result)) {
      LogWarning("dns-mitm", "wait failed: " + FormatLibnxResult(wait_result));
      svcSleepThread(kObserverRetryDelayNs);
      return;
    }
    if (signaled_index == 0) {
      AcceptSession();
      return;
    }
    if (signaled_index < 0 || static_cast<std::size_t>(signaled_index) >= handle_count) {
      return;
    }

    const std::size_t session_index = session_indices[static_cast<std::size_t>(signaled_index) - 1];
    ProcessSession(session_index);
  }

  void AcceptSession() {
    Handle client_session = INVALID_HANDLE;
    ::Result rc = svcAcceptSession(&client_session, context_->service.mitm_port);
    if (R_FAILED(rc)) {
      LogWarning("dns-mitm", "failed to accept sfdnsres MITM session: " + FormatLibnxResult(rc));
      return;
    }

    auto slot = std::find_if(sessions_.begin(), sessions_.end(), [](const DnsMitmClientSession& session) {
      return session.client_session == INVALID_HANDLE;
    });
    if (slot == sessions_.end()) {
      LogWarning("dns-mitm", "rejected sfdnsres MITM session because the server is at capacity");
      svcCloseHandle(client_session);
      return;
    }

    AtmosphereMitmProcessInfo info{};
    Handle forward_session = INVALID_HANDLE;
    rc = AcknowledgeAtmosphereMitmSession(&sm_session_, context_->service.service_name, &info, &forward_session);
    if (R_FAILED(rc)) {
      LogWarning("dns-mitm", "failed to acknowledge sfdnsres MITM session: " + FormatLibnxResult(rc));
      svcCloseHandle(client_session);
      return;
    }

    slot->client_session = client_session;
    slot->forward_session = forward_session;
    slot->client_info = info;
    LogInfo("dns-mitm", "accepted sfdnsres MITM session: pid=0x" + FormatHex(info.process_id, 16) +
                            " program=0x" + FormatHex(info.program_id, 16));
  }

  void CloseSession(std::size_t index) {
    if (index >= sessions_.size()) {
      return;
    }
    if (sessions_[index].client_session != INVALID_HANDLE) {
      svcCloseHandle(sessions_[index].client_session);
    }
    if (sessions_[index].forward_session != INVALID_HANDLE) {
      svcCloseHandle(sessions_[index].forward_session);
    }
    sessions_[index] = {};
  }

  void ProcessSession(std::size_t index) {
    DnsMitmClientSession& session = sessions_[index];
    s32 unused_index = -1;
    hipcMakeRequestInline(armGetTls());
    ::Result rc = svcReplyAndReceive(&unused_index, &session.client_session, 1, INVALID_HANDLE, UINT64_MAX);
    if (R_FAILED(rc)) {
      CloseSession(index);
      return;
    }

    const HipcParsedRequest request = hipcParseRequest(armGetTls());
    bool close_session = false;
    if (request.meta.type == CmifCommandType_Close) {
      close_session = true;
      PrepareCmifResponseWithToken(0, 0, nullptr, 0);
    } else if (request.meta.type == CmifCommandType_Request ||
               request.meta.type == CmifCommandType_RequestWithContext) {
      if (!HandleDnsMitmRequest(context_->runtime, session.client_info, request)) {
        rc = ForwardCurrentMitmRequest(session.forward_session);
        if (R_FAILED(rc)) {
          LogWarning("dns-mitm", "failed to forward sfdnsres request: " + FormatLibnxResult(rc));
          PrepareCmifResponseWithToken(rc, 0, nullptr, 0);
        }
      }
    } else {
      rc = ForwardCurrentMitmRequest(session.forward_session);
      if (R_FAILED(rc)) {
        PrepareCmifResponseWithToken(rc, 0, nullptr, 0);
      }
    }

    rc = svcReplyAndReceive(&unused_index, &session.client_session, 0, session.client_session, 0);
    if (R_FAILED(rc) && rc != KERNELRESULT(TimedOut)) {
      LogWarning("dns-mitm", "failed to reply to sfdnsres client: " + FormatLibnxResult(rc));
      close_session = true;
    }
    if (close_session) {
      CloseSession(index);
    }
  }

  DnsMitmServerContext* context_ = nullptr;
  TipcService sm_session_{};
  std::array<DnsMitmClientSession, kDnsMitmMaxSessions> sessions_{};
};

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
struct BsdServiceConfigIn {
  std::uint32_t version = 0;
  std::uint32_t tcp_tx_buf_size = 0;
  std::uint32_t tcp_rx_buf_size = 0;
  std::uint32_t tcp_tx_buf_max_size = 0;
  std::uint32_t tcp_rx_buf_max_size = 0;
  std::uint32_t udp_tx_buf_size = 0;
  std::uint32_t udp_rx_buf_size = 0;
  std::uint32_t sb_efficiency = 0;
};

struct BsdRegisterClientIn {
  BsdServiceConfigIn config{};
  std::uint64_t pid_placeholder = 0;
  std::uint64_t transfer_memory_size = 0;
};

struct BsdSocketIn {
  std::int32_t domain = 0;
  std::int32_t type = 0;
  std::int32_t protocol = 0;
};

struct BsdSockFdIn {
  std::int32_t sockfd = 0;
  std::int32_t flags = 0;
};

struct BsdPollIn {
  nfds_t nfds = 0;
  std::int32_t timeout = 0;
};

struct BsdSelectTimevalIn {
  timeval tv{};
  bool is_null = false;
};

struct BsdSelectIn {
  std::int32_t nfds = 0;
  BsdSelectTimevalIn timeout{};
};

struct BsdSockFdLevelOptionIn {
  std::int32_t sockfd = 0;
  std::int32_t level = 0;
  std::int32_t optname = 0;
};

struct BsdFcntlIn {
  std::int32_t fd = 0;
  std::int32_t cmd = 0;
  std::int32_t flags = 0;
};

struct BsdRetErrnoOut {
  std::int32_t ret = 0;
  std::int32_t errno_ = 0;
};

static_assert(sizeof(BsdRegisterClientIn) == 0x30);
static_assert(sizeof(BsdSocketIn) == 0x0c);
static_assert(sizeof(BsdSockFdIn) == 0x08);
static_assert(sizeof(BsdPollIn) == 0x08);
static_assert(sizeof(BsdFcntlIn) == 0x0c);
static_assert(sizeof(BsdRetErrnoOut) == 0x08);

const char* DescribeBsdCommand(std::uint32_t command_id) {
  switch (command_id) {
    case 0:
      return "RegisterClient";
    case 1:
      return "StartMonitoring";
    case 2:
      return "Socket";
    case 3:
      return "SocketExempt";
    case 4:
      return "Open";
    case 5:
      return "Select";
    case 6:
      return "Poll";
    case 7:
      return "Sysctl";
    case 8:
      return "Recv";
    case 9:
      return "RecvFrom";
    case 10:
      return "Send";
    case 11:
      return "SendTo";
    case 12:
      return "Accept";
    case 13:
      return "Bind";
    case 14:
      return "Connect";
    case 15:
      return "GetPeerName";
    case 16:
      return "GetSockName";
    case 17:
      return "GetSockOpt";
    case 18:
      return "Listen";
    case 19:
      return "Ioctl";
    case 20:
      return "Fcntl";
    case 21:
      return "SetSockOpt";
    case 22:
      return "Shutdown";
    case 23:
      return "ShutdownAllSockets";
    case 24:
      return "Write";
    case 25:
      return "Read";
    case 26:
      return "Close";
    case 27:
      return "DuplicateSocket";
    case 29:
      return "RecvMMsg";
    case 30:
      return "SendMMsg";
    default:
      return "Unknown";
  }
}

template <typename T>
const T* GetCmifPayloadAs(const HipcParsedRequest& request) {
  const CmifInHeader* header = GetCmifHeader(request);
  if (header == nullptr) {
    return nullptr;
  }

  const std::size_t data_size = static_cast<std::size_t>(request.meta.num_data_words) * sizeof(std::uint32_t);
  if (data_size < sizeof(CmifInHeader) + sizeof(T)) {
    return nullptr;
  }
  return reinterpret_cast<const T*>(header + 1);
}

Handle GetFirstIncomingHandle(const HipcParsedRequest& request) {
  if (request.meta.num_copy_handles > 0) {
    return request.data.copy_handles[0];
  }
  if (request.meta.num_move_handles > 0) {
    return request.data.move_handles[0];
  }
  return INVALID_HANDLE;
}

void CloseIncomingRequestHandles(const HipcParsedRequest& request, Handle preserved_handle = INVALID_HANDLE) {
  for (std::uint32_t index = 0; index < request.meta.num_copy_handles; ++index) {
    const Handle handle = request.data.copy_handles[index];
    if (handle != INVALID_HANDLE && handle != preserved_handle) {
      svcCloseHandle(handle);
    }
  }
  for (std::uint32_t index = 0; index < request.meta.num_move_handles; ++index) {
    const Handle handle = request.data.move_handles[index];
    if (handle != INVALID_HANDLE && handle != preserved_handle) {
      svcCloseHandle(handle);
    }
  }
}

void PrepareBsdRetErrnoResponse(std::uint32_t token, std::int32_t ret, std::int32_t errno_value) {
  BsdRetErrnoOut out{};
  out.ret = ret;
  out.errno_ = ret < 0 ? errno_value : 0;
  PrepareCmifResponseWithToken(0, token, &out, sizeof(out));
}

void PrepareBsdRetErrnoExtraResponse(std::uint32_t token,
                                      std::int32_t ret,
                                      std::int32_t errno_value,
                                      const void* extra,
                                      std::size_t extra_size) {
  std::array<std::uint8_t, sizeof(BsdRetErrnoOut) + sizeof(socklen_t)> payload{};
  BsdRetErrnoOut out{};
  out.ret = ret;
  out.errno_ = ret < 0 ? errno_value : 0;
  std::memcpy(payload.data(), &out, sizeof(out));
  if (extra != nullptr && extra_size != 0) {
    std::memcpy(payload.data() + sizeof(out), extra, std::min(extra_size, payload.size() - sizeof(out)));
  }

  PrepareCmifResponseWithToken(0, token, payload.data(), sizeof(out) + extra_size);
}

std::optional<std::string> Ipv4SockaddrToHost(const sockaddr_storage& address, socklen_t length) {
  if (length < sizeof(sockaddr_in)) {
    return std::nullopt;
  }

  const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
  if (ipv4->sin_family != AF_INET) {
    return std::nullopt;
  }

  char buffer[16]{};
  if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer, sizeof(buffer)) == nullptr) {
    return std::nullopt;
  }
  return std::string(buffer);
}

std::optional<std::uint16_t> Ipv4SockaddrToPort(const sockaddr_storage& address, socklen_t length) {
  if (length < sizeof(sockaddr_in)) {
    return std::nullopt;
  }

  const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
  if (ipv4->sin_family != AF_INET) {
    return std::nullopt;
  }
  return ntohs(ipv4->sin_port);
}

std::uint32_t Ipv4SockaddrToHostOrder(const sockaddr_storage& address) {
  const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
  return ntohl(ipv4->sin_addr.s_addr);
}

bool IsLocalBypassIpv4Host(std::uint32_t host_order_ipv4) {
  return (host_order_ipv4 & 0xf0000000u) == 0xe0000000u ||  // 224.0.0.0/4 multicast
         (host_order_ipv4 & 0xff000000u) == 0x0a000000u ||  // 10.0.0.0/8
         (host_order_ipv4 & 0xfff00000u) == 0xac100000u ||  // 172.16.0.0/12
         (host_order_ipv4 & 0xffff0000u) == 0xc0a80000u ||  // 192.168.0.0/16
         (host_order_ipv4 & 0xffff0000u) == 0xa9fe0000u ||  // 169.254.0.0/16
         (host_order_ipv4 & 0xff000000u) == 0x7f000000u ||  // 127.0.0.0/8
         host_order_ipv4 == 0xffffffffu;
}

bool IsLocalBypassSockaddr(const sockaddr_storage& address, socklen_t length) {
  if (length < sizeof(sockaddr_in)) {
    return false;
  }
  const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
  return ipv4->sin_family == AF_INET && IsLocalBypassIpv4Host(Ipv4SockaddrToHostOrder(address));
}

AppTrafficClass GuessBsdTrafficClass(const sockaddr_storage& address,
                                     socklen_t length,
                                     TransportProtocol transport) {
  const std::optional<std::uint16_t> port = Ipv4SockaddrToPort(address, length);
  if (transport == TransportProtocol::Udp) {
    if (port.has_value() && *port == 5353) {
      return AppTrafficClass::Discovery;
    }
    if (port.has_value() && (*port == 9 || *port == 7)) {
      return AppTrafficClass::WakeOnLan;
    }
  }
  return AppTrafficClass::Generic;
}

bool SameSockaddr(const sockaddr_storage& lhs, socklen_t lhs_length,
                  const sockaddr_storage& rhs, socklen_t rhs_length) {
  if (lhs_length != rhs_length || lhs_length < sizeof(sockaddr_in)) {
    return false;
  }

  const auto* lhs_ipv4 = reinterpret_cast<const sockaddr_in*>(&lhs);
  const auto* rhs_ipv4 = reinterpret_cast<const sockaddr_in*>(&rhs);
  return lhs_ipv4->sin_family == AF_INET && rhs_ipv4->sin_family == AF_INET &&
         lhs_ipv4->sin_port == rhs_ipv4->sin_port &&
         lhs_ipv4->sin_addr.s_addr == rhs_ipv4->sin_addr.s_addr;
}

std::optional<sockaddr_storage> ReadSockaddrFromBuffer(const HipcBufferView& buffer, socklen_t* out_length) {
  if (buffer.address == nullptr || buffer.size < sizeof(sockaddr)) {
    return std::nullopt;
  }
  if (buffer.size > sizeof(sockaddr_storage)) {
    return std::nullopt;
  }
  if (!IsLikelyHipcBuffer(buffer, buffer.size)) {
    return std::nullopt;
  }

  sockaddr_storage address{};
  std::memcpy(&address, buffer.address, buffer.size);
  *out_length = static_cast<socklen_t>(buffer.size);
  return address;
}

BsdMitmClientState* GetBsdClientState(BsdMitmClientSession& session) {
  return session.state.get();
}

BsdMitmVirtualSocket* FindVirtualSocket(BsdMitmClientSession& session, std::int32_t fd) {
  BsdMitmClientState* state = GetBsdClientState(session);
  if (state == nullptr) {
    return nullptr;
  }
  auto slot = std::find_if(state->virtual_sockets.begin(), state->virtual_sockets.end(),
                           [fd](const BsdMitmVirtualSocket& socket) {
                             return socket.used && socket.fd == fd;
                           });
  return slot == state->virtual_sockets.end() ? nullptr : &*slot;
}

BsdMitmVirtualSocket* TrackBsdSocket(BsdMitmClientSession& session,
                                     std::int32_t fd,
                                     const BsdSocketIn& input,
                                     bool original_bsd_fd) {
  if (fd < 0) {
    return nullptr;
  }
  BsdMitmClientState* state = GetBsdClientState(session);
  if (state == nullptr) {
    return nullptr;
  }

  auto slot = std::find_if(state->virtual_sockets.begin(), state->virtual_sockets.end(),
                           [fd](const BsdMitmVirtualSocket& socket) {
                             return socket.used && socket.fd == fd;
                           });
  if (slot == state->virtual_sockets.end()) {
    slot = std::find_if(state->virtual_sockets.begin(), state->virtual_sockets.end(),
                        [](const BsdMitmVirtualSocket& socket) {
                          return !socket.used;
                        });
  }
  if (slot == state->virtual_sockets.end()) {
    return nullptr;
  }

  *slot = {};
  slot->used = true;
  slot->fd = fd;
  slot->domain = input.domain;
  slot->type = input.type;
  slot->protocol = input.protocol;
  slot->original_bsd_fd = original_bsd_fd;
  if ((input.type & kBsdSocketCreateNonBlock) != 0) {
    slot->status_flags |= kBsdFcntlNxNonBlock;
  }
#if defined(FD_CLOEXEC)
  if ((input.type & kBsdSocketCreateCloseOnExec) != 0) {
    slot->descriptor_flags |= FD_CLOEXEC;
  }
#endif
  state->next_virtual_fd = std::max(state->next_virtual_fd, fd + 1);
  return &*slot;
}

bool IsBsdStreamSocket(const BsdMitmVirtualSocket& socket) {
  return socket.used && socket.domain == AF_INET && (socket.type & 0xff) == SOCK_STREAM;
}

bool IsBsdDatagramSocket(const BsdMitmVirtualSocket& socket) {
  return socket.used && socket.domain == AF_INET && (socket.type & 0xff) == SOCK_DGRAM;
}

bool IsBsdSocketReadable(IControlService* control_service, BsdMitmVirtualSocket& socket);

std::int32_t CurrentBsdErrnoOr(std::int32_t fallback) {
  return g_bsdErrno != 0 ? g_bsdErrno : fallback;
}

bool IsNonBlockingConnectProgress(std::int32_t errno_value) {
  return errno_value == EINPROGRESS || errno_value == EWOULDBLOCK ||
         errno_value == EAGAIN || errno_value == EALREADY ||
         errno_value == kLinuxErrnoInProgress || errno_value == kLinuxErrnoAlready;
}

Service BorrowForwardBsdService(Handle forward_session) {
  Service service{};
  service.session = forward_session;
  service.own_handle = 0;
  service.object_id = 0;
  service.pointer_buffer_size = kBsdMitmPointerBufferSize;
  return service;
}

::Result ForwardOriginalBsdRegisterClient(Handle forward_session,
                                          const BsdRegisterClientIn& input,
                                          Handle transfer_memory,
                                          std::uint64_t* out_pid) {
  if (forward_session == INVALID_HANDLE || transfer_memory == INVALID_HANDLE || out_pid == nullptr) {
    return MakeLibnxBadInput();
  }

  Service service = BorrowForwardBsdService(forward_session);
  SfDispatchParams params{};
  params.in_send_pid = true;
  params.in_num_handles = 1;
  params.in_handles[0] = transfer_memory;
  return serviceDispatchImpl(&service, 0, &input, sizeof(input), out_pid, sizeof(*out_pid), params);
}

::Result ForwardOriginalBsdStartMonitoring(Handle forward_session, std::uint64_t monitored_pid) {
  if (forward_session == INVALID_HANDLE) {
    return MakeLibnxBadInput();
  }

  Service service = BorrowForwardBsdService(forward_session);
  SfDispatchParams params{};
  params.in_send_pid = true;
  return serviceDispatchImpl(&service, 1, &monitored_pid, sizeof(monitored_pid), nullptr, 0, params);
}

::Result OpenReplacementOriginalBsdSocket(Handle forward_session,
                                          std::uint32_t command_id,
                                          const BsdSocketIn& input,
                                          BsdRetErrnoOut* out) {
  if (forward_session == INVALID_HANDLE || out == nullptr) {
    return MakeLibnxBadInput();
  }

  Service service = BorrowForwardBsdService(forward_session);
  SfDispatchParams params{};
  return serviceDispatchImpl(&service, command_id, &input, sizeof(input), out, sizeof(*out), params);
}

::Result CloseOriginalBsdSocketFd(Handle forward_session, std::int32_t fd, BsdRetErrnoOut* out) {
  if (forward_session == INVALID_HANDLE || out == nullptr) {
    return MakeLibnxBadInput();
  }

  Service service = BorrowForwardBsdService(forward_session);
  SfDispatchParams params{};
  return serviceDispatchImpl(&service, 26, &fd, sizeof(fd), out, sizeof(*out), params);
}

void CloseTunnelDatagramsForSocket(IControlService* control_service, BsdMitmVirtualSocket& socket) {
  if (control_service == nullptr) {
    return;
  }

  for (BsdMitmRemoteDatagram& remote : socket.remote_datagrams) {
    if (remote.datagram_id != 0) {
      static_cast<void>(control_service->CloseTunnelDatagram(remote.datagram_id));
    }
    remote = {};
  }
}

void CloseDirectNativeSocket(BsdMitmVirtualSocket& socket) {
  if (socket.native_fd != kBsdMitmInvalidNativeFd) {
    bsdClose(socket.native_fd);
    socket.native_fd = kBsdMitmInvalidNativeFd;
  }
}

bool CloseVirtualBsdSocket(IControlService* control_service, BsdMitmClientSession& session, std::int32_t fd) {
  BsdMitmVirtualSocket* socket = FindVirtualSocket(session, fd);
  if (socket == nullptr) {
    return false;
  }

  if (socket->original_bsd_fd && session.forward_session != INVALID_HANDLE) {
    BsdRetErrnoOut original_close{};
    static_cast<void>(CloseOriginalBsdSocketFd(session.forward_session, socket->fd, &original_close));
  }
  CloseTunnelDatagramsForSocket(control_service, *socket);
  CloseDirectNativeSocket(*socket);
  *socket = {};
  return true;
}

std::int32_t ErrnoFromSwgErrorCode(ErrorCode code) {
  switch (code) {
    case ErrorCode::NotFound:
      return kLinuxErrnoWouldBlock;
    case ErrorCode::Unsupported:
      return kLinuxErrnoOperationNotSupported;
    case ErrorCode::InvalidState:
      return kLinuxErrnoNetworkUnreachable;
    case ErrorCode::ParseError:
      return kLinuxErrnoInvalidArgument;
    default:
      return kLinuxErrnoNetworkUnreachable;
  }
}

Result<std::uint64_t> EnsureBsdAppSession(BsdMitmServerContext* context, BsdMitmClientSession& session) {
  BsdMitmClientState* state = GetBsdClientState(session);
  if (state == nullptr) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "BSD MITM client state is unavailable");
  }
  if (state->app_session_id != 0) {
    return MakeSuccess(state->app_session_id);
  }
  if (context == nullptr || !context->control_service) {
    return MakeFailure<std::uint64_t>(ErrorCode::InvalidState, "control service unavailable for BSD MITM");
  }

  AppTunnelRequest request{};
  request.app.title_id = session.client_info.program_id;
  request.app.client_name = "bsd:u";
  request.app.integration_tag = "transparent-bsd-mitm";
  request.requested_flags = ToFlags(RuntimeFlag::TransparentMode) | ToFlags(RuntimeFlag::DnsThroughTunnel);
  request.policy_overrides = ToFlags(AppPolicyOverrideFlag::AllowLocalNetworkBypass);
  request.allow_local_network_bypass = true;
  request.require_tunnel_for_default_traffic = true;
  request.prefer_tunnel_dns = true;
  request.allow_direct_internet_fallback = false;

  const Result<AppSessionInfo> opened = context->control_service->OpenAppSession(request);
  if (!opened.ok()) {
    return MakeFailure<std::uint64_t>(opened.error.code, opened.error.message);
  }

  state->app_session_id = opened.value.session_id;
  LogInfo("bsd-mitm", "opened transparent app session for bsd:u client: pid=0x" +
                          FormatHex(session.client_info.process_id, 16) +
                          " program=0x" + FormatHex(session.client_info.program_id, 16) +
                          " session=" + std::to_string(state->app_session_id) +
                          " tunnel_ready=" + (opened.value.tunnel_ready ? std::string("true") : std::string("false")));
  return MakeSuccess(state->app_session_id);
}

BsdMitmRemoteDatagram* FindRemoteDatagram(BsdMitmVirtualSocket& socket,
                                          const sockaddr_storage& remote_address,
                                          socklen_t remote_address_length) {
  auto slot = std::find_if(socket.remote_datagrams.begin(), socket.remote_datagrams.end(),
                           [&](const BsdMitmRemoteDatagram& remote) {
                             return remote.datagram_id != 0 &&
                                    SameSockaddr(remote.remote_address, remote.remote_address_length,
                                                 remote_address, remote_address_length);
                           });
  return slot == socket.remote_datagrams.end() ? nullptr : &*slot;
}

Result<BsdMitmRemoteDatagram*> EnsureRemoteDatagram(BsdMitmServerContext* context,
                                                    BsdMitmClientSession& session,
                                                    BsdMitmVirtualSocket& socket,
                                                    const sockaddr_storage& remote_address,
                                                    socklen_t remote_address_length) {
  if (BsdMitmRemoteDatagram* existing =
          FindRemoteDatagram(socket, remote_address, remote_address_length)) {
    return MakeSuccess(existing);
  }

  auto slot = std::find_if(socket.remote_datagrams.begin(), socket.remote_datagrams.end(),
                           [](const BsdMitmRemoteDatagram& remote) {
                             return remote.datagram_id == 0;
                           });
  if (slot == socket.remote_datagrams.end()) {
    return MakeFailure<BsdMitmRemoteDatagram*>(ErrorCode::Unsupported,
                                               "too many remote UDP peers for BSD MITM socket");
  }

  const std::optional<std::string> remote_host = Ipv4SockaddrToHost(remote_address, remote_address_length);
  const std::optional<std::uint16_t> remote_port = Ipv4SockaddrToPort(remote_address, remote_address_length);
  if (!remote_host.has_value() || !remote_port.has_value() || *remote_port == 0) {
    return MakeFailure<BsdMitmRemoteDatagram*>(ErrorCode::ParseError,
                                               "BSD MITM UDP adapter only supports IPv4 remote sockaddr");
  }

  const Result<std::uint64_t> app_session = EnsureBsdAppSession(context, session);
  if (!app_session.ok()) {
    return MakeFailure<BsdMitmRemoteDatagram*>(app_session.error.code, app_session.error.message);
  }

  TunnelDatagramOpenRequest request{};
  request.session_id = app_session.value;
  request.remote_host = *remote_host;
  request.remote_port = *remote_port;
  request.traffic_class = AppTrafficClass::Generic;
  request.route_preference = RoutePreference::RequireTunnel;
  request.local_network_hint = false;

  const Result<TunnelDatagramInfo> opened = context->control_service->OpenTunnelDatagram(request);
  if (!opened.ok()) {
    return MakeFailure<BsdMitmRemoteDatagram*>(opened.error.code, opened.error.message);
  }

  *slot = {};
  slot->remote_address = remote_address;
  slot->remote_address_length = remote_address_length;
  slot->remote_host = *remote_host;
  slot->remote_port = *remote_port;
  slot->datagram_id = opened.value.datagram_id;
  LogInfo("bsd-mitm", "opened tunnel UDP adapter: pid=0x" +
                          FormatHex(session.client_info.process_id, 16) +
                          " fd=" + std::to_string(socket.fd) +
                          " datagram=" + std::to_string(slot->datagram_id) +
                          " remote=" + slot->remote_host + ":" + std::to_string(slot->remote_port));
  return MakeSuccess(&*slot);
}

Result<std::uint64_t> SendBsdTunnelDatagram(BsdMitmServerContext* context,
                                            BsdMitmClientSession& session,
                                            BsdMitmVirtualSocket& socket,
                                            const sockaddr_storage& remote_address,
                                            socklen_t remote_address_length,
                                            const HipcBufferView& payload_buffer) {
  if (payload_buffer.address == nullptr || payload_buffer.size == 0) {
    return MakeFailure<std::uint64_t>(ErrorCode::ParseError, "empty BSD UDP payload");
  }
  if (!IsLikelyHipcBuffer(payload_buffer, payload_buffer.size)) {
    return MakeFailure<std::uint64_t>(ErrorCode::ParseError, "invalid BSD UDP payload buffer");
  }

  const Result<BsdMitmRemoteDatagram*> remote =
      EnsureRemoteDatagram(context, session, socket, remote_address, remote_address_length);
  if (!remote.ok()) {
    return MakeFailure<std::uint64_t>(remote.error.code, remote.error.message);
  }

  TunnelDatagramSendRequest request{};
  request.datagram_id = remote.value->datagram_id;
  const auto* payload = static_cast<const std::uint8_t*>(payload_buffer.address);
  request.payload.assign(payload, payload + payload_buffer.size);

  const Result<std::uint64_t> counter = context->control_service->SendTunnelDatagram(request);
  if (!counter.ok()) {
    return MakeFailure<std::uint64_t>(counter.error.code, counter.error.message);
  }

  ++socket.send_calls;
  if (ShouldLogSparseCount(socket.send_calls)) {
    LogInfo("bsd-mitm", "sent tunnel UDP datagram: pid=0x" +
                            FormatHex(session.client_info.process_id, 16) +
                            " fd=" + std::to_string(socket.fd) +
                            " bytes=" + std::to_string(payload_buffer.size) +
                            " counter=" + std::to_string(counter.value));
  }
  return counter;
}

void CacheBsdTunnelDatagrams(BsdMitmVirtualSocket& socket,
                             const BsdMitmRemoteDatagram& remote,
                             TunnelDatagramBurstResult&& burst) {
  for (TunnelDatagram& datagram : burst.datagrams) {
    if (socket.pending_datagrams.size() >= kBsdMitmMaxPendingDatagramsPerSocket) {
      socket.pending_datagrams.pop_front();
    }

    BsdMitmPendingDatagram pending{};
    pending.datagram = std::move(datagram);
    pending.remote_address = remote.remote_address;
    pending.remote_address_length = remote.remote_address_length;
    socket.pending_datagrams.push_back(std::move(pending));
  }
}

void RefreshBsdSocketPendingDatagrams(IControlService* control_service, BsdMitmVirtualSocket& socket) {
  if (control_service == nullptr || !socket.pending_datagrams.empty()) {
    return;
  }

  for (const BsdMitmRemoteDatagram& remote : socket.remote_datagrams) {
    if (remote.datagram_id == 0) {
      continue;
    }

    TunnelDatagramBurstRequest request{};
    request.datagram_id = remote.datagram_id;
    request.max_datagrams = kBsdMitmDatagramBurstMaxDatagrams;
    request.max_payload_bytes = kBsdMitmDatagramBurstMaxPayloadBytes;
    request.timeout_ms = 0;
    Result<TunnelDatagramBurstResult> received = control_service->RecvTunnelDatagramBurst(request);
    if (received.ok()) {
      CacheBsdTunnelDatagrams(socket, remote, std::move(received.value));
      if (!socket.pending_datagrams.empty()) {
        return;
      }
    }
  }
}

bool StorePendingSocketOption(BsdMitmVirtualSocket& socket,
                              std::int32_t level,
                              std::int32_t optname,
                              const HipcBufferView& value) {
  if (value.address == nullptr || value.size > kBsdMitmMaxPendingSocketOptionBytes ||
      !IsLikelyHipcBuffer(value, value.size)) {
    return false;
  }

  auto slot = std::find_if(socket.pending_options.begin(), socket.pending_options.end(),
                           [level, optname](const BsdMitmPendingSocketOption& option) {
                             return option.used && option.level == level && option.optname == optname;
                           });
  if (slot == socket.pending_options.end()) {
    slot = std::find_if(socket.pending_options.begin(), socket.pending_options.end(),
                        [](const BsdMitmPendingSocketOption& option) {
                          return !option.used;
                        });
  }
  if (slot == socket.pending_options.end()) {
    return false;
  }

  *slot = {};
  slot->used = true;
  slot->level = level;
  slot->optname = optname;
  slot->length = static_cast<socklen_t>(value.size);
  return CopyFromHipcBuffer(slot->value.data(), value, value.size);
}

bool ReplayPendingSocketOptions(BsdMitmVirtualSocket& socket) {
  for (const BsdMitmPendingSocketOption& option : socket.pending_options) {
    if (!option.used) {
      continue;
    }
    if (bsdSetSockOpt(socket.native_fd, option.level, option.optname,
                      option.value.data(), option.length) < 0) {
      return false;
    }
  }
  return true;
}

std::int32_t PollDirectNativeSocket(BsdMitmVirtualSocket& socket, std::int16_t events) {
  if (socket.native_fd == kBsdMitmInvalidNativeFd) {
    return 0;
  }

  pollfd native_poll{};
  native_poll.fd = socket.native_fd;
  native_poll.events = events;
  const int ret = bsdPoll(&native_poll, 1, 0);
  if (ret < 0) {
    return POLLERR;
  }
  return native_poll.revents;
}

bool IsBsdSocketReadable(IControlService* control_service, BsdMitmVirtualSocket& socket) {
  if (socket.backend == BsdMitmSocketBackend::DirectNative) {
    return (PollDirectNativeSocket(socket, POLLIN) & (POLLIN | POLLERR | POLLHUP)) != 0;
  }

  RefreshBsdSocketPendingDatagrams(control_service, socket);
  return !socket.pending_datagrams.empty();
}

bool IsBsdSocketWritable(const BsdMitmVirtualSocket& socket) {
  if (socket.backend == BsdMitmSocketBackend::DirectNative && socket.native_fd == kBsdMitmInvalidNativeFd) {
    return false;
  }
  return socket.used;
}

std::int32_t CountPollReady(const pollfd* fds, nfds_t count) {
  std::int32_t ready = 0;
  for (nfds_t index = 0; index < count; ++index) {
    if (fds[index].revents != 0) {
      ++ready;
    }
  }
  return ready;
}

void ClearFdSetBuffer(const HipcBufferView& buffer) {
  if (buffer.address != nullptr && buffer.size != 0 && IsLikelyHipcBuffer(buffer, buffer.size)) {
    std::memset(buffer.address, 0, buffer.size);
  }
}

bool FdSetContains(const HipcBufferView& buffer, std::int32_t fd) {
  if (buffer.address == nullptr || buffer.size < sizeof(fd_set) || fd < 0 || fd >= FD_SETSIZE ||
      !IsLikelyHipcBuffer(buffer, sizeof(fd_set))) {
    return false;
  }

  const auto* set = static_cast<const fd_set*>(buffer.address);
  return FD_ISSET(fd, set);
}

void FdSetInsert(const HipcBufferView& buffer, std::int32_t fd) {
  if (buffer.address == nullptr || buffer.size < sizeof(fd_set) || fd < 0 || fd >= FD_SETSIZE ||
      !IsLikelyHipcBuffer(buffer, sizeof(fd_set))) {
    return;
  }

  auto* set = static_cast<fd_set*>(buffer.address);
  FD_SET(fd, set);
}
}

class BsdMitmAdapterServer {
 public:
  explicit BsdMitmAdapterServer(BsdMitmServerContext* context) : context_(context) {
    sessions_.fill({});
  }

  ::Result Initialize() {
    return OpenAtmosphereSession(&sm_session_);
  }

  [[noreturn]] void Run() {
    while (true) {
      ProcessNext();
    }
  }

 private:
  void ProcessNext() {
    std::array<Handle, kBsdMitmMaxSessions + 1> handles{};
    handles[0] = context_->service.mitm_port;
    std::size_t handle_count = 1;
    std::array<std::size_t, kBsdMitmMaxSessions> session_indices{};
    for (std::size_t index = 0; index < sessions_.size(); ++index) {
      if (sessions_[index].client_session != INVALID_HANDLE) {
        handles[handle_count] = sessions_[index].client_session;
        session_indices[handle_count - 1] = index;
        ++handle_count;
      }
    }

    s32 signaled_index = -1;
    const ::Result wait_result =
        svcWaitSynchronization(&signaled_index, handles.data(), static_cast<s32>(handle_count), UINT64_MAX);
    if (R_FAILED(wait_result)) {
      LogWarning("bsd-mitm", "wait failed: " + FormatLibnxResult(wait_result));
      svcSleepThread(kObserverRetryDelayNs);
      return;
    }
    if (signaled_index == 0) {
      AcceptSession();
      return;
    }
    if (signaled_index < 0 || static_cast<std::size_t>(signaled_index) >= handle_count) {
      return;
    }

    const std::size_t session_index = session_indices[static_cast<std::size_t>(signaled_index) - 1];
    ProcessSession(session_index);
  }

  void AcceptSession() {
    Handle client_session = INVALID_HANDLE;
    ::Result rc = svcAcceptSession(&client_session, context_->service.mitm_port);
    if (R_FAILED(rc)) {
      LogWarning("bsd-mitm", "failed to accept bsd:u MITM session: " + FormatLibnxResult(rc));
      return;
    }

    auto slot = std::find_if(sessions_.begin(), sessions_.end(), [](const BsdMitmClientSession& session) {
      return session.client_session == INVALID_HANDLE;
    });
    if (slot == sessions_.end()) {
      LogWarning("bsd-mitm", "rejected bsd:u MITM session because the server is at capacity");
      svcCloseHandle(client_session);
      return;
    }

    AtmosphereMitmProcessInfo info{};
    Handle forward_session = INVALID_HANDLE;
    rc = AcknowledgeAtmosphereMitmSession(&sm_session_, context_->service.service_name, &info, &forward_session);
    if (R_FAILED(rc)) {
      LogWarning("bsd-mitm", "failed to acknowledge bsd:u MITM session: " + FormatLibnxResult(rc));
      svcCloseHandle(client_session);
      return;
    }

    slot->client_session = client_session;
    slot->forward_session = forward_session;
    slot->preserved_request_handle = INVALID_HANDLE;
    slot->client_info = info;
    slot->state = std::make_shared<BsdMitmClientState>();
    if (!slot->state) {
      svcCloseHandle(client_session);
      if (forward_session != INVALID_HANDLE) {
        svcCloseHandle(forward_session);
      }
      *slot = {};
      LogWarning("bsd-mitm", "failed to allocate shared bsd:u adapter state");
      return;
    }
    slot->state->client_info = info;
    slot->state->virtual_sockets.fill({});
    slot->state->next_virtual_fd = kBsdMitmFirstVirtualFd;
    slot->state->app_session_id = 0;
    slot->state->registered_tmem_handle = INVALID_HANDLE;
    slot->state->registered = false;
    slot->state->monitoring_started = false;
    slot->reserved_original_socket_zero_fd = -1;
    slot->request_count = 0;
    slot->handled_count = 0;
    slot->unsupported_count = 0;
    slot->post_reply_log.clear();
    LogInfo("bsd-mitm", "accepted bsd:u adapter session: pid=0x" + FormatHex(info.process_id, 16) +
                            " program=0x" + FormatHex(info.program_id, 16) +
                            " override_flags=0x" + FormatHex(info.override_flags, 16));
  }

  void CloseSession(std::size_t index) {
    if (index >= sessions_.size()) {
      return;
    }

    const BsdMitmClientSession& session = sessions_[index];
    if (session.client_session != INVALID_HANDLE) {
      const bool last_client_state_owner = session.state && session.state.use_count() == 1;
      if (last_client_state_owner) {
        for (BsdMitmVirtualSocket& socket : session.state->virtual_sockets) {
          if (socket.used) {
            CloseDirectNativeSocket(socket);
          }
        }
        if (context_ != nullptr && context_->control_service) {
          for (BsdMitmVirtualSocket& socket : session.state->virtual_sockets) {
            if (socket.used) {
              CloseTunnelDatagramsForSocket(context_->control_service.get(), socket);
            }
          }
          if (session.state->app_session_id != 0) {
            static_cast<void>(context_->control_service->CloseAppSession(session.state->app_session_id));
            session.state->app_session_id = 0;
          }
        }
        if (session.state->registered_tmem_handle != INVALID_HANDLE) {
          svcCloseHandle(session.state->registered_tmem_handle);
          session.state->registered_tmem_handle = INVALID_HANDLE;
        }
      }
      LogInfo("bsd-mitm", "closed bsd:u adapter session: pid=0x" +
                              FormatHex(session.client_info.process_id, 16) +
                              " program=0x" + FormatHex(session.client_info.program_id, 16) +
                              " requests=" + std::to_string(session.request_count) +
                              " handled=" + std::to_string(session.handled_count) +
                              " unsupported=" + std::to_string(session.unsupported_count));
      svcCloseHandle(session.client_session);
    }
    if (session.forward_session != INVALID_HANDLE) {
      svcCloseHandle(session.forward_session);
    }
    sessions_[index] = {};
  }

  bool AddClonedSession(const BsdMitmClientSession& parent, Handle server_session, Handle forward_session) {
    if (!parent.state) {
      return false;
    }
    auto slot = std::find_if(sessions_.begin(), sessions_.end(), [](const BsdMitmClientSession& session) {
      return session.client_session == INVALID_HANDLE;
    });
    if (slot == sessions_.end()) {
      return false;
    }

    slot->client_session = server_session;
    slot->forward_session = forward_session;
    slot->preserved_request_handle = INVALID_HANDLE;
    slot->reserved_original_socket_zero_fd = -1;
    slot->client_info = parent.client_info;
    slot->state = parent.state;
    slot->request_count = 0;
    slot->handled_count = 0;
    slot->unsupported_count = 0;
    slot->post_reply_log.clear();
    return true;
  }

  bool HandleControlRequest(std::size_t index, BsdMitmClientSession& session, const HipcParsedRequest& request) {
    const CmifInHeader* header = GetCmifHeader(request);
    if (header == nullptr) {
      PrepareCmifResponseWithToken(MakeLibnxBadInput(), 0, nullptr, 0);
      return true;
    }

    const std::uint32_t command_id = static_cast<std::uint32_t>(header->command_id);
    const std::uint32_t token = header->token;
    switch (command_id) {
      case 2:
      case 4: {
        Handle server_session = INVALID_HANDLE;
        Handle client_session = INVALID_HANDLE;
        const ::Result rc = svcCreateSession(&server_session, &client_session, 0, 0);
        if (R_FAILED(rc)) {
          LogWarning("bsd-mitm", "failed to create cloned bsd:u adapter session: " + FormatLibnxResult(rc));
          PrepareCmifResponseWithMoveHandle(rc, token, INVALID_HANDLE);
          return true;
        }

        Handle cloned_forward_session = INVALID_HANDLE;
        if (session.forward_session != INVALID_HANDLE) {
          if (command_id == 4) {
            const std::uint32_t* tag = GetCmifPayloadAs<std::uint32_t>(request);
            const std::uint32_t clone_tag = tag != nullptr ? *tag : 0;
            const ::Result clone_rc = cmifCloneCurrentObjectEx(session.forward_session,
                                                               clone_tag,
                                                               &cloned_forward_session);
            if (R_FAILED(clone_rc)) {
              svcCloseHandle(server_session);
              svcCloseHandle(client_session);
              LogWarning("bsd-mitm", "failed to clone original bsd:u session: " +
                                          FormatLibnxResult(clone_rc));
              PrepareCmifResponseWithMoveHandle(clone_rc, token, INVALID_HANDLE);
              return true;
            }
          } else {
            const ::Result clone_rc = cmifCloneCurrentObject(session.forward_session, &cloned_forward_session);
            if (R_FAILED(clone_rc)) {
              svcCloseHandle(server_session);
              svcCloseHandle(client_session);
              LogWarning("bsd-mitm", "failed to clone original bsd:u session: " +
                                          FormatLibnxResult(clone_rc));
              PrepareCmifResponseWithMoveHandle(clone_rc, token, INVALID_HANDLE);
              return true;
            }
          }
        }

        if (!AddClonedSession(session, server_session, cloned_forward_session)) {
          svcCloseHandle(server_session);
          svcCloseHandle(client_session);
          if (cloned_forward_session != INVALID_HANDLE) {
            svcCloseHandle(cloned_forward_session);
          }
          LogWarning("bsd-mitm", "failed to clone bsd:u adapter session because the server is at capacity");
          PrepareCmifResponseWithMoveHandle(MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                                            token,
                                            INVALID_HANDLE);
          return true;
        }

        ++session.handled_count;
        LogInfo("bsd-mitm", "cloned bsd:u adapter session: pid=0x" +
                                FormatHex(session.client_info.process_id, 16) +
                                " source_slot=" + std::to_string(index) +
                                " forward=" +
                                (cloned_forward_session != INVALID_HANDLE ? "cloned" : "missing"));
        PrepareCmifResponseWithMoveHandle(0, token, client_session);
        return true;
      }
      case 3: {
        std::uint16_t original_pointer_buffer_size = 0;
        std::string original_status = "missing";
        if (session.forward_session != INVALID_HANDLE) {
          const ::Result pointer_rc =
              cmifQueryPointerBufferSize(session.forward_session, &original_pointer_buffer_size);
          original_status = R_SUCCEEDED(pointer_rc)
                                ? "forwarded"
                                : "failed:" + FormatLibnxResult(pointer_rc);
        }
        const std::uint16_t pointer_buffer_size = 0;
        ++session.handled_count;
        LogInfo("bsd-mitm", "handled bsd:u QueryPointerBufferSize: pid=0x" +
                                FormatHex(session.client_info.process_id, 16) +
                                " size=0x" + FormatHex(pointer_buffer_size, 0) +
                                " original_size=0x" + FormatHex(original_pointer_buffer_size, 0) +
                                " original=" + original_status);
        PrepareCmifResponseWithToken(0, token, &pointer_buffer_size,
                                     sizeof(pointer_buffer_size));
        return true;
      }
      default:
        ++session.unsupported_count;
        LogWarning("bsd-mitm", "unsupported bsd:u adapter control command: pid=0x" +
                                    FormatHex(session.client_info.process_id, 16) +
                                    " command=" + std::to_string(header->command_id));
        PrepareCmifResponseWithToken(MakeLibnxBadInput(), token, nullptr, 0);
        return true;
    }
  }

  bool EnsureDirectBsdRuntime(std::uint32_t token) {
    const Error error = direct_socket_runtime_.Start();
    if (!error.ok()) {
      LogWarning("bsd-mitm", "failed to initialize direct BSD runtime: " + error.message);
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNetworkUnreachable);
      return false;
    }
    return true;
  }

  Result<NetworkPlan> PlanBsdRoute(BsdMitmClientSession& session,
                                   const sockaddr_storage& remote_address,
                                   socklen_t remote_address_length,
                                   TransportProtocol transport) {
    const std::optional<std::string> remote_host = Ipv4SockaddrToHost(remote_address, remote_address_length);
    const std::optional<std::uint16_t> remote_port = Ipv4SockaddrToPort(remote_address, remote_address_length);
    if (!remote_host.has_value() || !remote_port.has_value() || *remote_port == 0) {
      return MakeFailure<NetworkPlan>(ErrorCode::ParseError, "BSD MITM route plan only supports IPv4 sockaddr");
    }
    if (context_ == nullptr || !context_->control_service) {
      return MakeFailure<NetworkPlan>(ErrorCode::InvalidState, "control service unavailable for BSD MITM route plan");
    }

    const Result<std::uint64_t> app_session = EnsureBsdAppSession(context_, session);
    if (!app_session.ok()) {
      return MakeFailure<NetworkPlan>(app_session.error.code, app_session.error.message);
    }

    NetworkPlanRequest request{};
    request.session_id = app_session.value;
    request.remote_host = *remote_host;
    request.remote_port = *remote_port;
    request.transport = transport;
    request.traffic_class = GuessBsdTrafficClass(remote_address, remote_address_length, transport);
    request.route_preference = RoutePreference::Default;
    request.local_network_hint = IsLocalBypassSockaddr(remote_address, remote_address_length);
    return context_->control_service->GetNetworkPlan(request);
  }

  bool EnsureDirectNativeSocket(BsdMitmClientSession& session,
                                BsdMitmVirtualSocket& socket,
                                std::uint32_t token) {
    if (socket.native_fd != kBsdMitmInvalidNativeFd) {
      return true;
    }
    if (!EnsureDirectBsdRuntime(token)) {
      return false;
    }

    const int native_fd = bsdSocket(socket.domain, socket.type, socket.protocol);
    if (native_fd < 0) {
      PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoNetworkUnreachable));
      return false;
    }

    socket.native_fd = native_fd;
    socket.backend = BsdMitmSocketBackend::DirectNative;

    if (socket.status_flags != 0 && bsdFcntl(socket.native_fd, F_SETFL, socket.status_flags) < 0) {
      const std::int32_t errno_value = CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument);
      CloseDirectNativeSocket(socket);
      PrepareBsdRetErrnoResponse(token, -1, errno_value);
      return false;
    }
    if (!ReplayPendingSocketOptions(socket)) {
      const std::int32_t errno_value = CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument);
      CloseDirectNativeSocket(socket);
      PrepareBsdRetErrnoResponse(token, -1, errno_value);
      return false;
    }
    if (socket.bound &&
        bsdBind(socket.native_fd, reinterpret_cast<const sockaddr*>(&socket.local_address),
                socket.local_address_length) < 0) {
      const std::int32_t errno_value = CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument);
      CloseDirectNativeSocket(socket);
      PrepareBsdRetErrnoResponse(token, -1, errno_value);
      return false;
    }

    LogInfo("bsd-mitm", "opened direct native BSD socket: pid=0x" +
                            FormatHex(session.client_info.process_id, 16) +
                            " fd=" + std::to_string(socket.fd) +
                            " native_fd=" + std::to_string(socket.native_fd));
    return true;
  }

  bool HandleDirectSend(BsdMitmClientSession& session,
                        BsdMitmVirtualSocket& socket,
                        const HipcBufferView& payload,
                        const sockaddr_storage* remote_address,
                        socklen_t remote_address_length,
                        std::int32_t flags,
                        std::uint32_t token) {
    if (payload.address == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }
    if (!IsLikelyHipcBuffer(payload, payload.size)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }
    if (!EnsureDirectNativeSocket(session, socket, token)) {
      return true;
    }

    std::vector<std::uint8_t> payload_copy(payload.size);
    if (!payload_copy.empty() &&
        !CopyFromHipcBuffer(payload_copy.data(), payload, payload_copy.size())) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }

    int ret = -1;
    if (remote_address != nullptr) {
      ret = bsdSendTo(socket.native_fd, payload_copy.data(), payload_copy.size(), flags,
                      reinterpret_cast<const sockaddr*>(remote_address), remote_address_length);
    } else {
      ret = bsdSend(socket.native_fd, payload_copy.data(), payload_copy.size(), flags);
    }
    if (ret < 0) {
      PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoWouldBlock));
      return true;
    }

    ++socket.send_calls;
    ++session.handled_count;
    if (ShouldLogSparseCount(socket.send_calls)) {
      LogInfo("bsd-mitm", "sent direct native BSD payload: pid=0x" +
                              FormatHex(session.client_info.process_id, 16) +
                              " fd=" + std::to_string(socket.fd) +
                              " bytes=" + std::to_string(ret));
    }
    PrepareBsdRetErrnoResponse(token, ret, 0);
    return true;
  }

  bool HandleDirectRecv(BsdMitmClientSession& session,
                        BsdMitmVirtualSocket& socket,
                        const HipcBufferView& payload_output,
                        const HipcBufferView& remote_output,
                        bool include_remote_address,
                        std::int32_t flags,
                        std::uint32_t token) {
    if (payload_output.address == nullptr || payload_output.size == 0) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }
    const std::size_t receive_capacity =
        std::min<std::size_t>(payload_output.size, kBsdMitmDatagramBurstMaxPayloadBytes);
    if (!IsLikelyHipcBuffer(payload_output, receive_capacity)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }
    if (!EnsureDirectNativeSocket(session, socket, token)) {
      return true;
    }

    std::vector<std::uint8_t> receive_buffer(receive_capacity);
    sockaddr_storage remote_address{};
    socklen_t remote_length = sizeof(remote_address);
    int ret = -1;
    if (include_remote_address) {
      ret = bsdRecvFrom(socket.native_fd, receive_buffer.data(), receive_buffer.size(), flags,
                        reinterpret_cast<sockaddr*>(&remote_address), &remote_length);
    } else {
      ret = bsdRecv(socket.native_fd, receive_buffer.data(), receive_buffer.size(), flags);
      remote_length = 0;
    }
    if (ret < 0) {
      PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoWouldBlock));
      return true;
    }

    if (!CopyToHipcBuffer(payload_output, receive_buffer.data(), static_cast<std::size_t>(ret))) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }

    if (include_remote_address && remote_output.address != nullptr && remote_output.size != 0) {
      const std::size_t address_bytes = std::min<std::size_t>(remote_output.size, remote_length);
      if (!CopyToHipcBuffer(remote_output, &remote_address, address_bytes)) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
        return true;
      }
      remote_length = static_cast<socklen_t>(address_bytes);
    } else if (!include_remote_address) {
      remote_length = 0;
    }

    ++socket.recv_calls;
    ++session.handled_count;
    if (ShouldLogSparseCount(socket.recv_calls)) {
      LogInfo("bsd-mitm", "received direct native BSD payload: pid=0x" +
                              FormatHex(session.client_info.process_id, 16) +
                              " fd=" + std::to_string(socket.fd) +
                              " bytes=" + std::to_string(ret));
    }

    if (include_remote_address) {
      PrepareBsdRetErrnoExtraResponse(token, ret, 0, &remote_length, sizeof(remote_length));
    } else {
      PrepareBsdRetErrnoResponse(token, ret, 0);
    }
    return true;
  }

  bool HandleBind(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const auto* fd = GetCmifPayloadAs<std::int32_t>(request);
    BsdMitmVirtualSocket* socket = fd != nullptr ? FindVirtualSocket(session, *fd) : nullptr;
    if (socket == nullptr) {
      LogWarning("bsd-mitm", "bsd:u Bind for unknown fd: pid=0x" +
                                  FormatHex(session.client_info.process_id, 16) +
                                  " fd=" + std::to_string(fd != nullptr ? *fd : -1));
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }

    socklen_t address_length = 0;
    const std::optional<sockaddr_storage> address = ReadSockaddrFromBuffer(GetAutoSendBuffer(request, 0), &address_length);
    if (!address.has_value()) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }
    if (!Ipv4SockaddrToHost(*address, address_length).has_value()) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoAddressFamilyNotSupported);
      return true;
    }

    socket->local_address = *address;
    socket->local_address_length = address_length;
    socket->bound = true;
    if (socket->native_fd != kBsdMitmInvalidNativeFd &&
        bsdBind(socket->native_fd, reinterpret_cast<const sockaddr*>(&socket->local_address),
                socket->local_address_length) < 0) {
      PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument));
      return true;
    }
    ++session.handled_count;
    LogInfo("bsd-mitm", "handled bsd:u Bind: pid=0x" +
                            FormatHex(session.client_info.process_id, 16) +
                            " fd=" + std::to_string(socket->fd));
    PrepareBsdRetErrnoResponse(token, 0, 0);
    return true;
  }

  bool HandleConnect(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const auto* fd = GetCmifPayloadAs<std::int32_t>(request);
    BsdMitmVirtualSocket* socket = fd != nullptr ? FindVirtualSocket(session, *fd) : nullptr;
    if (socket == nullptr) {
      LogWarning("bsd-mitm", "bsd:u Connect for unknown fd: pid=0x" +
                                  FormatHex(session.client_info.process_id, 16) +
                                  " fd=" + std::to_string(fd != nullptr ? *fd : -1));
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }
    const bool datagram_socket = IsBsdDatagramSocket(*socket);
    const bool stream_socket = IsBsdStreamSocket(*socket);
    if (!datagram_socket && !stream_socket) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
      return true;
    }

    socklen_t address_length = 0;
    const std::optional<sockaddr_storage> address = ReadSockaddrFromBuffer(GetAutoSendBuffer(request, 0), &address_length);
    if (!address.has_value() || !Ipv4SockaddrToHost(*address, address_length).has_value()) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoAddressFamilyNotSupported);
      return true;
    }

    const Result<NetworkPlan> plan =
        PlanBsdRoute(session, *address, address_length, stream_socket ? TransportProtocol::Tcp : TransportProtocol::Udp);
    if (!plan.ok()) {
      PrepareBsdRetErrnoResponse(token, -1, ErrnoFromSwgErrorCode(plan.error.code));
      return true;
    }
    if (plan.value.action == RouteAction::Direct) {
      if (!EnsureDirectNativeSocket(session, *socket, token)) {
        return true;
      }
      const int ret = bsdConnect(socket->native_fd, reinterpret_cast<const sockaddr*>(&*address), address_length);
      const std::int32_t errno_value = CurrentBsdErrnoOr(EINPROGRESS);
      if (ret == 0 || IsNonBlockingConnectProgress(errno_value)) {
        socket->connected_remote_address = *address;
        socket->connected_remote_address_length = address_length;
        socket->connected = true;
        ++session.handled_count;
        const std::optional<std::string> remote_host = Ipv4SockaddrToHost(*address, address_length);
        const std::optional<std::uint16_t> remote_port = Ipv4SockaddrToPort(*address, address_length);
        LogInfo("bsd-mitm", std::string("handled bsd:u Connect direct ") +
                                (stream_socket ? "TCP" : "UDP") +
                                ": pid=0x" + FormatHex(session.client_info.process_id, 16) +
                                " fd=" + std::to_string(socket->fd) +
                                " target=" + remote_host.value_or("?") +
                                ":" + std::to_string(remote_port.value_or(0)) +
                                " ret=" + std::to_string(ret) +
                                " errno=" + std::to_string(ret < 0 ? errno_value : 0));
        PrepareBsdRetErrnoResponse(token, ret, ret < 0 ? errno_value : 0);
        return true;
      }

      const std::optional<std::string> remote_host = Ipv4SockaddrToHost(*address, address_length);
      const std::optional<std::uint16_t> remote_port = Ipv4SockaddrToPort(*address, address_length);
      LogWarning("bsd-mitm", std::string("failed bsd:u Connect direct ") +
                                    (stream_socket ? "TCP" : "UDP") +
                                    ": pid=0x" + FormatHex(session.client_info.process_id, 16) +
                                    " fd=" + std::to_string(socket->fd) +
                                    " target=" + remote_host.value_or("?") +
                                    ":" + std::to_string(remote_port.value_or(0)) +
                                    " ret=" + std::to_string(ret) +
                                    " errno=" + std::to_string(errno_value));
      PrepareBsdRetErrnoResponse(token, -1, errno_value);
      return true;
    }
    if (plan.value.action != RouteAction::Tunnel) {
      LogWarning("bsd-mitm", "rejected bsd:u Connect because route action is not supported: pid=0x" +
                                  FormatHex(session.client_info.process_id, 16) +
                                  " fd=" + std::to_string(socket->fd) +
                                  " action=" + std::string(ToString(plan.value.action)));
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNetworkUnreachable);
      return true;
    }
    if (stream_socket) {
      LogWarning("bsd-mitm", "rejected bsd:u Connect TCP tunnel because transparent TCP is not implemented yet: pid=0x" +
                                  FormatHex(session.client_info.process_id, 16) +
                                  " fd=" + std::to_string(socket->fd));
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
      return true;
    }

    socket->connected_remote_address = *address;
    socket->connected_remote_address_length = address_length;
    socket->connected = true;
    socket->backend = BsdMitmSocketBackend::TunnelDatagram;
    ++session.handled_count;
    LogInfo("bsd-mitm", "handled bsd:u Connect UDP: pid=0x" +
                            FormatHex(session.client_info.process_id, 16) +
                            " fd=" + std::to_string(socket->fd));
    PrepareBsdRetErrnoResponse(token, 0, 0);
    return true;
  }

  bool HandleSendDatagram(BsdMitmClientSession& session,
                          const HipcParsedRequest& request,
                          std::uint32_t token,
                          bool has_explicit_remote) {
    const BsdSockFdIn* input = GetCmifPayloadAs<BsdSockFdIn>(request);
    BsdMitmVirtualSocket* socket = input != nullptr ? FindVirtualSocket(session, input->sockfd) : nullptr;
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }
    const bool datagram_socket = IsBsdDatagramSocket(*socket);
    const bool stream_socket = IsBsdStreamSocket(*socket);
    if (!datagram_socket && !stream_socket) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
      return true;
    }

    sockaddr_storage remote_address{};
    socklen_t remote_address_length = 0;
    if (has_explicit_remote) {
      const std::optional<sockaddr_storage> parsed =
          ReadSockaddrFromBuffer(GetAutoSendBuffer(request, 1), &remote_address_length);
      if (!parsed.has_value()) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
        return true;
      }
      remote_address = *parsed;
    } else {
      if (!socket->connected) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNotConnected);
        return true;
      }
      remote_address = socket->connected_remote_address;
      remote_address_length = socket->connected_remote_address_length;
    }

    const HipcBufferView payload = GetAutoSendBuffer(request, 0);
    if (socket->backend == BsdMitmSocketBackend::DirectNative || stream_socket) {
      if (stream_socket && socket->backend != BsdMitmSocketBackend::DirectNative) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNotConnected);
        return true;
      }
      return HandleDirectSend(session, *socket, payload,
                              has_explicit_remote ? &remote_address : nullptr,
                              remote_address_length,
                              input->flags,
                              token);
    }

    const Result<NetworkPlan> plan =
        PlanBsdRoute(session, remote_address, remote_address_length, TransportProtocol::Udp);
    if (!plan.ok()) {
      PrepareBsdRetErrnoResponse(token, -1, ErrnoFromSwgErrorCode(plan.error.code));
      return true;
    }
    if (plan.value.action == RouteAction::Direct) {
      return HandleDirectSend(session, *socket, payload,
                              has_explicit_remote ? &remote_address : nullptr,
                              remote_address_length,
                              input->flags,
                              token);
    }
    if (plan.value.action != RouteAction::Tunnel) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNetworkUnreachable);
      return true;
    }

    socket->backend = BsdMitmSocketBackend::TunnelDatagram;
    const Result<std::uint64_t> sent =
        SendBsdTunnelDatagram(context_, session, *socket, remote_address, remote_address_length, payload);
    if (!sent.ok()) {
      PrepareBsdRetErrnoResponse(token, -1, ErrnoFromSwgErrorCode(sent.error.code));
      return true;
    }

    ++session.handled_count;
    PrepareBsdRetErrnoResponse(token, static_cast<std::int32_t>(payload.size), 0);
    return true;
  }

  bool HandleRecvDatagram(BsdMitmClientSession& session,
                          const HipcParsedRequest& request,
                          std::uint32_t token,
                          bool include_remote_address) {
    const BsdSockFdIn* input = GetCmifPayloadAs<BsdSockFdIn>(request);
    BsdMitmVirtualSocket* socket = input != nullptr ? FindVirtualSocket(session, input->sockfd) : nullptr;
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }
    const bool datagram_socket = IsBsdDatagramSocket(*socket);
    const bool stream_socket = IsBsdStreamSocket(*socket);
    if (!datagram_socket && !stream_socket) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
      return true;
    }

    if (socket->backend == BsdMitmSocketBackend::DirectNative || stream_socket) {
      if (stream_socket && socket->backend != BsdMitmSocketBackend::DirectNative) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNotConnected);
        return true;
      }
      return HandleDirectRecv(session, *socket,
                              GetAutoRecvBuffer(request, 0),
                              GetAutoRecvBuffer(request, 1),
                              include_remote_address,
                              input->flags,
                              token);
    }

    RefreshBsdSocketPendingDatagrams(context_ != nullptr ? context_->control_service.get() : nullptr, *socket);
    if (socket->pending_datagrams.empty()) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoWouldBlock);
      return true;
    }

    BsdMitmPendingDatagram pending = std::move(socket->pending_datagrams.front());
    socket->pending_datagrams.pop_front();

    const HipcBufferView payload_output = GetAutoRecvBuffer(request, 0);
    if (payload_output.address == nullptr || payload_output.size == 0) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }

    const std::size_t bytes_to_copy = std::min(payload_output.size, pending.datagram.payload.size());
    if (!CopyToHipcBuffer(payload_output, pending.datagram.payload.data(), bytes_to_copy)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }

    socklen_t remote_length = pending.remote_address_length;
    if (include_remote_address) {
      const HipcBufferView remote_output = GetAutoRecvBuffer(request, 1);
      if (remote_output.address != nullptr && remote_output.size != 0) {
        const std::size_t address_bytes = std::min<std::size_t>(remote_output.size, remote_length);
        if (!CopyToHipcBuffer(remote_output, &pending.remote_address, address_bytes)) {
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
          return true;
        }
        remote_length = static_cast<socklen_t>(address_bytes);
      } else {
        remote_length = 0;
      }
    }

    ++socket->recv_calls;
    ++session.handled_count;
    if (ShouldLogSparseCount(socket->recv_calls)) {
      LogInfo("bsd-mitm", "received tunnel UDP datagram: pid=0x" +
                              FormatHex(session.client_info.process_id, 16) +
                              " fd=" + std::to_string(socket->fd) +
                              " bytes=" + std::to_string(bytes_to_copy) +
                              " counter=" + std::to_string(pending.datagram.counter));
    }

    if (include_remote_address) {
      PrepareBsdRetErrnoExtraResponse(token, static_cast<std::int32_t>(bytes_to_copy), 0,
                                      &remote_length, sizeof(remote_length));
    } else {
      PrepareBsdRetErrnoResponse(token, static_cast<std::int32_t>(bytes_to_copy), 0);
    }
    return true;
  }

  bool HandlePoll(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const BsdPollIn* input = GetCmifPayloadAs<BsdPollIn>(request);
    if (input == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }

    const HipcBufferView input_buffer = GetAutoSendBuffer(request, 0);
    const HipcBufferView output_buffer = GetAutoRecvBuffer(request, 0);
    const std::size_t fds_size = static_cast<std::size_t>(input->nfds) * sizeof(pollfd);
    if (input_buffer.address == nullptr || output_buffer.address == nullptr ||
        input_buffer.size < fds_size || output_buffer.size < fds_size) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }
    if (!IsLikelyHipcBuffer(input_buffer, fds_size) ||
        !IsLikelyHipcBuffer(output_buffer, fds_size)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }

    std::vector<pollfd> fds(input->nfds);
    if (!fds.empty() && !CopyFromHipcBuffer(fds.data(), input_buffer, fds_size)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }
    for (nfds_t index = 0; index < input->nfds; ++index) {
      fds[index].revents = 0;
      BsdMitmVirtualSocket* socket = FindVirtualSocket(session, fds[index].fd);
      if (socket == nullptr) {
        fds[index].revents = POLLNVAL;
        continue;
      }
      ++socket->poll_calls;
      if (socket->backend == BsdMitmSocketBackend::DirectNative) {
        fds[index].revents = PollDirectNativeSocket(*socket, fds[index].events);
        continue;
      }
      if ((fds[index].events & POLLIN) != 0 &&
          IsBsdSocketReadable(context_ != nullptr ? context_->control_service.get() : nullptr, *socket)) {
        fds[index].revents |= POLLIN;
      }
      if ((fds[index].events & POLLOUT) != 0 && IsBsdSocketWritable(*socket)) {
        fds[index].revents |= POLLOUT;
      }
    }

    if (!CopyToHipcBuffer(output_buffer, fds.data(), fds_size)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
      return true;
    }
    ++session.handled_count;
    PrepareBsdRetErrnoResponse(token, CountPollReady(fds.data(), input->nfds), 0);
    return true;
  }

  bool HandleSelect(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const BsdSelectIn* input = GetCmifPayloadAs<BsdSelectIn>(request);
    if (input == nullptr || input->nfds < 0 || input->nfds > FD_SETSIZE) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }

    const HipcBufferView read_input = GetAutoSendBuffer(request, 0);
    const HipcBufferView write_input = GetAutoSendBuffer(request, 1);
    const HipcBufferView read_output = GetAutoRecvBuffer(request, 0);
    const HipcBufferView write_output = GetAutoRecvBuffer(request, 1);
    const HipcBufferView except_output = GetAutoRecvBuffer(request, 2);
    ClearFdSetBuffer(read_output);
    ClearFdSetBuffer(write_output);
    ClearFdSetBuffer(except_output);

    std::int32_t ready = 0;
    for (std::int32_t fd = 0; fd < input->nfds; ++fd) {
      BsdMitmVirtualSocket* socket = FindVirtualSocket(session, fd);
      if (socket == nullptr) {
        continue;
      }
      if (socket->backend == BsdMitmSocketBackend::DirectNative) {
        std::int16_t events = 0;
        if (FdSetContains(read_input, fd)) {
          events |= POLLIN;
        }
        if (FdSetContains(write_input, fd)) {
          events |= POLLOUT;
        }
        const std::int32_t revents = PollDirectNativeSocket(*socket, events);
        if ((revents & (POLLIN | POLLERR | POLLHUP)) != 0 && FdSetContains(read_input, fd)) {
          FdSetInsert(read_output, fd);
          ++ready;
        }
        if ((revents & (POLLOUT | POLLERR | POLLHUP)) != 0 && FdSetContains(write_input, fd)) {
          FdSetInsert(write_output, fd);
          ++ready;
        }
        continue;
      }
      if (FdSetContains(read_input, fd) &&
          IsBsdSocketReadable(context_ != nullptr ? context_->control_service.get() : nullptr, *socket)) {
        FdSetInsert(read_output, fd);
        ++ready;
      }
      if (FdSetContains(write_input, fd) && IsBsdSocketWritable(*socket)) {
        FdSetInsert(write_output, fd);
        ++ready;
      }
    }

    ++session.handled_count;
    PrepareBsdRetErrnoResponse(token, ready, 0);
    return true;
  }

  bool HandleGetSockName(BsdMitmClientSession& session,
                         const HipcParsedRequest& request,
                         std::uint32_t token,
                         bool peer) {
    const auto* fd = GetCmifPayloadAs<std::int32_t>(request);
    BsdMitmVirtualSocket* socket = fd != nullptr ? FindVirtualSocket(session, *fd) : nullptr;
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }

    if (socket->native_fd != kBsdMitmInvalidNativeFd) {
      sockaddr_storage native_address{};
      socklen_t native_length = sizeof(native_address);
      const int ret = peer ? bsdGetPeerName(socket->native_fd, reinterpret_cast<sockaddr*>(&native_address), &native_length)
                           : bsdGetSockName(socket->native_fd, reinterpret_cast<sockaddr*>(&native_address), &native_length);
      if (ret < 0) {
        PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoNotConnected));
        return true;
      }

      const HipcBufferView output = GetAutoRecvBuffer(request, 0);
      socklen_t output_length = 0;
      if (output.address != nullptr && output.size != 0) {
        output_length = static_cast<socklen_t>(std::min<std::size_t>(output.size, native_length));
        if (!CopyToHipcBuffer(output, &native_address, output_length)) {
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
          return true;
        }
      }

      ++session.handled_count;
      PrepareBsdRetErrnoExtraResponse(token, 0, 0, &output_length, sizeof(output_length));
      return true;
    }

    const sockaddr_storage* source = nullptr;
    socklen_t source_length = 0;
    if (peer) {
      if (!socket->connected) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNotConnected);
        return true;
      }
      source = &socket->connected_remote_address;
      source_length = socket->connected_remote_address_length;
    } else if (socket->bound) {
      source = &socket->local_address;
      source_length = socket->local_address_length;
    }

    sockaddr_in fallback{};
    if (source == nullptr) {
      fallback.sin_family = AF_INET;
      fallback.sin_port = 0;
      fallback.sin_addr.s_addr = htonl(INADDR_ANY);
      source = reinterpret_cast<const sockaddr_storage*>(&fallback);
      source_length = sizeof(fallback);
    }

    const HipcBufferView output = GetAutoRecvBuffer(request, 0);
    socklen_t output_length = 0;
    if (output.address != nullptr && output.size != 0) {
      output_length = static_cast<socklen_t>(std::min<std::size_t>(output.size, source_length));
      if (!CopyToHipcBuffer(output, source, output_length)) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
        return true;
      }
    }

    ++session.handled_count;
    PrepareBsdRetErrnoExtraResponse(token, 0, 0, &output_length, sizeof(output_length));
    return true;
  }

  bool HandleFcntl(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const BsdFcntlIn* input_ptr = GetCmifPayloadAs<BsdFcntlIn>(request);
    if (input_ptr == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoInvalidArgument);
      return true;
    }
    const BsdFcntlIn input = *input_ptr;
    BsdMitmVirtualSocket* socket = FindVirtualSocket(session, input.fd);
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }

    std::int32_t ret = -1;
    std::int32_t errno_value = 0;
    if (input.cmd == F_GETFL) {
      if (socket->native_fd != kBsdMitmInvalidNativeFd) {
        const int native_ret = bsdFcntl(socket->native_fd, F_GETFL, 0);
        if (native_ret < 0) {
          errno_value = CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument);
        } else {
          socket->status_flags = native_ret;
          ret = native_ret;
        }
      } else {
        ret = socket->status_flags;
      }
    } else if (input.cmd == F_SETFL) {
      socket->status_flags = input.flags;
      if (socket->native_fd != kBsdMitmInvalidNativeFd && bsdFcntl(socket->native_fd, F_SETFL, input.flags) < 0) {
        errno_value = CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument);
      } else {
        ret = 0;
      }
#if defined(F_GETFD)
    } else if (input.cmd == F_GETFD) {
      ret = socket->descriptor_flags;
#endif
#if defined(F_SETFD)
    } else if (input.cmd == F_SETFD) {
      socket->descriptor_flags = input.flags;
      ret = 0;
#endif
    } else {
      errno_value = kLinuxErrnoOperationNotSupported;
    }
    ++session.handled_count;
    LogInfo("bsd-mitm", "handled bsd:u Fcntl: pid=0x" +
                            FormatHex(session.client_info.process_id, 16) +
                            " fd=" + std::to_string(input.fd) +
                            " cmd=" + std::to_string(input.cmd) +
                            " flags=" + std::to_string(input.flags) +
                            " ret=" + std::to_string(ret) +
                            " errno=" + std::to_string(ret < 0 ? errno_value : 0) +
                            " native_fd=" + std::to_string(socket->native_fd));
    PrepareBsdRetErrnoResponse(token, ret, errno_value);
    return true;
  }

  bool HandleGetSockOpt(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const BsdSockFdLevelOptionIn* input = GetCmifPayloadAs<BsdSockFdLevelOptionIn>(request);
    BsdMitmVirtualSocket* socket = input != nullptr ? FindVirtualSocket(session, input->sockfd) : nullptr;
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }

    if (socket->native_fd != kBsdMitmInvalidNativeFd) {
      const HipcBufferView output = GetAutoRecvBuffer(request, 0);
      constexpr std::size_t kMaxNativeSockOptBytes = 256;
      std::array<std::uint8_t, kMaxNativeSockOptBytes> option_buffer{};
      socklen_t output_length = 0;
      if (output.address != nullptr && output.size != 0) {
        output_length = static_cast<socklen_t>(std::min<std::size_t>(output.size, option_buffer.size()));
        if (!IsLikelyHipcBuffer(output, output_length)) {
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
          return true;
        }
      }
      const int ret = bsdGetSockOpt(socket->native_fd, input->level, input->optname,
                                    option_buffer.data(), &output_length);
      if (ret < 0) {
        PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument));
        return true;
      }
      if (output_length != 0 &&
          !CopyToHipcBuffer(output, option_buffer.data(), std::min<std::size_t>(output_length, option_buffer.size()))) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
        return true;
      }

      ++session.handled_count;
      PrepareBsdRetErrnoExtraResponse(token, ret, 0, &output_length, sizeof(output_length));
      return true;
    }

    if (input->level == SOL_SOCKET && input->optname == SO_ERROR) {
      const HipcBufferView output = GetAutoRecvBuffer(request, 0);
      socklen_t output_length = 0;
      if (output.address != nullptr && output.size >= sizeof(std::int32_t)) {
        const std::int32_t value = 0;
        if (!CopyToHipcBuffer(output, &value, sizeof(value))) {
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
          return true;
        }
        output_length = sizeof(value);
      }
      PrepareBsdRetErrnoExtraResponse(token, 0, 0, &output_length, sizeof(output_length));
      ++session.handled_count;
      return true;
    }

    PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
    return true;
  }

  bool HandleSetSockOpt(BsdMitmClientSession& session, const HipcParsedRequest& request, std::uint32_t token) {
    const BsdSockFdLevelOptionIn* input = GetCmifPayloadAs<BsdSockFdLevelOptionIn>(request);
    BsdMitmVirtualSocket* socket = input != nullptr ? FindVirtualSocket(session, input->sockfd) : nullptr;
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }

    const HipcBufferView option = GetAutoSendBuffer(request, 0);
    if (socket->native_fd != kBsdMitmInvalidNativeFd) {
      if (option.address == nullptr || option.size > kBsdMitmDatagramBurstMaxPayloadBytes ||
          !IsLikelyHipcBuffer(option, option.size)) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
        return true;
      }
      std::vector<std::uint8_t> option_copy(option.size);
      if (!option_copy.empty() &&
          !CopyFromHipcBuffer(option_copy.data(), option, option_copy.size())) {
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadAddress);
        return true;
      }
      const int ret = bsdSetSockOpt(socket->native_fd, input->level, input->optname,
                                    option_copy.data(), static_cast<socklen_t>(option_copy.size()));
      if (ret < 0) {
        PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument));
        return true;
      }
      ++session.handled_count;
      PrepareBsdRetErrnoResponse(token, ret, 0);
      return true;
    }

    if (!StorePendingSocketOption(*socket, input->level, input->optname, option)) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
      return true;
    }

    ++session.handled_count;
    PrepareBsdRetErrnoResponse(token, 0, 0);
    return true;
  }

  bool HandleReadWrite(BsdMitmClientSession& session,
                       const HipcParsedRequest& request,
                       std::uint32_t token,
                       bool write) {
    const auto* fd = GetCmifPayloadAs<std::int32_t>(request);
    BsdMitmVirtualSocket* socket = fd != nullptr ? FindVirtualSocket(session, *fd) : nullptr;
    if (socket == nullptr) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
      return true;
    }
    if (socket->backend != BsdMitmSocketBackend::DirectNative) {
      PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
      return true;
    }

    if (write) {
      return HandleDirectSend(session, *socket, GetAutoSendBuffer(request, 0), nullptr, 0, 0, token);
    }
    return HandleDirectRecv(session, *socket, GetAutoRecvBuffer(request, 0), {}, false, 0, token);
  }

  bool HandleRequest(std::size_t index, BsdMitmClientSession& session, const HipcParsedRequest& request) {
    (void)index;
    const CmifInHeader* header = GetCmifHeader(request);
    if (header == nullptr) {
      PrepareCmifResponseWithToken(MakeLibnxBadInput(), 0, nullptr, 0);
      return true;
    }

    const auto command_id = static_cast<std::uint32_t>(header->command_id);
    const std::uint32_t token = header->token;
    switch (command_id) {
      case 0: {
        const BsdRegisterClientIn* input_ptr = GetCmifPayloadAs<BsdRegisterClientIn>(request);
        if (input_ptr == nullptr) {
          PrepareCmifResponseWithToken(MakeLibnxBadInput(), token, nullptr, 0);
          return true;
        }
        const BsdRegisterClientIn input = *input_ptr;

        const Handle tmem_handle = GetFirstIncomingHandle(request);
        BsdMitmClientState* state = GetBsdClientState(session);
        if (state == nullptr) {
          PrepareCmifResponseWithToken(MakeLibnxBadInput(), token, nullptr, 0);
          return true;
        }
        if (tmem_handle != INVALID_HANDLE) {
          if (state->registered_tmem_handle != INVALID_HANDLE &&
              state->registered_tmem_handle != tmem_handle) {
            svcCloseHandle(state->registered_tmem_handle);
          }
          state->registered_tmem_handle = tmem_handle;
          session.preserved_request_handle = tmem_handle;
        }

        state->registered = true;
        std::string original_status = "skipped";
        if (session.forward_session != INVALID_HANDLE && state->registered_tmem_handle != INVALID_HANDLE) {
          std::uint64_t original_pid = 0;
          const ::Result original_rc = ForwardOriginalBsdRegisterClient(session.forward_session,
                                                                        input,
                                                                        state->registered_tmem_handle,
                                                                        &original_pid);
          state->original_registered = R_SUCCEEDED(original_rc);
          original_status = state->original_registered
                                ? "registered"
                                : "failed:" + FormatLibnxResult(original_rc);
        }
        ++session.handled_count;
        const std::uint64_t pid = session.client_info.process_id;
        LogInfo("bsd-mitm", "handled bsd:u RegisterClient: pid=0x" +
                                FormatHex(session.client_info.process_id, 16) +
                                " program=0x" + FormatHex(session.client_info.program_id, 16) +
                                " version=" + std::to_string(input.config.version) +
                                " tmem=0x" + FormatHex(input.transfer_memory_size, 0) +
                                " tmem_handle=" +
                                (state->registered_tmem_handle != INVALID_HANDLE ? "preserved" : "missing") +
                                " original=" + original_status);
        PrepareCmifResponseWithToken(0, token, &pid, sizeof(pid));
        return true;
      }
      case 1: {
        const std::uint64_t* pid_ptr = GetCmifPayloadAs<std::uint64_t>(request);
        if (pid_ptr == nullptr) {
          PrepareCmifResponseWithToken(MakeLibnxBadInput(), token, nullptr, 0);
          return true;
        }
        const std::uint64_t pid = *pid_ptr;

        std::string original_status = "skipped";
        if (BsdMitmClientState* state = GetBsdClientState(session)) {
          state->monitoring_started = true;
          if (session.forward_session != INVALID_HANDLE) {
            const ::Result original_rc = ForwardOriginalBsdStartMonitoring(session.forward_session, pid);
            state->original_monitoring_started = R_SUCCEEDED(original_rc);
            original_status = state->original_monitoring_started
                                  ? "started"
                                  : "failed:" + FormatLibnxResult(original_rc);
          }
        }
        ++session.handled_count;
        LogInfo("bsd-mitm", "handled bsd:u StartMonitoring: pid=0x" +
                                FormatHex(session.client_info.process_id, 16) +
                                " monitor_pid=0x" + FormatHex(pid, 16) +
                                " original=" + original_status);
        PrepareCmifResponseWithToken(0, token, nullptr, 0);
        return true;
      }
      case 2:
      case 3: {
        const BsdSocketIn* input_ptr = GetCmifPayloadAs<BsdSocketIn>(request);
        if (input_ptr == nullptr) {
          PrepareCmifResponseWithToken(MakeLibnxBadInput(), token, nullptr, 0);
          return true;
        }
        const BsdSocketIn input = *input_ptr;

        const ::Result forward_rc = ForwardCurrentMitmRequest(session.forward_session);
        if (R_FAILED(forward_rc)) {
          ++session.handled_count;
          LogWarning("bsd-mitm", std::string("failed to forward original bsd:u ") +
                                      DescribeBsdCommand(command_id) +
                                      ": pid=0x" + FormatHex(session.client_info.process_id, 16) +
                                      " rc=" + FormatLibnxResult(forward_rc));
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNetworkUnreachable);
          return true;
        }

        std::array<std::uint8_t, kBsdMitmForwardedResponseSnapshotBytes> forwarded_response{};
        std::memcpy(forwarded_response.data(), armGetTls(), forwarded_response.size());

        CmifResponse response{};
        const ::Result parse_rc =
            cmifParseResponse(&response, armGetTls(), false, sizeof(BsdRetErrnoOut));
        if (R_FAILED(parse_rc)) {
          ++session.handled_count;
          LogWarning("bsd-mitm", std::string("failed to parse forwarded original bsd:u ") +
                                      DescribeBsdCommand(command_id) +
                                      " response: pid=0x" + FormatHex(session.client_info.process_id, 16) +
                                      " rc=" + FormatLibnxResult(parse_rc));
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoNetworkUnreachable);
          return true;
        }
        const BsdRetErrnoOut original_socket =
            *static_cast<const BsdRetErrnoOut*>(response.data);
        BsdRetErrnoOut visible_socket = original_socket;
        const std::size_t response_data_offset =
            static_cast<const std::uint8_t*>(response.data) -
            static_cast<const std::uint8_t*>(armGetTls());
        std::string fd_zero_patch_status = "not-needed";
        if (visible_socket.ret == 0 && session.reserved_original_socket_zero_fd < 0 &&
            response_data_offset + sizeof(BsdRetErrnoOut) <= forwarded_response.size()) {
          BsdRetErrnoOut replacement_socket{};
          const ::Result replacement_rc = OpenReplacementOriginalBsdSocket(session.forward_session,
                                                                           command_id,
                                                                           input,
                                                                           &replacement_socket);
          if (R_SUCCEEDED(replacement_rc) && replacement_socket.ret >= 0) {
            session.reserved_original_socket_zero_fd = original_socket.ret;
            visible_socket = replacement_socket;
            std::memcpy(forwarded_response.data() + response_data_offset,
                        &visible_socket,
                        sizeof(visible_socket));
            fd_zero_patch_status = "patched:" + std::to_string(replacement_socket.ret);
          } else {
            fd_zero_patch_status = "failed:" + FormatLibnxResult(replacement_rc) +
                                   ":ret=" + std::to_string(replacement_socket.ret) +
                                   ":errno=" + std::to_string(replacement_socket.errno_);
          }
        }

        BsdMitmVirtualSocket* socket = nullptr;
        if (visible_socket.ret >= 0) {
          socket = TrackBsdSocket(session, visible_socket.ret, input, true);
          if (socket == nullptr) {
            BsdRetErrnoOut original_close{};
            static_cast<void>(CloseOriginalBsdSocketFd(session.forward_session,
                                                       visible_socket.ret,
                                                       &original_close));
            ++session.handled_count;
            LogWarning("bsd-mitm", std::string("failed to track original bsd:u ") +
                                        DescribeBsdCommand(command_id) +
                                        " fd because the adapter table is full: pid=0x" +
                                        FormatHex(session.client_info.process_id, 16) +
                                        " fd=" + std::to_string(visible_socket.ret));
            PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoTooManyOpenFiles);
            return true;
          }
        }

        ++session.handled_count;
        session.post_reply_log = std::string("handled bsd:u ") + DescribeBsdCommand(command_id) +
                                 ": pid=0x" + FormatHex(session.client_info.process_id, 16) +
                                 " fd=" + std::to_string(visible_socket.ret) +
                                 " original_fd=" + std::to_string(original_socket.ret) +
                                 " fd_zero_patch=" + fd_zero_patch_status +
                                 " backend=" +
                                 (socket != nullptr && socket->original_bsd_fd ? "forwarded-original-bsd" : "original-error") +
                                 " domain=" + std::to_string(input.domain) +
                                 " type=" + std::to_string(input.type) +
                                 " protocol=" + std::to_string(input.protocol) +
                                 " errno=" + std::to_string(visible_socket.ret < 0 ? visible_socket.errno_ : 0);
        std::memcpy(armGetTls(), forwarded_response.data(), forwarded_response.size());
        return true;
      }
      case 5:
        return HandleSelect(session, request, token);
      case 6:
        return HandlePoll(session, request, token);
      case 8:
        return HandleRecvDatagram(session, request, token, false);
      case 9:
        return HandleRecvDatagram(session, request, token, true);
      case 10:
        return HandleSendDatagram(session, request, token, false);
      case 11:
        return HandleSendDatagram(session, request, token, true);
      case 13:
        return HandleBind(session, request, token);
      case 14:
        return HandleConnect(session, request, token);
      case 15:
        return HandleGetSockName(session, request, token, true);
      case 16:
        return HandleGetSockName(session, request, token, false);
      case 17:
        return HandleGetSockOpt(session, request, token);
      case 20:
        return HandleFcntl(session, request, token);
      case 21:
        return HandleSetSockOpt(session, request, token);
      case 22: {
        const BsdSockFdIn* input = GetCmifPayloadAs<BsdSockFdIn>(request);
        BsdMitmVirtualSocket* socket = input != nullptr ? FindVirtualSocket(session, input->sockfd) : nullptr;
        if (socket == nullptr) {
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
          return true;
        }
        if (socket->native_fd != kBsdMitmInvalidNativeFd &&
            bsdShutdown(socket->native_fd, input->flags) < 0) {
          PrepareBsdRetErrnoResponse(token, -1, CurrentBsdErrnoOr(kLinuxErrnoInvalidArgument));
          return true;
        }
        ++session.handled_count;
        PrepareBsdRetErrnoResponse(token, 0, 0);
        return true;
      }
      case 23:
        ++session.handled_count;
        PrepareBsdRetErrnoResponse(token, 0, 0);
        return true;
      case 24:
        return HandleReadWrite(session, request, token, true);
      case 25:
        return HandleReadWrite(session, request, token, false);
      case 26: {
        const auto* fd = GetCmifPayloadAs<std::int32_t>(request);
        if (fd == nullptr) {
          PrepareCmifResponseWithToken(MakeLibnxBadInput(), token, nullptr, 0);
          return true;
        }
        const std::int32_t fd_value = *fd;

        if (!CloseVirtualBsdSocket(context_ != nullptr ? context_->control_service.get() : nullptr, session, fd_value)) {
          PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoBadFileDescriptor);
          return true;
        }

        ++session.handled_count;
        LogInfo("bsd-mitm", "handled bsd:u Close: pid=0x" +
                                FormatHex(session.client_info.process_id, 16) +
                                " fd=" + std::to_string(fd_value));
        PrepareBsdRetErrnoResponse(token, 0, 0);
        return true;
      }
      default:
        ++session.unsupported_count;
        if (ShouldLogSparseCount(session.unsupported_count)) {
          LogWarning("bsd-mitm", std::string("unsupported bsd:u adapter command: pid=0x") +
                                     FormatHex(session.client_info.process_id, 16) +
                                     " command=" + std::to_string(command_id) +
                                     " name=" + DescribeBsdCommand(command_id) +
                                     " count=" + std::to_string(session.unsupported_count));
        }
        PrepareBsdRetErrnoResponse(token, -1, kLinuxErrnoOperationNotSupported);
        return true;
    }
  }

  void ProcessSession(std::size_t index) {
    BsdMitmClientSession& session = sessions_[index];
    s32 unused_index = -1;
    hipcMakeRequestInline(armGetTls());
    ::Result rc = svcReplyAndReceive(&unused_index, &session.client_session, 1, INVALID_HANDLE, UINT64_MAX);
    if (R_FAILED(rc)) {
      LogWarning("bsd-mitm", "failed to receive bsd:u request: slot=" + std::to_string(index) +
                                  " requests=" + std::to_string(session.request_count) +
                                  " handled=" + std::to_string(session.handled_count) +
                                  " rc=" + FormatLibnxResult(rc));
      CloseSession(index);
      return;
    }

    const HipcParsedRequest request = hipcParseRequest(armGetTls());
    bool close_session = false;
    std::string deferred_trace_log;

    if (request.meta.type == CmifCommandType_Close) {
      LogInfo("bsd-mitm", "received bsd:u Close request: slot=" + std::to_string(index) +
                            " requests=" + std::to_string(session.request_count) +
                            " handled=" + std::to_string(session.handled_count));
      close_session = true;
      PrepareCmifResponseWithToken(0, 0, nullptr, 0);
    } else if (request.meta.type == CmifCommandType_Request ||
               request.meta.type == CmifCommandType_RequestWithContext) {
      ++session.request_count;
      if (ShouldTraceBsdRequest(session.request_count)) {
        const CmifInHeader* header = GetCmifHeader(request);
        const std::uint32_t command_id = header != nullptr ? static_cast<std::uint32_t>(header->command_id) : 0;
        deferred_trace_log = std::string("dispatch bsd:u request: slot=") + std::to_string(index) +
                             " count=" + std::to_string(session.request_count) +
                             " command=" + std::to_string(command_id) +
                             " name=" + DescribeBsdCommand(command_id) +
                             " data_words=" + std::to_string(request.meta.num_data_words) +
                             " send_buffers=" + std::to_string(request.meta.num_send_buffers) +
                             " recv_buffers=" + std::to_string(request.meta.num_recv_buffers) +
                             " send_statics=" + std::to_string(request.meta.num_send_statics) +
                             " recv_statics=" + std::to_string(request.meta.num_recv_statics) +
                             " copy_handles=" + std::to_string(request.meta.num_copy_handles) +
                             " move_handles=" + std::to_string(request.meta.num_move_handles) +
                             " send_pid=" + std::to_string(request.meta.send_pid);
      }
      session.preserved_request_handle = INVALID_HANDLE;
      session.post_reply_log.clear();
      HandleRequest(index, session, request);
      CloseIncomingRequestHandles(request, session.preserved_request_handle);
      session.preserved_request_handle = INVALID_HANDLE;
    } else if (request.meta.type == CmifCommandType_Control ||
               request.meta.type == CmifCommandType_ControlWithContext) {
      ++session.request_count;
      session.preserved_request_handle = INVALID_HANDLE;
      session.post_reply_log.clear();
      HandleControlRequest(index, session, request);
      CloseIncomingRequestHandles(request, session.preserved_request_handle);
      session.preserved_request_handle = INVALID_HANDLE;
    } else {
      PrepareCmifResponseWithToken(MakeLibnxBadInput(), 0, nullptr, 0);
    }

    rc = svcReplyAndReceive(&unused_index, &session.client_session, 0, session.client_session, 0);
    if (R_FAILED(rc) && rc != KERNELRESULT(TimedOut)) {
      LogWarning("bsd-mitm", "failed to reply to bsd:u client: " + FormatLibnxResult(rc));
      close_session = true;
    }
    if (!session.post_reply_log.empty()) {
      LogInfo("bsd-mitm", session.post_reply_log);
      session.post_reply_log.clear();
    }
    if (!deferred_trace_log.empty()) {
      LogInfo("bsd-mitm", deferred_trace_log);
    }
    if (close_session) {
      CloseSession(index);
    }
  }

  BsdMitmServerContext* context_ = nullptr;
  BsdSocketRuntime direct_socket_runtime_{};
  TipcService sm_session_{};
  std::array<BsdMitmClientSession, kBsdMitmMaxSessions> sessions_{};
};
#endif

void DnsMitmServerThreadMain(void* arg) {
  auto* context = static_cast<DnsMitmServerContext*>(arg);
  DnsMitmServer server(context);
  const ::Result init_result = server.Initialize();
  if (R_FAILED(init_result)) {
    LogWarning("dns-mitm", "failed to open SM session for DNS MITM server: " + FormatLibnxResult(init_result));
    return;
  }
  LogInfo("dns-mitm", "active sfdnsres MITM proxy ready");
  server.Run();
}

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
void BsdMitmAdapterThreadMain(void* arg) {
  auto* context = static_cast<BsdMitmServerContext*>(arg);
  std::unique_ptr<BsdMitmAdapterServer> server(new (std::nothrow) BsdMitmAdapterServer(context));
  if (!server) {
    LogWarning("bsd-mitm", "failed to allocate bsd:u MITM adapter lab state");
    return;
  }

  const ::Result init_result = server->Initialize();
  if (R_FAILED(init_result)) {
    LogWarning("bsd-mitm", "failed to open SM session for bsd:u MITM adapter lab: " +
                               FormatLibnxResult(init_result));
    return;
  }
  LogInfo("bsd-mitm", "active bsd:u MITM adapter lab ready: socket_fd_source=forwarded_original_bsd, socket_response=forward_exact_fd0_patch, pointer_buffer_size=force_zero, stream_socket_native_open=deferred_connect, close_diag=enabled, fcntl_fd_flags=enabled, dispatch_trace=tls_deferred, title_selector=exact_allowlist, hbl_host_mitm=disabled");
  server->Run();
}
#endif

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
  if (service.target == MitmServiceTarget::DnsResolver || service.target == MitmServiceTarget::BsdUser) {
    const std::size_t slot = service.target == MitmServiceTarget::DnsResolver ? 0 : 1;
    g_observer_runtime.installed_services[slot] = service;
  }
  const char* mode = service.target == MitmServiceTarget::DnsResolver ? "active DNS replacement" : DescribeBsdMitmMode();
  LogInfo("mitm-observer", std::string("installed ") + mode + " MitM handles for " + service.service_name);
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
      {MitmServiceTarget::DnsResolver, "sfdnsres", true},
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
    ProcessQuerySession(service_index, context->services[service_index], *context);
  }
}

::Result StartMitmQueryResponderThread(const std::array<ObservedService, 2>& services,
                                       const MitmRuntimeSettings& settings,
                                       const Config& config) {
  if (g_observer_runtime.query_thread_started) {
    return 0;
  }

  g_observer_runtime.query_context.services = services;
  g_observer_runtime.query_context.settings = settings;
  g_observer_runtime.query_context.bsd_mitm_title_ids = BuildBsdMitmTitleAllowlist(config);
  if (!g_observer_runtime.query_context.bsd_mitm_title_ids.empty()) {
    LogInfo("mitm-observer", "loaded bsd:u MITM title allowlist entries=" +
                                  std::to_string(g_observer_runtime.query_context.bsd_mitm_title_ids.size()));
  }
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

::Result StartDnsMitmServerThread(const ObservedService& service, const DnsMitmRuntimeState& runtime) {
  if (g_observer_runtime.dns_thread_started) {
    return 0;
  }
  if (!service.installed || service.mitm_port == INVALID_HANDLE) {
    return MakeLibnxBadInput();
  }

  g_observer_runtime.dns_context.service = service;
  g_observer_runtime.dns_context.runtime = runtime;

  const int priority = 43;
  const int core_id = -2;
  const ::Result create_result =
      threadCreate(&g_observer_runtime.dns_thread, DnsMitmServerThreadMain,
                   &g_observer_runtime.dns_context, nullptr, kDnsMitmStackSize, priority, core_id);
  if (R_FAILED(create_result)) {
    return create_result;
  }

  const ::Result start_result = threadStart(&g_observer_runtime.dns_thread);
  if (R_FAILED(start_result)) {
    threadClose(&g_observer_runtime.dns_thread);
    return start_result;
  }

  g_observer_runtime.dns_thread_started = true;
  return 0;
}

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
::Result StartBsdMitmAdapterThread(const ObservedService& service) {
  if (g_observer_runtime.bsd_thread_started) {
    return 0;
  }
  if (!service.installed || service.mitm_port == INVALID_HANDLE) {
    return MakeLibnxBadInput();
  }

  g_observer_runtime.bsd_context.service = service;
  g_observer_runtime.bsd_context.control_service = g_observer_runtime.control_service;

  const int priority = 43;
  const int core_id = -2;
  const ::Result create_result =
      threadCreate(&g_observer_runtime.bsd_thread, BsdMitmAdapterThreadMain,
                   &g_observer_runtime.bsd_context, nullptr, kBsdMitmStackSize, priority, core_id);
  if (R_FAILED(create_result)) {
    return create_result;
  }

  const ::Result start_result = threadStart(&g_observer_runtime.bsd_thread);
  if (R_FAILED(start_result)) {
    threadClose(&g_observer_runtime.bsd_thread);
    return start_result;
  }

  g_observer_runtime.bsd_thread_started = true;
  return 0;
}
#endif

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

    LogInfo("mitm-observer", std::string("MitM query stats service=") + service.service_name +
                                  " total=" + std::to_string(total) +
                                  " selected=" +
                                  std::to_string(counters.selected.load(std::memory_order_relaxed)) +
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
    LogWarning("mitm-observer", "MitM query responder anomalies: wait_failures=" +
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

    const char* mode = service.target == MitmServiceTarget::DnsResolver ? "active DNS replacement" : DescribeBsdMitmMode();
    LogInfo("mitm-observer", std::string("activated ") + mode + " MitM hook for " + service.service_name);
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

  DnsMitmRuntimeState dns_runtime = LoadDnsMitmRuntimeState();

  auto services = BuildObservedServices(settings);
  if (!AnyServiceRequested(services)) {
    LogInfo("mitm-observer", "MitM observer disabled because no service hooks are requested");
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

  const ObservedService* dns_service = nullptr;
  for (const ObservedService& service : services) {
    if (service.target == MitmServiceTarget::DnsResolver && service.installed) {
      dns_service = &service;
      break;
    }
  }
  if (dns_service == nullptr) {
    LogWarning("dns-mitm", "active DNS MITM proxy disabled because sfdnsres was not installed");
  } else {
    const ::Result dns_thread_result = StartDnsMitmServerThread(*dns_service, dns_runtime);
    if (R_FAILED(dns_thread_result)) {
      LogWarning("dns-mitm", "failed to start active DNS MITM proxy thread: " +
                                 FormatLibnxResult(dns_thread_result));
      return;
    }
  }

  const ObservedService* bsd_service = nullptr;
  for (const ObservedService& service : services) {
    if (service.target == MitmServiceTarget::BsdUser && service.installed) {
      bsd_service = &service;
      break;
    }
  }
  if (bsd_service != nullptr) {
#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
    const ::Result bsd_thread_result = StartBsdMitmAdapterThread(*bsd_service);
    if (R_FAILED(bsd_thread_result)) {
      LogWarning("bsd-mitm", "failed to start bsd:u MITM adapter lab thread: " +
                               FormatLibnxResult(bsd_thread_result));
      return;
    }
#else
    LogWarning("bsd-mitm", "bsd:u adapter lab disabled; query hook will fail open");
#endif
  }

  const ::Result query_thread_result = StartMitmQueryResponderThread(services, settings, config.value);
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

#if defined(SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB)
namespace swg::sysmodule {
#endif

::Result StartExperimentalMitmObserverThread(std::shared_ptr<IControlService> control_service) {
  if (g_observer_runtime.started) {
    return 0;
  }
  g_observer_runtime.control_service = std::move(control_service);

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

void ShutdownExperimentalMitmObserver() {
  TipcService sm_session{};
  bool sm_open = false;
  for (ObservedService& service : g_observer_runtime.installed_services) {
    if (!service.installed) {
      continue;
    }

    if (!sm_open) {
      const ::Result open_result = OpenAtmosphereSession(&sm_session);
      if (R_FAILED(open_result)) {
        LogWarning("mitm-observer", "failed to open Atmosphere SM session for MITM shutdown: " +
                                      FormatLibnxResult(open_result));
        break;
      }
      sm_open = true;
    }

    const ::Result clear_result = ClearFutureMitm(&sm_session, service.service_name);
    if (R_FAILED(clear_result) && !IsSmResult(clear_result, 7)) {
      LogWarning("mitm-observer", std::string("failed to clear future MitM declaration during shutdown for ") +
                                      service.service_name + ": " + FormatLibnxResult(clear_result));
    }

    const ::Result uninstall_result = UninstallAtmosphereMitm(&sm_session, service.service_name);
    if (R_FAILED(uninstall_result) && !IsSmResult(uninstall_result, 7)) {
      LogWarning("mitm-observer", std::string("failed to uninstall MitM hook for ") +
                                      service.service_name + ": " + FormatLibnxResult(uninstall_result));
    } else {
      LogInfo("mitm-observer", std::string("uninstalled MitM hook for ") + service.service_name);
    }

    if (service.mitm_port != INVALID_HANDLE) {
      svcCloseHandle(service.mitm_port);
      service.mitm_port = INVALID_HANDLE;
    }
    if (service.query_session != INVALID_HANDLE) {
      svcCloseHandle(service.query_session);
      service.query_session = INVALID_HANDLE;
    }
    service.installed = false;
  }

  if (sm_open) {
    tipcClose(&sm_session);
  }
}

#else

::Result StartExperimentalMitmObserverThread() {
  LogWarning("mitm-observer", "experimental MitM service-open observer is disabled in this build");
  return 0;
}

void ShutdownExperimentalMitmObserver() {}

#endif

}  // namespace swg::sysmodule

#endif
