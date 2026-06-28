#if defined(SWG_PLATFORM_SWITCH)

#include "swg_sysmodule/mitm_observer_switch.h"

#include <array>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "swg/config.h"
#include "swg/hos_caps.h"
#include "swg/log.h"
#include "swg_sysmodule/experimental_dns_mitm.h"
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
constexpr std::size_t kDnsMitmStackSize = 0x10000;
constexpr std::size_t kDnsMitmMaxSessions = 8;
constexpr std::size_t kDnsMitmMaxHostsFileSize = 0x8000;
constexpr const char* kDnsMitmStartupLogPath = "sdmc:/atmosphere/logs/dns_mitm_startup.log";
constexpr const char* kDnsMitmDebugLogPath = "sdmc:/atmosphere/logs/dns_mitm_debug.log";

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
  Thread dns_thread{};
  QueryResponderContext query_context{};
  DnsMitmServerContext dns_context{};
  bool started = false;
  bool query_thread_started = false;
  bool dns_thread_started = false;
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
                                 (static_cast<std::uintptr_t>(entry.address_high) << 32));
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

void ProcessQuerySession(std::size_t service_index, ObservedService& service) {
  AtmosphereMitmProcessInfo raw_info{};
  const HipcParsedRequest request = hipcParseRequest(armGetTls());
  const bool parsed = ParseMitmQueryRequest(request, &raw_info);

  const bool should_mitm = parsed && service.target == MitmServiceTarget::DnsResolver;
  PrepareMitmQueryResponse(0, should_mitm);
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

::Result ForwardCurrentDnsRequest(Handle forward_session) {
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
        rc = ForwardCurrentDnsRequest(session.forward_session);
        if (R_FAILED(rc)) {
          LogWarning("dns-mitm", "failed to forward sfdnsres request: " + FormatLibnxResult(rc));
          PrepareCmifResponseWithToken(rc, 0, nullptr, 0);
        }
      }
    } else {
      rc = ForwardCurrentDnsRequest(session.forward_session);
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
  const char* mode = service.target == MitmServiceTarget::DnsResolver ? "active DNS replacement" : "observe-only";
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

    const char* mode = service.target == MitmServiceTarget::DnsResolver ? "active DNS replacement" : "observe-only";
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
