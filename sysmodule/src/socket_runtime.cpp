#include "swg_sysmodule/socket_runtime.h"

#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "swg/log.h"

#if defined(SWG_PLATFORM_SWITCH)
extern "C" size_t __nx_heap_size;

#ifdef __cplusplus
extern "C" {
#endif
#include <switch/kernel/tmem.h>
#include <switch/runtime/hosversion.h>
#include <switch/services/bsd.h>
#include <switch/services/sm.h>
#ifdef __cplusplus
}
#endif
#endif

namespace swg::sysmodule {
namespace {

#if !defined(SWG_PLATFORM_SWITCH)
std::string DescribeErrno(const char* operation) {
  return std::string(operation) + " failed: " + std::strerror(errno);
}
#endif

#if defined(SWG_PLATFORM_SWITCH)
std::string DescribeLibnxResult(::Result rc) {
  std::ostringstream stream;
  stream << "0x" << std::hex << static_cast<std::uint32_t>(rc) << std::dec << " (module=" << R_MODULE(rc)
         << ", description=" << R_DESCRIPTION(rc) << ')';
  return stream.str();
}

constexpr ::Result kProbeNotRun = static_cast<::Result>(0xFFFFFFFFu);
constexpr u32 kBsdServiceTypeUser = 1;
constexpr u32 kBsdServiceTypeSystem = 2;
constexpr u32 kDefaultBsdSessionCount = 3;
constexpr u32 kHighestKnownBsdVersion = 9;

struct BsdServiceRegisterConfig {
  u32 version = 0;
  u32 tcp_tx_buf_size = 0;
  u32 tcp_rx_buf_size = 0;
  u32 tcp_tx_buf_max_size = 0;
  u32 tcp_rx_buf_max_size = 0;
  u32 udp_tx_buf_size = 0;
  u32 udp_rx_buf_size = 0;
  u32 sb_efficiency = 0;
};

struct BsdServiceProbe {
  const char* service_name = "";
  ::Result open_result = kProbeNotRun;
  ::Result monitor_open_result = kProbeNotRun;
  ::Result tmem_result = kProbeNotRun;
  ::Result register_result = kProbeNotRun;
  ::Result start_monitor_result = kProbeNotRun;
  u64 client_pid = 0;
};

std::string BoolText(bool value) {
  return value ? "true" : "false";
}

std::string FormatHosVersion(u32 hos_version) {
  if (hos_version == 0) {
    return "unknown";
  }

  std::ostringstream stream;
  stream << static_cast<unsigned int>(HOSVER_MAJOR(hos_version)) << '.'
         << static_cast<unsigned int>(HOSVER_MINOR(hos_version)) << '.'
         << static_cast<unsigned int>(HOSVER_MICRO(hos_version));
  return stream.str();
}

std::string FormatHexValue(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value << std::dec;
  return stream.str();
}

const char* DescribeBsdServiceType(u32 service_type) {
  switch (service_type) {
    case kBsdServiceTypeUser:
      return "bsd:u";
    case kBsdServiceTypeSystem:
      return "bsd:s";
    case kBsdServiceTypeUser | kBsdServiceTypeSystem:
      return "auto";
    default:
      return "unknown";
  }
}

size_t ComputeTransferMemorySize(const BsdInitConfig& config) {
  const u32 tcp_tx_buf_max_size = config.tcp_tx_buf_max_size != 0 ? config.tcp_tx_buf_max_size : config.tcp_tx_buf_size;
  const u32 tcp_rx_buf_max_size = config.tcp_rx_buf_max_size != 0 ? config.tcp_rx_buf_max_size : config.tcp_rx_buf_size;
  u32 total = tcp_tx_buf_max_size + tcp_rx_buf_max_size + config.udp_tx_buf_size + config.udp_rx_buf_size;
  total = (total + 0xFFFu) & ~0xFFFu;
  return static_cast<size_t>(config.sb_efficiency) * total;
}

BsdServiceRegisterConfig MakeRegisterConfig(const BsdInitConfig& config) {
  BsdServiceRegisterConfig register_config{};
  register_config.version = config.version;
  register_config.tcp_tx_buf_size = config.tcp_tx_buf_size;
  register_config.tcp_rx_buf_size = config.tcp_rx_buf_size;
  register_config.tcp_tx_buf_max_size = config.tcp_tx_buf_max_size;
  register_config.tcp_rx_buf_max_size = config.tcp_rx_buf_max_size;
  register_config.udp_tx_buf_size = config.udp_tx_buf_size;
  register_config.udp_rx_buf_size = config.udp_rx_buf_size;
  register_config.sb_efficiency = config.sb_efficiency;
  return register_config;
}

bool ProbeSucceeded(const BsdServiceProbe& probe) {
  return probe.start_monitor_result != kProbeNotRun && R_SUCCEEDED(probe.start_monitor_result);
}

bool IsLibnxBadInput(::Result rc) {
  return R_FAILED(rc) && R_MODULE(rc) == Module_Libnx && R_DESCRIPTION(rc) == LibnxError_BadInput;
}

std::string DescribeProbeResult(::Result rc) {
  if (rc == kProbeNotRun) {
    return "n/a";
  }

  if (R_SUCCEEDED(rc)) {
    return "ok";
  }

  return DescribeLibnxResult(rc);
}

std::string DescribeProbe(const BsdServiceProbe& probe) {
  std::ostringstream stream;
  stream << probe.service_name << "{open=" << DescribeProbeResult(probe.open_result)
         << ", monitor_open=" << DescribeProbeResult(probe.monitor_open_result)
         << ", tmem=" << DescribeProbeResult(probe.tmem_result)
         << ", register=" << DescribeProbeResult(probe.register_result)
         << ", monitor_start=" << DescribeProbeResult(probe.start_monitor_result);
  if (ProbeSucceeded(probe)) {
    stream << ", pid=" << probe.client_pid;
  }
  stream << '}';
  return stream.str();
}

std::string DescribeInitContext(const BsdInitConfig& config, u32 num_sessions, u32 service_type) {
  const size_t min_tmem_size = ComputeTransferMemorySize(config);
  std::ostringstream stream;
  stream << "hos=" << FormatHosVersion(hosversionGet()) << ", atmosphere=" << BoolText(hosversionIsAtmosphere())
         << ", version=" << config.version << ", sessions=" << num_sessions
         << ", service=" << DescribeBsdServiceType(service_type)
    << ", min_tmem=" << FormatHexValue(min_tmem_size)
    << ", heap_budget=" << FormatHexValue(__nx_heap_size)
    << ", heap_headroom=" <<
      FormatHexValue(__nx_heap_size > min_tmem_size ? __nx_heap_size - min_tmem_size : 0);
  return stream.str();
}

BsdServiceProbe ProbeBsdServiceInitialization(const char* service_name, const BsdInitConfig& config) {
  BsdServiceProbe probe{};
  probe.service_name = service_name;

  Service service{};
  Service monitor{};
  TransferMemory transfer_memory{};

  probe.open_result = smGetService(&service, service_name);
  if (R_FAILED(probe.open_result)) {
    return probe;
  }

  probe.monitor_open_result = smGetService(&monitor, service_name);
  if (R_FAILED(probe.monitor_open_result)) {
    serviceClose(&service);
    return probe;
  }

  probe.tmem_result = tmemCreate(&transfer_memory, ComputeTransferMemorySize(config), Perm_None);
  if (R_FAILED(probe.tmem_result)) {
    serviceClose(&monitor);
    serviceClose(&service);
    return probe;
  }

  const BsdServiceRegisterConfig register_config = MakeRegisterConfig(config);
  const struct {
    BsdServiceRegisterConfig config;
    u64 pid_placeholder;
    u64 tmem_size;
  } request = {register_config, 0, transfer_memory.size};

  probe.register_result = serviceDispatchInOut(&service, 0, request, probe.client_pid,
                                               .in_send_pid = true,
                                               .in_num_handles = 1,
                                               .in_handles = {transfer_memory.handle});

  if (R_SUCCEEDED(probe.register_result)) {
    probe.start_monitor_result = serviceDispatchIn(&monitor, 1, probe.client_pid, .in_send_pid = true);
  }

  tmemClose(&transfer_memory);
  serviceClose(&monitor);
  serviceClose(&service);
  return probe;
}

u32 FindWorkingBsdVersion(const char* service_name, const BsdInitConfig& base_config) {
  for (u32 version = 1; version <= kHighestKnownBsdVersion; ++version) {
    if (version == base_config.version) {
      continue;
    }

    BsdInitConfig probe_config = base_config;
    probe_config.version = version;
    if (ProbeSucceeded(ProbeBsdServiceInitialization(service_name, probe_config))) {
      return version;
    }
  }

  return 0;
}

u32 SelectBsdVersion() {
  if (hosversionBefore(3, 0, 0)) {
    return 1;
  }
  if (hosversionBefore(4, 0, 0)) {
    return 2;
  }
  if (hosversionBefore(5, 0, 0)) {
    return 3;
  }
  if (hosversionBefore(6, 0, 0)) {
    return 4;
  }
  if (hosversionBefore(8, 0, 0)) {
    return 5;
  }
  if (hosversionBefore(9, 0, 0)) {
    return 6;
  }
  if (hosversionBefore(13, 0, 0)) {
    return 7;
  }
  if (hosversionBefore(16, 0, 0)) {
    return 8;
  }
  return 9;
}

std::string DescribeBsdFailure(const char* operation) {
  std::ostringstream stream;
  stream << operation << " failed: result=" << DescribeLibnxResult(g_bsdResult);
  if (g_bsdErrno != 0) {
    stream << ", bsd_errno=" << g_bsdErrno;
  }
  return stream.str();
}
#endif

}  // namespace

Error BsdSocketRuntime::Start() {
  if (started_) {
    return Error::None();
  }

#if defined(SWG_PLATFORM_SWITCH)
  BsdInitConfig config = *bsdGetDefaultInitConfig();
  config.version = SelectBsdVersion();
  const std::string init_context = DescribeInitContext(config, kDefaultBsdSessionCount, kBsdServiceTypeUser);
  LogInfo("socket_runtime", "starting BSD runtime: " + init_context);

  ::Result rc = bsdInitialize(&config, kDefaultBsdSessionCount, kBsdServiceTypeUser);
  if (R_FAILED(rc)) {
    const BsdServiceProbe user_probe = ProbeBsdServiceInitialization("bsd:u", config);
    const BsdServiceProbe system_probe = ProbeBsdServiceInitialization("bsd:s", config);

    if (!ProbeSucceeded(user_probe) && ProbeSucceeded(system_probe)) {
      LogWarning("socket_runtime", "retrying BSD runtime with bsd:s after successful system probe");
      rc = bsdInitialize(&config, kDefaultBsdSessionCount, kBsdServiceTypeSystem);
      if (R_SUCCEEDED(rc)) {
        LogInfo("socket_runtime", "BSD runtime initialized with bsd:s fallback: " +
                                      DescribeInitContext(config, kDefaultBsdSessionCount, kBsdServiceTypeSystem));
      }
    }

    u32 working_user_version = 0;
    const bool user_register_bad_input =
        IsLibnxBadInput(user_probe.register_result) || IsLibnxBadInput(user_probe.start_monitor_result);
    if (R_FAILED(rc) && user_register_bad_input) {
      working_user_version = FindWorkingBsdVersion("bsd:u", config);
      if (working_user_version != 0) {
        BsdInitConfig retry_config = config;
        retry_config.version = working_user_version;
        LogWarning("socket_runtime", "retrying BSD runtime with bsd:u version " +
                                         std::to_string(working_user_version));
        rc = bsdInitialize(&retry_config, kDefaultBsdSessionCount, kBsdServiceTypeUser);
        if (R_SUCCEEDED(rc)) {
          LogInfo("socket_runtime", "BSD runtime initialized with version fallback: " +
                                        DescribeInitContext(retry_config, kDefaultBsdSessionCount,
                                                            kBsdServiceTypeUser));
        }
      }
    }

    if (R_FAILED(rc)) {
      std::string message = "bsdInitialize failed: " + DescribeLibnxResult(rc) + "; " + init_context + "; " +
                            DescribeProbe(user_probe) + "; " + DescribeProbe(system_probe);
      if (working_user_version != 0) {
        message += "; working_bsd:u_version=" + std::to_string(working_user_version);
      }
      LogError("socket_runtime", message);
      return MakeError(ErrorCode::ServiceUnavailable, std::move(message));
    }
  }

  LogInfo("socket_runtime", "BSD runtime initialized: " + init_context);
#endif

  started_ = true;
  return Error::None();
}

void BsdSocketRuntime::Stop() {
  if (!started_) {
    return;
  }

#if defined(SWG_PLATFORM_SWITCH)
  bsdExit();
#endif

  started_ = false;
}

bool BsdSocketRuntime::IsStarted() const {
  return started_;
}

Result<int> BsdSocketRuntime::OpenConnectedUdpSocket(const PreparedTunnelEndpoint& endpoint) const {
  if (!started_) {
    return MakeFailure<int>(ErrorCode::InvalidState, "socket runtime is not initialized");
  }

  if (endpoint.state != PreparedEndpointState::Ready) {
    return MakeFailure<int>(ErrorCode::InvalidState,
                            "prepared endpoint must be resolved before opening a UDP socket");
  }

#if defined(SWG_PLATFORM_SWITCH)
  int socket_fd = bsdSocket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    return MakeFailure<int>(ErrorCode::IoError, DescribeBsdFailure("bsdSocket"));
  }
#else
  int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    return MakeFailure<int>(ErrorCode::IoError, DescribeErrno("socket"));
  }
#endif

  sockaddr_in remote{};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(endpoint.port);
  std::memcpy(&remote.sin_addr, endpoint.ipv4.data(), endpoint.ipv4.size());

  bool connect_failed = false;
  Error connect_error{};
#if defined(SWG_PLATFORM_SWITCH)
  if (bsdConnect(socket_fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) != 0) {
    connect_failed = true;
    connect_error = MakeError(ErrorCode::IoError, DescribeBsdFailure("bsdConnect"));
  }
#else
  if (::connect(socket_fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) != 0) {
    connect_failed = true;
    connect_error = MakeError(ErrorCode::IoError, DescribeErrno("connect"));
  }
#endif

  if (connect_failed) {
    CloseSocket(socket_fd);
    return Result<int>::Failure(connect_error);
  }

  return MakeSuccess(socket_fd);
}

void BsdSocketRuntime::CloseSocket(int socket_fd) const {
  if (socket_fd >= 0) {
#if defined(SWG_PLATFORM_SWITCH)
    bsdClose(socket_fd);
#else
    ::close(socket_fd);
#endif
  }
}

}  // namespace swg::sysmodule