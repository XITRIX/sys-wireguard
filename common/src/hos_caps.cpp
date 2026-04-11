#include "swg/hos_caps.h"

#include <initializer_list>
#include <sstream>

#if defined(SWG_PLATFORM_SWITCH)
#include <switch.h>
#endif

namespace swg {
namespace {

#if defined(SWG_PLATFORM_SWITCH)
bool ProbeService(const char* service_name, std::uint32_t* probe_result) {
  Handle handle = INVALID_HANDLE;
  const Result rc = smGetServiceOriginal(&handle, smEncodeName(service_name));
  if (probe_result != nullptr) {
    *probe_result = static_cast<std::uint32_t>(rc);
  }

  if (R_FAILED(rc)) {
    return false;
  }

  if (handle != INVALID_HANDLE) {
    svcCloseHandle(handle);
  }
  return true;
}

bool ProbeAnyService(std::initializer_list<const char*> service_names, std::uint32_t* probe_result) {
  std::uint32_t last_result = 0;
  for (const char* service_name : service_names) {
    std::uint32_t current_result = 0;
    if (ProbeService(service_name, &current_result)) {
      if (probe_result != nullptr) {
        *probe_result = 0;
      }
      return true;
    }
    last_result = current_result;
  }

  if (probe_result != nullptr) {
    *probe_result = last_result;
  }
  return false;
}

std::string FormatHosVersion(std::uint32_t hos_version) {
  if (hos_version == 0) {
    return "unknown";
  }

  std::ostringstream stream;
  stream << static_cast<unsigned int>(HOSVER_MAJOR(hos_version)) << '.'
         << static_cast<unsigned int>(HOSVER_MINOR(hos_version)) << '.'
         << static_cast<unsigned int>(HOSVER_MICRO(hos_version));
  return stream.str();
}
#else
std::string FormatHosVersion(std::uint32_t) {
  return "host";
}
#endif

std::string FormatProbeStatus(bool available, std::uint32_t probe_result) {
  if (available) {
    return "true";
  }

  std::ostringstream stream;
  stream << "false(rc=0x" << std::hex << probe_result << std::dec << ')';
  return stream.str();
}

}  // namespace

HosCapabilities DetectHosCapabilities() {
  HosCapabilities capabilities{};

#if defined(SWG_PLATFORM_SWITCH)
  capabilities.switch_target = true;
  capabilities.hos_version = hosversionGet();
  capabilities.atmosphere = hosversionIsAtmosphere();
  capabilities.has_bsd_a = ProbeAnyService({"bsd:a"}, &capabilities.bsd_a_probe_result);
  capabilities.has_dns_priv = ProbeAnyService({"dns:priv", "sfdnsres"}, &capabilities.dns_priv_probe_result);
  capabilities.has_ifcfg = ProbeAnyService({"ifcfg", "nifm:a", "nifm:s"}, &capabilities.ifcfg_probe_result);
  capabilities.has_bsd_nu = ProbeAnyService({"bsd:nu"}, &capabilities.bsd_nu_probe_result);
  capabilities.needs_new_tls_abi = capabilities.hos_version == 0 ? true : hosversionAtLeast(21, 0, 0);
#else
  capabilities.switch_target = false;
  capabilities.needs_new_tls_abi = false;
#endif

  return capabilities;
}

std::string DescribeHosCapabilities(const HosCapabilities& capabilities) {
  std::ostringstream stream;
  stream << "switch_target=" << (capabilities.switch_target ? "true" : "false")
         << ", hos_version=" << FormatHosVersion(capabilities.hos_version)
         << ", atmosphere=" << (capabilities.atmosphere ? "true" : "false")
         << ", has_bsd_a=" << FormatProbeStatus(capabilities.has_bsd_a, capabilities.bsd_a_probe_result)
         << ", has_dns_priv=" << FormatProbeStatus(capabilities.has_dns_priv, capabilities.dns_priv_probe_result)
         << ", has_ifcfg=" << FormatProbeStatus(capabilities.has_ifcfg, capabilities.ifcfg_probe_result)
         << ", has_bsd_nu=" << FormatProbeStatus(capabilities.has_bsd_nu, capabilities.bsd_nu_probe_result)
         << ", needs_new_tls_abi=" << (capabilities.needs_new_tls_abi ? "true" : "false");
  return stream.str();
}

}  // namespace swg
