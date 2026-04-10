#include "swg/hos_caps.h"

#include <sstream>

namespace swg {

HosCapabilities DetectHosCapabilities() {
  HosCapabilities capabilities{};

#if defined(SWG_PLATFORM_SWITCH)
  capabilities.switch_target = true;
  capabilities.needs_new_tls_abi = true;
#else
  capabilities.switch_target = false;
  capabilities.needs_new_tls_abi = false;
#endif

  return capabilities;
}

std::string DescribeHosCapabilities(const HosCapabilities& capabilities) {
  std::ostringstream stream;
  stream << "switch_target=" << (capabilities.switch_target ? "true" : "false")
         << ", has_bsd_a=" << (capabilities.has_bsd_a ? "true" : "false")
         << ", has_dns_priv=" << (capabilities.has_dns_priv ? "true" : "false")
         << ", has_ifcfg=" << (capabilities.has_ifcfg ? "true" : "false")
         << ", has_bsd_nu=" << (capabilities.has_bsd_nu ? "true" : "false")
         << ", needs_new_tls_abi=" << (capabilities.needs_new_tls_abi ? "true" : "false");
  return stream.str();
}

}  // namespace swg
