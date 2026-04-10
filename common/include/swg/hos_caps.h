#pragma once

#include <string>

namespace swg {

struct HosCapabilities {
  bool switch_target = false;
  bool has_bsd_a = false;
  bool has_dns_priv = false;
  bool has_ifcfg = false;
  bool has_bsd_nu = false;
  bool needs_new_tls_abi = false;
};

HosCapabilities DetectHosCapabilities();
std::string DescribeHosCapabilities(const HosCapabilities& capabilities);

}  // namespace swg
