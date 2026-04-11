#pragma once

#include <cstdint>
#include <string>

namespace swg {

struct HosCapabilities {
  bool switch_target = false;
  bool has_bsd_a = false;
  bool has_dns_priv = false;
  bool has_ifcfg = false;
  bool has_bsd_nu = false;
  bool needs_new_tls_abi = false;
  std::uint32_t hos_version = 0;
  bool atmosphere = false;
  std::uint32_t bsd_a_probe_result = 0;
  std::uint32_t dns_priv_probe_result = 0;
  std::uint32_t ifcfg_probe_result = 0;
  std::uint32_t bsd_nu_probe_result = 0;
};

HosCapabilities DetectHosCapabilities();
std::string DescribeHosCapabilities(const HosCapabilities& capabilities);

}  // namespace swg
