#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "swg_sysmodule/experimental_mitm.h"

namespace swg::sysmodule {

enum class DnsMitmRequestKind : std::uint8_t {
  GetHostByName = 0,
  GetHostByNameWithOptions,
  GetAddrInfo,
  GetAddrInfoWithOptions,
};

enum class DnsMitmAction : std::uint8_t {
  ForwardToResolver = 0,
  ResolveThroughTunnel,
  SynthesizeFailure,
};

struct DnsMitmRequestContext {
  DnsMitmRequestKind request_kind = DnsMitmRequestKind::GetAddrInfo;
  MitmClientInfo client;
  std::string host;
  std::string service;
  bool use_nsd_resolve = false;
  bool has_request_options = false;
};

struct DnsMitmInterceptionPlan {
  DnsMitmAction action = DnsMitmAction::ForwardToResolver;
  bool should_log_query = false;
  bool should_record_metric = false;
  bool use_tunnel_dns = false;
  bool fail_closed = false;
  std::string reason;
};

struct AtmosphereDnsRedirectRule {
  std::string host_pattern;
  std::uint32_t ipv4_address = 0;
};

struct AtmosphereDnsAddrInfoHint {
  std::uint32_t flags = 0;
  std::uint32_t family = 0;
  std::uint32_t socktype = 0;
  std::uint32_t protocol = 0;
  bool unsupported_family = false;
};

class AtmosphereDnsMitmRules {
 public:
  void Clear();
  void AddDefaultTelemetryRules(std::string_view environment_identifier);
  void AddHostsText(std::string_view hosts_text, std::string_view environment_identifier);

  [[nodiscard]] std::optional<std::uint32_t> ResolveRedirect(std::string_view hostname) const;
  [[nodiscard]] const std::vector<AtmosphereDnsRedirectRule>& rules() const {
    return rules_;
  }

 private:
  std::vector<AtmosphereDnsRedirectRule> rules_;
};

DnsMitmInterceptionPlan PlanExperimentalDnsMitmRequest(const DnsMitmPlan& plan,
                                                       const MitmRuntimeSettings& settings,
                                                       const DnsMitmRequestContext& request);

AtmosphereDnsMitmRules BuildAtmosphereDnsMitmRules(std::string_view hosts_text,
                                                   std::string_view environment_identifier,
                                                   bool add_default_telemetry_rules);
bool AtmosphereDnsWildcardMatch(std::string_view pattern, std::string_view hostname);
std::string DefaultAtmosphereDnsHostsFile();
std::string AtmosphereDnsDefaultHostsPath();
std::vector<std::string> AtmosphereDnsHostsFileSearchOrder(bool emummc_active, std::uint32_t emummc_id);
std::string FormatAtmosphereDnsIpv4(std::uint32_t address);
std::optional<AtmosphereDnsAddrInfoHint> ParseAtmosphereDnsSerializedAddrInfoHint(const void* data,
                                                                                  std::size_t size);
std::optional<std::size_t> SerializeAtmosphereDnsHostEnt(void* output,
                                                         std::size_t output_size,
                                                         std::string_view hostname,
                                                         std::uint32_t address);
std::optional<std::size_t> SerializeAtmosphereDnsAddrInfo(void* output,
                                                          std::size_t output_size,
                                                          std::string_view hostname,
                                                          std::uint32_t address,
                                                          std::uint16_t port,
                                                          const AtmosphereDnsAddrInfoHint* hint);

const char* ToString(DnsMitmRequestKind kind);
const char* ToString(DnsMitmAction action);

}  // namespace swg::sysmodule
