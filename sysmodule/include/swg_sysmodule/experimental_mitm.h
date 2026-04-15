#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "swg/config.h"
#include "swg/hos_caps.h"

namespace swg::sysmodule {

enum class MitmServiceTarget : std::uint8_t {
  DnsResolver = 0,
  BsdUser,
  BsdSystem,
};

enum class MitmImplementationState : std::uint8_t {
  Planned = 0,
  Scaffolded,
  Active,
};

enum class MitmSessionMode : std::uint8_t {
  ObserveOnly = 0,
  InterceptAndForward,
  RedirectToTunnel,
};

struct MitmRuntimeSettings {
  bool enable_dns_mitm = false;
  bool enable_bsd_user_mitm = false;
  bool enable_bsd_system_mitm = false;
  bool mitm_all_clients = false;
  bool log_client_sessions = true;
  bool dump_session_bytes = false;
  MitmSessionMode session_mode = MitmSessionMode::ObserveOnly;
};

struct MitmClientInfo {
  std::uint64_t process_id = 0;
  std::uint64_t program_id = 0;
  bool is_application = false;
  std::string client_name;
  std::string integration_tag;
};

struct MitmDecision {
  bool should_mitm = false;
  std::string reason;
};

struct MitmServiceDescriptor {
  MitmServiceTarget target = MitmServiceTarget::DnsResolver;
  std::string service_name;
  bool available = false;
  bool requested = false;
  bool ready = false;
  bool experimental = true;
  MitmImplementationState implementation_state = MitmImplementationState::Planned;
  std::string note;
};

struct DnsMitmPlan {
  std::string service_name = "sfdnsres";
  bool service_available = false;
  bool requested = false;
  bool ready = false;
  bool can_observe_queries = true;
  bool can_redirect_answers = true;
  bool can_forward_to_tunnel = true;
  std::string answer_source = "forward_only";
  std::vector<std::string> blockers;
};

MitmRuntimeSettings BuildDefaultMitmRuntimeSettings(const Config& config);
std::vector<MitmServiceDescriptor> DescribeExperimentalMitmServices(const Config& config,
                                                                    const HosCapabilities& capabilities,
                                                                    const MitmRuntimeSettings& settings);
DnsMitmPlan BuildDnsMitmPlan(const Config& config,
                             const HosCapabilities& capabilities,
                             const MitmRuntimeSettings& settings);
MitmDecision EvaluateMitmClient(const MitmServiceDescriptor& service,
                                const MitmRuntimeSettings& settings,
                                const MitmClientInfo& client);

const char* ToString(MitmServiceTarget target);
const char* ToString(MitmImplementationState state);
const char* ToString(MitmSessionMode mode);

class ExperimentalMitmHarness {
 public:
  ExperimentalMitmHarness(Config config, HosCapabilities capabilities, MitmRuntimeSettings settings);

  const Config& config() const {
    return config_;
  }

  const HosCapabilities& capabilities() const {
    return capabilities_;
  }

  const MitmRuntimeSettings& settings() const {
    return settings_;
  }

  const std::vector<MitmServiceDescriptor>& services() const {
    return services_;
  }

  const DnsMitmPlan& dns_plan() const {
    return dns_plan_;
  }

  const MitmServiceDescriptor* FindService(MitmServiceTarget target) const;
  MitmDecision EvaluateClient(MitmServiceTarget target, const MitmClientInfo& client) const;

 private:
  Config config_;
  HosCapabilities capabilities_;
  MitmRuntimeSettings settings_;
  std::vector<MitmServiceDescriptor> services_;
  DnsMitmPlan dns_plan_;
};

ExperimentalMitmHarness CreateDefaultExperimentalMitmHarness(const Config& config,
                                                             const HosCapabilities& capabilities);

}  // namespace swg::sysmodule