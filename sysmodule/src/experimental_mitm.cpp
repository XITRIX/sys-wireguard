#include "swg_sysmodule/experimental_mitm.h"

#include <algorithm>
#include <memory>
#include <string_view>
#include <utility>

namespace swg::sysmodule {
namespace {

bool ConfigRequestsTransparentMitm(const Config& config) {
  if (HasFlag(config.runtime_flags, RuntimeFlag::TransparentMode)) {
    return true;
  }

  return std::any_of(config.profiles.begin(), config.profiles.end(), [](const auto& entry) {
    return entry.second.transparent_mode;
  });
}

std::string DescribeUnavailableTarget(const HosCapabilities& capabilities, std::string_view service_name) {
  if (!capabilities.switch_target) {
    return std::string(service_name) + " requires a Switch-target build";
  }
  if (!capabilities.atmosphere) {
    return std::string(service_name) + " requires Atmosphere MITM extensions";
  }
  return std::string(service_name) + " availability still needs a direct capability probe";
}

}  // namespace

MitmRuntimeSettings BuildDefaultMitmRuntimeSettings(const Config& config) {
  MitmRuntimeSettings settings{};
  settings.enable_dns_mitm = ConfigRequestsTransparentMitm(config);
  settings.enable_bsd_user_mitm = false;
  settings.enable_bsd_system_mitm = false;
  settings.mitm_all_clients = false;
  settings.log_client_sessions = true;
  settings.dump_session_bytes = false;
  settings.session_mode = MitmSessionMode::ObserveOnly;
  return settings;
}

std::vector<MitmServiceDescriptor> DescribeExperimentalMitmServices(const Config& config,
                                                                    const HosCapabilities& capabilities,
                                                                    const MitmRuntimeSettings& settings) {
  std::vector<MitmServiceDescriptor> services;
  services.reserve(3);

  const bool transparent_requested = ConfigRequestsTransparentMitm(config);

  MitmServiceDescriptor dns{};
  dns.target = MitmServiceTarget::DnsResolver;
  dns.service_name = "sfdnsres";
  dns.available = capabilities.switch_target && capabilities.atmosphere && capabilities.has_dns_priv;
  dns.requested = settings.enable_dns_mitm;
  dns.ready = false;
  dns.experimental = true;
  dns.implementation_state = MitmImplementationState::Scaffolded;
  if (dns.available) {
    dns.note = "Resolver MITM scaffold exists in swg_sysmodule_core, but switch_main does not install it yet.";
  } else {
    dns.note = DescribeUnavailableTarget(capabilities, dns.service_name) +
               "; current compatibility notes only confirm dns access through has_dns_priv.";
  }
  if (!transparent_requested && !dns.requested) {
    dns.note += " Transparent mode is not currently requested by config or runtime flags.";
  }
  services.push_back(std::move(dns));

  MitmServiceDescriptor bsd_user{};
  bsd_user.target = MitmServiceTarget::BsdUser;
  bsd_user.service_name = "bsd:u";
  bsd_user.available = capabilities.switch_target && capabilities.atmosphere;
  bsd_user.requested = settings.enable_bsd_user_mitm;
  bsd_user.ready = false;
  bsd_user.experimental = true;
  bsd_user.implementation_state = MitmImplementationState::Planned;
  bsd_user.note = "Future socket MITM slot only. The current repo has no bsd:u command adapter, and live capability reporting does not probe bsd:u directly yet.";
  services.push_back(std::move(bsd_user));

  MitmServiceDescriptor bsd_system{};
  bsd_system.target = MitmServiceTarget::BsdSystem;
  bsd_system.service_name = "bsd:s";
  bsd_system.available = false;
  bsd_system.requested = settings.enable_bsd_system_mitm;
  bsd_system.ready = false;
  bsd_system.experimental = true;
  bsd_system.implementation_state = MitmImplementationState::Planned;
  bsd_system.note = "Deferred until the application-facing bsd:u MITM path proves viable. No direct capability probe exists for bsd:s in the current repo.";
  services.push_back(std::move(bsd_system));

  return services;
}

DnsMitmPlan BuildDnsMitmPlan(const Config& config,
                             const HosCapabilities& capabilities,
                             const MitmRuntimeSettings& settings) {
  DnsMitmPlan plan{};
  plan.service_available = capabilities.switch_target && capabilities.atmosphere && capabilities.has_dns_priv;
  plan.requested = settings.enable_dns_mitm;
  plan.ready = false;
  plan.can_observe_queries = true;
  plan.can_redirect_answers = true;
  plan.can_forward_to_tunnel = true;
  plan.answer_source = settings.session_mode == MitmSessionMode::RedirectToTunnel ? "tunnel_dns_pending_activation"
                                                                                  : "forward_only";

  if (!ConfigRequestsTransparentMitm(config)) {
    plan.blockers.push_back("transparent mode is not requested by any profile or runtime flag");
  }
  if (!capabilities.switch_target) {
    plan.blockers.push_back("requires a Nintendo Switch target build");
  }
  if (!capabilities.atmosphere) {
    plan.blockers.push_back("requires Atmosphere SM MITM extensions");
  }
  if (!capabilities.has_dns_priv) {
    plan.blockers.push_back("current compatibility probes did not confirm resolver access");
  }
  plan.blockers.push_back("the scaffold is not wired into switch_main yet");

  return plan;
}

MitmDecision EvaluateMitmClient(const MitmServiceDescriptor& service,
                                const MitmRuntimeSettings& settings,
                                const MitmClientInfo& client) {
  if (!service.requested) {
    return {false, service.service_name + " MITM is not requested"};
  }
  if (!service.available) {
    return {false, service.service_name + " is not available on the current target"};
  }
  if (!client.is_application && !settings.mitm_all_clients) {
    return {false, "default experimental MITM policy only targets application clients"};
  }

  switch (settings.session_mode) {
    case MitmSessionMode::ObserveOnly:
      return {true, "observe-only experimental MITM session selected"};
    case MitmSessionMode::InterceptAndForward:
      return {true, "intercept-and-forward experimental MITM session selected"};
    case MitmSessionMode::RedirectToTunnel:
      if (!service.ready) {
        return {false, service.service_name + " tunnel redirection is not wired yet"};
      }
      return {true, "redirect-to-tunnel experimental MITM session selected"};
  }

  return {false, service.service_name + " MITM session mode is not recognized"};
}

const char* ToString(MitmServiceTarget target) {
  switch (target) {
    case MitmServiceTarget::DnsResolver:
      return "dns_resolver";
    case MitmServiceTarget::BsdUser:
      return "bsd_user";
    case MitmServiceTarget::BsdSystem:
      return "bsd_system";
  }

  return "unknown";
}

const char* ToString(MitmImplementationState state) {
  switch (state) {
    case MitmImplementationState::Planned:
      return "planned";
    case MitmImplementationState::Scaffolded:
      return "scaffolded";
    case MitmImplementationState::Active:
      return "active";
  }

  return "unknown";
}

const char* ToString(MitmSessionMode mode) {
  switch (mode) {
    case MitmSessionMode::ObserveOnly:
      return "observe_only";
    case MitmSessionMode::InterceptAndForward:
      return "intercept_and_forward";
    case MitmSessionMode::RedirectToTunnel:
      return "redirect_to_tunnel";
  }

  return "unknown";
}

ExperimentalMitmHarness::ExperimentalMitmHarness(Config config,
                                                 HosCapabilities capabilities,
                                                 MitmRuntimeSettings settings)
    : config_(std::move(config)),
      capabilities_(capabilities),
      settings_(settings),
      services_(DescribeExperimentalMitmServices(config_, capabilities_, settings_)),
      dns_plan_(BuildDnsMitmPlan(config_, capabilities_, settings_)) {}

const MitmServiceDescriptor* ExperimentalMitmHarness::FindService(MitmServiceTarget target) const {
  const auto it = std::find_if(services_.begin(), services_.end(), [target](const MitmServiceDescriptor& service) {
    return service.target == target;
  });
  return it == services_.end() ? nullptr : std::addressof(*it);
}

MitmDecision ExperimentalMitmHarness::EvaluateClient(MitmServiceTarget target, const MitmClientInfo& client) const {
  const MitmServiceDescriptor* service = FindService(target);
  if (service == nullptr) {
    return {false, std::string("unknown MITM service target: ") + ToString(target)};
  }

  return EvaluateMitmClient(*service, settings_, client);
}

ExperimentalMitmHarness CreateDefaultExperimentalMitmHarness(const Config& config,
                                                             const HosCapabilities& capabilities) {
  return ExperimentalMitmHarness(config, capabilities, BuildDefaultMitmRuntimeSettings(config));
}

}  // namespace swg::sysmodule