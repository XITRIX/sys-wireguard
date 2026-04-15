#include <iostream>
#include <string>

#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg_sysmodule/experimental_dns_mitm.h"
#include "swg_sysmodule/experimental_mitm.h"

namespace {

bool Expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "test failure: " << message << '\n';
    return false;
  }
  return true;
}

swg::Config MakeExperimentalMitmConfig() {
  swg::Config config{};
  swg::ProfileConfig profile{};
  profile.name = "default";
  profile.endpoint_host = "vpn.example.com";
  profile.allowed_ips = {"0.0.0.0/0"};
  profile.addresses = {"10.0.0.2/32"};
  profile.transparent_mode = true;

  config.active_profile = profile.name;
  config.profiles.emplace(profile.name, profile);
  config.runtime_flags = swg::ToFlags(swg::RuntimeFlag::TransparentMode);
  return config;
}

swg::HosCapabilities MakeExperimentalMitmCapabilities() {
  swg::HosCapabilities capabilities{};
  capabilities.switch_target = true;
  capabilities.atmosphere = true;
  capabilities.has_dns_priv = true;
  capabilities.has_bsd_a = true;
  return capabilities;
}

}  // namespace

bool TestExperimentalMitmHarness() {
  const swg::Config config = MakeExperimentalMitmConfig();
  const swg::HosCapabilities capabilities = MakeExperimentalMitmCapabilities();
  const swg::sysmodule::ExperimentalMitmHarness harness =
      swg::sysmodule::CreateDefaultExperimentalMitmHarness(config, capabilities);

  bool ok = true;
  ok &= Expect(harness.services().size() == 3,
               "experimental MITM scaffold must describe dns, bsd:u, and bsd:s service slots");

  const auto* dns_service = harness.FindService(swg::sysmodule::MitmServiceTarget::DnsResolver);
  ok &= Expect(dns_service != nullptr, "dns MITM descriptor must be present");
  if (dns_service == nullptr) {
    return false;
  }

  ok &= Expect(dns_service->service_name == "sfdnsres", "dns MITM descriptor must target sfdnsres");
  ok &= Expect(dns_service->available,
               "dns MITM descriptor must report availability when Atmosphere and resolver access are present");
  ok &= Expect(dns_service->requested,
               "dns MITM descriptor must be requested when transparent mode is enabled in config");
  ok &= Expect(!dns_service->ready,
               "dns MITM descriptor must remain dormant until switch_main installs a resolver MITM server");
  ok &= Expect(dns_service->implementation_state == swg::sysmodule::MitmImplementationState::Scaffolded,
               "dns MITM descriptor must report scaffolded implementation state");

  const auto* bsd_user_service = harness.FindService(swg::sysmodule::MitmServiceTarget::BsdUser);
  ok &= Expect(bsd_user_service != nullptr, "bsd:u MITM descriptor must be present");
  if (bsd_user_service != nullptr) {
    ok &= Expect(!bsd_user_service->requested,
                 "bsd:u MITM must stay disabled by default until DNS MITM proves stable");
    ok &= Expect(bsd_user_service->implementation_state == swg::sysmodule::MitmImplementationState::Planned,
                 "bsd:u MITM must still be a planned slot in the current scaffold");
  }

  ok &= Expect(!harness.dns_plan().ready,
               "dns MITM plan must stay not ready until the Switch-side server path exists");
  ok &= Expect(!harness.dns_plan().blockers.empty(),
               "dns MITM plan must explain why activation is still blocked");
  if (!harness.dns_plan().blockers.empty()) {
    ok &= Expect(harness.dns_plan().blockers.back().find("switch_main") != std::string::npos,
                 "dns MITM blockers must mention the missing switch_main installation step");
  }

  const swg::sysmodule::MitmClientInfo app_client{
      0x1234,
      0x0100000000001000ull,
      true,
      "Example App",
      "example-app",
  };
  const swg::sysmodule::MitmClientInfo system_client{
      0x4321,
      0,
      false,
      "System Resolver User",
      "system-client",
  };

  const auto app_decision = harness.EvaluateClient(swg::sysmodule::MitmServiceTarget::DnsResolver, app_client);
  ok &= Expect(app_decision.should_mitm,
               "observe-only dns MITM scaffold must select application clients by default");

  const auto system_decision =
      harness.EvaluateClient(swg::sysmodule::MitmServiceTarget::DnsResolver, system_client);
  ok &= Expect(!system_decision.should_mitm,
               "observe-only dns MITM scaffold must reject system clients until mitm_all_clients is enabled");

  const swg::sysmodule::DnsMitmRequestContext request{
      swg::sysmodule::DnsMitmRequestKind::GetAddrInfoWithOptions,
      app_client,
      "api.example.com",
      "443",
      false,
      true,
  };
  const auto observe_plan =
      swg::sysmodule::PlanExperimentalDnsMitmRequest(harness.dns_plan(), harness.settings(), request);
  ok &= Expect(observe_plan.action == swg::sysmodule::DnsMitmAction::ForwardToResolver,
               "observe-only dns MITM must still forward to the normal resolver");
  ok &= Expect(observe_plan.should_log_query,
               "observe-only dns MITM must request query logging when logging is enabled");
  ok &= Expect(observe_plan.should_record_metric,
               "observe-only dns MITM must request metrics when the feature is enabled");
  ok &= Expect(!observe_plan.use_tunnel_dns,
               "observe-only dns MITM must not claim tunnel DNS is active yet");
  ok &= Expect(observe_plan.reason.find("observe-only") != std::string::npos,
               "observe-only dns MITM plan must explain the forwarding decision");

  swg::sysmodule::MitmRuntimeSettings redirect_settings = harness.settings();
  redirect_settings.session_mode = swg::sysmodule::MitmSessionMode::RedirectToTunnel;
  redirect_settings.mitm_all_clients = true;

  const swg::sysmodule::ExperimentalMitmHarness redirect_harness(config, capabilities, redirect_settings);
  const auto redirect_system_decision =
      redirect_harness.EvaluateClient(swg::sysmodule::MitmServiceTarget::DnsResolver, system_client);
  ok &= Expect(!redirect_system_decision.should_mitm,
               "redirect-to-tunnel dns MITM must stay dormant while the resolver path is not wired");

  const auto redirect_plan = swg::sysmodule::PlanExperimentalDnsMitmRequest(
      redirect_harness.dns_plan(), redirect_harness.settings(),
      swg::sysmodule::DnsMitmRequestContext{
          swg::sysmodule::DnsMitmRequestKind::GetHostByName,
          system_client,
          "cdn.example.com",
          "",
          false,
          false,
      });
  ok &= Expect(redirect_plan.action == swg::sysmodule::DnsMitmAction::ForwardToResolver,
               "redirect-to-tunnel dns MITM must still forward while the scaffold is inactive");
  ok &= Expect(redirect_plan.reason.find("not wired") != std::string::npos,
               "redirect-to-tunnel dns MITM must explain that activation is still pending");

  return ok;
}