#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

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

std::uint16_t ReadSerializedU16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint16_t value = 0;
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  return static_cast<std::uint16_t>(((value & 0x00ffu) << 8) | ((value & 0xff00u) >> 8));
}

std::uint32_t ReadSerializedU32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  return ((value & 0x000000ffu) << 24) |
         ((value & 0x0000ff00u) << 8) |
         ((value & 0x00ff0000u) >> 8) |
         ((value & 0xff000000u) >> 24);
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
    ok &= Expect(bsd_user_service->requested,
                 "bsd:u service-open observation must be requested when transparent mode is enabled");
    ok &= Expect(bsd_user_service->implementation_state == swg::sysmodule::MitmImplementationState::Scaffolded,
                 "bsd:u MITM must expose the service-open observation scaffold");
  }

  ok &= Expect(!harness.dns_plan().ready,
               "dns MITM plan must stay not ready until the Switch-side server path exists");
  ok &= Expect(!harness.dns_plan().blockers.empty(),
               "dns MITM plan must explain why activation is still blocked");
  if (!harness.dns_plan().blockers.empty()) {
    ok &= Expect(harness.dns_plan().blockers.back().find("service-open") != std::string::npos,
                 "dns MITM blockers must clarify that only service-open observation is active");
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

  swg::sysmodule::MitmServiceOpenObservation observation{};
  observation.target = swg::sysmodule::MitmServiceTarget::BsdUser;
  observation.service_name = "bsd:u";
  observation.client = app_client;
  observation.policy_decision = harness.EvaluateClient(swg::sysmodule::MitmServiceTarget::BsdUser, app_client);
  observation.active_interception = false;
  observation.mode = "service_open_observe_only";
  const std::string observation_log = swg::sysmodule::FormatMitmServiceOpenObservation(observation);
  ok &= Expect(observation_log.find("service=bsd:u") != std::string::npos,
               "service-open observation log must include the service name");
  ok &= Expect(observation_log.find("program=0x0100000000001000") != std::string::npos,
               "service-open observation log must include the caller program id");
  ok &= Expect(observation_log.find("active_mitm=false") != std::string::npos,
               "service-open observation log must show that active interception remains disabled");

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

bool TestAtmosphereDnsMitmRules() {
  bool ok = true;

  swg::sysmodule::AtmosphereDnsMitmRules rules;
  rules.AddDefaultTelemetryRules("lp1");

  const auto telemetry_dg = rules.ResolveRedirect("receive-lp1.dg.srv.nintendo.net");
  ok &= Expect(telemetry_dg.has_value(), "Atmosphere DNS defaults must redirect telemetry dg host");
  if (telemetry_dg.has_value()) {
    ok &= Expect(swg::sysmodule::FormatAtmosphereDnsIpv4(*telemetry_dg) == "127.0.0.1",
                 "Atmosphere DNS telemetry redirect must target loopback");
  }
  ok &= Expect(rules.ResolveRedirect("receive-dev.dg.srv.nintendo.net") == std::nullopt,
               "Atmosphere DNS percent expansion must use the active environment identifier");

  rules.AddHostsText(
      "# ignored comment\n"
      "1.2.3.4 *.example.com api.%.*\n"
      "5.6.7.8 api.example.com\n"
      " 9.9.9.9 indented.invalid\n"
      "300.301.302.303 wrapped.example.com\r\n",
      "lp1");

  const auto wildcard = rules.ResolveRedirect("cdn.example.com");
  ok &= Expect(wildcard.has_value(), "Atmosphere DNS wildcard rules must match subdomains");
  if (wildcard.has_value()) {
    ok &= Expect(swg::sysmodule::FormatAtmosphereDnsIpv4(*wildcard) == "1.2.3.4",
                 "Atmosphere DNS wildcard redirect must preserve IPv4 octet order");
  }

  const auto specific = rules.ResolveRedirect("api.example.com");
  ok &= Expect(specific.has_value(), "Atmosphere DNS specific rule must match exact host");
  if (specific.has_value()) {
    ok &= Expect(swg::sysmodule::FormatAtmosphereDnsIpv4(*specific) == "5.6.7.8",
                 "Atmosphere DNS later specific rule must override earlier wildcard match");
  }

  const auto percent_wildcard = rules.ResolveRedirect("api.lp1.anything");
  ok &= Expect(percent_wildcard.has_value(), "Atmosphere DNS percent tokens must expand inside host patterns");
  if (percent_wildcard.has_value()) {
    ok &= Expect(swg::sysmodule::FormatAtmosphereDnsIpv4(*percent_wildcard) == "1.2.3.4",
                 "Atmosphere DNS percent-expanded wildcard must keep its redirect address");
  }

  ok &= Expect(rules.ResolveRedirect("indented.invalid") == std::nullopt,
               "Atmosphere DNS parser must ignore lines that do not begin with an IPv4 digit");

  const auto wrapped = rules.ResolveRedirect("wrapped.example.com");
  ok &= Expect(wrapped.has_value(), "Atmosphere DNS parser must accept numeric octets beyond 255 like Atmosphere");
  if (wrapped.has_value()) {
    ok &= Expect(swg::sysmodule::FormatAtmosphereDnsIpv4(*wrapped) == "44.45.46.47",
                 "Atmosphere DNS parser must preserve Atmosphere-style octet wrapping");
  }

  rules.AddHostsText("10.0.0.5 receive-lp1.dg.srv.nintendo.net\n", "lp1");
  const auto overridden_default = rules.ResolveRedirect("receive-lp1.dg.srv.nintendo.net");
  ok &= Expect(overridden_default.has_value(), "Atmosphere DNS host file rules must still match defaults");
  if (overridden_default.has_value()) {
    ok &= Expect(swg::sysmodule::FormatAtmosphereDnsIpv4(*overridden_default) == "10.0.0.5",
                 "Atmosphere DNS loaded hosts must override prepended defaults");
  }

  ok &= Expect(swg::sysmodule::AtmosphereDnsWildcardMatch("*", "anything.example"),
               "Atmosphere DNS wildcard '*' must match any host");
  ok &= Expect(swg::sysmodule::AtmosphereDnsWildcardMatch("api.*.example.com", "api.lp1.example.com"),
               "Atmosphere DNS wildcard must match a middle segment");
  ok &= Expect(!swg::sysmodule::AtmosphereDnsWildcardMatch("api.*.example.com", "cdn.lp1.example.com"),
               "Atmosphere DNS wildcard must still respect literal prefixes");

  const auto with_defaults = swg::sysmodule::BuildAtmosphereDnsMitmRules(
      "10.0.0.8 custom.example\n", "lp1", true);
  ok &= Expect(with_defaults.ResolveRedirect("receive-lp1.er.srv.nintendo.net").has_value(),
               "Atmosphere DNS builder must prepend defaults when add-defaults is enabled");
  ok &= Expect(with_defaults.ResolveRedirect("custom.example").has_value(),
               "Atmosphere DNS builder must include loaded host rules after defaults");

  const auto without_defaults = swg::sysmodule::BuildAtmosphereDnsMitmRules(
      "10.0.0.8 custom.example\n", "lp1", false);
  ok &= Expect(without_defaults.ResolveRedirect("receive-lp1.er.srv.nintendo.net") == std::nullopt,
               "Atmosphere DNS builder must support the add-defaults opt-out");

  const auto emummc_paths = swg::sysmodule::AtmosphereDnsHostsFileSearchOrder(true, 0x42);
  ok &= Expect(emummc_paths.size() == 3, "Atmosphere DNS emummc search order must include three candidates");
  if (emummc_paths.size() == 3) {
    ok &= Expect(emummc_paths[0] == "/atmosphere/hosts/emummc_0042.txt",
                 "Atmosphere DNS emummc search order must check the specific emummc hosts file first");
    ok &= Expect(emummc_paths[1] == "/atmosphere/hosts/emummc.txt",
                 "Atmosphere DNS emummc search order must check the generic emummc hosts file second");
    ok &= Expect(emummc_paths[2] == swg::sysmodule::AtmosphereDnsDefaultHostsPath(),
                 "Atmosphere DNS emummc search order must fall back to default hosts");
  }

  const auto sysmmc_paths = swg::sysmodule::AtmosphereDnsHostsFileSearchOrder(false, 0);
  ok &= Expect(sysmmc_paths.size() == 2, "Atmosphere DNS sysmmc search order must include two candidates");
  if (sysmmc_paths.size() == 2) {
    ok &= Expect(sysmmc_paths[0] == "/atmosphere/hosts/sysmmc.txt",
                 "Atmosphere DNS sysmmc search order must check sysmmc hosts first");
    ok &= Expect(sysmmc_paths[1] == swg::sysmodule::AtmosphereDnsDefaultHostsPath(),
                 "Atmosphere DNS sysmmc search order must fall back to default hosts");
  }

  std::vector<std::uint8_t> hostent_buffer(128);
  const auto hostent_size = swg::sysmodule::SerializeAtmosphereDnsHostEnt(
      hostent_buffer.data(), hostent_buffer.size(), "blocked.example", 0x0100007fu);
  ok &= Expect(hostent_size.has_value(), "Atmosphere DNS hostent serialization must fit in the output buffer");
  if (hostent_size.has_value()) {
    ok &= Expect(std::string(reinterpret_cast<const char*>(hostent_buffer.data())) == "blocked.example",
                 "Atmosphere DNS hostent serialization must start with the canonical hostname");
    const std::size_t aliases_offset = std::string("blocked.example").size() + 1;
    ok &= Expect(ReadSerializedU32(hostent_buffer, aliases_offset) == 0,
                 "Atmosphere DNS hostent serialization must emit an empty alias list");
    ok &= Expect(ReadSerializedU16(hostent_buffer, aliases_offset + 4) == 2,
                 "Atmosphere DNS hostent serialization must emit AF_INET");
    ok &= Expect(ReadSerializedU16(hostent_buffer, aliases_offset + 6) == 4,
                 "Atmosphere DNS hostent serialization must emit a four-byte IPv4 address length");
    ok &= Expect(ReadSerializedU32(hostent_buffer, aliases_offset + 8) == 1,
                 "Atmosphere DNS hostent serialization must emit one IPv4 address");
    ok &= Expect(ReadSerializedU32(hostent_buffer, aliases_offset + 12) == 0x0100007fu,
                 "Atmosphere DNS hostent serialization must preserve the redirected IPv4 address");
  }

  std::vector<std::uint8_t> addrinfo_buffer(128);
  const auto addrinfo_size = swg::sysmodule::SerializeAtmosphereDnsAddrInfo(
      addrinfo_buffer.data(), addrinfo_buffer.size(), "blocked.example", 0x08080808u, 443, nullptr);
  ok &= Expect(addrinfo_size.has_value(), "Atmosphere DNS addrinfo serialization must fit in the output buffer");
  if (addrinfo_size.has_value()) {
    ok &= Expect(ReadSerializedU32(addrinfo_buffer, 0) == 0xbeefcafeu,
                 "Atmosphere DNS addrinfo serialization must start with the expected magic");
    ok &= Expect(ReadSerializedU32(addrinfo_buffer, 8) == 2,
                 "Atmosphere DNS addrinfo serialization must default to AF_INET");
    ok &= Expect(ReadSerializedU32(addrinfo_buffer, 12) == 1,
                 "Atmosphere DNS addrinfo serialization must default to SOCK_STREAM");
    ok &= Expect(ReadSerializedU32(addrinfo_buffer, 16) == 6,
                 "Atmosphere DNS addrinfo serialization must default to TCP");
    ok &= Expect(ReadSerializedU32(addrinfo_buffer, 20) == 16,
                 "Atmosphere DNS addrinfo serialization must emit a sockaddr_in length");
    ok &= Expect(ReadSerializedU16(addrinfo_buffer, 24) == 2,
                 "Atmosphere DNS addrinfo serialization must emit sockaddr AF_INET");
    ok &= Expect(ReadSerializedU16(addrinfo_buffer, 26) == 0xbb01,
                 "Atmosphere DNS addrinfo serialization must preserve the numeric service port in sockaddr order");
    ok &= Expect(ReadSerializedU32(addrinfo_buffer, 28) == 0x08080808u,
                 "Atmosphere DNS addrinfo serialization must preserve the redirected IPv4 address");
  }

  std::vector<std::uint8_t> hint(24);
  auto write_serialized_u32 = [&hint](std::size_t offset, std::uint32_t value) {
    const std::uint32_t serialized = ((value & 0x000000ffu) << 24) |
                                     ((value & 0x0000ff00u) << 8) |
                                     ((value & 0x00ff0000u) >> 8) |
                                     ((value & 0xff000000u) >> 24);
    std::memcpy(hint.data() + offset, &serialized, sizeof(serialized));
  };
  write_serialized_u32(0, 0xbeefcafeu);
  write_serialized_u32(8, 10);
  const auto parsed_hint =
      swg::sysmodule::ParseAtmosphereDnsSerializedAddrInfoHint(hint.data(), hint.size());
  ok &= Expect(parsed_hint.has_value() && parsed_hint->unsupported_family,
               "Atmosphere DNS addrinfo hint parser must flag IPv6-only hints for forwarding");
  ok &= Expect(!swg::sysmodule::SerializeAtmosphereDnsAddrInfo(
                    addrinfo_buffer.data(), addrinfo_buffer.size(), "blocked.example", 0x08080808u, 443,
                    parsed_hint.has_value() ? &*parsed_hint : nullptr)
                    .has_value(),
               "Atmosphere DNS addrinfo serializer must refuse unsupported IPv6-only hints");

  return ok;
}
