#include <filesystem>
#include <iostream>
#include <string>

#include "swg/app_session.h"
#include "swg/client.h"
#include "swg/config.h"
#include "swg/ipc_codec.h"
#include "swg/moonlight.h"
#include "swg/state_machine.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/wg_engine.h"
#include "swg_sysmodule/host_transport.h"
#include "swg_sysmodule/local_service.h"

namespace {

bool Require(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "test failure: " << message << '\n';
    return false;
  }
  return true;
}

constexpr const char* kSamplePrivateKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
constexpr const char* kSamplePublicKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
constexpr const char* kSamplePresharedKey = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";

bool TestEndpointAndNetworkParsing() {
  bool ok = true;

  const auto ipv4_network = swg::ParseIpNetwork("10.0.0.2/32", "address");
  ok &= Require(ipv4_network.ok(), "ipv4 network must parse");
  if (ipv4_network.ok()) {
    ok &= Require(ipv4_network.value.address.family == swg::ParsedIpFamily::IPv4,
                  "ipv4 network must preserve address family");
    ok &= Require(ipv4_network.value.normalized == "10.0.0.2/32", "ipv4 network must normalize");
  }

  const auto ipv6_network = swg::ParseIpNetwork("fd00::2/128", "address");
  ok &= Require(ipv6_network.ok(), "ipv6 network must parse");
  if (ipv6_network.ok()) {
    ok &= Require(ipv6_network.value.address.family == swg::ParsedIpFamily::IPv6,
                  "ipv6 network must preserve address family");
  }

  const auto dns_server = swg::ParseIpAddress("2606:4700:4700::1111", "dns");
  ok &= Require(dns_server.ok(), "ipv6 dns address must parse");

  const auto endpoint = swg::ParseEndpoint("[2001:db8::1]", 51820);
  ok &= Require(endpoint.ok(), "ipv6 endpoint literal must parse");
  if (endpoint.ok()) {
    ok &= Require(endpoint.value.type == swg::ParsedEndpointHostType::IPv6,
                  "ipv6 endpoint must be classified correctly");
    ok &= Require(endpoint.value.host == "2001:db8::1", "ipv6 endpoint must normalize brackets away");
  }

  const auto invalid_network = swg::ParseIpNetwork("10.0.0.2", "allowed_ips");
  ok &= Require(!invalid_network.ok(), "cidr parser must reject missing prefix length");

  const auto invalid_dns = swg::ParseIpAddress("dns.example.test", "dns");
  ok &= Require(!invalid_dns.ok(), "dns parser must currently reject hostnames");
  return ok;
}

swg::Config MakeValidConfig() {
  swg::Config config = swg::DefaultConfig();
  swg::ProfileConfig profile{};
  profile.name = "default";
  profile.private_key = kSamplePrivateKey;
  profile.public_key = kSamplePublicKey;
  profile.preshared_key = kSamplePresharedKey;
  profile.endpoint_host = "localhost";
  profile.endpoint_port = 51820;
  profile.allowed_ips = {"0.0.0.0/0", "::/0"};
  profile.addresses = {"10.0.0.2/32"};
  profile.dns_servers = {"1.1.1.1", "1.0.0.1"};
  profile.autostart = false;
  config.profiles.emplace(profile.name, profile);
  config.active_profile = profile.name;
  config.runtime_flags = swg::ToFlags(swg::RuntimeFlag::DnsThroughTunnel);
  return config;
}

bool TestWireGuardProfileValidation() {
  const swg::Config valid_config = MakeValidConfig();
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "valid WireGuard profile must pass connect validation");
  if (!validated.ok()) {
    return false;
  }

  ok &= Require(validated.value.has_preshared_key, "validated profile must preserve preshared key presence");
  ok &= Require(validated.value.endpoint.port == 51820, "validated profile must preserve endpoint port");
  ok &= Require(validated.value.endpoint.type == swg::ParsedEndpointHostType::Hostname,
                "validated profile must preserve endpoint host type");
  ok &= Require(validated.value.allowed_ips.size() == 2, "validated profile must parse allowed ip networks");
  ok &= Require(validated.value.addresses.size() == 1, "validated profile must parse interface addresses");
  ok &= Require(validated.value.dns_servers.size() == 2, "validated profile must parse dns servers");
  ok &= Require(validated.value.persistent_keepalive == 25,
                "validated profile must preserve keepalive interval");

  swg::Config invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").private_key = "not-base64";
  const auto invalid = swg::ValidateWireGuardProfileForConnect(invalid_config.profiles.at("default"));
  ok &= Require(!invalid.ok(), "invalid WireGuard key must fail connect validation");

  invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").allowed_ips = {"not-a-cidr"};
  const auto invalid_cidr = swg::ValidateWireGuardProfileForConnect(invalid_config.profiles.at("default"));
  ok &= Require(!invalid_cidr.ok(), "invalid allowed_ips entry must fail connect validation");
  return ok;
}

bool TestTunnelSessionPreparation() {
  const swg::Config valid_config = MakeValidConfig();
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for tunnel session prep");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared = swg::sysmodule::PrepareTunnelSession(
      valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "hostname-based IPv4-ready profile must prepare a tunnel session");
  if (!prepared.ok()) {
    return false;
  }

  ok &= Require(prepared.value.endpoint.state == swg::sysmodule::PreparedEndpointState::NeedsIpv4Resolution,
                "hostname endpoint must remain resolution-pending");
  ok &= Require(prepared.value.allowed_ipv4_routes.size() == 1,
                "only IPv4 allowed_ips entries should be kept for the current transport");
  ok &= Require(prepared.value.ignored_ipv6_allowed_ips == 1,
                "IPv6 allowed_ips entries should be recorded as ignored for the current transport");
  ok &= Require(prepared.value.interface_ipv4_addresses.size() == 1,
                "IPv4 interface addresses should be retained for the current transport");
  ok &= Require(prepared.value.dns_servers.size() == 2,
                "IPv4 DNS servers should be retained for the current transport");

  swg::Config ipv6_endpoint_config = MakeValidConfig();
  ipv6_endpoint_config.profiles.at("default").endpoint_host = "[2001:db8::1]";
  const auto validated_ipv6_endpoint =
      swg::ValidateWireGuardProfileForConnect(ipv6_endpoint_config.profiles.at("default"));
  ok &= Require(validated_ipv6_endpoint.ok(), "IPv6 endpoint should still parse at shared validation layer");
  if (validated_ipv6_endpoint.ok()) {
    const auto unsupported_endpoint = swg::sysmodule::PrepareTunnelSession(
        ipv6_endpoint_config.active_profile, validated_ipv6_endpoint.value, ipv6_endpoint_config.runtime_flags);
    ok &= Require(!unsupported_endpoint.ok(), "IPv6 transport endpoint should be rejected by Switch session prep");
  }

  swg::Config ipv6_address_config = MakeValidConfig();
  ipv6_address_config.profiles.at("default").addresses = {"fd00::2/128"};
  const auto validated_ipv6_address =
      swg::ValidateWireGuardProfileForConnect(ipv6_address_config.profiles.at("default"));
  ok &= Require(validated_ipv6_address.ok(), "IPv6 interface address should still parse at shared validation layer");
  if (validated_ipv6_address.ok()) {
    const auto unsupported_address = swg::sysmodule::PrepareTunnelSession(
        ipv6_address_config.active_profile, validated_ipv6_address.value, ipv6_address_config.runtime_flags);
    ok &= Require(!unsupported_address.ok(), "Switch session prep should require an IPv4 interface address");
  }

  return ok;
}

bool TestTunnelEndpointResolution() {
  bool ok = true;

  swg::Config literal_config = MakeValidConfig();
  literal_config.profiles.at("default").endpoint_host = "127.0.0.1";
  const auto validated_literal = swg::ValidateWireGuardProfileForConnect(literal_config.profiles.at("default"));
  ok &= Require(validated_literal.ok(), "IPv4 literal endpoint must validate before resolution");
  if (!validated_literal.ok()) {
    return false;
  }

  const auto prepared_literal =
      swg::sysmodule::PrepareTunnelSession(literal_config.active_profile, validated_literal.value,
                                           literal_config.runtime_flags);
  ok &= Require(prepared_literal.ok(), "IPv4 literal endpoint must prepare a session");
  if (!prepared_literal.ok()) {
    return false;
  }

  const auto resolved_literal = swg::sysmodule::ResolvePreparedTunnelSessionEndpoint(prepared_literal.value);
  ok &= Require(resolved_literal.ok(), "ready IPv4 literal endpoint must resolve without DNS");
  if (resolved_literal.ok()) {
    ok &= Require(resolved_literal.value.endpoint.state == swg::sysmodule::PreparedEndpointState::Ready,
                  "IPv4 literal endpoint must stay ready after resolution");
    ok &= Require(resolved_literal.value.endpoint.ipv4[0] == 127 && resolved_literal.value.endpoint.ipv4[3] == 1,
                  "IPv4 literal endpoint must preserve its numeric address bytes");
  }

  swg::Config hostname_config = MakeValidConfig();
  hostname_config.profiles.at("default").endpoint_host = "LOCALHOST";
  const auto validated_hostname = swg::ValidateWireGuardProfileForConnect(hostname_config.profiles.at("default"));
  ok &= Require(validated_hostname.ok(), "localhost endpoint must validate before resolution");
  if (!validated_hostname.ok()) {
    return false;
  }

  const auto prepared_hostname =
      swg::sysmodule::PrepareTunnelSession(hostname_config.active_profile, validated_hostname.value,
                                           hostname_config.runtime_flags);
  ok &= Require(prepared_hostname.ok(), "localhost endpoint must prepare a session");
  if (!prepared_hostname.ok()) {
    return false;
  }

  ok &= Require(prepared_hostname.value.endpoint.state == swg::sysmodule::PreparedEndpointState::NeedsIpv4Resolution,
                "hostname endpoint must require IPv4 resolution before transport");

  const auto resolved_hostname = swg::sysmodule::ResolvePreparedTunnelSessionEndpoint(prepared_hostname.value);
  ok &= Require(resolved_hostname.ok(), "localhost endpoint must resolve to an IPv4 address on host tests");
  if (resolved_hostname.ok()) {
    ok &= Require(resolved_hostname.value.endpoint.state == swg::sysmodule::PreparedEndpointState::Ready,
                  "resolved hostname endpoint must become ready");
    ok &= Require(resolved_hostname.value.endpoint.ipv4[0] == 127,
                  "localhost endpoint must resolve to the IPv4 loopback range");
    ok &= Require(resolved_hostname.value.endpoint.port == 51820,
                  "hostname resolution must preserve the endpoint port");
  }

  return ok;
}

bool TestTunnelEngineUdpScaffold() {
  const swg::Config valid_config = MakeValidConfig();
  const auto validated = swg::ValidateWireGuardProfileForConnect(valid_config.profiles.at("default"));

  bool ok = true;
  ok &= Require(validated.ok(), "validated profile must be available for engine start");
  if (!validated.ok()) {
    return false;
  }

  const auto prepared =
      swg::sysmodule::PrepareTunnelSession(valid_config.active_profile, validated.value, valid_config.runtime_flags);
  ok &= Require(prepared.ok(), "prepared session must be available for engine start");
  if (!prepared.ok()) {
    return false;
  }

  auto engine = swg::sysmodule::CreateStubWgTunnelEngine();
  const swg::Error start_error = engine->Start(swg::sysmodule::TunnelEngineStartRequest{prepared.value});
  ok &= Require(start_error.ok(), "engine start must open the UDP scaffold for a resolvable endpoint");
  ok &= Require(engine->IsRunning(), "engine must report running after UDP scaffold start");
  ok &= Require(engine->GetStats().successful_handshakes == 0,
                "UDP scaffold must not claim a successful WireGuard handshake");
  ok &= Require(engine->Stop().ok(), "engine stop must close the UDP scaffold cleanly");
  ok &= Require(!engine->IsRunning(), "engine must report stopped after shutdown");
  return ok;
}

bool TestConfigRoundTrip() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  const swg::RuntimePaths paths = swg::DetectRuntimePaths(runtime_root);
  const swg::Config expected = MakeValidConfig();
  const swg::Error save_error = swg::SaveConfigFile(expected, paths.config_file);
  if (!Require(save_error.ok(), "config save must succeed")) {
    return false;
  }

  const swg::Result<swg::Config> loaded = swg::LoadConfigFile(paths.config_file);
  if (!Require(loaded.ok(), "config load must succeed")) {
    return false;
  }

  bool ok = true;
  ok &= Require(loaded.value.active_profile == expected.active_profile, "active profile must round-trip");
  ok &= Require(loaded.value.profiles.size() == 1, "exactly one profile must round-trip");
  ok &= Require(loaded.value.runtime_flags == expected.runtime_flags, "runtime flags must round-trip");
  ok &= Require(loaded.value.profiles.at("default").endpoint_host == expected.profiles.at("default").endpoint_host,
                "endpoint_host must round-trip");
  return ok;
}

bool TestStateMachine() {
  swg::ConnectionStateMachine machine;
  const swg::Config config = MakeValidConfig();

  bool ok = true;
  ok &= Require(machine.ApplyConfig(config).ok(), "apply config must succeed");
  ok &= Require(machine.Connect().ok(), "connect transition must succeed");
  ok &= Require(machine.MarkConnected().ok(), "mark connected must succeed");

  const swg::StateSnapshot connected = machine.snapshot();
  ok &= Require(connected.state == swg::TunnelState::Connected, "state must be connected");

  ok &= Require(machine.Disconnect().ok(), "disconnect transition must succeed");
  ok &= Require(machine.MarkDisconnected().ok(), "mark disconnected must succeed");

  const swg::StateSnapshot ready = machine.snapshot();
  ok &= Require(ready.state == swg::TunnelState::ConfigReady, "state must return to config_ready");
  return ok;
}

bool TestClientHostBinding() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-client";
  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  const auto version = client.GetVersion();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(version.ok(), "attached host service must provide version");
  ok &= Require(status.ok(), "attached host service must provide status");
  ok &= Require(status.value.service_ready, "attached host service must be ready");
  return ok;
}

bool TestConnectPreflightStats() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-connect";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig()).ok(), "valid config must save before connect preflight test")) {
    return false;
  }
  if (!Require(client.Connect().ok(), "connect must succeed after WireGuard preflight")) {
    return false;
  }

  const auto stats = client.GetStats();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(stats.ok(), "stats query must succeed after connect");
  ok &= Require(status.ok(), "status query must succeed after connect");
  if (!stats.ok() || !status.ok()) {
    return false;
  }

  ok &= Require(stats.value.connect_attempts == 1, "connect must increment connect_attempts");
  ok &= Require(stats.value.successful_handshakes == 0,
                "connect must not claim a successful handshake before transport integration exists");
  ok &= Require(status.value.state == swg::TunnelState::Connected,
                "validated placeholder engine should keep the existing connected UX for now");
  return ok;
}

bool TestInvalidWireGuardConnectFails() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-invalid-connect";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  swg::Config invalid_config = MakeValidConfig();
  invalid_config.profiles.at("default").public_key = "invalid-key";

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(invalid_config).ok(), "invalid-format profile should still save at config layer")) {
    return false;
  }

  const swg::Error connect_error = client.Connect();
  const auto status = client.GetStatus();

  bool ok = true;
  ok &= Require(connect_error.code == swg::ErrorCode::InvalidConfig,
                "connect must fail with InvalidConfig when WireGuard keys are malformed");
  ok &= Require(status.ok(), "status query must succeed after failed connect");
  if (!status.ok()) {
    return false;
  }

  ok &= Require(status.value.state == swg::TunnelState::Error,
                "failed WireGuard preflight must move the service into error state");
  ok &= Require(status.value.last_error.find("public_key") != std::string::npos,
                "failed connect must surface the WireGuard validation error");
  return ok;
}

bool TestIpcCodecRoundTrip() {
  const swg::VersionInfo expected_version{};
  const swg::Result<swg::ByteBuffer> version_payload = swg::EncodePayload(expected_version);
  if (!Require(version_payload.ok(), "version payload encoding must succeed")) {
    return false;
  }

  const swg::Result<swg::VersionInfo> decoded_version = swg::DecodeVersionInfoPayload(version_payload.value);
  if (!Require(decoded_version.ok(), "version payload decoding must succeed")) {
    return false;
  }

  bool ok = true;
  ok &= Require(decoded_version.value.abi_version == expected_version.abi_version,
                "version payload must preserve abi version");
  ok &= Require(decoded_version.value.semantic_version == expected_version.semantic_version,
                "version payload must preserve semantic version");

  const swg::Config expected_config = MakeValidConfig();
  const swg::Result<swg::ByteBuffer> config_payload = swg::EncodePayload(expected_config);
  ok &= Require(config_payload.ok(), "config payload encoding must succeed");
  if (!config_payload.ok()) {
    return false;
  }

  const swg::Result<swg::Config> decoded_config = swg::DecodeConfigPayload(config_payload.value);
  ok &= Require(decoded_config.ok(), "config payload decoding must succeed");
  if (!decoded_config.ok()) {
    return false;
  }

  ok &= Require(decoded_config.value.active_profile == expected_config.active_profile,
                "config payload must preserve active profile");
  ok &= Require(decoded_config.value.profiles.at("default").endpoint_host ==
                    expected_config.profiles.at("default").endpoint_host,
                "config payload must preserve endpoint host");
  return ok;
}

bool TestMoonlightRoutePlanning() {
  const std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-moonlight";
  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  if (!Require(client.SaveConfig(MakeValidConfig()).ok(), "valid config must save before Moonlight planning")) {
    return false;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(swg::MakeMoonlightSessionRequest("default", true));
  if (!Require(opened.ok(), "Moonlight app session must open")) {
    return false;
  }

  bool ok = true;
  ok &= Require(!opened.value.tunnel_ready, "Moonlight session should start disconnected");
  ok &= Require(opened.value.active_profile == "default", "Moonlight session should bind to requested profile");

  const auto discovery = session.PlanNetwork(swg::MakeMoonlightDiscoveryPlan());
  ok &= Require(discovery.ok(), "discovery plan must succeed");
  ok &= Require(discovery.value.action == swg::RouteAction::Direct, "discovery must bypass the tunnel");
  ok &= Require(discovery.value.local_bypass, "discovery must be marked as local bypass");

  const auto wake = session.PlanNetwork(swg::MakeMoonlightWakeOnLanPlan("192.168.1.20"));
  ok &= Require(wake.ok(), "wake-on-lan plan must succeed");
  ok &= Require(wake.value.action == swg::RouteAction::Direct, "wake-on-lan must bypass the tunnel");

  const auto control_before_connect = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984));
  ok &= Require(control_before_connect.ok(), "control plan must succeed before connect");
  ok &= Require(control_before_connect.value.action == swg::RouteAction::Deny,
                "control traffic should be denied until the tunnel is connected");

  ok &= Require(client.Connect().ok(), "service connect must succeed for Moonlight planning");

  const auto dns = session.PlanNetwork(swg::MakeMoonlightDnsPlan("vpn.example.test"));
  ok &= Require(dns.ok(), "dns plan must succeed after connect");
  ok &= Require(dns.value.action == swg::RouteAction::Tunnel, "dns should use the tunnel after connect");
  ok &= Require(dns.value.use_tunnel_dns, "dns plan must mark tunnel dns usage");

  const auto control_after_connect = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("vpn.example.test", 47984));
  ok &= Require(control_after_connect.ok(), "control plan must succeed after connect");
  ok &= Require(control_after_connect.value.action == swg::RouteAction::Tunnel,
                "control traffic should use the tunnel after connect");

  const auto video = session.PlanNetwork(swg::MakeMoonlightVideoPlan("vpn.example.test", 47998));
  ok &= Require(video.ok(), "video plan must succeed after connect");
  ok &= Require(video.value.action == swg::RouteAction::Tunnel, "video traffic should use the tunnel after connect");

  ok &= Require(session.Close().ok(), "Moonlight app session must close cleanly");
  return ok;
}

}  // namespace

int main() {
  const bool endpoint_parser_ok = TestEndpointAndNetworkParsing();
  const bool config_ok = TestConfigRoundTrip();
  const bool wg_validation_ok = TestWireGuardProfileValidation();
  const bool tunnel_session_ok = TestTunnelSessionPreparation();
  const bool endpoint_resolution_ok = TestTunnelEndpointResolution();
  const bool udp_scaffold_ok = TestTunnelEngineUdpScaffold();
  const bool state_ok = TestStateMachine();
  const bool client_ok = TestClientHostBinding();
  const bool connect_preflight_ok = TestConnectPreflightStats();
  const bool invalid_connect_ok = TestInvalidWireGuardConnectFails();
  const bool codec_ok = TestIpcCodecRoundTrip();
  const bool moonlight_ok = TestMoonlightRoutePlanning();
        return (endpoint_parser_ok && config_ok && wg_validation_ok && tunnel_session_ok && endpoint_resolution_ok &&
          udp_scaffold_ok && state_ok && client_ok && connect_preflight_ok && invalid_connect_ok && codec_ok &&
          moonlight_ok)
             ? 0
             : 1;
}
