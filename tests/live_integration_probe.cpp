#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "swg/app_session.h"
#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg/moonlight.h"
#include "swg/session_socket.h"
#include "swg/tunnel_datagram.h"
#include "swg/tunnel_stream.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/host_transport.h"

namespace {

constexpr std::chrono::milliseconds kReceivePollInterval(100);
constexpr int kReceivePollAttempts = 20;
constexpr char kHarnessHttpSignature[] = "service=swg-integration-server";

struct ProbeOptions {
  std::filesystem::path config_path = std::filesystem::path(SWG_SOURCE_DIR) / "docs/config.ini";
  std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-live-integration-probe";
  std::string profile_override;
};

struct DiagnosticTarget {
  std::string host;
  bool is_hostname = false;
  bool is_numeric_ipv4 = false;
  bool is_numeric_ipv6 = false;
};

struct IntegrationServerTarget {
  DiagnosticTarget endpoint;
  std::string dns_hostname;
  std::uint16_t tcp_echo_port = 0;
  std::uint16_t http_port = 0;
  std::uint16_t udp_echo_port = 0;
  std::string http_path;
  bool uses_profile_endpoint = false;
};

void PrintUsage() {
  std::cout << "usage: swg_live_integration_probe [--config PATH] [--runtime-root PATH] [--profile NAME]\n";
}

std::string ToString(const std::vector<std::uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

std::vector<std::uint8_t> ToByteVector(std::string_view text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::string DescribeStats(const swg::TunnelStats& stats) {
  return "connect_attempts=" + std::to_string(stats.connect_attempts) +
         ", successful_handshakes=" + std::to_string(stats.successful_handshakes) +
         ", reconnects=" + std::to_string(stats.reconnects) +
         ", bytes_in=" + std::to_string(stats.bytes_in) +
         ", bytes_out=" + std::to_string(stats.bytes_out) +
         ", packets_in=" + std::to_string(stats.packets_in) +
         ", packets_out=" + std::to_string(stats.packets_out);
}

swg::Result<ProbeOptions> ParseOptions(int argc, char** argv) {
  ProbeOptions options;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--config") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --config");
      }
      options.config_path = argv[++index];
      continue;
    }

    if (argument == "--runtime-root") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --runtime-root");
      }
      options.runtime_root = argv[++index];
      continue;
    }

    if (argument == "--profile") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --profile");
      }
      options.profile_override = argv[++index];
      continue;
    }

    if (argument == "--help" || argument == "-h") {
      PrintUsage();
      std::exit(0);
    }

    return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError,
                                          "unrecognized argument: " + std::string(argument));
  }

  return swg::MakeSuccess(std::move(options));
}

swg::Result<DiagnosticTarget> ClassifyDiagnosticTarget(std::string host, std::string_view field_name) {
  if (host.empty()) {
    return swg::MakeFailure<DiagnosticTarget>(swg::ErrorCode::ParseError,
                                              std::string(field_name) + " must not be empty");
  }

  DiagnosticTarget target{};
  target.host = std::move(host);

  const swg::Result<swg::ParsedIpAddress> parsed = swg::ParseIpAddress(target.host, std::string(field_name));
  if (!parsed.ok()) {
    target.is_hostname = true;
  } else if (parsed.value.family == swg::ParsedIpFamily::IPv4) {
    target.is_numeric_ipv4 = true;
  } else {
    target.is_numeric_ipv6 = true;
  }

  return swg::MakeSuccess(std::move(target));
}

std::string DescribeDiagnosticTarget(const DiagnosticTarget& target) {
  if (target.is_hostname) {
    return target.host + " (hostname)";
  }
  if (target.is_numeric_ipv4) {
    return target.host + " (numeric IPv4)";
  }
  return target.host + " (numeric IPv6)";
}

std::string ResolveDesiredProfile(const swg::Config& config, std::string_view profile_override) {
  if (!profile_override.empty()) {
    return std::string(profile_override);
  }

  if (!config.active_profile.empty()) {
    return config.active_profile;
  }

  if (!config.profiles.empty()) {
    return config.profiles.begin()->first;
  }

  return {};
}

swg::Result<IntegrationServerTarget> GetIntegrationServerTarget(const swg::Config& config,
                                                                std::string_view desired_profile) {
  IntegrationServerTarget target{};
  target.tcp_echo_port = config.integration_test.tcp_echo_port;
  target.http_port = config.integration_test.http_port;
  target.udp_echo_port = config.integration_test.udp_echo_port;
  target.http_path = config.integration_test.http_path;

  if (!config.integration_test.target_host.empty()) {
    const auto classified =
        ClassifyDiagnosticTarget(config.integration_test.target_host, "integration_test.target_host");
    if (!classified.ok()) {
      return swg::MakeFailure<IntegrationServerTarget>(classified.error.code, classified.error.message);
    }
    target.endpoint = classified.value;
  } else {
    const auto profile_it = config.profiles.find(std::string(desired_profile));
    if (profile_it == config.profiles.end()) {
      return swg::MakeFailure<IntegrationServerTarget>(swg::ErrorCode::NotFound,
                                                       "desired profile not found: " + std::string(desired_profile));
    }

    const auto classified = ClassifyDiagnosticTarget(profile_it->second.endpoint_host, "profile.endpoint_host");
    if (!classified.ok()) {
      return swg::MakeFailure<IntegrationServerTarget>(classified.error.code, classified.error.message);
    }
    target.endpoint = classified.value;
    target.uses_profile_endpoint = true;
  }

  if (!config.integration_test.dns_hostname.empty()) {
    target.dns_hostname = config.integration_test.dns_hostname;
  } else if (target.endpoint.is_hostname) {
    target.dns_hostname = target.endpoint.host;
  }

  return swg::MakeSuccess(std::move(target));
}

std::string DescribeIntegrationServerTarget(const IntegrationServerTarget& target) {
  std::string description = DescribeDiagnosticTarget(target.endpoint);
  description += " tcp=" + std::to_string(target.tcp_echo_port);
  description += " http=" + std::to_string(target.http_port);
  description += " udp=" + std::to_string(target.udp_echo_port);
  description += target.uses_profile_endpoint ? " source=profile.endpoint_host" : " source=integration_test.target_host";
  if (!target.dns_hostname.empty()) {
    description += " dns=" + target.dns_hostname;
  }
  return description;
}

swg::AppTunnelRequest MakeIntegrationSessionRequest(std::string desired_profile) {
  swg::AppTunnelRequest request{};
  request.app.client_name = "SWG Integration";
  request.app.integration_tag = "switch-integration";
  request.desired_profile = std::move(desired_profile);
  return request;
}

swg::Result<swg::TunnelDatagram> PollTunnelDatagramReceive(const swg::TunnelDatagramSocket& socket) {
  for (int attempt = 0; attempt < kReceivePollAttempts; ++attempt) {
    const auto result = socket.Receive();
    if (result.ok()) {
      return result;
    }
    if (result.error.code != swg::ErrorCode::NotFound) {
      return result;
    }
    std::this_thread::sleep_for(kReceivePollInterval);
  }

  return swg::MakeFailure<swg::TunnelDatagram>(swg::ErrorCode::NotFound,
                                               "timed out waiting for a tunnel datagram response");
}

swg::Result<swg::TunnelStreamReadResult> PollTunnelStreamReceive(const swg::TunnelStreamSocket& socket) {
  for (int attempt = 0; attempt < kReceivePollAttempts; ++attempt) {
    const auto result = socket.Receive();
    if (result.ok()) {
      if (!result.value.payload.empty() || result.value.peer_closed) {
        return result;
      }
    } else if (result.error.code != swg::ErrorCode::NotFound) {
      return result;
    }

    std::this_thread::sleep_for(kReceivePollInterval);
  }

  return swg::MakeFailure<swg::TunnelStreamReadResult>(swg::ErrorCode::NotFound,
                                                       "timed out waiting for a tunnel stream response");
}

void PrintStep(bool passed, std::string_view label, const std::string& detail) {
  std::cout << (passed ? "PASS " : "FAIL ") << label << ": " << detail << '\n';
}

}  // namespace

int main(int argc, char** argv) {
  const auto options = ParseOptions(argc, argv);
  if (!options.ok()) {
    std::cerr << "argument error: " << options.error.message << '\n';
    PrintUsage();
    return 2;
  }

  std::error_code filesystem_error;
  std::filesystem::remove_all(options.value.runtime_root, filesystem_error);

  const auto loaded = swg::LoadConfigFile(options.value.config_path);
  if (!loaded.ok()) {
    std::cerr << "config load failed: " << loaded.error.message << '\n';
    return 1;
  }

  const std::string desired_profile = ResolveDesiredProfile(loaded.value, options.value.profile_override);
  if (desired_profile.empty()) {
    std::cerr << "no active or fallback profile is available in the config" << '\n';
    return 1;
  }

  const auto target = GetIntegrationServerTarget(loaded.value, desired_profile);
  if (!target.ok()) {
    std::cerr << "integration target error: " << target.error.message << '\n';
    return 1;
  }

  std::cout << "config: " << options.value.config_path << '\n';
  std::cout << "runtime_root: " << options.value.runtime_root << '\n';
  std::cout << "profile: " << desired_profile << '\n';
  std::cout << "target: " << DescribeIntegrationServerTarget(target.value) << '\n';

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(options.value.runtime_root));
  const swg::Error save_error = client.SaveConfig(loaded.value);
  if (save_error) {
    std::cerr << "config save failed: " << save_error.message << '\n';
    return 1;
  }

  const swg::Error connect_error = client.Connect();
  if (connect_error) {
    std::cerr << "connect failed: " << connect_error.message << '\n';
    return 1;
  }

  swg::AppSession session(client);
  const auto opened = session.Open(MakeIntegrationSessionRequest(desired_profile));
  if (!opened.ok()) {
    std::cerr << "app session open failed: " << opened.error.message << '\n';
    static_cast<void>(client.Disconnect());
    return 1;
  }

  const auto initial_status = client.GetStatus();
  const auto initial_stats = client.GetStats();
  if (initial_status.ok()) {
    std::cout << "status: state=" << swg::ToString(initial_status.value.state)
              << " active_profile=" << initial_status.value.active_profile << '\n';
  }
  if (initial_stats.ok()) {
    std::cout << "stats: " << DescribeStats(initial_stats.value) << '\n';
  }

  bool all_ok = true;

  if (target.value.dns_hostname.empty()) {
    PrintStep(false, "dns", "configure integration_test.dns_hostname to exercise tunnel DNS for this target");
    all_ok = false;
  } else {
    const auto dns = session.ResolveDns(target.value.dns_hostname);
    if (!dns.ok()) {
      PrintStep(false, "dns", dns.error.message);
      all_ok = false;
    } else if (!dns.value.resolved || dns.value.addresses.empty()) {
      PrintStep(false, "dns", "resolve returned no IPv4 addresses");
      all_ok = false;
    } else {
      PrintStep(true,
                "dns",
                std::string(swg::ToString(dns.value.action)) + " addrs=" +
                    (dns.value.addresses.empty() ? std::string("<none>") : dns.value.addresses.front()));
    }
  }

  const auto session_datagram =
      swg::SessionSocket::OpenDatagram(session,
                                       swg::MakeMoonlightVideoSocketRequest(target.value.endpoint.host,
                                                                            target.value.udp_echo_port));
  const auto session_stream =
      swg::SessionSocket::OpenStream(session,
                                     swg::MakeMoonlightStreamControlSocketRequest(target.value.endpoint.host,
                                                                                  target.value.tcp_echo_port));
  if (!session_datagram.ok() || !session_stream.ok()) {
    const std::string error = !session_datagram.ok() ? session_datagram.error.message : session_stream.error.message;
    PrintStep(false, "session-socket", error);
    all_ok = false;
  } else {
    const bool ok = session_datagram.value.uses_tunnel_packets() && session_stream.value.uses_tunnel_packets();
    PrintStep(ok,
              "session-socket",
              std::string("udp=") + std::string(swg::ToString(session_datagram.value.info().mode)) +
                  " tcp=" + std::string(swg::ToString(session_stream.value.info().mode)));
    all_ok &= ok;
  }

  {
    const auto stream = swg::TunnelStreamSocket::Open(
        session, swg::MakeMoonlightStreamControlStreamRequest(target.value.endpoint.host, target.value.tcp_echo_port));
    if (!stream.ok()) {
      PrintStep(false, "tcp-echo", stream.error.message);
      all_ok = false;
    } else {
      const std::string payload_text = "SWG-TCP-ECHO-HOST";
      const auto sent = stream.value.Send(ToByteVector(payload_text));
      if (!sent.ok()) {
        PrintStep(false, "tcp-echo", sent.error.message);
        all_ok = false;
      } else {
        const auto received = PollTunnelStreamReceive(stream.value);
        if (!received.ok()) {
          PrintStep(false, "tcp-echo", received.error.message);
          all_ok = false;
        } else {
          const std::string response = ToString(received.value.payload);
          const bool ok = response == payload_text;
          PrintStep(ok,
                    "tcp-echo",
                    "send_counter=" + std::to_string(sent.value) +
                        " bytes=" + std::to_string(received.value.payload.size()));
          all_ok &= ok;
        }
      }
    }
  }

  {
    swg::TunnelStreamOpenRequest http_request{};
    http_request.remote_host = target.value.endpoint.host;
    http_request.remote_port = target.value.http_port;
    http_request.transport = swg::TransportProtocol::Https;
    http_request.traffic_class = swg::AppTrafficClass::HttpsControl;
    http_request.route_preference = swg::RoutePreference::RequireTunnel;

    const auto stream = swg::TunnelStreamSocket::Open(session, http_request);
    if (!stream.ok()) {
      PrintStep(false, "http-probe", stream.error.message);
      all_ok = false;
    } else {
      const std::string host_header = target.value.dns_hostname.empty() ? target.value.endpoint.host : target.value.dns_hostname;
      const std::string request_text = "GET " + target.value.http_path +
                                       " HTTP/1.1\r\nHost: " + host_header +
                                       "\r\nConnection: close\r\nUser-Agent: swg-live-integration-probe/1\r\n\r\n";
      const auto sent = stream.value.Send(ToByteVector(request_text));
      if (!sent.ok()) {
        PrintStep(false, "http-probe", sent.error.message);
        all_ok = false;
      } else {
        const auto received = PollTunnelStreamReceive(stream.value);
        if (!received.ok()) {
          PrintStep(false, "http-probe", received.error.message);
          all_ok = false;
        } else {
          const std::string response = ToString(received.value.payload);
          const bool ok = response.find("HTTP/1.1 200 OK") != std::string::npos &&
                          response.find(kHarnessHttpSignature) != std::string::npos;
          PrintStep(ok,
                    "http-probe",
                    "send_counter=" + std::to_string(sent.value) +
                        " bytes=" + std::to_string(received.value.payload.size()));
          all_ok &= ok;
        }
      }
    }
  }

  {
    const auto socket = swg::TunnelDatagramSocket::Open(
        session, swg::MakeMoonlightVideoDatagramRequest(target.value.endpoint.host, target.value.udp_echo_port));
    if (!socket.ok()) {
      PrintStep(false, "udp-echo", socket.error.message);
      all_ok = false;
    } else {
      const std::string payload_text = "SWG-UDP-ECHO-HOST";
      const auto sent = socket.value.Send(ToByteVector(payload_text));
      if (!sent.ok()) {
        PrintStep(false, "udp-echo", sent.error.message);
        all_ok = false;
      } else {
        const auto received = PollTunnelDatagramReceive(socket.value);
        if (!received.ok()) {
          PrintStep(false, "udp-echo", received.error.message);
          all_ok = false;
        } else {
          const std::string response = ToString(received.value.payload);
          const bool ok = response == payload_text;
          PrintStep(ok,
                    "udp-echo",
                    "send_counter=" + std::to_string(sent.value) +
                        " bytes=" + std::to_string(received.value.payload.size()));
          all_ok &= ok;
        }
      }
    }
  }

  const auto final_stats = client.GetStats();
  if (final_stats.ok()) {
    std::cout << "final stats: " << DescribeStats(final_stats.value) << '\n';
  }
  std::cout << "log file: " << (options.value.runtime_root / "logs/swg/swg.log") << '\n';

  static_cast<void>(session.Close());
  static_cast<void>(client.Disconnect());
  return all_ok ? 0 : 1;
}