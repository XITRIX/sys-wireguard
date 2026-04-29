#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>

#include "swg/app_session.h"
#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg/result.h"
#include "swg/tunnel_stream.h"
#include "swg_sysmodule/host_transport.h"

namespace {

constexpr char kCompatBridgeClientName[] = "Moonlight-Switch";
constexpr char kCompatBridgeIntegrationTag[] = "moonlight-switch";
constexpr std::chrono::milliseconds kReceivePollInterval(100);
constexpr int kReceivePollAttempts = 50;

struct ProbeOptions {
  std::filesystem::path config_path = std::filesystem::path(SWG_SOURCE_DIR) / "docs/config.ini";
  std::filesystem::path runtime_root = std::filesystem::current_path() / "test-runtime-live-moonlight-control-probe";
  std::filesystem::path client_cert_path = std::filesystem::path(SWG_SOURCE_DIR) / "docs/key/client.pem";
  std::filesystem::path client_key_path = std::filesystem::path(SWG_SOURCE_DIR) / "docs/key/key.pem";
  std::string profile_override;
  std::string host;
  std::uint16_t http_port = 47989;
  std::uint16_t https_port = 47984;
  std::uint16_t rtsp_port = 48010;
  std::string http_path = "/serverinfo";
  std::string https_serverinfo_path = "/serverinfo?uniqueid=swg-live-moonlight-control-probe";
  std::string https_applist_path = "/applist?uniqueid=swg-live-moonlight-control-probe";
  std::string https_resume_path =
      "/resume?uniqueid=swg-live-moonlight-control-probe&rikey=000102030405060708090a0b0c0d0e0f&rikeyid=0&corever=1";
  std::string rtsp_target;
  bool rtsp_only = false;
  bool rtsp_via_resume = false;
};

void PrintUsage() {
  std::cout << "usage: swg_live_moonlight_control_probe --host HOST [--config PATH] [--runtime-root PATH] [--client-cert PATH] [--client-key PATH] [--profile NAME] [--http-port PORT] [--https-port PORT] [--rtsp-port PORT] [--http-path PATH] [--https-serverinfo-path PATH] [--https-applist-path PATH] [--https-resume-path PATH] [--rtsp-target URL] [--rtsp-only] [--rtsp-via-resume]\n";
}

std::vector<std::uint8_t> ToByteVector(std::string_view text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::string ToString(const std::vector<std::uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
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

bool ParsePort(std::string_view value, std::uint16_t* port) {
  if (port == nullptr || value.empty()) {
    return false;
  }

  std::uint32_t parsed = 0;
  for (const char ch : value) {
    if (ch < '0' || ch > '9') {
      return false;
    }
    parsed = parsed * 10u + static_cast<std::uint32_t>(ch - '0');
    if (parsed > 65535u) {
      return false;
    }
  }

  if (parsed == 0u) {
    return false;
  }

  *port = static_cast<std::uint16_t>(parsed);
  return true;
}

class TunnelStreamIo {
 public:
  TunnelStreamIo(swg::TunnelStreamSocket socket, int timeout_ms)
      : socket_(std::move(socket)), timeout_ms_(timeout_ms) {}

  bool SendAll(const std::string& request, std::string* error) {
    std::vector<std::uint8_t> payload(request.begin(), request.end());
    const auto sent = socket_.Send(payload);
    if (!sent.ok()) {
      if (error) {
        *error = sent.error.message;
      }
      return false;
    }
    return true;
  }

  int Read(unsigned char* buffer, std::size_t length, bool* peer_closed, std::string* error) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms_);
    while (pending_offset_ >= pending_.size()) {
      pending_.clear();
      pending_offset_ = 0;

      const auto received = socket_.Receive();
      if (received.ok()) {
        pending_ = std::move(received.value.payload);
        peer_closed_seen_ = received.value.peer_closed;
        if (pending_.empty()) {
          if (received.value.peer_closed) {
            *peer_closed = true;
            return 0;
          }
          continue;
        }
        break;
      }

      if (received.error.code != swg::ErrorCode::NotFound) {
        if (error) {
          *error = received.error.message;
        }
        return -1;
      }

      if (std::chrono::steady_clock::now() >= deadline) {
        if (peer_closed_seen_) {
          *peer_closed = true;
          return 0;
        }

        if (error) {
          *error = "timed out waiting for tunnel stream data";
        }
        return 0;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    const std::size_t available = pending_.size() - pending_offset_;
    const std::size_t copy_length = std::min(length, available);
    std::memcpy(buffer, pending_.data() + pending_offset_, copy_length);
    pending_offset_ += copy_length;
    *peer_closed = peer_closed_seen_ && pending_offset_ >= pending_.size();
    return static_cast<int>(copy_length);
  }

  static int BioSend(void* context, const unsigned char* buffer, std::size_t length) {
    auto* io = static_cast<TunnelStreamIo*>(context);
    std::string error;
    std::string request(reinterpret_cast<const char*>(buffer), length);
    if (!io->SendAll(request, &error)) {
      io->last_error_ = error;
      return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return static_cast<int>(length);
  }

  static int BioRecv(void* context, unsigned char* buffer, std::size_t length) {
    auto* io = static_cast<TunnelStreamIo*>(context);
    bool peer_closed = false;
    std::string error;
    const int received = io->Read(buffer, length, &peer_closed, &error);
    if (received > 0) {
      return received;
    }
    if (peer_closed) {
      return 0;
    }
    io->last_error_ = error;
    return error.empty() ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_RECV_FAILED;
  }

  const std::string& last_error() const {
    return last_error_;
  }

 private:
  swg::TunnelStreamSocket socket_{};
  int timeout_ms_ = 0;
  std::vector<std::uint8_t> pending_{};
  std::size_t pending_offset_ = 0;
  bool peer_closed_seen_ = false;
  std::string last_error_{};
};

std::string FormatTlsError(std::string_view operation, int rc) {
  char buffer[256] = {};
  mbedtls_strerror(rc, buffer, sizeof(buffer));
  return std::string(operation) + " failed: " + buffer + " (" + std::to_string(rc) + ")";
}

bool PerformTlsRequest(swg::TunnelStreamSocket socket,
                       const std::string& host,
                       const std::filesystem::path& cert_path,
                       const std::filesystem::path& key_path,
                       const std::string& request_text,
                       std::vector<std::uint8_t>* raw_response,
                       std::string* error) {
  TunnelStreamIo io(std::move(socket), 5000);
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config config;
  mbedtls_x509_crt certificate;
  mbedtls_pk_context private_key;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&config);
  mbedtls_x509_crt_init(&certificate);
  mbedtls_pk_init(&private_key);

  const auto cleanup = [&]() {
    mbedtls_pk_free(&private_key);
    mbedtls_x509_crt_free(&certificate);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
  };

  const char* personalization = "swg-live-probe";
  int rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 reinterpret_cast<const unsigned char*>(personalization),
                                 std::strlen(personalization));
  if (rc != 0) {
    if (error) {
      *error = FormatTlsError("mbedtls_ctr_drbg_seed", rc);
    }
    cleanup();
    return false;
  }

  rc = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) {
    if (error) {
      *error = FormatTlsError("mbedtls_ssl_config_defaults", rc);
    }
    cleanup();
    return false;
  }

  mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &ctr_drbg);

  if (!cert_path.empty() && !key_path.empty()) {
    rc = mbedtls_x509_crt_parse_file(&certificate, cert_path.c_str());
    if (rc == 0) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
      rc = mbedtls_pk_parse_keyfile(&private_key, key_path.c_str(), nullptr,
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
#else
      rc = mbedtls_pk_parse_keyfile(&private_key, key_path.c_str(), nullptr);
#endif
    }
    if (rc == 0) {
      rc = mbedtls_ssl_conf_own_cert(&config, &certificate, &private_key);
    }
    if (rc != 0) {
      if (error) {
        *error = FormatTlsError("loading TLS client credentials", rc);
      }
      cleanup();
      return false;
    }
  }

  rc = mbedtls_ssl_setup(&ssl, &config);
  if (rc != 0) {
    if (error) {
      *error = FormatTlsError("mbedtls_ssl_setup", rc);
    }
    cleanup();
    return false;
  }

  rc = mbedtls_ssl_set_hostname(&ssl, host.c_str());
  if (rc != 0) {
    if (error) {
      *error = FormatTlsError("mbedtls_ssl_set_hostname", rc);
    }
    cleanup();
    return false;
  }

  mbedtls_ssl_set_bio(&ssl, &io, TunnelStreamIo::BioSend, TunnelStreamIo::BioRecv, nullptr);
  while ((rc = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }

    if (error) {
      *error = io.last_error().empty() ? FormatTlsError("mbedtls_ssl_handshake", rc)
                                       : io.last_error();
    }
    cleanup();
    return false;
  }

  std::size_t written = 0;
  while (written < request_text.size()) {
    rc = mbedtls_ssl_write(&ssl,
                           reinterpret_cast<const unsigned char*>(request_text.data() + written),
                           request_text.size() - written);
    if (rc > 0) {
      written += static_cast<std::size_t>(rc);
      continue;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }

    if (error) {
      *error = io.last_error().empty() ? FormatTlsError("mbedtls_ssl_write", rc)
                                       : io.last_error();
    }
    cleanup();
    return false;
  }

  raw_response->clear();
  std::array<unsigned char, 4096> buffer{};
  for (;;) {
    rc = mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
    if (rc > 0) {
      raw_response->insert(raw_response->end(), buffer.begin(), buffer.begin() + rc);
      continue;
    }
    if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      break;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }

    if (error) {
      *error = io.last_error().empty() ? FormatTlsError("mbedtls_ssl_read", rc)
                                       : io.last_error();
    }
    cleanup();
    return false;
  }

  cleanup();
  return true;
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

    if (argument == "--client-cert") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --client-cert");
      }
      options.client_cert_path = argv[++index];
      continue;
    }

    if (argument == "--client-key") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --client-key");
      }
      options.client_key_path = argv[++index];
      continue;
    }

    if (argument == "--profile") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --profile");
      }
      options.profile_override = argv[++index];
      continue;
    }

    if (argument == "--host") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --host");
      }
      options.host = argv[++index];
      continue;
    }

    if (argument == "--http-port") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --http-port");
      }
      if (!ParsePort(argv[++index], &options.http_port)) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "invalid --http-port value");
      }
      continue;
    }

    if (argument == "--https-port") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --https-port");
      }
      if (!ParsePort(argv[++index], &options.https_port)) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "invalid --https-port value");
      }
      continue;
    }

    if (argument == "--rtsp-port") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --rtsp-port");
      }
      if (!ParsePort(argv[++index], &options.rtsp_port)) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "invalid --rtsp-port value");
      }
      continue;
    }

    if (argument == "--http-path") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "missing value after --http-path");
      }
      options.http_path = argv[++index];
      continue;
    }

    if (argument == "--https-serverinfo-path") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError,
                                              "missing value after --https-serverinfo-path");
      }
      options.https_serverinfo_path = argv[++index];
      continue;
    }

    if (argument == "--https-applist-path") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError,
                                              "missing value after --https-applist-path");
      }
      options.https_applist_path = argv[++index];
      continue;
    }

    if (argument == "--https-resume-path") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError,
                                              "missing value after --https-resume-path");
      }
      options.https_resume_path = argv[++index];
      continue;
    }

    if (argument == "--rtsp-target") {
      if (index + 1 >= argc) {
        return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError,
                                              "missing value after --rtsp-target");
      }
      options.rtsp_target = argv[++index];
      continue;
    }

    if (argument == "--rtsp-only") {
      options.rtsp_only = true;
      continue;
    }

    if (argument == "--rtsp-via-resume") {
      options.rtsp_via_resume = true;
      continue;
    }

    if (argument == "--help" || argument == "-h") {
      PrintUsage();
      std::exit(0);
    }

    return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError,
                                          "unrecognized argument: " + std::string(argument));
  }

  if (options.host.empty()) {
    return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::ParseError, "--host is required");
  }

  return swg::MakeSuccess(std::move(options));
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

swg::AppTunnelRequest MakeCompatBridgeSessionRequest(std::string desired_profile) {
  swg::AppTunnelRequest request{};
  request.app.client_name = kCompatBridgeClientName;
  request.app.integration_tag = kCompatBridgeIntegrationTag;
  request.desired_profile = std::move(desired_profile);
  request.allow_local_network_bypass = false;
  return request;
}

swg::NetworkPlanRequest MakeControlPlan(std::string host,
                                        std::uint16_t port,
                                        swg::TransportProtocol transport) {
  swg::NetworkPlanRequest request{};
  request.remote_host = std::move(host);
  request.remote_port = port;
  request.transport = transport;
  request.traffic_class = swg::AppTrafficClass::HttpsControl;
  request.route_preference = swg::RoutePreference::RequireTunnel;
  return request;
}

swg::NetworkPlanRequest MakeRtspPlan(std::string host, std::uint16_t port) {
  swg::NetworkPlanRequest request{};
  request.remote_host = std::move(host);
  request.remote_port = port;
  request.transport = swg::TransportProtocol::Tcp;
  request.traffic_class = swg::AppTrafficClass::StreamControl;
  request.route_preference = swg::RoutePreference::RequireTunnel;
  return request;
}

swg::TunnelStreamOpenRequest MakeControlStreamRequest(std::string host,
                                                      std::uint16_t port,
                                                      swg::TransportProtocol transport) {
  swg::TunnelStreamOpenRequest request{};
  request.remote_host = std::move(host);
  request.remote_port = port;
  request.transport = transport;
  request.traffic_class = swg::AppTrafficClass::HttpsControl;
  request.route_preference = swg::RoutePreference::RequireTunnel;
  return request;
}

swg::TunnelStreamOpenRequest MakeRtspStreamRequest(std::string host, std::uint16_t port) {
  swg::TunnelStreamOpenRequest request{};
  request.remote_host = std::move(host);
  request.remote_port = port;
  request.transport = swg::TransportProtocol::Tcp;
  request.traffic_class = swg::AppTrafficClass::StreamControl;
  request.route_preference = swg::RoutePreference::RequireTunnel;
  return request;
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

std::string FirstResponseLine(std::string response) {
  const std::size_t newline = response.find('\n');
  if (newline == std::string::npos) {
    return response;
  }
  response.resize(newline);
  if (!response.empty() && response.back() == '\r') {
    response.pop_back();
  }
  return response;
}

swg::Result<std::string> ExtractXmlTag(std::string_view xml, std::string_view tag_name) {
  const std::string open_tag = "<" + std::string(tag_name) + ">";
  const std::string close_tag = "</" + std::string(tag_name) + ">";
  const std::size_t begin = xml.find(open_tag);
  if (begin == std::string_view::npos) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::NotFound,
                                         "missing XML tag: " + std::string(tag_name));
  }

  const std::size_t content_begin = begin + open_tag.size();
  const std::size_t end = xml.find(close_tag, content_begin);
  if (end == std::string_view::npos) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::ParseError,
                                         "unterminated XML tag: " + std::string(tag_name));
  }

  return swg::MakeSuccess(std::string(xml.substr(content_begin, end - content_begin)));
}

swg::Result<std::string> ExtractQueryParameter(std::string_view path, std::string_view name) {
  const std::string needle = std::string(name) + "=";
  const std::size_t begin = path.find(needle);
  if (begin == std::string_view::npos) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::NotFound,
                                         "missing query parameter: " + std::string(name));
  }

  const std::size_t value_begin = begin + needle.size();
  const std::size_t value_end = path.find('&', value_begin);
  return swg::MakeSuccess(std::string(path.substr(value_begin, value_end - value_begin)));
}

swg::Result<std::array<std::uint8_t, 16>> ParseHexKey16(std::string_view hex) {
  if (hex.size() != 32) {
    return swg::MakeFailure<std::array<std::uint8_t, 16>>(swg::ErrorCode::ParseError,
                                                          "rikey must be exactly 32 hex characters");
  }

  std::array<std::uint8_t, 16> key{};
  auto from_hex = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    return -1;
  };

  for (std::size_t index = 0; index < key.size(); ++index) {
    const int hi = from_hex(hex[index * 2]);
    const int lo = from_hex(hex[index * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return swg::MakeFailure<std::array<std::uint8_t, 16>>(swg::ErrorCode::ParseError,
                                                            "rikey contains non-hex characters");
    }
    key[index] = static_cast<std::uint8_t>((hi << 4) | lo);
  }

  return swg::MakeSuccess(key);
}

std::uint32_t LoadBe32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) |
         static_cast<std::uint32_t>(bytes[3]);
}

void StoreBe32(std::vector<std::uint8_t>* bytes, std::uint32_t value) {
  bytes->push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
  bytes->push_back(static_cast<std::uint8_t>(value & 0xffu));
}

swg::Result<std::vector<std::uint8_t>> EncryptRtspMessage(std::string_view plaintext,
                                                          const std::array<std::uint8_t, 16>& key,
                                                          std::uint32_t sequence_number) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  const int key_result =
      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned int>(key.size() * 8));
  if (key_result != 0) {
    mbedtls_gcm_free(&gcm);
    return swg::MakeFailure<std::vector<std::uint8_t>>(swg::ErrorCode::ParseError,
                                                       FormatTlsError("mbedtls_gcm_setkey", key_result));
  }

  std::array<std::uint8_t, 12> iv{};
  iv[0] = static_cast<std::uint8_t>(sequence_number & 0xffu);
  iv[1] = static_cast<std::uint8_t>((sequence_number >> 8) & 0xffu);
  iv[2] = static_cast<std::uint8_t>((sequence_number >> 16) & 0xffu);
  iv[3] = static_cast<std::uint8_t>((sequence_number >> 24) & 0xffu);
  iv[10] = static_cast<std::uint8_t>('C');
  iv[11] = static_cast<std::uint8_t>('R');

  std::vector<std::uint8_t> encrypted;
  encrypted.reserve(8 + 16 + plaintext.size());
  StoreBe32(&encrypted, 0x80000000u | static_cast<std::uint32_t>(plaintext.size()));
  StoreBe32(&encrypted, sequence_number);
  const std::size_t tag_offset = encrypted.size();
  encrypted.resize(tag_offset + 16 + plaintext.size());

  const int encrypt_result = mbedtls_gcm_crypt_and_tag(&gcm,
                                                       MBEDTLS_GCM_ENCRYPT,
                                                       plaintext.size(),
                                                       iv.data(),
                                                       iv.size(),
                                                       nullptr,
                                                       0,
                                                       reinterpret_cast<const unsigned char*>(plaintext.data()),
                                                       encrypted.data() + tag_offset + 16,
                                                       16,
                                                       encrypted.data() + tag_offset);
  mbedtls_gcm_free(&gcm);
  if (encrypt_result != 0) {
    return swg::MakeFailure<std::vector<std::uint8_t>>(swg::ErrorCode::ParseError,
                                                       FormatTlsError("mbedtls_gcm_crypt_and_tag", encrypt_result));
  }

  return swg::MakeSuccess(std::move(encrypted));
}

swg::Result<std::string> DecryptRtspMessage(const std::vector<std::uint8_t>& encrypted,
                                            const std::array<std::uint8_t, 16>& key) {
  if (encrypted.size() < 24) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::ParseError,
                                         "encrypted RTSP response is too short");
  }

  const std::uint32_t type_and_length = LoadBe32(encrypted.data());
  if ((type_and_length & 0x80000000u) == 0) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::ParseError,
                                         "RTSP response does not have the encrypted framing bit set");
  }

  const std::size_t payload_size = static_cast<std::size_t>(type_and_length & ~0x80000000u);
  if (encrypted.size() != 24 + payload_size) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::ParseError,
                                         "encrypted RTSP response has an unexpected length");
  }

  const std::uint32_t sequence_number = LoadBe32(encrypted.data() + 4);
  std::array<std::uint8_t, 12> iv{};
  iv[0] = static_cast<std::uint8_t>(sequence_number & 0xffu);
  iv[1] = static_cast<std::uint8_t>((sequence_number >> 8) & 0xffu);
  iv[2] = static_cast<std::uint8_t>((sequence_number >> 16) & 0xffu);
  iv[3] = static_cast<std::uint8_t>((sequence_number >> 24) & 0xffu);
  iv[10] = static_cast<std::uint8_t>('H');
  iv[11] = static_cast<std::uint8_t>('R');

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const int key_result =
      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned int>(key.size() * 8));
  if (key_result != 0) {
    mbedtls_gcm_free(&gcm);
    return swg::MakeFailure<std::string>(swg::ErrorCode::ParseError,
                                         FormatTlsError("mbedtls_gcm_setkey", key_result));
  }

  std::string plaintext(payload_size, '\0');
  const int decrypt_result = mbedtls_gcm_auth_decrypt(
      &gcm,
      payload_size,
      iv.data(),
      iv.size(),
      nullptr,
      0,
      encrypted.data() + 8,
      16,
      encrypted.data() + 24,
      reinterpret_cast<unsigned char*>(plaintext.data()));
  mbedtls_gcm_free(&gcm);
  if (decrypt_result != 0) {
    return swg::MakeFailure<std::string>(swg::ErrorCode::ParseError,
                                         FormatTlsError("mbedtls_gcm_auth_decrypt", decrypt_result));
  }

  return swg::MakeSuccess(std::move(plaintext));
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

  std::cout << "config: " << options.value.config_path << '\n';
  std::cout << "runtime_root: " << options.value.runtime_root << '\n';
  std::cout << "client_cert: " << options.value.client_cert_path << '\n';
  std::cout << "client_key: " << options.value.client_key_path << '\n';
  std::cout << "profile: " << desired_profile << '\n';
  std::cout << "host: " << options.value.host << " http_port=" << options.value.http_port
            << " https_port=" << options.value.https_port << " rtsp_port=" << options.value.rtsp_port
            << " path=" << options.value.http_path << '\n';

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
  const auto opened = session.Open(MakeCompatBridgeSessionRequest(desired_profile));
  if (!opened.ok()) {
    std::cerr << "app session open failed: " << opened.error.message << '\n';
    static_cast<void>(client.Disconnect());
    return 1;
  }

  bool all_ok = true;

  const auto rtsp_plan = session.PlanNetwork(MakeRtspPlan(options.value.host, options.value.rtsp_port));
  if (!options.value.rtsp_only) {
    const auto http_plan = session.PlanNetwork(
        MakeControlPlan(options.value.host, options.value.http_port, swg::TransportProtocol::Http));
    const auto https_plan = session.PlanNetwork(
        MakeControlPlan(options.value.host, options.value.https_port, swg::TransportProtocol::Https));
    if (http_plan.ok()) {
      PrintStep(http_plan.value.action == swg::RouteAction::Tunnel,
                "http-plan",
                std::string(swg::ToString(http_plan.value.action)) + ": " + http_plan.value.reason);
      all_ok &= http_plan.value.action == swg::RouteAction::Tunnel;
    } else {
      PrintStep(false, "http-plan", http_plan.error.message);
      all_ok = false;
    }
    if (https_plan.ok()) {
      PrintStep(https_plan.value.action == swg::RouteAction::Tunnel,
                "https-plan",
                std::string(swg::ToString(https_plan.value.action)) + ": " + https_plan.value.reason);
      all_ok &= https_plan.value.action == swg::RouteAction::Tunnel;
    } else {
      PrintStep(false, "https-plan", https_plan.error.message);
      all_ok = false;
    }
  }
  if (rtsp_plan.ok()) {
    PrintStep(rtsp_plan.value.action == swg::RouteAction::Tunnel,
              "rtsp-plan",
              std::string(swg::ToString(rtsp_plan.value.action)) + ": " + rtsp_plan.value.reason);
    all_ok &= rtsp_plan.value.action == swg::RouteAction::Tunnel;
  } else {
    PrintStep(false, "rtsp-plan", rtsp_plan.error.message);
    all_ok = false;
  }

  if (!options.value.rtsp_only) {
    const auto stream = swg::TunnelStreamSocket::Open(
        session, MakeControlStreamRequest(options.value.host, options.value.http_port, swg::TransportProtocol::Http));
    if (!stream.ok()) {
      PrintStep(false, "http-open", stream.error.message);
      all_ok = false;
    } else {
      const std::string request_text = "GET " + options.value.http_path + " HTTP/1.1\r\nHost: " +
                                       options.value.host +
                                       "\r\nConnection: close\r\nUser-Agent: swg-live-moonlight-control-probe/1\r\n\r\n";
      const auto sent = stream.value.Send(ToByteVector(request_text));
      if (!sent.ok()) {
        PrintStep(false, "http-request", sent.error.message);
        all_ok = false;
      } else {
        const auto received = PollTunnelStreamReceive(stream.value);
        if (!received.ok()) {
          PrintStep(false, "http-request", received.error.message);
          all_ok = false;
        } else {
          const std::string response = ToString(received.value.payload);
          const bool ok = response.find("HTTP/") != std::string::npos;
          PrintStep(ok,
                    "http-request",
                    FirstResponseLine(response) + " bytes=" + std::to_string(received.value.payload.size()));
          all_ok &= ok;
        }
      }
    }
  }

  const bool has_client_credentials = std::filesystem::exists(options.value.client_cert_path) &&
                                      std::filesystem::exists(options.value.client_key_path);
  const auto perform_https_request = [&](const std::string& path,
                                         std::vector<std::uint8_t>* raw_response,
                                         std::string* tls_error) -> bool {
    auto stream = swg::TunnelStreamSocket::Open(
        session, MakeControlStreamRequest(options.value.host, options.value.https_port, swg::TransportProtocol::Https));
    if (!stream.ok()) {
      if (tls_error) {
        *tls_error = stream.error.message;
      }
      return false;
    }

    if (!has_client_credentials) {
      if (tls_error) {
        *tls_error = "no client TLS credentials configured";
      }
      return false;
    }

    const std::string request_text = "GET " + path + " HTTP/1.1\r\nHost: " + options.value.host +
                                     "\r\nConnection: close\r\nUser-Agent: swg-live-moonlight-control-probe/1\r\n\r\n";
    return PerformTlsRequest(std::move(stream.value),
                             options.value.host,
                             options.value.client_cert_path,
                             options.value.client_key_path,
                             request_text,
                             raw_response,
                             tls_error);
  };
  const auto run_https_request = [&](std::string_view label, const std::string& path) {
    if (!has_client_credentials) {
      PrintStep(true, label, "tunnel stream handshake completed; no client TLS credentials configured");
      return;
    }

    std::vector<std::uint8_t> raw_response;
    std::string tls_error;
    if (!perform_https_request(path, &raw_response, &tls_error)) {
      PrintStep(false, label, tls_error);
      all_ok = false;
      return;
    }

    const std::string response = ToString(raw_response);
    const bool ok = response.find("HTTP/1.1 200") != std::string::npos ||
                    response.find("HTTP/1.0 200") != std::string::npos;
    PrintStep(ok,
              label,
              FirstResponseLine(response) + " bytes=" + std::to_string(raw_response.size()));
    all_ok &= ok;
  };

  if (!options.value.rtsp_only) {
    run_https_request("https-serverinfo", options.value.https_serverinfo_path);
    run_https_request("https-applist", options.value.https_applist_path);
  }

  {
    std::string rtsp_target = options.value.rtsp_target.empty()
                                  ? "rtsp://" + options.value.host + ":" + std::to_string(options.value.rtsp_port)
                                  : options.value.rtsp_target;
    if (options.value.rtsp_via_resume) {
      if (!has_client_credentials) {
        PrintStep(false, "https-resume", "client TLS credentials are required for tunneled /resume");
        all_ok = false;
      } else {
        std::vector<std::uint8_t> raw_response;
        std::string tls_error;
        if (!perform_https_request(options.value.https_resume_path, &raw_response, &tls_error)) {
          PrintStep(false, "https-resume", tls_error);
          all_ok = false;
        } else {
          const std::string response = ToString(raw_response);
          const bool ok = response.find("HTTP/1.1 200") != std::string::npos ||
                          response.find("HTTP/1.0 200") != std::string::npos;
          if (!ok) {
            PrintStep(false, "https-resume", FirstResponseLine(response));
            all_ok = false;
          } else {
            const auto session_url = ExtractXmlTag(response, "sessionUrl0");
            if (!session_url.ok()) {
              PrintStep(false, "https-resume", session_url.error.message);
              all_ok = false;
            } else {
              rtsp_target = session_url.value;
              PrintStep(true,
                        "https-resume",
                        FirstResponseLine(response) + " sessionUrl0=" + session_url.value);
            }
          }
        }
      }
    }

    const std::string request_text = "OPTIONS " + rtsp_target +
                                     " RTSP/1.0\r\nCSeq: 1\r\nX-GS-ClientVersion: 14\r\nHost: " +
                                     options.value.host + "\r\n\r\n";
    const bool encrypted_rtsp = rtsp_target.rfind("rtspenc://", 0) == 0;
    std::array<std::uint8_t, 16> encrypted_rtsp_key{};
    if (encrypted_rtsp) {
      const auto rikey = ExtractQueryParameter(options.value.https_resume_path, "rikey");
      if (!rikey.ok()) {
        PrintStep(false, "rtsp-options", rikey.error.message);
        all_ok = false;
      } else {
        const auto parsed_key = ParseHexKey16(rikey.value);
        if (!parsed_key.ok()) {
          PrintStep(false, "rtsp-options", parsed_key.error.message);
          all_ok = false;
        } else {
          encrypted_rtsp_key = parsed_key.value;
        }
      }
    }

    const auto stream = swg::TunnelStreamSocket::Open(session,
                                                      MakeRtspStreamRequest(options.value.host,
                                                                            options.value.rtsp_port));
    if (!stream.ok()) {
      PrintStep(false, "rtsp-options", stream.error.message);
      all_ok = false;
    } else {
      swg::Result<std::uint64_t> sent = swg::MakeFailure<std::uint64_t>(swg::ErrorCode::ParseError,
                                                                        "encrypted RTSP request was not prepared");
      if (encrypted_rtsp) {
        const auto encrypted_request = EncryptRtspMessage(request_text, encrypted_rtsp_key, 1);
        if (!encrypted_request.ok()) {
          PrintStep(false, "rtsp-options", encrypted_request.error.message);
          all_ok = false;
        } else {
          sent = stream.value.Send(encrypted_request.value);
        }
      } else {
        sent = stream.value.Send(ToByteVector(request_text));
      }
      if (!sent.ok()) {
        PrintStep(false, "rtsp-options", sent.error.message);
        all_ok = false;
      } else {
        const auto received = PollTunnelStreamReceive(stream.value);
        if (!received.ok()) {
          PrintStep(false, "rtsp-options", received.error.message);
          all_ok = false;
        } else {
          std::string response;
          if (encrypted_rtsp) {
            const auto decrypted = DecryptRtspMessage(received.value.payload, encrypted_rtsp_key);
            if (!decrypted.ok()) {
              PrintStep(false, "rtsp-options", decrypted.error.message);
              all_ok = false;
              response.clear();
            } else {
              response = decrypted.value;
            }
          } else {
            response = ToString(received.value.payload);
          }
          if (response.empty()) {
            if (!encrypted_rtsp) {
              PrintStep(false, "rtsp-options", "empty RTSP response payload");
              all_ok = false;
            }
          } else {
            const bool ok = response.find("RTSP/1.0 200") != std::string::npos;
            PrintStep(ok,
                      "rtsp-options",
                      FirstResponseLine(response) + " bytes=" + std::to_string(received.value.payload.size()) +
                          (encrypted_rtsp ? " enc=true" : " enc=false"));
            all_ok &= ok;
          }
        }
      }
    }
  }

  const auto stats = client.GetStats();
  if (stats.ok()) {
    std::cout << "final stats: " << DescribeStats(stats.value) << '\n';
  }
  std::cout << "log file: " << (options.value.runtime_root / "logs/swg/swg.log") << '\n';

  static_cast<void>(session.Close());
  static_cast<void>(client.Disconnect());
  return all_ok ? 0 : 1;
}