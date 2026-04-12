#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "swg/client.h"
#include "swg/config.h"
#include "swg/ipc_protocol.h"
#include "swg/wg_handshake.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/host_transport.h"

namespace {

constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kHexAlphabet[] = "0123456789abcdef";
constexpr std::size_t kInitiationSenderIndexOffset = 4;
constexpr std::size_t kInitiationEphemeralOffset = 8;
constexpr std::size_t kInitiationEncryptedStaticOffset = 40;
constexpr std::size_t kInitiationEncryptedStaticSize = 48;
constexpr std::size_t kInitiationEncryptedTimestampOffset = 88;
constexpr std::size_t kInitiationEncryptedTimestampSize = 28;
constexpr std::size_t kInitiationMac1Offset = 116;
constexpr std::size_t kInitiationMacSize = 16;

struct ProbeOptions {
  std::filesystem::path config_path;
  std::filesystem::path runtime_root;
  std::string profile_override;
  std::filesystem::path dump_initiation_path;
  std::filesystem::path compare_initiation_path;
  bool connect = true;
};

struct FieldRange {
  const char* name;
  std::size_t offset;
  std::size_t size;
};

constexpr std::array<FieldRange, 6> kInitiationFields = {{
    {"header", 0, 4},
    {"sender_index", kInitiationSenderIndexOffset, 4},
    {"ephemeral_public", kInitiationEphemeralOffset, swg::kWireGuardKeySize},
    {"encrypted_static", kInitiationEncryptedStaticOffset, kInitiationEncryptedStaticSize},
    {"encrypted_timestamp", kInitiationEncryptedTimestampOffset, kInitiationEncryptedTimestampSize},
    {"mac1", kInitiationMac1Offset, kInitiationMacSize},
}};

std::string EncodeBase64(const swg::WireGuardKey& key) {
  std::string output;
  output.reserve(((key.bytes.size() + 2) / 3) * 4);

  for (std::size_t index = 0; index < key.bytes.size(); index += 3) {
    const std::uint32_t a = key.bytes[index];
    const std::uint32_t b = index + 1 < key.bytes.size() ? key.bytes[index + 1] : 0;
    const std::uint32_t c = index + 2 < key.bytes.size() ? key.bytes[index + 2] : 0;
    const std::uint32_t chunk = (a << 16) | (b << 8) | c;

    output.push_back(kBase64Alphabet[(chunk >> 18) & 0x3F]);
    output.push_back(kBase64Alphabet[(chunk >> 12) & 0x3F]);
    output.push_back(index + 1 < key.bytes.size() ? kBase64Alphabet[(chunk >> 6) & 0x3F] : '=');
    output.push_back(index + 2 < key.bytes.size() ? kBase64Alphabet[chunk & 0x3F] : '=');
  }

  return output;
}

std::string DescribeStats(const swg::TunnelStats& stats) {
  return "connect_attempts=" + std::to_string(stats.connect_attempts) +
         ", successful_handshakes=" + std::to_string(stats.successful_handshakes) +
         ", bytes_in=" + std::to_string(stats.bytes_in) + ", bytes_out=" + std::to_string(stats.bytes_out) +
         ", packets_in=" + std::to_string(stats.packets_in) + ", packets_out=" + std::to_string(stats.packets_out);
}

std::string EncodeHex(const std::uint8_t* data, std::size_t size) {
  std::string output;
  output.reserve(size * 2);
  for (std::size_t index = 0; index < size; ++index) {
    const std::uint8_t value = data[index];
    output.push_back(kHexAlphabet[(value >> 4) & 0x0F]);
    output.push_back(kHexAlphabet[value & 0x0F]);
  }
  return output;
}

template <std::size_t N>
std::string EncodeHex(const std::array<std::uint8_t, N>& bytes) {
  return EncodeHex(bytes.data(), bytes.size());
}

int ParseHexNibble(char ch) {
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
}

swg::Result<std::vector<std::uint8_t>> ParseHexBytes(std::string_view encoded) {
  std::string compact;
  compact.reserve(encoded.size());
  for (char ch : encoded) {
    if (std::isspace(static_cast<unsigned char>(ch)) == 0) {
      compact.push_back(ch);
    }
  }

  if (compact.empty()) {
    return swg::MakeFailure<std::vector<std::uint8_t>>(swg::ErrorCode::ParseError, "hex dump file is empty");
  }
  if ((compact.size() % 2) != 0) {
    return swg::MakeFailure<std::vector<std::uint8_t>>(swg::ErrorCode::ParseError,
                                                       "hex dump must contain an even number of digits");
  }

  std::vector<std::uint8_t> bytes;
  bytes.reserve(compact.size() / 2);
  for (std::size_t index = 0; index < compact.size(); index += 2) {
    const int high = ParseHexNibble(compact[index]);
    const int low = ParseHexNibble(compact[index + 1]);
    if (high < 0 || low < 0) {
      return swg::MakeFailure<std::vector<std::uint8_t>>(swg::ErrorCode::ParseError,
                                                         "hex dump contains a non-hex character");
    }
    bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }

  return swg::MakeSuccess(std::move(bytes));
}

swg::Result<std::vector<std::uint8_t>> ReadPacketDumpFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return swg::MakeFailure<std::vector<std::uint8_t>>(swg::ErrorCode::NotFound,
                                                       "failed to open packet dump file: " + path.string());
  }

  const std::vector<std::uint8_t> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (raw.size() == swg::kWireGuardHandshakeInitiationSize) {
    return swg::MakeSuccess(raw);
  }

  const std::string as_text(raw.begin(), raw.end());
  return ParseHexBytes(as_text);
}

swg::Error WriteHexDumpFile(const std::filesystem::path& path, const std::uint8_t* data, std::size_t size) {
  std::error_code filesystem_error;
  std::filesystem::create_directories(path.parent_path(), filesystem_error);
  if (filesystem_error) {
    return swg::MakeError(swg::ErrorCode::IoError,
                          "failed to create dump directory: " + filesystem_error.message());
  }

  std::ofstream output(path, std::ios::trunc);
  if (!output.is_open()) {
    return swg::MakeError(swg::ErrorCode::IoError, "failed to open dump file for write: " + path.string());
  }

  output << EncodeHex(data, size) << '\n';
  if (!output.good()) {
    return swg::MakeError(swg::ErrorCode::IoError, "failed while writing dump file: " + path.string());
  }

  return swg::Error::None();
}

swg::WireGuardHandshakeInitiationOptions MakeDeterministicInitiationOptions() {
  swg::WireGuardHandshakeInitiationOptions options{};

  swg::WireGuardKey ephemeral_private_key{};
  for (std::size_t index = 0; index < ephemeral_private_key.bytes.size(); ++index) {
    ephemeral_private_key.bytes[index] = static_cast<std::uint8_t>(index + 1);
  }

  options.ephemeral_private_key = ephemeral_private_key;
  options.sender_index = 0x11223344u;
  options.timestamp = std::array<std::uint8_t, 12>{0x40, 0x00, 0x00, 0x00, 0x65, 0x00,
                                                   0x00, 0x00, 0x11, 0x22, 0x33, 0x44};
  return options;
}

swg::WireGuardHandshakeConfig MakeHandshakeConfig(const swg::ValidatedWireGuardProfile& profile) {
  swg::WireGuardHandshakeConfig config{};
  config.local_private_key = profile.private_key;
  config.local_public_key = profile.local_public_key;
  config.peer_public_key = profile.public_key;
  config.preshared_key = profile.preshared_key;
  config.has_preshared_key = profile.has_preshared_key;
  return config;
}

void PrintInitiationSummary(const swg::WireGuardHandshakeInitiation& initiation) {
  std::cout << "deterministic_dump.sender_index: 0x" << std::hex << initiation.state.sender_index << std::dec
            << '\n';
  std::cout << "deterministic_dump.ephemeral_private_key: "
            << EncodeHex(initiation.state.ephemeral_private_key.bytes.data(),
                         initiation.state.ephemeral_private_key.bytes.size())
            << '\n';
  std::cout << "deterministic_dump.ephemeral_public_key: "
            << EncodeBase64(initiation.state.ephemeral_public_key) << '\n';
  for (const FieldRange& field : kInitiationFields) {
    std::cout << "deterministic_dump." << field.name << ": "
              << EncodeHex(initiation.packet.data() + static_cast<std::ptrdiff_t>(field.offset), field.size) << '\n';
  }
  std::cout << "deterministic_dump.packet_hex: " << EncodeHex(initiation.packet) << '\n';
}

void ComparePacketRange(const std::uint8_t* generated, const std::uint8_t* reference, const FieldRange& field) {
  std::size_t differences = 0;
  std::size_t first_difference = field.size;
  for (std::size_t offset = 0; offset < field.size; ++offset) {
    if (generated[field.offset + offset] != reference[field.offset + offset]) {
      if (first_difference == field.size) {
        first_difference = offset;
      }
      ++differences;
    }
  }

  std::cout << "comparison." << field.name << ": ";
  if (differences == 0) {
    std::cout << "match" << '\n';
    return;
  }

  std::cout << "differs (bytes=" << differences << ", first_offset=" << (field.offset + first_difference) << ")"
            << '\n';
}

void CompareInitiationPackets(const swg::WireGuardHandshakeInitiation& generated,
                              const std::vector<std::uint8_t>& reference) {
  std::cout << "comparison.note: exact byte equality only makes sense when both generators use the same sender index,\n"
               "comparison.note: ephemeral private key, and timestamp overrides. This probe fixes those values for the generated packet."
            << '\n';

  if (reference.size() != generated.packet.size()) {
    std::cout << "comparison.packet_size: mismatch (generated=" << generated.packet.size()
              << ", reference=" << reference.size() << ")" << '\n';
    return;
  }

  std::size_t differences = 0;
  std::size_t first_difference = generated.packet.size();
  for (std::size_t index = 0; index < generated.packet.size(); ++index) {
    if (generated.packet[index] != reference[index]) {
      if (first_difference == generated.packet.size()) {
        first_difference = index;
      }
      ++differences;
    }
  }

  if (differences == 0) {
    std::cout << "comparison.packet: exact match" << '\n';
  } else {
    std::cout << "comparison.packet: differs (bytes=" << differences << ", first_offset=" << first_difference
              << ")" << '\n';
  }

  for (const FieldRange& field : kInitiationFields) {
    ComparePacketRange(generated.packet.data(), reference.data(), field);
  }
}

void PrintUsage(const char* argv0) {
  std::cerr << "usage: " << argv0
        << " [--config PATH] [--profile NAME] [--runtime-root PATH] [--dump-initiation PATH]"
          " [--compare-initiation PATH] [--no-connect]\n"
            << "  --config defaults to "
#if defined(SWG_SOURCE_DIR)
            << SWG_SOURCE_DIR << "/docs/config.ini"
#else
            << "./docs/config.ini"
#endif
        << "\n"
        << "  --dump-initiation writes a deterministic initiation packet as hex\n"
        << "  --compare-initiation compares that deterministic packet with a reference raw or hex dump\n"
        << "  --no-connect skips the live UDP handshake and runs diagnostics only"
            << "\n";
}

swg::Result<ProbeOptions> ParseOptions(int argc, char** argv) {
  ProbeOptions options{};
#if defined(SWG_SOURCE_DIR)
  options.config_path = std::filesystem::path(SWG_SOURCE_DIR) / "docs" / "config.ini";
#else
  options.config_path = std::filesystem::current_path() / "docs" / "config.ini";
#endif
  options.runtime_root = std::filesystem::current_path() / "test-runtime-live-handshake";

  for (int index = 1; index < argc; ++index) {
    const std::string_view current(argv[index]);
    if (current == "--help" || current == "-h") {
      PrintUsage(argv[0]);
      return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::InvalidConfig, "help requested");
    }

    if (current == "--no-connect") {
      options.connect = false;
      continue;
    }

    if (index + 1 >= argc) {
      return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::InvalidConfig,
                                            "missing value for argument " + std::string(current));
    }

    if (current == "--config") {
      options.config_path = argv[++index];
      continue;
    }

    if (current == "--profile") {
      options.profile_override = argv[++index];
      continue;
    }

    if (current == "--runtime-root") {
      options.runtime_root = argv[++index];
      continue;
    }

    if (current == "--dump-initiation") {
      options.dump_initiation_path = argv[++index];
      continue;
    }

    if (current == "--compare-initiation") {
      options.compare_initiation_path = argv[++index];
      continue;
    }

    return swg::MakeFailure<ProbeOptions>(swg::ErrorCode::InvalidConfig,
                                          "unknown argument " + std::string(current));
  }

  return swg::MakeSuccess(std::move(options));
}

swg::Config NormalizeConfig(swg::Config config, const std::string& profile_override) {
  if (!profile_override.empty()) {
    config.active_profile = profile_override;
  }

  if (config.active_profile.empty() && config.profiles.size() == 1) {
    config.active_profile = config.profiles.begin()->first;
  }

  return config;
}

int RunProbe(const ProbeOptions& options) {
  const std::filesystem::path config_path = std::filesystem::absolute(options.config_path);
  const std::filesystem::path runtime_root = std::filesystem::absolute(options.runtime_root);
  const swg::RuntimePaths runtime_paths = swg::DetectRuntimePaths(runtime_root);

  const swg::Result<swg::Config> loaded = swg::LoadConfigFile(config_path);
  if (!loaded.ok()) {
    std::cerr << "failed to load config: " << loaded.error.message << '\n';
    return 1;
  }

  const swg::Config config = NormalizeConfig(loaded.value, options.profile_override);
  const swg::Error config_error = swg::ValidateConfig(config);
  if (config_error) {
    std::cerr << "config validation failed: " << config_error.message << '\n';
    return 1;
  }

  const auto profile_it = config.profiles.find(config.active_profile);
  if (profile_it == config.profiles.end()) {
    std::cerr << "active profile not found after normalization: " << config.active_profile << '\n';
    return 1;
  }

  const swg::Result<swg::ValidatedWireGuardProfile> validated =
      swg::ValidateWireGuardProfileForConnect(profile_it->second);
  if (!validated.ok()) {
    std::cerr << "WireGuard preflight failed: " << validated.error.message << '\n';
    return 1;
  }

  std::error_code filesystem_error;
  std::filesystem::remove_all(runtime_root, filesystem_error);
  if (filesystem_error) {
    std::cerr << "warning: failed to clear runtime root " << runtime_root << ": "
              << filesystem_error.message() << '\n';
  }

  std::cout << "loaded config: " << swg::DescribeConfig(config) << '\n';
  std::cout << "config path: " << config_path << '\n';
  std::cout << "runtime root: " << runtime_root << '\n';
  std::cout << "active profile: " << config.active_profile << '\n';
  std::cout << "endpoint: " << profile_it->second.endpoint_host << ':' << profile_it->second.endpoint_port << '\n';
  std::cout << "local_public_key: " << EncodeBase64(validated.value.local_public_key) << '\n';
  std::cout << "peer_public_key: " << EncodeBase64(validated.value.public_key) << '\n';
  std::cout << "preshared_key: " << (validated.value.has_preshared_key ? "enabled" : "disabled") << '\n';

  if (!options.dump_initiation_path.empty() || !options.compare_initiation_path.empty()) {
    const auto deterministic = swg::CreateHandshakeInitiation(MakeHandshakeConfig(validated.value),
                                                              MakeDeterministicInitiationOptions());
    if (!deterministic.ok()) {
      std::cerr << "failed to build deterministic initiation dump: " << deterministic.error.message << '\n';
      return 1;
    }

    PrintInitiationSummary(deterministic.value);

    if (!options.dump_initiation_path.empty()) {
      const std::filesystem::path dump_path = std::filesystem::absolute(options.dump_initiation_path);
      const swg::Error dump_error =
          WriteHexDumpFile(dump_path, deterministic.value.packet.data(), deterministic.value.packet.size());
      if (dump_error) {
        std::cerr << "failed to write initiation dump: " << dump_error.message << '\n';
        return 1;
      }
      std::cout << "deterministic_dump.file: " << dump_path << '\n';
    }

    if (!options.compare_initiation_path.empty()) {
      const std::filesystem::path compare_path = std::filesystem::absolute(options.compare_initiation_path);
      const auto reference = ReadPacketDumpFile(compare_path);
      if (!reference.ok()) {
        std::cerr << "failed to read reference initiation dump: " << reference.error.message << '\n';
        return 1;
      }
      std::cout << "comparison.reference_file: " << compare_path << '\n';
      CompareInitiationPackets(deterministic.value, reference.value);
    }
  }

  if (!options.connect) {
    return 0;
  }

  swg::Client client(swg::sysmodule::CreateLocalControlTransport(runtime_root));
  const swg::Error save_error = client.SaveConfig(config);
  if (save_error) {
    std::cerr << "failed to save config into host runtime: " << save_error.message << '\n';
    std::cerr << "log file: " << runtime_paths.log_file << '\n';
    return 1;
  }

  const swg::Error connect_error = client.Connect();
  const auto status = client.GetStatus();
  const auto stats = client.GetStats();

  if (!connect_error.ok()) {
    std::cerr << "live host handshake failed: " << connect_error.message << '\n';
    if (status.ok()) {
      std::cerr << "service state: " << swg::ToString(status.value.state) << '\n';
      if (!status.value.last_error.empty()) {
        std::cerr << "service last_error: " << status.value.last_error << '\n';
      }
    }
    if (stats.ok()) {
      std::cerr << "stats: " << DescribeStats(stats.value) << '\n';
    }
    std::cerr << "log file: " << runtime_paths.log_file << '\n';
    return 1;
  }

  std::cout << "live host handshake succeeded" << '\n';
  if (status.ok()) {
    std::cout << "service state: " << swg::ToString(status.value.state) << '\n';
  }
  if (stats.ok()) {
    std::cout << "stats: " << DescribeStats(stats.value) << '\n';
  }
  std::cout << "log file: " << runtime_paths.log_file << '\n';

  const swg::Error disconnect_error = client.Disconnect();
  if (disconnect_error) {
    std::cerr << "warning: disconnect failed after successful handshake: " << disconnect_error.message << '\n';
  }

  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const auto options = ParseOptions(argc, argv);
  if (!options.ok()) {
    if (options.error.message != "help requested") {
      std::cerr << options.error.message << '\n';
      PrintUsage(argv[0]);
      return 1;
    }
    return 0;
  }

  return RunProbe(options.value);
}