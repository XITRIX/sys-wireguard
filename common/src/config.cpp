#include "swg/config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace swg {
namespace {

std::string Trim(std::string_view input) {
  std::size_t begin = 0;
  std::size_t end = input.size();

  while (begin < end && std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
    ++begin;
  }

  while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
    --end;
  }

  return std::string(input.substr(begin, end - begin));
}

std::vector<std::string> SplitCsv(std::string_view input) {
  std::vector<std::string> parts;
  std::stringstream stream{std::string(input)};
  std::string item;

  while (std::getline(stream, item, ',')) {
    const std::string trimmed = Trim(item);
    if (!trimmed.empty()) {
      parts.push_back(trimmed);
    }
  }

  return parts;
}

std::string JoinCsv(const std::vector<std::string>& values) {
  std::ostringstream stream;

  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      stream << ", ";
    }
    stream << values[index];
  }

  return stream.str();
}

Result<bool> ParseBool(std::string_view input) {
  const std::string value = Trim(input);

  if (value == "true" || value == "1" || value == "yes" || value == "on") {
    return MakeSuccess(true);
  }

  if (value == "false" || value == "0" || value == "no" || value == "off") {
    return MakeSuccess(false);
  }

  return MakeFailure<bool>(ErrorCode::ParseError, "invalid boolean value: " + value);
}

Result<std::uint16_t> ParseU16(std::string_view input) {
  const std::string value = Trim(input);

  try {
    const unsigned long parsed = std::stoul(value);
    if (parsed > 65535UL) {
      return MakeFailure<std::uint16_t>(ErrorCode::ParseError, "value out of range: " + value);
    }
    return MakeSuccess(static_cast<std::uint16_t>(parsed));
  } catch (const std::exception&) {
    return MakeFailure<std::uint16_t>(ErrorCode::ParseError, "invalid integer value: " + value);
  }
}

RuntimeFlags ParseRuntimeFlags(std::string_view input) {
  RuntimeFlags flags = 0;

  for (const std::string& token : SplitCsv(input)) {
    if (token == "transparent_mode") {
      flags |= ToFlags(RuntimeFlag::TransparentMode);
    } else if (token == "dns_through_tunnel") {
      flags |= ToFlags(RuntimeFlag::DnsThroughTunnel);
    } else if (token == "kill_switch") {
      flags |= ToFlags(RuntimeFlag::KillSwitch);
    }
  }

  return flags;
}

Error AssignProfileValue(ProfileConfig& profile, const std::string& key, const std::string& value) {
  if (key == "private_key") {
    profile.private_key = value;
    return Error::None();
  }

  if (key == "public_key") {
    profile.public_key = value;
    return Error::None();
  }

  if (key == "preshared_key") {
    profile.preshared_key = value;
    return Error::None();
  }

  if (key == "endpoint_host") {
    profile.endpoint_host = value;
    return Error::None();
  }

  if (key == "endpoint_port") {
    const Result<std::uint16_t> parsed = ParseU16(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    profile.endpoint_port = parsed.value;
    return Error::None();
  }

  if (key == "allowed_ips") {
    profile.allowed_ips = SplitCsv(value);
    return Error::None();
  }

  if (key == "address") {
    profile.addresses = SplitCsv(value);
    return Error::None();
  }

  if (key == "dns") {
    profile.dns_servers = SplitCsv(value);
    return Error::None();
  }

  if (key == "persistent_keepalive") {
    const Result<std::uint16_t> parsed = ParseU16(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    profile.persistent_keepalive = parsed.value;
    return Error::None();
  }

  if (key == "autostart") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    profile.autostart = parsed.value;
    return Error::None();
  }

  if (key == "transparent_mode") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    profile.transparent_mode = parsed.value;
    return Error::None();
  }

  if (key == "kill_switch") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    profile.kill_switch = parsed.value;
    return Error::None();
  }

  return MakeError(ErrorCode::ParseError, "unknown profile key: " + key);
}

Error AssignAppPolicyValue(AppPolicyConfig& policy, const std::string& key, const std::string& value) {
  if (key == "client_name") {
    policy.client_name = value;
    return Error::None();
  }

  if (key == "integration_tag") {
    policy.integration_tag = value;
    return Error::None();
  }

  if (key == "desired_profile") {
    policy.desired_profile = value;
    return Error::None();
  }

  if (key == "requested_flags") {
    policy.requested_flags = ParseRuntimeFlags(value);
    return Error::None();
  }

  if (key == "allow_local_network_bypass") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    policy.allow_local_network_bypass = parsed.value;
    return Error::None();
  }

  if (key == "require_tunnel_for_default_traffic") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    policy.require_tunnel_for_default_traffic = parsed.value;
    return Error::None();
  }

  if (key == "prefer_tunnel_dns") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    policy.prefer_tunnel_dns = parsed.value;
    return Error::None();
  }

  if (key == "allow_direct_internet_fallback") {
    const Result<bool> parsed = ParseBool(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    policy.allow_direct_internet_fallback = parsed.value;
    return Error::None();
  }

  return MakeError(ErrorCode::ParseError, "unknown app policy key: " + key);
}

Error AssignIntegrationTestValue(IntegrationTestConfig& config,
                                 const std::string& key,
                                 const std::string& value) {
  if (key == "target_host") {
    config.target_host = value;
    return Error::None();
  }

  if (key == "dns_hostname") {
    config.dns_hostname = value;
    return Error::None();
  }

  if (key == "tcp_echo_port") {
    const Result<std::uint16_t> parsed = ParseU16(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    config.tcp_echo_port = parsed.value;
    return Error::None();
  }

  if (key == "http_port") {
    const Result<std::uint16_t> parsed = ParseU16(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    config.http_port = parsed.value;
    return Error::None();
  }

  if (key == "udp_echo_port") {
    const Result<std::uint16_t> parsed = ParseU16(value);
    if (!parsed.ok()) {
      return parsed.error;
    }
    config.udp_echo_port = parsed.value;
    return Error::None();
  }

  if (key == "http_path") {
    config.http_path = value;
    return Error::None();
  }

  return MakeError(ErrorCode::ParseError, "unknown integration test key: " + key);
}

bool HasCompleteKeyMaterial(const ProfileConfig& profile) {
  return !profile.private_key.empty() && !profile.public_key.empty() && !profile.endpoint_host.empty() &&
         !profile.allowed_ips.empty() && !profile.addresses.empty();
}

}  // namespace

Config DefaultConfig() {
  Config config{};
  AppPolicyConfig default_policy{};
  default_policy.name = "default";
  default_policy.allow_local_network_bypass = false;
  default_policy.require_tunnel_for_default_traffic = true;
  default_policy.prefer_tunnel_dns = true;
  default_policy.allow_direct_internet_fallback = false;
  config.app_policies.emplace(default_policy.name, default_policy);
  return config;
}

RuntimePaths DetectRuntimePaths(const std::filesystem::path& root_override) {
  RuntimePaths paths{};

#if defined(SWG_PLATFORM_SWITCH)
  (void)root_override;
  paths.root_dir = "sdmc:/";
  paths.config_dir = "sdmc:/config/swg";
  paths.log_dir = "sdmc:/atmosphere/logs/swg";
#else
  paths.root_dir = root_override.empty() ? (std::filesystem::current_path() / "runtime") : root_override;
  paths.config_dir = paths.root_dir / "config" / "swg";
  paths.log_dir = paths.root_dir / "logs" / "swg";
#endif

  paths.config_file = paths.config_dir / "config.ini";
  paths.log_file = paths.log_dir / "swg.log";
  return paths;
}

Result<Config> LoadConfigFile(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input.is_open()) {
    return MakeFailure<Config>(ErrorCode::NotFound, "config file not found: " + path.string());
  }

  Config config = DefaultConfig();
  std::string line;
  std::string current_section;
  std::string current_profile_name;
  std::string current_policy_name;
  std::size_t line_number = 0;

  while (std::getline(input, line)) {
    ++line_number;
    const std::string trimmed = Trim(line);

    if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == ';') {
      continue;
    }

    if (trimmed.front() == '[' && trimmed.back() == ']') {
      const std::string section = trimmed.substr(1, trimmed.size() - 2);

      if (section == "runtime") {
        current_section = "runtime";
        current_profile_name.clear();
        current_policy_name.clear();
        continue;
      }

      if (section.rfind("profile.", 0) == 0 && section.size() > 8) {
        current_section = "profile";
        current_profile_name = section.substr(8);
        current_policy_name.clear();
        ProfileConfig& profile = config.profiles[current_profile_name];
        profile.name = current_profile_name;
        continue;
      }

      if (section.rfind("app_policy.", 0) == 0 && section.size() > 11) {
        current_section = "app_policy";
        current_profile_name.clear();
        current_policy_name = section.substr(11);
        AppPolicyConfig& policy = config.app_policies[current_policy_name];
        policy.name = current_policy_name;
        continue;
      }

      if (section == "integration_test") {
        current_section = "integration_test";
        current_profile_name.clear();
        current_policy_name.clear();
        continue;
      }

      return MakeFailure<Config>(ErrorCode::ParseError,
                                 "unknown section at line " + std::to_string(line_number) + ": " + section);
    }

    const std::size_t separator = trimmed.find('=');
    if (separator == std::string::npos) {
      return MakeFailure<Config>(ErrorCode::ParseError,
                                 "expected key=value at line " + std::to_string(line_number));
    }

    const std::string key = Trim(trimmed.substr(0, separator));
    const std::string value = Trim(trimmed.substr(separator + 1));

    if (current_section == "runtime") {
      if (key == "active_profile") {
        config.active_profile = value;
      } else if (key == "runtime_flags") {
        config.runtime_flags = ParseRuntimeFlags(value);
      } else {
        return MakeFailure<Config>(ErrorCode::ParseError,
                                   "unknown runtime key at line " + std::to_string(line_number) + ": " + key);
      }
      continue;
    }

    if (current_section == "profile") {
      ProfileConfig& profile = config.profiles[current_profile_name];
      profile.name = current_profile_name;
      const Error assign_error = AssignProfileValue(profile, key, value);
      if (assign_error) {
        return MakeFailure<Config>(assign_error.code,
                                   assign_error.message + " at line " + std::to_string(line_number));
      }
      continue;
    }

    if (current_section == "app_policy") {
      AppPolicyConfig& policy = config.app_policies[current_policy_name];
      policy.name = current_policy_name;
      const Error assign_error = AssignAppPolicyValue(policy, key, value);
      if (assign_error) {
        return MakeFailure<Config>(assign_error.code,
                                   assign_error.message + " at line " + std::to_string(line_number));
      }
      continue;
    }

    if (current_section == "integration_test") {
      const Error assign_error = AssignIntegrationTestValue(config.integration_test, key, value);
      if (assign_error) {
        return MakeFailure<Config>(assign_error.code,
                                   assign_error.message + " at line " + std::to_string(line_number));
      }
      continue;
    }

    return MakeFailure<Config>(ErrorCode::ParseError,
                               "key encountered before section at line " + std::to_string(line_number));
  }

  const Error validation_error = ValidateConfig(config);
  if (validation_error) {
    return Result<Config>::Failure(validation_error);
  }

  return MakeSuccess(std::move(config));
}

Result<Config> LoadOrCreateConfigFile(const std::filesystem::path& path) {
  const Result<Config> loaded = LoadConfigFile(path);
  if (loaded.ok()) {
    return loaded;
  }

  if (loaded.error.code != ErrorCode::NotFound) {
    return loaded;
  }

  Config config = DefaultConfig();
  const Error save_error = SaveConfigFile(config, path);
  if (save_error) {
    return Result<Config>::Failure(save_error);
  }

  return MakeSuccess(std::move(config));
}

Error SaveConfigFile(const Config& config, const std::filesystem::path& path) {
  const Error validation_error = ValidateConfig(config);
  if (validation_error) {
    return validation_error;
  }

  std::error_code filesystem_error;
  std::filesystem::create_directories(path.parent_path(), filesystem_error);
  if (filesystem_error) {
    return MakeError(ErrorCode::IoError,
                     "failed to create config directory: " + filesystem_error.message());
  }

  std::ofstream output(path, std::ios::trunc);
  if (!output.is_open()) {
    return MakeError(ErrorCode::IoError, "failed to open config file for write: " + path.string());
  }

  output << "; Switch WireGuard Phase A configuration\n";
  output << "[runtime]\n";
  output << "active_profile = " << config.active_profile << "\n";
  output << "runtime_flags = " << RuntimeFlagsToString(config.runtime_flags) << "\n\n";

  output << "[integration_test]\n";
  output << "target_host = " << config.integration_test.target_host << "\n";
  output << "dns_hostname = " << config.integration_test.dns_hostname << "\n";
  output << "tcp_echo_port = " << config.integration_test.tcp_echo_port << "\n";
  output << "http_port = " << config.integration_test.http_port << "\n";
  output << "udp_echo_port = " << config.integration_test.udp_echo_port << "\n";
  output << "http_path = " << config.integration_test.http_path << "\n\n";

  for (const auto& [name, policy] : config.app_policies) {
    output << "[app_policy." << name << "]\n";
    output << "client_name = " << policy.client_name << "\n";
    output << "integration_tag = " << policy.integration_tag << "\n";
    output << "desired_profile = " << policy.desired_profile << "\n";
    output << "requested_flags = " << RuntimeFlagsToString(policy.requested_flags) << "\n";
    output << "allow_local_network_bypass = " << (policy.allow_local_network_bypass ? "true" : "false")
           << "\n";
    output << "require_tunnel_for_default_traffic = "
           << (policy.require_tunnel_for_default_traffic ? "true" : "false") << "\n";
    output << "prefer_tunnel_dns = " << (policy.prefer_tunnel_dns ? "true" : "false") << "\n";
    output << "allow_direct_internet_fallback = "
           << (policy.allow_direct_internet_fallback ? "true" : "false") << "\n\n";
  }

  for (const auto& [name, profile] : config.profiles) {
    output << "[profile." << name << "]\n";
    output << "private_key = " << profile.private_key << "\n";
    output << "public_key = " << profile.public_key << "\n";
    output << "preshared_key = " << profile.preshared_key << "\n";
    output << "endpoint_host = " << profile.endpoint_host << "\n";
    output << "endpoint_port = " << profile.endpoint_port << "\n";
    output << "allowed_ips = " << JoinCsv(profile.allowed_ips) << "\n";
    output << "address = " << JoinCsv(profile.addresses) << "\n";
    output << "dns = " << JoinCsv(profile.dns_servers) << "\n";
    output << "persistent_keepalive = " << profile.persistent_keepalive << "\n";
    output << "autostart = " << (profile.autostart ? "true" : "false") << "\n";
    output << "transparent_mode = " << (profile.transparent_mode ? "true" : "false") << "\n";
    output << "kill_switch = " << (profile.kill_switch ? "true" : "false") << "\n\n";
  }

  if (!output.good()) {
    return MakeError(ErrorCode::IoError, "failed while writing config file: " + path.string());
  }

  return Error::None();
}

Error ValidateConfig(const Config& config) {
  if (!config.active_profile.empty() && config.profiles.find(config.active_profile) == config.profiles.end()) {
    return MakeError(ErrorCode::InvalidConfig,
                     "active_profile does not match any profile: " + config.active_profile);
  }

  if (config.integration_test.tcp_echo_port == 0) {
    return MakeError(ErrorCode::InvalidConfig, "integration_test tcp_echo_port must not be 0");
  }

  if (config.integration_test.http_port == 0) {
    return MakeError(ErrorCode::InvalidConfig, "integration_test http_port must not be 0");
  }

  if (config.integration_test.udp_echo_port == 0) {
    return MakeError(ErrorCode::InvalidConfig, "integration_test udp_echo_port must not be 0");
  }

  if (config.integration_test.http_path.empty() || config.integration_test.http_path.front() != '/') {
    return MakeError(ErrorCode::InvalidConfig,
                     "integration_test http_path must start with '/'");
  }

  for (const auto& [name, profile] : config.profiles) {
    if (name.empty()) {
      return MakeError(ErrorCode::InvalidConfig, "profile name must not be empty");
    }

    if (!HasCompleteKeyMaterial(profile)) {
      return MakeError(ErrorCode::InvalidConfig,
                       "profile '" + name + "' is missing required endpoint, address, or key material");
    }

    if (profile.endpoint_port == 0) {
      return MakeError(ErrorCode::InvalidConfig,
                       "profile '" + name + "' has invalid endpoint_port 0");
    }
  }

  for (const auto& [name, policy] : config.app_policies) {
    if (name.empty()) {
      return MakeError(ErrorCode::InvalidConfig, "app policy name must not be empty");
    }

    if (!policy.desired_profile.empty() && config.profiles.find(policy.desired_profile) == config.profiles.end()) {
      return MakeError(ErrorCode::InvalidConfig,
                       "app policy '" + name + "' references unknown desired_profile '" +
                           policy.desired_profile + "'");
    }
  }

  return Error::None();
}

std::string DescribeConfig(const Config& config) {
  std::ostringstream stream;
  stream << "profiles=" << config.profiles.size();
  stream << ", app_policies=" << config.app_policies.size();

  if (!config.active_profile.empty()) {
    stream << ", active_profile=" << config.active_profile;
  }

  if (!config.integration_test.target_host.empty()) {
    stream << ", integration_target=" << config.integration_test.target_host;
  }

  stream << ", runtime_flags=" << RuntimeFlagsToString(config.runtime_flags);
  return stream.str();
}

}  // namespace swg
