#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "swg/ipc_protocol.h"
#include "swg/result.h"

namespace swg {

struct ProfileConfig {
  std::string name;
  std::string private_key;
  std::string public_key;
  std::string preshared_key;
  std::string endpoint_host;
  std::uint16_t endpoint_port = 51820;
  std::vector<std::string> allowed_ips;
  std::vector<std::string> addresses;
  std::vector<std::string> dns_servers;
  std::uint16_t persistent_keepalive = 25;
  bool autostart = false;
  bool transparent_mode = false;
  bool kill_switch = false;
};

struct AppPolicyConfig {
  std::string name;
  std::string client_name;
  std::string integration_tag;
  std::string desired_profile;
  RuntimeFlags requested_flags = 0;
  bool allow_local_network_bypass = false;
  bool require_tunnel_for_default_traffic = true;
  bool prefer_tunnel_dns = true;
  bool allow_direct_internet_fallback = false;
};

struct IntegrationTestConfig {
  std::string target_host;
  std::string dns_hostname;
  std::uint16_t tcp_echo_port = 28080;
  std::uint16_t http_port = 28081;
  std::uint16_t udp_echo_port = 28082;
  std::string http_path = "/swg/health";
};

struct Config {
  std::map<std::string, ProfileConfig> profiles;
  std::map<std::string, AppPolicyConfig> app_policies;
  IntegrationTestConfig integration_test;
  std::string active_profile;
  RuntimeFlags runtime_flags = 0;
};

struct RuntimePaths {
  std::filesystem::path root_dir;
  std::filesystem::path config_dir;
  std::filesystem::path config_file;
  std::filesystem::path log_dir;
  std::filesystem::path log_file;
};

Config DefaultConfig();
RuntimePaths DetectRuntimePaths(const std::filesystem::path& root_override = {});
Result<Config> LoadConfigFile(const std::filesystem::path& path);
Result<Config> LoadOrCreateConfigFile(const std::filesystem::path& path);
Error SaveConfigFile(const Config& config, const std::filesystem::path& path);
Error ValidateConfig(const Config& config);
std::string DescribeConfig(const Config& config);

}  // namespace swg
