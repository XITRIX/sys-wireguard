#include "swg_sysmodule/experimental_dns_mitm.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace swg::sysmodule {
namespace {

constexpr const char* kDefaultAtmosphereHosts =
    "# Nintendo telemetry servers\n"
    "127.0.0.1 receive-%.dg.srv.nintendo.net receive-%.er.srv.nintendo.net\n";
constexpr const char* kAtmosphereDefaultHostsPath = "/atmosphere/hosts/default.txt";
constexpr std::uint32_t kSerializedAddrInfoMagic = 0xbeefcafe;
constexpr std::uint32_t kAfUnspec = 0;
constexpr std::uint32_t kAfInet = 2;
constexpr std::uint32_t kSockStream = 1;
constexpr std::uint32_t kIpProtoTcp = 6;
constexpr std::size_t kSerializedSockAddrInSize = 16;

std::uint16_t HostToSerialized16(std::uint16_t value) {
  return static_cast<std::uint16_t>(((value & 0x00ffu) << 8) | ((value & 0xff00u) >> 8));
}

std::uint32_t HostToSerialized32(std::uint32_t value) {
  return ((value & 0x000000ffu) << 24) |
         ((value & 0x0000ff00u) << 8) |
         ((value & 0x00ff0000u) >> 8) |
         ((value & 0xff000000u) >> 24);
}

std::uint32_t SerializedToHost32(std::uint32_t value) {
  return HostToSerialized32(value);
}

bool AppendBytes(std::uint8_t** cursor,
                 std::size_t* remaining,
                 const void* data,
                 std::size_t size) {
  if (*cursor == nullptr || data == nullptr || *remaining < size) {
    return false;
  }
  std::memcpy(*cursor, data, size);
  *cursor += size;
  *remaining -= size;
  return true;
}

bool AppendU8(std::uint8_t** cursor, std::size_t* remaining, std::uint8_t value) {
  return AppendBytes(cursor, remaining, &value, sizeof(value));
}

bool AppendU16(std::uint8_t** cursor, std::size_t* remaining, std::uint16_t value) {
  const std::uint16_t serialized = HostToSerialized16(value);
  return AppendBytes(cursor, remaining, &serialized, sizeof(serialized));
}

bool AppendU32(std::uint8_t** cursor, std::size_t* remaining, std::uint32_t value) {
  const std::uint32_t serialized = HostToSerialized32(value);
  return AppendBytes(cursor, remaining, &serialized, sizeof(serialized));
}

bool AppendCString(std::uint8_t** cursor, std::size_t* remaining, std::string_view value) {
  return AppendBytes(cursor, remaining, value.data(), value.size()) &&
         AppendU8(cursor, remaining, 0);
}

std::optional<std::uint32_t> ReadSerializedU32(const std::uint8_t* data,
                                               std::size_t size,
                                               std::size_t offset) {
  if (data == nullptr || offset + sizeof(std::uint32_t) > size) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  std::memcpy(&value, data + offset, sizeof(value));
  return SerializedToHost32(value);
}

bool IsHostWhitespace(char c) {
  return c == ' ' || c == '\t' || c == '\r';
}

bool IsLineBreak(char c) {
  return c == '\n';
}

std::string ExpandEnvironmentToken(std::string_view token, std::string_view environment_identifier) {
  std::string expanded;
  expanded.reserve(token.size() + environment_identifier.size());
  for (char c : token) {
    if (c == '%') {
      expanded.append(environment_identifier);
    } else {
      expanded.push_back(c);
    }
  }
  return expanded;
}

bool ParseAtmosphereIpv4(std::string_view line, std::size_t* out_offset, std::uint32_t* out_address) {
  std::size_t offset = 0;
  std::uint32_t address = 0;
  for (int octet = 0; octet < 4; ++octet) {
    if (offset >= line.size() || !std::isdigit(static_cast<unsigned char>(line[offset]))) {
      return false;
    }

    std::uint32_t value = 0;
    while (offset < line.size() && std::isdigit(static_cast<unsigned char>(line[offset]))) {
      value *= 10;
      value += static_cast<std::uint32_t>(line[offset] - '0');
      ++offset;
    }

    address |= (value & 0xffu) << static_cast<std::uint32_t>(octet * 8);
    if (octet < 3) {
      if (offset >= line.size() || line[offset] != '.') {
        return false;
      }
      ++offset;
    }
  }

  if (offset >= line.size() || (line[offset] != ' ' && line[offset] != '\t')) {
    return false;
  }

  *out_offset = offset;
  *out_address = address;
  return true;
}

}  // namespace

void AtmosphereDnsMitmRules::Clear() {
  rules_.clear();
}

void AtmosphereDnsMitmRules::AddDefaultTelemetryRules(std::string_view environment_identifier) {
  AddHostsText(kDefaultAtmosphereHosts, environment_identifier);
}

void AtmosphereDnsMitmRules::AddHostsText(std::string_view hosts_text, std::string_view environment_identifier) {
  std::size_t line_start = 0;
  while (line_start <= hosts_text.size()) {
    std::size_t line_end = line_start;
    while (line_end < hosts_text.size() && !IsLineBreak(hosts_text[line_end])) {
      ++line_end;
    }

    const std::string_view line = hosts_text.substr(line_start, line_end - line_start);
    if (!line.empty() && std::isdigit(static_cast<unsigned char>(line.front()))) {
      std::size_t offset = 0;
      std::uint32_t address = 0;
      if (ParseAtmosphereIpv4(line, &offset, &address)) {
        while (offset < line.size()) {
          while (offset < line.size() && IsHostWhitespace(line[offset])) {
            ++offset;
          }

          const std::size_t token_start = offset;
          while (offset < line.size() && !IsHostWhitespace(line[offset])) {
            ++offset;
          }

          if (offset > token_start) {
            const std::string host_pattern =
                ExpandEnvironmentToken(line.substr(token_start, offset - token_start), environment_identifier);
            rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
                                        [&host_pattern](const AtmosphereDnsRedirectRule& rule) {
                                          return rule.host_pattern == host_pattern;
                                        }),
                         rules_.end());
            rules_.push_back({host_pattern, address});
          }
        }
      }
    }

    if (line_end == hosts_text.size()) {
      break;
    }
    line_start = line_end + 1;
  }
}

std::optional<std::uint32_t> AtmosphereDnsMitmRules::ResolveRedirect(std::string_view hostname) const {
  for (auto it = rules_.rbegin(); it != rules_.rend(); ++it) {
    if (AtmosphereDnsWildcardMatch(it->host_pattern, hostname)) {
      return it->ipv4_address;
    }
  }
  return std::nullopt;
}

AtmosphereDnsMitmRules BuildAtmosphereDnsMitmRules(std::string_view hosts_text,
                                                   std::string_view environment_identifier,
                                                   bool add_default_telemetry_rules) {
  AtmosphereDnsMitmRules rules;
  if (add_default_telemetry_rules) {
    rules.AddDefaultTelemetryRules(environment_identifier);
  }
  rules.AddHostsText(hosts_text, environment_identifier);
  return rules;
}

bool AtmosphereDnsWildcardMatch(std::string_view pattern, std::string_view hostname) {
  std::size_t pattern_index = 0;
  std::size_t host_index = 0;
  std::optional<std::size_t> wildcard_index;
  std::size_t wildcard_host_resume = 0;

  while (host_index < hostname.size()) {
    if (pattern_index < pattern.size() &&
        (pattern[pattern_index] == hostname[host_index])) {
      ++pattern_index;
      ++host_index;
      continue;
    }

    if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
      wildcard_index = pattern_index++;
      wildcard_host_resume = host_index;
      continue;
    }

    if (wildcard_index.has_value()) {
      pattern_index = *wildcard_index + 1;
      host_index = ++wildcard_host_resume;
      continue;
    }

    return false;
  }

  while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
    ++pattern_index;
  }
  return pattern_index == pattern.size();
}

std::string DefaultAtmosphereDnsHostsFile() {
  return kDefaultAtmosphereHosts;
}

std::string AtmosphereDnsDefaultHostsPath() {
  return kAtmosphereDefaultHostsPath;
}

std::vector<std::string> AtmosphereDnsHostsFileSearchOrder(bool emummc_active, std::uint32_t emummc_id) {
  std::vector<std::string> paths;
  paths.reserve(3);

  if (emummc_active) {
    char specific_path[64]{};
    std::snprintf(specific_path, sizeof(specific_path), "/atmosphere/hosts/emummc_%04x.txt", emummc_id);
    paths.emplace_back(specific_path);
    paths.emplace_back("/atmosphere/hosts/emummc.txt");
  } else {
    paths.emplace_back("/atmosphere/hosts/sysmmc.txt");
  }

  paths.emplace_back(kAtmosphereDefaultHostsPath);
  return paths;
}

std::string FormatAtmosphereDnsIpv4(std::uint32_t address) {
  char buffer[32]{};
  std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", address & 0xffu, (address >> 8) & 0xffu,
                (address >> 16) & 0xffu, (address >> 24) & 0xffu);
  return buffer;
}

std::optional<AtmosphereDnsAddrInfoHint> ParseAtmosphereDnsSerializedAddrInfoHint(const void* data,
                                                                                  std::size_t size) {
  if (data == nullptr || size == 0) {
    return AtmosphereDnsAddrInfoHint{};
  }
  if (size < 6 * sizeof(std::uint32_t)) {
    return std::nullopt;
  }

  const auto* bytes = static_cast<const std::uint8_t*>(data);
  const auto magic = ReadSerializedU32(bytes, size, 0);
  const auto flags = ReadSerializedU32(bytes, size, 4);
  const auto family = ReadSerializedU32(bytes, size, 8);
  const auto socktype = ReadSerializedU32(bytes, size, 12);
  const auto protocol = ReadSerializedU32(bytes, size, 16);
  if (!magic.has_value() || !flags.has_value() || !family.has_value() ||
      !socktype.has_value() || !protocol.has_value() || *magic != kSerializedAddrInfoMagic) {
    return std::nullopt;
  }

  AtmosphereDnsAddrInfoHint hint{};
  hint.flags = *flags;
  hint.family = *family;
  hint.socktype = *socktype;
  hint.protocol = *protocol;
  hint.unsupported_family = hint.family != kAfUnspec && hint.family != kAfInet;
  return hint;
}

std::optional<std::size_t> SerializeAtmosphereDnsHostEnt(void* output,
                                                         std::size_t output_size,
                                                         std::string_view hostname,
                                                         std::uint32_t address) {
  if (output == nullptr || hostname.empty()) {
    return std::nullopt;
  }

  auto* cursor = static_cast<std::uint8_t*>(output);
  std::size_t remaining = output_size;
  const auto* start = cursor;

  if (!AppendCString(&cursor, &remaining, hostname)) {
    return std::nullopt;
  }
  if (!AppendU32(&cursor, &remaining, 0)) {
    return std::nullopt;
  }
  if (!AppendU16(&cursor, &remaining, static_cast<std::uint16_t>(kAfInet)) ||
      !AppendU16(&cursor, &remaining, sizeof(std::uint32_t))) {
    return std::nullopt;
  }
  if (!AppendU32(&cursor, &remaining, 1) ||
      !AppendU32(&cursor, &remaining, address)) {
    return std::nullopt;
  }

  return static_cast<std::size_t>(cursor - start);
}

std::optional<std::size_t> SerializeAtmosphereDnsAddrInfo(void* output,
                                                          std::size_t output_size,
                                                          std::string_view hostname,
                                                          std::uint32_t address,
                                                          std::uint16_t port,
                                                          const AtmosphereDnsAddrInfoHint* hint) {
  (void)hostname;
  if (output == nullptr || (hint != nullptr && hint->unsupported_family)) {
    return std::nullopt;
  }

  auto* cursor = static_cast<std::uint8_t*>(output);
  std::size_t remaining = output_size;
  const auto* start = cursor;

  const std::uint32_t flags = hint == nullptr ? 0 : hint->flags;
  std::uint32_t family = hint == nullptr ? kAfInet : hint->family;
  if (family == kAfUnspec) {
    family = kAfInet;
  }
  const std::uint32_t socktype =
      hint == nullptr || hint->socktype == 0 ? kSockStream : hint->socktype;
  const std::uint32_t protocol =
      hint == nullptr || hint->protocol == 0 ? kIpProtoTcp : hint->protocol;

  if (!AppendU32(&cursor, &remaining, kSerializedAddrInfoMagic) ||
      !AppendU32(&cursor, &remaining, flags) ||
      !AppendU32(&cursor, &remaining, family) ||
      !AppendU32(&cursor, &remaining, socktype) ||
      !AppendU32(&cursor, &remaining, protocol) ||
      !AppendU32(&cursor, &remaining, kSerializedSockAddrInSize)) {
    return std::nullopt;
  }

  if (!AppendU16(&cursor, &remaining, static_cast<std::uint16_t>(kAfInet)) ||
      !AppendU16(&cursor, &remaining, HostToSerialized16(port)) ||
      !AppendU32(&cursor, &remaining, address)) {
    return std::nullopt;
  }

  const std::uint8_t zeros[8]{};
  if (!AppendBytes(&cursor, &remaining, zeros, sizeof(zeros)) ||
      !AppendU8(&cursor, &remaining, 0) ||
      !AppendU32(&cursor, &remaining, 0)) {
    return std::nullopt;
  }

  return static_cast<std::size_t>(cursor - start);
}

DnsMitmInterceptionPlan PlanExperimentalDnsMitmRequest(const DnsMitmPlan& plan,
                                                       const MitmRuntimeSettings& settings,
                                                       const DnsMitmRequestContext& request) {
  DnsMitmInterceptionPlan interception{};
  interception.should_log_query = settings.log_client_sessions;
  interception.should_record_metric = plan.requested;

  if (!plan.requested) {
    interception.reason = "dns MITM is disabled for the current runtime settings";
    return interception;
  }

  if (request.host.empty()) {
    interception.reason = "dns MITM request has no host name to evaluate";
    return interception;
  }

  if (!request.client.is_application && !settings.mitm_all_clients) {
    interception.reason = "dns MITM currently targets application clients only";
    return interception;
  }

  if (!plan.service_available) {
    interception.reason = plan.blockers.empty() ? "resolver service is not available" : plan.blockers.front();
    return interception;
  }

  switch (settings.session_mode) {
    case MitmSessionMode::ObserveOnly:
      interception.reason = "observe-only dns MITM scaffold will forward the query unchanged";
      return interception;
    case MitmSessionMode::InterceptAndForward:
      interception.reason = "dns MITM intercept scaffold will forward the query after inspection";
      return interception;
    case MitmSessionMode::RedirectToTunnel:
      if (!plan.ready) {
        interception.reason = "dns tunnel redirection is planned, but the scaffold is not wired into switch_main yet";
        return interception;
      }

      interception.action = DnsMitmAction::ResolveThroughTunnel;
      interception.use_tunnel_dns = true;
      interception.reason = "dns query will resolve through the active WireGuard tunnel";
      return interception;
  }

  interception.reason = "dns MITM session mode is not recognized";
  return interception;
}

const char* ToString(DnsMitmRequestKind kind) {
  switch (kind) {
    case DnsMitmRequestKind::GetHostByName:
      return "get_host_by_name";
    case DnsMitmRequestKind::GetHostByNameWithOptions:
      return "get_host_by_name_with_options";
    case DnsMitmRequestKind::GetAddrInfo:
      return "get_addr_info";
    case DnsMitmRequestKind::GetAddrInfoWithOptions:
      return "get_addr_info_with_options";
  }

  return "unknown";
}

const char* ToString(DnsMitmAction action) {
  switch (action) {
    case DnsMitmAction::ForwardToResolver:
      return "forward_to_resolver";
    case DnsMitmAction::ResolveThroughTunnel:
      return "resolve_through_tunnel";
    case DnsMitmAction::SynthesizeFailure:
      return "synthesize_failure";
  }

  return "unknown";
}

}  // namespace swg::sysmodule
