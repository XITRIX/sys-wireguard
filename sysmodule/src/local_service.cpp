#include "swg_sysmodule/local_service.h"

#include <cctype>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include "swg/config.h"
#include "swg/hos_caps.h"
#include "swg/log.h"
#include "swg/state_machine.h"
#include "swg/wg_profile.h"
#include "swg_sysmodule/wg_engine.h"

namespace swg::sysmodule {
namespace {

bool ProfileHasCompleteKeyMaterial(const ProfileConfig& profile) {
  return !profile.private_key.empty() && !profile.public_key.empty() && !profile.endpoint_host.empty() &&
         !profile.allowed_ips.empty() && !profile.addresses.empty();
}

struct AppSessionRecord {
  AppTunnelRequest request;
  std::string selected_profile;
};

RuntimeFlags ResolveGrantedFlags(RuntimeFlags active_flags, RuntimeFlags requested_flags) {
  return requested_flags == 0 ? active_flags : (active_flags & requested_flags);
}

bool StartsWith(std::string_view value, std::string_view prefix) {
  return value.rfind(prefix, 0) == 0;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
  return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}

bool IsPrivateIpv4(std::string_view host) {
  if (StartsWith(host, "10.") || StartsWith(host, "127.") || StartsWith(host, "192.168.") ||
      StartsWith(host, "169.254.")) {
    return true;
  }

  if (!StartsWith(host, "172.")) {
    return false;
  }

  const std::size_t first_dot = host.find('.');
  if (first_dot == std::string_view::npos) {
    return false;
  }

  const std::size_t second_dot = host.find('.', first_dot + 1);
  const std::string second_octet = std::string(host.substr(first_dot + 1, second_dot - first_dot - 1));
  try {
    const int value = std::stoi(second_octet);
    return value >= 16 && value <= 31;
  } catch (const std::exception&) {
    return false;
  }
}

bool LooksLocalHost(std::string_view host) {
  if (host.empty()) {
    return false;
  }

  std::string normalized(host);
  for (char& ch : normalized) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  return normalized == "localhost" || normalized == "::1" || StartsWith(normalized, "fe80:") ||
         StartsWith(normalized, "fc") || StartsWith(normalized, "fd") || EndsWith(normalized, ".local") ||
         IsPrivateIpv4(normalized);
}

bool IsRemoteStreamTraffic(AppTrafficClass traffic_class) {
  return traffic_class == AppTrafficClass::HttpsControl || traffic_class == AppTrafficClass::StreamControl ||
         traffic_class == AppTrafficClass::StreamVideo || traffic_class == AppTrafficClass::StreamAudio ||
         traffic_class == AppTrafficClass::StreamInput;
}

std::string SelectProfile(const Config& config, const AppTunnelRequest& request) {
  if (!request.desired_profile.empty()) {
    return request.desired_profile;
  }

  return config.active_profile;
}

std::string BuildAppSessionNotes(const AppTunnelRequest& request, const std::string& profile_name,
                                 const StateSnapshot& snapshot, RuntimeFlags granted_flags) {
  std::ostringstream stream;
  stream << "app=" << (request.app.client_name.empty() ? "unknown" : request.app.client_name)
         << ", profile=" << (profile_name.empty() ? "<none>" : profile_name)
         << ", runtime_flags=" << RuntimeFlagsToString(granted_flags)
         << ", state=" << ToString(snapshot.state);
  if (request.require_tunnel_for_default_traffic) {
    stream << ", default_routes=require_tunnel";
  }
  if (request.allow_local_network_bypass) {
    stream << ", local_bypass=enabled";
  }
  return stream.str();
}

TunnelStats MergeEngineStats(const TunnelStats& base, const TunnelStats& engine) {
  TunnelStats merged = base;
  merged.bytes_in += engine.bytes_in;
  merged.bytes_out += engine.bytes_out;
  merged.packets_in += engine.packets_in;
  merged.packets_out += engine.packets_out;
  merged.successful_handshakes += engine.successful_handshakes;
  merged.reconnects += engine.reconnects;
  merged.dns_queries += engine.dns_queries;
  merged.dns_fallbacks += engine.dns_fallbacks;
  merged.leak_prevention_events += engine.leak_prevention_events;
  merged.last_handshake_age_seconds = engine.last_handshake_age_seconds;
  return merged;
}

class LocalControlService final : public IControlService {
 public:
  explicit LocalControlService(std::filesystem::path runtime_root) : paths_(DetectRuntimePaths(runtime_root)) {
    const Error init_error = Initialize();
    if (init_error) {
      initialization_error_ = init_error;
    }
  }

  Result<VersionInfo> GetVersion() const override {
    return MakeSuccess(VersionInfo{});
  }

  Result<ServiceStatus> GetStatus() const override {
    std::scoped_lock lock(mutex_);

    const StateSnapshot snapshot = state_machine_.snapshot();
    ServiceStatus status{};
    status.service_ready = initialization_error_.ok();
    status.state = initialization_error_ ? TunnelState::Error : snapshot.state;
    status.runtime_flags = snapshot.runtime_flags;
    status.active_profile = snapshot.active_profile;
    status.last_error = initialization_error_ ? initialization_error_.message : snapshot.last_error;
    return MakeSuccess(std::move(status));
  }

  Result<std::string> GetLastError() const override {
    const Result<ServiceStatus> status = GetStatus();
    if (!status.ok()) {
      return MakeFailure<std::string>(status.error.code, status.error.message);
    }
    return MakeSuccess(status.value.last_error);
  }

  Result<std::vector<ProfileSummary>> ListProfiles() const override {
    std::scoped_lock lock(mutex_);

    std::vector<ProfileSummary> profiles;
    profiles.reserve(config_.profiles.size());
    for (const auto& [name, profile] : config_.profiles) {
      profiles.push_back(ProfileSummary{
          name,
          profile.autostart,
          profile.transparent_mode,
          ProfileHasCompleteKeyMaterial(profile),
      });
    }

    return MakeSuccess(std::move(profiles));
  }

  Result<Config> GetConfig() const override {
    std::scoped_lock lock(mutex_);
    return MakeSuccess(config_);
  }

  Error SaveConfig(const Config& config) override {
    std::scoped_lock lock(mutex_);

    if (!IsConfigMutationAllowed()) {
      return MakeError(ErrorCode::InvalidState, "cannot save config while tunnel is active");
    }

    const Error validation_error = ValidateConfig(config);
    if (validation_error) {
      return validation_error;
    }

    config_ = config;
    NormalizeActiveProfile();
    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      return save_error;
    }

    ApplyConfigToState();
    LogInfo("sysmodule", "config saved: " + DescribeConfig(config_));
    return Error::None();
  }

  Error SetActiveProfile(std::string_view profile_name) override {
    std::scoped_lock lock(mutex_);

    const std::string profile(profile_name);
    if (config_.profiles.find(profile) == config_.profiles.end()) {
      return MakeError(ErrorCode::NotFound, "profile not found: " + profile);
    }

    const Error state_error = state_machine_.SetActiveProfile(profile);
    if (state_error) {
      return state_error;
    }

    config_.active_profile = profile;
    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      return save_error;
    }

    LogInfo("sysmodule", "active profile set to " + profile);
    return Error::None();
  }

  Error Connect() override {
    std::scoped_lock lock(mutex_);

    if (initialization_error_) {
      return initialization_error_;
    }

    const auto profile_it = config_.profiles.find(config_.active_profile);
    if (profile_it == config_.profiles.end()) {
      return MakeError(ErrorCode::InvalidConfig, "active profile does not exist: " + config_.active_profile);
    }

    const Error connect_error = state_machine_.Connect();
    if (connect_error) {
      return connect_error;
    }

    TunnelStats stats = state_machine_.snapshot().stats;
    ++stats.connect_attempts;
    state_machine_.UpdateStats(stats);

    const Result<ValidatedWireGuardProfile> validated_profile =
        ValidateWireGuardProfileForConnect(profile_it->second);
    if (!validated_profile.ok()) {
      state_machine_.MarkConnectFailed(validated_profile.error.message);
      LogError("sysmodule", "connect validation failed for profile " + config_.active_profile + ": " +
                                 validated_profile.error.message);
      return validated_profile.error;
    }

    const Result<PreparedTunnelSession> prepared_session =
        PrepareTunnelSession(config_.active_profile, validated_profile.value, config_.runtime_flags);
    if (!prepared_session.ok()) {
      state_machine_.MarkConnectFailed(prepared_session.error.message);
      LogError("sysmodule", "connect session preparation failed for profile " + config_.active_profile + ": " +
                                 prepared_session.error.message);
      return prepared_session.error;
    }

    const Error engine_error = tunnel_engine_->Start(TunnelEngineStartRequest{prepared_session.value});
    if (engine_error) {
      state_machine_.MarkConnectFailed(engine_error.message);
      LogError("sysmodule", "WireGuard engine start failed for profile " + config_.active_profile + ": " +
                                 engine_error.message);
      return engine_error;
    }

    const Error mark_error = state_machine_.MarkConnected();
    if (mark_error) {
      tunnel_engine_->Stop();
      return mark_error;
    }

    LogInfo("sysmodule", "connect requested with prepared session: " +
                            DescribePreparedTunnelSession(prepared_session.value) +
                            " (WireGuard response validated)");
    return Error::None();
  }

  Error Disconnect() override {
    std::scoped_lock lock(mutex_);

    const Error disconnect_error = state_machine_.Disconnect();
    if (disconnect_error) {
      return disconnect_error;
    }

    const TunnelStats final_engine_stats = tunnel_engine_->GetStats();

    const Error engine_error = tunnel_engine_->Stop();
    if (engine_error) {
      state_machine_.MarkConnectFailed(engine_error.message);
      return engine_error;
    }

    const Error mark_error = state_machine_.MarkDisconnected();
    if (mark_error) {
      return mark_error;
    }

    state_machine_.UpdateStats(MergeEngineStats(state_machine_.snapshot().stats, final_engine_stats));

    LogInfo("sysmodule", "disconnect requested");
    return Error::None();
  }

  Result<TunnelStats> GetStats() const override {
    std::scoped_lock lock(mutex_);

    TunnelStats stats = state_machine_.snapshot().stats;
    if (tunnel_engine_->IsRunning()) {
      stats = MergeEngineStats(stats, tunnel_engine_->GetStats());
    }

    return MakeSuccess(std::move(stats));
  }

  Error SetRuntimeFlags(RuntimeFlags flags) override {
    std::scoped_lock lock(mutex_);

    config_.runtime_flags = flags;
    const Error state_error = state_machine_.SetRuntimeFlags(flags);
    if (state_error) {
      return state_error;
    }

    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      return save_error;
    }

    LogInfo("sysmodule", "runtime flags set to " + RuntimeFlagsToString(flags));
    return Error::None();
  }

  Result<CompatibilityInfo> GetCompatibilityInfo() const override {
    const HosCapabilities capabilities = DetectHosCapabilities();
    CompatibilityInfo info{};
    info.switch_target = capabilities.switch_target;
    info.has_bsd_a = capabilities.has_bsd_a;
    info.has_dns_priv = capabilities.has_dns_priv;
    info.has_ifcfg = capabilities.has_ifcfg;
    info.has_bsd_nu = capabilities.has_bsd_nu;
    info.needs_new_tls_abi = capabilities.needs_new_tls_abi;
#if defined(SWG_PLATFORM_SWITCH)
    info.notes = DescribeHosCapabilities(capabilities) +
         "; probe mapping: has_dns_priv checks dns:priv then sfdnsres, has_ifcfg checks ifcfg then nifm:a/nifm:s; "
         "Phase A exposes the control plane through the registered swg:ctl service.";
#else
    info.notes = DescribeHosCapabilities(capabilities) + "; Phase A currently exercises the control plane through a local stub service.";
#endif
    return MakeSuccess(std::move(info));
  }

  Result<AppSessionInfo> OpenAppSession(const AppTunnelRequest& request) override {
    std::scoped_lock lock(mutex_);

    if (initialization_error_) {
      return Result<AppSessionInfo>::Failure(initialization_error_);
    }

    const std::string profile_name = SelectProfile(config_, request);
    if (!request.desired_profile.empty() && config_.profiles.find(request.desired_profile) == config_.profiles.end()) {
      return MakeFailure<AppSessionInfo>(ErrorCode::NotFound, "requested profile not found: " + request.desired_profile);
    }

    const std::uint64_t session_id = next_session_id_++;
    app_sessions_[session_id] = AppSessionRecord{request, profile_name};

    const StateSnapshot snapshot = state_machine_.snapshot();
    const RuntimeFlags granted_flags = ResolveGrantedFlags(config_.runtime_flags, request.requested_flags);

    AppSessionInfo info{};
    info.session_id = session_id;
    info.service_ready = true;
    info.tunnel_ready = snapshot.state == TunnelState::Connected && !profile_name.empty() &&
                        snapshot.active_profile == profile_name;
    info.dns_ready = info.tunnel_ready && request.prefer_tunnel_dns && HasFlag(granted_flags, RuntimeFlag::DnsThroughTunnel);
    info.transparent_mode_ready = info.tunnel_ready && HasFlag(granted_flags, RuntimeFlag::TransparentMode);
    info.active_profile = profile_name;
    info.granted_flags = granted_flags;
    info.notes = BuildAppSessionNotes(request, profile_name, snapshot, granted_flags);

    LogInfo("sysmodule", "opened app session " + std::to_string(session_id) + " for " +
                            (request.app.client_name.empty() ? std::string("unknown_app") : request.app.client_name));
    return MakeSuccess(std::move(info));
  }

  Error CloseAppSession(std::uint64_t session_id) override {
    std::scoped_lock lock(mutex_);

    const auto it = app_sessions_.find(session_id);
    if (it == app_sessions_.end()) {
      return MakeError(ErrorCode::NotFound, "app session not found: " + std::to_string(session_id));
    }

    app_sessions_.erase(it);
    LogInfo("sysmodule", "closed app session " + std::to_string(session_id));
    return Error::None();
  }

  Result<NetworkPlan> GetNetworkPlan(const NetworkPlanRequest& request) const override {
    std::scoped_lock lock(mutex_);

    const auto session_it = app_sessions_.find(request.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<NetworkPlan>(ErrorCode::NotFound,
                                      "app session not found: " + std::to_string(request.session_id));
    }

    const AppSessionRecord& session = session_it->second;
    const StateSnapshot snapshot = state_machine_.snapshot();
    const RuntimeFlags granted_flags = ResolveGrantedFlags(config_.runtime_flags, session.request.requested_flags);
    const bool tunnel_ready = snapshot.state == TunnelState::Connected && !session.selected_profile.empty() &&
                              snapshot.active_profile == session.selected_profile;

    NetworkPlan plan{};
    plan.profile_name = session.selected_profile;
    plan.transparent_eligible = tunnel_ready && HasFlag(granted_flags, RuntimeFlag::TransparentMode);

    const bool explicit_bypass = request.route_preference == RoutePreference::BypassTunnel;
    const bool local_bypass = session.request.allow_local_network_bypass &&
                              (request.local_network_hint || request.traffic_class == AppTrafficClass::Discovery ||
                               request.traffic_class == AppTrafficClass::WakeOnLan ||
                               request.traffic_class == AppTrafficClass::ExternalAddressProbe ||
                               LooksLocalHost(request.remote_host));

    if (explicit_bypass || local_bypass) {
      plan.action = RouteAction::Direct;
      plan.local_bypass = local_bypass;
      plan.reason = explicit_bypass ? "caller requested direct routing"
                                   : "local discovery or local-network traffic bypasses the tunnel";
      return MakeSuccess(std::move(plan));
    }

    if (request.traffic_class == AppTrafficClass::Dns) {
      const bool wants_tunnel_dns = session.request.prefer_tunnel_dns && HasFlag(granted_flags, RuntimeFlag::DnsThroughTunnel);
      if (wants_tunnel_dns && tunnel_ready) {
        plan.action = RouteAction::Tunnel;
        plan.use_tunnel_dns = true;
        plan.reason = "DNS should resolve through the active tunnel for this app session";
        return MakeSuccess(std::move(plan));
      }

      if (wants_tunnel_dns && !session.request.allow_direct_internet_fallback) {
        plan.action = RouteAction::Deny;
        plan.reason = "tunnel DNS requested but the tunnel is not ready";
        return MakeSuccess(std::move(plan));
      }

      plan.action = RouteAction::Direct;
      plan.reason = wants_tunnel_dns ? "falling back to direct DNS because tunnel DNS is unavailable"
                                     : "app session does not require tunnel DNS";
      return MakeSuccess(std::move(plan));
    }

    bool wants_tunnel = false;
    switch (request.route_preference) {
      case RoutePreference::RequireTunnel:
      case RoutePreference::PreferTunnel:
        wants_tunnel = true;
        break;
      case RoutePreference::Default:
        wants_tunnel = IsRemoteStreamTraffic(request.traffic_class) || session.request.require_tunnel_for_default_traffic;
        break;
      case RoutePreference::BypassTunnel:
        wants_tunnel = false;
        break;
    }

    if (wants_tunnel) {
      if (tunnel_ready) {
        plan.action = RouteAction::Tunnel;
        plan.reason = "remote control or streaming traffic should use the active tunnel";
        return MakeSuccess(std::move(plan));
      }

      if (request.route_preference != RoutePreference::RequireTunnel && session.request.allow_direct_internet_fallback) {
        plan.action = RouteAction::Direct;
        plan.reason = "tunnel unavailable; app session allows direct fallback";
        return MakeSuccess(std::move(plan));
      }

      plan.action = RouteAction::Deny;
      plan.reason = "tunnel-required traffic cannot proceed until the selected profile is connected";
      return MakeSuccess(std::move(plan));
    }

    plan.action = RouteAction::Direct;
    plan.reason = "traffic class does not require the tunnel";
    return MakeSuccess(std::move(plan));
  }

  Result<std::uint64_t> SendPacket(const TunnelSendRequest& request) override {
    std::scoped_lock lock(mutex_);

    if (request.payload.empty()) {
      return MakeFailure<std::uint64_t>(ErrorCode::ParseError,
                                        "authenticated transport payload must not be empty");
    }

    const auto session_it = app_sessions_.find(request.session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<std::uint64_t>(ErrorCode::NotFound,
                                        "app session not found: " + std::to_string(request.session_id));
    }

    const AppSessionRecord& session = session_it->second;
    const StateSnapshot snapshot = state_machine_.snapshot();
    if (snapshot.state != TunnelState::Connected || !tunnel_engine_->IsRunning()) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "tunnel is not connected for packet send");
    }

    if (session.selected_profile.empty() || snapshot.active_profile != session.selected_profile) {
      return MakeFailure<std::uint64_t>(ErrorCode::InvalidState,
                                        "app session profile is not active on the connected tunnel");
    }

    return tunnel_engine_->SendPacket(request.payload);
  }

  Result<TunnelPacket> RecvPacket(std::uint64_t session_id) override {
    std::scoped_lock lock(mutex_);

    const auto session_it = app_sessions_.find(session_id);
    if (session_it == app_sessions_.end()) {
      return MakeFailure<TunnelPacket>(ErrorCode::NotFound,
                                       "app session not found: " + std::to_string(session_id));
    }

    const AppSessionRecord& session = session_it->second;
    const StateSnapshot snapshot = state_machine_.snapshot();
    if (snapshot.state != TunnelState::Connected || !tunnel_engine_->IsRunning()) {
      return MakeFailure<TunnelPacket>(ErrorCode::InvalidState,
                                       "tunnel is not connected for packet receive");
    }

    if (session.selected_profile.empty() || snapshot.active_profile != session.selected_profile) {
      return MakeFailure<TunnelPacket>(ErrorCode::InvalidState,
                                       "app session profile is not active on the connected tunnel");
    }

    const Result<WireGuardConsumedTransportPacket> packet = tunnel_engine_->ReceivePacket();
    if (!packet.ok()) {
      return MakeFailure<TunnelPacket>(packet.error.code, packet.error.message);
    }

    TunnelPacket received{};
    received.counter = packet.value.counter;
    received.payload = std::move(packet.value.payload);
    return MakeSuccess(std::move(received));
  }

 private:
  Error Initialize() {
    const Error logger_error = Logger::Instance().Initialize(paths_.log_file);
    if (logger_error) {
      return logger_error;
    }

    LogInfo("sysmodule", "initializing control service");

    const Result<Config> loaded = LoadOrCreateConfigFile(paths_.config_file);
    if (!loaded.ok()) {
      LogError("sysmodule", "config load failed: " + loaded.error.message);
      return loaded.error;
    }

    config_ = loaded.value;
    NormalizeActiveProfile();

    const Error save_error = SaveConfigFile(config_, paths_.config_file);
    if (save_error) {
      LogError("sysmodule", "config save failed during init: " + save_error.message);
      return save_error;
    }

    ApplyConfigToState();
    LogInfo("sysmodule", "control service ready: " + DescribeConfig(config_));
    return Error::None();
  }

  void NormalizeActiveProfile() {
    if (config_.active_profile.empty() && config_.profiles.size() == 1) {
      config_.active_profile = config_.profiles.begin()->first;
    }
  }

  void ApplyConfigToState() {
    state_machine_.ApplyConfig(config_);
  }

  bool IsConfigMutationAllowed() const {
    const TunnelState state = state_machine_.snapshot().state;
    return state != TunnelState::Connecting && state != TunnelState::Connected &&
           state != TunnelState::Disconnecting;
  }

  RuntimePaths paths_{};
  mutable std::mutex mutex_;
  Config config_{};
  ConnectionStateMachine state_machine_{};
  std::unique_ptr<IWgTunnelEngine> tunnel_engine_ = CreateWgTunnelEngine();
  Error initialization_error_{};
  std::uint64_t next_session_id_ = 1;
  mutable std::unordered_map<std::uint64_t, AppSessionRecord> app_sessions_{};
};

}  // namespace

std::shared_ptr<IControlService> CreateLocalControlService(const std::filesystem::path& runtime_root) {
  return std::make_shared<LocalControlService>(runtime_root);
}

}  // namespace swg::sysmodule
