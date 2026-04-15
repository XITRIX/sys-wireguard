#include "swg_sysmodule/experimental_dns_mitm.h"

namespace swg::sysmodule {

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