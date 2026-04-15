#pragma once

#include <cstdint>
#include <string>

#include "swg_sysmodule/experimental_mitm.h"

namespace swg::sysmodule {

enum class DnsMitmRequestKind : std::uint8_t {
  GetHostByName = 0,
  GetHostByNameWithOptions,
  GetAddrInfo,
  GetAddrInfoWithOptions,
};

enum class DnsMitmAction : std::uint8_t {
  ForwardToResolver = 0,
  ResolveThroughTunnel,
  SynthesizeFailure,
};

struct DnsMitmRequestContext {
  DnsMitmRequestKind request_kind = DnsMitmRequestKind::GetAddrInfo;
  MitmClientInfo client;
  std::string host;
  std::string service;
  bool use_nsd_resolve = false;
  bool has_request_options = false;
};

struct DnsMitmInterceptionPlan {
  DnsMitmAction action = DnsMitmAction::ForwardToResolver;
  bool should_log_query = false;
  bool should_record_metric = false;
  bool use_tunnel_dns = false;
  bool fail_closed = false;
  std::string reason;
};

DnsMitmInterceptionPlan PlanExperimentalDnsMitmRequest(const DnsMitmPlan& plan,
                                                       const MitmRuntimeSettings& settings,
                                                       const DnsMitmRequestContext& request);

const char* ToString(DnsMitmRequestKind kind);
const char* ToString(DnsMitmAction action);

}  // namespace swg::sysmodule