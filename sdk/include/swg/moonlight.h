#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "swg/ipc_protocol.h"
#include "swg/session_socket.h"

namespace swg {

inline AppTunnelRequest MakeMoonlightSessionRequest(std::string desired_profile = {}, bool require_tunnel = true) {
  AppTunnelRequest request{};
  request.app.client_name = "Moonlight-Switch";
  request.app.integration_tag = "moonlight-switch";
  request.desired_profile = std::move(desired_profile);
  request.requested_flags = ToFlags(RuntimeFlag::DnsThroughTunnel);
  request.allow_local_network_bypass = true;
  request.require_tunnel_for_default_traffic = require_tunnel;
  request.prefer_tunnel_dns = true;
  request.allow_direct_internet_fallback = !require_tunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightDiscoveryPlan(std::string remote_host = "224.0.0.251",
                                                     std::uint16_t remote_port = 5353) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::Discovery;
  request.route_preference = RoutePreference::BypassTunnel;
  request.local_network_hint = true;
  return request;
}

inline NetworkPlanRequest MakeMoonlightWakeOnLanPlan(std::string remote_host, std::uint16_t remote_port = 9) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::WakeOnLan;
  request.route_preference = RoutePreference::BypassTunnel;
  request.local_network_hint = true;
  return request;
}

inline NetworkPlanRequest MakeMoonlightDnsPlan(std::string remote_host) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.traffic_class = AppTrafficClass::Dns;
  request.route_preference = RoutePreference::PreferTunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightHttpsControlPlan(std::string remote_host, std::uint16_t remote_port) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Https;
  request.traffic_class = AppTrafficClass::HttpsControl;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightStreamControlPlan(std::string remote_host, std::uint16_t remote_port) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Tcp;
  request.traffic_class = AppTrafficClass::StreamControl;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightVideoPlan(std::string remote_host, std::uint16_t remote_port) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::StreamVideo;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightAudioPlan(std::string remote_host, std::uint16_t remote_port) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::StreamAudio;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightInputPlan(std::string remote_host, std::uint16_t remote_port) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::StreamInput;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline NetworkPlanRequest MakeMoonlightStunPlan(std::string remote_host = "stun.moonlight-stream.org",
                                                std::uint16_t remote_port = 3478) {
  NetworkPlanRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::ExternalAddressProbe;
  request.route_preference = RoutePreference::BypassTunnel;
  return request;
}

inline SessionSocketRequest MakeMoonlightHttpsControlSocketRequest(std::string remote_host,
                                                                   std::uint16_t remote_port) {
  SessionSocketRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Https;
  request.traffic_class = AppTrafficClass::HttpsControl;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline SessionSocketRequest MakeMoonlightStreamControlSocketRequest(std::string remote_host,
                                                                    std::uint16_t remote_port) {
  SessionSocketRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Tcp;
  request.traffic_class = AppTrafficClass::StreamControl;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline SessionSocketRequest MakeMoonlightVideoSocketRequest(std::string remote_host,
                                                            std::uint16_t remote_port) {
  SessionSocketRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::StreamVideo;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline SessionSocketRequest MakeMoonlightAudioSocketRequest(std::string remote_host,
                                                            std::uint16_t remote_port) {
  SessionSocketRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::StreamAudio;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

inline SessionSocketRequest MakeMoonlightInputSocketRequest(std::string remote_host,
                                                            std::uint16_t remote_port) {
  SessionSocketRequest request{};
  request.remote_host = std::move(remote_host);
  request.remote_port = remote_port;
  request.transport = TransportProtocol::Udp;
  request.traffic_class = AppTrafficClass::StreamInput;
  request.route_preference = RoutePreference::RequireTunnel;
  return request;
}

}  // namespace swg
