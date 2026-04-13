#pragma once

#include <cstdint>
#include <string>
#include <vector>

#if defined(__SWITCH__) || defined(SWG_PLATFORM_SWITCH)
#include <sys/socket.h>
#include <sys/types.h>
#endif

namespace swg {

enum class CompatHttpRoute {
  Direct = 0,
  Success,
  Failed,
};

enum class CompatSocketRoute : int {
  Failed = -1,
  Direct = 0,
  Tunnel = 1,
};

void ConfigureCompatBridgeIdentity(std::string client_name,
                                   std::string integration_tag,
                                   std::string http_user_agent = {});

void ConfigureCompatHttpCredentials(std::string certificate_path,
                                    std::string key_path);

CompatHttpRoute CompatHttpRequest(const std::string& url,
                                  std::vector<std::uint8_t>* response_body,
                                  long timeout_seconds,
                                  std::string* error);

#if defined(__SWITCH__) || defined(SWG_PLATFORM_SWITCH)
CompatSocketRoute CompatResolveStreamHost(const std::string& host,
                                          std::uint16_t port,
                                          struct sockaddr_storage* addr,
                                          socklen_t* addr_len,
                                          std::string* error = nullptr);
#endif

}  // namespace swg