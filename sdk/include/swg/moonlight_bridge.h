#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "swg/compat_bridge.h"

namespace swg {

using MoonlightHttpRoute = CompatHttpRoute;

inline void ConfigureMoonlightHttpCredentials(std::string certificate_path,
                                                                                            std::string key_path) {
    ConfigureCompatHttpCredentials(std::move(certificate_path), std::move(key_path));
}

inline MoonlightHttpRoute MoonlightHttpRequest(const std::string& url,
                                                                                             std::vector<std::uint8_t>* response_body,
                                                                                             long timeout_seconds,
                                                                                             std::string* error) {
    return CompatHttpRequest(url, response_body, timeout_seconds, error);
}

}  // namespace swg