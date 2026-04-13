#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "swg/compat_bridge.h"

namespace swg {

using MoonlightHttpRoute = CompatHttpRoute;

void ConfigureMoonlightHttpCredentials(std::string certificate_path,
                                       std::string key_path);

MoonlightHttpRoute MoonlightHttpRequest(const std::string& url,
                                        std::vector<std::uint8_t>* response_body,
                                        long timeout_seconds,
                                        std::string* error);

}  // namespace swg