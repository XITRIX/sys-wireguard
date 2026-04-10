#pragma once

#include <memory>

#include "swg/client_transport.h"

namespace swg {

std::shared_ptr<IClientTransport> CreateSwitchControlTransport();

}  // namespace swg