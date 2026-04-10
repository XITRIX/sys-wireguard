#pragma once

#include <filesystem>
#include <memory>

#include "swg/client_transport.h"
#include "swg/control_service.h"

namespace swg::sysmodule {

std::shared_ptr<IClientTransport> CreateHostInProcessTransport(const std::shared_ptr<IControlService>& service);
std::shared_ptr<IClientTransport> CreateLocalControlTransport(const std::filesystem::path& runtime_root = {});

}  // namespace swg::sysmodule
