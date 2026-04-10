#pragma once

#include <filesystem>
#include <memory>

#include "swg/control_service.h"

namespace swg::sysmodule {

std::shared_ptr<IControlService> CreateLocalControlService(const std::filesystem::path& runtime_root = {});

}  // namespace swg::sysmodule
