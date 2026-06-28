#pragma once

#include <filesystem>
#include <functional>
#include <memory>

#include "swg/control_service.h"

namespace swg::sysmodule {

class IWgTunnelEngine;

using ShutdownCallback = std::function<void()>;

std::shared_ptr<IControlService> CreateLocalControlService(const std::filesystem::path& runtime_root = {},
                                                           ShutdownCallback shutdown_callback = {});
std::shared_ptr<IControlService> CreateLocalControlServiceForTest(
	std::unique_ptr<IWgTunnelEngine> tunnel_engine,
	const std::filesystem::path& runtime_root = {});

}  // namespace swg::sysmodule
