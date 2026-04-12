#pragma once

#include <filesystem>
#include <memory>

#include "swg/control_service.h"

namespace swg::sysmodule {

class IWgTunnelEngine;

std::shared_ptr<IControlService> CreateLocalControlService(const std::filesystem::path& runtime_root = {});
std::shared_ptr<IControlService> CreateLocalControlServiceForTest(
	std::unique_ptr<IWgTunnelEngine> tunnel_engine,
	const std::filesystem::path& runtime_root = {});

}  // namespace swg::sysmodule
