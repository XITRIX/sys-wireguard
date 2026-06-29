#pragma once

#if defined(SWG_PLATFORM_SWITCH)

#include <switch.h>

#include <memory>

namespace swg {

class IControlService;

namespace sysmodule {

bool IsExperimentalMitmObserverBuildEnabled();
::Result StartExperimentalMitmObserverThread(std::shared_ptr<IControlService> control_service = {});
void ShutdownExperimentalMitmObserver();

}  // namespace sysmodule
}  // namespace swg

#endif
