#pragma once

#if defined(SWG_PLATFORM_SWITCH)

#include <switch.h>

namespace swg::sysmodule {

bool IsExperimentalMitmObserverBuildEnabled();
::Result StartExperimentalMitmObserverThread();
void ShutdownExperimentalMitmObserver();

}  // namespace swg::sysmodule

#endif
