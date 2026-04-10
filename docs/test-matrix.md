# Test Matrix

## Host-side

| Check | Status | Notes |
| --- | --- | --- |
| CMake configure | Verified | `cmake --preset host-debug` succeeds on macOS |
| CMake build | Verified | `cmake --build --preset host-debug` succeeds on macOS |
| Config round-trip | Verified | Covered by `swg_tests` |
| State transitions | Verified | Covered by `swg_tests` |
| SDK client host binding | Verified | Regression-covered in `swg_tests` |
| Moonlight route planning | Verified | Covered by `swg_tests` using app-session helpers |
| Overlay/manager smoke flow | Verified | `sample-profile`, `status`, and `connect` commands exercised |

## On-device

| Check | Status | Notes |
| --- | --- | --- |
| Switch preset configure | Verified | `cmake --preset switch-debug` succeeds with devkitPro |
| Switch shared-code build | Verified | `cmake --build --preset switch-debug` succeeds for current libraries |
| Sysmodule boot | Not started | Requires libnx/sysmodule target |
| Config survives reboot | Not started | Requires device deployment |
| Overlay queries status | Not started | Requires Tesla target |
| Connect/disconnect loop | Not started | Placeholder state machine only |
