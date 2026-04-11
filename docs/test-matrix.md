# Test Matrix

## Host-side

| Check | Status | Notes |
| --- | --- | --- |
| CMake configure | Verified | `cmake --preset host-debug` succeeds on macOS |
| CMake build | Verified | `cmake --build --preset host-debug` succeeds on macOS |
| Config round-trip | Verified | Covered by `swg_tests` |
| State transitions | Verified | Covered by `swg_tests` |
| IPC codec round-trip | Verified | Covered by `swg_tests` using request/response encoding helpers |
| SDK client host binding | Verified | Regression-covered in `swg_tests` |
| Moonlight route planning | Verified | Covered by `swg_tests` using app-session helpers |
| Overlay/manager smoke flow | Verified | `sample-profile`, `status`, and `connect` commands exercised |

## On-device

| Check | Status | Notes |
| --- | --- | --- |
| Switch preset configure | Verified | `cmake --preset switch-debug` succeeds with devkitPro |
| Switch shared-code build | Verified | `cmake --build --preset switch-debug` succeeds for the current libraries, sysmodule package, and manager NRO |
| Sysmodule boot | Verified | Current boot2 package reaches the main loop and emits logs on hardware |
| Switch manager build | Verified | `build/switch-debug/manager/swg_manager.nro` and staged `build/switch-debug/manager/switch/swg_manager.nro` are generated |
| Switch manager control flow | Verified | Manager now queries `swg:ctl` successfully on hardware and surfaces compatibility diagnostics |
| Milestone 3 manager frontend | Verified | Current manager implementation is sufficient to close the manager-first frontend milestone |
| Tesla live start/stop | Deferred | Tesla is intentionally excluded from Phase A; verify later if the overlay path is revived |
| Config survives reboot | Not started | Requires device deployment |
| Overlay queries status | Deferred | Tesla overlay is intentionally outside the current Phase A scope |
| Connect/disconnect loop | In progress | `Connect()` now runs WireGuard preflight validation before using the stub tunnel engine, but handshake and UDP transport are not integrated yet |
