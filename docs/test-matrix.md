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
| WireGuard handshake round-trip | Verified | `swg_tests` now covers initiation build, responder processing, and initiator response validation in-process |
| Live real-config handshake probe | Manual | `build/host-debug/tests/swg_live_handshake_probe --config "$PWD/docs/config.ini"` exercises the real host `Connect()` path against a live endpoint without making `ctest` depend on external network state |
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
| Connect/disconnect loop | In progress | `Connect()` now resolves the IPv4 endpoint, sends a real initiation packet, validates the handshake response, sends one authenticated keepalive, and only then reports `Connected`; broader sustained transport traffic is the next on-device check |
