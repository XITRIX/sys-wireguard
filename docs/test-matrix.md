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
| WireGuard keepalive scheduling | Verified | `swg_tests` now validates the immediate post-handshake keepalive plus one scheduled keepalive and checks live stats growth |
| Inbound authenticated keepalive stats | Verified | `swg_tests` now sends one responder-side authenticated keepalive after connect and waits for live `GetStats()` counters to reflect it |
| Inbound authenticated payload stats | Verified | `swg_tests` now sends one responder-side authenticated non-empty transport packet after connect and waits for live `GetStats()` counters to reflect it |
| Engine inbound payload queue | Verified | `swg_tests` now drains one validated payload packet from the bounded engine receive queue after connect |
| App-session packet send | Verified | `swg_tests` now sends one authenticated payload packet through `AppSession::SendPacket()` over the marshalled host transport and validates it at a local responder |
| App-session packet receive | Verified | `swg_tests` now drains one validated payload packet through `AppSession::ReceivePacket()` over the marshalled host transport |
| App-session sustained traffic | Verified | `swg_tests` now repeats authenticated `AppSession::SendPacket()` / `ReceivePacket()` calls over one connected session and checks transport counters plus stats growth across multiple packets |
| Engine reconnect after send failure | Verified | `swg_tests` uses a scripted UDP runtime to force one outbound transport send failure, then verifies the engine re-handshakes with backoff and retries the payload successfully |
| Engine reconnect after receive failure | Verified | `swg_tests` uses a scripted UDP runtime to force one receive-loop transport failure, then verifies the engine re-handshakes and remains usable |
| Engine reconnect after keepalive failure | Verified | `swg_tests` uses a scripted UDP runtime to force one periodic keepalive send failure, then verifies the engine re-handshakes and remains usable |
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
| Connect/disconnect loop | In progress | `Connect()` now resolves the IPv4 endpoint, sends a real initiation packet, validates the handshake response, sends an authenticated keepalive, can schedule periodic keepalives, exposes authenticated payload send/receive through `swg:ctl`, has host regression coverage for repeated app-session traffic, and now has bounded reconnect coverage for send, receive, and keepalive transport failures; the next gap is confirming the same recovery behavior on hardware |
