# Switch WireGuard Sysmodule

This repository bootstraps the Phase A control plane for a Nintendo Switch WireGuard project.

Current scope:
- CMake-based monorepo layout.
- Shared config, logging, compatibility, and IPC-facing data structures.
- Host-side sysmodule, overlay, and manager stubs that exercise the control plane without requiring a Switch target yet.
- A placeholder connection state machine with persistence and diagnostics.
- An app-facing session and route-planning API designed for low-friction consumers such as Moonlight-Switch.

Not implemented yet:
- Real libnx service registration.
- Tesla UI wiring.
- WireGuard protocol engine.
- Transparent routing or MITM paths.

## Repository layout

- `common`: shared structs, config parsing, logging, compatibility helpers, and state machine.
- `sysmodule`: local control-service implementation used as the Phase A sysmodule stub.
- `sdk`: client API that other components consume.
- `overlay`: host-side overlay stub consuming the SDK API only.
- `manager`: host-side manager CLI for heavier config operations.
- `docs`: architecture, tasks, compatibility, debugging, and test notes.
- `tests`: host-side regression coverage for config and state behavior.

## Build

Host development build:

```sh
cmake --preset host-debug
cmake --build --preset host-debug
ctest --preset host-debug
```

Switch-target configuration slice:

```sh
cmake --preset switch-debug
```

The `switch-debug` preset uses `$DEVKITPRO/cmake/Switch.cmake`. At this stage it configures shared code and project structure only; libnx- and Tesla-backed binaries are intentionally deferred until the control plane stabilizes.

## Host stub commands

After a host build:

```sh
./build/host-debug/sysmodule/swg_sysmodule_stub status
./build/host-debug/manager/swg_manager_stub sample-profile
./build/host-debug/overlay/swg_overlay_stub status
./build/host-debug/overlay/swg_overlay_stub connect
```

The host runtime creates files under `build/host-debug/runtime/` when executed from the build directory, or `runtime/` from the current working directory.

## Phase A status

Implemented:
- sysmodule control stub
- config load/save + validation
- logging
- stable SDK client surface
- app-session and route-planning SDK surface
- overlay/manager stubs wired through the client API
- placeholder connection state machine

## App integration

The SDK now exposes a generic `swg::AppSession` wrapper and a route-planning surface for app consumers that still use their own sockets and HTTP stack.

Moonlight-oriented helpers are provided in `sdk/include/swg/moonlight.h`:
- open an app session with `MakeMoonlightSessionRequest()`
- plan local discovery and Wake-on-LAN as direct bypass traffic
- plan HTTPS control, stream-control, video, audio, and input traffic as tunnel-required
- plan DNS through the tunnel when the profile enables it

This keeps the sysmodule consumer API aligned with Moonlight-Switch's current architecture, where libcurl and direct sockets remain in the app while the sysmodule decides whether traffic should use the tunnel, bypass it, or fail closed.

Next:
- real Switch IPC registration and ABI packing
- Tesla UI integration
- libnx capability probes and firmware-specific routing hooks
