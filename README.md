# Switch WireGuard Sysmodule

This repository bootstraps the Phase A control plane for a Nintendo Switch WireGuard project.

Current scope:
- CMake-based monorepo layout.
- Shared config, logging, compatibility, and IPC-facing data structures.
- Versioned binary IPC request/response encoding, a real `swg:ctl` CMIF transport on Switch, and an in-process host transport for development.
- Host-side sysmodule, overlay, and manager stubs that exercise the same control-plane ABI without requiring device deployment.
- A placeholder connection state machine with persistence and diagnostics.
- An app-facing session and route-planning API designed for low-friction consumers such as Moonlight-Switch.

Not implemented yet:
- Tesla UI wiring.
- WireGuard protocol engine.
- Transparent routing or MITM paths.

## Repository layout

- `common`: shared structs, config parsing, logging, compatibility helpers, and state machine.
- `sysmodule`: control-service implementation and the Switch-side `swg:ctl` service host.
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
cmake --build --preset switch-debug
```

The `switch-debug` preset uses `$DEVKITPRO/cmake/Switch.cmake` and now produces:
- `build/switch-debug/sysmodule/swg_sysmodule.nsp`
- `build/switch-debug/sysmodule/atmosphere/contents/00FF53574743544C/exefs.nsp`
- `build/switch-debug/sysmodule/atmosphere/contents/00FF53574743544C/flags/boot2.flag`
- `build/switch-debug/sysmodule/atmosphere/contents/00FF53574743544C/toolbox.json`

The `atmosphere/contents/...` tree is the ready-to-copy SD-card layout for the current sysmodule title ID.
The staged `toolbox.json` allows Tesla's `ovl-sysmodules` overlay to list the sysmodule and toggle its boot flag.

Phase A now ships a real `swg:ctl` service host on Switch. Overlay and manager remain host-only stubs until the Tesla and homebrew frontend targets are wired in.

Switch runtime files use the `sdmc:/` mount:
- config: `sdmc:/config/swg/config.ini`
- logs: `sdmc:/atmosphere/logs/swg/swg.log`
- early boot marker: `sdmc:/atmosphere/logs/swg/boot_marker.log`

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
- versioned IPC message encoding + in-process transport bridge
- real `swg:ctl` service registration and CMIF envelope transport on Switch
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
- Tesla UI integration
- libnx capability probes and firmware-specific routing hooks
