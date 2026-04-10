# Architecture Summary

## Phase A intent

Phase A establishes a stable control plane before any real tunnel engine or transparent-routing work.

Current implementation boundaries:
- `swg_common`: config schema, logging, state machine, compatibility probes, and IPC-facing structs.
- `swg_common` also owns the request/response codec and command dispatcher used by the current `swg:ctl` ABI.
- `swg_sysmodule_core`: a local control-service stub that behaves like the future `swg:ctl` owner.
- `swg_sdk`: the client layer used by overlay and manager code, including a libnx-backed transport for Switch builds.
- `swg::AppSession`: an app-facing lifecycle wrapper for route planning and future per-app tunnel control.
- `swg_overlay_stub`: a host-side stand-in for the future Tesla overlay.
- `swg_manager_stub`: a host-side config-management CLI.
- `swg_manager_switch`: a Switch homebrew NRO that talks to `swg:ctl` over the same SDK transport as future device-side frontends.

## Key decisions

- No Linux tun/tap assumptions appear in the codebase.
- Config, runtime state, and logging are centralized in the sysmodule service boundary.
- The overlay stub talks through the SDK client, not by mutating files directly.
- Host execution is a first-class development mode so the control plane can be tested without device-only dependencies.
- Firmware and service assumptions are isolated behind `swg/hos_caps.h` and documented separately.
- App-facing routing decisions are exposed as a stable control-plane concern before transparent MITM exists.
- Moonlight-Switch compatibility is treated as a concrete design constraint for the SDK surface.
- Host tools now use an in-process transport adapter that marshals requests through the shared IPC envelope instead of calling the service implementation directly.
- Switch builds now register `swg:ctl` through `smRegisterService(...)` and carry the existing binary envelope over one CMIF command with alias buffers.
- The first on-device control consumer is a plain console manager app so service validation does not depend on libtesla yet.

## Runtime paths

Host development paths:
- root: `runtime/`
- config: `runtime/config/swg/config.ini`
- logs: `runtime/logs/swg/swg.log`

Planned Switch paths:
- config: `/config/swg/config.ini`
- logs: `/atmosphere/logs/swg/swg.log`
- manager app: `sdmc:/switch/swg_manager.nro`

Switch service packaging:
- service name: `swg:ctl`
- CMake output: `build/switch-debug/sysmodule/swg_sysmodule.nsp`
- Atmosphere install path: `sdmc:/atmosphere/contents/00FF53574743544C/exefs.nsp`
- boot flag: `sdmc:/atmosphere/contents/00FF53574743544C/flags/boot2.flag`

## Control flow

1. The sysmodule stub initializes logging.
2. It discovers or creates config.
3. Validation runs before state is exposed.
4. The connection state machine owns the public runtime state.
5. The SDK client consumes the same control-service API the overlay and manager use.
6. App consumers can open scoped sessions and ask the sysmodule for per-traffic routing decisions.
7. Host-side tools and tests pass through the same versioned command envelope the Switch service now exposes through `swg:ctl`.
8. The Switch manager NRO uses the same client transport and IPC envelope as other consumers, so it doubles as the first on-device integration test for the control plane.

## Moonlight-oriented app API

Moonlight-Switch already uses libcurl, direct sockets, local discovery, STUN, and Wake-on-LAN. The current SDK therefore supports a low-friction integration model:
- local discovery and Wake-on-LAN can stay direct
- remote stream traffic can be marked tunnel-required
- DNS can be marked tunnel-preferred
- future transparent routing can replace some of those explicit decisions later without changing the service contract

## What is intentionally deferred

- Tesla rendering and input handling
- WireGuard engine integration
- DNS-over-tunnel and MITM logic
- policy-driven transparent routing
