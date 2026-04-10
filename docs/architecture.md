# Architecture Summary

## Phase A intent

Phase A establishes a stable control plane before any real tunnel engine or transparent-routing work.

Current implementation boundaries:
- `swg_common`: config schema, logging, state machine, compatibility probes, and IPC-facing structs.
- `swg_sysmodule_core`: a local control-service stub that behaves like the future `swg:ctl` owner.
- `swg_sdk`: the client layer used by overlay and manager code.
- `swg::AppSession`: an app-facing lifecycle wrapper for route planning and future per-app tunnel control.
- `swg_overlay_stub`: a host-side stand-in for the future Tesla overlay.
- `swg_manager_stub`: a host-side config-management CLI.

## Key decisions

- No Linux tun/tap assumptions appear in the codebase.
- Config, runtime state, and logging are centralized in the sysmodule service boundary.
- The overlay stub talks through the SDK client, not by mutating files directly.
- Host execution is a first-class development mode so the control plane can be tested without device-only dependencies.
- Firmware and service assumptions are isolated behind `swg/hos_caps.h` and documented separately.
- App-facing routing decisions are exposed as a stable control-plane concern before transparent MITM exists.
- Moonlight-Switch compatibility is treated as a concrete design constraint for the SDK surface.

## Runtime paths

Host development paths:
- root: `runtime/`
- config: `runtime/config/swg/config.ini`
- logs: `runtime/logs/swg/swg.log`

Planned Switch paths:
- config: `/config/swg/config.ini`
- logs: `/atmosphere/logs/swg/swg.log`

## Control flow

1. The sysmodule stub initializes logging.
2. It discovers or creates config.
3. Validation runs before state is exposed.
4. The connection state machine owns the public runtime state.
5. The SDK client consumes the same control-service API the overlay and manager use.
6. App consumers can open scoped sessions and ask the sysmodule for per-traffic routing decisions.

## Moonlight-oriented app API

Moonlight-Switch already uses libcurl, direct sockets, local discovery, STUN, and Wake-on-LAN. The current SDK therefore supports a low-friction integration model:
- local discovery and Wake-on-LAN can stay direct
- remote stream traffic can be marked tunnel-required
- DNS can be marked tunnel-preferred
- future transparent routing can replace some of those explicit decisions later without changing the service contract

## What is intentionally deferred

- real `swg:ctl` registration and IPC marshalling
- Tesla rendering and input handling
- WireGuard engine integration
- DNS-over-tunnel and MITM logic
- policy-driven transparent routing
