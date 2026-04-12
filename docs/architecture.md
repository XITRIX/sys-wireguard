# Architecture Summary

## Phase A intent

Phase A establishes a stable control plane and manager frontend before any real tunnel engine, Tesla overlay work, or transparent-routing work.

Current implementation boundaries:
- `swg_common`: config schema, logging, state machine, compatibility probes, and IPC-facing structs.
- `swg_common` also owns the request/response codec and command dispatcher used by the current `swg:ctl` ABI.
- `swg_sysmodule_core`: a local control-service stub that behaves like the future `swg:ctl` owner.
- `swg_sdk`: the client layer used by overlay and manager code, including a libnx-backed transport for Switch builds.
- `swg::AppSession`: an app-facing lifecycle wrapper for route planning, send/receive packet calls, and future per-app tunnel control.
- `swg_integration_switch`: a dedicated Switch-side integration harness that exercises the app-facing SDK path separately from the manager UI.
- `swg_overlay_stub`: a host-side stand-in for the future Tesla overlay.
- `swg_manager_stub`: a host-side config-management CLI.
- `swg_manager_switch`: a Switch homebrew NRO that talks to `swg:ctl` over the same SDK transport as future device-side frontends.

## Key decisions

- No Linux tun/tap assumptions appear in the codebase.
- Config, runtime state, and logging are centralized in the sysmodule service boundary.
- The overlay stub talks through the SDK client, not by mutating files directly.
- Host execution is a first-class development mode so the control plane can be tested without device-only dependencies.
- A dedicated host live-handshake probe now exists for Milestone 4 diagnosis so a real config can be exercised through the same local control service and tunnel engine path without deploying to hardware.
- Firmware and service assumptions are isolated behind `swg/hos_caps.h` and documented separately.
- App-facing routing decisions are exposed as a stable control-plane concern before transparent MITM exists.
- Moonlight-Switch compatibility is treated as a concrete design constraint for the SDK surface.
- Host tools now use an in-process transport adapter that marshals requests through the shared IPC envelope instead of calling the service implementation directly.
- Switch builds now register `swg:ctl` through `smRegisterService(...)` and carry the existing binary envelope over one CMIF command with alias buffers.
- The manager app, not Tesla, is the current Phase A device control surface.
- The new Switch integration app is the current device-side SDK validation surface; it is intentionally separate from the manager so operator controls and app-consumer scenarios do not collapse into one UI.
- Compatibility reporting now probes HOS version and live service reachability on Switch so device-side diagnostics reflect the actual firmware surface.
- `swg_common` now performs real X25519 key derivation and static peer shared-secret validation through mbedTLS PSA as part of WireGuard profile preflight.
- Prepared tunnel sessions now separate profile validation from endpoint resolution, so a later UDP backend can resolve IPv4 hostnames without coupling DNS behavior to the config parser.
- The current engine owns a small BSD socket runtime boundary, resolves IPv4 endpoints, sends a WireGuard initiation packet, validates the handshake response, sends an authenticated post-handshake keepalive, schedules further keepalives from `persistent_keepalive`, moves authenticated transport payloads through bounded send/receive paths that are regression-covered under repeated app-session traffic, and performs a bounded reconnect with backoff for outbound send failures plus worker-path receive and keepalive transport failures.
- The Switch sysmodule now relies on a 4 MiB `svcSetHeapSize`-managed heap rather than a tiny inner fake heap so BSD transfer memory can be allocated in-process.
- Control-service stats now merge live engine counters while connected so manager and future overlay consumers can observe keepalive traffic without disconnecting first.
- The control plane now exposes authenticated transport payload send/receive through `swg:ctl::SendPacket` and `swg:ctl::RecvPacket`, both currently gated by an open app session on the active connected profile.

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
- DNS can be marked tunnel-preferred and resolved through a policy-aware helper
- authenticated payloads can be sent and received through the same `swg::AppSession`
- a route-aware `SessionSocket` wrapper can collapse plan, DNS, and packet-channel selection into one app-facing transport object
- future transparent routing can replace some of those explicit decisions later without changing the service contract

The current tunnel DNS implementation is intentionally conservative: it crafts IPv4 UDP DNS queries inside the WireGuard transport for SDK consumers, parses matching IPv4 A-record answers back out of the receive queue, and leaves broader resolver features to later milestones.

## What is intentionally deferred

- Tesla overlay parity, rendering, and input handling
- WireGuard cookie handling plus later rekey or roaming policy
- DNS-over-tunnel and MITM logic
- policy-driven transparent routing
