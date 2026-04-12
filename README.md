# Switch WireGuard Sysmodule

This repository bootstraps the Phase A control plane for a Nintendo Switch WireGuard project.

Current scope:
- CMake-based monorepo layout.
- Shared config, logging, compatibility, and IPC-facing data structures.
- Versioned binary IPC request/response encoding, a real `swg:ctl` CMIF transport on Switch, and an in-process host transport for development.
- Host-side sysmodule, overlay, and manager stubs that exercise the same control-plane ABI without requiring device deployment.
- A Switch-side manager NRO that can query `swg:ctl`, change the active profile, toggle runtime flags, and issue connect/disconnect requests on hardware.
- A compatibility report backed by real HOS version and service reachability probes so device-side tools can surface the current firmware/service baseline.
- A placeholder connection state machine with persistence and diagnostics.
- Real X25519-based WireGuard cryptographic preflight using mbedTLS PSA, including local public-key derivation and static peer shared-secret validation.
- A real WireGuard handshake path that builds an initiation packet, exchanges the handshake response over UDP, sends one authenticated post-handshake keepalive, and only then reports `Connected`.
- An app-facing session and route-planning API designed for low-friction consumers such as Moonlight-Switch.

Not implemented yet:
- Tesla UI wiring, deferred from Phase A.
- WireGuard cookie replies, retries/rekeys, and a persistent transport packet loop.
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

Manual live host handshake probe against a real config and server:

```sh
./build/host-debug/tests/swg_live_handshake_probe --config "$PWD/docs/config.ini"
```

That probe loads a real config file, stages it into an isolated host runtime root, and runs the normal `swg:ctl` host `Connect()` path against the configured endpoint. It is intentionally not part of the default `ctest` suite because it depends on external network reachability and server state.

Deterministic initiation dump and packet comparison:

```sh
./build/host-debug/tests/swg_live_handshake_probe \
	--config "$PWD/docs/config.ini" \
	--dump-initiation "$PWD/test-runtime-live-handshake/initiation.hex" \
	--no-connect
```

```sh
./build/host-debug/tests/swg_live_handshake_probe \
	--config "$PWD/docs/config.ini" \
	--compare-initiation /path/to/reference-initiation.hex \
	--no-connect
```

The comparison mode generates a deterministic initiation packet with fixed sender index, ephemeral private key, and timestamp so exact byte comparison is meaningful. The reference file can be a raw 148-byte packet or a hex dump with whitespace.

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
- `build/switch-debug/manager/swg_manager.nro`
- `build/switch-debug/manager/switch/swg_manager.nro`

The `atmosphere/contents/...` tree is the ready-to-copy SD-card layout for the current sysmodule title ID.
The staged `toolbox.json` allows Tesla's `ovl-sysmodules` overlay to list the sysmodule and toggle its boot flag.
The current metadata marks the sysmodule as dynamic, so `ovl-sysmodules` can start and stop it live with `A`; the boot flag remains a separate persistent toggle in that overlay.

Phase A now ships a real `swg:ctl` service host on Switch.
The manager NRO is the Phase A device frontend.
The overlay remains a host-only stub until Tesla work is picked up later.

Switch runtime files use the `sdmc:/` mount:
- config: `sdmc:/config/swg/config.ini`
- logs: `sdmc:/atmosphere/logs/swg/swg.log`
- early boot marker: `sdmc:/atmosphere/logs/swg/boot_marker.log`

## Creating a config now

Right now, the Switch manager can read and use an existing config, but it cannot create or edit profiles yet.
The practical way to try the current connect path is to manually create `sdmc:/config/swg/config.ini` using the example in [docs/sample-config.ini](/Users/xitrix/Documents/Dev/Switch/WGSysModule/docs/sample-config.ini).

Current constraints:
- `Connect()` now validates real X25519 key material, resolves the IPv4 endpoint, sends a real WireGuard initiation packet, validates the response, and then sends one authenticated keepalive before the service enters `Connected`.
- It still does not implement cookie replies, retransmits, rekeying, or a persistent transport packet loop yet.
- The keys in the sample file are real X25519 test fixtures for cryptographic preflight, not a real peer configuration.

If you want a real peer-ready config for later milestones, generate actual keys on a desktop machine with WireGuard tools and replace the sample values before copying the file to the SD card.

For host-only development, `./build/host-debug/manager/swg_manager_stub sample-profile` now writes a syntactically valid sample profile into the host runtime config.

## Host stub commands

After a host build:

```sh
./build/host-debug/sysmodule/swg_sysmodule_stub status
./build/host-debug/manager/swg_manager_stub sample-profile
./build/host-debug/overlay/swg_overlay_stub status
./build/host-debug/overlay/swg_overlay_stub connect
./build/host-debug/tests/swg_live_handshake_probe --config "$PWD/docs/config.ini"
```

The host runtime creates files under `build/host-debug/runtime/` when executed from the build directory, or `runtime/` from the current working directory.
The live handshake probe uses its own isolated runtime root, prints the derived local and configured peer public keys before connect, and is useful for separating host-side protocol behavior from Switch BSD or connectivity issues.
It can also emit a deterministic initiation packet dump for side-by-side comparison with a reference client or server capture.

## Phase A status

Phase A is currently defined around a manager-first control plane. Tesla integration is intentionally deferred until later milestones.
Milestones 0 through 3 are now complete. Milestone 4 is the active implementation slice.

Implemented:
- sysmodule control stub
- config load/save + validation
- logging
- stable SDK client surface
- versioned IPC message encoding + in-process transport bridge
- real `swg:ctl` service registration and CMIF envelope transport on Switch
- Switch manager NRO for on-device control-plane validation
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
- manager UX expansion
- WireGuard cookie reply handling, retries/rekeys, and a persistent transport packet loop on top of the new handshake plus keepalive path
- firmware-specific routing hooks and DNS/tunnel integration
- Tesla UI integration later
