# Task Board

## Completed

- Repository skeleton created with CMake presets and per-component `CMakeLists.txt` files.
- Shared Phase A headers and source files added for config, logging, IPC structs, compatibility, and state handling.
- Local sysmodule control-service stub implemented.
- SDK client stub implemented.
- App-session and route-planning SDK surface implemented.
- Moonlight-Switch helper functions added to the SDK.
- Versioned IPC codec and host in-process transport adapter implemented.
- Real `swg:ctl` service registration and CMIF envelope transport implemented for Switch builds.
- Switch `swg_sysmodule.nsp` ExeFS packaging target added to the CMake `switch-debug` preset.
- Switch manager NRO target added for on-device control-plane validation through `swg:ctl`.
- Manager frontend now satisfies the current Milestone 3 definition of done for the manager-first Phase A plan.
- Real HOS and service reachability probes added to the compatibility report used by the manager and control API.
- Initial Milestone 4 slice added: WireGuard profile preflight validation plus a tunnel-engine integration boundary behind `Connect()`.
- Current Milestone 4 preflight now parses endpoint literals, CIDR networks, interface addresses, and numeric DNS servers into prepared session data.
- WireGuard profile preflight now performs real X25519 cryptographic validation: local public-key derivation plus static peer shared-secret validation via mbedTLS PSA.
- The tunnel-engine seam now prepares an explicit IPv4-only session plan for current Switch transport, keeps hostname endpoints resolution-pending, and records skipped IPv6-only inputs instead of pretending they are usable on-device.
- Prepared tunnel sessions now have an IPv4 endpoint-resolution helper for future transport wiring, with host tests covering both numeric and `localhost` endpoint resolution without changing current connect behavior.
- The engine scaffold now initializes a bounded BSD socket runtime and opens a connected IPv4 UDP socket for the resolved endpoint, giving Milestone 4 a real transport lifecycle without yet attempting a WireGuard handshake.
- The BSD runtime now prefers libnx's `bsd:u` defaults and emits staged on-device diagnostics for service access, transfer-memory setup, client registration, and monitor startup when initialization fails.
- The sysmodule runtime now allocates a 4 MiB process heap through `svcSetHeapSize`, and BSD startup diagnostics report that heap budget alongside the required transfer-memory size after the old 512 KiB inner heap proved too small.
- Overlay and manager host stubs implemented.
- Host-side tests added for config and state transitions.
- Host configure, build, test, and control-plane smoke checks verified on macOS.
- Switch preset configure and deployable sysmodule build verified with devkitPro.

## Next slices

- Expand the Switch manager beyond the current console UI if a richer device-side control surface is needed before Tesla.
- Replace the stub tunnel-engine backend with real WireGuard handshake and transport integration.
- Add BLAKE2s, HKDF/mix helpers, and handshake packet assembly on top of the new X25519 cryptographic preflight.
- Feed packets through the connected UDP socket and add bounded TX/RX buffers for the future handshake loop.
- Accept or deliberately reject additional endpoint/DNS formats once the real handshake backend defines those constraints.
- Add real tunnel-aware DNS resolution results for app consumers.
- Add a Tesla frontend target later, once the manager-first path and tunnel milestones are stable and libtesla is wired into the build.
