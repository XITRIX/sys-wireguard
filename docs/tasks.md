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
- The engine now initializes a bounded BSD socket runtime, sends a real WireGuard initiation packet over UDP, validates the handshake response, sends one authenticated post-handshake keepalive, and only then reports `Connected`.
- Connected sessions now schedule authenticated WireGuard keepalives from the configured `persistent_keepalive` interval, and `GetStats()` now reports live engine traffic while the tunnel remains active.
- The engine now accepts authenticated inbound WireGuard keepalives from the validated peer endpoint and folds them into live tunnel stats while connected.
- The shared transport layer now authenticates non-empty WireGuard transport packets too, and the engine now stores validated inbound payload packets in a bounded internal receive queue while folding them into live stats.
- The control plane now exposes that bounded receive queue through `swg:ctl::RecvPacket`, `Client::RecvPacket()`, and `AppSession::ReceivePacket()` with host regression coverage through the marshalled transport path.
- The control plane now also exposes outbound authenticated transport through `swg:ctl::SendPacket`, `Client::SendPacket()`, and `AppSession::SendPacket()`, and host regression coverage now validates an app-session payload end to end against a local responder.
- Host regression coverage now also exercises repeated app-session authenticated send/receive traffic across a single connected session and validates transport counters plus stats growth over multiple packets.
- The engine now performs a bounded reconnect with backoff when an outbound authenticated transport send hits an I/O failure, and a scripted host runtime test verifies that it re-handshakes and retries the payload successfully.
- The engine now also routes receive-loop transport failures and periodic keepalive send failures through the same bounded reconnect path, with scripted host runtime tests covering both recovery triggers.
- A separate Switch integration app now stages as its own NRO and exercises the real `swg::Client` plus `swg::AppSession` flow on hardware without coupling test scenarios to the manager UI.
- The SDK and control service now expose a route-aware `ResolveDns` helper that resolves direct-safe hosts locally, fails closed before connect when tunnel DNS is required, and returns tunnel-DNS guidance plus configured profile resolvers once the tunnel is up.
- A manual host live-handshake probe now loads a real config file and runs the same local-control-service `Connect()` path against a live endpoint for off-device handshake validation.
- The BSD runtime now prefers libnx's `bsd:u` defaults and emits staged on-device diagnostics for service access, transfer-memory setup, client registration, and monitor startup when initialization fails.
- The sysmodule runtime now allocates a 4 MiB process heap through `svcSetHeapSize`, and BSD startup diagnostics report that heap budget alongside the required transfer-memory size after the old 512 KiB inner heap proved too small.
- Overlay and manager host stubs implemented.
- Host-side tests added for config and state transitions.
- Host configure, build, test, and control-plane smoke checks verified on macOS.
- Switch preset configure and deployable sysmodule build verified with devkitPro.

## Next slices

- Expand the Switch manager beyond the current console UI if a richer device-side control surface is needed before Tesla.
- Add WireGuard cookie reply handling on top of the current one-shot handshake path.
- Run the broadened reconnect paths on-device and confirm the same bounded recovery behavior under Horizon BSD.
- Run the new Switch integration app against a working VPN peer and record on-device connect, route-plan, and diagnostic payload results.
- Accept or deliberately reject additional endpoint/DNS formats once the real handshake backend defines those constraints.
- Expose the new DNS resolve helper through the Switch integration app so on-device Moonlight-style flows can validate it directly.
- Finish the rest of Milestone 6 with a higher-level socket or stream abstraction and a concrete usage example app.
- Add a Tesla frontend target later, once the manager-first path and tunnel milestones are stable and libtesla is wired into the build.
