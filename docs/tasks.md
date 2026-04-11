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
- Overlay and manager host stubs implemented.
- Host-side tests added for config and state transitions.
- Host configure, build, test, and control-plane smoke checks verified on macOS.
- Switch preset configure and deployable sysmodule build verified with devkitPro.

## Next slices

- Expand the Switch manager beyond the current console UI if a richer device-side control surface is needed before Tesla.
- Replace the stub tunnel-engine backend with real WireGuard handshake and transport integration.
- Add richer validation errors for endpoint and address formats.
- Add real tunnel-aware DNS resolution results for app consumers.
- Add a Tesla frontend target later, once the manager-first path and tunnel milestones are stable and libtesla is wired into the build.
