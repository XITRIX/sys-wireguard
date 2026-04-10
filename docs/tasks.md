# Task Board

## Completed

- Repository skeleton created with CMake presets and per-component `CMakeLists.txt` files.
- Shared Phase A headers and source files added for config, logging, IPC structs, compatibility, and state handling.
- Local sysmodule control-service stub implemented.
- SDK client stub implemented.
- App-session and route-planning SDK surface implemented.
- Moonlight-Switch helper functions added to the SDK.
- Overlay and manager host stubs implemented.
- Host-side tests added for config and state transitions.
- Host configure, build, test, and control-plane smoke checks verified on macOS.
- Switch preset configure and shared-code cross-build verified with devkitPro.

## Next slices

- Define packed IPC request and response structs for a real `swg:ctl` ABI.
- Carry the app-session and network-plan API over that real IPC ABI.
- Replace the local service injection path with libnx service transport.
- Add a Tesla frontend target once libtesla is wired into the build.
- Extend compatibility probing with real libnx and HOS service checks.
- Add richer validation errors for endpoint and address formats.
- Add real tunnel-aware DNS resolution results for app consumers.
