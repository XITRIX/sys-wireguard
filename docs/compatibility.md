# Compatibility Matrix

## Target policy

- Target firmware family: HOS 21.x+
- Target Atmosphere family: current stable releases matching HOS 21.x+
- Target toolchain: current devkitPro + libnx with updated TLS ABI support

## Current implementation state

| Area | Status | Notes |
| --- | --- | --- |
| Host build | Implemented | Used for Phase A control-plane development and tests |
| Switch configure preset | Implemented | Uses `$DEVKITPRO/cmake/Switch.cmake` |
| libnx service registration | Implemented | `swg:ctl` is registered on Switch and exercised by the manager app |
| Tesla integration | Deferred | Intentionally excluded from Phase A; host overlay stub only for now |
| DNS MITM | Scaffolded | Dormant `sfdnsres` planning code exists in `swg_sysmodule_core`, but no Switch-side MITM server is installed yet |
| `bsd:u` MITM | Planned | Deferred until DNS MITM stabilizes and direct `bsd:u` probing exists |

## Service assumptions

- No tun/tap device is assumed.
- No Linux route-table or raw-socket behavior is assumed.
- Future service checks must stay centralized in `swg/hos_caps.h` and its implementation.
- `sfdnsres` is the first transparent-mode interception target; `bsd:u` remains a later experimental step.
