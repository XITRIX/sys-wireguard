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
| DNS MITM | Active lab | Normal `switch-debug` installs an active `sfdnsres` Atmosphere MITM replacement, loads Atmosphere-compatible hosts/settings, redirects matching hosts, and forwards unsupported requests |
| `bsd:u` MITM | Query lab | Normal `switch-debug` installs the query hook and fails open; hardware logs show Moonlight starts cleanly with `selected=0`; the manual adapter lab handles only bootstrap/socket bookkeeping commands so far |

## Service assumptions

- No tun/tap device is assumed.
- No Linux route-table or raw-socket behavior is assumed.
- Future service checks must stay centralized in `swg/hos_caps.h` and its implementation.
- `sfdnsres` is the first transparent-mode interception target; `bsd:u` is now a validated query-only lab and still needs UDP/TCP command adapters before it can force traffic through the tunnel.
