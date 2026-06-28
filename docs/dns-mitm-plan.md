# DNS MITM Slice

## Intent

The first transparent-routing MITM slice should target `sfdnsres`, not `bsd:u`.

That keeps the interception surface narrow, lets the current tunnel-aware DNS path stay the answer engine, and avoids coupling early transparent-mode work to the full socket API before we have enough observability.

## External references used

- Atmosphere `ams_mitm` `dns_mitm`: relevant for service registration shape, per-client `ShouldMitm` gating, resolver command selection, and buffer-forwarding patterns.
- `network_mitm`: useful only as a reminder that subobject MITM should be config-gated and cheap when disabled. It is SSL-only and not a direct routing reference.

## Scope

Current DNS MITM replacement does the following:

- install an Atmosphere MITM server for `sfdnsres`
- return `ShouldMitm=true` for resolver clients when the replacement is enabled
- load Atmosphere-compatible hosts/settings on-device
- synthesize matching hosts-file A/hostent answers
- forward unchanged when a hostname is unmatched or a request shape is unsupported
- later answer selected A-record lookups through the existing tunnel-DNS path

## Atmosphere-Compatible Replacement Core

Before SWG can safely replace Atmosphere's built-in DNS MITM, it must preserve Atmosphere's documented DNS protection behavior:

- default telemetry hosts redirect to `127.0.0.1`
- `%` expands to the active `nsd!environment_identifier` value, normally `lp1` on production devices
- `*` is a hostname wildcard
- later matching hosts rules override earlier rules
- the selected hosts file is loaded after defaults unless add-defaults is disabled
- host files are searched in the emummc/sysmmc/default order documented by Atmosphere

The current implementation covers this rules layer in `swg_sysmodule_core`, host tests, and the Switch-side active `sfdnsres` proxy.

## Non-goals for the first slice

- no `bsd:u` or `bsd:s` interception
- no broad resolver feature parity on day one
- no AAAA synthesis or full IPv6 behavior in the first milestone
- no new independent DNS engine inside the sysmodule
- no direct file mutation by clients outside `swg:ctl`

## Recommended command focus

Prioritize the resolver commands that matter most for app traffic:

1. `GetHostByNameRequest`
2. `GetHostByNameRequestWithOptions`
3. `GetAddrInfoRequest`
4. `GetAddrInfoRequestWithOptions`

Anything else should forward untouched unless a specific title proves it is required.

## Proposed repo shape

Current shared files:

- `sysmodule/include/swg_sysmodule/experimental_mitm.h`
- `sysmodule/src/experimental_mitm.cpp`
- `sysmodule/include/swg_sysmodule/experimental_dns_mitm.h`
- `sysmodule/src/experimental_dns_mitm.cpp`

Current Switch activation file:

- `sysmodule/src/mitm_observer_switch.cpp`

The normal Switch debug preset now builds this activation path. A non-MITM build remains possible only by turning `SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER=OFF` manually.

## Request flow

1. Atmosphere MITM accepts an `sfdnsres` session and captures `MitmProcessInfo`.
2. `ShouldMitm` applies a conservative default policy: application clients only unless a future `mitm_all_clients` feature flag is enabled.
3. The resolver command is classified into an internal request kind.
4. The DNS MITM planner decides one of three actions:
   - forward unchanged
   - resolve through the active WireGuard tunnel
   - synthesize failure later if fail-closed behavior is explicitly requested
5. When the action is `resolve through the active WireGuard tunnel`, the implementation should reuse the current tunnel-DNS machinery behind `ResolveDns()` rather than creating a second resolver stack.

## Rollout order

### Stage 0

- research complete
- shared scaffold compiled into `swg_sysmodule_core`
- host tests cover policy, planning, hosts matching, and resolver serialization

### Stage 1a

- `sfdnsres` MITM query hook installs in the normal Switch debug build
- `bsd:u` query-only MITM installs in the normal Switch debug build
- service-open observation logs client program IDs, process IDs, override flags, service name, and query counters
- hardware logs confirm Moonlight-Switch opens `bsd:u` with `selected=0` and does not crash or freeze

### Stage 1a.5

- load Atmosphere-compatible DNS hosts/settings on-device
- create `/atmosphere/hosts/default.txt` with the default telemetry rules when missing
- honor add-defaults and debug-log settings before taking ownership of resolver sessions
- emit startup diagnostics for the selected hosts file and loaded redirect rules

### Stage 1b

- Switch-only `sfdnsres` active proxy accepts selected sessions in the normal MITM debug build
- debug-log mode records client program IDs, hostnames, request kind, and decision
- unmatched or unsupported requests forward untouched

### Stage 2

- matched A-record queries resolve through the active tunnel-DNS path
- fail-open behavior remains the default
- stats increment query, fallback, and leak-prevention counters

### Stage 3

- explicit fail-open and fail-closed policy
- per-title overrides
- optional small cache if it proves necessary

### Stage 4

- keep the normal `bsd:u` query lab fail-open, then replace individual socket commands in the manual adapter lab with tunnel-backed adapters

## Key constraints

- the stable control plane remains the source of truth; MITM code must not bypass `swg:ctl`-owned runtime state
- query handling must remain bounded and allocation-aware
- unsupported resolver behaviors should forward or fail explicitly, never silently guess
- title-based policy should stay separate from tunnel cryptography and packet transport

## Immediate next implementation tasks

1. confirm telemetry hosts still resolve to loopback through the SWG replacement
2. connect matched non-Atmosphere DNS policy to the current `ResolveDns()` and tunnel-DNS stats
3. implement tunnel-backed UDP `bsd:u` adapters for `sendto`/`recvfrom` plus poll/select readiness in the manual adapter lab
4. add TCP `connect`/`send`/`recv` adapters after the UDP path has a clean hardware trace
