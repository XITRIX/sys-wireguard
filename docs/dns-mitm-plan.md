# DNS MITM Slice

## Intent

The first transparent-routing MITM slice should target `sfdnsres`, not `bsd:u`.

That keeps the interception surface narrow, lets the current tunnel-aware DNS path stay the answer engine, and avoids coupling early transparent-mode work to the full socket API before we have enough observability.

## External references used

- Atmosphere `ams_mitm` `dns_mitm`: relevant for service registration shape, per-client `ShouldMitm` gating, resolver command selection, and buffer-forwarding patterns.
- `network_mitm`: useful only as a reminder that subobject MITM should be config-gated and cheap when disabled. It is SSL-only and not a direct routing reference.

## Scope

Initial DNS MITM should do only the following:

- install an Atmosphere MITM server for `sfdnsres`
- decide per client whether interception is active
- observe and log resolver requests first
- forward unchanged when the feature is disabled or unsupported
- later answer selected A-record lookups through the existing tunnel-DNS path

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

Current scaffold files:

- `sysmodule/include/swg_sysmodule/experimental_mitm.h`
- `sysmodule/src/experimental_mitm.cpp`
- `sysmodule/include/swg_sysmodule/experimental_dns_mitm.h`
- `sysmodule/src/experimental_dns_mitm.cpp`

Future Switch-only activation files:

- `sysmodule/src/dns_mitm_switch.cpp`
- `sysmodule/src/dns_mitm_switch.h`
- optional later `sysmodule/src/bsd_mitm_switch.cpp`

The scaffold is intentionally dormant. It does not change `swg:ctl` behavior until a dedicated Switch-only resolver server is added.

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
- dormant scaffold compiled into `swg_sysmodule_core`
- host tests cover policy and planning logic only

### Stage 1

- Switch-only `sfdnsres` MITM server installs behind an explicit feature flag
- observe-only mode logs client program IDs, hostnames, request kind, and decision
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

- only after DNS MITM is stable, begin `bsd:u` observation work

## Key constraints

- the stable control plane remains the source of truth; MITM code must not bypass `swg:ctl`-owned runtime state
- query handling must remain bounded and allocation-aware
- unsupported resolver behaviors should forward or fail explicitly, never silently guess
- title-based policy should stay separate from tunnel cryptography and packet transport

## Immediate next implementation tasks

1. add a Switch-only `sfdnsres` MITM server shell that installs through Atmosphere SM MITM APIs
2. map only the core resolver commands listed above
3. forward everything while emitting structured logs
4. connect the forwarded-path decision layer to the current `ResolveDns()` and tunnel-DNS stats once observe-only logging is stable