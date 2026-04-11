# AGENTS.md — Switch WireGuard Sysmodule Project

## Mission
Build a Nintendo Switch homebrew project for Atmosphère + libnx that delivers:

1. a **stable WireGuard control sysmodule** with Tesla configuration and status UI,
	delivered through a manager-based control UI first and a Tesla overlay later,
2. a **clean IPC/service API** that other homebrew apps can use easily, and
3. an **experimental transparent-routing mode** that attempts to redirect system traffic through a WireGuard tunnel.

The project must be approached as a **multi-stage Switch-native networking project**, not as a Linux VPN port.

---

## Primary goal
The end-state is a sysmodule that can:

- store one or more WireGuard profiles,
- connect/disconnect from a configured tunnel,
- expose state and stats via IPC,
- allow manager-based configuration and live control immediately, with Tesla-based quick control added later,
- provide a simple SDK/API for homebrew apps to opt into tunnel usage,
- optionally MITM or replace selected Horizon networking services to transparently reroute traffic.

---

## Absolute platform truths
Treat these as hard architectural constraints unless verified otherwise from current SwitchBrew / Atmosphère sources:

1. Horizon does **not** expose a normal Linux-style tun/tap interface to homebrew.
2. The documented socket service surface is based around `bsd:u`, `bsd:s`, and related services.
3. The documented registered socket domains are only `AF_INET` and `AF_ROUTE`.
4. `/dev/bpf` exists for limited packet access/promiscuous workflows, but it is **not** a drop-in VPN interface.
5. Switch applications do not go through a dedicated HTTP sysmodule; HTTP(S) commonly uses libcurl + socket/ssl services.
6. Transparent full-device VPN behavior therefore likely requires **service interception and/or lower-level routing tricks**, not merely embedding a WireGuard library.
7. Custom sysmodules are memory-constrained and sensitive to firmware / Atmosphère changes.
8. All modern homebrew in this project must target a **current libnx compatible with HOS 21.x+ TLS ABI changes**.

**Do not make Linux assumptions.**

---

## Product strategy
Always implement the project in this order:

### Phase A — reliable control plane
- sysmodule skeleton
- config load/save
- logging
- control IPC service
- manager application frontend
- connection state machine

Tesla overlay work is intentionally deferred until the manager-driven control plane and tunnel path are stable.

### Phase B — tunnel engine
- userspace WireGuard protocol integration
- UDP transport
- handshake / keepalive / stats
- DNS-over-tunnel support

### Phase C — app-facing API
- stable homebrew SDK
- app opt-in tunnel usage
- DNS resolve helpers
- socket-like or stream/datagram abstractions

### Phase D — transparent mode
- DNS MITM first
- `bsd:u` MITM prototype second
- per-title routing policy
- kill-switch / bypass policy
- broader system traffic support only after the above are proven

If forced to choose, always prioritize:

**homebrew-consumable API > DNS path > transparent full-tunnel MITM**

---

## Non-goals for early milestones
Do **not** attempt these in early milestones:

- full transparent routing on day one,
- multi-peer roaming,
- polished mobile-app-grade UX,
- dynamic route policy UI for dozens of titles,
- complete parity with Linux WireGuard tooling,
- packet capture/inspection features beyond what is needed for debugging,
- broad firmware-version support without first getting one known-good target working.

---

## Recommended repository structure
Use a monorepo with clean boundaries:

```text
/common        # shared structs, config schema, error codes, IPC protocol, logging
/sysmodule     # swg:ctl service, lifecycle, tunnel manager, later MITM logic
/overlay       # Tesla overlay UI
/manager       # optional hbmenu app for heavy config/log operations
/sdk           # client library for homebrew consumers
/third_party   # vendored WG core or wrappers
/docs          # architecture notes, task logs, firmware compatibility matrix
/tests         # host-side tests and protocol/unit tests where possible
```

Use namespaced identifiers consistently. Example internal naming:

- service: `swg:ctl`
- config dir: `/config/swg/`
- logs dir: `/atmosphere/logs/swg/`
- overlay title: `Switch WireGuard`
- SDK namespace: `swg`

---

## Required architectural components

### 1. `swg:ctl` — control/config service
This is the center of the system.

Responsibilities:
- load and validate config
- own global state machine
- start/stop tunnel sessions
- expose status/stats/errors
- own routing policy state
- coordinate DNS and transparent mode

The overlay and manager app must talk to the sysmodule via IPC, not by mutating files directly.

### 2. `wgcore`
A protocol engine boundary that handles:
- key material
- handshake state
- encryption/decryption
- peer state
- allowed IP evaluation
- keepalive timing

The surrounding sysmodule must own:
- sockets / UDP IO
- timers and event loop integration
- queues / packet pools
- routing policy
- integration with Horizon services

### 3. `swg-overlay`
A Tesla overlay for:
- connect/disconnect
- active profile selection
- endpoint + peer visibility
- current state and last error
- handshake age
- bytes in/out
- transparent-mode toggle
- DNS toggle and summary info

This is a deferred frontend slice, not a Phase A completion gate.

### 4. `libswg`
An SDK for homebrew apps.

It should be easier for another app to use `libswg` than to integrate WireGuard independently.

### 5. MITM layer
Separate from the control plane and added only after the above are stable.

Subparts:
- DNS interception path
- `bsd` interception path
- policy engine for bypass/exemptions

---

## Required implementation style

### General coding rules
- Prefer C or C++ matching libnx/Atmosphère ecosystem expectations.
- Keep exception-heavy or allocation-heavy code out of hot paths.
- Avoid unbounded heap growth.
- Prefer explicit ownership and fixed-size buffers or bounded pools.
- Use small worker counts.
- Put all service/version-specific logic behind capability checks.
- Centralize all HOS-version branching.
- Log enough to debug field failures without requiring a debugger.

### Performance and memory rules
- Use bounded queues.
- Avoid per-packet heap allocation in the steady state.
- Reuse packet buffers.
- Keep telemetry compact.
- Keep overlay queries cheap.
- Avoid large static allocations that assume old sysmodule memory budgets.

### Compatibility rules
- Build against current libnx for the active target firmware.
- Track service availability by firmware.
- Maintain a compatibility matrix in `/docs/compatibility.md`.
- Any code path that depends on a specific service revision must be guarded.

---

## Hard instructions for the coding agent

### The agent must always
1. Think in **phases**, not in one giant leap.
2. Produce working code in small vertical slices.
3. Keep the system bootable after every milestone.
4. Add instrumentation before complex MITM work.
5. Prefer a stable control service over clever packet tricks.
6. Treat DNS routing as its own milestone.
7. Treat transparent `bsd` interception as experimental until proven.
8. Write short architecture notes after each milestone.
9. Update the task list and known-risks list after each major change.
10. Never silently assume a Switch service behaves like BSD/Linux just because the names are similar.

### The agent must never
1. Start by implementing full transparent routing.
2. Assume a tun/tap device exists.
3. Bury core routing logic inside the overlay.
4. Couple config parsing tightly to UI code.
5. Introduce many long-lived threads without necessity.
6. Add uncontrolled logging in hot paths.
7. Merge experimental MITM code into the stable control path without feature flags.
8. Rewrite large areas at once when a staged refactor works.

---

## Milestones

## Milestone 0 — repo bootstrap
Deliverables:
- buildable repo skeleton
- shared config/error headers
- minimal README
- task board in `/docs/tasks.md`
- architecture summary in `/docs/architecture.md`

Definition of done:
- project builds cleanly
- no runtime functionality required yet

## Milestone 1 — minimal sysmodule
Deliverables:
- sysmodule entrypoint
- init/exit path
- basic logging
- config file discovery
- placeholder state machine

Definition of done:
- sysmodule boots reliably
- it can create/read config
- it can expose a version/status stub via IPC

## Milestone 2 — control IPC
Deliverables:
- `swg:ctl` registration
- client library for IPC calls
- commands for version/status/config/connect/disconnect/stats
- error-code conventions

Definition of done:
- a small test client or manager app can query the service
- the future overlay can consume the same IPC layer later unchanged

## Milestone 3 — manager frontend
Deliverables:
- manager app UI
- profile display
- connect/disconnect action
- status and error display

Definition of done:
- manager never directly edits runtime state except through IPC
- UI remains responsive even when tunnel operations fail

## Deferred frontend slice — Tesla overlay
Deliverables:
- overlay menu
- profile display
- connect/disconnect action
- status and error display

Definition of done:
- overlay never directly edits runtime state except through IPC
- UI remains responsive even when tunnel operations fail

## Milestone 4 — WireGuard engine integration
Deliverables:
- protocol library wired in
- key parsing/validation
- endpoint handling
- state transitions for handshake / connected / error

Definition of done:
- successful handshake against a controlled test peer
- stats exposed through `swg:ctl`

## Milestone 5 — UDP transport and reliability
Deliverables:
- UDP socket backend
- keepalive scheduling
- packet TX/RX loop
- bounded packet pools
- reconnect policy

Definition of done:
- stable sustained tunnel traffic in a controlled test app
- no unbounded memory growth

## Milestone 6 — homebrew SDK
Deliverables:
- `libswg` API
- session/init helpers
- DNS resolve helpers
- optional socket-like wrapper or stream/datagram abstraction
- usage example app

Definition of done:
- another homebrew app can use the tunnel without understanding implementation details

## Milestone 7 — DNS through tunnel
Deliverables:
- DNS-over-tunnel path or tunnel-aware resolver service
- config support for DNS servers
- split behavior for fallback / fail-closed policy

Definition of done:
- SDK clients can reliably resolve via tunnel
- DNS behavior is observable via logs/stats

## Milestone 8 — DNS MITM prototype
Deliverables:
- service interception for resolver path
- feature flag for MITM mode
- bypass rules for safety

Definition of done:
- selected processes/titles resolve through tunnel without SDK changes
- failures degrade in a controlled way

## Milestone 9 — `bsd:u` MITM prototype
Deliverables:
- interception harness
- logging for socket lifecycle events
- support matrix for implemented operations
- TCP/UDP happy-path prototype

Definition of done:
- selected title(s) can establish outbound traffic through the tunnel under experimental mode
- unsupported calls fail loudly and diagnostically

## Milestone 10 — routing policy engine
Deliverables:
- per-title policy
- bypass list
- local subnet exemptions
- Nintendo service exemptions if needed
- kill-switch semantics

Definition of done:
- routing is policy-driven, not hard-coded

## Milestone 11 — stabilization
Deliverables:
- compatibility matrix
- performance notes
- regression tests
- panic/failure triage guide
- release packaging

Definition of done:
- project can be used as both an SDK-backed tunnel and an experimental transparent-mode sysmodule

---

## Suggested IPC surface
The exact ABI can evolve, but start with commands like:

- `GetVersion`
- `GetStatus`
- `GetLastError`
- `ListProfiles`
- `LoadProfile`
- `SaveProfile`
- `DeleteProfile`
- `SetActiveProfile`
- `Connect`
- `Disconnect`
- `GetStats`
- `GetRuntimeConfig`
- `SetRuntimeFlags`
- `ResolveDns`
- `GetCompatibilityInfo`
- later: `OpenTunnelSocket`, `SendPacket`, `RecvPacket`, `SetPolicy`

Ensure IPC structs are versioned.

---

## Configuration schema guidance
Support a minimal but extensible schema:

```ini
[profile.default]
private_key = ...
public_key = ...
preshared_key = ...
endpoint_host = ...
endpoint_port = 51820
allowed_ips = 0.0.0.0/0, ::/0
address = 10.0.0.2/32
dns = 1.1.1.1, 1.0.0.1
persistent_keepalive = 25
autostart = false
transparent_mode = false
kill_switch = false
```

Add room later for:
- per-title rules
- bypass ranges
- split-tunnel mode
- resolver policy
- debug flags

Always validate config at load time and expose human-readable validation errors to the overlay.

---

## WireGuard integration rules
- The protocol core is not the product; platform integration is the product.
- Treat WireGuard as an engine embedded inside a Switch-specific orchestration layer.
- Keep cryptographic code isolated.
- Avoid spreading key handling throughout the codebase.
- Do not mix packet-routing policy with handshake/state logic.
- Keep the tunnel engine testable outside the sysmodule where possible.

If using a third-party WireGuard core:
- vendor it cleanly,
- document local patches,
- isolate the wrapper boundary,
- do not let upstream internals leak across the whole codebase.

---

## Transparent mode guidance
Transparent mode is a separate product tier inside the repo.

### Design assumptions
- There is no documented simple VPN interface to plug into.
- Traffic redirection likely means service interception rather than route-table configuration alone.
- DNS interception is lower risk than full socket interception.
- A partial transparent mode for selected titles is acceptable before system-wide routing.

### Safe rollout order
1. Observe resolver behavior.
2. MITM DNS for selected targets.
3. Observe `bsd:u` call patterns.
4. Implement outbound TCP/UDP happy path only.
5. Add title-based policy.
6. Add failure policy and kill-switch semantics.
7. Expand compatibility surface.

### Transparent mode requirements
- feature-flagged
- diagnostic logging enabled in dev builds
- support matrix clearly documented
- unsupported features fail explicitly
- easy way to disable from config if boot stability issues arise

---

## DNS guidance
Treat DNS as a first-class subsystem.

Support these modes:
- disabled
- SDK-only tunnel DNS
- transparent DNS MITM
- fail-open fallback
- fail-closed policy

Track stats:
- query count
- cache hits if caching is added
- fallback count
- leak-prevention events

---

## Logging and diagnostics
Every milestone must improve diagnostics.

Minimum required logs:
- service init/exit
- config load result
- profile activation result
- connect/disconnect reason
- handshake transitions
- endpoint changes
- DNS mode changes
- transparent-mode enable/disable
- MITM failures by operation
- memory-pressure warnings if detectable

Provide a panic triage note in `/docs/debugging.md`.

Debug builds may add:
- packet counters per stage
- resolver decision logs
- policy engine traces

Do not dump sensitive keys in logs.

---

## Testing strategy

### Host-side tests
Use host-side tests where possible for:
- config parsing
- route/policy evaluation
- profile validation
- stats accumulation
- non-HOS packet transform logic

### On-device tests
Create a controlled test matrix:

1. sysmodule boots with overlay installed
2. config save/load survives reboot
3. connect/disconnect works repeatedly
4. WG handshake succeeds to a known peer
5. homebrew SDK app can resolve DNS and reach a test endpoint
6. tunnel reconnect works after network interruption
7. transparent DNS mode works for a selected title
8. `bsd` MITM prototype handles a known simple target
9. disable flag recovers from experimental failures

Track each result in `/docs/test-matrix.md`.

---

## Firmware and service compatibility policy
Maintain a live matrix documenting:
- target HOS version(s)
- target Atmosphère version(s)
- target libnx version
- service availability and differences
- known breakpoints in MITM behavior

Never scatter version assumptions around the codebase.

Create a dedicated compatibility layer such as:

```text
/common/hos_caps.h
/common/hos_caps.cpp
```

with helpers like:
- `has_bsd_a()`
- `has_dns_priv()`
- `has_ifcfg()`
- `has_bsd_nu()`
- `needs_new_tls_abi()`

---

## Task execution protocol for the agent
For every task, the agent should produce:

1. **Intent** — what is being built and why.
2. **Files to touch** — exact paths.
3. **Constraints** — memory, ABI, service compatibility, safety.
4. **Implementation** — small coherent patch.
5. **Verification** — build/test/log checks.
6. **Follow-up tasks** — the next smallest useful slices.

When blocked, the agent should:
- document the blocker,
- reduce scope,
- ship the next smallest working vertical slice,
- avoid speculative large rewrites.

---

## Prioritized backlog
The agent should keep these at the top of the backlog in roughly this order:

1. sysmodule boot reliability
2. control IPC stability
3. config correctness
4. manager usability
5. tunnel handshake reliability
6. homebrew SDK usability
7. DNS correctness
8. transparent-mode observability
9. selective transparent routing
10. Tesla overlay parity, broader compatibility and performance

---

## Definition of success
The project is successful if it ends up with:

### Minimum success
- stable sysmodule
- stable manager control flow
- working WireGuard tunnel
- usable SDK/API for homebrew apps

### Strong success
- tunnel-aware DNS
- Tesla control flow
- selected-title transparent routing
- clear compatibility matrix

### Stretch success
- broad transparent routing of Horizon traffic through policy-driven MITM

If transparent full-tunnel mode remains partial but the SDK path is excellent, the project is still a success.

---

## Initial tasks the agent should execute immediately
1. Create the monorepo skeleton.
2. Add architecture and task docs.
3. Implement `swg:ctl` service stub.
4. Implement config parser + validation.
5. Add IPC client stub.
6. Add minimal manager app consuming IPC.
7. Add placeholder state machine.
8. Add stats/error structs.
9. Add build/test notes.
10. Only then begin `wgcore` integration.

---

## Final instruction to the agent
Be conservative with transparent system interception and aggressive about delivering a stable control plane.

A working Switch-native control service plus homebrew SDK is the foundation.
A full transparent VPN is the advanced layer built on top of that foundation.

If there is a tradeoff, always choose the path that preserves bootability, debuggability, and incremental progress.
