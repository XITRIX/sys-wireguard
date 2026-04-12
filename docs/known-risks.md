# Known Risks

- The Switch service currently exposes one CMIF command that carries the versioned binary envelope in alias buffers; larger future config payloads may require chunking or a larger negotiated buffer budget.
- Tesla overlay work is intentionally deferred from Phase A; the overlay target remains a host stub.
- Tesla live toggling now relies on `ovl-sysmodules` using `pmshellTerminateProgram()` / `pmshellLaunchProgram()`; active clients should tolerate abrupt `swg:ctl` disconnects during manual stop/start.
- The Switch manager is the current Phase A control UI; it is text-mode and intentionally simpler than the future Tesla UX.
- The current Milestone 4 slice now performs a one-shot WireGuard initiation/response handshake, but cookie replies, retry policy, rekeying, and transport data packets are still not implemented.
- The current Switch tunnel session preparation is intentionally IPv4-only: hostname endpoints are left unresolved for a later resolver/UDP slice, IPv6 endpoints are rejected, and IPv6 routes or DNS entries are only tracked as skipped metadata.
- The live connect path now resolves IPv4 endpoints, validates the handshake, schedules authenticated keepalives, and surfaces inbound authenticated transport packets through a bounded receive queue exposed by `swg:ctl`, but there is still no send-side packet path, endpoint roaming support, or retransmit/backoff policy beyond the current bounded handshake retry.
- `RecvPacket` is currently session-gated rather than per-app demultiplexed; multiple consumers on the same connected profile would compete for one bounded queue until a richer socket/session model exists.
- The new host live-handshake probe can separate protocol and remote-peer issues from Switch-specific networking behavior, but a host success still does not prove that Horizon BSD behavior or on-device UDP reachability is identical.
- BSD startup still depends on Horizon service behavior that can differ by firmware and sysmodule context; the runtime now logs staged diagnostics on failure, but real hardware validation is still required to confirm which BSD registration path is accepted.
- The current Switch heap budget is 4 MiB so BSD can allocate its `0x234000` transfer-memory block with headroom; future WireGuard packet pools or transparent-mode buffers may require retuning that heap size.
- DNS servers currently need to be numeric IP literals during connect preflight; hostname-based resolver configuration is not accepted yet.
- Capability detection now probes live service reachability, but some flags still map to nearest current surfaces (`sfdnsres` for resolver reachability and `nifm:a`/`nifm:s` for network-configuration reachability) rather than final transparent-mode hooks.
- Config validation checks presence and basic ranges, not cryptographic key or CIDR correctness.
- The new app route planner is advisory until real DNS responses or transparent socket interception are implemented.
- The sysmodule NPDM is intentionally permissive in Phase A (`service_access = ["*"]`) and should be tightened once the exact service dependencies are fixed.
