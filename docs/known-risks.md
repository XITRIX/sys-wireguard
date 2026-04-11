# Known Risks

- The Switch service currently exposes one CMIF command that carries the versioned binary envelope in alias buffers; larger future config payloads may require chunking or a larger negotiated buffer budget.
- Tesla overlay work is intentionally deferred from Phase A; the overlay target remains a host stub.
- Tesla live toggling now relies on `ovl-sysmodules` using `pmshellTerminateProgram()` / `pmshellLaunchProgram()`; active clients should tolerate abrupt `swg:ctl` disconnects during manual stop/start.
- The Switch manager is the current Phase A control UI; it is text-mode and intentionally simpler than the future Tesla UX.
- The current Milestone 4 slice only validates WireGuard profile material and starts a stub tunnel-engine boundary; it does not perform a real handshake or UDP transport yet.
- The current Switch tunnel session preparation is intentionally IPv4-only: hostname endpoints are left unresolved for a later resolver/UDP slice, IPv6 endpoints are rejected, and IPv6 routes or DNS entries are only tracked as skipped metadata.
- A host-tested IPv4 endpoint resolver now exists for prepared sessions, but the live Switch connect path still does not invoke it until BSD init, timeout policy, and UDP lifecycle handling are wired into the real transport backend.
- The live engine path now opens a connected IPv4 UDP socket, but it still has no packet loop, no keepalive scheduling, no handshake state, and no on-device validation yet for socket initialization or endpoint resolution through Horizon networking services.
- BSD startup still depends on Horizon service behavior that can differ by firmware and sysmodule context; the runtime now logs staged diagnostics on failure, but real hardware validation is still required to confirm which BSD registration path is accepted.
- The current Switch heap budget is 4 MiB so BSD can allocate its `0x234000` transfer-memory block with headroom; future WireGuard packet pools or transparent-mode buffers may require retuning that heap size.
- DNS servers currently need to be numeric IP literals during connect preflight; hostname-based resolver configuration is not accepted yet.
- Capability detection now probes live service reachability, but some flags still map to nearest current surfaces (`sfdnsres` for resolver reachability and `nifm:a`/`nifm:s` for network-configuration reachability) rather than final transparent-mode hooks.
- Config validation checks presence and basic ranges, not cryptographic key or CIDR correctness.
- The new app route planner is advisory until real DNS responses or transparent socket interception are implemented.
- The sysmodule NPDM is intentionally permissive in Phase A (`service_access = ["*"]`) and should be tightened once the exact service dependencies are fixed.
