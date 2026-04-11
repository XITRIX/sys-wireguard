# Known Risks

- The Switch service currently exposes one CMIF command that carries the versioned binary envelope in alias buffers; larger future config payloads may require chunking or a larger negotiated buffer budget.
- Tesla overlay work is intentionally deferred from Phase A; the overlay target remains a host stub.
- Tesla live toggling now relies on `ovl-sysmodules` using `pmshellTerminateProgram()` / `pmshellLaunchProgram()`; active clients should tolerate abrupt `swg:ctl` disconnects during manual stop/start.
- The Switch manager is the current Phase A control UI; it is text-mode and intentionally simpler than the future Tesla UX.
- The current Milestone 4 slice only validates WireGuard profile material and starts a stub tunnel-engine boundary; it does not perform a real handshake or UDP transport yet.
- DNS servers currently need to be numeric IP literals during connect preflight; hostname-based resolver configuration is not accepted yet.
- Capability detection now probes live service reachability, but some flags still map to nearest current surfaces (`sfdnsres` for resolver reachability and `nifm:a`/`nifm:s` for network-configuration reachability) rather than final transparent-mode hooks.
- Config validation checks presence and basic ranges, not cryptographic key or CIDR correctness.
- The new app route planner is advisory until real DNS responses or transparent socket interception are implemented.
- The sysmodule NPDM is intentionally permissive in Phase A (`service_access = ["*"]`) and should be tightened once the exact service dependencies are fixed.
