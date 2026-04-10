# Known Risks

- The Switch service currently exposes one CMIF command that carries the versioned binary envelope in alias buffers; larger future config payloads may require chunking or a larger negotiated buffer budget.
- The overlay target is a host stub, not a Tesla binary.
- The Switch manager is a text-mode validation tool, not the final Tesla UX, so device control is functional but intentionally minimal.
- Capability detection is conservative and mostly placeholder until libnx-backed probes are added.
- Config validation checks presence and basic ranges, not cryptographic key or CIDR correctness.
- The new app route planner is advisory until real DNS responses or transparent socket interception are implemented.
- The sysmodule NPDM is intentionally permissive in Phase A (`service_access = ["*"]`) and should be tightened once the exact service dependencies are fixed.
