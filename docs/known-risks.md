# Known Risks

- The current service transport is in-process only; no real Horizon IPC registration exists yet.
- The overlay target is a host stub, not a Tesla binary.
- Capability detection is conservative and mostly placeholder until libnx-backed probes are added.
- Config validation checks presence and basic ranges, not cryptographic key or CIDR correctness.
- Switch-target presets currently validate project structure rather than producing deployable binaries.
- The new app route planner is advisory until real DNS responses or transparent socket interception are implemented.
