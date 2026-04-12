# Debugging Notes

## Log locations

Host mode:
- `runtime/logs/swg/swg.log`

Planned Switch mode:
- `sdmc:/atmosphere/logs/swg/swg.log`
- `sdmc:/atmosphere/logs/swg/boot_marker.log`

The logger currently flushes every line. On Switch builds it now closes the file after each write so the log can be copied while the sysmodule is still running.

## Basic triage

1. Confirm the config file exists and validates.
2. Check the service status command for `service_ready` and `last_error`.
3. Review the latest log lines for init, config load, connect, or disconnect failures.
4. If config writes fail, verify the runtime root is writable.
5. If the normal log is missing, check `boot_marker.log` to see whether the sysmodule reached `main` before crashing.

## Current diagnostic coverage

- service init
- config load/save
- active profile changes
- runtime flag changes
- connect/disconnect requests

## Current connect semantics

At the current Milestone 4 slice, `Connected` only means the sysmodule validated the active profile, completed X25519 cryptographic preflight, resolved the IPv4 endpoint if needed, started BSD successfully, and opened a connected UDP socket.

It does not yet mean a real WireGuard handshake succeeded. Malformed or unusable X25519 key material now fails during connect preflight, but an offline VPN server, wrong peer configuration beyond that static-key check, or a server that never responds can still appear as `Connected` at this stage as long as the local UDP setup succeeds.

Sensitive material is never intentionally written to logs.
