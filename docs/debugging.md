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

At the current Milestone 4 slice, `Connected` means the sysmodule validated the active profile, completed X25519 cryptographic preflight, resolved the IPv4 endpoint if needed, started BSD successfully, sent a real WireGuard initiation packet, and validated the responder's handshake response.

It still does not mean the full transport path is implemented. Cookie replies, retry logic, rekeys, and transport data packets are not wired yet, so a server that requires cookie handling or a post-handshake keepalive/data confirmation can still fail even though the initial initiation/response exchange now works.

An offline VPN server, a wrong endpoint, or a peer that never replies should now leave `Connect()` in `Error` instead of reporting `Connected`.

If `Connect()` fails with `waiting for WireGuard response failed: recv timed out after 5000ms`, the current sysmodule now retries once and logs the resolved endpoint plus the local public key it used for the initiation. That usually means one of these is true:
- the server never received the UDP initiation
- the endpoint host or port is wrong
- the server received the packet but silently dropped it because the Switch local public key is not configured as an allowed peer

The handshake transport now uses an unconnected UDP socket for the initiation/response exchange. If a reply arrives from a different source tuple than the configured endpoint, the engine logs that actual reply source before validation.

When triaging that timeout, compare the logged `local_public_key` value with the peer public key configured on the server first.

The shared profile validator now also rejects a config where the profile `public_key` matches the local public key derived from `private_key`. In this config format, `public_key` must be the remote WireGuard peer or server public key, not the Switch client's own public key.

For off-device diagnosis, the host probe now also supports deterministic initiation dumps:
- `./build/host-debug/tests/swg_live_handshake_probe --config "$PWD/docs/config.ini" --dump-initiation "$PWD/test-runtime-live-handshake/initiation.hex" --no-connect`
- `./build/host-debug/tests/swg_live_handshake_probe --config "$PWD/docs/config.ini" --compare-initiation /path/to/reference-initiation.hex --no-connect`

The dump/compare mode fixes the sender index, ephemeral private key, and timestamp so exact byte comparison is meaningful when the reference generator can use the same overrides. Reference dumps may be raw 148-byte packets or hex text.

Sensitive material is never intentionally written to logs.
