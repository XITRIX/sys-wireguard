# Debugging Notes

## Log locations

Host mode:
- `runtime/logs/swg/swg.log`

Planned Switch mode:
- `sdmc:/atmosphere/logs/swg/swg.log`
- `sdmc:/atmosphere/logs/swg/moonlight.log`
- `sdmc:/atmosphere/logs/swg/boot_marker.log`

The logger currently flushes every line. On Switch builds it now closes the file after each write so the log can be copied while the sysmodule is still running.

Moonlight-Switch now mirrors its Borealis and connection-callback logs into `moonlight.log` in the same directory, so on-device RTSP and bridge diagnostics can be collected from the SWG log folder without hunting through separate app output channels.

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
- active DNS MITM service opens and resolver proxying for `sfdnsres`
- optional observe-only `bsd:u` service-open logging in separately gated builds

## MITM Observer Triage

The normal `switch-debug` preset now builds with `SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER=ON` and starts an active Atmosphere-compatible `sfdnsres` replacement. The `bsd:u` observer is additionally gated by `SWG_ENABLE_EXPERIMENTAL_BSD_MITM_OBSERVER=ON` because it sits directly in Moonlight's socket service-open path.

Resolver-replacement builds should show activation and later snapshot lines like:

```text
[INFO] [mitm-observer] activated active DNS replacement MitM hook for sfdnsres
[INFO] [dns-mitm] active sfdnsres MITM proxy ready
[INFO] [mitm-observer] MitM query stats service=sfdnsres total=... unsupported=... reply_failures=... last_pid=0x... last_program=0x...
```

For the current slice, matching Atmosphere hosts rules are answered by SWG and unmatched or unsupported resolver calls are forwarded to Nintendo's original resolver session. If Moonlight-Switch does not appear in these snapshots, first check whether it is launched through hbloader or a forwarder title, because the logged `last_program=0x...` value may belong to that host title rather than a unique Moonlight title.

If the observer repeats `MitM service-open observer install pending ... 0x1015 (module=21, description=8)`, Atmosphere is returning `sm::ResultNotAllowed`. For MITM install, that usually means the sysmodule NPDM does not have `service_host` access for the target service. The packaged sysmodule now grants host access for `swg:ctl`, `sfdnsres`, and `bsd:u`; after deploying an older package, rebuild and replace `exefs.nsp`.

If the observer reports `0x815 (module=21, description=4)`, Atmosphere is returning `sm::ResultAlreadyRegistered`. Another MITM already owns that service name, commonly Atmosphere's built-in DNS MITM for `sfdnsres`. SWG cannot observe that service-open path at the same time; current builds mark the hook blocked and stop retrying.

For SWG replacement builds, `atmosphere!enable_dns_mitm=false` is expected. That setting disables Atmosphere's built-in DNS MITM so `sfdnsres` is free; SWG still enables its own DNS replacement from the `switch-debug` build configuration.

If the log says `experimental MITM observer disabled in this build`, the package was configured manually with `SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER=OFF`; the normal `switch-debug` preset should not produce that package anymore. If a MITM-enabled build logs `bsd:u MitM observer disabled in this build`, only the resolver replacement is active.

In MITM-enabled packages, the safe startup sequence is:
- `installed active DNS replacement MitM handles for sfdnsres`
- `active sfdnsres MITM proxy ready`
- `activated active DNS replacement MitM hook for sfdnsres`
- optional `MitM query stats service=sfdnsres ...` snapshots after clients start opening the hooked service

The DNS replacement also writes `sdmc:/atmosphere/logs/dns_mitm_startup.log` when it loads settings and host rules. If `atmosphere!enable_dns_mitm_debug_log` is enabled, per-query redirect decisions are appended to `sdmc:/atmosphere/logs/dns_mitm_debug.log`.

The responder must be ready before future MITM declarations are cleared. Query handling must not write logs in the synchronous SM query path; the responder only replies and updates counters, while the observer thread writes periodic snapshots later. Logging in the synchronous query path can deadlock service opens because SM is waiting for the query response.

## Current connect semantics

At the current Milestone 4 slice, `Connected` means the sysmodule validated the active profile, completed X25519 cryptographic preflight, resolved the IPv4 endpoint if needed, started BSD successfully, sent a real WireGuard initiation packet, validated the responder's handshake response, and sent one authenticated post-handshake keepalive packet.

It still does not mean the full transport path is implemented. Cookie replies, retry logic, rekeys, and a persistent transport packet loop are not wired yet, so a server that requires cookie handling or sustained data traffic can still fail even though the initial initiation/response exchange now works and one keepalive is sent.

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
