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
- experimental `bsd:u` service-open query logging in `switch-debug` builds

## MITM Observer Triage

The normal `switch-debug` preset now builds with `SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER=ON` and `SWG_ENABLE_EXPERIMENTAL_BSD_MITM_OBSERVER=ON`, but keeps `SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB=OFF`. It starts an active Atmosphere-compatible `sfdnsres` replacement and installs a `bsd:u` query hook that fails open. The old raw BSD pass-through lab crashed Moonlight during BSD initialization; the manual lab mode now uses explicit BSD command adapters and returns BSD errno values for unsupported commands.

Resolver-replacement builds should show activation and later snapshot lines like:

```text
[INFO] [mitm-observer] activated active DNS replacement MitM hook for sfdnsres
[INFO] [dns-mitm] active sfdnsres MITM proxy ready
[INFO] [mitm-observer] MitM query stats service=sfdnsres total=... selected=... unsupported=... reply_failures=... last_pid=0x... last_program=0x...
```

For the current slice, matching Atmosphere hosts rules are answered by SWG and unmatched or unsupported resolver calls are forwarded to Nintendo's original resolver session. If Moonlight-Switch does not appear in these snapshots, first check whether it is launched through hbloader or a forwarder title, because the logged `last_program=0x...` value may belong to that host title rather than a unique Moonlight title.

If the observer repeats `MitM service-open observer install pending ... 0x1015 (module=21, description=8)`, Atmosphere is returning `sm::ResultNotAllowed`. For MITM install, that usually means the sysmodule NPDM does not have `service_host` access for the target service. The packaged sysmodule now grants host access for `swg:ctl`, `sfdnsres`, and `bsd:u`; after deploying an older package, rebuild and replace `exefs.nsp`.

If the observer reports `0x815 (module=21, description=4)`, Atmosphere is returning `sm::ResultAlreadyRegistered`. Another MITM already owns that service name, commonly Atmosphere's built-in DNS MITM for `sfdnsres`. SWG cannot observe that service-open path at the same time; current builds mark the hook blocked and stop retrying.

For SWG replacement builds, `atmosphere!enable_dns_mitm=false` is expected. That setting disables Atmosphere's built-in DNS MITM so `sfdnsres` is free; SWG still enables its own DNS replacement from the `switch-debug` build configuration.

SWG now calls Atmosphere's `UninstallMitm` during graceful sysmodule exit. A stale `sfdnsres` MITM left by an older build cannot be reclaimed by a newly started process because Atmosphere only lets the original owner process id uninstall it; reboot once after deploying the fixed build if the old owner is already stranded.

For MITM-enabled builds, stop the sysmodule through SWG's own control path before restarting it. The Switch manager has a `- stop sysmodule` action that sends `RequestShutdown` over `swg:ctl`; the sysmodule replies, leaves the service loop, and then runs the MITM uninstall path. External hard-kill toggles can still bypass `__appExit` and leave Atmosphere's `sfdnsres` MITM registration owned by a dead process until the next reboot.

If the log says `experimental MITM observer disabled in this build`, the package was configured manually with `SWG_ENABLE_EXPERIMENTAL_MITM_OBSERVER=OFF`; the normal `switch-debug` preset should not produce that package anymore. If a MITM-enabled build logs `bsd:u MitM observer disabled in this build`, only the resolver replacement is active.

In MITM-enabled packages, the safe startup sequence is:
- `installed active DNS replacement MitM handles for sfdnsres`
- `active sfdnsres MITM proxy ready`
- `activated active DNS replacement MitM hook for sfdnsres`
- `installed query-only MitM handles for bsd:u`
- `bsd:u adapter lab disabled; query hook will fail open`
- `activated query-only MitM hook for bsd:u`
- optional `MitM query stats service=sfdnsres ...` snapshots after clients start opening the hooked service
- optional `MitM query stats service=bsd:u ... selected=0 ...` lines after application or homebrew clients open the socket service

The current hardware baseline is healthy when Moonlight-Switch opens `bsd:u` with `selected=0`, opens `sfdnsres` with `selected` increasing, exits without app or console freeze, and SWG stop logs `uninstalled MitM hook for sfdnsres` plus `uninstalled MitM hook for bsd:u`.

When `SWG_ENABLE_EXPERIMENTAL_BSD_MITM_ADAPTER_LAB=ON`, the BSD hook is expected to show `installed adapter lab MitM handles for bsd:u`, `active bsd:u MITM adapter lab ready`, `socket_fd_source=original_bsd`, `stream_socket_native_open=deferred_connect`, `dispatch_trace=tls_deferred`, `title_selector=exact_allowlist`, and `selected` increasing for `bsd:u`. The current UDP slice handles `RegisterClient`, `StartMonitoring`, `cmifCloneCurrentObject` session cloning, original-service-backed `Socket`/`SocketExempt` fd allocation, `Bind`, UDP `Connect`, `Send`/`SendTo`, `Recv`/`RecvFrom`, `Poll`, `Select`, `GetSockName`, `GetPeerName`, `Fcntl` including `F_GETFD`/`F_SETFD`/`F_GETFL`/`F_SETFL`, `GetSockOpt(SO_ERROR)`, `SetSockOpt`, `Shutdown`, and `Close`. It also has a direct native BSD backend for policy-approved local/multicast IPv4 UDP and local IPv4 TCP probes once `Connect` reveals the destination. Useful lab logs include `original=registered`, `backend=original-bsd`, `cloned bsd:u adapter session ... forward=cloned`, `dispatch bsd:u request`, `handled bsd:u Fcntl`, `opened transparent app session`, `opened direct native BSD socket`, `handled bsd:u Connect direct`, `opened tunnel UDP adapter`, `sent tunnel UDP datagram`, `received tunnel UDP datagram`, and sparse `unsupported bsd:u adapter command` lines for commands not implemented yet.

The default adapter-lab package now logs `hbl_host_mitm=disabled` and only actively selects exact title ids explicitly allowlisted by `[app_policy.*] title_id` plus `requested_flags = transparent_mode`. Forwarder ids may not live in the usual `0x01...` application range, so exact allowlist matching is the source of truth. If Moonlight-Switch is launched through Sphaira/hbloader and the query stats show a host `program=0x...` with HBL or program-specific override flags, SWG intentionally leaves `selected=0` for `bsd:u` unless that exact host title was explicitly allowlisted. At that service boundary HOS exposes the homebrew host process, not the individual `.nro`, so active BSD replacement would also affect Sphaira and can make reopen/freeze failures contagious. Use a forwarder/application title for active BSD MITM tests, or build an explicitly unsafe `SWG_ENABLE_EXPERIMENTAL_BSD_MITM_HBL_HOST_LAB=ON` package only for short crash-lab runs.

If host discovery logs `rejected tunnel datagram open ... target=224.0.0.251:5353`, or `GetNetworkPlan` denies `192.168.x.x` / `224.0.0.251` while the tunnel is disconnected, the adapter is incorrectly treating local traffic as tunnel-required. The BSD adapter app-session log should include `local_bypass=enabled`, and the local/multicast direct backend should open a native BSD socket and send that packet outside the tunnel.

If the transparent BSD session log says `app=bsd:u` without `local_bypass=enabled`, the adapter request did not override the default app policy and all local discovery/status traffic can be denied while disconnected. The adapter-lab build requests `AllowLocalNetworkBypass` explicitly before opening its transparent app session.

If a LAN route now logs `-> direct` and `opened direct native BSD socket` but no `handled bsd:u Connect direct` line follows, the native nonblocking `connect()` returned an errno the adapter did not classify as in-progress. Current adapter-lab builds accept `EINPROGRESS`, `EWOULDBLOCK`/`EAGAIN`, `EALREADY`, and the observed HOS/Linux numeric values `115` / `114`, and log the target plus errno for direct connect results.

If stopping SWG produces an Atmosphère crash report for process `bsdsocket` (`0100000000000012`) with a user break, check whether the adapter-lab build was issuing synthetic forwarded `Close` commands while tearing down selected `bsd:u` sessions. Forced adapter teardown should close SWG-owned direct native sockets and tunnel handles, then close the forwarded `bsd:u` session handles; original bsdsocket fd cleanup belongs to the forwarded service session close. App-requested `bsd:u Close` commands may still be forwarded during normal operation.

If a selected app accepts `bsd:u`, logs `RegisterClient` and `StartMonitoring`, then immediately closes both adapter sessions without any `cloned bsd:u adapter session` line, libnx probably failed during BSD session-manager setup. The adapter must support `cmifCloneCurrentObject` before production apps such as Moonlight-Switch can safely progress to normal socket calls.

If `cloned bsd:u adapter session` appears repeatedly and then logs `failed to clone bsd:u adapter session because the server is at capacity`, the lab session table is too small for the app's libnx BSD session pool. The adapter-lab build now reserves enough slots for libnx's 16-session maximum plus the extra monitor session.

If Moonlight creates a TCP socket and then logs `Curl error: Could not connect to server` while SWG only shows `handled bsd:u Socket` and no `handled bsd:u Connect direct`, first check the bootstrap and socket lines. The adapter-lab build should report `original=registered` on `RegisterClient`, `handled bsd:u QueryPointerBufferSize ... size=0x0 original_size=0x1000`, `forward=cloned` on clone lines, `socket_response=forward_exact_fd0_patch` at BSD MITM startup, `backend=forwarded-original-bsd` for initial AF_INET stream sockets, `fd_zero_patch=patched:<fd>` when original BSD returns fd zero, and `domain=2`; it opens direct native BSD backing only at `Connect`, once policy has the remote address. Original HOS BSD can return fd `0`, so the adapter socket table uses an explicit active flag rather than treating zero as an empty slot. If Curl still stops immediately after a forwarded-original `handled bsd:u Socket` line, the next suspect is the client-side libnx handle allocation or the next IPC request failing before SWG can parse it. If an older log reports `domain=1329808979`, that is the CMIF `SFCO` response magic from a nested native BSD call reusing TLS, not the app's real socket input. Current builds copy command payloads before nested native calls, log bounded `dispatch bsd:u request` lines with handle counts, and should reveal whether Curl stops on `Fcntl`, `SetSockOpt`, `GetSockOpt`, or another pre-connect command. Libnx can create the fd on one cloned session and call `connect()` on another; the adapter-lab build stores tracked sockets, app-session id, and the preserved `RegisterClient` transfer-memory handle in shared per-client state.

If Moonlight-Switch opens successfully but crashes while closing and the crash report symbols land in `socketExit()` / `bsdExit()` / libnx `tmemClose`, check the `RegisterClient` line for `tmem_handle=preserved`. The adapter must keep the `RegisterClient` transfer-memory handle alive until the root BSD session closes; closing that incoming handle during request cleanup can break the client's BSD transfer-memory teardown.

If HOS crashes while Moonlight reaches host-status ping and the sysmodule crash symbols land in `BsdMitmAdapterServer::HandleGetSockName`, suspect an unsafe HIPC AutoSelect output buffer. The adapter-lab build now reports a non-zero BSD pointer-buffer size, masks recv-list addresses, uses AutoSelect buffer decoding for BSD command payloads, and bounces direct native `send`/`recv`/`getsockopt` data through sysmodule-owned scratch buffers. A bad forwarded buffer should now return BSD `EFAULT` instead of causing a sysmodule data abort.

If an adapter-lab crash report points at `BsdMitmAdapterThreadMain` and the saved stack pointer is outside the crashed thread stack range, treat it as a sysmodule thread stack overflow. The BSD adapter server state must stay heap-backed; moving its session/socket table back onto the thread stack can crash HOS before the `active bsd:u MITM adapter lab ready` line is written.

The DNS replacement also writes `sdmc:/atmosphere/logs/dns_mitm_startup.log` when it loads settings and host rules. If `atmosphere!enable_dns_mitm_debug_log` is enabled, per-query redirect decisions are appended to `sdmc:/atmosphere/logs/dns_mitm_debug.log`.

The responder must be ready before future MITM declarations are cleared. Query handling must not write logs in the synchronous SM query path; the responder only replies and updates counters, while the observer thread writes periodic snapshots later. Logging in the synchronous query path can deadlock service opens because SM is waiting for the query response.

BSD adapter dispatch tracing must also stay TLS-safe. The incoming HIPC request lives in TLS, and Switch logging may use service calls that reuse the same TLS buffer. The adapter captures trace text before handling, replies to the client, and only then writes `dispatch bsd:u request` lines; adding logs before payload parsing can corrupt requests such as `RegisterClient`.

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
