# WireGuard Backend Replacement

## Intent

Replace the local WireGuard protocol implementation with a maintained open-source backend so project bugs are more likely to live in SWG's platform integration, socket runtime, IPC, queueing, DNS, or policy code rather than in Noise/WireGuard cryptographic message construction.

This is a Phase B tunnel-engine cleanup, not a transparent-routing milestone. The sysmodule remains Switch-native: no Linux tun/tap assumption, no lwIP netif adoption, and no routing logic moved into UI code.

## Files Touched

- `.gitmodules`: records the `third_party/wireguard-lwip` submodule.
- `third_party/wireguard-lwip`: upstream `smartalock/wireguard-lwip`, pinned to `f0d0ca5`.
- `third_party/CMakeLists.txt`: builds only upstream protocol/crypto sources into `wireguard_lwip_core`.
- `third_party/wireguard_lwip_compat/include/lwip/*`: minimal type stubs needed by upstream public headers.
- `third_party/wireguard_lwip_platform.cpp`: host/Switch time and randomness hooks required by upstream.
- `third_party/README.md`: local dependency policy and wrapper notes.
- `CMakeLists.txt` and `common/CMakeLists.txt`: enable C and link `swg_common` against `wireguard_lwip_core`.
- `common/src/wg_handshake.cpp`: adapter from SWG's existing handshake/transport API to `wireguard-lwip`.
- `common/include/swg/wg_crypto.h` and `common/src/wg_crypto.cpp`: removed the unused local keypair-generation API left over from the old backend.
- `docs/architecture.md`, `docs/tasks.md`, and `docs/known-risks.md`: milestone notes and risk tracking.

## Constraints

- Horizon does not expose a normal tun/tap interface to homebrew, so upstream lwIP interface glue is not used.
- `swg:ctl` remains the stable control boundary for manager, future Tesla overlay, SDK consumers, and tests.
- Sysmodule-owned concerns remain local: BSD socket runtime, endpoint resolution, connect/disconnect state, bounded queues, stats, reconnect policy, DNS helpers, app policy, and future MITM gates.
- Crypto keys must not be logged.
- Hot paths must avoid unbounded heap growth and uncontrolled logging.
- Switch builds must continue to target current libnx/HOS 21.x-compatible ABI expectations.
- Transparent mode remains deferred and feature-gated; this backend swap does not activate any MITM behavior.

## Implementation

The selected upstream is `smartalock/wireguard-lwip` because it is C, BSD-3-Clause, compact, and exposes protocol-level functions for handshake and transport packets. SWG compiles:

- `wireguard.c`
- `crypto.c`
- reference BLAKE2s, ChaCha20-Poly1305, Poly1305, and X25519 sources
- a local platform hook file

SWG does not compile `wireguardif.c` or use the upstream lwIP network-interface path.

`common/src/wg_handshake.cpp` now constructs a one-peer upstream `wireguard_device`, calls upstream handshake initiation/response functions, starts upstream keypairs, and copies the resulting session indexes and keys into SWG's existing structs. Transport packet encryption/decryption also goes through upstream `wireguard_encrypt_packet()` and `wireguard_decrypt_packet()`.

The old local implementation removed from the active file included:

- local BLAKE2s hashing and HMAC/KDF routines
- local WireGuard Noise handshake construction
- local responder-side test handshake construction
- local ChaCha20-Poly1305 packet encryption/decryption calls
- local session-key derivation logic

`wg_crypto` remains intentionally small and non-protocol-owning. It still uses mbedTLS PSA for config preflight only:

- derive the configured local public key from the configured private key
- reject invalid/all-zero peer shared secrets
- provide random bytes for deterministic test override scripts when needed

The deterministic host probe and scripted tests are preserved with thread-local override hooks in `wireguard_lwip_platform.cpp`; those hooks are cleared after each upstream call and are not part of runtime tunnel behavior.

## Verification

Host configure/build:

```sh
cmake --preset host-debug -DCMAKE_OSX_SYSROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk
cmake --build --preset host-debug
```

Host tests:

```sh
ctest --preset host-debug
```

The host test command requires localhost socket permissions. In this sandbox, non-elevated loopback bind fails with `Operation not permitted`, so the passing run was executed with elevated permissions.

Switch configure/build:

```sh
cmake --preset switch-debug
cmake --build --preset switch-debug
```

Hygiene:

```sh
git diff --check
```

Latest local results:

- Host build: passed.
- Host `swg_tests`: passed.
- Switch build: passed, including sysmodule package, manager NRO, and integration NRO staging.
- Whitespace check: passed.

## Follow-Up Tasks

- Run the rebuilt sysmodule on hardware against a known-good WireGuard peer and record the result in `docs/test-matrix.md`.
- Add cookie-reply handling using upstream cookie support instead of local reconstruction.
- Integrate upstream rekey/session-rotation primitives deliberately; do not bolt them into the reconnect path without instrumentation.
- Decide whether SWG's exact-payload transport helpers should adopt normal WireGuard 16-byte inner-packet padding once all packet consumers carry parseable IPv4 payloads.
- Add a short submodule update procedure before routinely bumping upstream.
- Keep transparent DNS and `bsd:*` MITM work separate from this backend boundary.
