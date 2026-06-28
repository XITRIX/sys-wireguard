# Third-Party Dependencies

## wireguard-lwip

`wireguard-lwip` is vendored as a git submodule at `third_party/wireguard-lwip`.

- Upstream: https://github.com/smartalock/wireguard-lwip
- License: BSD-3-Clause, see `third_party/wireguard-lwip/LICENSE`
- Local target: `wireguard_lwip_core`

Only the protocol and crypto sources are compiled for SWG. The upstream lwIP
network-interface glue is intentionally not used by the sysmodule path because
Horizon does not expose a Linux-style VPN interface and this project owns its
own socket, IPC, queue, and routing-policy boundaries.

Local wrapper files:

- `wireguard_lwip_compat/include/lwip/*`: minimal type stubs required by the
  upstream public protocol header.
- `wireguard_lwip_platform.cpp`: Switch/host time and randomness hooks required
  by the upstream core, plus deterministic test overrides.

Do not patch the submodule casually. Prefer adapting at the local wrapper or
`common/src/wg_handshake.cpp` boundary and document any required upstream patch
before carrying it.
