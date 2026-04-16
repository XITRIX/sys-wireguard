# Integration Harness

The current harness adds a passive host-side server and a one-button Switch runner so tunnel validation can move beyond route-planning alone.

## Host server

Build the host tools, then run:

```sh
cmake --build --preset host-debug --target swg_integration_server
./build/host-debug/integration/swg_integration_server --bind 0.0.0.0
```

For a Raspberry Pi or other Linux box, use the server-only preset so the passive harness builds without pulling in the full Switch, SDK, and WireGuard crypto tree. On Raspberry Pi OS or Debian-like systems:

```sh
sudo apt update
sudo apt install -y cmake ninja-build g++
cmake --preset host-server
cmake --build --preset host-server --target swg_integration_server
./build/host-server/integration/swg_integration_server --bind 0.0.0.0
```

If you prefer not to use presets, this is the equivalent manual configure line:

```sh
cmake -S . -B build/pi-server -G Ninja -DCMAKE_BUILD_TYPE=Release -DSWG_BUILD_HOST_TOOLS=ON -DSWG_BUILD_SWITCH_TARGETS=OFF -DSWG_BUILD_TESTS=OFF -DSWG_BUILD_INTEGRATION_SERVER_ONLY=ON
cmake --build build/pi-server --target swg_integration_server
./build/pi-server/integration/swg_integration_server --bind 0.0.0.0
```

Remote update from your main machine works well over SSH:

```sh
rsync -av --delete ./ pi@raspberrypi:/home/pi/WGSysModule/
ssh pi@raspberrypi 'cd /home/pi/WGSysModule && cmake --build build/pi-server --target swg_integration_server'
```

The server exposes three IPv4 listeners:

- TCP echo on `28080`
- HTTP probe on `28081`
- UDP echo on `28082`

The HTTP listener returns a plain-text `200 OK` response on `/swg/health` with the observed client address and request path. The TCP and UDP listeners echo the exact payload bytes they receive.

If the test machine sits behind the VPN server on the routed LAN, point the Switch-side `target_host` at that machine. If the routed host is configured with a numeric IPv4 address, also set `dns_hostname` so the DNS test still exercises tunnel resolution.

## Switch config

Add or update this section in the active runtime config:

```ini
[integration_test]
target_host = 192.168.50.10
dns_hostname = tunnel-test.example.net
tcp_echo_port = 28080
http_port = 28081
udp_echo_port = 28082
http_path = /swg/health
```

If `target_host` is left empty, the integration app falls back to the active profile `endpoint_host`.

## Switch controls

- `A`: connect or disconnect the active tunnel
- `X`: open or close the app session
- `Y`: run the full harness
- `Up`: run only the DNS probe
- `Down`: run only the session-socket planning probe
- `LStick`: open the built-in Switch keyboard and edit `integration_test.target_host`

The `Y` action ensures the tunnel and app session are ready, then records per-step pass or fail results for:

- connect and session readiness
- route-planning smoke checks
- integration target resolution
- tunnel DNS
- `SessionSocket` planning mode selection
- TCP echo over `TunnelStreamSocket`
- HTTP probe over `TunnelStreamSocket`
- UDP echo over `TunnelDatagramSocket`

## Current limits

- The harness is IPv4-only because the current tunnel transport is IPv4-only.
- The HTTP probe uses plain HTTP over the tunnel stream path. It validates the byte-stream transport, not TLS.
- `SessionSocket` validation still checks planning mode only; real app-facing traffic validation is handled by the stream and datagram tests.