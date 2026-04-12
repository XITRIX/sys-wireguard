# Moonlight-Switch Integration Notes

## Why this matters

Moonlight-Switch already owns its own networking stack. It uses:
- libcurl HTTPS control requests for pairing and app launch
- direct socket traffic for streaming and Wake-on-LAN
- mDNS discovery on the local network
- STUN-based external address probing

That means the easiest integration path is not a Moonlight-specific socket wrapper inside `wgsysmodule`.

The better fit is:
- a generic app session API
- route-planning decisions per traffic type
- tunnel-aware DNS responses and guidance
- later, transparent mode as an optimization rather than a hard dependency

## Implemented SDK surface

Core pieces:
- `swg::Client` for service calls
- `swg::AppSession` for app-scoped lifecycle
- `Client::OpenAppSession()` / `CloseAppSession()` / `GetNetworkPlan()` / `ResolveDns()` / `SendPacket()` / `RecvPacket()`
- `AppSession::ResolveDns()` / `SendPacket()` / `ReceivePacket()` for DNS policy checks plus authenticated payload movement once tunnel traffic is flowing
- `swg::TunnelDatagramSocket` for real UDP payload movement over the active tunnel with per-handle remote endpoint metadata
- `swg::TunnelStreamSocket` for real TCP byte-stream movement over the active tunnel with per-handle remote endpoint metadata
- `swg::SessionSocket` for a route-aware wrapper that collapses plan + DNS + packet-channel usage into one SDK object

Moonlight helpers:
- `MakeMoonlightSessionRequest()`
- `MakeMoonlightDiscoveryPlan()`
- `MakeMoonlightWakeOnLanPlan()`
- `MakeMoonlightDnsPlan()`
- `MakeMoonlightHttpsControlPlan()`
- `MakeMoonlightStreamControlPlan()`
- `MakeMoonlightVideoPlan()`
- `MakeMoonlightAudioPlan()`
- `MakeMoonlightInputPlan()`
- `MakeMoonlightStunPlan()`

## Current routing model

For a Moonlight session:
- local discovery bypasses the tunnel
- Wake-on-LAN bypasses the tunnel
- STUN and other external-address probes can bypass the tunnel
- HTTPS control and stream traffic require the active tunnel
- DNS prefers the tunnel when `DnsThroughTunnel` is enabled

`ResolveDns()` currently behaves like this:
- when direct DNS is allowed, it resolves IPv4 hosts locally and returns concrete addresses
- when Moonlight requires tunnel DNS before connect, it fails closed instead of leaking a direct lookup
- once the selected profile is connected, it sends an IPv4 UDP DNS query through the WireGuard session and returns IPv4 answers when a matching response arrives
- if the tunnel DNS query cannot produce an IPv4 answer, it still returns the configured profile DNS servers so the caller can report or debug the unresolved tunnel state without leaking direct DNS

`SessionSocket` currently behaves like this:
- when policy selects `Direct`, it returns resolved IPv4 addresses so Moonlight can open its own native socket
- when policy selects `Tunnel`, it exposes the current session packet channel for caller-managed datagram payloads and framed stream payloads
- when policy selects `Deny`, it preserves the reason as a structured SDK result instead of forcing the caller to manually combine route and DNS calls

`TunnelDatagramSocket` now behaves like this:
- it opens only when the app session, active profile, and route policy all agree that the UDP flow must use the connected tunnel
- it resolves hostname targets to one IPv4 address before opening and binds a stable tunnel-side source UDP port for the handle lifetime
- `Send()` wraps caller payloads as inner IPv4/UDP packets and forwards them through WireGuard
- `Receive()` filters the inbound WireGuard payload queue and returns only UDP packets that match the handle's remote IPv4/port and local source port

`TunnelStreamSocket` now behaves like this:
- it opens only when the app session, active profile, and route policy all agree that the TCP or HTTPS flow must use the connected tunnel
- it resolves hostname targets to one IPv4 address before opening, binds a stable tunnel-side source TCP port, and seeds a deterministic initial send sequence
- `Open()` performs a simple SYN, SYN-ACK, ACK handshake against the remote inner IPv4/TCP endpoint over WireGuard
- `Send()` emits inner IPv4/TCP PSH+ACK segments through WireGuard and advances the tracked local send sequence
- `Receive()` filters inbound WireGuard payloads to the matching inner IPv4/TCP flow, acknowledges in-order payload or FIN segments, and returns the inner TCP payload plus peer-close state

If Moonlight opens a session that requires the tunnel, remote traffic will fail closed until the selected profile is connected.

## Example usage

```cpp
swg::Client client;
swg::AppSession session(client);

auto opened = session.Open(swg::MakeMoonlightSessionRequest("home", true));
if (!opened.ok()) {
  return;
}

auto discovery = session.PlanNetwork(swg::MakeMoonlightDiscoveryPlan());
auto dns_plan = session.PlanNetwork(swg::MakeMoonlightDnsPlan("pc.example.net"));
auto dns = session.ResolveDns("pc.example.net");
auto control = session.PlanNetwork(swg::MakeMoonlightHttpsControlPlan("pc.example.net", 47984));
auto video = session.PlanNetwork(swg::MakeMoonlightVideoPlan("pc.example.net", 47998));
auto video_socket = swg::SessionSocket::OpenDatagram(
  session, swg::MakeMoonlightVideoSocketRequest("203.0.113.8", 47998));
auto video_tunnel = swg::TunnelDatagramSocket::Open(
  session, swg::MakeMoonlightVideoDatagramRequest("203.0.113.8", 47998));
auto control_socket = swg::SessionSocket::OpenStream(
  session, swg::MakeMoonlightHttpsControlSocketRequest("pc.example.net", 47984));
auto control_tunnel = swg::TunnelStreamSocket::Open(
  session, swg::MakeMoonlightHttpsControlStreamRequest("pc.example.net", 47984));
```

Moonlight can keep using its own sockets and libcurl. The sysmodule decides whether that traffic should go direct, require the tunnel, or wait for the tunnel to come up.

The packet API is intentionally narrow: it gives a Moonlight-side shim one place to push and pull authenticated tunnel payloads without requiring transparent routing first, but it still does not replace Moonlight's existing socket semantics by itself.

For Moonlight adoption, the intended split is now:
- discovery, Wake-on-LAN, and STUN stay on Moonlight's native direct sockets
- video, audio, and input can move onto `TunnelDatagramSocket`
- HTTPS control and TCP control can move onto `TunnelStreamSocket`, with TLS or HTTP layered above that byte stream on the app side

The first real Moonlight-Switch consumer patch now exists in the sibling Switch app repo:
- the Switch build imports `swg_common` and `swg_sdk` directly from the sibling `WGSysModule` checkout
- a Switch-only `SwgBridge` owns route planning, tunnel-aware hostname resolution, and TLS-over-`TunnelStreamSocket` for control requests
- `app/src/libgamestream/http.cpp` now tries the `SwgBridge` first, so pairing, app-launch, and other HTTPS control requests can ride the active tunnel without replacing Moonlight's higher-level HTTP call sites
- `extern/moonlight-common-c/src/PlatformSockets.c` now consults the bridge for stream-host DNS so tunneled streaming hosts can resolve through `swg::AppSession` policy before falling back to native resolution
- the integrated Moonlight-Switch Switch target now configures and builds to `Moonlight.nro` with the new bridge enabled

The next consumer patch now moves the rest of Moonlight's transport stack onto the same Switch-only bridge layer:
- `PlatformSockets.c` now classifies recognized Moonlight TCP and UDP sockets on Switch and attaches them to `TunnelStreamSocket` or `TunnelDatagramSocket` before native connect/bind when policy requires the tunnel
- raw TCP and UDP call sites in `ControlStream.c`, `InputStream.c`, `AudioStream.c`, `VideoStream.c`, and `RtspConnection.c` now use bridge-aware helpers so tunneled sockets keep Moonlight's existing send/recv flow
- `enet/unix.c` now routes ENet client sockets through the same datagram bridge on Switch, so Gen 5+ control traffic and ENet-backed RTSP can use the tunnel without changing Moonlight's higher-level ENet logic
- the sibling Switch build still completes successfully after those transport changes, and a deployable `build/switch-swg/Moonlight-Switch.nro` artifact is produced for hardware testing

The DNS helper is still intentionally narrow: it now executes IPv4 A-record DNS queries through the tunnel transport, but it does not yet cover AAAA lookups, TCP fallback, caching, or transparent resolver interception.

The Switch integration app now uses the active profile `endpoint_host` as its live DNS and socket-helper target. If that field is a numeric endpoint, the app skips the DNS probe instead of querying the old placeholder hostname.

`SessionSocket::OpenStream()` is still intentionally staged: in tunnel mode it exposes framed payload flow over the current session packet channel, not a native TCP stack or transparent HTTPS transport. Moonlight-ready TCP flows should use `TunnelStreamSocket` instead.

## Next steps for real integration

- run the new transport bridge on hardware and verify pairing, app launch, RTSP setup, ENet control, audio, video, and input against a real Sunshine/Moonlight host
- capture on-device failures separately by phase: HTTPS control, RTSP setup, ENet control, audio/video receive, and input send
- expand tunnel DNS beyond the current IPv4 A-record path
- add per-title policy so Moonlight NSP forwarders can opt into the tunnel automatically
- add transparent DNS and later `bsd:u` interception as an optional fast path
