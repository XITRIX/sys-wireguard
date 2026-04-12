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
- once the selected profile is connected, it returns a tunnel action plus the configured profile DNS servers so the caller can stage tunnel-side resolution without guessing policy

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
```

Moonlight can keep using its own sockets and libcurl. The sysmodule decides whether that traffic should go direct, require the tunnel, or wait for the tunnel to come up.

The packet API is intentionally narrow: it gives a Moonlight-side shim one place to push and pull authenticated tunnel payloads without requiring transparent routing first, but it still does not replace Moonlight's existing socket semantics by itself.

The DNS helper is also intentionally staged: it provides policy-safe direct results and tunnel-DNS guidance now, but it does not yet execute DNS queries through the tunnel transport itself.

## Next steps for real integration

- add a higher-level socket or stream abstraction on top of the raw packet API
- execute tunnel-side DNS lookups behind the current `ResolveDns()` guidance response
- add per-title policy so Moonlight NSP forwarders can opt into the tunnel automatically
- add transparent DNS and later `bsd:u` interception as an optional fast path
