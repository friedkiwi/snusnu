# Rust router configuration

`snusnu-router --config FILE` starts multiple independent LLC2 associations and explicit routes. Each `[[llc]]` entry names the guest MAC on one Linux Ethernet interface; `guest_mac` is always required. For an LLC-to-LLC route, each endpoint uses the opposite peer's `guest_mac` as its local proxy address by default. For an LLC route to a non-LLC target, `[[route]] proxy_mac` can specify the local address the guest contacts; a concentrator route normally obtains it from the server's managed CP binding instead. Several entries may use the same TAP. The process needs permission to open AF_PACKET sockets (for example, `CAP_NET_RAW`).

For the two V4R4 guests used in [the LLC lab](llc-lab.md), save this as `router.toml`:

```toml
[[llc]]
id = "snaa"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"

[[llc]]
id = "snab"
interface = "sol4"
guest_mac = "02:00:35:27:23:02"

[[route]]
from = "snaa"
to = "snab"
bidirectional = true
```

Run `sudo sna_router/target/debug/snusnu-router --config router.toml` from the repository root. Each route selects a target association by its stable local ID. A source must have exactly one target while the current flow-control contract is per association. The loader rejects unknown IDs, ambiguous routes, duplicate associations, invalid MACs and ports without a route before opening any socket. `bidirectional` defaults to `true`.

## Local status page

Add an optional `[web]` table to serve the router's read-only status page:

```toml
[web]
listen = "127.0.0.1:8082"
password = "choose-a-password"
```

Open the configured address in a browser. The page shows locally observed LLC and MPTN peers, connection and circuit state, and routes and managed MACs received from the configured concentrator. It does not enable or deny peers; that policy belongs to whichever concentrator is in use. Omit `password`, or set it to an empty string, to allow access without signing in. Omit `[web]` to leave the page disabled. The HTML, CSS, and JavaScript are embedded in the router binary. The read-only status JSON is at `/api/status` and uses the same password session as the page. The local peer cache is stored beside the router config; for `router.toml` its name is `router.peers.toml`. Entries return as `stale` until the peer is observed again. Received upstream routes are never cached.

`proxy_mac` on `[[route]]` overrides an inferred target address for one LLC-facing direction. A bidirectional LLC-to-LLC route has two different local addresses, so it cannot use one route-level override; use the opposite guests' MACs as shown above.

An optional `[[concentrator]]` entry makes a WebSocket hop another named port. For example, use this as a separate configuration to route one LLC association to `upstream`:

```toml
[[llc]]
id = "snaa"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
local_cp = "SOLNET.SNAA"
lus = ["SOLNET.SNAA"]
lu_types = { "SOLNET.SNAA" = ["lu_6_2"] }

[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
target_cp = "SOLNET.SNAB"
token = "replace-with-router-credential"

[[route]]
from = "snaa"
to = "upstream"
```

`token` is optional. Omit it or set `token = ""` to send no Authorization header. Keep a file containing a real token readable only by the router operator; the token is never printed in logs. The older `--remote-link` command still reads `SNUSNU_ROUTER_TOKEN` from the environment.

Configured `[[concentrator]]` entries share one WebSocket connection and publish one snapshot of CPs and LUs derived from their attached local peers. An LLC association declares its CP and LUs once on `[[llc]]`; the router uses those declarations for publication and verifies the CP against the guest's XID3 before LLC2 contact. The `target_cp` (and optional `target_lu`) on an LLC concentrator route currently selects one destination from the concentrator's advertised directory. These target fields are temporary per-circuit selection until the router can select a destination from each incoming session. Standalone LLC routes can omit identity declarations. With route `proxy_mac` omitted, the LLC port waits for the server-assigned virtual MAC of the target CP before accepting or transmitting LLC frames. An explicit managed-prefix route `proxy_mac` remains a provisional value and can be replaced by that binding while LLC is disconnected. Configure the OS/400 remote adapter address to the assigned value shown by the concentrator.

For the embedded APING responder, set `target_cp = "SNUSNU.SVC"` and `target_lu = "SNUSNU.PING"` on the concentrator entry, and configure the guest's remote controller for NETID `SNUSNU`, CP `SVC`, and adapter address `02:53:4e:ff:ff:ff`. The guest's local CP and LU must be declared under `[[llc]]` and supported as LU 6.2. This selects the service for that LLC route until destination selection can be derived from each incoming session. The current service supports APINGD only, with a maximum single PIU of 1496 bytes.

An exported LU can optionally declare its supported type on its local peer for the global directory and remote route metadata. Omitted declarations remain `Unknown`; they are not inferred from the LU name. Keys must also appear in the same peer's `lus`, and duplicate or empty type lists are rejected:

```toml
lus = ["SOLNET.PAYROLL"]
lu_types = { "SOLNET.PAYROLL" = ["lu_6_2"] }
```

Supported values are `lu_0`, `lu_1`, `lu_2`, `lu_3`, and `lu_6_2`. These values are publisher declarations, not proof of a successful BIND negotiation.

This single-target V5R4 TCP62 gateway accepts initiation from either side.
The `[[mptn]]` definition supplies its local CP/LU export and target identity;
the concentrator entry needs only its URL and optional token:

```toml
[[mptn]]
profile = "gateway"
id = "bob-v5"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
local_node_id = "FFF12345"

[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = "replace-with-bob-router-credential"

[[route]]
from = "bob-v5"
to = "upstream"
converter = "mptn_lu62"
user_tp_hex = "30f0f0f5"
```

For a gateway, omitted `source_lu` and `destination_lu` default to `local_cp`
and `peer_cp` respectively. Set either LU explicitly when it differs from
its CP. The local XID station defaults to the local CP name and the TG number
defaults to 1. `bidirectional = true` and `timeout_seconds = 600` are route
defaults. `user_tp_hex` is the four-byte transaction program used when the
concentrator initiates; it is required for that direction. The current native
user address allocation is specific to the QA fixture, and the gateway serves
one active user session at a time. See [the cross-NETID lab](cross-netid-lab.md).

### Several destinations on one TCP62 listener

An incoming TCP62 Connect names both `source_lu` and its destination LU. The
gateway validates those names against the BIND and selects a `[[route]]` by
the exact network-qualified destination. Different remote locations on one
OS/400 peer may therefore resolve to the same gateway IP and TCP/UDP port 397.
The `destination_lu` on each route selects a target behind that listener; if
there is only one gateway route, it may be omitted and defaults to the
gateway's `destination_lu`. For example, the same Bob listener can select two
concentrator targets:

```toml
[[mptn]]
profile = "gateway"
id = "bob-v5"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
source_lu = "QABOB.SNAB"
destination_lu = "QAALICE.SNAA"
local_station = "BOB"
local_node_id = "FFF12345"
tg_number = 1

[[concentrator]]
id = "alice"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = "replace-with-bob-router-credential"
target_cp = "QAALICE.SNAA"
target_lu = "QAALICE.SNAA"

[[concentrator]]
id = "carol"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = "replace-with-bob-router-credential"
target_cp = "QACAROL.SNAC"
target_lu = "QACAROL.SNAC"

[[route]]
from = "bob-v5"
to = "alice"
converter = "mptn_lu62"
destination_lu = "QAALICE.SNAA"

[[route]]
from = "bob-v5"
to = "carol"
converter = "mptn_lu62"
destination_lu = "QACAROL.SNAC"
```

The gateway publishes `QABOB.SNAB` once and uses separate circuit state for
each destination. The URLs and tokens on these concentrator entries must
match, and destination LUs must be unique on the listener. This multiple
destination configuration remains an opt-in QA gateway configuration. The
`peer_cp` and gateway `destination_lu` describe the original single-target
profile; each additional route supplies its own exact target LU and CP.

### Initiating toward a local MPTN peer

In the reverse direction, a native LLC or concentrator session opens with a
BIND for an LU hosted by the local MPTN peer. For this example that target is
`QABOB.SNAB`, the gateway's `source_lu`. The router resolves the target
LU to `bob-v5`, dials `10.99.4.3:397` from `10.99.4.11`, completes the peer's
MPTN management/CNOS exchange, and sends an outbound Connect whose source is
the initiating LU (for example `QAALICE.SNAA`) and destination is
`QABOB.SNAB`. The Connect correlator and native BIND result belong to that
one session; normal, expedited, abort, and close traffic must use its own
state and credit. The ordinary `--config` runtime supports one standalone
LLC-to-MPTN route or one concentrator-to-MPTN route with a configured LU and TP.

An LLC guest still needs a local adapter address for the target CP. On a
standalone route, that address belongs on `[[route]] proxy_mac`; when the
target is advertised through the concentrator, the concentrator assigns and
publishes the virtual CP MAC. The MPTN peer itself is addressed by IP and
does not need an Ethernet MAC. The standalone reverse example below uses a
route-owned proxy MAC.

When `[[llc]] local_cp` is set, the LLC port checks the guest's format-3 XID CP name against it and blocks LLC2 contact until a matching XID3 arrives. A mismatched or malformed XID3 closes that route; the gate resets after disconnect. The router still publishes configured reachability on WebSocket connection before seeing the guest XID: a passive OS/400 peer may need the concentrator route to receive the XID that elicits its own. Publication therefore asserts configured ownership, while live XID verification gates session activation. LU names remain configuration declarations; XID3 identifies the CP, not individual LUs.

An EE link can also be attached without any LLC peers. Each `[[ee]]` entry binds UDP ports 12000–12004 on its `local_ip`, accepts datagrams only from `peer_ip`, and preserves the EE priority port. To relay two EE links, configure two distinct local addresses and route the two IDs together:

```toml
[[ee]]
id = "ee_a"
local_ip = "192.0.2.1"
peer_ip = "192.0.2.11"

[[ee]]
id = "ee_b"
local_ip = "192.0.2.2"
peer_ip = "192.0.2.12"

[[route]]
from = "ee_a"
to = "ee_b"
```

EE↔EE relays EE datagrams. The loader rejects LLC↔EE routes and does not translate LLC2 PIUs into AnyNet MPTN or HPR records. Those profiles require explicit protocol converters.

The [V5R4 EE lab](ee-lab.md) records a complete OS/400 pass-through through this EE configuration on two isolated TAPs.

## Experimental HPR LAN to EE media route

`[[hpr_lan]]` describes one HPR-capable OS/400 Ethernet peer through AF_PACKET. Its `proxy_mac` is the remote adapter address configured on that guest. Pair it with one `[[ee]]` port on an IP address assigned to the host. The media adapter code translates HPR LAN UI framing and EE UDP framing while preserving HPR NLP bytes. **The runtime currently rejects this configuration as unsupported** until it can validate XID3 transmission-group agreement across both media before SETMODE. The example records the intended configuration shape for that integration test.

```toml
[[hpr_lan]]
id = "lan_a"
interface = "sol6"
guest_mac = "02:04:ac:05:45:04"
proxy_mac = "02:04:ac:05:45:05"
experimental = true

[[ee]]
id = "ee_b"
local_ip = "192.0.2.2"
peer_ip = "192.0.2.12"

[[route]]
from = "lan_a"
to = "ee_b"
```

The loader requires `experimental = true` and rejects HPR LAN routes to LLC, AnyNet, WebSocket or another HPR LAN port. It still returns an explicit unsupported error for the HPR LAN to EE pair. The HPR LAN adapter negotiates its HPR SAP from XID3; no fixed `0xC8` SAP is configured. The [direct V5R4 HPR LAN baseline](hpr-lan-lab.md) documents the guest configuration used to validate the adapter.

## MPTN support for IBM AnyNet peers

IBM calls its implementation of Multiprotocol Transport Networking (MPTN) **AnyNet**; the Rust config uses the protocol name. A `relay` profile forwards MPTN records between two IP peers, while a `gateway` profile converts one MPTN LU6.2 session to a native SNA circuit. These profiles need different session handling, so the `profile` field is required. [IBM's glossary](https://www.ibm.com/docs/en/i/7.4.0?topic=glossary-) describes the AnyNet and MPTN relationship.

Two `[[mptn]]` relay ports can form a standalone IP-to-IP route for AnyNet peers. Each port binds TCP and UDP port 397 on its `local_ip` and accepts only the configured `peer_ip`. The adapter handles **one TCP62 LU6.2 session at a time** and validates complete MPTN records before forwarding them. It also validates and rewrites IPv4 UDP/397 node-pair keepalives (`0x84`), including response correlation. UDP/397 expedited traffic (`0x83`) and unknown datagrams close the routed session because their session semantics are not yet supported. This is a constrained MPTN relay.

```toml
[[mptn]]
profile = "relay"
id = "mptn_a"
local_ip = "192.0.2.1"
peer_ip = "192.0.2.11"
local_lu = "SOLNET.SNAA"
remote_lu = "SOLNET.SNAB"

[[mptn]]
profile = "relay"
id = "mptn_b"
local_ip = "192.0.2.2"
peer_ip = "192.0.2.12"
local_lu = "SOLNET.SNAB"
remote_lu = "SOLNET.SNAA"

[[route]]
from = "mptn_a"
to = "mptn_b"
```

Each `local_ip` must already be assigned on the host. Binding TCP and UDP port 397 requires root or `CAP_NET_BIND_SERVICE`. `local_lu` identifies the LU reached through this port's `peer_ip`; `remote_lu` is the LU at the other end of the route. Set both names or omit both, and use the reciprocal pair on the opposite port. With names present, the adapter validates MPTN Connect LU identities and correlator before forwarding the session. The loader rejects duplicate MPTN listener IPs and routes between a relay profile and LLC, EE or WebSocket profiles until a session converter is implemented. IBM AnyNet addressing may embed provider IP addresses, so successful use still depends on paired peer configuration and trace validation.

The [V5R4 AnyNet lab](anynet-lab.md) records an OS/400 pass-through over the configured TCP relay.

## Standalone LLC to MPTN gateway

An ordinary `--config` route can convert a native LLC2 LU6.2 session into
TCP62 for one local MPTN peer. This staged Solstice example uses V4R4 on
`sol5` as the initiator and V5R4 at `10.99.4.3` as the MPTN destination:

```toml
[[llc]]
id = "v4-alice"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
local_cp = "SOLNET.SNAA"
lus = ["SOLNET.SNAA"]

[[mptn]]
profile = "gateway"
id = "v5-bob"
local_ip = "10.99.4.10"
peer_ip = "10.99.4.3"
local_cp = "SOLNET.SNAB"
peer_cp = "SOLNET.SNAA"
source_lu = "SOLNET.SNAB"
destination_lu = "SOLNET.SNAA"
local_station = "SNAB"
local_node_id = "fff12345"
tg_number = 1

[[route]]
from = "v4-alice"
to = "v5-bob"
converter = "mptn_lu62"
proxy_mac = "02:00:35:27:23:02"
user_tp_hex = "30f0f0f5"
timeout_seconds = 600
```

The proxy MAC is the address configured on the initiating LLC guest for the
MPTN-hosted CP. `user_tp_hex` is the four-byte LU6.2 transaction program
name in hexadecimal. `timeout_seconds` bounds session setup; an established
session remains open until a peer closes it or the router stops. The loader requires exactly one LLC peer, one gateway,
one bidirectional route, one exported LLC LU, and matching CP/LU NETIDs.
The converter runs one isolated circuit at a time and rearms after it closes.
It handles TCP62 normal records and correlated UDP X'83' expedited delivery
and normal-end abort; unsupported termination RUs fail closed. The [Solstice lab](anynet-lab.md)
records a V4R4-to-V5R4 Sign On through this ordinary config path.

### Concentrator to a local MPTN peer

The concentrator can also supply the native circuit. The local router
publishes its MPTN-hosted LU once; an authenticated incoming circuit from the
configured source CP opens an outbound TCP62 session to the peer. For example:

```toml
[[mptn]]
profile = "gateway"
id = "bob-v5"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
source_lu = "QABOB.SNAB"
destination_lu = "QAALICE.SNAA"
local_station = "BOB"
local_node_id = "FFF12345"
tg_number = 1

[[concentrator]]
id = "alice"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = "replace-with-bob-router-credential"
target_cp = "QAALICE.SNAA"
target_lu = "QAALICE.SNAA"

[[route]]
from = "alice"
to = "bob-v5"
converter = "mptn_lu62"
destination_lu = "QAALICE.SNAA"
user_tp_hex = "30f0f0f5"
timeout_seconds = 300
```

This is one isolated reverse circuit at a time. The [cross-NETID lab](cross-netid-lab.md)
records Alice V4R4 reaching Bob V5R4 Sign On through this route. Normal
return-home teardown is still being validated.
