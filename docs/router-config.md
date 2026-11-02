# Rust router configuration

`snusnu-router --config FILE` starts multiple independent LLC2 associations and explicit routes. Each `[[llc]]` entry names one guest MAC and the proxy MAC that the guest addresses on one Linux Ethernet interface. Several entries may use the same TAP. The process needs permission to open AF_PACKET sockets (for example, `CAP_NET_RAW`).

For the two V4R4 guests used in [the LLC lab](llc-lab.md), save this as `router.toml`:

```toml
[[llc]]
id = "snaa"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:00:35:27:23:02"

[[llc]]
id = "snab"
interface = "sol4"
guest_mac = "02:00:35:27:23:02"
proxy_mac = "02:00:35:27:23:01"

[[route]]
from = "snaa"
to = "snab"
bidirectional = true
```

Run `sudo sna_router/target/debug/snusnu-router --config router.toml` from the repository root. Each route selects a target association by its stable local ID. A source must have exactly one target while the current flow-control contract is per association. The loader rejects unknown IDs, ambiguous routes, duplicate associations, invalid MACs and ports without a route before opening any socket. `bidirectional` defaults to `true`.

An optional `[[concentrator]]` entry makes a WebSocket hop another named port. For example, use this as a separate configuration to route one LLC association to `upstream`:

```toml
[[llc]]
id = "snaa"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:53:4e:00:00:02"
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

`token` is the concentrator's bearer credential for this router. Use `token = ""` when the endpoint does not require bearer authentication. Keep a file containing a real token readable only by the router operator; the token is never printed in logs. The older `--remote-link` command still reads `SNUSNU_ROUTER_TOKEN` from the environment.

Configured `[[concentrator]]` entries share one authenticated connection and publish one snapshot of CPs and LUs derived from their attached local peers. An LLC association declares its CP and LUs once on `[[llc]]`; the router uses those declarations for publication and verifies the CP against the guest's XID3 before LLC2 contact. The `target_cp` (and optional `target_lu`) on an LLC concentrator route currently selects one destination from the concentrator's advertised directory. These target fields are temporary per-circuit selection until the router can select a destination from each incoming session. Standalone LLC routes can omit identity declarations. The configured proxy MAC must be in the `02:53:4e` managed namespace and is updated to the server-assigned virtual MAC while its LLC association is disconnected. Configure the OS/400 remote adapter address to the assigned value shown by the concentrator.

An exported LU can optionally declare its supported type on its local peer for the global directory and remote route metadata. Omitted declarations remain `Unknown`; they are not inferred from the LU name. Keys must also appear in the same peer's `lus`, and duplicate or empty type lists are rejected:

```toml
lus = ["SOLNET.PAYROLL"]
lu_types = { "SOLNET.PAYROLL" = ["lu_6_2"] }
```

Supported values are `lu_0`, `lu_1`, `lu_2`, `lu_3`, and `lu_6_2`. These values are publisher declarations, not proof of a successful BIND negotiation.

The opt-in V5R4 TCP62 gateway uses its `[[mptn_gateway]]` definition as the
source of local CP/LU exports and the remote destination names. It therefore
needs no CP/LU fields on `[[concentrator]]`:

```toml
[[mptn_gateway]]
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
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = "replace-with-bob-router-credential"

[[route]]
from = "bob-v5"
to = "upstream"
converter = "mptn_lu62"
```

This gateway still requires `--mptn-ws-gateway-lab FILE
--acknowledge-experimental-x83`; the ordinary `--config` runtime rejects it
because its native address selection and session lifecycle are specific to
the QA fixture. See [the cross-NETID lab](cross-netid-lab.md).

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

## Constrained AnyNet relay

Two `[[anynet]]` ports can form a standalone AnyNet↔AnyNet route. Each port binds TCP and UDP port 397 on its `local_ip` and accepts only the configured `peer_ip`. The adapter handles **one TCP62 LU6.2 session at a time** and validates complete MPTN records before forwarding them. It also validates and rewrites IPv4 UDP/397 node-pair keepalives (`0x84`), including response correlation. UDP/397 expedited traffic (`0x83`) and unknown datagrams close the routed session because their session semantics are not yet supported. This is a constrained AnyNet relay, not a general MPTN gateway.

```toml
[[anynet]]
id = "mptn_a"
local_ip = "192.0.2.1"
peer_ip = "192.0.2.11"
local_lu = "SOLNET.SNAA"
remote_lu = "SOLNET.SNAB"

[[anynet]]
id = "mptn_b"
local_ip = "192.0.2.2"
peer_ip = "192.0.2.12"
local_lu = "SOLNET.SNAB"
remote_lu = "SOLNET.SNAA"

[[route]]
from = "mptn_a"
to = "mptn_b"
```

Each `local_ip` must already be assigned on the host. Binding TCP and UDP port 397 requires root or `CAP_NET_BIND_SERVICE`. `local_lu` identifies the LU reached through this port's `peer_ip`; `remote_lu` is the LU at the other end of the route. Set both names or omit both, and use the reciprocal pair on the opposite port. With names present, the adapter validates MPTN Connect LU identities and correlator before forwarding the session. The loader rejects duplicate AnyNet listener IPs and routes between AnyNet and LLC, EE or WebSocket profiles until a session converter is implemented. IBM's AnyNet addressing may embed provider IP addresses, so successful use still depends on paired peer configuration and trace validation.

The [V5R4 AnyNet lab](anynet-lab.md) records an OS/400 pass-through over the configured TCP relay.

## LLC to AnyNet gateway route intent

The route syntax reserves an explicit converter for a future native LU6.2 to MPTN gateway:

```toml
[[route]]
from = "native_lu62"
to = "mptn_lu62"
converter = "mptn_lu62"
```

This route currently fails configuration loading with an `Unsupported` error. Native LLC2 information fields and TCP62 records require session-state translation, including BIND negotiation and the requested MPTN compensations. The router will enable this converter only when both protocol handlers are complete and tested against peers. A cross-profile route without a converter is rejected as an unsupported route.
