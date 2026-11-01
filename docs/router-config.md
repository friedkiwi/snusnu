# Rust router configuration

`snusnu-router --config FILE` starts multiple independent LLC2 associations and explicit routes. Each `[[llc]]` entry names one guest MAC and the proxy MAC that the guest addresses on one Linux Ethernet interface. Several entries may use the same TAP. The process needs permission to open AF_PACKET sockets (for example, `CAP_NET_RAW`).

For the two V4R4 Solstice guests used in [the LLC lab](llc-lab.md), save this as `router.toml`:

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

An optional `[[remote]]` entry makes a WebSocket hop another named port. For example, use this as a separate configuration to route one LLC association to `upstream`:

```toml
[[llc]]
id = "snaa"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:53:4e:00:00:02"

[[remote]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
local_cp = "SOLNET.SNAA"
target_cp = "SOLNET.SNAB"
lus = ["SOLNET.SNAA"]

[[route]]
from = "snaa"
to = "upstream"
```

Set `SNUSNU_ROUTER_TOKEN` in the environment for a remote route. Do not put bearer tokens in the TOML file. The existing `--local-link`, `--remote-link` and `--lab-link` commands remain available.

Configured `[[remote]]` entries share one authenticated connection and publish one snapshot containing all listed CPs and LUs. Each remote circuit must have one local LLC association. `lus` names additional LUs hosted by `local_cp` to export. The configured proxy MAC must be in the `02:53:4e` managed namespace and is updated to the server-assigned virtual MAC while its LLC association is disconnected. Configure the OS/400 remote adapter address to the assigned value shown by the concentrator.

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
