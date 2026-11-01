# Enterprise Extender V5R4 lab

On 2026-11-01, two emulated V5R4 OS/400 guests completed `STRPASTHR`, remote sign-on, and `ENDPASTHR` through the Rust router's configured EE↔EE UDP relay. The relay carried XID3 activation on UDP 12000 and HPR UI traffic on UDP 12000, 12001, and 12003. This tests EE media forwarding between two HPRIP links. It does not test conversion to native LLC2 APPN.

## Guests and links

Use writable clones of the private V5R4 network template; do not modify the template disk. The lab used two isolated TAPs, with no bridge between them:

| Guest | TAP | Local IP | Local CP | HPRIP remote IP |
| --- | --- | --- | --- | --- |
| A | `sol6` | `10.99.4.2` | `SOLNET.SNAA` | `10.99.4.10` |
| B | `sol7` | `10.99.4.3` | `SOLNET.SNAB` | `10.99.4.11` |

The cloned guests initially had the same Ethernet MAC and IP address. Give B a distinct locally administered line adapter address, for example `0204AC054505`, while `ETHLIN` is varied off. Move B's TCP/IP interface from `10.99.4.2` to `10.99.4.3`, then start it and confirm A can ping B before separating the TAPs. Do not place both clones on a shared network while their MAC or IP identities still collide.

Set `LCLNETID(SOLNET)`, `LCLCPNAME(SNAA)`/`(SNAB)`, and matching `LCLLOCNAME` on A/B. Enable EE with `CHGNETA ALWHPRTWR(*YES)` on each guest. Create and vary on the HPRIP controllers:

```text
CRTCTLAPPC CTLD(EETOB) LINKTYPE(*HPRIP) RMTINTNETA('10.99.4.10') LCLINTNETA('10.99.4.2') RMTNETID(SOLNET) RMTCPNAME(SNAB)  [A]
CRTCTLAPPC CTLD(EETOA) LINKTYPE(*HPRIP) RMTINTNETA('10.99.4.11') LCLINTNETA('10.99.4.3') RMTNETID(SOLNET) RMTCPNAME(SNAA)  [B]
```

Both guests also needed an APPN remote configuration list entry for the other location. A used `CRTCFGL TYPE(*APPNRMT) APPNRMTE((SNAB SOLNET *NETATR SNAB SOLNET))`; B used the corresponding `SNAA` entry. Without it, `STRPASTHR` reported that the route to the location was not found.

## Host and router

Assign a host address to each TAP and a host route to its guest:

```sh
sudo ip addr add 10.99.4.10/32 dev sol6
sudo ip addr add 10.99.4.11/32 dev sol7
sudo ip route add 10.99.4.2/32 dev sol6 src 10.99.4.10
sudo ip route add 10.99.4.3/32 dev sol7 src 10.99.4.11
```

The router configuration was:

```toml
[[ee]]
id = "ee_a"
local_ip = "10.99.4.10"
peer_ip = "10.99.4.2"

[[ee]]
id = "ee_b"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"

[[route]]
from = "ee_a"
to = "ee_b"
```

Start `snusnu-router --config ee.toml` before varying the guest HPRIP controllers on. A `STRPASTHR RMTLOCNAME(SNAB)` reached B's remote Sign On and Main Menu; `ENDPASTHR` returned A to its Main Menu. The isolated TAP captures contained matching XID3, TEST, and UI HPR packets on each leg, and the router reported no warnings or errors during the session. Packet captures stay outside this repository because application data can appear in them.

The EE wire format and its limits are described in [SNA over IP](sna-over-ip.md). The two guests must treat the router-facing IPs as their EE neighbors; the relay preserves SAP bytes and UDP priority ports while using each configured local IP as the source address on that leg.
