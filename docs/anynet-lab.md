# AnyNet Solstice baseline

Two V5R4 OS/400 guests completed a direct AnyNet pass-through and a second pass-through through the Rust AnyNet↔AnyNet proxy on 2026-11-01. A's `STRPASTHR RMTLOCNAME(SNAB)` reached B's remote Sign On and Main Menu; `ENDPASTHR` returned to A in both runs. These are TCP62 peer baselines and do not demonstrate LLC2↔AnyNet conversion.

The guests were writable clones of `solstice/machine-v5r4-net`, booted with the custom Solstice build at commit `8f89217`. They had distinct Ethernet MACs and IP addresses: A `SOLNET.SNAA` / `10.99.4.2` on `sol6`, B `SOLNET.SNAB` / `10.99.4.3` on `sol7`. Only these two TAPs were connected by an isolated `br-ip-sna` bridge. See the [EE lab](ee-lab.md) for the clone identity and IP setup; HPRIP controllers were varied off for this AnyNet run.

Both guests had `CHGNETA ALWANYNET(*YES)` and their matching `LCLNETID`, `LCLCPNAME`, and `LCLLOCNAME` values. The host table mapped the remote SNA location alias to its IP address:

```text
ADDTCPHTE INTNETADR('10.99.4.3') HOSTNAME(SNAB.SOLNET.SNA.IBM.COM)  [A]
CHGTCPHTE INTNETADR('10.99.4.2') HOSTNAME((*SAME) (SNAA.SOLNET.SNA.IBM.COM))  [B; existing .2 entry]
```

Each guest had a matching APPN remote configuration list entry, such as A's `CRTCFGL TYPE(*APPNRMT) APPNRMTE((SNAB SOLNET *NETATR SNAB SOLNET))`. Create and vary on the AnyNet APPC controllers:

```text
CRTCTLAPPC CTLD(ANYTOB) LINKTYPE(*ANYNW) RMTNETID(SOLNET) RMTCPNAME(SNAB)  [A]
CRTCTLAPPC CTLD(ANYTOA) LINKTYPE(*ANYNW) RMTNETID(SOLNET) RMTCPNAME(SNAA)  [B]
```

The unfiltered `sol6` capture showed a TCP connection from A to B port 397, a 230-byte `MPTN_Connect` request, a 189-byte positive response, normal records, expedited records, and expedited acknowledgements. The Connect request carried BIND and the response carried RSP(BIND). A separate idle session emitted a UDP/397 node-pair keepalive after about four minutes: a `0x84` request and `0x84` response, each with both peer IPv4 addresses embedded in its payload. A proxy that changes outer source IPs must translate this address pair or terminate and reoriginate the keepalive. Solstice emits IP in 802.3 SNAP frames, so a conventional `tcpdump udp` or `tcpdump tcp` capture filter on the TAP missed traffic; capture without a filter and inspect offline. Raw captures and application payloads stay outside this repository.

The Rust [TCP62 codec](../sna_router/crates/transport-ip-sna/src/mptn_connect.rs) now accepts both observed Connect headers. Its BIND-to-FID2 converter is limited to complete normal PIUs after session establishment. The full LLC2↔AnyNet gateway still needs APPN control handling, BIND/session correlation, pacing, expedited traffic, segmentation, UDP keepalive, and teardown behavior.

## Rust AnyNet proxy

For the proxy run, remove `sol6` and `sol7` from the direct bridge. Assign `10.99.4.10/32` to `sol6` and `10.99.4.11/32` to `sol7`, with host routes to guest A `.2` via `sol6` and guest B `.3` via `sol7`, as in the [EE lab](ee-lab.md). Change A's host alias `SNAB.SOLNET.SNA.IBM.COM` to `.10` and B's `SNAA.SOLNET.SNA.IBM.COM` alias to `.11`. Keep the HPRIP controllers off and vary the AnyNet controllers on after starting the router.

```toml
[[anynet]]
id = "mptn_a"
local_ip = "10.99.4.10"
peer_ip = "10.99.4.2"
local_lu = "SOLNET.SNAA"
remote_lu = "SOLNET.SNAB"

[[anynet]]
id = "mptn_b"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_lu = "SOLNET.SNAB"
remote_lu = "SOLNET.SNAA"

[[route]]
from = "mptn_a"
to = "mptn_b"
```

With the TCP-only router at commit `bb4acf2`, the OS/400 pass-through completed remote sign-on, login, and `ENDPASTHR`. The router recorded 13 TCP62 records in each direction (one Connect, ten normal, one expedited, one expedited acknowledgement), with no warnings or errors. Each TAP contained only its guest-to-router IP pair.

The UDP-capable router at commit `77233ef` was then run with an authenticated B Main Menu held idle. After about four minutes, B sent one UDP/397 `0x84` keepalive to its router-facing IP. The sol7 capture showed provider addresses `.3,.11`; the sol6 egress showed rewritten `.10,.2`. A replied with `.10,.2`, and the sol7 egress returned `.3,.11` to B. Each TAP recorded one request and one response, the router logged no warnings or errors, and a subsequent remote `DSPNETA` command still displayed B's network attributes. This proves the supported IPv4 node-pair keepalive path for this V5R4 pair. UDP `0x83` out-of-band traffic remains unsupported and closes the route.
