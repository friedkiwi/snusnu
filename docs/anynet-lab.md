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

A fresh pass-through on the later `cd967f6` tree, including Connect response-direction validation and route fault isolation, again reached B's Main Menu and ended normally. Both router-facing TAPs contained only their configured guest/IP pair, and the router logged no warnings or errors. The test router and captures were stopped afterward.

## Direct teardown observations

An isolated direct V5R4 run captured both TAPs during `STRPASTHR`, B sign-on, and a normal `ENDPASTHR`. A second active session was terminated by varying B's `ANYTOA` controller off; B reported that device `SNAA00` was varied off while in session, and A reported a communications failure for `SNAB00`. The controllers were restored afterward. The unfiltered captures are private at `/tmp/snusnu-v5r4-ip-lab/direct-anynet-teardown-sol6.pcap` and `direct-anynet-teardown-sol7.pcap`.

Neither case emitted UDP/397 `0x83` out-of-band data. The active-session failure produced one 59-byte TCP `0x10` compensation record from B and then a TCP reset from A. Both session starts had TCP `0x01` expedited records of 15 and 11 bytes and a five-byte `0x03` acknowledgement. This trace supports strict TCP expedited acknowledgement framing; it does not establish the V5R4 UDP `0x83` wire shape or justify enabling that path in the router.

## Focused expedited and out-of-band capture

A further direct run on the isolated `sol6`/`sol7` bridge captured two A-to-B pass-through starts, remote sign-on, and normal `ENDPASTHR` returns. Each start sent a 15-byte TCP62 `0x01` expedited record B→A, an 11-byte `0x01` record A→B, and a five-byte `0x03` acknowledgement B→A. The unfiltered captures contain 143 frames on `sol6` and 142 on `sol7`. Neither contains any UDP datagram. Private captures are at `/tmp/snusnu-v5r4-ip-lab/direct-anynet-oob-sol6.pcap` and `direct-anynet-oob-sol7.pcap`.

To test delayed expedited acknowledgement, the host applied a 15-second `tc netem` delay on `sol6` egress (B→A) for one pass-through start and, separately, for one `ENDPASTHR`. Each delay had a bounded lifetime and the original `fq_codel` queue discipline was restored. Both pass-throughs completed and ended normally, but no UDP/397 `0x83` appeared on either TAP. This is a negative result for these actions and this OS/400 configuration; it does not establish that V5R4 cannot send `0x83`. The [IBM AnyNet guide](https://publibz.boulder.ibm.com/epubs/pdf/f1ap6000.pdf) describes UDP out-of-band retries when an expedited acknowledgement is delayed and UDP UNBIND for some session termination flows, but this template did not exercise either wire path. A trace-backed `0x83` codec still needs a peer/application setup that actually emits one.

A more focused run dropped exactly one B→A TCP62 `0x03` acknowledgement while leaving other TCP records and UDP untouched. The temporary egress filter matched the full 79-byte 802.3 SNAP frame shape: 802.3 length 65, IPv4 total length 57, B `.3` to A `.2`, TCP source port 397, a 32-byte TCP header, and record `00 00 00 05 03`. An offline check against the private V5 captures found only five-byte `0x03` records; a live counter-only run matched one 79-byte ACK before the drop run. During the drop run, `sol7` recorded the ACK at 19:36:11.363852 local time, `sol6` recorded no corresponding egress frame, and `tc` counted one 79-byte drop. The filter expired after 35 seconds and was removed along with its temporary queue discipline. A still reached B's Main Menu and returned normally with `ENDPASTHR`. Both TAP captures contain zero UDP/397 datagrams. This proves only that this single lost ACK did not elicit `0x83` during the observation window; it does not cover other expedited events or longer retries. Private captures are `/tmp/snusnu-v5r4-ip-lab/anynet-oob-drop-sol6.pcap` and `anynet-oob-drop-sol7.pcap`.

The dropped five-byte `0x03` record was not retransmitted with the same TCP
sequence before capture stopped; later normal TCP records continued. This
helps explain the lack of a UDP fallback in this particular exchange, but
does not establish when other expedited senders choose to retry.

The UDP wire format has an unresolved contradiction in the [IBM-authored TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00): section 3.2.2.1 says an out-of-band UDP datagram omits the four-byte record length because UDP preserves message boundaries, while section 5.3.3 lists that length as the first field of `MPTN_DG_OOB_Data`. No captured `0x83` packet settles which form V5R4 sends. Rust has a bounded section-5.3.3 structural parser and separate TCP/UDP expedited sequence-deduplication state, but `GatewaySession` does not accept or emit `0x83`, send its UDP acknowledgement, or retry it. The `0x83` required compensation must stay unavailable. To complete it, capture an actual V5R4 `0x83` request and response, establish the record-length and alias forms, then verify duplicate suppression when the same expedited message arrives over both TCP and UDP, response correlation, retry limits, and abort handling.

## Proposed V4R4 LLC2 to V5R4 AnyNet lab

This topology is a plan for the first media-conversion test; it has not been
run. Keep V4R4 A on isolated `sol5` and V5R4 B on isolated `sol7`, with no
Linux bridge between them. Remove `sol7` from the direct V5 bridge and keep
V5R4 A on `sol6` disconnected or stopped, so its `SOLNET.SNAA` identity cannot
compete with the Rust router. The V4R4 A guest is `SOLNET.SNAA`, MAC
`02:00:35:27:23:01`; its existing `SNAB` LAN controller targets proxy MAC
`02:00:35:27:23:02` and remote CP `SOLNET.SNAB`. V5R4 B is `SOLNET.SNAB`, IP
`10.99.4.3`; its existing `ANYTOA` controller targets remote CP
`SOLNET.SNAA`, with `ALWANYNET(*YES)` and the `SNAA` APPN remote entry.

When the gateway harness is ready, give the Rust host `10.99.4.10/32` on
`sol7` and a host route to B. The V4R4 LLC leg needs no IP address:

```sh
sudo ip link set sol7 nomaster
sudo ip addr add 10.99.4.10/32 dev sol7
sudo ip route replace 10.99.4.3/32 dev sol7 src 10.99.4.10
```

On B, point the host-table name `SNAA.SOLNET.SNA.IBM.COM` at `.10` instead of
the direct V5 peer `.2`, checking the existing entry before changing it.
IBM documents this [AnyNet name form](https://www.ibm.com/docs/en/i/7.5.0?topic=beginning-add-tcpip-host-table-entry)
and the [host-entry address rename command](https://www.ibm.com/docs/en/i/7.5.0?topic=r-rename-tcpip-host-table-entry).
If `.2` has a dedicated `SNAA` entry, the planned OS/400 command is
`RNMTCPHTE INTNETADR('10.99.4.2') NEWINTNETA('10.99.4.10')`; otherwise edit
only that alias. Vary B `ANYTOA` off before the change and on after Rust is
listening. Vary A `SNAB` on only after the LLC side is listening.

The Rust LLC side must present CP `SOLNET.SNAB`, station `SNAB`, and proxy MAC
`02:00:35:27:23:02` to A. Its AnyNet side must bind `.10`, target B `.3`,
and present local LU `SOLNET.SNAA` to remote LU `SOLNET.SNAB`. These local
identities are the adjacent peer identities each guest already expects.
The mixed test requires the gateway to correlate user BIND, management
teardown, FMH-5 Attach and replies, pacing, and session cleanup across the
two media. The current native probe has reached A's first FMH-5 Attach but
has not completed an application conversation, so the plan is not yet a
pass-through acceptance result.
