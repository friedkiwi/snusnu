# AnyNet V5R4 baseline

Two V5R4 OS/400 guests completed a direct AnyNet pass-through and a second pass-through through the Rust MPTN relay on 2026-11-01. A's `STRPASTHR RMTLOCNAME(SNAB)` reached B's remote Sign On and Main Menu; `ENDPASTHR` returned to A in both runs. These are TCP62 peer baselines and do not demonstrate LLC2↔AnyNet conversion. The current Rust config calls this `[[mptn]] profile = "relay"`; IBM's AnyNet is the guest implementation.

The guests were writable clones of a private V5R4 network template. They had distinct Ethernet MACs and IP addresses: A `SOLNET.SNAA` / `10.99.4.2` on `sol6`, B `SOLNET.SNAB` / `10.99.4.3` on `sol7`. Only these two TAPs were connected by an isolated `br-ip-sna` bridge. See the [EE lab](ee-lab.md) for the clone identity and IP setup; HPRIP controllers were varied off for this AnyNet run.

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

The unfiltered `sol6` capture showed a TCP connection from A to B port 397, a 230-byte `MPTN_Connect` request, a 189-byte positive response, normal records, expedited records, and expedited acknowledgements. The Connect request carried BIND and the response carried RSP(BIND). A separate idle session emitted a UDP/397 node-pair keepalive after about four minutes: a `0x84` request and `0x84` response, each with both peer IPv4 addresses embedded in its payload. A proxy that changes outer source IPs must translate this address pair or terminate and reoriginate the keepalive. The lab emulator emits IP in 802.3 SNAP frames, so a conventional `tcpdump udp` or `tcpdump tcp` capture filter on the TAP missed traffic; capture without a filter and inspect offline. Raw captures and application payloads stay outside this repository.

The Rust [TCP62 codec](../sna_router/crates/transport-ip-sna/src/mptn_connect.rs) now accepts both observed Connect headers. Its BIND-to-FID2 converter is limited to complete normal PIUs after session establishment. The full LLC2↔AnyNet gateway still needs APPN control handling, BIND/session correlation, pacing, expedited traffic, segmentation, UDP keepalive, and teardown behavior.

## Rust MPTN relay for AnyNet peers

For the proxy run, remove `sol6` and `sol7` from the direct bridge. Assign `10.99.4.10/32` to `sol6` and `10.99.4.11/32` to `sol7`, with host routes to guest A `.2` via `sol6` and guest B `.3` via `sol7`, as in the [EE lab](ee-lab.md). Change A's host alias `SNAB.SOLNET.SNA.IBM.COM` to `.10` and B's `SNAA.SOLNET.SNA.IBM.COM` alias to `.11`. Keep the HPRIP controllers off and vary the AnyNet controllers on after starting the router.

```toml
[[mptn]]
profile = "relay"
id = "mptn_a"
local_ip = "10.99.4.10"
peer_ip = "10.99.4.2"
local_lu = "SOLNET.SNAA"
remote_lu = "SOLNET.SNAB"

[[mptn]]
profile = "relay"
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

A later isolated test delayed B-to-A frames for 15 seconds during both startup and `ENDPASTHR`; a separate test dropped one exact five-byte TCP `0x03` acknowledgement. Both completed without any UDP/397 `0x83` datagram. IBM's [TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00), section 3.2.2.1, says an OOB datagram does not need a four-byte length field for its data portion, while section 5.3.3 explicitly includes a four-byte Record Length in the `0x83` command format. The bounded parser follows the detailed section 5.3.3 command format. With no captured `0x83` packet, that choice remains unverified against V5R4 and must not enable the X19 compensation gate.

## Focused expedited and out-of-band capture

A further direct run on the isolated `sol6`/`sol7` bridge captured two A-to-B pass-through starts, remote sign-on, and normal `ENDPASTHR` returns. Each start sent a 15-byte TCP62 `0x01` expedited record B→A, an 11-byte `0x01` record A→B, and a five-byte `0x03` acknowledgement B→A. The unfiltered captures contain 143 frames on `sol6` and 142 on `sol7`. Neither contains any UDP datagram. Private captures are at `/tmp/snusnu-v5r4-ip-lab/direct-anynet-oob-sol6.pcap` and `direct-anynet-oob-sol7.pcap`.

To test delayed expedited acknowledgement, the host applied a 15-second `tc netem` delay on `sol6` egress (B→A) for one pass-through start and, separately, for one `ENDPASTHR`. Each delay had a bounded lifetime and the original `fq_codel` queue discipline was restored. Both pass-throughs completed and ended normally, but no UDP/397 `0x83` appeared on either TAP. This is a negative result for these actions and this OS/400 configuration; it does not establish that V5R4 cannot send `0x83`. The [IBM AnyNet guide](https://publibz.boulder.ibm.com/epubs/pdf/f1ap6000.pdf) describes UDP out-of-band retries when an expedited acknowledgement is delayed and UDP UNBIND for some session termination flows, but this template did not exercise either wire path. A trace-backed `0x83` codec still needs a peer/application setup that actually emits one.

A more focused run dropped exactly one B→A TCP62 `0x03` acknowledgement while leaving other TCP records and UDP untouched. The temporary egress filter matched the full 79-byte 802.3 SNAP frame shape: 802.3 length 65, IPv4 total length 57, B `.3` to A `.2`, TCP source port 397, a 32-byte TCP header, and record `00 00 00 05 03`. An offline check against the private V5 captures found only five-byte `0x03` records; a live counter-only run matched one 79-byte ACK before the drop run. During the drop run, `sol7` recorded the ACK at 19:36:11.363852 local time, `sol6` recorded no corresponding egress frame, and `tc` counted one 79-byte drop. The filter expired after 35 seconds and was removed along with its temporary queue discipline. A still reached B's Main Menu and returned normally with `ENDPASTHR`. Both TAP captures contain zero UDP/397 datagrams. This proves only that this single lost ACK did not elicit `0x83` during the observation window; it does not cover other expedited events or longer retries. Private captures are `/tmp/snusnu-v5r4-ip-lab/anynet-oob-drop-sol6.pcap` and `anynet-oob-drop-sol7.pcap`.

The dropped five-byte `0x03` record was not retransmitted with the same TCP
sequence before capture stopped; later normal TCP records continued. This
helps explain the lack of a UDP fallback in this particular exchange, but
does not establish when other expedited senders choose to retry.

The UDP wire format has an unresolved contradiction in the [IBM-authored TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00): section 3.2.2.1 says an out-of-band UDP datagram omits the four-byte record length because UDP preserves message boundaries, while section 5.3.3 lists that length as the first field of `MPTN_DG_OOB_Data`. No captured `0x83` packet settles which form V5R4 sends. Rust has a bounded section-5.3.3 structural parser and separate TCP/UDP expedited sequence-deduplication state, but `GatewaySession` does not accept or emit `0x83`, send its UDP acknowledgement, or retry it. The `0x83` required compensation must stay unavailable. To complete it, capture an actual V5R4 `0x83` request and response, establish the record-length and alias forms, then verify duplicate suppression when the same expedited message arrives over both TCP and UDP, response correlation, retry limits, and abort handling.

## V4R4 LLC2 to V5R4 AnyNet mixed lab

This topology was staged for the first media-conversion test. Keep V4R4 A on
isolated `sol5` and V5R4 B on isolated `sol7`, with no
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

The writable B clone's `.2` host-table entry contained both
`S1054504.LABHOST.LOCAL` and `SNAA.SOLNET.SNA.IBM.COM`. To preserve B's
system hostname, the mixed-lab setup moved only the second name:

```text
CHGTCPHTE INTNETADR('10.99.4.2') HOSTNAME((*SAME) (*BLANK))
ADDTCPHTE INTNETADR('10.99.4.10') HOSTNAME(SNAA.SOLNET.SNA.IBM.COM)
```

The B host-table display then showed `.2` with only the system hostname and
`.10` with only the SNAA AnyNet alias. The [V5R4 CHGTCPHTE reference](https://public.dhe.ibm.com/systems/power/docs/systemi/v5r4/en_US/SS1-4.pdf)
defines `*SAME` and `*BLANK` for individual host-name slots. B's `ANYTOA`
controller remained varied on with its `SNAA00` device varied off, and its
`QAPPNRMT` entry still mapped remote `SNAA` in `SOLNET` to local `SNAB`.
The host `.10/32` address and route to B `.3` were staged on isolated `sol7`,
and two host pings to B succeeded. These are setup checks; the mixed gateway
has not yet carried a conversation. Vary A `SNAB` on only after the LLC side
is listening.

The Rust LLC side must present CP `SOLNET.SNAB`, station `SNAB`, and proxy MAC
`02:00:35:27:23:02` to A. Its AnyNet side must bind `.10`, target B `.3`,
and present local LU `SOLNET.SNAA` to remote LU `SOLNET.SNAB`. These local
identities are the adjacent peer identities each guest already expects.
The mixed test requires the gateway to correlate user BIND, management
teardown, FMH-5 Attach and replies, pacing, and session cleanup across the
two media. The current native probe has reached A's first FMH-5 Attach but
has not completed an application conversation, so the plan is not yet a
pass-through acceptance result.

The first opt-in mixed harness run on 1 November 2026 reached native LLC2
and management exchange. A sent its 141-byte user BIND while Rust's
management BIS I-frame was awaiting its LLC acknowledgement. A's BIND
carried N(R)=4; A subsequently sent RR with N(R)=5. The harness rejected
the early user BIND and sent DISC before opening TCP/397 to B. This exposed
an overly strict transition in the Rust harness, not an AnyNet Connect
failure. The private unfiltered captures are
`/tmp/snusnu-v4r4-regression/native-converter-v5-sol5.pcap` and
`/tmp/snusnu-v5r4-ip-lab/native-converter-v5-sol7.pcap`. No application
conversation crossed the media boundary in this run.

The retry after the native overlap fix reached TCP62. Rust sent a 225-byte
MPTN Connect request from `.10` to B `.3:397`, with destination
`SOLNET.SNAB`, source `SOLNET.SNAA`, and a 141-byte BIND connection-data
option. B ACKed it, then opened a separate connection from `.3` to
`.10:397`; the host returned TCP RST because this diagnostic did not listen
on port 397. B's 126-byte negative Connect response used processing flags
`0xEA` and included a negative BIND sense `08050000` plus an `0xF0`
diagnostic option. Rust then closed the outbound connection and sent native
DISC. The failed reverse connection and negative response are observed in
the private captures `native-converter-v5-retry-sol5.pcap` and
`native-converter-v5-retry-sol7.pcap` in the lab directories above. Their
causal relationship remains to be tested with a reverse TCP/397 listener.

A subsequent reverse-listener diagnostic stopped before TCP: after a valid
management UNBIND response, A sent the 141-byte user BIND with DAF `0x01`
instead of the `0x02` seen in the earlier run. The only other differences
in the two user BIND PIUs were the session-specific FQPCID and correlator
bytes. Rust's strict session-address check rejected it and sent DISC; the
capture contains no user BIND response. This demonstrates that the writable
V4R4 guest can reuse address `0x01` for the user session after management
teardown. The private capture is `native-converter-v5-third-sol5.pcap` in
the V4 lab directory.

## Fresh direct management baseline

To resolve the mixed lab's reverse management Connect, both writable V5R4
clones were connected directly after stopping the Rust diagnostic and keeping
the V4 controller off. A's `ETHLIN` initially referenced missing hardware
resource `CMN01`; `WRKHDWRSC TYPE(*CMN)` showed `CMN02` operational, so the
writable A clone used `CHGLINETH LIND(ETHLIN) RSRCNAME(CMN02)`, then varied
`ETHLIN` on. Its TCP/IP interface `.2`, `ETHLINET` controller, and `ETHLITCP`
device became active. A ping to B `.3` produced four request/reply pairs.
For this direct run only, B's SNAA host alias moved from `.10` back to `.2`;
the host route and address `.10/32` were left intact. Captures started before
the sol6/sol7 bridge was connected.

The direct pass-through reached B's remote Sign On. On the private `sol7`
capture, frame 61 was A `.2` to B `.3:397` with a 230-byte MPTN Connect
request containing a 137-byte `SNASVCMG` BIND. Frame 62, 66 ms later, was
B's 189-byte positive Connect response with a 96-byte positive BIND response
and the same correlator. Both carried options `0x05`, `0x0A`, `0x18`, `0x19`,
and `0x1A` (`0x84` keepalive). Frames 63–66 were the CNOS Attach/reply and
BIS exchange in normal records; frame 67 was an Abort ending the management
session. Frames 74–76 then opened and accepted the user Connect and carried
the first FMH-5 Attach. B did not initiate a reverse TCP Connect during this
clean direct startup. The private captures are
`/tmp/snusnu-v5r4-ip-lab/direct-management-sol6.pcap` and
`direct-management-sol7.pcap`; no raw capture or application data is in this
repository.

After `ENDPASTHR` returned normally, A was stopped and the bridge removed.
B's host table was restored to `.2` containing only its system hostname and
`.10` containing only `SNAA.SOLNET.SNA.IBM.COM`; B's `SNAA00` device was
varied off. The original host `.10/32` route to B `.3` again passed two pings.

## Outbound management and first real mixed Attach

The first opt-in Rust outbound management attempt on the isolated `.10` to
B `.3:397` path received a 189-byte *positive* SNASVCMG Connect response,
but its strict response validator rejected B's newly allocated BIND token.
The direct baseline token ended `80 00`; this positive response ended
`00 00`. The LU pair, correlator, 22-byte FQPCID, BIND structure, and
option set matched. The validator was corrected to admit both observed token
forms. This diagnostic did not open the native LLC endpoint or touch V4.

In the next opt-in run, Rust sent a 230-byte SNASVCMG Connect request and
received B's 189-byte positive response. The subsequent normal records were
CNOS Attach (47 bytes), CNOS reply (35), and two 11-byte BIS records,
followed by a 38-byte management Abort. Rust then opened the native LLC
endpoint. V4R4 A's `STRPASTHR RMTLOCNAME(SNAB)` reached the user BIND; Rust
sent a 225-byte user Connect request to B, received a 184-byte positive
response, and delivered A's first FMH-5 Attach in a 243-byte TCP62 normal
record to the real V5R4 peer. The opt-in diagnostic deliberately stopped
there. V4 returned to Main Menu with APPC failure `E022000BA2100000`, so
this is evidence of BIND admission and one application record crossing the
LLC/AnyNet boundary, not a completed remote sign-on.

The private captures are
`/tmp/snusnu-v5r4-ip-lab/native-management-outbound-retry-sol7.pcap` and
`/tmp/snusnu-v4r4-regression/native-management-outbound-retry-sol5.pcap`.
After the run, B's `SNAA00` device and V4's `SNAB` controller/device were
varied off. B's `.10` alias, host route, and isolated sol7 topology remain
ready for a sustained-flow test.

The first sustained-flow diagnostic advanced one record further. After
Rust sent A's 242-byte FMH-5 Attach to B, B returned an 83-byte TCP62 normal
record; Rust forwarded its 82-byte SNA body to A. A acknowledged the LLC
I-frame and sent its own nine-byte pacing IPR PIU
`2c0001020000830100`. Rust had previously sent A an IPR
`2d0002010000830100`, which A also acknowledged. The diagnostic then
rejected A's IPR as violating session pacing and sent DISC. The failure is
in the Rust pacing state after a valid peer response, before remote sign-on.
V4 displayed APPC failure `E022000BA2100000`. Private captures are
`/tmp/snusnu-v4r4-regression/native-sustained-sol5.pcap` and
`/tmp/snusnu-v5r4-ip-lab/native-sustained-sol7.pcap`; both guest devices
were varied off after the run.

The next run after a pacing-state adjustment made the response sequence
clearer. The user BIND used DAF/OAF `02/02`. After Rust forwarded B's
82-byte first user response, A sent a nine-byte IPR
`2c0002020000830100`, followed about 5 ms later by a distinct nine-byte
PIU `2c000202800083a000` with its TH response bit set. The latter coincided
with the Rust `native user IPR violates session pacing` error. The exact
meaning of that second PIU and B's first response still need protocol-level
validation before accepting it as ordinary pacing. The private captures are
`native-sustained2-sol5.pcap` and `native-sustained2-sol7.pcap` in the same
lab directories; both devices were varied off afterward.

A third local sustained run forwarded B's first FMD positive response and
V4's separate user IPR and positive response across the LLC/AnyNet boundary.
B then sent a 525-byte TCP62 normal record whose SNA body began with an RQE1
and definite-response request. The Rust diagnostic stopped with
`TCP62 definite response request is unsupported or outstanding` before that
record reached V4. The V4 workstation did not reach remote Sign On. Private
captures are `native-sustained3-sol5.pcap` and
`native-sustained3-sol7.pcap` in the same lab directories.

After adding the bounded RQE1/definite-response handling, a fourth local
run reached V5R4 B's remote Sign On screen from the V4R4 A workstation.
The screen identified B's system and virtual display; no credentials were
entered. The Sign On stayed stable until the Rust diagnostic was stopped
cleanly. The private `native-sustained4-sol5.pcap` and
`native-sustained4-sol7.pcap` captures contain 60 and 26 packets respectively,
with zero capture drops. Attempts to invoke System Request from the remote
Sign On did not produce a visible menu, so normal application `ENDPASTHR`
teardown was not verified in this run. After stopping the diagnostic, V4's
`SNAB` controller and device and B's `SNAA00` device were varied off. This
run verifies local LLC2-to-AnyNet conversion through remote Sign On; it does
not exercise the concentrator or WebSocket route.

On 2 November 2026, the staged `sol5`/`sol7` pair repeated the sustained
reverse test with the current Rust tree. The first attempt exposed a V5R4
SNASVCMG response whose fresh X'13' instance type was X'24'; the initiator
had accepted only X'23'. The response matched the request's FQPCID and
transport correlator. After accepting both observed instance types, the
management/CNOS exchange completed. With the router listening on `sol5`,
varying V4R4 A's `SNAB` controller off and on restored APPN contact. A's
`STRPASTHR RMTLOCNAME(SNAB)` then reached V5R4 B's remote Sign On screen:
system `S1054504`, subsystem `QBASE`, display `QPADEV0001`. The router log
records XID3, LLC2, native management BIND, user BIND, and first Attach
delivery. The TCP user connection from `10.99.4.10` to `10.99.4.3:397`
remained established at the Sign On screen. No concentrator was running.
The opt-in command was:

```sh
sudo sna_router/target/debug/snusnu-router \
  --native-converter-v5-flow-lab /tmp/snusnu-native-v4a-user-pacing.toml \
  10.99.4.10 10.99.4.3 --acknowledge-experimental-x83
```

The private runtime log is `/tmp/snusnu-reverse-20261102c.log`; the failed
management attempt was captured at
`/tmp/snusnu-reverse-20261102-sol7.pcap`. The diagnostic was stopped after
the Sign On check. A returned to its local menu with a communications failure,
and its `SNAB` controller and B's `SNAA00` device were varied off. This live
run verifies the opt-in LLC2→TCP62 direction through Sign On. It did not
exercise ordinary `--config`, normal `ENDPASTHR` teardown, UDP X'83', or the
WebSocket concentrator.

The extracted one-circuit runner repeated that Sign On through its opt-in
`--mptn-llc-reverse-lab` entry. On 2 November 2026, the same staged guests
then completed an **ordinary `--config`** run using the standalone
LLC-to-MPTN example in [router-config.md](router-config.md). The router
started from `/tmp/snusnu-reverse-ordinary.toml` at 09:49:55 UTC, completed
V5R4 SNASVCMG/CNOS, and opened LLC2 after V4R4's `SNAB` controller was varied
on. `STRPASTHR RMTLOCNAME(SNAB)` reached V5R4 Sign On at system `S1054504`,
subsystem `QBASE`, display `QPADEV0001`. The TCP user connection
`10.99.4.10:48697 → 10.99.4.3:397` remained established while the Sign On
screen was held for over 50 seconds. Router output recorded XID3/LLC2,
native management BIND/CNOS/BIS/UNBIND, and user BIND. The router was then
stopped with SIGINT; it disconnected LLC cleanly and V4R4 returned to its
Main Menu with a communications failure. The QA concentrator was not running.
This verifies ordinary standalone LLC→MPTN routing through Sign On; normal
`ENDPASTHR`, UDP X'83' abort, and concentrator→MPTN initiation remain untested
or unsupported.

The same `sol5`/`sol7` pair then reached the V5R4 remote Sign On through the
extracted reverse runner, which uses the reusable outbound TCP62 connector,
V5R4 management/CNOS initiator, `GatewayEdge`, and a route Connect template.
The command was:

```sh
sudo sna_router/target/debug/snusnu-router \
  --mptn-llc-reverse-lab /tmp/snusnu-native-v4a-user-pacing.toml \
  10.99.4.10 10.99.4.3 --acknowledge-experimental-x83
```

After A's `SNAB` controller was varied on, `STRPASTHR RMTLOCNAME(SNAB)`
displayed B's `S1054504` Sign On (`QBASE`, `QPADEV0001`). The private log
`/tmp/snusnu-reverse-extracted-20261102.log` records management readiness,
XID3/LLC2 contact, native BIND validation, and the separate user TCP/397
connection. This verifies the extracted opt-in runner; ordinary `--config`
and normal session teardown remain separate acceptance checks.
