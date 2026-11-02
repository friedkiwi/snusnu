# Isolated cross-NETID router lab

The completed lab route is V5R4 AnyNet to router A, WebSocket through the QA
concentrator, router B to V4R4 LLC2. V5R4 initiates a pass-through to V4R4.
The two OS/400 guests and routers must use different owners and NETIDs.
This topology is separate from the `SOLNET` regression guests in the
[LLC lab](llc-lab.md) and [AnyNet lab](anynet-lab.md).

| Role | Writable guest | TAP | TN5250 ports | Local CP/LU | QA owner |
| --- | --- | --- | --- | --- | --- |
| V4R4 destination | `/tmp/snusnu-cross-netid/v4-alice` | `sol8` | 25183, 25184 | `QAALICE.SNAA` | Alice |
| V5R4 initiator | `/tmp/snusnu-cross-netid/v5-bob` | `sol9` | 9571, 9572 | `QABOB.SNAB` | Bob |

The directories were cold sparse copies of powered-off writable guests on
2026-11-02, not copies of the original private templates. Their chassis
files use independent TAPs and console ports. The source guests
retain `sol5`/`sol7` and their original ports. The host filesystem does not
support reflink copies, so the two copies occupy about 9 GiB of allocated
disk space. Do not bridge `sol8` and `sol9`: each guest must see only its own
router endpoint. Guest MACs may match the source clones because the TAPs
remain isolated.

The QA seed gives Alice and Bob one bearer token for each router. The
concentrator automatically allocates a stable managed MAC when each router
first advertises `QAALICE.SNAA` or `QABOB.SNAB`; read the resulting address
from the global directory before entering it in V4's controller. The Go forwarding policy allows different
owners by default unless a router is paused or either user blocks the other.

Configure only the copied OS/400 guests after they reach Main Menu:

1. Vary V4 controller/device `SNAB` off. Set `CHGNETA LCLNETID(QAALICE)`;
   keep local CP and location `SNAA`. Change controller `SNAB` to remote
   NETID `QABOB`, remote CP `SNAB`, adapter address equal to Bob's assigned
   managed MAC, and `INLCNN(*ANS)` so V4 can answer V5's session. Confirm
   with `DSPNETA` and `DSPCTLD CTLD(SNAB)` before varying it on.
2. Vary V5 device `SNAA00` and controller `ANYTOA` off. Set
   `CHGNETA LCLNETID(QABOB)`; keep local CP and location `SNAB`. Change
   controller `ANYTOA` to remote NETID `QAALICE` and remote CP `SNAA`.
   In `WRKCFGL`/`QAPPNRMT`, replace the remote `SNAA` entry's NETID and
   CP NETID with `QAALICE`, preserving local location `SNAB`. Change only
   the SNA host alias to `SNAA.QAALICE.SNA.IBM.COM` at router A's IP;
   preserve B's system hostname entry and its address. Confirm the host
   table, controller, and remote-location list before varying `ANYTOA` on.
3. Use host IP `10.99.4.11/32` and an on-link host route on `sol9` to reach
   the V5 guest's existing `10.99.4.3` address; bind router A's TCP/UDP 397
   endpoint to `10.99.4.11`.
   Router B uses `sol8` and Bob's server-owned managed MAC toward V4. Both
   routers connect to the same QA WebSocket endpoint with their respective
   bearer tokens. Publish the local CP/LU on each router, then initiate
   `STRPASTHR RMTLOCNAME(SNAA) RMTNETID(QAALICE) LCLLOCNAME(SNAB)` from V5.

The end-to-end route reached the remote V4R4 Sign On twice; the eighth run
remained active past the former 180-second lab deadline. It currently uses
the opt-in `--mptn-ws-gateway-lab` path. The ordinary `--config` runtime
keeps the `[[mptn]] profile = "gateway"` path gated because native session addressing still uses
the QA fixture's address and the gateway handles one user session per run.
The X'83' UDP completion and teardown handlers are implemented and covered
by focused tests, but have not been exercised against a live OS/400 UDP
exchange. The `SOLNET` regression guests remain separate from this lab.
The preserved QA router TOML files record the exact successful run but need
conversion before reuse: their `[[remote]]` entries repeat local export
fields that the current loader rejects, and Bob's old `[[mptn_gateway]]`
section predates the unified MPTN config. Use `[[concentrator]]` with `url`,
`token`, and any needed destination selector; declare the local CP and LUs
on `[[llc]]` or `[[mptn]] profile = "gateway"` once. See
[router configuration](router-config.md).

## Prepared clone state

Both cold copies booted and reached Main Menu on 2026-11-02. Their original
`SOLNET` guests were powered off during the copies to keep the DASD images
consistent. The original guests were then restarted from their unchanged
disks; `DSPNETA` reconfirmed `SOLNET.SNAA` on V4 and `SOLNET.SNAB` on V5.
On the V4 copy, the following changes succeeded with its APPC
controllers varied off:

```text
VRYCFG CFGOBJ(SNAB) CFGTYPE(*CTL) STATUS(*OFF)
VRYCFG CFGOBJ(QILANM3601) CFGTYPE(*CTL) STATUS(*OFF)
CHGNETA LCLNETID(QAALICE)
CHGCTLAPPC CTLD(SNAB) RMTNETID(QABOB) RMTCPNAME(SNAB) ADPTADR(02534E000002) INLCNN(*ANS)
```

`DSPNETA` confirmed `QAALICE.SNAA`, and `DSPCTLD SNAB` confirmed remote
`QABOB.SNAB`, answer mode, and the expected Bob managed MAC. The managed MAC
was later compared with the live fresh QA address-book assignment: the
concentrator sent `QABOB.SNAB` as `02:53:4e:00:00:02` to Alice's router,
matching V4's configured adapter address.
An opt-in active-XID probe on isolated `sol8` then reached LLC2 contact:
Alice answered the null XID, negotiated XID3, and sent SABME to Rust; the
probe answered UA. The probe stopped before any application session. Alice's
`SNAB` controller and device were varied off afterward.

On the V5 copy, `ANYTOA` and the automatically created virtual APPN
controller `QAPEND0001` had to be varied off before `CHGNETA` would accept
the NETID change. The following changes then succeeded:

```text
CHGNETA LCLNETID(QABOB)
CHGCTLAPPC CTLD(ANYTOA) RMTNETID(QAALICE) RMTCPNAME(SNAA)
RMVTCPHTE INTNETADR('10.99.4.10')
ADDTCPHTE INTNETADR('10.99.4.11') HOSTNAME(SNAA.QAALICE.SNA.IBM.COM)
```

`CHGCFGL TYPE(*APPNRMT)` provided the V5R4 entry screen; the existing
`SNAA` row was edited to remote NETID `QAALICE`, local location `SNAB`,
remote CP `SNAA`, and CP NETID `QAALICE`. `DSPNETA`, `DSPCTLD ANYTOA`,
the configuration-list screen, and `CFGTCP` option 10 confirmed the new
values. The system hostname entry was preserved. `QAPEND0001` and
`ANYTOA` were then varied on. The IBM [AnyNet setup guide](https://www.ibm.com/support/pages/setting-ibm-anynet-os400-system)
describes the `location.NETID.SNA.IBM.COM` host alias and `QAPPNRMT`
relationship.

The source `SOLNET` V5 guest also uses IP `10.99.4.3` on a different TAP.
The host therefore uses a source policy route for Bob's copied guest rather
than replacing the source guest's main-table route:

```sh
sudo ip addr add 10.99.4.11/32 dev sol9
sudo ip route add 10.99.4.3/32 dev sol9 src 10.99.4.11 table 109
sudo ip rule add pref 1009 from 10.99.4.11/32 lookup 109
```

`ip route get 10.99.4.3 from 10.99.4.11` selected `sol9`, while the
unchanged `.10` source selected `sol7`; two source-pinned pings to Bob's
guest succeeded. The TAPs remain outside any bridge.

## First Bob-initiated management probe

An opt-in Rust TCP62 listener on `10.99.4.11:397` accepted only the Bob
guest's `10.99.4.3` source. An unqualified
`STRPASTHR RMTLOCNAME(SNAA)` returned `Route to specified location not
found` before any TCP/397 packet. Both `SNAA` devices were active and no
`QAPPNLCL` list shadowed the target. With the same guest configuration,

```text
STRPASTHR RMTLOCNAME(SNAA) RMTNETID(QAALICE) LCLLOCNAME(SNAB)
```

sent a 228-byte SNASVCMG TCP62 Connect to `10.99.4.11:397`. The opt-in
listener rejected a previously unobserved guarded token flag before its
positive response, so the guest reported APPC failure
`0009000000000000`. This probe proves that explicit remote NETID selection
reaches the router from the prepared V5 clone; it does not prove a completed
management session. Captures remain private outside the repository.

A third bounded probe, after the guarded token parser accepted Bob's
observed variant, completed the TCP62 management exchange: Bob sent a
228-byte SNASVCMG Connect and received a 189-byte positive response; it
then sent a 47-byte CNOS record and received a 35-byte AcceptedPending
reply. The peers exchanged 11-byte BIS records, and Bob sent a correlated
37-byte management UNBIND before FIN. Bob opened a second TCP/397 session
and sent a 228-byte user Connect. The opt-in management-only listener
deliberately rejected that user session, and Bob reported APPC failure
`68268002000032FE`. The private capture contains 22 packets and no UDP
datagrams. This proves the copied V5 guest can initiate cross-NETID AnyNet
management and reach user Connect; it does not establish the WebSocket or
LLC2 route.

## First combined WebSocket gateway runs

The QA concentrator authenticated Bob and Alice as separate router owners.
Its managed binding for `QABOB.SNAB` was delivered to Alice as
`02:53:4e:00:00:02`. A virtual native management probe through the
WebSocket concentrator reached the passive V4 Alice guest and completed
SNASVCMG BIND, CNOS/IPR/BIS, and correlated management UNBIND response.

The first combined AnyNet/WebSocket/LLC run exposed an autonomous Bob user
Connect retry before the manual pass-through trigger; the router rejected
that unexpected order. The next run reached Alice's positive user BIND
response with TH/RH `2f0002020000 eb8500`, an observed V4R4 response
variant. A corrected run then missed a short idle LLC window by about one
second: Alice disconnected before Bob's first TCP SYN. Prefilling the
NETID-qualified `STRPASTHR` and pressing Enter immediately after the TCP
listener became ready removed that timing gap.

In the fourth combined run, Bob's user Connect reached V4 Alice; Alice
returned a positive user BIND response, and the router queued the positive
TCP62 Connect response. The router forwarded Bob's first FMH-5 Attach to
Alice, then stopped on Alice's first 12-byte native pacing PIU
(`2f0002020000 830100 000003`) with the diagnostic
`native pacing response must be handled locally`. Bob reported APPC failure
`E01A8002000032FE`; remote Sign On was not reached. Private captures are
`/tmp/snusnu-cross-netid/combined4-sol9.pcap` and `combined4-sol8.pcap`
(13 and 70 packets, zero capture drops). The next gateway step is to
consume that native pacing response locally and continue the user session.

The sixth combined run consumed Alice's first 12-byte pacing IPR and
advanced to a live V4 target session: Alice's `SNAB` controller and devices
became active, with mode `BLANK` shown as `ACTIVE/TARGET *PASSTHR`. Bob's
console selected virtual device `QPADEV0001` on Alice's system but remained
at pass-through initialization until its APPC timeout
`E01A8002000032FE`; no remote Sign On appeared. The wire trace narrowed
the stall: after Alice's 82-byte FMD response, Rust sent a nine-byte empty
native IPR `2f0002020000830100` and a nine-byte positive response. In the
successful direct V4R4 baseline the originator instead sent a 12-byte IPR
`2f0002020000830100000006` before the destination produced its display
record; the positive response matched. The missing three-byte pacing grant
is the next live gateway question. Private captures are
`combined6-sol9.pcap` and `combined6-sol8.pcap` in the lab directory (18
and 109 packets, zero capture drops).

The seventh combined run used the adaptive 12-byte native IPR grant. Bob's
NETID-qualified `STRPASTHR` traversed its AnyNet TCP/397 connection, Rust
router A, the QA concentrator WebSocket, Rust router B, and Alice's LLC2
link. Bob displayed Alice's remote `Sign On` screen (`System S1012345`,
virtual display `QPADEV0001`). No credentials were entered. The private
captures `combined7-sol9.pcap` and `combined7-sol8.pcap` contain 13 and
97 packets respectively, with zero capture drops. This verifies the
cross-NETID route through the first remote display; authenticated sign-on
and normal session teardown remain to be checked. The seventh router used
a bounded 180-second lab timeout, so a follow-up with an established
session held open is planned.

The eighth combined run used a router build that keeps an established user
session open. The same NETID-qualified pass-through reached Alice's remote
`Sign On` again on Bob's console, with blank credentials. The two private
captures, `combined8-sol9.pcap` and `combined8-sol8.pcap`, contain 13 and
87 packets and had zero capture drops. Both captures were stopped while
the guest screen and QA concentrator/router processes remained running.
At 00:22:08 UTC the Bob router process had been alive for 3 minutes 8
seconds, past the earlier 180-second deadline, and Bob still displayed
Alice's remote `Sign On` with blank credentials. Both QA router processes,
the concentrator, and both writable QA guests were left running.

## Multi-target gateway regression on 2026-11-02

The QA concentrator was started temporarily on `0.0.0.0:8081`. Alice's
current-schema `[[llc]]` router published `QAALICE.SNAA` and received Bob's
managed MAC `02:53:4e:00:00:02`. Bob's opt-in MPTN gateway used one
`10.99.4.11:397` listener and two `[[route]] destination_lu` selectors:
`QAALICE.SNAA` (Alice's live route) and `QAALICE.SNAC` (deliberately absent
from the QA directory). Both concentrator targets shared one WebSocket and
Bob's `QABOB.SNAB` LU export.

The first user attempt exposed an overly strict ingress check: Bob's live
Connect carried a PLU-generated X'03' session instance starting with `0x24`,
while the validator required `0x23`. The failing 228-byte Connect is in the
private capture `/tmp/snusnu-cross-netid/multi-target-bob-20261102.pcap`.
After the validator accepted the generated byte while still requiring the
repeated X'13' token to match, the next run logged
`source_lu=QABOB.SNAB destination_lu=QAALICE.SNAA target=0`. Bob's V5R4
console reached Alice V4R4's remote **Sign On**, system `S1012345`, virtual
device `QPADEV0001`, through Bob's TCP62 listener, the WebSocket
concentrator, and Alice's LLC2 link. The screen remained up for about 50
seconds before the test processes were stopped. No credentials were entered.

This run verifies the live target selector for `QAALICE.SNAA` and that an
unreachable second configured target did not prevent the first route from
working. Bob has no remote-location definition for `QAALICE.SNAC`, so the
second selector was not exercised by a live OS/400 Connect. Repeated
sessions on one target and native-initiated LLC-to-MPTN routing remain
unverified here. Both Rust routers and the QA concentrator were stopped
after the run; the isolated Solstice guests remain booted.

## Concentrator to local MPTN peer on 2026-11-02

Alice V4R4 on `sol8` initiated `STRPASTHR RMTLOCNAME(SNAB)
RMTNETID(QABOB) LCLLOCNAME(SNAA)` through its LLC2 router and the QA
concentrator. Bob's router used ordinary `--config` with a directed
`[[route]]` from the concentrator to its local `[[mptn]] profile = "gateway"`
peer at `10.99.4.3:397`. Its hosted LU was `QABOB.SNAB`; the source LU was
`QAALICE.SNAA`. Both routers published their CP/LU exports under separate
QA bearer tokens and NETIDs. Alice's `SNAB` controller was temporarily
changed from `INLCNN(*ANS)` to `*DIAL`, retaining Bob's managed MAC
`02:53:4e:00:00:02`.

The fifth live attempt reached V5R4 Bob's remote **Sign On** on Alice's
TN5250 display: system `S1054504`, subsystem `QBASE`, virtual device
`QPADEV0001`. The operator log records the Sign On at guest time 11:11:58.
Bob's router log is `/tmp/snusnu-cross-netid/ws-reverse-bob4.log`; Alice's
is `ws-reverse-alice4.log`. The log records authenticated WebSocket Open,
XID3/LLC2, native SNASVCMG/CNOS and UNBIND, outbound TCP62 management,
user BIND, first FMH-5 Attach, and a 524-byte display PIU. TCP
`10.99.4.11:39515 → 10.99.4.3:397` remained established while the Sign On
screen was visible for over a minute. No credentials were entered.

The first live run exposed a one-slot assumption in the WebSocket native
CNOS response queue; a focused fix allowed the pair of responses. A later
run exposed management UNBIND being mistaken for a user BIND; the next
focused fix recognized and acknowledged that UNBIND. Guest controller
status also needed attention: when `SNAB` and `SNAB00` were `VARY ON
PENDING`, Alice sent no LLC frames. Varying the controller off and on with
both routers available made them `ACTIVE`.

The return-home SysReq action did **not** complete normally. Bob's router
exited with `TCP62 normal data is not an FM request` after a native FM
response, and Alice reported a communications failure for `SNAB00`.
At that point normal teardown in this direction remained unverified. After the test,
Alice's controller was restored to `INLCNN(*ANS)` and varied on; both Rust
routers and QA concentrator were stopped. Ports 397 and 8081 had no
listeners. The isolated Solstice guests remain booted.

### Final return-home retest

The final retest used the transport fix that correlates V5's short TCP62
FM positive response with Alice's outstanding definite-response request.
Alice again reached Bob V5R4's **Sign On** (`S1054504`, `QBASE`,
`QPADEV0001`) through LLC2, the QA WebSocket concentrator, and Bob's
MPTN TCP/397 peer. The TCP session remained established while the screen
was displayed. A fresh QA directory assigned Bob managed MAC
`02:53:4e:00:00:01`, so Alice's `SNAB` `ADPTADR` was temporarily changed
from `02534E000002` to `02534E000001` for this run.

Alice's System Request generated three FM definite-response requests.
For each, Bob sent native IPR, forwarded V5's `RH 83a000` positive response
over the WebSocket, and Alice acknowledged that response on LLC2. The
bounded `sol8` capture records the three request sequence numbers
`0003`, `0004`, and `0005` and the corresponding LLC receive
acknowledgments. Bob's router stayed running and no communications failure
appeared. On Alice's local System Request menu, option `2` (End previous
request) returned to its Main Menu with `Last request at level 3 ended.`
Options `11` and `15` returned to the remote Sign On and did not end the
pass-through request.

Private evidence is in `/tmp/snusnu-cross-netid/ws-reverse-bob-final.log`,
`ws-reverse-alice-final.log`, `ws-reverse-final-sol9.pcap` (43 packets), and
`ws-reverse-sysreq-sol8.pcap` (24 packets); both captures had zero drops.
Alice's `SNAB` was restored to `INLCNN(*ANS)` and `ADPTADR(02534E000002)`,
verified by `DSPCTLD`. Both Rust routers and the QA concentrator were
stopped, with no listeners on ports 397 or 8081. The isolated Solstice
guests remain booted. No remote sign-on credentials were entered.

## One configured Bob gateway, both initiation directions

On 2026-11-02, Bob's V5R4 router used one `[[mptn]] profile = "gateway"`,
one `[[concentrator]]`, and one bidirectional `mptn_lu62` route with
`user_tp_hex = "30f0f0f5"`. The QA concentrator listened on
`0.0.0.0:8081`, with Alice's V4R4 router attached over LLC2. A fresh QA
directory assigned Bob the managed MAC `02:53:4e:00:00:01`.

Bob first initiated `STRPASTHR RMTLOCNAME(SNAA) RMTNETID(QAALICE)
LCLLOCNAME(SNAB)` and reached Alice's remote Sign On (`S1012345`,
`QPADEV0001`) through TCP62, Bob's shared WebSocket, the concentrator,
and Alice's LLC2 link. Alice then initiated `STRPASTHR RMTLOCNAME(SNAB)
RMTNETID(QABOB) LCLLOCNAME(SNAA)` and reached Bob's remote Sign On
(`S1054504`, `QPADEV0001`) through the reverse path. After Alice ended
that request, Bob initiated again and reached Alice's Sign On **without
restarting Bob's router**. The latter two sessions and the intervening
router recovery are recorded in
`/tmp/snusnu-cross-netid/bob-duplex-reverse.log`.

The reverse session's native teardown still raises `later native PIU is not
an FM request`; Bob's router logs the session error, recreates its circuit,
and remains available. Alice's dial controller briefly reopened an idle
native link before it was varied off. The earlier Bob-initiated session
also remained attached after the local return-home action; varying Bob's
`ANYTOA` controller off closed TCP62 and exposed an unsupported TCP62
UNBIND shape. The router now treats that peer protocol failure as a
circuit failure and retries, rather than exiting. These are teardown gaps,
so this run proves sequential initiation in both directions and Sign On,
not clean protocol shutdown or concurrent opposite-direction sessions.

Alice's `SNAB` controller was restored to `INLCNN(*ANS)` and its original
`ADPTADR(02534E000002)`, then varied on. Bob's `ANYTOA` was varied on.
Both Rust routers and the QA concentrator were stopped; ports 397 and 8081
had no listeners. No remote sign-on credentials were entered.
