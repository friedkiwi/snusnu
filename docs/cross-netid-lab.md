# Isolated cross-NETID router lab

The final lab target is V5R4 AnyNet to router A, WebSocket through the QA
concentrator, router B to V4R4 LLC2. V5R4 initiates a pass-through to V4R4.
The two OS/400 guests and routers must use different owners and NETIDs.
This topology is separate from the `SOLNET` regression guests in the
[LLC lab](llc-lab.md) and [AnyNet lab](anynet-lab.md).

| Role | Writable guest | TAP | TN5250 ports | Local CP/LU | QA owner |
| --- | --- | --- | --- | --- | --- |
| V4R4 destination | `/tmp/snusnu-cross-netid/v4-alice` | `sol8` | 25183, 25184 | `QAALICE.SNAA` | Alice |
| V5R4 initiator | `/tmp/snusnu-cross-netid/v5-bob` | `sol9` | 9571, 9572 | `QABOB.SNAB` | Bob |

The directories were cold sparse copies of powered-off writable guests on
2026-11-02, not copies of the original Solstice templates. Their chassis
files use independent TAPs and console ports. The source `SOLNET` guests
retain `sol5`/`sol7` and their original ports. The host filesystem does not
support reflink copies, so the two copies occupy about 9 GiB of allocated
disk space. Do not bridge `sol8` and `sol9`: each guest must see only its own
router endpoint. Guest MACs may match the source clones because the TAPs
remain isolated.

The QA seed gives Alice managed CP `QAALICE.SNAA` and Bob managed CP
`QABOB.SNAB`, with one bearer token for each router. The seed allocates
Alice before Bob, so a fresh database normally gives Bob's CP managed MAC
`02:53:4e:00:00:02`; read the assigned address from the concentrator before
entering it in V4's controller. The Go forwarding policy allows different
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
   `STRPASTHR RMTLOCNAME(SNAA)` from V5.

The current production Rust config accepts a remote WebSocket port only with
an LLC port; it cannot yet configure AnyNet to remote WebSocket conversion.
The native APPN answer side, bidirectional session conversion, and remote
circuit mapping must be ready before running the final test. Do not change
the `SOLNET` regression guests or start the QA concentrator as part of guest
preparation.

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
