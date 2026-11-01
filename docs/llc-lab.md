# Local LLC2 and SNA lab

The Rust router's `--lab-link` mode joins two isolated Linux TAP interfaces. It relays LLC TEST and XID frames, terminates LLC2 separately on each interface, and forwards accepted SNA information fields in order. The OS/400 guests own XID3, APPC sessions, and APPN names. This mode is a fixed two-peer test path for local interoperability.

## V4R4 emulator setup

The first interoperability run used two writable clones of a private V4R4 template, each booted with IPL source A, keyswitch normal, and no virtual panel. Keep the template disk untouched. Attach guest A to `sol5` and guest B to `sol4`; leave both TAPs out of any host bridge. The TAPs must be up and owned by the user running the emulator. Give the clones distinct console ports and MAC addresses:

| Guest | TAP | MAC | Network / control point | IP |
| --- | --- | --- | --- | --- |
| A | `sol5` | `02:00:35:27:23:01` | `SOLNET.SNAA` | `10.99.0.2` |
| B | `sol4` | `02:00:35:27:23:02` | `SOLNET.SNAB` | `10.99.0.3` |

The template has Ethernet line `ETHLIN`. On each guest, vary controller `QILANM3601` off before changing the network attributes. The relevant OS/400 commands are:

```text
VRYCFG CFGOBJ(QILANM3601) CFGTYPE(*CTL) STATUS(*OFF)
CHGNETA LCLNETID(SOLNET) LCLCPNAME(SNAA) LCLLOCNAME(SNAA)  [A]
CHGNETA LCLNETID(SOLNET) LCLCPNAME(SNAB) LCLLOCNAME(SNAB)  [B]
CRTCTLAPPC CTLD(SNAB) LINKTYPE(*LAN) SWTLINLST(ETHLIN) RMTNETID(SOLNET) RMTCPNAME(SNAB) ADPTADR(020035272302)  [A]
CRTCTLAPPC CTLD(SNAA) LINKTYPE(*LAN) SWTLINLST(ETHLIN) RMTNETID(SOLNET) RMTCPNAME(SNAA) ADPTADR(020035272301) INLCNN(*ANS)  [B]
VRYCFG CFGOBJ(SNAA) CFGTYPE(*CTL) STATUS(*ON)  [B]
VRYCFG CFGOBJ(SNAB) CFGTYPE(*CTL) STATUS(*ON)  [A]
STRPASTHR RMTLOCNAME(SNAB)  [A]
```

Use the `CHGNETA` line marked for each guest, not both. Change B's cloned TCP/IP interface address if TCP/IP is enabled; duplicate addresses are unrelated to APPC but interfere with ordinary IP tests.

The lab deliberately gives each guest's control point and default local location the same name. `SOLNET.SNAB` is therefore both B's network-qualified CP and its default LU/location here; these are distinct OS/400 settings. See [OS/400 SNA names](os400-sna-names.md).

Build and start the Rust relay before varying A's controller on:

```sh
cd sna_router
cargo build --workspace
sudo target/debug/snusnu-router --lab-link sol5 sol4 02:00:35:27:23:01 02:00:35:27:23:02
```

The packet sockets require `CAP_NET_RAW`. `--lab-link` accepts only the two specified source/destination MACs and SNA SAP `0x04`. It has bounded queues and a one-frame LLC2 send window. It waits briefly after one leg connects before initiating SABME on the other leg so an OS/400 guest can finish its outstanding XID3 exchange.

## Observed result

On 2026-11-01, two emulated V4R4M0 guests reached B's remote Sign On from A through the Rust relay. Signing on to B's virtual display and issuing `ENDPASTHR` returned A to its Main Menu normally. Both TAP captures show XID3, SABME/UA, I frames, and RR acknowledgements; the emulator trace shows SNA PIUs and BIND. The router logged both LLC2 legs connected and SNA information fields delivered in both directions. The earlier direct-bridge baseline reached the same remote Sign On.

The initial relay attempt failed when B received SABME before completing its final XID exchange. A short connection barrier resolved that lab timing race. This is an observed interoperability result for these two guests, not a general LLC2 conformance claim.

The raw captures and emulator disks stay outside this repository because SNA application data can appear in them. The TEST/XID bytes used by the parser's regression tests are in `sna_router/crates/router-core/tests/v4r4_llc.rs`.

## Standalone and remote router modes

After extracting the reusable LLC endpoint, the same two V4R4 guests
completed `STRPASTHR`, remote sign-on, and `ENDPASTHR` again through both
`--lab-link` and the standalone route mode:

```sh
sudo target/debug/snusnu-router --local-link \
  sol5 02:00:35:27:23:01 02:00:35:27:23:02 \
  sol4 02:00:35:27:23:02 02:00:35:27:23:01
```

`--local-link` configures each LLC endpoint independently. The endpoints
exchange XID/TEST and SNA information through the router's `RoutePort`
interface. It operates without a concentrator.

The same guests also completed the session through the declarative
[`--config` router](router-config.md) on 2026-11-01. A's `STRPASTHR
RMTLOCNAME(SNAB)` reached B's remote Sign On at 17:02:56 local time;
QSECOFR sign-on reached B's Main Menu at 17:03:05, and `ENDPASTHR`
returned A to its Main Menu at 17:03:12. The router logged both LLC2
associations connected and bidirectional MAC routes. This regression used
the existing two isolated TAPs; same-interface multi-peer filtering has
a separate synthetic AF_PACKET test.

For one LLC endpoint routed through a concentrator, use a router credential
in the environment rather than on the command line:

```sh
export SNUSNU_ROUTER_TOKEN='the-router-credential'
sudo --preserve-env=SNUSNU_ROUTER_TOKEN target/debug/snusnu-router --remote-link \
  sol5 02:00:35:27:23:01 02:00:35:27:23:02 \
  SOLNET.SNAA SOLNET.SNAB wss://concentrator.example/router/v1/ws
```

A second router uses B's TAP and reversed CP/MAC values.

The Rust WebSocket path was also verified with two separate router processes
and the loopback lab broker, using these same configured V4R4 guests. Start
the broker with:

```sh
cargo run -p transport-ws --example lab_broker -- 127.0.0.1:18743
```

Its test credentials are `lab-a` and `lab-b`. Each router then uses
`ws://127.0.0.1:18743/router/v1/ws` and its respective credential.
This broker runs only on loopback and is a test harness for the circuit
protocol; it does not provide concentrator authentication or policy.

In that run, A's `STRPASTHR` reached B's remote Sign On through the two Rust
routers, remote QSECOFR sign-on reached B's Main Menu, and `ENDPASTHR`
returned A to its Main Menu. The broker observed an accepted circuit,
bidirectional XID/TEST, link-ready events, SNA information, and credit. The
first attempt after reboot sent no Ethernet frames until both OS/400 APPC
controllers were varied on again. A complete session then succeeded.

After the WebSocket adapter was changed to share one authenticated socket
between multiple logical circuits, the same legacy `--remote-link` scenario
was rerun through the loopback broker on 2026-11-01. A reached B's remote
Sign On at 17:04:55 local time, signed in to B's Main Menu at 17:05:18,
and returned to A's Main Menu with `ENDPASTHR` at 17:05:21. The broker
observed the accepted circuit, bidirectional XID/TEST, link-ready events,
and SNA information. The broker and router processes were stopped after
the test; the two V4R4 guests remained running.

## Go QA concentrator interoperability

On 2026-11-01, two separate `--remote-link` Rust routers attached to the
same V4R4 guests through the Go QA concentrator's real `/router/v1/ws`
handler. The QA process listened on its default `:8081` address and used
the seeded Alice and Bob router credentials described in
[QA.md](../concentrator/QA.md). Each router published its local CP and
received the other's managed CP binding and live route reference.

A issued `STRPASTHR RMTLOCNAME(SNAB)` at 16:32:07 local time, reached B's
remote Sign On at 16:32:22, signed in to B's Main Menu at 16:32:49, and
issued `ENDPASTHR` at 16:32:52. A returned to its Main Menu immediately.
The QA database retained both live CP advertisements and 178 symmetric
traffic records at the inspection point: 68 Type 1, 100 SNA information,
and 10 link-ready records. The pass-through completed before a likely teardown race:
Go logged `unknown or pending circuit` after forwarding A's close, then
closed B's WebSocket. B reconnected with a fresh epoch and republished its
route. The session result was unaffected. Go should tolerate messages that
were already in flight from an authenticated circuit participant when the
other participant closed the circuit.
The APPC controllers had to be varied on after guest IPL before initiating
the pass-through session.

## One-guest native APPN probe

`--native-probe` tests the Rust router as one locally identified APPN link
station against an isolated guest. It handles TEST, a null XID poll, XID3
role negotiation, and LLC2 contact. On the first SNASVCMG BIND, it logs the
PLU/SLU and disconnects because a positive management BIND response is not yet
implemented. It does not advertise a ready route or carry user traffic.

Use a dedicated TAP and a guest configured to target the probe's proxy MAC and
CP. For the isolated V4R4 SNAA guest on `sol5`, an example configuration is:

```toml
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:00:35:27:23:02"
local_cp = "SOLNET.SNAB"
local_station = "SNAB"
local_node_id = "fff12345"
tg_number = 1
role = "secondary"
timeout_seconds = 600
```

The node ID must be a locally assigned eight-digit hexadecimal value in the
`000` or `FFF` block with a nonzero ID number; it must not be copied from the
guest. `local_station` is this router's unqualified adjacent link-station name.
The configured TG number must match the guest's link definition. The probe
advertises the actual LLC receive limits: BTU 1496 and one I-frame before
acknowledgement. `role` can be `primary` or `secondary`; the primary sends
SABME after complementary XID3 negotiation, while the secondary waits for it.

Run `snusnu-router --native-probe probe.toml` with `CAP_NET_RAW` and optionally
`RUST_LOG=debug` for decoded frames and hex dumps. Exit status 0 with a
`reached SNASVCMG BIND` log means XID3 and LLC2 contact succeeded and the
first management BIND arrived. Protocol errors and the configured timeout
exit with status 1. An operator interrupt exits without a success claim.

For an OS/400 controller configured with `INLCNN(*ANS)`, set `active_xid = true`
in the probe TOML and keep `role = "secondary"`. The probe sends the initial
null XID, follows with its locally configured XID3, waits for the guest's
SABME, and exits successfully at LLC2 contact. It stops before sending a
management BIND. The option is available only with `--native-probe`.

On 2026-11-01, the one-guest probe reached this milestone against the
isolated V4R4 SNAA guest on `sol5` with the fixed-secondary SNAB profile
above. The guest sent a null XID, then prenegotiation and negotiation XID3s.
It resolved itself to primary and sent SABME; Rust answered UA. The link
remained in LLC2 contact with RR polls. After `STRPASTHR`, A sent a 141-byte
SNASVCMG BIND for PLU `SOLNET.SNAA` and SLU `SOLNET.SNAB`. Rust logged the
BIND, sent DISC, and the one-shot probe exited successfully. The captured
BIND used FID2 TH `2d0001020000` and RH `6b8000`, whereas the two-OS/400
baseline used `2f0001020000` and `6b8500`. A management responder must
validate this variation before it can send a positive BIND response. The
capture remains outside the repository because it may include application
data.

### Bounded management-session probe

`--native-management-probe` uses the same isolated-link configuration with
`remote_cp = "SOLNET.SNAA"` added. It validates the guest's SNASVCMG BIND
against the configured LU pair, sends a fixed one-stage +RSP(BIND), accounts
for the LLC acknowledgement, then handles one CNOS Attach with a pacing grant
and an accepted-pending CEB reply. A received isolated pacing response must
match the CNOS flow. It then accepts the guest's BIS, sends its own BIS after
the CNOS bracket drains, and responds to a correlated management UNBIND.
Exit status 0 means the UNBIND response was acknowledged by LLC2. The probe
does not accept a user BIND,
advertise a ready route, or carry routed traffic. Link loss, unsupported
management PIUs, and timeout exit with status 1. Keep `timeout_seconds = 600`
for a full V4R4 IPL and manual `STRPASTHR` activation.
This bounded responder follows the captured remote-first BIS order. BIS is a
normal-flow DFC request and shares the negotiated fixed session pacing: the
guest's BIS receives another IPR, while Rust's BIS uses the next local send
slot without a new pacing indicator.

On 2026-11-01, an initial live run reached the accepted-pending CNOS reply;
the guest sent BIS after that one-shot process exited. A subsequent run with
the BIS responder active reached the following control sequence on the
isolated `sol5` TAP. PIU lengths exclude the LLC header.

| Sender | Control PIU | PIU length | TH / RH or RU marker |
| --- | --- | ---: | --- |
| Guest A | SNASVCMG BIND | 141 | `2d00010200006b8000`, RU `31` |
| Rust | Positive BIND response | 89 | `2d0002010000eb8000`, RU `31` |
| Guest A | FMH-5 Attach / CNOS request | 46 | `2c00010200010b9120`, TP `06f1` |
| Rust | Isolated pacing response | 9 | `2d0002010000830100` |
| Rust | Accepted-pending CNOS reply with CEB | 34 | `2c0002010001039101`, GDS `1210` service `0a` |
| Guest A | Isolated pacing response, then BIS | 9, 10 | BIS `2c00010200024b910070` |
| Rust | Isolated pacing response, then BIS | 9, 10 | BIS `2c00020100024bb00070` |
| Guest A | User BIND with blank mode | 141 | `2d00020200006b8000`, RU `31` |

Rust closed the link on the user BIND as its unsupported gateway boundary
requires. The guest had acknowledged the CNOS reply and both sides had sent
BIS; this run did not reach management UNBIND or a user session. The guest's
display remained at pass-through initialization until the writable clone was
stopped. The private capture is outside the repository and was not used as an
application-data fixture.

### Experimental user BIND response probe

`--native-user-bind-probe` uses the same isolated configuration and follows
the validated management BIND, CNOS, and BIS exchanges. It accepts only the
captured blank/default-mode user BIND for the configured CP pair, then sends
one fixed-window candidate +RSP(BIND). It waits for the LLC acknowledgement,
then validates and answers the correlated management UNBIND if it arrives.
It sends DISC on the next user PIU, logging its TH/RH and packet dump at
debug level. This experiment cannot carry an application conversation or
advertise a route. It exits with status 1 on the deliberate unsupported
follow-up or a timeout; inspect the capture to judge whether OS/400 accepted
the response. Run it only on an isolated TAP with an expendable guest.

In the first live user-response probe, OS/400 acknowledged the 89-byte user
+RSP(BIND), then sent a management UNBIND whose FQPCID matched the earlier
SNASVCMG BIND. The same order occurs in the two-OS/400 baseline. The probe
closed before responding to UNBIND, and OS/400 reported an APPC failure. The
LLC ACK and UNBIND order do not establish user-session acceptance; the next
probe must answer the management teardown and observe the following user PIU.

The direct two-OS/400 baseline continues after management UNBIND with a
242-byte user-session FMH-5 Attach (`RH 0b9120`, 36-byte FMH-5 header), then
an 82-byte user-session reply (`RH 03a100`). A read-only Rust parser now
recognizes the first Attach header and leaves its application data opaque.
The reply semantics still need the next live probe and APPC conversation
implementation before Rust can generate a response.

### Experimental user pacing probe

`--native-user-pacing-probe` adds a separate fixed-window user-session pacing
test after the user BIND response. Supply explicit policy fields alongside
the management probe configuration:

```toml
user_plu = "SOLNET.SNAA"
user_slu = "SOLNET.SNAB"
user_tp_hex = "30f0f0f5"
```

The TP value is the raw four-byte name observed for this pass-through test;
other applications require their own configured LU pair and TP value. The
probe validates and retains exactly one first FMH-5 Attach, reserves a bounded
receive slot, sends a correlated nine-byte user pacing response, and closes
on the next user PIU. It never sends an APPC Attach reply or advertises a
ready route. Use only the isolated V4R4 guest and expect exit status 1 at the
intentional unsupported user-data boundary.

In the next isolated V4R4 run, the guest sent the same 242-byte first user
FMH-5 Attach after Rust acknowledged management UNBIND. Rust validated and
buffered it, sent a nine-byte user IPR (`2d0002020000830100`), and the guest
acknowledged that IPR at LLC2 N(R)=8. No further user PIU arrived during the
observation window. The direct two-OS/400 trace sends an application GDS
reply at that point; this pacing probe deliberately has no APPC reply or
application target. The link is still not a usable user gateway.

In the isolated V4R4 A run on 2026-11-01, the probe sent its 89-byte candidate
user +RSP(BIND), and A acknowledged the LLC I-frame with RR `N(R)=6`. About
14 ms later A sent a 37-byte PIU with TH `2d 00 01 02 00 00`, RH `6b 80 00`,
and RU beginning `32 01 00 00 00 00`: UNBIND with SON `0x01`
([normal end of session](https://www.ibm.com/docs/en/zos/2.5.0?topic=routine-unbind)).
Its FQPCID matched the management BIND, consistent with the management
teardown in the direct two-OS/400 baseline. The probe acknowledged UNBIND
and sent DISC as designed. A's `STRPASTHR` returned to Main Menu with APPC
failure `E022000BA2100000`, consistent with the deliberate probe disconnect.
An LLC RR proves frame receipt, not acceptance of the candidate BIND response
or establishment of a usable user session. The private unfiltered capture is
`/tmp/snusnu-v4r4-regression/native-userbind-sol5.pcap`; no raw application
payload is included here.

The follow-up isolated V4R4 run used the probe that also replies to the
correlated management UNBIND. The observed order was SNASVCMG BIND and
+RSP(BIND), CNOS Attach and replies, bilateral BIS, user BIND and the candidate
89-byte +RSP(BIND), management UNBIND (SON `0x01`) and +RSP(UNBIND), then A's
first user-session FMH-5 Attach. That next PIU was 242 bytes, with TH
`2c 00 02 02 00 01`, RH `0b 91 20`, and a 36-byte FMH-5 header; its 197-byte
tail remains opaque. This progression is evidence that A advanced past the
candidate user BIND response and management teardown to user traffic. The
probe then deliberately sent DISC without answering the Attach. A returned
to Main Menu with APPC failure `E022000BA2100000`; no remote Sign On or user
conversation completed. The private capture
`/tmp/snusnu-v4r4-regression/native-userbind2-sol5.pcap` has 50 frames and
no capture drops. The next native milestone is a valid user FMH-5 reply and
conversation handling, with the opaque tail treated as application data.

The subsequent opt-in user pacing probe buffered that same 242-byte Attach
and sent one nine-byte user-session IPR, TH `2d 00 02 02 00 00`, RH
`83 01 00`. A acknowledged it with LLC RR `N(R)=8`; only periodic LLC RR
polls followed during a bounded observation interval. The guest display
remained at “Pass-through initialization in progress,” with no error shown.
The probe was stopped by the operator; no Attach reply or application
conversation was attempted. This verifies delivery of the IPR frame, while
leaving its higher-level acceptance and the necessary Attach reply unproven.
The private capture `/tmp/snusnu-v4r4-regression/native-attach-ipr-sol5.pcap`
has 58 frames and no capture drops.

## Isolated native-to-TCP62 mock converter

`--native-converter-mock-lab FILE` starts the same dynamic XID3, LLC2, and
APPN management peer as the one-shot probes. It accepts the first validated
V4R4 user BIND, opens an in-process TCP62 mock on loopback, relays a derived
Connect request and response, and forwards the first validated user FMH-5
Attach as one TCP62 normal record. It sends the correlated native user IPR
only after reserving a receive slot and queuing the TCP record. The harness
stops after the mock receives that record and the native IPR is acknowledged.
It does not send an application reply or expose a production route.

Use the same isolated `--native-user-pacing-probe` TOML file, including
`user_plu`, `user_slu`, `user_tp_hex`, and `timeout_seconds = 600` for V4R4 IPL:

```sh
cargo run -p snusnu-router -- --native-converter-mock-lab /path/to/native-probe.toml
```

For this fixture the configured user LU pair must match the management CP
pair. The mock alone advertises the six TCP62 compensation codes needed by
the converter test. Those codes are unavailable in the normal route loader
until UDP X'83' and later APPC handlers exist. A successful harness exit
means one Attach crossed the LLC-to-TCP62 boundary and its local pacing
response was acknowledged; it does not mean the application conversation
completed.

The first live V4R4 A run of this harness on isolated `sol5` reached user
+RSP(BIND), management +RSP(UNBIND), and the 242-byte FMH-5 Attach. Rust
queued the Attach toward its loopback TCP62 mock and sent a nine-byte user
IPR; A acknowledged it with LLC RR `N(R)=8`. The mock TCP connection then
closed, so Rust sent DISC before any application reply. A returned to Main
Menu with APPC failure `E022000BA2100000`. This run does not establish that
the Attach reached a usable TCP62 peer or that a conversation completed.
The private unfiltered capture
`/tmp/snusnu-v4r4-regression/native-converter-mock-sol5.pcap` contains 53
frames with no capture drops. This exposed a mock TCP lifecycle defect.

With that defect fixed, a second isolated V4R4 A run reached the same first
242-byte FMH-5 Attach. Rust produced one 243-byte TCP62 normal record, and
the in-process loopback mock received it. Rust then sent the nine-byte native
user IPR, which A acknowledged with LLC RR `N(R)=8`. The harness exited
successfully and deliberately sent DISC without an application reply. A
returned to Main Menu with APPC failure `E022000BA2100000`, as expected for
this bounded test. The private unfiltered capture
`/tmp/snusnu-v4r4-regression/native-converter-mock2-sol5.pcap` contains 52
frames with no capture drops. This establishes the first user Attach crossing
the native LLC2-to-TCP62 boundary in the mock harness, while a real V5R4
AnyNet peer and completed conversation remain untested.

The separate `--native-converter-v5-lab` diagnostic uses the same native
configuration and dials a real isolated V5R4 AnyNet listener at TCP/397.
For the sol5/sol7 lab only, the invocation is:

```sh
cargo run -p snusnu-router -- --native-converter-v5-lab \
  /tmp/snusnu-native-v4a-user-pacing.toml 10.99.4.10 10.99.4.3 \
  --acknowledge-experimental-x83
```

The local IPv4 address must already exist on isolated sol7. The diagnostic
binds UDP/397 locally and stops on any incoming datagram; it has no X'83'
out-of-band responder. Its TCP62 Connect advertises the six codes only under
the explicit lab flag, following the observed V5R4 Connect profile for its
nonvolatile fields except the optional X'84' keepalive field, which it omits
because it has no keepalive responder. It closes after the first native Attach has been fully
written to TCP and its native IPR is LLC-acknowledged. Any positive result is
limited to that exchange; production configuration continues to reject
LLC-to-AnyNet conversion.
