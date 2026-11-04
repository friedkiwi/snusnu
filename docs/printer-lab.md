# SNUSNU.PRINTER interoperability lab

The acceptance target is a spool from an emulated IBM i system, carried over
both AnyNet and LLC through a router to the embedded concentrator printer,
then visible as fixed-pitch text and downloadable as a greenbar PDF. **This
target has not been reached.** The observations below are setup and protocol
probes, not a successful print test.

## Printer protocol

The IBM [5494 remote workstation controller setup](https://www.ibm.com/support/pages/configuring-5494-remote-control-units)
requires an APPC controller and a separate remote workstation controller on
IBM i. Its LU 6.2 sessions use mode `QRMTWSC`, with a controller-management
session and printer sessions. A printer device can be `3812` model `1` with
class `*RMT`, attached to the remote workstation controller. The host sends
SCS in encapsulated LU 4 PIUs. [RFC 4777 section 11](https://www.rfc-editor.org/rfc/rfc4777.html#section-11)
describes TN5250E printer records and does not apply to this SNA path.
[Microsoft's APPC printing documentation](https://learn.microsoft.com/en-us/host-integration-server/core/as-400-appc-printing1)
describes SCS and optional Host Print Transform. The first implementation
target is SCS text; an HPT or IPDS stream needs a separate renderer.

The [IBM 5494 Functions Reference, chapter 8](https://bitsavers.trailing-edge.com/pdf/ibm/5494/SC30-3533-02_5494_Remote_Control_Unit_Functions_Reference_Rel_2.0_199311.pdf)
settles the session direction: the 5494 first negotiates session limits with
CNOS and initiates the controller BIND. It then reports a powered-on printer;
IBM i validates the device and initiates a second LU 6.2 BIND for that printer.
LU 4 printer traffic is encapsulated inside the LU 6.2 device session. The
firmware shows that the power-on report is built as an NMVT FID2 PIU and
submitted to a resident session service. The final framing produced by that
service has not been recovered. The service needs the controller conversation
and the power-on report before a writer can send spool data.

The transport-independent Go `sna/services/printer` package now parses the
IBM-defined inner LU 4 FID3 PIU header, classifies a printer BIND, builds
candidate ACTLU and printer BIND responses, and renders common SCS fixed-pitch
text. It also parses and emits the observed private `D824` controller GDS
around one complete inner PIU, rejecting mismatched lengths and keys. Its LU 4
device state advances through ACTLU and BIND only after each
prepared response is acknowledged by the transport. The outer device-session
envelope remains outside that state machine. The package also encodes the
short, hardware-only NMVT Reply Product Set ID used
to announce a powered-on printer, with runtime SNA address and VPD supplied by
the caller. The candidate ACTLU response has now been exercised against the
guest for station 56; it led to a host LU 7 BIND. This is not the printer at
address 01. VG15 itself adds no LU 6.2 GDS envelope to the NMVT; the resident
session service's final wire framing, live FID2 TH/RH, and printer device
session's private GDS behavior remain to be established.
The package does not perform APPC session management, store jobs, or produce a
PDF. The concentrator now has owner-scoped durable raw SCS storage,
a searchable print list, a monospace preview, and a greenbar PDF writer. These
are not connected to a live 5494 printer conversation yet. The renderer
retains no information about font, forms, or graphics orders, so raw SCS is
stored with each preview.

The reusable `sna/lu62` package also constructs candidate `QRMTWSC` CNOS and
controller BIND requests with dynamic LU names, CP name, and FQPCID. The 5494
CNOS helper requests one source-controlled controller session and up to 56
target-controlled device sessions, matching the firmware's count direction. Its
CNOS reply validator checks the accepted-pending service, mode, session limits,
and reversed FID2 addresses before the controller can proceed. Outbound CNOS
uses the 15-byte FMH-5 Attach observed in the 5494 firmware; the parser also
accepts the 12-byte form captured from V4R4. Its
binary architecture-TP Attach parser can retain the controller TPN
`30F0F6F6` without treating it as an EBCDIC application name. The CNOS and
controller BIND requests have been accepted by a live V5R4 guest over AnyNet.
The library now
offers a candidate controller Attach from the mutable work area and appends
the 18-byte allocation/PIP record built by VG0F. That PIP is fixed except for
one runtime controller-table byte, which the caller must supply. The firmware
proves the TPN overwrite, PIP construction and append length; the QA probe's
Attach was positively acknowledged by V5R4. Sending the NMVT on the
network-management path remains to be implemented.

IBM's [LU 6.2 guide](https://www.ibm.com/docs/en/SSLTBW_3.1.0/pdf/istp620_v3r1.pdf)
defines both basic and mapped FMH-5 conversation forms. The parser accepts
either form. The Release 3.2 controller template uses the basic `D0` form;
its complete runtime PIP and transmitted Attach still need a trace.

## V5R4 guest setup and probe

The writable V5R4 B clone from the [EE APING lab](ee-aping-lab.md) has a
`5494` remote workstation controller `SNUPRT`, remote location `PRINTER` in
NETID `SNUSNU`, and a `3812-1` remote printer device `SNUPRT01` at address
`01`. The guest accepted these commands, varied the controller on, and
submitted a writer for `SNUPRT01`:

```text
CRTCTLRWS CTLD(SNUPRT) TYPE(5494) MODEL(1) LINKTYPE(*NONE) RMTLOCNAME(PRINTER) RMTNETID(SNUSNU)
CRTDEVPRT DEVD(SNUPRT01) DEVCLS(*RMT) TYPE(3812) MODEL(1) LOCADR(01) CTL(SNUPRT) FONT(11)
ADDCFGLE TYPE(*APPNRMT) APPNRMTE((PRINTER SNUSNU SNAB SVC SNUSNU *NONE *NO))
VRYCFG CFGOBJ(SNUPRT) CFGTYPE(*CTL) STATUS(*ON)
STRPRTWTR DEV(SNUPRT01)
```

The command forms above summarize values entered through the V5R4 prompts;
use the prompts to confirm syntax before replaying on another release. The
guest reported `SNUPRT` and `SNUPRT01` as **VARY ON PENDING**. A `DSPLIB
LIB(QGPL) OUTPUT(*PRINT)` spool was requested after setting the job output
queue to `SNUPRT01`; no printer data was observed at the concentrator.

The initial `RMTLOCNAME(PRINTER)` above was corrected to `SVC` on the
isolated guest with `CHGCTLRWS CTLD(SNUPRT) RMTLOCNAME(SVC)`. IBM's
[5494 configuration guide](https://www.ibm.com/support/pages/configuring-5494-remote-control-units)
shows that the remote workstation controller's location is the 5494 CP
name, matching the APPC controller's remote CP. The guest's `LLCPRT` and
`ANYSVC` APPC controllers both name `SNUSNU.SVC`; `DSPCFGL CFGL(QAPPNRMT)`
confirmed a `SVC` remote-location entry for the guest's local LU
`SOLNET.S1054504`. A separate `SNUSNU.PRINTER` LU remains advertised for
the user-facing printer service. This correction did not by itself vary
`SNUPRT01` on.

An isolated QA concentrator advertised `SNUSNU.PRINTER` as LU 6.2 using a
diagnostic handler. A V5R4 `VFYAPPCCNN` to that LU sent a successful HPR
RouteSetup, then exposed two independent gates:

1. The router's HPR session adapter rejects the service-directed
   `SNASVCMG` BIND because its exception names only `SNUSNU.PING`
   (`ManagementBind`).
2. Widening that exception to `SNUSNU.PRINTER` in a disposable probe build
   produced a real WebSocket circuit to local route `3`. The Go endpoint then
   rejected the BIND because its standalone LU 6.2 responder also names only
   `SNUSNU.PING` (`unsupported user LU 6.2 BIND`).

The repository now has a QA-only `-printer-probe` endpoint which advertises
`SNUSNU.PRINTER`, completes link XID, and logs incoming FID2/session records.
Run the QA binary with `-printer-probe -sna-debug` to record full protocol bytes
and internal circuit state to stderr. The production service still does not
advertise PRINTER or accept printer BIND. The earlier temporary router changes
live only in `/tmp/snusnu-printer-probe`. That probe used EE to
establish a known route baseline; it did **not** test the required AnyNet or
LLC routes. The pending controller also shows that advertising a passive LU
does not itself make a 5494-like printer available to the guest. The service
must initiate the controller session and accept the host-initiated printer
session, including `QRMTWSC` application records.

The QA binary can also take `-printer-probe-dial NETID.LU` to make one
outbound native DLC circuit open when the guest LU is advertised. An isolated
V5R4 clone on `sol10` now uses `SOLNET.PRTGUEST` as its CP,
`SOLNET.S1054504` as its default LU, and `10.99.6.2` as its IP address. Its
`ANYSVC` AnyNet controller targets `SNUSNU.SVC` through a router listener at
`10.99.6.1:397`. A `VFYAPPCCNN` to `SNUSNU.PRINTER` emitted real SNASVCMG and
user TCP62 Connect requests. The router admitted both after separating the
FQPCID CP name from the LU name; the user request opened a native DLC circuit
to the QA printer probe. A separate QA outbound circuit reached XID3 with the
same router. These are connection probes, not printer traffic. The QA probe
now completes native SNASVCMG BIND, CNOS, BIS, and UNBIND with the router's
responder. The router then completes a separate outbound AnyNet management
exchange with the isolated V5R4 guest. The guest's positive BIND response
used instance marker `25`, which the TCP62 validator now accepts. The next
QA controller BIND reached the router and exposed its fixed default-mode
profile restriction. The router now accepts the 5494 controller BIND profile,
and the guest has acknowledged that BIND and the following Attach. NMVT and
the address-01 LU4 data path still need completion before a spool file can be
accepted.

The original V5R4 B guest still has an `ANYPRT` controller varied off because
its active `EETOA` low-entry-node controller already targets `SNUSNU.SVC`
(CPD2628 reason 00002217). It was left untouched. An LLC null XID sent to
that guest elicited no response; the isolated clone is the current capture
target for both media.

## Remaining acceptance work

### Recovered V5R4 lab, 2026-11-04

After the host power loss, a fresh writable V5R4 clone was booted and signed
in using the lab image's existing QA account. The source image was left
untouched. The clone uses `SOLNET.PRTGUEST`, `SNUSNU.SVC`, a 5494 remote
controller `SNUPRT`, and a `3812-1` printer `SNUPRT01` at location `01`.
The verbose LLC router and QA concentrator again completed XID3, source
`QRMTWSC` CNOS, the 5494 controller BIND, and the `30F0F6F6` Attach.
The guest then sent its address-56 LU7 setup traffic. A three-page `QPDSPLIB`
spool is queued on `SNUPRT01`; the device is still `VARY ON PENDING`, so no
address-01 LU4 BIND or SCS print data has been received.

On this clone, `STRMOD` reported a route-selection error when the remote
network identifier was omitted. The explicit command
`STRMOD SVC SVC MODE(QRMTWSC) RMTNETID(SNUSNU)` completed successfully and
immediately led to the source controller exchange. A QA-only Reply-PSID trial
with FID2 OAF `01` received negative sense `10030001` from V5R4. The
original zero-address form received a positive SNA response, so the OAF
trial was removed. The host auto-created `QNXDEV`, a `3287` remote printer
at local address `01` under APPC controller `LLCPRT`; its relationship to
the pending 5494 printer remains unproven. This guest also reported that
`QNXDEV` was not responding normally, with ACTLU response code `00000000`.
That message and the address-56 exchange need investigation before counting
any printer activation.

### Live V5R4 native LLC probe, 2026-11-03

The isolated V5R4 guest at MAC `02:04:ac:05:45:04` connected over 802.3
LLC2 through the Rust router on `sol10` to the QA concentrator. The guest
identified itself as `SOLNET.PRTGUEST` with LU `SOLNET.S1054504`. The
concentrator's QA responder completed the guest-originated SNASVCMG BIND,
default-mode CNOS, BIS, and UNBIND on this native circuit. This verifies
the native transport and management path; it has not carried a printer job.

In the same trace, immediately after BIS and before the management UNBIND,
the guest sent a second BIND with FID2 addresses `(2,2)`, PLU
`SOLNET.S1054504`, SLU `SNUSNU.PRINTER`, and a blank mode. This was the
separate user connection requested by `VFYAPPCCNN`, not a `QRMTWSC`
controller BIND. The QA printer probe did not answer that user BIND; it
must not be counted as evidence that the printer controller session advanced.

A subsequent concentrator-originated source-management BIND reached the
guest, but was rejected before QRMTWSC CNOS. FID2 address pair `(2,1)` and
`(2,3)` returned `80040000` (unknown or missing SLU name); `(2,2)` returned
`08090000` (mode inconsistency), including with PLU `SNUSNU.PRINTER` and
SLU `SOLNET.S1054504`. The equal address pair is valid as a wire shape:
the guest itself sent a BIND using `(2,2)`. These responses do not establish
that the guest accepted the source session or printer service. The next
native gate is finding the correct source-session activation.

The candidate direct NMVT path received a positive SNA response on LLC. A QA-only short hardware PSID
with FID2 addresses `00/00`, RH `0B 80 00`, and address-01 status
`09 82 04 10 00 01 03 20 01` received a positive IBM i response:

```text
2C FF 00 00 00 01  8B 80 00  41 03 8D
```

IBM i subsequently sent `2F 00 01 00 00 00 6B 80 00 0D 01 01`, a direct
FID2 ACTLU. Its FID2 address byte `01` identifies the outer LU session, not
twinax printer address 01. A 5494 workstation address appears in the inner
FID3 LSID (`41` for the address-01 SS-LU session), which this PIU lacks. The
QA probe returned `0D 01 01 00 84 00 00 00`, but that response cannot be
counted as printer activation. This is a real guest response to a constructed
probe record, not a captured physical 5494.
The `3812` VPD fields and address-list prefix in the probe were chosen for
the lab and remain unverified against hardware. The configured remote
workstation controller `SNUPRT` and device `SNUPRT01` still report
`VARY ON PENDING`; no inner FID3 address-01 ACTLU, LU4 BIND, or SCS print
data has followed in the recorded trials. The guest rejected a
shared-session QRMTWSC Attach with `80050000` after its default
management session ended, so the source CNOS/session association remains
the next blocker.

After correcting `SNUPRT` to `RMTLOCNAME(SVC)`, the QA concentrator also
advertised a controller LU `SNUSNU.SVC` alongside `SNUSNU.PRINTER`. The
guest's LLC management BIND then named `SNUSNU.SVC`; its CNOS completed,
and IBM i positively acknowledged the address-01 NMVT on this circuit.
`SNUPRT` remained pending. The source controller BIND is still missing on
LLC, so neither the remote workstation controller nor the printer became
active.

Two further QA-only source CNOS timing probes were removed after capture.
Sending the QRMTWSC Attach immediately after the guest's SNASVCMG BIND, or
on receipt of its BIS before answering BIS, caused a host UNBIND of type
`FE` with sense `20030000` (bracket state error). Sending it after BIS
completion yielded `80050000` because the session had ended. These traces
rule out reusing the guest's default-management bracket in those states;
they do not identify the separate source-session activation sequence.

An outbound native source-BIND probe with the captured `6B 80 00` request
RH was sent first immediately after XID and then only after answering the
host's `ACTLU`. With FID2 addresses `(2,1)`, IBM i returned `80040000`
in both orders. Using the advertised `SNUSNU.PRINTER` and
`SOLNET.S1054504` LU names after `ACTLU` also returned `80040000`.
A separate probe sent a source BIND with addresses `(2,2)` while the
guest-originated management session was still active, just after the
default-mode CNOS reply; IBM i returned `08090000`. These probes were
run with both QA and router debug logging, then removed from the source.
The rejection therefore persists beyond the request RH, those names,
and those three timing points. The source-session address and activation
state still need a real 5494 trace or a stronger firmware reconstruction.

The 5494 BIND builder at VG10 image `0x6185` copies a TH template whose
DAF/OAF bytes are zero and a sequence from the runtime session record at
`+0x2e`. The common send routine fills addressing from the resolved
session descriptor. The firmware therefore does not supply a constant
DAF/OAF pair for a native source BIND. Re-varying `SNUPRT` with the LLC
route online produced no controller PIU by itself; a later `VFYAPPCCNN`
sent only a blank-mode user BIND. This is consistent with management
state surviving that QA restart, so further trials need controlled
fresh guest/session state and the descriptor mapping.

### Live V5R4 AnyNet controller trace, 2026-11-03

An isolated V5R4 clone at `10.99.6.2` accepted `QRMTWSC` source CNOS
(57 sessions, one source winner, 56 target winners), the 5494 controller
BIND, and the `30F0F6F6` controller Attach with the firmware-derived PIP.
The initial `08640000` FMH-7 termination followed an earlier failed
`SNUPRT` controller state: guest message `CPF9360` reported that later
connection attempts were rejected because the controller was not valid.
Varying `SNUPRT` off and on cleared that state.

With the controller active, the host sent a private `D822` record, then a
`D824` GDS carrying an inner FID3 ACTLU:

The captured `D822` is a controller clock update. In `VG0F.BIN`, image
`0x1D2A` recognizes GDS key `D822` with subtype zero and calls `0x1F37`;
that routine reads six EBCDIC digits at record offsets `0x46` and `0x4C`
and invokes BIOS clock interrupts `1A/05` and `1A/03`. In this run those
fields decode to `261103` and `153227`, matching the guest date and time.
This record supplies no printer address, so the probe must continue looking
for the address-01 announcement after the clock update.

```text
00 0C D8 24 3D 78 6B 80 00 0D 01 01
```

The QA probe answered that ACTLU and the guest advanced to an inner LU 7
BIND at FID3 address `38` (LSID `F8`):

```text
00 23 D8 24 3D F8 6B 80 00 31 00 07 07 B0 B0 10 81 ...
```

The probe echoed this BIND as a positive inner response. The guest then
sent `00 10 D8 24 3C F8 03 90 20 04 F3 00 05 D8 20 02`.
An AnyNet rerun with verbose router and QA logging matched the QA ACTLU
response to the router's WebSocket receive event and to the complete TCP62
normal record accepted by the socket:

```text
QA PIU:     2e00010200020391200011d8243d78eb80000d01010084000000
TCP62:      0000001b0000020390200011d8243d78eb80000d01010084000000
```

The guest's following LU 7 BIND confirms it processed that response. The
router also logs each complete TCP62 record at the socket boundary when
`transport_ip_sna=debug` is enabled.
These are observed guest bytes. The probe responses are constructed, not
captured from a real 5494. Station `38` is not the configured printer at
address `01`, and its LU type is 7 rather than 4. The controller remains
`VARY ON PENDING`; the guest has queued spool files but has not sent an
address-01 printer BIND or SCS data. No spool has reached the concentrator.

A QA-only trial answered the next address-56 LU7 FMD (`03 90 20`) with an
unsolicited positive inner response. The guest then sent a TCP62 expedited
SIGNAL `C9 00 01 00 01` and a negative inner response with sense `10030000`
to that positive response. The `03 90 20` request is exception-response
form, so the trial response was removed. This trial did reveal a generic
router gap: the AnyNet converter rejected all TCP62 expedited records and
closed the circuit. The converter now restores the FID2 expedited bit,
forwards the SIGNAL to the concentrator, and sends the five-byte TCP62 ACK.
Verbose router and QA traces confirm the exact SIGNAL arrived at QA. This
does not make the address-56 device exchange or printer session complete.

With `SNUPRT` corrected to remote location `SVC`, an outbound AnyNet
controller circuit sourced from the distinct LU route `SNUSNU.SVC`
again completed source CNOS, the controller BIND, and the `30F0F6F6`
Attach. The guest still emitted the address-56 LU7 exchange. Sending the
same direct address-01 NMVT PIU on that bound TCP62 controller association
caused the router to reject it as `native PIU session address mismatch`;
the guest did not receive it. AnyNet therefore needs a separate
management-services path for the NMVT, or evidence of the correct MPTN
envelope, rather than inserting it into the controller LU6.2 session.

The next protocol gate is activating the 5494 controller session and
observing the host's printer-session BIND and private `D824` records. The current
AnyNet reverse gateway completes and releases its separate SNASVCMG
management association before the controller session, so it cannot yet carry
that NMVT. A lab-only attempt to send the PSID as a TCP62 normal record on
this association after CNOS/BIS received no IBM i response and did not change
the subsequent controller exchange; that experiment was removed from the
router source. The native LLC path is verified for XID3, SNASVCMG, and the
direct NMVT, as described above.

In a later AnyNet run, the guest sent a WSF `D8 20 02` request inside the
address-56 LU7 `D824` device GDS. A QA-only probe, gated by
`SNUSNU_PRINTER_PROBE_LU7_QUERY=1`, returned the 26-byte `VG03.BIN` Query
reply template (file offset `0x183A0`). Bytes 20–21 of that template are
normally patched from the controller's runtime capabilities; the probe
used the disk defaults and does not establish a real device's values.
The guest then sent `D8 21 10`. QA returned `VG03`'s eight-byte reply
template (file offset `0x183C2`), after which the guest sent another LU7
WSF beginning `04 F3 03 18 D8 22 02`. The meaning and complete chain of
that last WSF remain to be established.

The same verbose run exposed and verified a router expedited-response fix.
The guest sent TCP62 expedited SIGNAL `C9 00 01 00 01`; the router forwarded
the complete FID2 PIU `2F00020180004B8000C900010001` to QA. QA returned
positive response `2F0001028000CB8000` over the WebSocket circuit. The
router logged that PIU on receipt, wrote TCP62 record
`0000000A018000CB8000` to the guest socket, and received its five-byte
expedited ACK `0000000503`. These adjacent logs prove the QA response was
relayed to the guest, while the ACK only establishes TCP62 delivery. No
address-01 LU4 BIND or SCS spool data followed in this run. The QA reply
logic remains experimental and disabled without the environment flag.

A contemporaneous guest status check showed `ANYSVC` and its APPC device
`SVC00` active, with `QRMTWSC` marked `ACTIVE/TARGET`. `DSPMODD QRMTWSC`
showed the IBM-recommended 57 sessions, 57 conversations, and 56 locally
controlled sessions. Yet `WRKCFGSTS` still showed `SNUPRT` and `SNUPRT01`
as `VARY ON PENDING`. The mode's capacity and the AnyNet controller
association are therefore present; the address-01 device announcement and
its follow-on LU4 session remain the live acceptance gate. IBM's
[5494 configuration instructions](https://www.ibm.com/support/pages/configuring-5494-remote-control-units)
also distinguish the APPC controller description from the remote workstation
controller description and specify those QRMTWSC limits.

A simultaneous-media probe kept the AnyNet controller circuit open and
started a second QA listener plus LLC router on `sol10`, intending to send
the address-01 NMVT over LLC. The LLC router published its managed MAC, but
the guest's `LLCPRT` APPC controller was varied off. `VRYCFG` to vary it on
returned `Controller LLCPRT Vary Configuration failed`; no LLC XID or NMVT
followed. The second QA/router pair was stopped, leaving the AnyNet circuit
untouched. This trial establishes no cross-media correlation and gives no
evidence that the guest accepted simultaneous paths to `SNUSNU.SVC`.

In a later native LLC run with `LLCPRT` active, a guest-initiated
`VFYAPPCCNN` management exchange negotiated `QRMTWSC` with 57 sessions,
56 source winners, and one target winner. The guest accepted the probe's
direct address-01 NMVT Reply PSID. After the management UNBIND, the QA
probe sent a 5494-style controller BIND on FID2 address pair `(2,2)`.
Verbose traces show the identical 108-byte BIND leaving QA, arriving at
the router over WebSocket, and leaving `sol10` as an LLC I-frame. The guest
acknowledged the frame and returned negative BIND sense `08090000` (mode
inconsistency). The router received that 14-byte response on `sol10` and
forwarded it to QA. This verifies both directions of the LLC relay, but
the guest-initiated CNOS did not establish a usable 5494 source-winner
controller session on that address pair. The next trial must establish the
5494-originated source CNOS or derive the actual source BIND session
addresses from the host's session descriptor; changing the BIND address
pair alone has no supporting evidence.

A QA-only outbound LLC trial then prepared a 5494 source CNOS request
(`QRMTWSC`, 57 sessions, one source winner, 56 target winners) and used
the guest's management LU `SOLNET.S1054504` in the preceding source
SNASVCMG BIND. The guest replied to that BIND on `(2,1)` with negative
sense `80040000` before any CNOS was sent. The earlier source BIND using
the guest CP name `SOLNET.PRTGUEST` received the same sense. Both tests
followed XID3/link readiness after varying `LLCPRT` on, with the guest's
ACTLU following the rejected BIND. The source-CNOS option is gated by
`SNUSNU_PRINTER_PROBE_SOURCE_QRMTWSC=1`; it makes the intended mode limits
explicit once a source management session can be activated. The successful
AnyNet source CNOS uses a separate router-to-guest management path.

The guest has two LLC APPC devices attached to `LLCPRT`: `PRINTER00`
identifies `SNUSNU.PRINTER`, while `SVC` identifies `SNUSNU.SVC`. The first
mode-status check examined `PRINTER00` and showed only `SNASVCMG`; it was
not evidence about the `SVC` route. With `SVC` varied on, an explicit
`STRMOD` for remote location `SVC`, remote network `SNUSNU`, device `SVC`,
and mode `QRMTWSC` completed successfully. `DSPMODSTS` then showed device
`SVC` ACTIVE, mode `QRMTWSC` Started, and negotiated limits of 57 total,
56 locally controlled, and one remotely controlled session. The LLC QA
trace contains the matching guest management BIND and CNOS. A separate
QA flag, `SNUSNU_PRINTER_PROBE_PASSIVE_QRMTWSC=1`, accepts that CNOS
without injecting a controller BIND.

Repeating the post-UNBIND `(2,2)` controller BIND in this confirmed `SVC`
mode state changed the negative sense to `80040000` (unknown or missing
SLU name under IBM's Type 2.1 ASM rules). This does not establish that the
FID2 destination address was wrong. The 5494 source
SNASVCMG/CNOS session must be
activated separately; a successful target-side CNOS does not by itself
allocate its FID2 address. The probe has still received no LU4 BIND or SCS.

The [IBM Type 2.1 format and protocol reference](https://bitsavers.org/pdf/ibm/sna/SC30-3422-0_SNA_Format_and_Protocol_Reference_Manual_-_Architecture_Logic_for_Type_2.1_Nodes_198612.pdf)
specifies first 5494 source-assigned LFSID `0200`; the BIND-direction TH uses
DAF `00` and OAF `02`. After sending that address pair, QA still received
`80040000`. A firmware disassembly check at VG10 image `0x64B3..0x64C2`
shows why the original 27-byte variable boundary was correct: VG10 copies
28 template bytes, then overwrites the last template byte with the PLU name
length at RU offset 27. A trial that incorrectly inserted a 28th fixed wire
byte returned `08350027`, IBM's invalid BIND parameter at offset `0x27`.
That trial was reverted. The QA source BIND now uses the observed 5494
`D0 B3` fixed profile and shorter firmware-shaped user data, but a fresh
live response is still required. The LLC router's verbose trace confirms
the earlier trial PIU and guest response traversed both directions.

On 2026-11-03, changing the QA XID3 role to secondary resolved the source
management BIND rejection. Through LLC, V5R4 positively answered the
firmware-shaped source BIND, accepted source CNOS for QRMTWSC (57 total,
one source winner, 56 target winners), completed the UNBIND handshake, and
accepted the subsequent controller BIND and QND5MAIN Attach with the
`30F0F6F6` TPN and `04 D4 07 30` PIP subvector. IBM i then sent its
controller clock `D822` and a `D824` ACTLU and BIND for address 56, LU7.
The QA probe answered ACTLU and BIND; the guest followed with a LU7 query.
The address-01 NMVT Reply PSID was positively acknowledged both before and
after controller Attach, but `SNUPRT` and its configured 3812-1 device
`SNUPRT01` remained VARY ON PENDING. No address-01 LU4 BIND or SCS has
yet arrived. The next diagnostic step is to complete the address-56 LU7
query and SIGNAL exchanges, then check whether IBM i activates the printer.
These observations come from `/tmp/snusnu-printer-qa-secondary-3.log` and
`/tmp/snusnu-printer-qa-secondary-4.log`, with matching router debug logs.

The [TCP62 transport draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00.txt)
specifies LU 6.2 application conversion, whereas IBM's
[management-services guide](https://public.dhe.ibm.com/software/network/commserver/publications/cslin_64/czx41100.pdf)
places NMVT on the PU–SSCP management session. The router's current TCP62
controller association is an LU 6.2 session, and its normal-record decoder
reconstructs that association's FID2 addresses. Reusing it for the
address-01 NMVT would lose the direct management-session addressing. The
AnyNet acceptance path therefore needs an identified management transport
or a captured OEM controller exchange; the existing LU 6.2 record converter
does not establish either one. This is a transport finding, not proof that
IBM i cannot support an AnyNet printer.

An independent vendor's [I-O print-server guide](https://products.iocorp.com/ftp/Host_Print/Manuals/Print%20Servers%20User%27s%20Guide.pdf)
documents an AnyNet printer configuration that creates a 5494 remote
controller and printer device on IBM i. This is evidence that an AnyNet
acceptance path exists in shipped equipment; the guide does not publish
the network-management wire format or a reusable trace. Its firmware
download instructions refer to the former `ftp.iocorp.com` archive, but
that archive was not reachable in this investigation.

The publicly archived [5494 Release 3.2 base diskette files](https://www.ardent-tool.com/5494/Files.html)
provide a direct source for the missing controller sender code. In
`5494_Base.zip`, `VG*.BIN` contains 16-bit x86 code. `VG1C.BIN` is the only
module with the EBCDIC `QRMTWSC` constant (`D8 D9 D4 E3 E6 E2 C3` at file
offset `0x2032`), near its `5494CONFDEFHOST` configuration strings. The
EBCDIC `SNASVCMG` constant appears in `VG10.BIN` at offset `0x7236`.
`VG10.BIN` also contains the fixed controller BIND prefix
`6B 80 00 31 00 13 07 B0 B0 D0 B3 00 00 86 86 80 00 06 02` at offset
`0x7244`. This independently supports the fixed portion built by the Go
candidate; it does not reveal the dynamically generated names or PCID.
At `VG10.BIN` offset `0x928A`, a basic-conversation FMH-5 work area has binary
TPN `30F0F5F1` and the PIP-present flag set. The firmware copies
`30F0F6F6` from `5494CONF.DAT` over that TPN at runtime for the controller
Attach. VG0F constructs the 18-byte allocation/PIP area as
`00 12 12 F5 00 0E 12 E2 03 20 01 xx 38 04 04 D4 07 30`.
`VG0F` reads `xx` from offset `+8` of the shared far pointer `1000:C000`
(image `0x1BDB`). `VG1C` initializes that same pointer's `+8` to zero at
image `0x1751`, so zero is the firmware's initial value. A later runtime
writer could still change it; the final transmitted work area needs capture.
Another local constant contains `30F0F6F3`,
whose purpose still needs to be traced.
`DUMP5494.DAT` file begins with `CC` filler and is not a useful trace. These
observations do not establish a successful 5494 conversation.

The firmware's `VG15.BIN` constructs an NMVT Reply PSID (`41 03 8D` request,
`00 90` major-vector key) with address-01 power-on bytes
`09 82 04 10 00 01 03 20 01`. Its product subvector starts `19 10` and
copies machine type, model, plant and serial from runtime twinax VPD. The
[research report](https://github.com/friedkiwi/syspass_research/blob/master/docs/sources/ibm-5494-lu62-lu4-printer-wire-protocol.md)
traces `VG15` building the NMVT and handing it to resident service `0x13`.
VG15 does not add a private LU 6.2 GDS. It prepends a 12-byte FID2
TH/RH/NMVT header, but the resident service's final wire framing has not
been recovered. IBM's 5494 Functions Reference says workstation notification
reaches the host on the controller session, so a direct NMVT probe's positive
SNA response cannot, by itself, prove that the controller application saw the
device announcement.
RH0 is `0B`; RH1/RH2 and FID2 addressing come from runtime session state.
VG15 marks the device ready after a resident-service transmit completion.
The real 5494's runtime header bytes and any host application response beyond
the SNA response still need a live trace.
The configured `3812` machine type would be `F3 F8 F1 F2` in EBCDIC, but that
value was not observed in a populated firmware VPD table.
IBM SNA Formats defines this Reply-PSID's `0A 04 01 00 00 00 00 00 00 01`
Address List as one single local address: format `00`, five reserved zero
bytes, then address `01`. The six zero bytes in QA's record are therefore
architected for that address format, not a missing MAC or CP identifier.

The November 3 LLC probe used the firmware-derived 5494 controller XID and
sent a constructed address-01 Reply PSID after the controller Attach. With
both router and concentrator QA debug enabled, the same 75-byte PIU appears
as QA WebSocket output, router WebSocket input, and an LLC information frame
sent to IBM i. IBM i returned `8B 80 00 41 03 8D`, which the router relayed
back to QA. This is a positive SNA response to the NMVT; it does not prove
that IBM i accepted the printer VPD or associated `SNUPRT01` with the
controller. `SNUPRT` and `SNUPRT01` remained `VARY ON PENDING`.

IBM i then completed an address-56 LU7 ACTLU and BIND, followed by `D820/02`
query and `D821/10` station-state exchanges. QA's candidate replies received
positive SNA responses. IBM i next sent an inner LU7 `D822/02` record, for
which the probe has no handler; it later sent an expedited SIGNAL. No
address-01 LU4 BIND or SCS data followed. The 5494 firmware contains `D822`
handling in `VG03.BIN`, so the next probe must derive this exchange from the
firmware rather than treat the positive SNA responses as device readiness.

One disposable probe sent `00 05 D8 23 02` on the controller session after
the NMVT response. IBM i subsequently sent UNBIND with sense `20020000`
(chain error). The probe was removed. `VG0F.BIN` runtime `0x1537` constructs
that GDS only for a station record whose state byte at offset `+3` is `01`;
the `0x044F` event path invokes it when station state reaches `07`. It cannot
be sent opportunistically on the controller session. Neither this trial nor
the address-56 dialogue has activated the configured printer.

A later isolated probe waited for the first station-56 LU7 `D822/02` FMD
fragment before sending `D823/02`. IBM i acknowledged it and transmitted
two more `D824` fragments. The three inner RUs were 50, 503 and 241 bytes:
the first two bytes are `04 F3` (Write Structured Field), followed by exactly
`0x0318` (792) structured-field bytes. Their inner RH chain flags were first
`02`, middle `00`, and last `01`; the last fragment carried CD. This proves
that a `D824` record is one PIU, not necessarily one complete application
request. A second `D823/02` after the final fragment also received a positive
SNA response, but no address-01 LU4 printer session followed. The 5494's
correct station-56 completion behavior remains to be established.

VG0F's `D823/02` builder at image `0x1537` (file `0x1953`) first checks a
per-station record's state byte `+3` for `01`; only that branch allocates a
five-byte `00 05 D8 23 02` record (instructions `0x15C2..0x15D2`). Its
`D824` receive path at image `0x2AF9` checks the GDS length and subtype
before dispatch. The QA trial did not establish that station 56 was in that
state when either reply was sent. Positive SNA acknowledgements to those
replies therefore do not validate the timing or the application exchange.
The next wire trial should derive the station state transition and send one
reply at the firmware-defined point.

An isolated LLC trial sent only the first-fragment `D823/02` on the controller
session, with the corrected date, zero procedure ID, and address-01 NMVT sent
after Attach. IBM i still delivered all three address-56 fragments and an
expedited SIGNAL. QA answered the SIGNAL; no address-01 BIND followed, and
`SNUPRT` and `SNUPRT01` stayed `VARY ON PENDING`. This rules out the second
`D823/02` as the sole cause of the stalled printer activation, but does not
establish that the first notice was correctly timed. The verbose evidence is
in `/tmp/snusnu-printer-qa-first-notice.log` and
`/tmp/snusnu-printer-router-first-notice.log` on the test host.

The three station-56 LU7 fragments reassemble to 794 bytes: a `04 F3`
Write Structured Field command followed by a 792-byte structured field.
Its EBCDIC entries repeatedly name `3486` and `3487` display models and
`AJLPY...` objects. This is display-side setup on address 56; it does not
show that the address-01 3812 printer has started, though the exchange may
still gate controller readiness. The final fragment's
inner RH is `01 90 20`. The IBM 5494 Functions Reference RH table defines
`90` on a request as exception response, so a positive inner SNA response
is not requested. A disposable QA trial attempted to prepare one; the
library rejected it and the trial reset its circuit. That trial did not
test printer activation. The next printer probe should establish both
the controller exchange completion and the NMVT/VPD to remote-device
transition.

A fresh LLC trial kept the controller job alive and deferred the corrected
address-01 NMVT until after the final address-56 WSF fragment and the
second `D823/02` response. QA sent `2C 00 ... 41 03 8D` with zero procedure
ID and a current binary timestamp at 20:41:32; the router relayed IBM i's
positive `8B 80 00 41 03 8D` response to QA. `SNUPRT` and `SNUPRT01`
remained `VARY ON PENDING`, and no address-01 BIND followed. This rules out
the immediate-after-Attach timing of the earlier corrected NMVT as the sole
cause. In a preceding live trial, `WRKACTJOB` showed the controller's
`QUSER/SVC` job active, its call stack was `QND5MAIN` under `QWTPIPPP`, and
its job log said it was running for `SNUPRT` without an error. The delayed
trial again showed a new `QUSER/SVC` job in the same call stack. These
observations establish that the Attach starts the IBM i controller TP, but
not why its address-01 device state remains pending. The verbose trial logs
are `/tmp/snusnu-printer-qa-late-nmvt-corrected.log` and
`/tmp/snusnu-printer-router-late-nmvt-corrected.log`.

A later LLC trial corrected the experimental Reply-PSID FID2 TH byte 1
from `FF` to `00`, matching the reserved byte in the 5494 reference and
firmware. The verbose router log shows the corrected `2C 00 ... 41 03 8D`
PIU crossing the LLC link and IBM i returning `8B 80 00 41 03 8D` through
the router to QA. `SNUPRT` and `SNUPRT01` still showed `VARY ON PENDING`;
there was no address-01 BIND. This response proves SNA receipt, not
workstation activation.

IBM [SNA Formats](https://www.bitsavers.org/pdf/ibm/sna/GA27-3136-8_SNA_Formats_Jun87.pdf)
requires the procedure related ID in an unsolicited NMVT
to be zero. The QA probe previously sent `0001`, despite its unsolicited
flag, and the Go PSID encoder rejected zero. A subsequent LLC trial sent
`2C 00 ... 41 03 8D 00 00 00 00 10 ...`; IBM i returned a positive
NMVT response, but SNUPRT and SNUPRT01 remained pending and no address-01
BIND followed. The library now requires zero for its unsolicited form.

The 5494 firmware also converts BIOS BCD clock fields to binary before
placing them in the Reply-PSID Date/Time subvector. QA's fixed year `26`
was encoded as hex `26`, or binary 38, and its fixed time was stale. QA now
uses the process's current local date and time as binary fields. A live LLC
trial with this date, zero PRID, and TH byte 1 zero received the same positive
SNA response, but still produced no address-01 BIND or SCS data.

The guest also sends controller-conversation `D8 22 00` immediately after
Attach (the late-NMVT trial received an `00 52 D8 22 00 ...` GDS). VG0F's
receive handler at image `0x1D1D` checks that subtype, updates local
controller state through `0x294D`, and invokes the station path at `0x900`.
For the clock-bearing form, `0x1F37` sets the BIOS date and time. This path
does not construct an immediate controller-conversation reply to `D8 22 00`.
QA's lack of such a reply is therefore not, by itself, an identified missing
packet. The V5R4 `QUSER/SVC` job log after the positive NMVT response still
says only that `QND5MAIN` is running for `SNUPRT`, without an error message.

The V5R4 guest's `DSPDEVD SNUPRT01` confirms a 3812 model 1 printer at
location address `01` under `SNUPRT`; `DSPCTLD SNUPRT` confirms a 5494 remote
controller for `SNUSNU.SVC`. IBM's [5494 configuration guide](https://www.ibm.com/support/pages/configuring-5494-remote-control-units)
says the controller model field is for reference only, so its displayed model
1 does not explain the failure despite the probe's XID3 product model 002.
The latest QSYSOPR controller-failure message was sent at 19:59:09, before
the corrected 20:01 NMVT trial. The existing `SNUPRT01 not available` writer
message was sent at 13:12:38; neither is evidence of a new rejection of the
corrected NMVT. Both controller and printer remain `VARY ON PENDING`.

The six zero Address List bytes in the QA Reply PSID also match the VG15
short-product firmware template at raw-image offset `0x1407`. In the power-on
builder (`0x5C0..0x833`), the only write to the ten-byte Address List after
copying that template is at output offset `+0x12`, where the final linear
workstation address is set to `01`. This rules out those six zero bytes as an
identified deviation from this firmware branch. It does not establish that
the host's positive SNA response delivered the report to the closed 5494
controller application: the [5494 Functions Reference](https://bitsavers.org/pdf/ibm/5494/SC30-3533-04_5494_Remote_Control_Unit_Functions_Reference_Rel_3.1_1995.pdf)
describes workstation notification as travelling on the controller session.

After the 20:41 corrected NMVT trial, varying `SNUPRT01` off and back on did
not cause another address-01 session. `WRKCFGSTS CFGTYPE(*DEV)
CFGD(SNUPRT01)` reported "Powered off or not yet available". The verbose
router and QA logs show no new SNA information following that vary-on; the
existing LLC traffic was supervisory keepalives.

The V4R4 host-side `QND5MAIN` analysis found an Attach PIP parser at native
offset `0xCC14`. It walks length-prefixed subvectors and recognizes a
four-byte `04 D4 07 30` subvector identifying the 5494 controller family.
The [research report](https://github.com/friedkiwi/syspass_research/blob/master/docs/sources/ibm-5494-lu62-lu4-printer-wire-protocol.md)
also gives V5R4 `STRCMNTRC` commands for full LLC and AnyNet captures. This
subvector is part of Attach PIP; treating it as the printer address or the
power-on record would be unsupported.

1. Capture the actual V5R4 `QRMTWSC` control and printer sessions against a
   compatible 5494 or APPC printer peer. The firmware establishes the NMVT
   Reply PSID payload and its inner FID2 PIU. Resident service `13` owns the
   physical send path; its outer framing, dynamic TH/RH fields, IBM i's
   application acceptance, and correlation with the parallel printer session
   still need a trace.
2. Generalize the router's service-directed BIND admission and both transport
   adapters for the printer's session profile. The concentrator local service
   registry can now open an outbound circuit from its own LU, but the router's
   HPR attachment still rejects unsolicited opens. Verify the guest no longer
   stays `VARY ON PENDING`.
3. Add a reusable Go printer conversation in `sna`, then an embedded
   concentrator adapter that stamps the authenticated owner and source CP/LU,
   persists the raw stream, and acknowledges only durably accepted data.
   The library already has the Reply PSID FID2 encoder and an LU4 actor for
   ACTLU, printer BIND and durably accepted FMD chains. The private outer
   device-session record and a reliable spool completion signal remain open.

The QA-only address-01 handler now uses that LU4 actor, assembles FID3 print
chains inside `D824`, syncs their SCS bytes to a private partial spool, and
publishes an owner-scoped job before answering a completed chain with CD.
Exception-response chains are accepted without an unnecessary positive inner
response. CD is a candidate job boundary for this probe, not a verified
separator between two consecutive IBM i spool files. No address-01 chain has
arrived from the guest yet; the live acceptance result above is unchanged.

The rebuilt QA and verbose LLC router were exercised again on 3 November at
21:38 CET. IBM i reopened circuit
`08788555-a367-4e27-a328-29b44a3056f0`; QA reached controller management
phase 6 and marked its experimental NMVT sent. The guest's `WRKCFGSTS` still
showed `SNUPRT` and `SNUPRT01` as `VARY ON PENDING`, and `WRKDEV` described
`SNUPRT01` as "Powered off or not yet available". Replying `R` to the pending
`CPA3387` printer-writer inquiry produced no address-01 PIU or print row; the
new QA database contained zero print jobs. The most recent `CPI5935` controller
failure message was stamped 21:34:12, before this fresh circuit. This run
checks the new binary and the writer retry, but still does not demonstrate a
printer session.
4. Print from the guest through AnyNet and LLC separately, capturing each
   router-to-concentrator circuit and confirming the received spool and both
   renderings. Passing APING or `VFYAPPCCNN` alone is insufficient.

### 3 November relay and recovery check

The verbose 20:37 CET LLC run proves that QA's 75-byte NMVT PIU crossed the
router: `/tmp/snusnu-printer-qa-jobwatch.log` records the send on circuit
`99e70429-3427-43a6-a5c7-6f847f953e59`; the matching router log records the
same bytes received over WebSocket and then sent as an LLC Ethernet frame.
The guest's 12-byte positive `8B 80 00 41 03 8D` PIU traveled back through the
router to QA. This proves delivery and response routing for that NMVT; it does
not prove that IBM i accepted the proposed printer identity.

An isolated trial changed only the Attach allocation byte after `03 20 01`
from `00` to `01` with `SNUSNU_PRINTER_PROBE_PIP_BYTE=1`. The first fresh circuit
reached XID and outer ACTLU, but no controller BIND or Attach followed. Guest
controller `LLCPRT` later entered `FAILED` state, so this trial did not test the
new PIP value. Further firmware inspection found that `VG0F` reads this byte
from shared memory `1000:C000+8`, which `VG1C` initializes to `00`. The `01`
in the disk configuration file is a different field; a later runtime change
to shared memory has not been excluded. The next trial should use the observed
`00` initialization. The probe also ignored the guest's `DACTLU` during the reset;
it now returns the architected positive DACTLU RU `0E`. The Go pre-commit gate
passed for that fix. After a clean guest IPL, the controller did not auto-vary
on, leaving the PIP trial pending an authorized guest sign-on and vary-on.

For the AnyNet leg, an existing LU6.2 TCP association cannot carry a separate
SSCP-PU PIU by changing its FID2 addresses. The
[IBM AnyNet guide](https://publibz.boulder.ibm.com/epubs/pdf/f1ap6000.pdf)
describes dependent-LU management as encapsulated SSCP-PU and SSCP-LU flows
over dedicated `CPSVRMGR` sessions. Whether the 5494-style Reply PSID in this
IBM i scenario uses that path still needs a guest capture; the current router
rejects the direct NMVT on the unrelated LU6.2 association.
