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
firmware shows that the power-on report uses a direct NMVT network-management
FID2 PIU, separate from the LU 6.2 controller Attach conversation. The service
needs both paths before a writer can send spool data.

The transport-independent Go `sna/services/printer` package now parses the
IBM-defined inner LU 4 FID3 PIU header, classifies a printer BIND, builds
candidate ACTLU and printer BIND responses, and renders common SCS fixed-pitch
text. Its LU 4 device state advances through ACTLU and BIND only after each
prepared response is acknowledged by the transport. The outer device-session
envelope remains outside that state machine. The package also encodes the
short, hardware-only NMVT Reply Product Set ID used
to announce a powered-on printer, with runtime SNA address and VPD supplied by
the caller. The candidate ACTLU response has now been exercised against the
guest for station 56; it led to a host LU 7 BIND. This is not the printer at
address 01. The NMVT has no LU 6.2 GDS envelope; its live FID2 TH/RH and the
printer device session's private GDS behavior remain to be established.
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

### Live V5R4 native LLC probe, 2026-11-03

The isolated V5R4 guest at MAC `02:04:ac:05:45:04` connected over 802.3
LLC2 through the Rust router on `sol10` to the QA concentrator. The guest
identified itself as `SOLNET.PRTGUEST` with LU `SOLNET.S1054504`. The
concentrator's QA responder completed the guest-originated SNASVCMG BIND,
default-mode CNOS, BIS, and UNBIND on this native circuit. This verifies
the native transport and management path; it has not carried a printer job.

A subsequent concentrator-originated source-management BIND reached the
guest, but was rejected before QRMTWSC CNOS. FID2 address pair `(2,1)` and
`(2,3)` returned `80040000` (unrecognized destination); `(2,2)` returned
`08090000` (mode inconsistency), including with PLU `SNUSNU.PRINTER` and
SLU `SOLNET.S1054504`. The equal address pair is valid as a wire shape:
the guest itself sent a BIND using `(2,2)`. These responses do not establish
that the guest accepted the source session or printer service. The next
native gate is finding the correct source-session activation.

The direct NMVT path is now confirmed on LLC. A QA-only short hardware PSID
with FID2 addresses `00/00`, RH `0B 80 00`, and address-01 status
`09 82 04 10 00 01 03 20 01` received a positive IBM i response:

```text
2C FF 00 00 00 01  8B 80 00  41 03 8D
```

IBM i subsequently sent `2F 00 01 00 00 00 6B 80 00 0D 01 01`, an
address-01 ACTLU on the native link. The QA probe returned the architected
available-printer response `0D 01 01 00 84 00 00 00`. This is a real guest
response to a constructed probe record, not a captured physical 5494.
The `3812` VPD fields and address-list prefix in the probe were chosen for
the lab and remain unverified against hardware. The configured remote
workstation controller `SNUPRT` and device `SNUPRT01` still report
`VARY ON PENDING`; no LU4 BIND or SCS print data has followed. The guest
rejected a shared-session QRMTWSC Attach with `80050000` after its default
management session ended, so the source CNOS/session association remains
the next blocker.

Two further QA-only source CNOS timing probes were removed after capture.
Sending the QRMTWSC Attach immediately after the guest's SNASVCMG BIND, or
on receipt of its BIS before answering BIS, caused a host UNBIND of type
`FE` with sense `20030000` (bracket state error). Sending it after BIS
completion yielded `80050000` because the session had ended. These traces
rule out reusing the guest's default-management bracket in those states;
they do not identify the separate source-session activation sequence.

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
These are observed guest bytes. The probe responses are constructed, not
captured from a real 5494. Station `38` is not the configured printer at
address `01`, and its LU type is 7 rather than 4. The controller remains
`VARY ON PENDING`; the guest has queued spool files but has not sent an
address-01 printer BIND or SCS data. No spool has reached the concentrator.

The next protocol gate is activating the 5494 controller session and
observing the host's printer-session BIND and private `D824` records. The current
AnyNet reverse gateway completes and releases its separate SNASVCMG
management association before the controller session, so it cannot yet carry
that NMVT. A lab-only attempt to send the PSID as a TCP62 normal record on
this association after CNOS/BIS received no IBM i response and did not change
the subsequent controller exchange; that experiment was removed from the
router source. The native LLC path is verified for XID3, SNASVCMG, and the
direct NMVT, as described above.

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
The runtime byte `xx` and final transmitted work area still need capture.
Another local constant contains `30F0F6F3`,
whose purpose still needs to be traced.
`DUMP5494.DAT` file begins with `CC` filler and is not a useful trace. These
observations do not establish a successful 5494 conversation.

The firmware's `VG15.BIN` constructs an NMVT Reply PSID (`41 03 8D` request,
`00 90` major-vector key) with address-01 power-on bytes
`09 82 04 10 00 01 03 20 01`. Its product subvector starts `19 10` and
copies machine type, model, plant and serial from runtime twinax VPD. The
[research report](https://github.com/friedkiwi/syspass_research/blob/master/docs/sources/ibm-5494-lu62-lu4-printer-wire-protocol.md)
traces `VG15`'s direct network-management send path. It does not pass the NMVT
through a private LU 6.2 GDS. VG15 prepends a 12-byte FID2 TH/RH/NMVT header.
RH0 is `0B`; RH1/RH2 and FID2 addressing come from runtime session state.
VG15 marks the device ready after a resident-service transmit completion.
IBM i's response and runtime header bytes still need a live trace.
The configured `3812` machine type would be `F3 F8 F1 F2` in EBCDIC, but that
value was not observed in a populated firmware VPD table.

The V4R4 host-side `QND5MAIN` analysis found an Attach PIP parser at native
offset `0xCC14`. It walks length-prefixed subvectors and recognizes a
four-byte `04 D4 07 30` subvector identifying the 5494 controller family.
The [research report](https://github.com/friedkiwi/syspass_research/blob/master/docs/sources/ibm-5494-lu62-lu4-printer-wire-protocol.md)
also gives V5R4 `STRCMNTRC` commands for full LLC and AnyNet captures. This
subvector is part of Attach PIP; treating it as the printer address or the
power-on record would be unsupported.

1. Capture the actual V5R4 `QRMTWSC` control and printer sessions against a
   compatible 5494 or APPC printer peer. The firmware establishes the NMVT
   Reply PSID payload and its direct network-management path, but dynamic
   TH/RH fields, IBM i's response, and correlation with the parallel printer
   session still need a trace.
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
4. Print from the guest through AnyNet and LLC separately, capturing each
   router-to-concentrator circuit and confirming the received spool and both
   renderings. Passing APING or `VFYAPPCCNN` alone is insufficient.
