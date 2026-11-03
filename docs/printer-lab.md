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
CNOS and initiates the controller BIND. It then reports a powered-on printer
on that controller session; IBM i validates the device and initiates a second
LU 6.2 BIND for that printer. LU 4 printer traffic is encapsulated inside the
LU 6.2 device session. The service therefore needs both session directions
and the controller notification before a writer can send spool data.

The transport-independent Go `sna/services/printer` package now parses the
IBM-defined inner LU 4 FID3 PIU header, classifies a printer BIND, builds
candidate ACTLU and printer BIND responses, and renders common SCS fixed-pitch
text. It also encodes the short, hardware-only NMVT Reply Product Set ID used
to announce a powered-on printer, with runtime SNA address and VPD supplied by
the caller. These candidates have not been exercised against the guest. The
enclosing LU 6.2 controller and device GDS envelopes remain unknown.
The package does not perform APPC session management, store jobs, or produce a
PDF. The concentrator now has owner-scoped durable raw SCS storage,
a searchable print list, a monospace preview, and a greenbar PDF writer. These
are not connected to a live 5494 printer conversation yet. The renderer
retains no information about font, forms, or graphics orders, so raw SCS is
stored with each preview.

The reusable `sna/lu62` package also constructs candidate `QRMTWSC` CNOS and
controller BIND requests with dynamic LU names, CP name, and FQPCID. Its
CNOS reply validator checks the accepted-pending service, mode, session limits,
and reversed FID2 addresses before the controller can proceed. Its
binary architecture-TP Attach parser can retain the controller TPN
`30F0F6F6` without treating it as an EBCDIC application name. These requests
have not been accepted by a live IBM i controller session. Building the
controller Attach, processing its reply, and wrapping the NMVT in the live
controller exchange remain to be implemented.

IBM's [LU 6.2 guide](https://www.ibm.com/docs/en/SSLTBW_3.1.0/pdf/istp620_v3r1.pdf)
defines both basic and mapped FMH-5 conversation forms. The parser accepts
either form; the 5494's choice and its allocation data still need a trace.

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

Those temporary changes live only in `/tmp/snusnu-printer-probe`. They do not
constitute printer service support in the repository. This probe used EE to
establish a known route baseline; it did **not** test the required AnyNet or
LLC routes. The pending controller also shows that advertising a passive LU
does not itself make a 5494-like printer available to the guest. The service
must initiate the controller session and accept the host-initiated printer
session, including `QRMTWSC` application records.

## Remaining acceptance work

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
At `VG10.BIN` offset `0x9288`, a basic-conversation FMH-5 template has binary
TPN `30F0F5F1` and the PIP-present flag set. The firmware copies
`30F0F6F6` from `5494CONF.DAT` over that TPN at runtime for the controller
Attach. This establishes the target TP for Release 3.2, though the transmitted
FMH-5 and PIP still need a trace. Another local constant contains `30F0F6F3`,
whose purpose still needs to be traced.
`DUMP5494.DAT` file begins with `CC` filler and is not a useful trace. These
observations do not establish a successful 5494 conversation.

The firmware's `VG15.BIN` constructs an NMVT Reply PSID (`41 03 8D` request,
`00 90` major-vector key) with address-01 power-on bytes
`09 82 04 10 00 01 03 20 01`. Its product subvector starts `19 10` and
copies machine type, model, plant and serial from runtime twinax VPD. The
[research report](https://github.com/friedkiwi/syspass_research/blob/master/docs/sources/ibm-5494-lu62-lu4-printer-wire-protocol.md)
lists exact firmware offsets and the remaining unknown wrapper and host reply.
The configured `3812` machine type would be `F3 F8 F1 F2` in EBCDIC, but that
value was not observed in a populated firmware VPD table.

The V4R4 host-side `QND5MAIN` analysis found an Attach PIP parser at native
offset `0xCC14`. It walks length-prefixed subvectors and recognizes a
four-byte `04 D4 aa bb` subvector, whose final two bytes have not been
identified. The [research report](https://github.com/friedkiwi/syspass_research/blob/master/docs/sources/ibm-5494-lu62-lu4-printer-wire-protocol.md)
also gives V5R4 `STRCMNTRC` commands for full LLC and AnyNet captures. This
subvector is part of Attach PIP; treating it as the printer address or the
power-on record would be unsupported.

1. Capture the actual V5R4 `QRMTWSC` control and printer sessions against a
   compatible 5494 or APPC printer peer. The firmware establishes the NMVT
   Reply PSID payload, but its outer controller record, IBM i's immediate
   reply, and correlation with the parallel printer session still need a trace.
2. Generalize the router's service-directed BIND admission and both transport
   adapters for the printer's session profile. The concentrator local service
   registry can now open an outbound circuit from its own LU, but the router's
   HPR attachment still rejects unsolicited opens. Verify the guest no longer
   stays `VARY ON PENDING`.
3. Add a reusable Go printer conversation in `sna`, then an embedded
   concentrator adapter that stamps the authenticated owner and source CP/LU,
   persists the raw stream, and acknowledges only durably accepted data.
4. Print from the guest through AnyNet and LLC separately, capturing each
   router-to-concentrator circuit and confirming the received spool and both
   renderings. Passing APING or `VFYAPPCCNN` alone is insufficient.
