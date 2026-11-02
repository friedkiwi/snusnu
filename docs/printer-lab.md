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
SCS in printer records; [RFC 2877 section 10](https://datatracker.ietf.org/doc/html/rfc2877#section-10)
documents the related GDS `12A0` pass-through record shape and a print
completion response. [Microsoft's APPC printing documentation](https://learn.microsoft.com/en-us/host-integration-server/core/as-400-appc-printing1)
describes SCS and optional Host Print Transform. The first implementation
target is SCS text; an HPT or IPDS stream needs a separate renderer.

The [IBM 5494 Functions Reference, chapter 8](https://bitsavers.trailing-edge.com/pdf/ibm/5494/SC30-3533-02_5494_Remote_Control_Unit_Functions_Reference_Rel_2.0_199311.pdf)
settles the session direction: the 5494 first negotiates session limits with
CNOS and initiates the controller BIND. It then reports a powered-on printer
on that controller session; IBM i validates the device and initiates a second
LU 6.2 BIND for that printer. LU 4 printer traffic is encapsulated inside the
LU 6.2 device session. The service therefore needs both session directions
and the controller notification before a writer can send spool data.

The transport-independent Go `sna/services/printer` package now parses a
bounded printer record stream and renders common SCS fixed-pitch text. It does
not yet perform APPC session management, store jobs, or produce a PDF. The
renderer retains no information about font, forms, or graphics orders, so
raw SCS must be stored with any preview.

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

1. Capture the actual V5R4 `QRMTWSC` control and printer sessions against a
   compatible 5494 or APPC printer peer. Identify the Attach TP, startup,
   print, completion, and teardown records rather than treating APING as a
   printer protocol.
2. Generalize the router's service-directed BIND admission and both transport
   adapters for the printer's session profile, including printer-initiated
   sessions if the controller requires them. Verify the guest no longer stays
   `VARY ON PENDING`.
3. Add a reusable Go printer conversation in `sna`, then an embedded
   concentrator adapter that stamps the authenticated owner and source CP/LU,
   persists the raw stream, and acknowledges only durably accepted data.
4. Add per-owner spool listing, monospace preview, and greenbar PDF download.
5. Print from the guest through AnyNet and LLC separately, capturing each
   router-to-concentrator circuit and confirming the received spool and both
   renderings. Passing APING or `VFYAPPCCNN` alone is insufficient.
