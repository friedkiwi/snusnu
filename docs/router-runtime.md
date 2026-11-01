# Standalone Rust routing runtime

The Rust executable is the router. It must be able to bind two local endpoints and pass traffic between them without a Go process, WebSocket connection or concentrator. Remote links are optional next hops selected by the same route table. Locally reachable destinations exported over that hop use the [route advertisement format](route-advertisements.md). This is a target design, not an implemented feature: today `--lab-link` joins exactly two TAPs, `--site-id` only waits for shutdown, and `transport-ws` contains a placeholder trait.

## Three separate jobs

| Job | Owns | Examples |
| --- | --- | --- |
| I/O endpoint | Local interface or socket, framing and receive/send lifecycle | Linux AF_PACKET, TCP/UDP sockets, optional WebSocket peer |
| Protocol adapter | Link or session semantics and a typed event stream | LLC2 circuit, EE LDLC/HPR link, AnyNet MPTN/LU6.2 session |
| Route/converter | Chooses an egress, checks compatible event types, translates when required | LLC2 circuit relay, MPTN gateway, potential HPR media adapter |

An endpoint is not itself a route, and an arbitrary byte string is not a common protocol. The runtime should dispatch typed ingress events through an explicit route or converter and return typed commands to the egress adapter. Each adapter owns its local timers and protocol acknowledgements. The route owns the binding, circuit generation, failure propagation, queue limits and pressure between legs.

For a native LLC2 circuit, useful events are `Type1(XID|TEST, bytes)`, `Connected`, `Piu(bytes)`, `Closed` and `Reset`; commands include sending Type 1 traffic, opening/closing the link, sending a PIU and changing receive-busy state. The event identity includes local endpoint, peer MAC and SAP pair. Do not call HPR NLPs or AnyNet MPTN records `Piu` merely to fit this interface. EE's event stream must distinguish LDLC control and UI HPR NLP; AnyNet's must distinguish MPTN connect/BIND, normal/expedited data, UNBIND and keepalive.

## Route compatibility

| Ingress ↔ egress | Required route behavior | Initial status |
| --- | --- | --- |
| Native LLC2 ↔ native LLC2 | Relay Type 1 and PIU events while terminating LLC2 independently | Working fixed two-TAP lab; general runtime missing |
| Native LLC2 ↔ AnyNet | MPTN gateway for a configured LU6.2 session; native APPN CP/TG and IP-side MPTN behavior both matter | Research and captures needed |
| AnyNet ↔ AnyNet | Session-level forwarding with full MPTN state, or ordinary IP routing when no conversion is wanted | Not implemented |
| EE ↔ EE | Ordinary IP routing for EE-capable peers; an in-process EE link adapter only if local policy/translation requires it | IP network already supplies the underlay |
| EE ↔ native HPR LAN | Possible HPR media conversion with per-leg XID/link state and both LAN SAP paths; verify with paired traces | Unverified |
| EE ↔ legacy LLC2 APPC | APPN/HPR network-node behavior or a genuine dual-attached node | Not implemented |
| Any compatible circuit ↔ WebSocket ↔ remote circuit | Transport versioned, typed circuit events between Rust routers; both ends retain adapter state | Optional future hop |

Reject an unsupported or ambiguous route when loading configuration. Route selectors differ: native LLC uses endpoint/MAC/SAP, AnyNet uses configured LU/CP names and IP, and EE uses IP/SAP/TG link identity. MPTN correlators identify live sessions rather than static routes. A configured conversion must state its protocol and supported session scope; `llc-to-anynet` cannot mean every possible SNA PIU.

An illustrative local configuration, **not accepted by the current executable**, would define `lan_a` as an AF_PACKET LLC2 endpoint, `ip_b` as an AnyNet TCP/UDP 397 endpoint, and a bidirectional route between them with converter `mptn_lu62`, local and remote CP/LU names, peer MAC/SAP, remote IP and one supported mode/session policy. A second configuration could route `lan_a` to `lan_c` as a native circuit relay. Neither configuration would mention a concentrator. A remote route would select a WebSocket endpoint explicitly.

## Required implementation sequence

1. **Local runtime:** extract one `lab.rs` leg into a reusable LLC2 adapter, parameterize MAC/SAP and timers, add an endpoint registry and route table, and make `--config` start local routes. Keep `--lab-link` as a compatibility configuration. Preserve the V4R4 pass-through result through the new path.
2. **Flow control:** stop acknowledging data into an already-full route. `Llc2::receive` currently emits `Deliver` followed by RR immediately; the lab resets both legs when its 32-entry queue fills. Add receiver admission/local-busy control (RNR then RR on recovery), bounded per-route/session queues, timeout and reset propagation. Test these state transitions and the direct two-TAP regression.
3. **AnyNet evidence:** capture direct V5R4 AnyNet APPC traffic on TCP/UDP 397 and the same application over native LLC2. Parse MPTN framing and correlate BIND, data, pacing, expedited, UNBIND and keepalive with native PIUs. The [IBM-authored TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00) describes access nodes but explicitly leaves MPTN gateway behavior beyond its scope.
4. **First standalone LLC2 ↔ AnyNet route:** support one configured independent LU6.2 pair and one session/mode. Terminate native LLC2; track native CP/session and BIND state; map the session to TCP/397; translate full/reduced TH, RH pacing and segmented RUs; handle UDP/397 out-of-band and keepalive. Prove initiation and teardown from both directions against real Solstice peers before widening supported session types.
5. **EE investigation:** capture EE between EE-capable peers and paired native HPR LAN traffic. Add separate LDLC/HPR types and validate any proposed media adapter against XID/TG/link activation and both LAN SAP paths. General legacy LLC2-to-EE APPN routing is a larger network-node feature.
6. **Remote hop:** define a versioned, typed circuit envelope, then implement `transport-ws` and its Go concentrator path. Local route behavior and tests must continue to work with the remote endpoint absent.

The V5R4 Solstice network template has TCP/IP but no documented successful AnyNet or EE session yet; it also uses a frozen custom Solstice build. Validate that guest setup before relying on IP captures. The V4R4 LLC2 two-TAP pass-through is the current regression baseline.

Protocol background: [RFC 2353, APPN/HPR in IP Networks](https://www.rfc-editor.org/rfc/rfc2353.html); [IBM-authored TCP62 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00); [IBM System i EE configuration](https://www.ibm.com/support/pages/configuring-ee-enterprise-extender-between-two-ibm-system-i-systems). The EE-to-HPR-LAN media-adapter possibility is an inference pending captures, not an interoperability claim.
