# Standalone Rust routing runtime

The Rust executable is the router. [`--config`](router-config.md) binds multiple local LLC2 peers, including peers on one TAP, and routes them without Go or a WebSocket connection. It can also relay two configured `[[hpr_ip]]` UDP links, implementing the IP side of Enterprise Extender (EE). Remote LLC2 routes share one authenticated WebSocket connection and publish configured CP and LU reachability using the [route advertisement format](route-advertisements.md). The remote circuit profile currently carries native DLC Type 1 and LLC2 information fields; it does not carry AnyNet sessions or HPR NLPs.

## Three separate jobs

| Job | Owns | Examples |
| --- | --- | --- |
| I/O endpoint | Local interface or socket, framing and receive/send lifecycle | Linux AF_PACKET, TCP/UDP sockets, optional WebSocket peer |
| Protocol adapter | Link or session semantics and a typed event stream | LLC2 circuit, HPR/IP LDLC/HPR link (EE), AnyNet MPTN/LU6.2 session |
| Route/converter | Chooses an egress, checks compatible event types, translates when required | LLC2 circuit relay, MPTN gateway, potential HPR media adapter |

An endpoint is not itself a route, and an arbitrary byte string is not a common protocol. The runtime should dispatch typed ingress events through an explicit route or converter and return typed commands to the egress adapter. Each adapter owns its local timers and protocol acknowledgements. The route owns the binding, circuit generation, failure propagation, queue limits and pressure between legs.

For a native LLC2 circuit, useful events are `Type1(XID|TEST, bytes)`, `Connected`, `Piu(bytes)`, `Closed` and `Reset`; commands include sending Type 1 traffic, opening/closing the link, sending a PIU and changing receive-busy state. The event identity includes local endpoint, peer MAC and SAP pair. Do not call HPR NLPs or AnyNet MPTN records `Piu` merely to fit this interface. EE's event stream must distinguish LDLC control and UI HPR NLP; AnyNet's must distinguish MPTN connect/BIND, normal/expedited data, UNBIND and keepalive.

## Route compatibility

| Ingress ↔ egress | Required route behavior | Initial status |
| --- | --- | --- |
| Native LLC2 ↔ native LLC2 | Relay Type 1 and PIU events while terminating LLC2 independently | Configured multi-peer runtime; V4R4 pass-through completed through `--config` |
| Native LLC2 ↔ MPTN | MPTN gateway for a configured LU6.2 session; native APPN CP/TG and IP-side MPTN behavior both matter | Opt-in V5R4 AnyNet to V4R4 LLC2 path reached remote Sign On through the concentrator; ordinary config remains gated |
| MPTN ↔ MPTN | Configured TCP62 session forwarding and IPv4 UDP node-pair keepalive translation | V5R4 AnyNet pass-through and live idle keepalive completed through Rust relay |
| HPR/IP ↔ HPR/IP (EE) | Preserve LDLC/HPR UDP payloads and priority ports between configured peers | Configured UDP relay completed V5R4 pass-through through separate TAPs |
| HPR/IP ↔ native HPR LAN | Possible HPR media conversion with per-leg XID/link state and both LAN SAP paths | Separate direct V5R4 captures and a typed LAN port prototype; mixed-link activation unverified |
| HPR/IP ↔ legacy LLC2 APPC | APPN/HPR network-node behavior or a genuine dual-attached node | Not implemented |
| Native LLC2 ↔ WebSocket ↔ native LLC2 | Transport a versioned logical circuit between Rust routers; each router owns its local LLC2 state | Working V4R4 pass-through, including Go QA concentrator; multi-circuit hub has mock-server tests |

Reject an unsupported or ambiguous route when loading configuration. Local route selectors differ: native LLC uses endpoint/MAC/SAP, AnyNet uses configured LU/CP names and IP, and HPR/IP uses IP/SAP/TG link identity. MPTN correlators identify live sessions rather than static routes. Exported reachability uses network-qualified [CP or LU identities](os400-sna-names.md) without publishing those local selectors. A configured conversion must state its protocol and supported session scope; `llc-to-anynet` cannot mean every possible SNA PIU.

The current configuration accepts LLC2↔LLC2, HPR/IP↔HPR/IP, LLC2↔WebSocket, and `[[mptn]] profile = "relay"` to relay routes. It rejects a direct LLC2↔MPTN route; `[[mptn]] profile = "gateway"` can connect an AnyNet peer to a native WebSocket circuit only through the opt-in QA path. Ordinary gateway config remains gated until native session addressing and lifecycle are generalized. A future HPR/IP/native HPR adapter needs XID3 link and SAP negotiation. Conversion cannot be implemented by forwarding raw PIU bytes into another wire format.

## Implementation status and next protocol work

1. **Local runtime and flow control:** `--config` registers separate LLC2 associations, validates MAC selectors, and installs bidirectional routes. LLC2 uses local busy RNR/RR and bounded queues. A local port I/O fault quarantines its connected route component with bounded backoff while other local components keep polling. A failed shared WebSocket transport still rebuilds the configured runtime during reconnect. The fixed `--lab-link` and `--local-link` modes remain available. The configured path completed V4R4 remote sign-on and pass-through teardown.
2. **Remote hop:** `transport-ws` and the Go concentrator carried a complete V4R4 pass-through. The Rust hub now exports multiple CP/LU routes and demultiplexes multiple circuits on one authenticated connection. The native DLC/PIU profile is the only supported WebSocket data profile.
3. **MPTN evidence and gateway:** bounded TCP/UDP 397 codecs, relay, and opt-in native session conversion are implemented for IBM AnyNet peers. A [direct V5R4 AnyNet pass-through](anynet-lab.md) captured MPTN Connect/BIND, normal, expedited, and acknowledgement records; the [cross-NETID lab](cross-netid-lab.md) reached V4R4 remote Sign On through Rust gateway, concentrator, and LLC2. The gateway still needs general native address selection, persistent session lifecycle, and a live OS/400 UDP `0x83` interoperability test. The [IBM-authored TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00) describes access nodes but leaves full MPTN gateway behavior beyond its scope.
4. **EE evidence and media conversion:** the configured EE↔EE UDP relay and LDLC/UI codec carried a complete V5R4 remote sign-on and teardown. A separate [direct HPR LAN session](hpr-lan-lab.md) captured XID3, LLC2 control, and SAP C8 UI traffic. The typed HPR LAN port is still unconfigured pending a tested mapping of LAN SABME/UA/RR to EE activation and CV61 SAP negotiation. General legacy LLC2 APPC to EE requires APPN/HPR network-node behavior, beyond UDP framing.

The direct V4R4 trace continues from a user BIND and FMH-5 Attach to an 82-byte GDS X'12A0' record. Its header matches the 5250 startup record in [IBM-authored RFC 2877 §9](https://www.rfc-editor.org/rfc/rfc2877.html#section-9). It is application data, not an APPC Attach acknowledgment; the observed `I903` response code has no meaning assigned in that RFC. The Rust parser correlates the record for diagnostics only. A native router must forward the Attach to an actual destination LU/transaction program and let that application produce the status record.

The V5R4 lab guests completed a direct AnyNet session, a direct EE session, and an EE session through the Rust relay. The V4R4 LLC2 pass-through remains the native DLC interoperability baseline.

Protocol background: [RFC 2353, APPN/HPR in IP Networks](https://www.rfc-editor.org/rfc/rfc2353.html); [IBM-authored TCP62 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00); [IBM System i EE configuration](https://www.ibm.com/support/pages/configuring-ee-enterprise-extender-between-two-ibm-system-i-systems). The EE-to-HPR-LAN media-adapter possibility is an inference pending captures, not an interoperability claim.
