# HPR/IP gateway implementation plan

`[[hpr_ip]]` currently binds UDP 12000–12004, validates EE LDLC/UI datagrams,
and relays each datagram to one configured HPR/IP peer. The two-V5R4
[EE lab](ee-lab.md) completed pass-through in both directions through that
configured relay. This is a link relay, not an APPN node or a source of LU
sessions. Automatic routing rejects `[[hpr_ip]]` until there is an adapter with
the semantics required by the selected route.

The intended gateway terminates an HPR/IP adjacency and presents *verified LU
sessions* to the router's carrier-neutral session contract. It must also
accept sessions from LLC, MPTN or a concentrator circuit and create the
corresponding HPR-side session. Merely transporting an HPR NLP as a generic
`SnaInformation` byte vector does not provide either direction.

## Existing pieces and limits

| Code | Existing capability | Limit |
| --- | --- | --- |
| [`transport-ip-sna::ee`](../sna_router/crates/transport-ip-sna/src/ee.rs) | Five UDP sockets and bounded LDLC/UI datagram codec | No link, APPN, RTP or LU session state |
| [`EePort`](../sna_router/crates/snusnu-router/src/ip_ports.rs) | One configured peer IP and `RoutedUnit::EeDatagram` relay | Homogeneous HPR/IP route only; one peer per local IP |
| [`hpr_lan`](../sna_router/crates/router-core/src/hpr_lan.rs) | LAN UI framing, HPR SAP and NLP classification | No activated LAN↔IP TG |
| [`HprXidLeg`](../sna_router/crates/router-core/src/hpr_xid_leg.rs) and [`SetModeBridge`](../sna_router/crates/router-core/src/hpr_setmode.rs) | Evidence tracking and a proposed LAN↔IP SETMODE mapping | Neither is an HPR/IP endpoint; XID agreement alone cannot activate a TG |
| [`hpr_rtp`](../sna_router/crates/router-core/src/hpr_rtp.rs) | Strict NHDR/THDR framing, full 64-bit TCIDs, CIE parsing and bounded message assembly | No active RTP connection or wire reliability |
| [`hpr_rtp_setup`](../sna_router/crates/router-core/src/hpr_rtp_setup.rs), [`hpr_rtp_reply`](../sna_router/crates/router-core/src/hpr_rtp_reply.rs) | Receive-side setup evidence and bounded STATUS+CIE packet encoding | Return path, status exchange, transmission and retries are not established |
| [`hpr_rtp_receive`](../sna_router/crates/router-core/src/hpr_rtp_receive.rs), [`hpr_rtp_send`](../sna_router/crates/router-core/src/hpr_rtp_send.rs) | Bounded RSEQ/ABSP accounting and retransmission candidates | No timers, ARB pacing or live RTP transport loop |
| [`hpr_fid5`](../sna_router/crates/router-core/src/hpr_fid5.rs), [`hpr_session_address`](../sna_router/crates/router-core/src/hpr_session_address.rs), [`hpr_route_setup`](../sna_router/crates/router-core/src/hpr_route_setup.rs) | Receive-side FID5, BIND/CV62 association and Route Setup parsing | No APPN route response, LU session admission or HPR egress |
| [`SessionFabric`](../sna_router/crates/router-core/src/session_fabric.rs) | Bounded carrier-neutral LU/CP route selection and session event queues | Existing runtime adapters are not yet wired through it |

[RFC 2353](https://www.rfc-editor.org/rfc/rfc2353.html) defines HPR/IP as a
native IP DLC: LDLC controls the link, while HPR RTP carries session traffic.
IBM describes an ANR intermediate node as having no session awareness, and
notes that multiple APPN sessions may share one RTP connection. A relay that
only forwards ANR packets therefore cannot produce the LU BIND and PIU events
needed by a carrier-neutral session gateway. [IBM HPR overview](https://www.ibm.com/docs/en/i/7.4.0?topic=performance-communications-optimization-using-high-routing).

## State boundaries

Implement separate bounded state machines rather than placing all state in a
UDP socket:

1. **Listener and adjacency.** One local IP owns the five UDP ports. Demux by
   remote IP and negotiated SAP/link identity, with an explicit limit on
   adjacencies. Accept control packets from an unconfigured IP only after
   validation; do not treat the UDP source port as peer identity. Track
   source IP, local IP, CP, NETID, link generation and timers. A configured
   peer IP remains a useful strict mode for the existing relay.
2. **LDLC and TG.** Parse XID3 identity, CV61 HPR/LDLC capabilities, CV46/CV80
   TG identity, roles and negotiated SAPs. Maintain pre-negotiation,
   negotiation, SETMODE, active, liveness and closing phases. Implement
   XID_DONE, TEST and DISC/DM replies and retries per leg. Never advertise
   unsupported HPR/RTP/Control-Flows-over-RTP capability bits to OS/400.
3. **APPN/HPR control plane.** Establish the CP/TG relationship and control
   flow RTP connection, process route setup and ANR label allocation, and
   derive a verifiable hosting CP and LU reachability. XID3 proves a CP,
   not every LU hosted by that CP. A distinct peer with a wrong assigned
   NETID is rejected and logged before any upstream announcement.
4. **RTP endpoint.** Correlate each directional connection identifier and
   qualifier; implement setup, ACK, bounded reorder/retransmit buffers,
   selective recovery, message segmentation/reassembly, EOM accounting,
   adaptive-rate flow control and teardown. Only packets from a fully
   established connection may yield session data. Unknown optional segments
   and unsupported path-switch behavior fail the affected connection closed.
5. **Session adapter.** Demultiplex the verified RTP message stream into
   individual LU sessions. Translate BIND, information/expedited data, pacing
   and UNBIND into the shared session contract, retaining source LU, target
   LU, hosting CP and session correlators. The reverse adapter creates HPR
   route/session setup and emits RTP traffic for a carrier-neutral session
   selected for this HPR/IP adjacency.

The HPR/IP listener should not itself select the concentrator or another
carrier. It supplies an ingress session and observations to the existing
directory; the router chooses a destination and creates an isolated egress
session. Preserve priority and datagram boundaries within the HPR link/RTP
layer. They are not LU session attributes.

## Test gates before enabling the gateway

1. Capture a direct V5R4 HPR/IP session against a genuine APPN/HPR peer in
   both initiation directions. Sanitize and retain control packets and
   expected decoded fields for XID3, XID_DONE, TEST, control-flow RTP setup,
   route setup, a user BIND, segmented information, pacing and teardown.
   The current [EE lab](ee-lab.md) captures link relay, not a router-owned
   HPR endpoint. The [HPR LAN lab](hpr-lan-lab.md) shows a failed mixed-media
   activation after XID3; it is not a successful gateway trace.
2. Feed captured and malformed packets to each state machine. Assert
   identity continuity, role/TG/SAP agreement, current generation, bounded
   lengths/queues, timer behavior, duplicate and out-of-order XID/TEST,
   wrong UDP IP/priority port, RTP gaps/duplicates/wraparound, stale ACKs,
   qualifier mismatch, and cleanup after a peer or upstream failure.
3. Run a live V5R4 `LINKTYPE(*HPRIP)` peer against the new Rust
   endpoint and show active TG, control-flow RTP, user session BIND, data and
   clean UNBIND. A Sign On reached via an opaque EE relay is insufficient.
4. Route that session through the shared contract to another V5R4 HPR/IP
   peer, then to an existing MPTN and LLC peer, in both initiation directions.
   Test standalone and concentrator hops, different owners/NETIDs, route
   withdrawal, and reconnect. Existing LLC↔LLC, MPTN↔LLC, MPTN↔MPTN and
   configured HPR/IP↔HPR/IP labs remain regression gates.
5. Run the staged-tree Rust CI gate before each commit and push. Keep the
   gateway disabled in normal configuration until the live link, RTP and LU
   gates pass; retain the working explicit HPR/IP relay throughout.

## Embedded APING acceptance test

The first end-to-end application target is an OS/400 guest connected to
`sna_router` over EE and running
`VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(16) NBRITER(1)`.
The concentrator publishes `SNUSNU.SVC` and its LU 6.2 service
`SNUSNU.PING`. A `snusnu.v2` open must reference a live, authenticated source
LU 6.2 route and the PING target route. A passing test needs the guest command
to report success, with captured EE XID/TG activation, control RTP, user BIND,
APINGD Attach, version, echo, and orderly close across the router and
concentrator. The existing LLC APING trace reached echo and close but did not
capture the guest's final command result.

The Go APING service currently consumes native XID/TEST, `LinkReady`, and
complete FID2 PIUs. EE supplies LDLC, RTP, and FID5. A gateway cannot send
the FID5 bytes directly to that service or simply replace the FID5 header:
directional session addresses and FID2 address fields have different owners,
and the native service has its own management session state. One integration
option is a versioned carrier-neutral session circuit for BIND, BIND result,
information, credit, UNBIND, and reset; the existing native profile remains
for LLC. Another is a complete virtual native DLC/FID2 adapter in Rust. The
Go and Rust sides must agree on one of these contracts before the APING route
is enabled for EE. The `SNUSNU` target NETID also makes cross-NETID APPN
reachability a separate live test after same-NETID EE adjacency works.

An earlier, independent milestone may transport validated HPR/IP datagrams
between two routers through a typed WebSocket link profile. That preserves
EE↔EE behavior across the concentrator but **does not** enter the LU session
pipeline or claim HPR endpoint support. It needs its own wire contract and
Go/Rust interoperability vectors.
