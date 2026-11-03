# HPR/IP session gateway

`[[hpr_ip]]` is the router's Enterprise Extender (EE) attachment. Automatic
mode terminates the guest's five UDP priority ports, LDLC adjacency, HPR RTP
connections and LU 6.2 session. It passes verified session events through the
same route selection and `SessionV1` contract used by LLC and MPTN adapters.
The configured EE-to-EE datagram relay remains a separate supported path.
See [router runtime](router-runtime.md) for the shared discovery and route
registry model.

## Current state

| Component | Implemented responsibility | Current limit |
| --- | --- | --- |
| [`ee`](../sna_router/crates/transport-ip-sna/src/ee.rs) and [`auto_hpr_runtime`](../sna_router/crates/snusnu-router/src/auto_hpr_runtime.rs) | Five UDP priority ports per attachment, bounded LDLC/UI decoding, XID3 adjacency, control/user RTP, RouteSetup and FID5 session events | Multiple automatic EE attachments are supported; a two-EE live session is pending |
| [`hpr_shared_local`](../sna_router/crates/snusnu-router/src/hpr_shared_local.rs) | Shares process-long LLC and TCP62 attachments with EE; accepts verified local offers | Peer proof and active session state remain specific to each carrier |
| [`route_registry`](../sna_router/crates/router-core/src/route_registry.rs) and [`hpr_destination_directory`](../sna_router/crates/snusnu-router/src/hpr_destination_directory.rs) | Select unambiguous CP/LU next hops from versioned local and upstream owners | Configured identity hints alone do not create an active LU route |
| [`SessionFabric`](../sna_router/crates/router-core/src/session_fabric.rs) | Bounded LU/CP session selection and event queues | Each ingress and egress adapter must implement its own wire protocol and session lifecycle |
| [`transport-ws`](../sna_router/crates/transport-ws/src) | `SessionV1` BIND, result, information, pacing credit and UNBIND over the concentrator | Go's relay authorizes and forwards the session, but does not convert carriers |

The EE adapter validates XID3 CP identity and derives LU reachability from
RouteSetup/BIND and other verified control exchange. It does not infer every
LU from a CP XID. LLC and MPTN adapters maintain their own discovery proofs.
Replacing or withdrawing one proof updates the shared directory without
discarding unrelated attachments. A concentrator outage withdraws its remote
routes; local attachments continue polling. The server's assigned NETID
restricts local route **publication upstream**, not routing between local
attachments.

## Live evidence, 2026-11-03

1. A V5R4 guest connected over EE, sent APINGD through Rust and a
   `SessionV1` circuit to the concentrator's embedded `SNUSNU.PING` responder,
   and reported one successful round trip (31 ms).
2. V5R4 EE → Rust → Go concentrator → Rust → V4R4 LLC2 reached the V4R4
   remote Sign On screen. The circuit carried user BIND, information and
   pacing in both directions. Ending the request closed the upstream circuit,
   but an earlier LLC native UNBIND response variant led the adapter to
   restart discovery. Short native UNBIND and source-close fixes are now
   code-gated; a live normal-close and route-retention retest is pending.
3. The reverse V4R4 LLC2 → Rust → Go → Rust → V5R4 EE path completed EE
   external SNASVCMG management, CNOS/BIS, user BIND and first display
   traffic. At 18:23:36 UTC the V4R4 console displayed the V5R4 remote
   Sign On. The QA circuit was `b38611ed` (prefix). An earlier positive user
   BIND response exposed a pacing mode bit that Rust rejected; the corrected
   parser allowed this live session. Normal teardown and repeated sessions
   in this direction still need verification.
4. Without a concentrator, V4R4 LLC2 → Rust → V5R4 EE reached remote
   Sign On at 19:16:06 UTC. V5R4 EE → Rust → V4R4 LLC2 reached remote
   Sign On at 19:32:13 UTC. The latter session borrowed an existing verified
   LLC dialout adjacency; returning it after close remains part of the
   pending live teardown retest.
   Both results demonstrate local gateway routing to the first display, not
   a completed normal teardown or a two-EE guest bridge.

These are session gateway tests, distinct from the older configured EE UDP
relay and direct [EE lab](ee-lab.md). The [cross-NETID lab](cross-netid-lab.md)
records the guest and concentrator setup. Private captures and logs remain
outside the repository.

## Next test gates

1. Retest EE → LLC2 normal teardown with a synchronized V4R4 capture. Check
   the short native UNBIND and source-close fixes, and verify that the idle
   LLC2 adjacency and published route survive. Also exercise remote reset
   and peer loss.
2. Repeat the embedded APING test after the reverse-path fixes, then test
   local EE↔MPTN without a concentrator. Check routing among
   different local NETIDs, route withdrawal, reconnect and duplicate-route
   ambiguity.
3. Connect two EE guests to different attachments on one router and verify
   the bounded `SessionEvent` bridge in both directions. Test repeated and
   overlapping sessions, normal close and recovery after a guest or
   concentrator disconnect. The multi-EE implementation is code-gated but
   has no two-EE live guest result yet.
4. Keep the configured EE↔EE relay, native LLC↔LLC and MPTN↔LLC live paths
   as regression tests. Run the staged-tree CI gate before each commit and
   push.

HPR/IP is a native IP DLC: LDLC controls the link while HPR RTP carries
session traffic. [RFC 2353](https://www.rfc-editor.org/rfc/rfc2353.html)
describes the IP encapsulation, and [IBM's HPR overview](https://www.ibm.com/docs/en/i/7.4.0?topic=performance-communications-optimization-using-high-routing)
distinguishes intermediate packet forwarding from APPN session awareness.
An HPR LAN attachment still needs a separately tested LAN link/SAP adapter;
the direct [HPR LAN capture](hpr-lan-lab.md) does not establish a working
LAN↔IP media gateway.
