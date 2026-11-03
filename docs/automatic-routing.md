# Automatic routing contract

With no `[[route]]` entries, the router makes each configured LLC, MPTN
`gateway`, and HPR/IP attachment a source and a possible destination. Each
carrier discovers its adjacent peer using its own protocol, then updates the
shared local route registry. The router selects one unambiguous live CP or LU
next hop for each new session. Missing or ambiguous destinations fail closed
and are logged; frames are never broadcast to all attachments. Explicit
`[[route]]` configurations retain their separate fixed-route behavior.

LLC discovery needs its adjacent OS/400 peer to dial out to a proxy MAC. The
router answers XID, verifies the peer CP from XID3, and learns LUs from
management and session evidence. A unique verified CP can be used to start a
local session before the target LU is known, but the exact LU is registered
only after a positive BIND. A passive LLC peer that never dials out remains
undiscovered. MPTN validates TCP62 management/BIND and tracks a lease on the
adjacent peer. EE validates XID3, HPR control and RouteSetup/BIND; an XID CP
alone does not prove every LU. Optional configured CP/LU names serve as
candidate hints and become reachable only with the required live proof.

The registry owns reachability, not carrier sockets or correlators. A route
selection carries an attachment and a versioned lease; withdrawal or peer
replacement invalidates old selections. An adapter owns link timers,
acknowledgments, flow control and discovery lifetime. The shared session
bridge carries BIND, result, information, pacing credit, UNBIND and reset;
converter code on each carrier maps those events to its wire format.

Local routes are usable without a concentrator, including identities outside
any one owner's upstream NETID. When a concentrator is configured, its Welcome
assigns the router one NETID. Only locally verified CP/LU identities in that
NETID are published upstream. Received routes are never republished.
Managed proxy MAC bindings and peer authorization come from the concentrator;
they are separate from local discovery.

The current automatic runtime supports local LLC↔LLC, LLC↔MPTN and
MPTN↔MPTN session paths, as well as EE↔LLC/MPTN and multiple EE attachments.
One process-long LLC/TCP62 owner is shared with the EE runtime. A selected
local MPTN session may lease a verified LLC dialout adjacency; the adjacency
returns to discovery after the session. Distinct EE attachments use bounded
`SessionEvent` bridges, and a failed EE attachment is retired independently.
The HPR LAN prototype and MPTN `relay` profile remain separate explicit
configurations.

## Verification status

- V5R4 TCP62 → standalone Rust → V4R4 LLC2 reached remote Sign On at
  19:07:34 UTC on 2026-11-03. The LLC target was selected by its unique
  verified CP, then the exact LU was learned from a positive user BIND.
  V4R4 LLC2 → standalone Rust → V5R4 TCP62 reached remote Sign On at
  19:11 UTC. These are both local MPTN↔LLC initiation directions.
- V5R4 TCP62 → Rust → QA concentrator → Rust → V4R4 LLC2 reached remote
  Sign On. Both directions of V5R4 EE↔V4R4 LLC2 through the concentrator
  also reached remote Sign On. V5R4 EE reached the embedded APING responder.
- V4R4 LLC2 → standalone Rust → V5R4 EE reached remote Sign On at
  19:16:06 UTC. V5R4 EE → standalone Rust → V4R4 LLC2 reached remote
  Sign On at 19:32:13 UTC using the verified LLC dialout adjacency borrowed
  by the EE session. No concentrator participated in either call.
- Multiple EE attachments and their bounded shared session bridge are
  implemented and code-gated. The in-process EE↔EE bridge test exchanges
  BIND/result, information in both directions, credit and UNBIND, then
  withdraws one destination while another pair remains open. No live
  session between two EE guests through that bridge has passed yet.
- In-process local MPTN↔MPTN and MPTN→EE event-path tests cover deferred
  target open, BIND/result, bidirectional information, credit, UNBIND and
  close/lease cleanup. These are not two-peer live guest results. A cold
  destination LU is withheld when another verified local CP in the NETID
  makes the fallback ambiguous; the router must not guess the LLC peer.
- On master `ef8c033`, a controlled V5R4 EE source `ENDJOB` closed one QA
  circuit; the router returned the same verified V4R4 LLC carrier and
  accepted a reverse call about 10 ms later without new XID or SNASVCMG.
  The reverse call reached V5R4 remote Sign On. This proves immediate
  same-link reuse after source close. Alice's controlled `ENDJOB` then closed
  the reverse QA circuit at 19:54:12 UTC; native user UNBIND completed and
  the verified LLC adjacency remained available. The guest's idle LLC DISC
  about 32 seconds after the first return can limit later reuse.

See [router runtime](router-runtime.md), [HPR/IP gateway](hpr-gateway.md),
[route advertisements](route-advertisements.md), and the
[cross-NETID lab](cross-netid-lab.md).
