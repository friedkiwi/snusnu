# Automatic routing contract

When a router config contains no `[[route]]` entries, each attachment is a
source and a possible destination. The router resolves the destination of
each new session from its LLC proxy MAC, XID3 CP, native BIND LU, or TCP62
Connect LU. It selects one locally observed attachment or one route from the
concentrator directory. Missing or ambiguous destinations are rejected and
logged; frames are never broadcast to every attachment. Each accepted
session owns a private circuit and flow-control state. Explicit `[[route]]`
configs retain their current behavior.

The concentrator's Welcome assigns one NETID to an authenticated router.
Automatic publication includes only **locally observed** CP/LU identities in
that NETID. Other local identities remain available for local routing. A
router never republishes routes learned from the concentrator. The server
continues to apply its own owner and peer policy when opening a circuit.

## Shared WebSocket protocol requirement

The existing v2 `OpenRequest.source_route` is a `RouteReference`; its protobuf
shape needs no change. To carry both transparent LLC and LU6.2 gateway
circuits on one v2 connection, the concentrator must validate two cases:

| Source route | Target route | Open behavior |
| --- | --- | --- |
| CP | CP | Permit a CP-scoped circuit after checking both references belong to live exports, the source CP is in the authenticated owner's NETID, the target CP belongs to the target router, and normal owner/peer policy allows the pair. Forward the source CP reference in `IncomingOpen`. |
| LU | LU | Keep the existing v2 source LU, target LU, hosting CP, and policy checks for gateway sessions. |

Reject CP-to-LU, LU-to-CP, absent source references, stale generations, and
cross-owner source claims. The Rust receiver must validate the same route
kinds before accepting `IncomingOpen`. A CP-scoped circuit carries native
LLC Type1 and SNA information. An LU-scoped circuit uses the existing gateway
converter. Circuit credit and close semantics are unchanged.

Current Go validation in `concentrator/internal/server/router_circuits.go`
requires a source LU for every v2 OPEN. Until it accepts the CP-to-CP case,
the mixed automatic runtime must reject CP-scoped upstream opens rather than
send a request the server cannot safely authorize.
