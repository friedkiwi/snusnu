# Rust router ↔ Go concentrator WebSocket draft

The WebSocket is an optional route hop. A Rust router can still route between local endpoints without Go. On a remote route, Go authenticates the routers, distributes their SNA CP/LU reachability, pairs circuits and forwards bounded circuit events. It does not interpret XID, PIUs, AnyNet or HPR. The draft protobuf messages are in [`snusnu_ws_v1.proto`](../proto/snusnu_ws_v1.proto) and the [route schema](../proto/snusnu_routes_v1.proto). Neither endpoint implements this protocol yet.

## Connection

1. Rust opens `wss://<concentrator>/router/v1/ws` with `Authorization: Bearer <router credential>` and requests `Sec-WebSocket-Protocol: snusnu.v1`. Go authenticates the token to its server-owned router UUID **before** the WebSocket upgrade, and selects exactly `snusnu.v1`. The token is never placed in the URL, WebSocket subprotocol value or application messages. [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) permits authentication headers and defines subprotocol selection; [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) defines bearer header use.
2. Go sends `RouterWelcome` as the first application message: router UUID, owner-selected display name, fresh server-generated 16-byte connection epoch and limits. Rust logs the assigned UUID and display name but cannot set either. The server fences any older WebSocket using that UUID.
   If the owner renames an active router, Go sends `RouterIdentityUpdate` with the new display name; a reconnect always receives the latest name in `RouterWelcome`.
3. Rust sends a complete `RouteSnapshot` echoing the server epoch, revision 1. Go stamps the authenticated router UUID, filters each recipient's view and sends `OriginRouteSnapshot`/`OriginWithdraw`. Subsequent changes are complete atomic snapshots with increasing revisions. Go rejects an epoch mismatch or stale revision.

One `WsEnvelope` protobuf is encoded into one **binary WebSocket message**. No second length prefix, text message or per-event sequence number is used. WebSocket supplies message boundaries and connection order; Go must maintain FIFO for each circuit when forwarding between two sockets. WebSocket Ping/Pong checks connection liveness. Circuits are never resumed or replayed after a connection loss. [RFC 6455, sections 5.4–5.5](https://www.rfc-editor.org/rfc/rfc6455.html)

## Circuit lifecycle

| Step | Message | Action |
| --- | --- | --- |
| 1 | `OpenRequest(request_id, RouteReference, initial receive allowance)` | Source Rust asks Go to reach a currently advertised CP/LU route. |
| 2 | `IncomingOpen(circuit_id, source_router_id, target, source allowance)` | Go validates source permission and current target, allocates a fresh 16-byte circuit ID, and offers it to the owning Rust router. |
| 3 | `OpenDecision(accept/reject, target receive allowance)` | Target rechecks its route, local readiness and conversion ability. |
| 4 | `OpenResult` to source; `OpenReady` to target | Go binds exactly two authenticated connections. Each side may send circuit events after its positive confirmation. |
| 5 | `CircuitEvent`, `CircuitCredit` | Go relays to the other bound router, checks sender and credit, and maintains bounded queues. |
| 6 | `CircuitClose` or `CircuitReset` | Close ends normally after prior events; reset aborts and discards queued events. Either router or Go can reset. |

The route advertisement contains only the SNA resource identity. `OpenRequest` names the target route handle and carries no claim about the target's local encapsulation. The v1 circuit event profile is the native DLC/PIU representation already exercised by the two-TAP lab: structured XID/TEST command or response with P/F and SAPs, a link-ready event, and the opaque SNA information field accepted from an LLC2 I frame. MAC headers, LLC2 sequence numbers, SABME/UA/RR and retransmission timers stay with each local Rust adapter. The information field is not guaranteed to be one complete PIU; converters must parse/reassemble when required.

This event profile is a **data-plane contract**, not a claim that every CP or LU uses LLC2 locally. An AnyNet adapter can accept it only after its MPTN gateway is implemented; an EE/HPR adapter requires separate HPR conversion or a later overlay event profile. Until then the owning Rust router rejects an unsupported open. Go only checks message validity, route authorization, size, circuit binding and credit, never the SNA payload.

## Pressure and failure

Each direction has an absolute cumulative `allowance_bytes` for `sna_information` payload bytes since circuit creation. The opening messages grant the initial allowance; the receiving Rust router increases it with `CircuitCredit` after it has consumed data from bounded storage. Go rejects data beyond the allowance and limits its own per-circuit and per-connection queues. XID/TEST, link-ready, close, reset and credit are uncredited control events but have strict size, rate and queue bounds. v1 limits are at most 64 KiB per encoded WebSocket message, 16 KiB per `sna_information` event and 64 KiB of unforwarded data per circuit; `RouterWelcome` supplies the active maximum message size and circuit count.

Go preserves event order within each circuit even while scheduling many circuits fairly. Rust's LLC2 adapter needs local busy/RNR before its downstream queue fills: the current lab acknowledges an I frame immediately and resets when its 32-item queue fills. Source and target must treat `CircuitClose`/`CircuitReset` as terminal. A WebSocket loss or credential revocation withdraws that router's routes and resets all circuits bound to its connection; reconnect receives a new epoch and starts new circuits. Route withdrawal prevents new opens; a lost local endpoint also resets its active circuits.

Shared Go/Rust vectors should cover welcome and epoch echo, snapshot replacement, unauthorized/stale route open, accepted and rejected opens, both-direction credit, event ordering across two circuits, oversized messages, reset, and disconnect/reconnect. The first end-to-end milestone is the existing V4R4 LLC2 pass-through across two Rust routers and the Go concentrator; standalone two-TAP behavior remains a regression test.
