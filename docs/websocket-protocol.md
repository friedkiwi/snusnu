# Rust router ↔ Go concentrator WebSocket protocol

The WebSocket is an optional route hop. A Rust router can still route between local endpoints without Go. On a remote route, Go authenticates routers, distributes SNA CP/LU reachability, pairs circuits, and forwards bounded circuit events without parsing their SNA payloads. The same hub also exposes an embedded APING endpoint that does parse its own traffic. The protobuf messages are in [`snusnu_ws_v1.proto`](../proto/snusnu_ws_v1.proto) and the [route schema](../proto/snusnu_routes_v1.proto). Both Go and Rust implement the protocol; a two-V4R4 guest pass-through through Go has completed.

## Connection

1. Rust opens `wss://<concentrator>/router/v1/ws` with `Authorization: Bearer <router credential>` and requests `Sec-WebSocket-Protocol: snusnu.v1` or `snusnu.v2`. The bundled router also sends `X-Snusnu-Software-Name: sna_router` and `X-Snusnu-Software-Version` with its Cargo package version. Other clients should send their own name and version in these headers; older clients without either header remain accepted and appear as `unknown`. A partial or malformed identity is rejected. Go authenticates the token to its server-owned router UUID **before** the WebSocket upgrade and selects the offered subprotocol. `snusnu.v2` requires a source LU route reference on each open; v1 native CP opens omit it. The token is never placed in the URL, WebSocket subprotocol value, or application messages. [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) permits authentication headers and defines subprotocol selection; [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) defines bearer header use.
2. Go sends `RouterWelcome` as the first application message: router UUID, owner-selected display name, owner-assigned NETID, fresh server-generated 16-byte connection epoch and limits. For `sna_router` only, an older allowed version receives `SoftwareUpdateAvailable.latest_version` in this welcome; the router logs a warning. The concentrator's compiled latest version is kept in sync with the router Cargo manifest by a Go test. A newer version is accepted without an update notice. Server code defines a minimum and an exact-version blacklist for `sna_router`; third-party names receive no first-party update notice or version restriction. Go logs every connecting client's reported name and version, including third-party clients, and shows them on the admin router sessions page. Rust logs the assigned UUID, display name and NETID but cannot set them. The server fences any older WebSocket using that UUID and rejects advertisements outside the assigned NETID.
   If the owner renames an active router, Go sends `RouterIdentityUpdate` with the new display name; a reconnect always receives the latest name in `RouterWelcome`.
3. Rust sends a complete `RouteSnapshot` echoing the server epoch, revision 1. Go stamps the authenticated router UUID, filters each recipient's view and sends `OriginRouteSnapshot`/`OriginWithdraw`. Subsequent changes are complete atomic snapshots with increasing revisions. Go rejects an epoch mismatch or stale revision.

Managed virtual LLC addresses are a separate server-owned address book, described in [virtual-llc-mac.md](virtual-llc-mac.md). A Rust `RouteSnapshot` and `RouteExport` remain MAC-free. For a recipient that is explicitly configured as LLC-facing and authorized to reach a live CP, Go may send `ManagedCpBindingSnapshot` (schema version 1) alongside or after the server-stamped reachability view. It is a full replacement scoped to the recipient's current connection epoch with increasing revision; an empty snapshot withdraws all bindings from that view. Each binding carries the durable CP address-book UUID, qualified CP, six-byte `02:53:4E` local MAC and the currently authorized route references. LUs receive no separate MAC and use their hosting CP's link address. Go does not send bindings to IP-only recipients or to a router blocked by either owner.

The managed prefix validates a server-issued local address; it does not authenticate Go. TLS server authentication and the router bearer credential remain the trust boundary. Offline or withdrawn CP routes remove that recipient's live binding but do not retire the durable address-book record. Pausing a router or changing authorization triggers a new downstream view and circuit teardown. The concentrator reserves `02:53:4E:FF:FF:FF` for its own `SNUSNU.SVC` CP and publishes `SNUSNU.PING` as a hosted LU 6.2 service.

One `WsEnvelope` protobuf is encoded into one **binary WebSocket message**. No second length prefix, text message or per-event sequence number is used. WebSocket supplies message boundaries and connection order; Go must maintain FIFO for each circuit when forwarding between two sockets. WebSocket Ping/Pong checks connection liveness. Circuits are never resumed or replayed after a connection loss. [RFC 6455, sections 5.4–5.5](https://www.rfc-editor.org/rfc/rfc6455.html)

## Circuit lifecycle

| Step | Message | Action |
| --- | --- | --- |
| 1 | `OpenRequest(request_id, RouteReference, initial receive allowance)` | Source Rust asks Go to reach a currently advertised CP/LU route. |
| 2 | `IncomingOpen(circuit_id, source_router_id, target, source allowance)` | Go validates source permission and current target, allocates a fresh 16-byte circuit ID, and offers it to the owning Rust router or its local service endpoint. In v2, the validated source LU reference is forwarded. |
| 3 | `OpenDecision(accept/reject, target receive allowance)` | Target rechecks its route, local readiness and conversion ability. |
| 4 | `OpenResult` to source; `OpenReady` to target | Go binds exactly two authenticated connections. Each side may send circuit events after its positive confirmation. |
| 5 | `CircuitEvent`, `CircuitCredit` | Go relays to the other bound router, checks sender and credit, and maintains bounded queues. |
| 6 | `CircuitClose` or `CircuitReset` | Close ends normally after prior events; reset aborts and discards queued events. Either router or Go can reset. |

The route advertisement contains only the SNA resource identity. `OpenRequest` names the target route handle and carries no claim about the target's local encapsulation. The current circuit event profile is the native DLC/PIU representation: structured XID/TEST command or response with P/F and SAPs, a link-ready event, and the opaque SNA information field accepted from an LLC2 I frame. MAC headers, LLC2 sequence numbers, SABME/UA/RR and retransmission timers stay with each local Rust adapter. The information field is not guaranteed to be one complete PIU; converters must parse/reassemble when required. The embedded APING endpoint currently requires one complete PIU of at most 1496 bytes.

This native event profile is a **data-plane contract**, not a claim that every CP or LU uses LLC2 locally. The constrained MPTN gateway can convert an LU 6.2 session into this native profile. EE/HPR still requires its own link, RTP, and session adapter before it can use the session profile below. The owning router rejects unsupported opens. Go's relay checks message validity, route authorization, size, circuit binding, and credit without parsing SNA; the concentrator-owned APING endpoint is a distinct local consumer.

`OpenRequest.profile = CIRCUIT_PROFILE_SESSION_V1` selects a second, carrier-neutral
event profile for one LU session per circuit. It requires `snusnu.v2`, a live
authenticated source LU route, and a live target LU route. `SessionEvent`
carries complete reduced SNA units (two-byte SNF, three-byte RH, then RU) for
BIND, BIND result, information, and UNBIND; an explicit pacing-credit event
keeps carrier pacing separate from `CircuitCredit` byte-queue accounting. The
Go embedded `SNUSNU.PING` service accepts this profile and handles APINGD
without a synthetic DLC exchange on the WebSocket. Its private FID2 envelope
only adapts the established Go LU 6.2 responder's internal API; no FID2
address appears in the session event. The default profile remains the native
DLC/PIU profile used by existing LLC routes. Rust HPR/IP runtime integration
still requires a verified EE/RTP session before emitting these events.

## Pressure and failure

Each direction has an absolute cumulative `allowance_bytes` for `sna_information` payload bytes since circuit creation. The opening messages grant the initial allowance; the receiving Rust router increases it with `CircuitCredit` after it has consumed data from bounded storage. Go rejects data beyond the allowance and limits its own per-circuit and per-connection queues. XID/TEST, link-ready, close, reset and credit are uncredited control events but have strict size, rate and queue bounds. v1 limits are at most 64 KiB per encoded WebSocket message, 16 KiB per `sna_information` event and 64 KiB of unforwarded data per circuit; `RouterWelcome` supplies the active maximum message size and circuit count.

Go preserves event order within each circuit while scheduling many circuits. Rust's LLC2 adapter uses local busy/RNR for receive pressure and bounded queues. Source and target treat `CircuitClose`/`CircuitReset` as terminal. A WebSocket loss or credential revocation withdraws that router's routes and resets all circuits bound to its connection; reconnect receives a new epoch and starts new circuits. Route withdrawal prevents new opens; a lost local endpoint also resets its active circuits.

Go and Rust tests cover welcome and epoch handling, snapshot replacement, route authorization, circuit opens, credit, event ordering, size limits, reset, and reconnect. The V4R4 LLC2 pass-through through two Rust routers and Go is an end-to-end regression path; standalone two-TAP behavior remains another.
