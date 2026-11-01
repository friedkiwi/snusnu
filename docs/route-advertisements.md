# Exported route advertisements

The Rust router publishes **exported reachability** over its optional WebSocket connection. It does not publish its private route table, TAP names, local converter internals or APPN topology. An export says that this router is currently prepared to accept a particular typed circuit/session open for a destination. Local-only routes still work with no WebSocket or concentrator.

The draft wire schema is [`proto/snusnu_routes_v1.proto`](../proto/snusnu_routes_v1.proto). These protobuf messages ride inside a version-negotiated binary WebSocket control envelope; the envelope and Go/Rust generated bindings do not exist yet. The HELLO exchange must negotiate route-message support and handoff types before either side accepts an advertisement. A protobuf encoding is binary but need not have a byte-for-byte canonical serialization: receivers validate the decoded fields, and shared fixtures test the same semantic values and rejection cases.

## Snapshot and identity

After authentication, the Rust publisher sends a full `RouteSnapshot` and sends a new full snapshot whenever its export set changes. `epoch` is a fresh 16-byte connection nonce and `revision` starts at 1 and increases for each snapshot in that epoch. The receiver applies a valid snapshot atomically, replacing that origin's previous set; an empty set withdraws all entries. Snapshots remove the need for delta ordering in version 1. The concentrator accepts only increasing revisions for its current authenticated connection and discards the whole epoch on disconnect or replacement.

The concentrator adds the **authenticated origin ID** in `OriginRouteSnapshot`, filters exports for each recipient's permissions, and relays the resulting snapshot. A publisher cannot name another origin. `OriginWithdraw` clears one exact `(origin, epoch)` when that connection disappears or policy revokes it. A late withdrawal for an old epoch cannot clear a replacement connection. Version 1 permits one active WebSocket connection per origin ID; multiple Rust routers at one site need distinct origin IDs.

Each export has a nonzero opaque `id`, stable while it denotes the same configured target, and a nonzero `generation` that increments when that ID is retargeted. A remote circuit `OPEN` references `(origin, epoch, id, generation, handoff)` through `RouteReference`. The origin rechecks current readiness and permission when it receives `OPEN`; a published route is not an unconditional promise of capacity. The remote routing table is keyed by origin and route ID, not by MAC or LU name alone. Duplicate matching destinations, whether within one origin or across origins, require an explicit preference or cause an ambiguous-route error.

Only **locally originated** exports may be published in version 1. A route learned from WebSocket is never re-exported. The concentrator does not reflect an origin's routes to itself. This gives the hub topology a clear loop rule; transitive advertisement would need a separate path-vector design.

## Selector and handoff

`destination` answers *what is reachable*; `handoff` answers *which event contract the origin accepts*. These are separate because a gateway may expose an LU6.2 destination while accepting native LLC2 circuit events from a remote router. An `LlcDestination` contains the six-byte destination MAC and destination SAP. A `Lu62Destination` contains a network-qualified LU and the exact mode names accepted by this configured service. It asserts configured gateway reachability, not APPN discovery. An AnyNet route is exported only after the origin has a working converter for the advertised handoff and mode.

Version 1 defines native LLC2 and LU6.2 session handoffs. HPR/Enterprise Extender gets new selector and handoff values after its link semantics are implemented and captured. Unknown destination types, unsupported handoffs and invalid selector/handoff combinations are ignored as unusable exports; an `OPEN` for one is rejected. The local router's route configuration must make each export and its accepted handoff explicit.

## Validation and limits

The first implementation should enforce a 64 KiB maximum encoded snapshot size, at most 256 entries and 512 encoded bytes per entry, unique nonzero IDs, 16-byte epochs, nonzero monotonic revisions and generations, six-byte unicast MACs, and even SAPs from 2 through 254. SNA names and modes must follow their name rules and fit within eight bytes; an LU6.2 entry may list at most 32 distinct modes and must list at least one. It must reject malformed, duplicate or oversized entries before installing any part of a snapshot. Limit protobuf parse allocation as well as post-decode values. Frame-level limits and unknown-field policy belong to the common control envelope.

The Go directory table currently represents planning data. Live advertisements have separate connection-scoped state and must be intersected with authorization before relay. Go need only understand selectors and handoff metadata for validation/filtering; it does not parse SNA PIUs or perform protocol conversion. Circuit forwarding uses `RouteReference` and checks the referenced origin and generation again at the destination.

Shared Go/Rust fixtures should cover one LLC export, one LU6.2 export, empty replacement, revision regression, stale epoch withdrawal, duplicate ID, malformed MAC/SAP, unsupported handoff, duplicate destination ambiguity and an `OPEN` after retargeting. No WebSocket implementation is needed to test snapshot validation and route selection locally.
