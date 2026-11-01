# Exported route advertisements

The Rust router publishes **exported reachability** over its optional WebSocket connection. It does not publish its private route table, TAP names, local converter internals or APPN topology. An export says that this router currently offers a named SNA peer to remote routers. Local-only routes still work with no WebSocket or concentrator.

The draft wire schema is [`proto/snusnu_routes_v1.proto`](../proto/snusnu_routes_v1.proto). These protobuf messages ride inside a version-negotiated binary WebSocket control envelope; the envelope and Go/Rust generated bindings do not exist yet. The HELLO exchange must negotiate route-message support before either side accepts an advertisement. A protobuf encoding is binary but need not have a byte-for-byte canonical serialization: receivers validate the decoded fields, and shared fixtures test the same semantic values and rejection cases.

## Snapshot and identity

After authentication, the Rust publisher sends a full `RouteSnapshot` and sends a new full snapshot whenever its export set changes. `epoch` is a fresh 16-byte connection nonce and `revision` starts at 1 and increases for each snapshot in that epoch. The receiver applies a valid snapshot atomically, replacing that origin's previous set; an empty set withdraws all entries. Snapshots remove the need for delta ordering in version 1. The concentrator accepts only increasing revisions for its current authenticated connection and discards the whole epoch on disconnect or replacement.

The concentrator adds the **authenticated origin ID** in `OriginRouteSnapshot`, filters exports for each recipient's permissions, and relays the resulting snapshot. A publisher cannot name another origin. `OriginWithdraw` clears one exact `(origin, epoch)` when that connection disappears or policy revokes it. A late withdrawal for an old epoch cannot clear a replacement connection. Version 1 permits one active WebSocket connection per origin ID; multiple Rust routers at one site need distinct origin IDs.

Each export has a nonzero opaque `id`, stable while it denotes the same configured target, and a nonzero `generation` that increments when that ID is retargeted. A remote circuit `OPEN` references `(origin, epoch, id, generation)` through `RouteReference`. The origin rechecks current readiness and permission when it receives `OPEN`; a published route is not an unconditional promise of capacity. The remote routing table is keyed by origin and route ID. Duplicate matching peer names, whether within one origin or across origins, require an explicit preference or cause an ambiguous-route error.

Only **locally originated** exports may be published in version 1. A route learned from WebSocket is never re-exported. The concentrator does not reflect an origin's routes to itself. This gives the hub topology a clear loop rule; transitive advertisement would need a separate path-vector design.

## Peer identity and local mappings

`peer_id` is a stable operator-assigned name for the reachable peer or service, scoped by `origin`. It can be a familiar qualified SNA name such as `SOLNET.SNAB` or a configured alias. If different LUs need independent route choices, export separate peer IDs. The advertisement does not say whether the origin reaches that peer by LLC, AnyNet, Enterprise Extender or another encapsulation.

Each Rust router privately maps its local ingress addresses to peer IDs: an LLC destination MAC/SAP, an AnyNet LU name/IP, or an EE link identity. For example, a native LLC initiator may send XID to a MAC before its remote CP name is known; its local router needs a configured MAC/SAP-to-peer mapping to select the exported route. The origin maps the peer ID to its local endpoint and converter. Go treats peer IDs as opaque policy keys and does not inspect the local encapsulation.

Route discovery is independent of encapsulation, but the data plane still needs a common logical circuit contract and working conversion at each end. LLC2 PIUs, MPTN session records and HPR NLPs cannot be forwarded as interchangeable byte strings. A route can be advertised only while its origin is prepared to serve the configured peer; an unsupported circuit open must fail cleanly. Full LLC↔AnyNet↔EE interworking requires the respective MPTN and APPN/HPR gateway work described in [router-runtime.md](router-runtime.md).

## Validation and limits

The first implementation should enforce a 64 KiB maximum encoded snapshot size, at most 256 entries and 512 encoded bytes per entry, unique nonzero IDs, 16-byte epochs, and nonzero monotonic revisions and generations. A peer ID is 1–64 ASCII characters from `A–Z`, `0–9`, `.`, `_`, `-`, `@`, `$` and `#`; normalize configured IDs to uppercase. It must reject malformed, duplicate or oversized entries before installing any part of a snapshot. Limit protobuf parse allocation as well as post-decode values. Frame-level limits and unknown-field policy belong to the common control envelope.

The Go directory table currently represents planning data. Live advertisements have separate connection-scoped state and must be intersected with authorization before relay. Go needs only origin and peer identity for validation/filtering; it does not parse SNA PIUs or perform protocol conversion. Circuit forwarding uses `RouteReference` and checks the referenced origin and generation again at the destination.

Shared Go/Rust fixtures should cover a peer export, empty replacement, revision regression, stale epoch withdrawal, duplicate ID, malformed peer ID, duplicate name ambiguity and an `OPEN` after retargeting. No WebSocket implementation is needed to test snapshot validation and route selection locally.
