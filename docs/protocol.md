# `snusnu.v1` binary protocol — draft

This is a proposed snusnu-specific circuit protocol for an optional WebSocket hop between Rust routers, not an IBM-defined wire format or RFC 1795 DLSw SSP. No circuit-data byte layout or interoperability claim is frozen yet. The Rust router must also run with only local routes. Route discovery names peers without exposing their local encapsulation. A common logical circuit contract and local protocol converters are still needed for data traffic; LLC2 PIUs, HPR NLPs and MPTN records cannot be treated as one raw byte stream. See [router-runtime.md](router-runtime.md) and the draft [route advertisement schema](route-advertisements.md).

## Goals and proposed invariants

- Explicit versioning and capability negotiation precede circuit traffic. Unsupported versions and required capabilities fail closed.
- Messages are binary and independently implementable in Go and Rust. Route advertisements use the draft protobuf schema in `proto/snusnu_routes_v1.proto`; circuit-data fields and the common envelope still need specification. Receivers validate decoded values rather than requiring identical protobuf byte serialization.
- Every message and payload has a strict documented maximum; parsing rejects oversized or inconsistent lengths before allocation.
- Every circuit has an identifier scoped to its connection generation. Every relevant message carries a generation and sequence number; stale generations, replayed or out-of-order messages cannot mutate a replacement circuit.
- The lifecycle covers open, accepted open, data, close, and reset. XID and TEST carriage is explicit and state validated; carriage does not make the concentrator an LLC2 endpoint.
- Per-circuit credit updates gate sending. Bounded queues and fair scheduling prevent one circuit from exhausting memory or starving another.
- Unknown, malformed, oversized, or state-invalid input is rejected. The precise error versus connection-close policy remains to be specified.
- Go and Rust must agree on decoded meaning, rejection, and applicable state transitions using the same language-neutral fixtures.

All identifiers, credits, generation semantics, sequence rules, message types, and limits above are **proposed snusnu features**, not IBM requirements. The circuit header layout, negotiation order, sequence wrap policy, reset semantics, XID/TEST payload representation, and credit recovery after reconnect are unresolved design questions. Route advertisement limits and semantics are specified separately; no shared protocol vectors exist yet.
