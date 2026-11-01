# `snusnu.v1` binary protocol — draft

This is a proposed snusnu-specific WSS circuit protocol, not an IBM-defined wire format or RFC 1795 DLSw SSP. No byte layout or interoperability claim is frozen yet. IBM SNA and APPN behavior remains at the endpoints; this protocol concerns the switched DLC circuit between routers.

## Goals and proposed invariants

- Explicit versioning and capability negotiation precede circuit traffic. Unsupported versions and required capabilities fail closed.
- Messages are binary and independently implementable in Go and Rust. Integer widths, byte order, field order, optional fields, and canonical encoding still need specification.
- Every message and payload has a strict documented maximum; parsing rejects oversized or inconsistent lengths before allocation.
- Every circuit has an identifier scoped to its connection generation. Every relevant message carries a generation and sequence number; stale generations, replayed or out-of-order messages cannot mutate a replacement circuit.
- The lifecycle covers open, accepted open, data, close, and reset. XID and TEST carriage is explicit and state validated; carriage does not make the concentrator an LLC2 endpoint.
- Per-circuit credit updates gate sending. Bounded queues and fair scheduling prevent one circuit from exhausting memory or starving another.
- Unknown, malformed, oversized, or state-invalid input is rejected. The precise error versus connection-close policy remains to be specified.
- Go and Rust must agree on canonical encoding, successful decoding, rejection, and applicable state transitions using the same language-neutral fixtures.

All identifiers, credits, generation semantics, sequence rules, message types, and limits above are **proposed snusnu features**, not IBM requirements. The initial header layout, numeric limits, negotiation order, sequence wrap policy, reset semantics, XID/TEST payload representation, and credit recovery after reconnect are unresolved research/design questions. No protocol vectors exist until those decisions are recorded.
