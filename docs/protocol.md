# `snusnu.v1` binary protocol — draft

This is a proposed snusnu-specific circuit protocol for an optional WebSocket hop between Rust routers, not an IBM-defined wire format or RFC 1795 DLSw SSP. The concrete v1 message flow and draft wire schema are in [websocket-protocol.md](websocket-protocol.md). The Rust router must also run with only local routes. Route discovery names SNA CPs/LUs without exposing their local encapsulation. A common logical circuit contract and local protocol converters are still needed for data traffic; LLC2 PIUs, HPR NLPs and MPTN records cannot be treated as one raw byte stream. See [router-runtime.md](router-runtime.md) and [route advertisements](route-advertisements.md).

## Goals and proposed invariants

- The `snusnu.v1` WebSocket subprotocol and server Welcome precede circuit traffic. Unsupported versions fail closed; later event profiles will need explicit negotiation.
- Messages are binary and independently implementable in Go and Rust. Route advertisements and circuit messages use the draft protobuf schemas in `proto/`. Receivers validate decoded values rather than requiring identical protobuf byte serialization.
- Every message and payload has a strict documented maximum; parsing rejects oversized or inconsistent lengths before allocation.
- Every circuit has a server-issued identifier bound to two authenticated connection epochs. Stale epochs and route generations cannot mutate replacement circuits. V1 resets circuits on reconnect and relies on WebSocket order plus per-circuit FIFO at Go, without a data-event sequence number.
- The lifecycle covers open, accepted open, data, close, and reset. XID and TEST carriage is explicit and state validated; carriage does not make the concentrator an LLC2 endpoint.
- Per-direction cumulative byte credit gates circuit information data. Bounded queues and fair scheduling prevent one circuit from exhausting memory or starving another.
- Unknown, malformed, oversized, or state-invalid input is rejected. The precise error versus connection-close policy remains to be specified.
- Go and Rust must agree on decoded meaning, rejection, and applicable state transitions using the same language-neutral fixtures.

All identifiers, credits, epochs, message types, and limits above are **proposed snusnu features**, not IBM requirements. The v1 message flow and XID/TEST representation are recorded in the linked draft; detailed Go/Rust validation rules and shared protocol vectors still need implementation.
