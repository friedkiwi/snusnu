# Snusnu WebSocket circuit protocol

`snusnu.v1` and `snusnu.v2` are snusnu-specific binary WebSocket subprotocols between Rust routers and the Go concentrator. They are not IBM SNA wire formats or RFC 1795 DLSw SSP. The implemented message flow, limits, and failure behavior are in [WebSocket protocol](websocket-protocol.md); the protobuf schemas are in [`proto/`](../proto/). Rust routers can also route locally without WebSocket.

## Implemented invariants

- A bearer-authenticated router receives a server-owned UUID, allowed NETID, limits, and fresh 16-byte connection epoch in `RouterWelcome` before it publishes routes or opens circuits.
- A route snapshot replaces that router's earlier exports atomically. Each live route reference includes router UUID, epoch, route ID, and generation. The concentrator filters views by policy and rejects stale references.
- `snusnu.v1` permits CP-scoped native circuits without a source route. `snusnu.v2` requires a live source LU reference and validates both source and target LU routes. The embedded `SNUSNU.PING` service accepts only an authorized LU 6.2 source.
- One protobuf `WsEnvelope` occupies one binary WebSocket message. A circuit carries Type 1 XID/TEST, link-ready, and bounded SNA information events, plus open, credit, close, and reset control messages. There is no per-event sequence number; WebSocket order and per-circuit FIFO preserve event order.
- Per-direction cumulative byte credit gates SNA information. The server caps messages at 64 KiB, information events at 16 KiB, queued unforwarded data at 64 KiB per circuit, and active circuits at 64 per router connection. Oversized, malformed, stale, or state-invalid messages fail closed.
- Connection loss or credential revocation withdraws that router's routes and resets its circuits. A reconnect receives a new epoch; live circuits are not replayed.
- Go relays remote PIUs without interpreting them. Its concentrator-owned APING service is an explicit local endpoint and terminates XID3, FID2, LU 6.2, and APING through the reusable Go [`sna`](../sna/README.md) module.

## Scope and evidence

The native DLC/PIU event profile has carried a V4R4 guest-to-guest pass-through through two Rust routers and Go. The Go APING endpoint reached version, echo, and wire-level close with a live V4R4 guest; the guest's final command result was not captured. The constrained MPTN gateway has reached remote Sign On in standalone and cross-NETID configurations but is not a general AnyNet/LLC converter. HPR NLPs and MPTN records are not interchangeable with native PIUs; mixed-media routes need explicit converters. See [runtime status](router-runtime.md), [cross-NETID lab](cross-netid-lab.md), and [APING vectors](test-vectors/aping-v4r4.md).
