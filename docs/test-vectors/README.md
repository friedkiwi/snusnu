# Shared protocol evidence

## Captured vectors

- [V4R4 APING application records](aping-v4r4.md) contain decoded version, echo, and no-echo records from the guest lab. The Go APING package and concentrator circuit tests use those shapes.

The versioned WebSocket schema is in [`proto/`](../../proto/). Go and Rust protocol tests live beside their implementations; this directory records safe, trace-backed cross-language evidence. Private raw captures and application data stay outside the repository.
