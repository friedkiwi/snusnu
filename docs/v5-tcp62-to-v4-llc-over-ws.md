# V5R4 TCP62 to V4R4 LLC2 across WebSocket

Target path: a V5R4 OS/400 guest initiates TCP62/AnyNet to Rust router A; A connects through the Go concentrator to Rust router B; B reaches a V4R4 OS/400 guest over LLC2. A and B belong to different users with different server-assigned NETIDs. The opt-in QA gateway reached the V4R4 remote Sign On through this path twice. Ordinary `--config` gateway use remains gated by QA-specific native addressing and one-session runtime behavior; see [the live lab record](cross-netid-lab.md). The design discussion below records how the gateway was built and which protocol boundaries remain relevant.

## Use the existing native circuit event profile

The smallest data-plane design is for A to terminate TCP62 and present a **virtual native DLC/APPN peer** over the WebSocket circuit. B keeps its existing native LLC2 adapter. The existing v1 `CircuitEvent` variants suffice only if A implements that virtual peer and converts the session into correct native SNA information fields:

| Traffic | Across the WebSocket | Local responsibility |
| --- | --- | --- |
| Link activation | `Type1` XID/TEST and `LinkReady` | A generates/answers a valid XID3/CP identity and APPN link behavior; B owns Ethernet, SABME/UA/RR, MAC/SAP and LLC2 retries. |
| BIND and BIND response | Native SNA PIU bytes in `sna_information` | A maps TCP62 `MPTN_Connect` BIND data to a native session and waits for the V4R4 BIND result before sending TCP62 Connect response. |
| CNOS/BIS, FMH-5, positive FM responses | Native PIU bytes in `sna_information` | A converts TCP62 normal/expedited records and tracks LU6.2 brackets, responses and session identifiers; B forwards native PIUs to/from V4R4. |
| Native pacing | Native IPR/IPM PIUs may cross as `sna_information` | A translates between native pacing and TCP62's suppressed pacing; LLC2 acknowledgment and WebSocket byte credit remain separate. Neither Go nor B's generic LLC2 relay interprets pacing. |
| Termination | Native UNBIND/response PIUs, then `CircuitClose`; `CircuitReset` on failure | A owns TCP close, TCP62 out-of-band/UDP 397 retry and keepalive. Semantic expedited/UNBIND effects must be converted before a native session closes. |

The `sna_information` payload is an LLC2 information field, so it may contain only part of a PIU. Any converter that needs complete BIND, FM or UNBIND units must reassemble and segment as needed. Go forwards the existing binary events in circuit order and accounts `sna_information` bytes against current credit. It has no TCP62, XID or PIU parser. Putting raw TCP62 records directly in `sna_information` would violate the native circuit contract.

The difficult part was A's virtual APPN CP/link and management-session behavior. The V4R4 guest saw a peer CP in A's NETID through XID3/link setup and SNASVCMG/CNOS/BIS exchange. Captured V4R4/V5R4 traces drove native TH address assignment, BIND response correlation and pacing through the first remote display. Full sign-on, normal teardown and a live UDP X'83' exchange remain unverified.

## Open-time source identity

The v2 `OpenRequest` includes both target and source `RouteReference` values. Go verifies that the source LU belongs to the authenticated router's current route snapshot and the target LU is live; `IncomingOpen` carries the validated source reference. For a local LLC route, Rust currently selects a destination with `[[concentrator]] target_lu = "DSTNET.LUB"` and `target_cp = "DSTNET.CPB"`. A TCP62 gateway derives that selection from its local `[[mptn]] profile = "gateway"` definition, which accepts an IBM AnyNet/400 peer. The additive fields are:

```protobuf
message OpenRequest {
  // Existing fields 1..3 remain unchanged.
  RouteReference source_route = 4;
}
message IncomingOpen {
  // Existing fields 1..4 remain unchanged.
  RouteReference source_route = 5; // Validated and relayed by Go.
}
```

A publishes its source LU and CP under its own NETID, then supplies the LU export's current route reference. A's TCP62 adapter checks that this LU matches the inbound Connect. Go derives A's router identity from its authenticated WebSocket and verifies `source_route` belongs to A's current epoch/snapshot and names an LU under A's NETID. It verifies the target reference is a live LU export on B, applies owner policy, and forwards the checked source reference to B. B checks the opened target and expected source before accepting. Source and target NETIDs are intentionally different; each export is restricted to its own user's assigned NETID.

The gateway requires the negotiated `snusnu.v2` subprotocol for source-LU authorization. Existing v1 CP-only native circuits retain their open behavior. The virtual DLC uses the existing `CircuitEvent` payloads; a future semantic LU6.2 circuit profile would need a separate versioned contract.

## Implementation record and remaining gates

The opt-in gateway now converts V5 inbound Connect to a native virtual DLC/CP endpoint, holds the TCP62 positive until native BIND acceptance, and preserves backpressure through the WebSocket circuit. The concentrator checks live source and target LU route references under v2. B's LLC-facing proxy uses the concentrator-managed CP MAC. The QA run covered Connect, cross-NETID open, XID3, V4 management and user BIND, FMH-5, pacing and the first remote display. Remaining live checks include full sign-on, normal teardown, failure/reconnect and UDP X'83' handling. The ordinary configured gateway still needs generic native session address assignment and a multi-session runtime.

IBM's [TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00) describes MPTN access-node framing but leaves MPTN gateway control-flow conversion beyond its scope. See [the WebSocket contract](websocket-protocol.md) and [route advertisement schema](route-advertisements.md) for the circuit protocol.
