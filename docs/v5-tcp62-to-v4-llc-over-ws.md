# V5R4 TCP62 to V4R4 LLC2 across WebSocket

Target path: a V5R4 OS/400 guest initiates TCP62/AnyNet to Rust router A; A connects through the Go concentrator to Rust router B; B reaches a V4R4 OS/400 guest over LLC2. A and B belong to different users with different server-assigned NETIDs. This path is **not operational yet**. The current inbound TCP62 code admits a narrow Connect profile but does not complete the reverse MPTN/native gateway or attach it to WebSocket routing.

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

The difficult part is A's virtual APPN CP/link and management-session behavior. The V4R4 guest must see a plausible peer CP in A's NETID, including XID3/link setup and whatever SNASVCMG/CNOS/BIS control exchange it initiates or expects. The existing isolated native and TCP62 lab state machines do not yet prove this composition. Native TH address assignment, BIND response correlation, pacing, positive FM response and UNBIND must be driven by actual V4R4/V5R4 traces before claiming success.

## Proposed open-time source identity

The current `OpenRequest` identifies only a target `RouteReference`; `IncomingOpen` has a server-stamped source router UUID but no source CP/LU route. Rust can now select a target LU route using `[[remote]] target_lu = "DSTNET.LUB"` with `target_cp = "DSTNET.CPB"`. To authorize a cross-user LU6.2 gateway open, add these **proposed, unimplemented** protobuf fields:

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

A publishes its actual source LU and CP under its own NETID, then supplies the LU export's current route reference. A's TCP62 adapter checks that this LU matches the inbound Connect. Go derives A's router identity from its authenticated WebSocket and verifies `source_route` belongs to A's current epoch/snapshot and names an LU under A's NETID. It verifies the target reference is a live LU export on B, applies the existing owner block/pause policy, and forwards the checked source reference to B. B checks it against its configured source LU and the opened target LU before accepting. Source and target NETIDs are intentionally different; each export is restricted to its **own** user's assigned NETID. `source_router_id` alone is insufficient to identify the initiating LU.

These fields are protobuf-additive, but an older Go server would silently ignore `source_route`. The gateway must therefore require an explicitly negotiated `snusnu.v2` subprotocol (or equivalent acknowledged feature) before relying on source-LU authorization. Existing v1 CP-only native circuits keep their current open behavior. No new `CircuitEvent` variant is needed for this specific virtual-DLC design; a future semantic LU6.2 circuit profile would be a separate versioned contract.

## Remaining implementation gates

1. Implement A's reverse TCP62-to-native gateway and virtual DLC/CP endpoint. It must hold the TCP62 Connect response until the native BIND outcome and preserve backpressure through both directions.
2. Allow an inbound AnyNet session to select a WebSocket route in Rust A. The current configured remote port requires a local LLC peer, and `WsRoutePort` rejects raw AnyNet records. The new route must emit native `Type1`, `LinkReady` and `sna_information` from the converter, not raw records.
3. Add the source-route fields and v2 negotiation in Rust, Go and shared vectors. Go checks both live references and relays only the existing native circuit events. B validates the expected source identity at `IncomingOpen`.
4. Configure B's LLC-facing proxy identity for A's CP. The present managed binding gate expects an enabled server-managed CP MAC and a live A CP export before B accepts an incoming circuit; retain that requirement or replace it with an explicitly specified virtual-CP address policy.
5. Test the direction and lifecycle in order: V5 inbound Connect admission; cross-NETID LU route/open; virtual XID3; V4 management and user BIND; first FMH-5 and positive response; pacing/credit; UNBIND; failure/reconnect. Keep the direct two-V4R4 WebSocket path as a regression.

The gateway and source-route checks above are snusnu design proposals. IBM's [TCP62 draft](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00) describes MPTN access-node framing but explicitly leaves MPTN gateway control-flow conversion beyond its scope. See [the current WebSocket contract](websocket-protocol.md) and [route advertisement schema](route-advertisements.md) for implemented v1 behavior.
