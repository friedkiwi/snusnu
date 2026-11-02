# Architecture

The Rust router handles local SNA links and can run without the concentrator. A Go concentrator is an optional authenticated hop between routers and also hosts `SNUSNU.SVC` and `SNUSNU.PING`. See [router runtime](router-runtime.md), [route advertisements](route-advertisements.md), and [SNA over IP](sna-over-ip.md) for the implemented boundaries.

| Component | Responsibility and current scope |
| --- | --- |
| Rust router | Owns local LLC2, configured HPR/IP and MPTN attachments, route selection, circuit/session state, queues, and WebSocket client transport. It can relay local LLC2, HPR/IP, or MPTN peers; protocol conversion is explicit and limited to the configured gateway profile. |
| Go concentrator | Authenticates routers, distributes live CP/LU exports and managed MAC bindings, applies owner policy, and relays bounded circuits. Its embedded Go SNA stack terminates only the concentrator-owned APING service. |
| Genuine SNA/APPN nodes | Own APPN topology, directory services, class-of-service decisions, and their application sessions. Snusnu's CP/LU directory is reachability for its own routes, not an APPN network-node directory. |

LLC2 sequencing, retransmission, and SABME/UA/RR terminate at each Rust LLC adapter. The WebSocket circuit carries Type 1, link-ready, and SNA information events; it does not flood LAN frames. Go treats PIUs as opaque in the relay. Concentrator-owned LUs register with a local service registry under `SNUSNU.SVC`; each service declares its advertised LU types, source eligibility and handler. The registry dispatches by destination route and preserves the server-stamped source router, account owner, NETID, CP and LU. For `SNUSNU.PING`, the handler parses XID3, FID2, LU 6.2, and APING records through the reusable [Go SNA module](../sna/README.md). Other services can use their own SNA packages and transports without coupling print or other application logic to the router.

AnyNet MPTN records and HPR NLPs are not interchangeable with LLC2 information fields. Configured MPTN relay and HPR/IP relay preserve their own formats. The constrained `mptn_lu62` gateway converts one LU 6.2 session between LLC2 and AnyNet; general mixed-media routing still has the gates described in [router runtime](router-runtime.md) and [HPR gateway](hpr-gateway.md).

## Identity, pressure, and failure

The concentrator assigns each router a UUID, allowed NETID, and fresh connection epoch. It validates route names and route generations, filters each recipient's view, and checks live references again on circuit open. `SNUSNU` is reserved for the concentrator's service CP and LU. Its virtual CP MAC is `02:53:4E:FF:FF:FF`; user CP allocations exclude that address.

Per-direction cumulative byte credit and bounded queues limit circuit data. A lost WebSocket, revoked credential, withdrawn route, or failed local endpoint closes affected circuits. A reconnect gets a new epoch; live circuits are not replayed. TLS authenticates a remote concentrator in production, and the router bearer credential authenticates the router to Go. See [WebSocket protocol](websocket-protocol.md) and [virtual MACs](virtual-llc-mac.md).

## Verified paths and open work

- Local V4R4 LLC2 pass-through, a two-router WebSocket pass-through, V5R4 HPR/IP relay, and V5R4 AnyNet relay completed live guest tests.
- The embedded `SNUSNU.PING` LU exchanged APING version and echo records with a live V4R4 guest and reached wire-level CONFIRM, BIS, and UNBIND. The final guest command status was not captured.
- A standalone LLC2-to-AnyNet gateway reached remote Sign On, and the cross-NETID gateway reached Sign On in both initiation directions. General native address selection, concurrent sessions, clean teardown, and live UDP `0x83` handling remain open.
- HPR/IP to native HPR LAN and HPR/IP to legacy LLC2 APPC are not operational routes. Paired activation and APPN/HPR behavior remain open.

These are interoperability observations for the documented guests, not general SNA conformance claims. Dated captures and exact conditions are in the [LLC](llc-lab.md), [EE](ee-lab.md), [AnyNet](anynet-lab.md), [cross-NETID](cross-netid-lab.md), and [APING](test-vectors/aping-v4r4.md) records.
