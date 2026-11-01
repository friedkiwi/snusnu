# Architecture

This is an implementer-facing foundation, based primarily on the read-only research note `syspass_research/docs/sources/hobbyist-sna-internet-network.md`. The Rust process is intended to route between local SNA links without a concentrator. A WebSocket link to another Rust router is an optional route hop. The concrete decomposition and compatibility rules are in [router-runtime.md](router-runtime.md); [sna-over-ip.md](sna-over-ip.md) covers Enterprise Extender and AnyNet.

## Boundaries

| Component | Responsibility |
| --- | --- |
| Local Rust router | Owns endpoint adapters, protocol conversion, route selection, circuit/session lifecycle, bounded queues and local forwarding. The present code implements only a fixed two-TAP LLC2 lab route. |
| Optional Go concentrator | Connects remote Rust routers and applies site-level policy when a route uses a WebSocket hop. It is not needed for local routes or LLC-to-AnyNet conversion. |
| Genuine SNA/APPN nodes | SNA sessions and PIUs; APPN topology, directory services, class-of-service route selection, and LU resource routing. |

**IBM-defined boundary.** IBM's APPN network nodes exchange topology information and use directory and topology services to locate resources and select session routes. The router's proposed MAC/SAP lookup is DLC reachability only; it cannot substitute for those APPN functions. See IBM, *APPN network topology*, *How directory services locate resources in APPN*, and *Route selection in an APPN network* (references below).

**snusnu design choice.** The Rust router starts with local endpoint and route definitions. LLC2 sequencing, retries and link control terminate there. Route compatibility is checked before traffic flows: native LLC2 circuits can exchange Type 1 and PIU events, while AnyNet requires an LU6.2/MPTN gateway and Enterprise Extender requires an HPR/LDLC adapter or an APPN/HPR node, depending on the route. WebSocket can carry typed circuit events to a remote Rust router but does not change the local routing model. The router does not flood arbitrary LAN frames across sites.

The Rust `router-core` owns the initial LLC parser and LLC2 state machine. The fixed lab endpoint is currently in `snusnu-router`; `link-linux` isolates Linux packet capture/injection behind a safe interface; `transport-ws` is only a placeholder. The initial host targets are Linux amd64 and arm64. The local two-TAP lab path has packet I/O and LLC2 termination; there is no general route runtime, AnyNet/EE adapter or WSS implementation yet.

## Resource and failure rules (proposed snusnu behavior)

Every circuit needs a bounded queue, explicit credit accounting, and a scheduler that gives independent circuits fair service. Exhausted credit or a full queue applies backpressure rather than allowing unlimited buffering. A connection generation changes on reconnect; messages from earlier generations must be rejected so an old close, reset, or data message cannot affect a replacement connection. Route changes or lost connections reset affected circuits rather than silently moving a live LLC2 association.

WSS server authentication and concentrator-owned [router identity](router-identity.md) will protect remote transport. Authorization must be checked independently for CP/LU reachability claims and circuit opens. Payload and circuit limits, strict parsing, and redacted diagnostics form further boundaries. Authentication, authorization and WSS are design requirements, not current features.

## Stages

1. Build local 802.3/802.2 capture and replay, then collect TEST, XID and LLC2 traces from genuine SNA equipment. Keep SNA information fields opaque while validating DLC behavior.
2. Implement trace-tested LLC Type 1 handling and the local LLC2 endpoint, including timers, sequencing and bounded buffering. Test against scripted peers and captured traffic.
3. Extract the lab's LLC2 legs into reusable local endpoints and route them through a standalone Rust runtime. Validate missing/ambiguous routes, queue pressure and teardown; rerun the V4R4 interoperability test.
4. Capture and implement AnyNet/TCP62 as a separate LU6.2 gateway, beginning with one configured native LLC2-to-AnyNet session. Capture Enterprise Extender and native HPR LAN links before attempting HPR media conversion.
5. Specify the cross-language circuit protocol and shared vectors, then add the optional authenticated WebSocket path, remote reachability, fault/reconnect tests and operational facilities.

## References and status

- IBM, [*APPN network topology*](https://www.ibm.com/docs/en/zos-basic-skills?topic=appn-network-topology), sections “How directory services locate resources in APPN” and “Route calculation in APPN”.
- IBM, [*Route selection in an APPN network*](https://www.ibm.com/docs/en/csfdcd/7.1?topic=services-route-selection-in-appn-network), Communications Server documentation.
- IBM, [*SNA Network Implementation Guide*](https://www.ibm.com/docs/en/SSLTBW_2.3.0/pdf/istimp0_v2r3.pdf), z/OS Communications Server.

**Assumption needing IBM source review:** the detailed LLC2 TEST/XID exchange, timers, and PIU TH/RH/RU treatment have not yet been specified here. They require documentary and trace review before implementation. The libgeist MCP server described for this task was not exposed in this session, so no claim here is represented as verified through libgeist.
