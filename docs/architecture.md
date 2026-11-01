# Architecture

This is an implementer-facing foundation, based primarily on the read-only research note `syspass_research/docs/sources/hobbyist-sna-internet-network.md`. Its AnyNet investigation is background for a separate future gateway; AnyNet is outside this milestone.

## Boundaries

| Component | Responsibility |
| --- | --- |
| Local Rust router | Future Ethernet 802.3/802.2 packet I/O, local TEST/XID and LLC2 endpoint, MAC/SAP policy, DLC next-hop selection, and outbound WSS connections. |
| Central Go concentrator | Future authenticated site connections, authorized MAC/SAP reachability matching, independent circuit multiplexing, admission policy, resource limits, fairness, and operational HTTP facilities. |
| Genuine SNA/APPN nodes | SNA sessions and PIUs; APPN topology, directory services, class-of-service route selection, and LU resource routing. |

**IBM-defined boundary.** IBM's APPN network nodes exchange topology information and use directory and topology services to locate resources and select session routes. The router's proposed MAC/SAP lookup is DLC reachability only; it cannot substitute for those APPN functions. See IBM, *APPN network topology*, *How directory services locate resources in APPN*, and *Route selection in an APPN network* (references below).

**snusnu design choice.** Multiple sites initiate outbound connections to one central concentrator. A future binary circuit protocol over WSS carries circuit events, XID/TEST exchanges and information payloads. LLC2 sequencing, retries and link control terminate at the local router. The concentrator matches authorized DLC endpoints and forwards circuit messages; it does not inspect PIUs to route LUs. This is a stateful switched circuit service, not a stretched Ethernet broadcast domain: it does not flood arbitrary LAN frames across sites.

The Rust `router-core` will own link/circuit state and route decisions. `link-linux` will isolate Linux packet capture/injection behind a safe interface; `transport-ws` will isolate the outbound concentrator connection. The initial host targets are Linux amd64 and arm64. No packet I/O or WSS implementation exists yet.

## Resource and failure rules (proposed snusnu behavior)

Every circuit needs a bounded queue, explicit credit accounting, and a scheduler that gives independent circuits fair service. Exhausted credit or a full queue applies backpressure rather than allowing unlimited buffering. A connection generation changes on reconnect; messages from earlier generations must be rejected so an old close, reset, or data message cannot affect a replacement connection. Route changes or lost connections reset affected circuits rather than silently moving a live LLC2 association.

WSS server authentication and site authentication will protect the transport. Authorization must be checked independently for MAC/SAP claims and circuit opens. Payload and circuit limits, strict parsing, and redacted diagnostics form further boundaries. Authentication, authorization and WSS are design requirements, not current features.

## Stages

1. Specify the byte format and state rules, then share encode/decode/rejection vectors between Go and Rust.
2. Implement trace-tested local LLC2 handling and a minimal authenticated WSS circuit path with bounded flow control.
3. Add authorized DLC reachability, fault/reconnect tests, and operational facilities; test with genuine APPN nodes.

## References and status

- IBM, [*APPN network topology*](https://www.ibm.com/docs/en/zos-basic-skills?topic=appn-network-topology), sections “How directory services locate resources in APPN” and “Route calculation in APPN”.
- IBM, [*Route selection in an APPN network*](https://www.ibm.com/docs/en/csfdcd/7.1?topic=services-route-selection-in-appn-network), Communications Server documentation.
- IBM, [*SNA Network Implementation Guide*](https://www.ibm.com/docs/en/SSLTBW_2.3.0/pdf/istimp0_v2r3.pdf), z/OS Communications Server.

**Assumption needing IBM source review:** the detailed LLC2 TEST/XID exchange, timers, and PIU TH/RH/RU treatment have not yet been specified here. They require documentary and trace review before implementation. The libgeist MCP server described for this task was not exposed in this session, so no claim here is represented as verified through libgeist.
