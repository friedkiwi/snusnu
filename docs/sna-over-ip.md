# SNA over IP: Enterprise Extender and AnyNet

This note separates two IBM protocols that both carry SNA-related traffic over IP but meet the current Rust LLC2 router at different boundaries. The direct Solstice V4R4 result in [llc-lab.md](llc-lab.md) is native 802.3/LLC2 APPC, not either IP protocol.

## Wire formats

| | Enterprise Extender (EE) | AnyNet / TCP62 (APPC over TCP/IP) |
| --- | --- | --- |
| Purpose | Native APPN/HPR link over IP | MPTN conversion of LU6.2 sessions to IP |
| Transport | UDP destination 12000–12004 | TCP and UDP port 397 |
| Link establishment | LDLC XID3/TEST on UDP 12000 | TCP `MPTN_Connect` (`0x80`) with BIND RU |
| Data | Three-byte LLC UI header, then HPR network layer packet (NLP); 12001–12004 represent network, high, medium, and low priority | TCP record: four-byte big-endian total length, compensation byte, reduced TH, RH and RU |
| Other traffic | UDP 12000 also carries DISC/DM and function-routed NLPs | UDP `0x83` out-of-band expedited/UNBIND traffic and `0x84` node-pair keepalive; acknowledgement/retry rules apply |
| Recovery | HPR/RTP handles ordering, recovery and rate control; LDLC has no LLC2 I/RR/SABME data link | TCP carries normal data, with MPTN session, pacing, expedited, segmentation and keepalive rules above it |

The EE UDP payload begins with DSAP, SSAP and LLC control. Control traffic uses XID/TEST/DISC/DM; data uses UI (`0x03`) and HPR NLP. The HPR SAP is negotiated in XID3, so a parser must not assume the lab's SAP `0x04`. EE's LLC-looking header does **not** mean its data can be passed to `Llc2::send_information` as an I-frame payload. See [RFC 2353, sections 2.1–2.3, 2.6.1 and appendix 6](https://www.rfc-editor.org/rfc/rfc2353.html). IBM's [System i EE configuration](https://www.ibm.com/support/pages/configuring-ee-enterprise-extender-between-two-ibm-system-i-systems) uses `LINKTYPE(*HPRIP)` and UDP 12000–12004; its example is for V5R4 and later.

AnyNet's TCP connection is one LU6.2 session, not an LLC2 link. Its `MPTN_Connect` includes source and destination information, a correlator and the BIND RU. Normal records retain only part of the SNA transmission header; the receiving MPTN node reconstructs the rest and handles pacing. UDP/397 is part of the protocol, not an optional discovery channel. The detailed public wire description is the IBM-authored, **expired Internet-Draft** [LU6.2 over TCP/IP](https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00), sections 3 and 5; live OS/400 captures must settle any version-specific behavior. IBM's [OS/400 AnyNet setup](https://www.ibm.com/support/pages/setting-ibm-anynet-os400-system) uses `ALWANYNET(*YES)` and `LINKTYPE(*ANYNW)` with LU-name-to-IP resolution. IBM also documents [embedded IP addresses in AnyNet keepalives and lack of NAT support](https://www.ibm.com/support/pages/ibm-anynet-not-supported-over-networks-using-nat).

## Where they meet this codebase

The existing `router-core` LLC2 endpoint delivers opaque native I-frame information fields. `snusnu-router/src/lab.rs` joins two fixed TAP peers, relays TEST/XID and terminates LLC2 independently on each leg. That has been enough for a V4R4-to-V4R4 APPC pass-through. It does not parse APPN topology, BIND, HPR NLP or MPTN records.

For EE, ordinary IP connectivity suffices between genuine EE-capable APPN/HPR peers. General interworking between EE and legacy LLC2 APPN links needs a dual-attached APPN/HPR node or equivalent protocol implementation. A constrained EE-to-native-HPR-LAN media adapter might be possible, but its XID, link activation and control-flow behavior needs paired captures first; native HPR LAN can use both LLC2 and HPR UI SAPs. A Rust EE endpoint would need LDLC state, not merely UDP framing. These gateway and media-adapter boundaries are architectural inferences from [RFC 2353](https://www.rfc-editor.org/rfc/rfc2353.html), not conversions specified by it.

For AnyNet, a Rust AnyNet-to-LLC2 gateway must be a separate **LU6.2 session** component: parse and correlate TCP/UDP 397 messages, process BIND/UNBIND, rebuild/suppress TH and pacing, handle expedited traffic, segmentation, retries and keepalives. It must also hide the IP network from native APPN control flows. The public TCP62 draft explicitly describes this extra MPTN gateway duty but specifies only the access-node function, so gateway behavior requires trace-driven research. Sending MPTN TCP records directly as LLC2 information fields is invalid.

The first useful refactor for either path is a reusable native DLC circuit interface: MAC/SAP identity, TEST/XID exchange, connect/reset events, PIU delivery and bounded backpressure. Keep EE's HPR/LDLC adapter and AnyNet's LU6.2/MPTN gateway separate from that native circuit interface. The current fixed lab hardcodes SAP `0x04`, drops UI and acknowledges received I-frames promptly; a session gateway needs configurable SAPs and explicit receive pressure before its queue fills. Native HPR-over-LAN UI support is another separate router feature and should be trace-tested independently of EE.

## Suggested experiments

1. Preserve the working V4R4 LLC2 baseline and extract its fixed lab link into a reusable, trace-tested native DLC circuit.
2. Capture an actual AnyNet session between suitable OS/400 guests on TCP/UDP 397. Compare `MPTN_Connect`, BIND, data, expedited traffic, UNBIND and keepalive against the draft before implementing a decoder or gateway. The local V5R4 research has binary evidence but no complete live MPTN session trace yet.
3. Capture EE between genuinely EE-capable peers on UDP 12000–12004. Verify XID3 negotiation and UI NLPs. IBM's System i example starts at V5R4; the current V4R4 lab is not an established EE test peer. The V5R4 Solstice network template uses a frozen custom emulator build, so that guest setup needs separate validation.
4. Demonstrate a genuine dual-attached APPN/HPR or MPTN gateway linking IP peers to the working native LLC2 circuit. Implement a custom gateway only after the corresponding captures identify the required session behavior.

The Rust runtime must support standalone local routes. Native LLC2 circuit reliability and observability are the first implementation step; AnyNet interoperation then needs a session gateway. WebSocket and the Go concentrator are optional remote hops, not a prerequisite for any local route.
