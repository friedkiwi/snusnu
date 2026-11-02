# SNA over IP: Enterprise Extender and MPTN (IBM AnyNet)

This note separates two IBM protocols that both carry SNA-related traffic over IP but meet the current Rust LLC2 router at different boundaries. MPTN is the generic architecture; AnyNet is IBM's implementation. The Rust config uses `[[mptn]]` with a `relay` or `gateway` profile for IBM AnyNet peers. [IBM's glossary](https://www.ibm.com/docs/en/i/7.4.0?topic=glossary-) names AnyNet as an MPTN implementation. The direct V4R4 lab result in [llc-lab.md](llc-lab.md) is native 802.3/LLC2 APPC, not either IP protocol.

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

The existing `router-core` LLC2 endpoint delivers native I-frame information fields. `snusnu-router` can route multiple configured LLC associations, including peers on one TAP, and has completed a V4R4-to-V4R4 APPC pass-through. The separate EE UDP adapter completed a [V5R4-to-V5R4 pass-through](ee-lab.md) while preserving LDLC and HPR payloads. A configured MPTN relay also completed a [V5R4-to-V5R4 AnyNet pass-through](anynet-lab.md). The opt-in MPTN gateway reached a remote V4R4 Sign On through the [cross-NETID WebSocket lab](cross-netid-lab.md). Ordinary `--config` gateway mode remains gated by QA-specific session addressing and one-session runtime behavior.

For EE, ordinary IP connectivity suffices between genuine EE-capable APPN/HPR peers. The Rust EE relay preserves LDLC and HPR bytes between two configured IP adjacencies; it does not terminate either EE link. General interworking between EE and legacy LLC2 APPN links needs a dual-attached APPN/HPR node or equivalent protocol implementation. A constrained EE-to-native-HPR-LAN media adapter might be possible, but its XID, link activation and control-flow behavior needs paired native HPR LAN captures first; native HPR LAN can use both LLC2 and HPR UI SAPs. A terminating EE endpoint would need LDLC state, not merely UDP framing. These gateway and media-adapter boundaries are architectural inferences from [RFC 2353](https://www.rfc-editor.org/rfc/rfc2353.html), not conversions specified by it.

For AnyNet, a Rust AnyNet-to-LLC2 gateway must be a separate **LU6.2 session** component: parse and correlate TCP/UDP 397 messages, process BIND/UNBIND, rebuild/suppress TH and pacing, handle expedited traffic, segmentation, retries and keepalives. It must also hide the IP network from native APPN control flows. The public TCP62 draft explicitly describes this extra MPTN gateway duty but specifies only the access-node function, so gateway behavior requires trace-driven research. Sending MPTN TCP records directly as LLC2 information fields is invalid.

The Rust router has reusable native LLC2 associations, bounded receive pressure, a configured `[[hpr_ip]]` EE relay, and a configured `[[mptn]] profile = "relay"` for AnyNet TCP62 peers. Its `[[mptn]] profile = "gateway"` path implements native APPN management and LU6.2 conversion for the opt-in QA topology, including tested UDP `0x83` handling; a live OS/400 `0x83` exchange remains unverified. The relay carried an observed IPv4 `0x84` keepalive across both TAPs and fails closed on unsupported UDP `0x83` out-of-band traffic. Native HPR-over-LAN UI support is another separate router feature and should be trace-tested independently of EE.

## Suggested experiments

1. Extend the [direct V5R4 AnyNet capture](anynet-lab.md) through teardown and out-of-band traffic. It already showed `MPTN_Connect`, BIND, normal, expedited, and acknowledgement records on TCP/397, plus a UDP/397 keepalive with embedded peer IPs after four minutes idle. Compare these with native PIUs before adding a gateway.
2. Compare the [direct HPR LAN capture](hpr-lan-lab.md) with direct and Rust-relayed EE captures. The LAN session had XID3, SABME/UA/RR and SAP C8 UI NLPs, but no LLC2 I frames; EE used XID3 and SAP 04 UI over UDP. Test a constrained media adapter only after defining the activation and SAP mapping.
3. Demonstrate a genuine dual-attached APPN/HPR or MPTN gateway linking IP peers to the working native LLC2 circuit. Implement a custom gateway only after the corresponding captures identify the required session behavior.

The Rust runtime supports standalone local LLC2 and EE routes. AnyNet interoperation with LLC2 still needs a session gateway. WebSocket and the Go concentrator are optional remote hops, not a prerequisite for local routes.
