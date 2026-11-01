# Native HPR LAN Solstice baseline

On 2026-11-01, two V5R4 OS/400 guests completed `STRPASTHR`, remote sign-on, and `ENDPASTHR` over native HPR LAN. This establishes a direct peer baseline for evaluating an HPR-LAN↔Enterprise Extender media adapter. It is not a Rust router interoperability result.

The guests were the writable V5R4 clones described in the [EE lab](ee-lab.md): A `SOLNET.SNAA` on `sol6` with Ethernet adapter address `0204AC054504`, B `SOLNET.SNAB` on `sol7` with distinct address `0204AC054505`. Only `sol6` and `sol7` were connected to the isolated `br-sna-v5-hpr` bridge. Their AnyNet and HPRIP controllers were varied off. Both had APPN/HPR enabled.

Each guest had a LAN APPC controller pointing to the other guest's adapter address. The lab used `HLTOB` on A and `HLTOA` on B with `LINKTYPE(*LAN)`, `SWTLINLST(ETHLIN)`, `APPN(*YES)`, `HPR(*YES)`, `RMTNETID(SOLNET)`, and the matching remote CP name. B used `INLCNN(*ANS)` and A used `INLCNN(*DIAL)`. Both controllers were varied on before A issued `STRPASTHR RMTLOCNAME(SNAB)`.

The unfiltered `sol6` capture through normal `ENDPASTHR` contained 73 LLC UI frames on SAP `0xC8`, 20 SAP `0x04` supervisory RR frames, 11 SAP `0x04` XID frames, one SABME and one UA. It contained **no SAP `0x04` LLC2 I frames** during link activation, remote sign-on, B Main Menu, or teardown. XID3 CV61 explicitly advertised HPR SAP `0xC8`; the direct EE capture advertised SAP `0x04`. Raw captures stay outside this repository because SNA application data can appear in them.

The [HPR LAN codec](../sna_router/crates/router-core/src/hpr_lan.rs) handles UI NLP framing and priority classification. The [EE relay](ee-lab.md) operates over UDP 12000–12004. A live LAN↔EE adapter still needs correct XID3 SAP negotiation and a mapping for LAN LLC2 SABME/UA/RR versus EE LDLC/XID_DONE activation. The absence of LLC2 I frames in this run makes a constrained media relay worth testing; it does not establish that arbitrary APPN traffic needs no base-link control.
