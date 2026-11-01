# Native HPR LAN baseline

On 2026-11-01, two V5R4 OS/400 guests completed `STRPASTHR`, remote sign-on, and `ENDPASTHR` over native HPR LAN. This establishes a direct peer baseline for evaluating an HPR-LAN↔Enterprise Extender media adapter. It is not a Rust router interoperability result.

The guests were the writable V5R4 clones described in the [EE lab](ee-lab.md): A `SOLNET.SNAA` on `sol6` with Ethernet adapter address `0204AC054504`, B `SOLNET.SNAB` on `sol7` with distinct address `0204AC054505`. Only `sol6` and `sol7` were connected to the isolated `br-sna-v5-hpr` bridge. Their AnyNet and HPRIP controllers were varied off. Both had APPN/HPR enabled.

Each guest had a LAN APPC controller pointing to the other guest's adapter address. The lab used `HLTOB` on A and `HLTOA` on B with `LINKTYPE(*LAN)`, `SWTLINLST(ETHLIN)`, `APPN(*YES)`, `HPR(*YES)`, `RMTNETID(SOLNET)`, and the matching remote CP name. B used `INLCNN(*ANS)` and A used `INLCNN(*DIAL)`. Both controllers were varied on before A issued `STRPASTHR RMTLOCNAME(SNAB)`.

The unfiltered `sol6` capture through normal `ENDPASTHR` contained 73 LLC UI frames on SAP `0xC8`, 20 SAP `0x04` supervisory RR frames, 11 SAP `0x04` XID frames, one SABME and one UA. It contained **no SAP `0x04` LLC2 I frames** during link activation, remote sign-on, B Main Menu, or teardown. XID3 CV61 explicitly advertised HPR SAP `0xC8`; the direct EE capture advertised SAP `0x04`. Raw captures stay outside this repository because SNA application data can appear in them.

The [HPR LAN codec](../sna_router/crates/router-core/src/hpr_lan.rs) handles UI NLP framing and priority classification. The [EE relay](ee-lab.md) operates over UDP 12000–12004. A live LAN↔EE adapter still needs correct XID3 SAP negotiation and a mapping for LAN LLC2 SABME/UA/RR versus EE LDLC/XID_DONE activation. The absence of LLC2 I frames in this run makes a constrained media relay worth testing; it does not establish that arbitrary APPN traffic needs no base-link control.

## Mixed-media XID diagnostic

A diagnostic-only Rust harness later connected A's LAN controller to B's HPRIP controller on separate TAPs. It forwarded only validated SAP `0x04` XID/TEST/DISC/DM traffic, including the empty XID bootstrap probes, and deliberately blocked SETMODE and UI data. Both full XID3 directions reached the opposite guest: B's EE XID3 crossed UDP 12000 to A's LAN, and A's LAN XID3 crossed to B's EE UDP 12000. B then sent DISC twice within 2–4 ms of A's final XID3. Its OS/400 log reported unsuccessful controller contact and a probable configuration problem, without a more specific rejection sense in the capture.

This diagnostic does **not** establish mixed-media activation. The immediate DISC may reflect incompatible CV61 link capabilities or the absence of the SETMODE translation deliberately blocked by the harness. The LAN and EE captures differ in CV61 error-recovery/LDLC capability profiles, enhanced XID completion flags, BTU, and the presence of a TG Identifier vector. Rust preserves those capability bytes and does not expose `[[hpr_lan]]` as a live route until it can validate per-leg TG negotiation and activate both DLCs correctly. Raw captures remain private outside the repository.
