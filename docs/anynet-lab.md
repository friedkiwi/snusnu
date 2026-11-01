# AnyNet Solstice baseline

Two V5R4 OS/400 guests completed a direct AnyNet pass-through on 2026-11-01. A's `STRPASTHR RMTLOCNAME(SNAB)` reached B's remote Sign On and Main Menu; `ENDPASTHR` returned to A. This is a direct peer baseline for the Rust TCP62 codec and gateway work, not an LLC2↔AnyNet router result.

The guests were writable clones of `solstice/machine-v5r4-net`, booted with the custom Solstice build at commit `8f89217`. They had distinct Ethernet MACs and IP addresses: A `SOLNET.SNAA` / `10.99.4.2` on `sol6`, B `SOLNET.SNAB` / `10.99.4.3` on `sol7`. Only these two TAPs were connected by an isolated `br-ip-sna` bridge. See the [EE lab](ee-lab.md) for the clone identity and IP setup; HPRIP controllers were varied off for this AnyNet run.

Both guests had `CHGNETA ALWANYNET(*YES)` and their matching `LCLNETID`, `LCLCPNAME`, and `LCLLOCNAME` values. The host table mapped the remote SNA location alias to its IP address:

```text
ADDTCPHTE INTNETADR('10.99.4.3') HOSTNAME(SNAB.SOLNET.SNA.IBM.COM)  [A]
CHGTCPHTE INTNETADR('10.99.4.2') HOSTNAME((*SAME) (SNAA.SOLNET.SNA.IBM.COM))  [B; existing .2 entry]
```

Each guest had a matching APPN remote configuration list entry, such as A's `CRTCFGL TYPE(*APPNRMT) APPNRMTE((SNAB SOLNET *NETATR SNAB SOLNET))`. Create and vary on the AnyNet APPC controllers:

```text
CRTCTLAPPC CTLD(ANYTOB) LINKTYPE(*ANYNW) RMTNETID(SOLNET) RMTCPNAME(SNAB)  [A]
CRTCTLAPPC CTLD(ANYTOA) LINKTYPE(*ANYNW) RMTNETID(SOLNET) RMTCPNAME(SNAA)  [B]
```

The unfiltered `sol6` capture showed a TCP connection from A to B port 397, a 230-byte `MPTN_Connect` request, a 189-byte positive response, normal records, expedited records, and an expedited acknowledgement. The Connect request carried BIND and the response carried RSP(BIND). A short session and the first two minutes of a separate idle session showed no UDP/397 datagrams; that observation does not establish that UDP keepalives are unnecessary. Solstice emits IP in 802.3 SNAP frames, so a conventional `tcpdump udp` or `tcpdump tcp` capture filter on the TAP missed traffic; capture without a filter and inspect offline. Raw captures and application payloads stay outside this repository.

The Rust [TCP62 codec](../sna_router/crates/transport-ip-sna/src/mptn_connect.rs) now accepts both observed Connect headers. Its BIND-to-FID2 converter is limited to complete normal PIUs after session establishment. The full LLC2↔AnyNet gateway still needs APPN control handling, BIND/session correlation, pacing, expedited traffic, segmentation, UDP keepalive, and teardown behavior.
