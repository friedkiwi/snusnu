# Local LLC2 and SNA lab

The Rust router's `--lab-link` mode joins two isolated Linux TAP interfaces. It relays LLC TEST and XID frames, terminates LLC2 separately on each interface, and forwards accepted SNA information fields in order. The OS/400 guests own XID3, APPC sessions, and APPN names. This mode is a fixed two-peer test path for local interoperability.

## V4R4 Solstice setup

The first interoperability run used two writable clones of `solstice-templates/v4r4-advanced36`, each booted with `solstice boot DIR --ipl A --keyswitch N --no-panel`. Keep the template disk untouched. Attach guest A to `sol5` and guest B to `sol4`; leave both TAPs out of any host bridge. The TAPs must be up and owned by the user running Solstice. Give the clones distinct console ports and MAC addresses:

| Guest | TAP | MAC | Network / control point | IP |
| --- | --- | --- | --- | --- |
| A | `sol5` | `02:00:35:27:23:01` | `SOLNET.SNAA` | `10.99.0.2` |
| B | `sol4` | `02:00:35:27:23:02` | `SOLNET.SNAB` | `10.99.0.3` |

The template has Ethernet line `ETHLIN`. On each guest, vary controller `QILANM3601` off before changing the network attributes. The relevant OS/400 commands are:

```text
VRYCFG CFGOBJ(QILANM3601) CFGTYPE(*CTL) STATUS(*OFF)
CHGNETA LCLNETID(SOLNET) LCLCPNAME(SNAA) LCLLOCNAME(SNAA)  [A]
CHGNETA LCLNETID(SOLNET) LCLCPNAME(SNAB) LCLLOCNAME(SNAB)  [B]
CRTCTLAPPC CTLD(SNAB) LINKTYPE(*LAN) SWTLINLST(ETHLIN) RMTNETID(SOLNET) RMTCPNAME(SNAB) ADPTADR(020035272302)  [A]
CRTCTLAPPC CTLD(SNAA) LINKTYPE(*LAN) SWTLINLST(ETHLIN) RMTNETID(SOLNET) RMTCPNAME(SNAA) ADPTADR(020035272301) INLCNN(*ANS)  [B]
VRYCFG CFGOBJ(SNAA) CFGTYPE(*CTL) STATUS(*ON)  [B]
VRYCFG CFGOBJ(SNAB) CFGTYPE(*CTL) STATUS(*ON)  [A]
STRPASTHR RMTLOCNAME(SNAB)  [A]
```

Use the `CHGNETA` line marked for each guest, not both. Change B's cloned TCP/IP interface address if TCP/IP is enabled; duplicate addresses are unrelated to APPC but interfere with ordinary IP tests.

Build and start the Rust relay before varying A's controller on:

```sh
cd sna_router
cargo build --workspace
sudo target/debug/snusnu-router --lab-link sol5 sol4 02:00:35:27:23:01 02:00:35:27:23:02
```

The packet sockets require `CAP_NET_RAW`. `--lab-link` accepts only the two specified source/destination MACs and SNA SAP `0x04`. It has bounded queues and a one-frame LLC2 send window. It waits briefly after one leg connects before initiating SABME on the other leg so an OS/400 guest can finish its outstanding XID3 exchange.

## Observed result

On 2026-11-01, V4R4M0 guests on Solstice 0.4.1 reached B's remote Sign On from A through the Rust relay. Signing on to B's virtual display and issuing `ENDPASTHR` returned A to its Main Menu normally. Both TAP captures show XID3, SABME/UA, I frames, and RR acknowledgements; Solstice's trace shows SNA PIUs and BIND. The router logged both LLC2 legs connected and SNA information fields delivered in both directions. The earlier direct-bridge baseline reached the same remote Sign On.

The initial relay attempt failed when B received SABME before completing its final XID exchange. A short connection barrier resolved that lab timing race. This is an observed interoperability result for these two guests, not a general LLC2 conformance claim.

The raw captures and emulator disks stay outside this repository because SNA application data can appear in them. The TEST/XID bytes used by the parser's regression tests are in `sna_router/crates/router-core/tests/v4r4_llc.rs`.
