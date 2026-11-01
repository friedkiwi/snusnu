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

The lab deliberately gives each guest's control point and default local location the same name. `SOLNET.SNAB` is therefore both B's network-qualified CP and its default LU/location here; these are distinct OS/400 settings. See [OS/400 SNA names](os400-sna-names.md).

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

## Standalone and remote router modes

After extracting the reusable LLC endpoint, the same two V4R4 guests
completed `STRPASTHR`, remote sign-on, and `ENDPASTHR` again through both
`--lab-link` and the standalone route mode:

```sh
sudo target/debug/snusnu-router --local-link \
  sol5 02:00:35:27:23:01 02:00:35:27:23:02 \
  sol4 02:00:35:27:23:02 02:00:35:27:23:01
```

`--local-link` configures each LLC endpoint independently. The endpoints
exchange XID/TEST and SNA information through the router's `RoutePort`
interface. It operates without a concentrator.

The same guests also completed the session through the declarative
[`--config` router](router-config.md) on 2026-11-01. A's `STRPASTHR
RMTLOCNAME(SNAB)` reached B's remote Sign On at 17:02:56 local time;
QSECOFR sign-on reached B's Main Menu at 17:03:05, and `ENDPASTHR`
returned A to its Main Menu at 17:03:12. The router logged both LLC2
associations connected and bidirectional MAC routes. This regression used
the existing two isolated TAPs; same-interface multi-peer filtering has
a separate synthetic AF_PACKET test.

For one LLC endpoint routed through a concentrator, use a router credential
in the environment rather than on the command line:

```sh
export SNUSNU_ROUTER_TOKEN='the-router-credential'
sudo --preserve-env=SNUSNU_ROUTER_TOKEN target/debug/snusnu-router --remote-link \
  sol5 02:00:35:27:23:01 02:00:35:27:23:02 \
  SOLNET.SNAA SOLNET.SNAB wss://concentrator.example/router/v1/ws
```

A second router uses B's TAP and reversed CP/MAC values.

The Rust WebSocket path was also verified with two separate router processes
and the loopback lab broker, using these same configured V4R4 guests. Start
the broker with:

```sh
cargo run -p transport-ws --example lab_broker -- 127.0.0.1:18743
```

Its test credentials are `lab-a` and `lab-b`. Each router then uses
`ws://127.0.0.1:18743/router/v1/ws` and its respective credential.
This broker runs only on loopback and is a test harness for the circuit
protocol; it does not provide concentrator authentication or policy.

In that run, A's `STRPASTHR` reached B's remote Sign On through the two Rust
routers, remote QSECOFR sign-on reached B's Main Menu, and `ENDPASTHR`
returned A to its Main Menu. The broker observed an accepted circuit,
bidirectional XID/TEST, link-ready events, SNA information, and credit. The
first attempt after reboot sent no Ethernet frames until both OS/400 APPC
controllers were varied on again. A complete session then succeeded.

After the WebSocket adapter was changed to share one authenticated socket
between multiple logical circuits, the same legacy `--remote-link` scenario
was rerun through the loopback broker on 2026-11-01. A reached B's remote
Sign On at 17:04:55 local time, signed in to B's Main Menu at 17:05:18,
and returned to A's Main Menu with `ENDPASTHR` at 17:05:21. The broker
observed the accepted circuit, bidirectional XID/TEST, link-ready events,
and SNA information. The broker and router processes were stopped after
the test; the two V4R4 guests remained running.

## Go QA concentrator interoperability

On 2026-11-01, two separate `--remote-link` Rust routers attached to the
same V4R4 guests through the Go QA concentrator's real `/router/v1/ws`
handler. The QA process listened on its default `:8081` address and used
the seeded Alice and Bob router credentials described in
[QA.md](../concentrator/QA.md). Each router published its local CP and
received the other's managed CP binding and live route reference.

A issued `STRPASTHR RMTLOCNAME(SNAB)` at 16:32:07 local time, reached B's
remote Sign On at 16:32:22, signed in to B's Main Menu at 16:32:49, and
issued `ENDPASTHR` at 16:32:52. A returned to its Main Menu immediately.
The QA database retained both live CP advertisements and 178 symmetric
traffic records at the inspection point: 68 Type 1, 100 SNA information,
and 10 link-ready records. The pass-through completed before a likely teardown race:
Go logged `unknown or pending circuit` after forwarding A's close, then
closed B's WebSocket. B reconnected with a fresh epoch and republished its
route. The session result was unaffected. Go should tolerate messages that
were already in flight from an authenticated circuit participant when the
other participant closed the circuit.
The APPC controllers had to be varied on after guest IPL before initiating
the pass-through session.
