# V5R4 EE to embedded APING acceptance lab

The acceptance result is a guest-reported success for
`VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(16) NBRITER(1)` from an OS/400
instance attached to `sna_router` by Enterprise Extender. A matching trace
must show EE link activation, control and user RTP, BIND, APINGD Attach,
version, echo, and orderly deallocation through the Rust router and Go
concentrator. The existing two-guest [EE relay lab](ee-lab.md) does not meet
this criterion.

## Isolated guest and host state

The writable V5R4 B clone at `/tmp/snusnu-v5r4-ip-lab/b` is already running
on TAP `sol7`, with guest IP `10.99.4.3`, CP `SOLNET.SNAB`, and a TN5250
station at `127.0.0.1:9562`. Its `EETOA` controller is currently **varied
off**. It uses `LINKTYPE(*HPRIP)`, local IP `10.99.4.3`, remote CP
`SOLNET.SNAA`, and remote IP `10.99.4.11`. Its `QAPPNRMT` currently contains
only `SNAA` under `QAALICE`, a remnant of the cross-NETID lab. Confirm these
values with `DSPNETA`, `DSPCTLD CTLD(EETOA)`, `WRKCFGSTS CFGTYPE(*CTL)
CFGD(EETOA)`, and `DSPCFGL CFGL(QAPPNRMT)` before changing the guest.

Host address `10.99.4.11` and its source-based route currently belong to
`sol9`, another live clone. For this guest, the host has `10.99.4.10/32` on
`sol7` and a main-table host route to `10.99.4.3` through `sol7`. Use
`10.99.4.10` as the router's local EE address; do not reassign `.11` or
change table 109. Verify with `ip route get 10.99.4.3 from 10.99.4.10`.

The guest is an APPN `*ENDNODE`. [IBM permits an end node to use a network
node server in a different NETID](https://www.ibm.com/docs/en/zos-basic-skills?topic=types-end-nodes-en). This lab will make the router present the
concentrator-owned `SNUSNU.SVC` identity as a network node server on the EE
link, so `SNUSNU.PING` is local to that server's NETID. This must wait until
the Rust APPN CP-CP service and its XID3 network-node claim are truthful.
The source guest remains `SOLNET.SNAB`; a separate QA concentrator with Alice
assigned `SOLNET` is used for its authenticated route export. An isolated
instance can be started on `127.0.0.1:8083` with the QA binary's
`-alice-netid SOLNET` option, leaving the existing `:8081` instance alone.
The router must not publish `SNUSNU.SVC` as an Alice-owned route: it presents
that server-owned CP only on the local EE adjacency and exports the guest's
`SOLNET.SNAB` source LU upstream.

When the endpoint is ready, change only the varied-off `EETOA` controller,
the end node's preferred server, and the PING remote location:

```text
CHGCTLAPPC CTLD(EETOA) RMTINTNETA('10.99.4.10') RMTNETID(SNUSNU) RMTCPNAME(SVC)
CHGNETA NETSERVER((SNUSNU SVC))
ADDCFGLE TYPE(*APPNRMT) APPNRMTE((PING SNUSNU SNAB SVC SNUSNU *NONE *NO))
```

The `CHGCTLAPPC`, `CHGNETA`, and `ADDCFGLE` V5R4 prompts were checked
without executing them. The existing `SNAA`/`QAALICE` configuration-list
entry can remain during this test; it does not match the `PING` target.
If the PING entry already exists, inspect `DSPCFGL CFGL(QAPPNRMT)` before
adding another. The earlier V4R4 APING lab used the same PING entry shape.

Check the resulting `DSPCFGL CFGL(QAPPNRMT)` display before varying `EETOA`
on. The authenticated router must export the guest's source LU as LU 6.2 and
see the concentrator's live `SNUSNU.SVC` and `SNUSNU.PING` routes. The Go
responder currently expects its native circuit profile; EE acceptance also
requires the agreed carrier-neutral session profile or a complete virtual
native adapter. The end-node-to-network-node design avoids the separate
network-node border function; the live trace must still prove that V5R4
selects the server and locates PING.

To return the guest to the recorded pre-test values, vary `EETOA` off, then
run:

```text
RMVCFGLE TYPE(*APPNRMT) APPNRMTE((PING SNUSNU SNAB))
CHGNETA NETSERVER((*LCLNETID *ANY))
CHGCTLAPPC CTLD(EETOA) RMTINTNETA('10.99.4.11') RMTNETID(SOLNET) RMTCPNAME(SNAA)
```

Do not vary `EETOA` on after restoring it while `.11` belongs to the other
isolated TAP lab. `RMVCFGLE` needs only the remote location, NETID, and local
location key, as verified in the guest prompt.

## Capture and result

Start an unfiltered TAP capture immediately before the trial:

```sh
scripts/capture-ee-aping.sh sol7 /tmp/snusnu-ee-aping 180
```

The script records one timestamped pcap and stops after three minutes. Run
the OS/400 command from the 5250 command line while the capture is active:

```text
VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(16) NBRITER(1)
```

Keep the pcap outside Git because it may contain guest credentials or
application data. Record the guest's final command status and correlate the
same connection in Rust and concentrator logs. A trace that only reaches
APING echo, or an EE relay between two OS/400 guests, is not a pass.

After this single-packet run passes, repeat with
`VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(4) NBRPKT(2) NBRITER(1)
ECHO(*NO)` and then repeat after disconnect/reconnect. Keep the existing
LLC, MPTN, and EE relay tests as regression gates.
