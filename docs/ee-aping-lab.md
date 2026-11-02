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
station at `127.0.0.1:9562`; the system console is at `127.0.0.1:9561`.
The recorded pre-test `EETOA` controller used `LINKTYPE(*HPRIP)`, local IP
`10.99.4.3`, remote CP `SOLNET.SNAA`, and remote IP `10.99.4.11`, and was
varied off. Its `QAPPNRMT` contained `SNAA` under `QAALICE`, a remnant of
the cross-NETID lab. The live acceptance trial changed the controller to
remote CP `SNUSNU.SVC` at `10.99.4.10`, set `NETSERVER` to `SNUSNU.SVC`,
added `SNUSNU.PING`, and varied `EETOA` on. Confirm the current values with
`DSPNETA`, `DSPCTLD CTLD(EETOA)`, `WRKCFGSTS CFGTYPE(*CTL) CFGD(EETOA)`,
and `DSPCFGL CFGL(QAPPNRMT)` before changing the guest again.

Host address `10.99.4.11` and its source-based route currently belong to
`sol9`, another live clone. For this guest, the host has `10.99.4.10/32` on
`sol7` and a main-table host route to `10.99.4.3` through `sol7`. Use
`10.99.4.10` as the router's local EE address; do not reassign `.11` or
change table 109. Verify with `ip route get 10.99.4.3 from 10.99.4.10`.

The guest is an APPN `*ENDNODE`. [IBM permits an end node to use a network
node server in a different NETID](https://www.ibm.com/docs/en/zos-basic-skills?topic=types-end-nodes-en). This lab will make the router present the
concentrator-owned `SNUSNU.SVC` identity as a network node server on the EE
link, so `SNUSNU.PING` is local to that server's NETID. The live trace must
prove that the Rust APPN CP-CP service honors its XID3 network-node claim.
The source guest remains `SOLNET.SNAB`; a separate QA concentrator with Alice
assigned `SOLNET` is used for its authenticated route export. An isolated
instance can be started on `127.0.0.1:8083` with the QA binary's
`-alice-netid SOLNET` option, leaving the existing `:8081` instance alone.
The router must not publish `SNUSNU.SVC` as an Alice-owned route: it presents
that server-owned CP only on the local EE adjacency and exports the guest's
`SOLNET.SNAB` source LU upstream.

For a fresh guest clone, change only the varied-off `EETOA` controller, the
end node's preferred server, and the PING remote location:

```text
CHGCTLAPPC CTLD(EETOA) RMTINTNETA('10.99.4.10') RMTNETID(SNUSNU) RMTCPNAME(SVC)
CHGNETA NETSERVER((SNUSNU SVC))
ADDCFGLE TYPE(*APPNRMT) APPNRMTE((PING SNUSNU SNAB SVC SNUSNU *NONE *NO))
```

The `CHGCTLAPPC`, `CHGNETA`, and `ADDCFGLE` commands succeeded on the live
V5R4 guest. The existing `SNAA`/`QAALICE` configuration-list
entry can remain during this test; it does not match the `PING` target.
If the PING entry already exists, inspect `DSPCFGL CFGL(QAPPNRMT)` before
adding another. The earlier V4R4 APING lab used the same PING entry shape.

Check the resulting `DSPCFGL CFGL(QAPPNRMT)` display before varying `EETOA`
on. The authenticated router must export the guest's source LU as LU 6.2 and
see the concentrator's live `SNUSNU.SVC` and `SNUSNU.PING` routes. The
end-node-to-network-node design avoids the separate network-node border
function; the live trace must still prove that V5R4 selects the server and
locates PING.

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
scripts/capture-ee-aping.sh sol7 /tmp/snusnu-ee-aping 600
```

The script records one timestamped pcap and stops after ten minutes. Run
the OS/400 command from the 5250 command line while the capture is active:

```text
VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(16) NBRITER(1)
```

After restarting the Rust router, force a fresh EE XID exchange by varying
the guest controller off and on before running `VFYAPPCCNN` again:

```text
VRYCFG CFGOBJ(EETOA) CFGTYPE(*CTL) STATUS(*OFF) FRCVRYOFF(*YES)
VRYCFG CFGOBJ(EETOA) CFGTYPE(*CTL) STATUS(*ON)
```

If the vary-off command waits for `QSYSOPR`, attach to the separate system
console at `127.0.0.1:9561` and run `DSPMSG MSGQ(QSYSOPR)`. On the live V5R4
guest, inquiry **CPA2611** said “Controller EETOA cannot be varied off at
this time. (C G)” because network jobs still used it. Select option 5 for
the message and reply `G` to vary it off with active jobs. The alternative
reply `C` cancels the vary-off. The forced vary-off form above was verified
on V5R4 and completed without that inquiry. If `WRKCFGSTS` still displays
`VARY OFF PENDING` after completion, press F5 to refresh it and confirm
`VARIED OFF` before varying the controller on. A prior verification job can
hold the controller; F3 cancels that job. The console also had an
unrelated IBM service inquiry; leave that one alone.

### Successful live result, 2026-11-02

At 18:40:55 UTC, the V5R4 guest completed the command above over EE to the
Rust router (`a239d92`) and isolated Go QA concentrator (`4c8b393`). The
router served the adjacent CP as `SNUSNU.SVC`, established both CPSVCMG
sessions, answered RouteSetup for `SNUSNU.PING`, and forwarded the guest's
APINGD session to the embedded responder. The packet trace includes the
APING version exchange, a 20-byte echo, and positive CONFIRM; the QA log
shows no circuit reset. The guest's `DSP02` job log, viewed through
`WRKACTJOB` → option 5 → option 10 → F10, reports:

```text
VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(16) NBRITER(1)
Allocate took .109 seconds.
Remote system type is OS/400.
Initial exchange took .095 seconds.
Iteration 1 took .030 seconds.
Round-trip (in milliseconds) min/avg/max = 30/30/30
```

The station job returned to `MNU-MAIN`/`DSPW`, confirming the command
finished. The full TAP capture is
`/tmp/snusnu-ee-aping/sol7-20261102T183623Z.pcap`; the Rust debug log is
`/tmp/snusnu-ee-aping/router-v12.log`, and the isolated QA log is
`/tmp/snusnu-ee-aping/qa-8083-v14.log`. These files are lab artifacts and
are not committed. The original QA service on `0.0.0.0:8081` was left
untouched. The isolated QA service listens on `127.0.0.1:8083`; the Rust EE
attachment uses `10.99.4.10` with guest `10.99.4.3`.

Keep the pcap outside Git because it may contain guest credentials or
application data. Record the guest's final command status and correlate the
same connection in Rust and concentrator logs. A trace that only reaches
APING echo, or an EE relay between two OS/400 guests, is not a pass.

After this single-packet run passes, repeat with
`VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(4) NBRPKT(2) NBRITER(1)
ECHO(*NO)` and then repeat after disconnect/reconnect. Keep the existing
LLC, MPTN, and EE relay tests as regression gates.
