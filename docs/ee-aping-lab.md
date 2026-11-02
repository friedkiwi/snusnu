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

Once the Rust EE endpoint can truthfully negotiate its APPN/HPR capabilities,
point `EETOA` at `10.99.4.10` while it remains varied off. It should identify
the router's local CP as `SOLNET.SNAA` for the first same-NETID adjacency.
Restore the `SNAA` remote configuration list entry to `SOLNET` and add a
`SNUSNU.PING` remote location hosted by `SNUSNU.SVC`. V5R4's
`ADDCFGLE TYPE(*APPNRMT)` prompt accepts remote location, remote NETID,
local location, remote CP, and CP NETID as separate fields. The earlier V4R4
APING lab used this entry shape:

```text
ADDCFGLE TYPE(*APPNRMT) APPNRMTE((PING SNUSNU SNAB SVC SNUSNU *NONE *NO))
```

Check the resulting `DSPCFGL CFGL(QAPPNRMT)` display before varying `EETOA`
on. The authenticated router must export the guest's source LU as LU 6.2 and
see the concentrator's live `SNUSNU.SVC` and `SNUSNU.PING` routes. The Go
responder currently expects its native circuit profile; EE acceptance also
requires the agreed carrier-neutral session profile or a complete virtual
native adapter. The route to the `SNUSNU` NETID is an additional APPN
cross-network problem; the configuration-list entry alone does not make the
Rust node a border node or prove that OS/400 will select this path.

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
