# Isolated cross-NETID router lab

The final lab target is V5R4 AnyNet to router A, WebSocket through the QA
concentrator, router B to V4R4 LLC2. V5R4 initiates a pass-through to V4R4.
The two OS/400 guests and routers must use different owners and NETIDs.
This topology is separate from the `SOLNET` regression guests in the
[LLC lab](llc-lab.md) and [AnyNet lab](anynet-lab.md).

| Role | Writable guest | TAP | TN5250 ports | Local CP/LU | QA owner |
| --- | --- | --- | --- | --- | --- |
| V4R4 destination | `/tmp/snusnu-cross-netid/v4-alice` | `sol8` | 25183, 25184 | `QAALICE.SNAA` | Alice |
| V5R4 initiator | `/tmp/snusnu-cross-netid/v5-bob` | `sol9` | 9571, 9572 | `QABOB.SNAB` | Bob |

The directories were cold sparse copies of powered-off writable guests on
2026-11-02, not copies of the original Solstice templates. Their chassis
files use independent TAPs and console ports. The source `SOLNET` guests
retain `sol5`/`sol7` and their original ports. The host filesystem does not
support reflink copies, so the two copies occupy about 9 GiB of allocated
disk space. Do not bridge `sol8` and `sol9`: each guest must see only its own
router endpoint. Guest MACs may match the source clones because the TAPs
remain isolated.

The QA seed gives Alice managed CP `QAALICE.SNAA` and Bob managed CP
`QABOB.SNAB`, with one bearer token for each router. The seed allocates
Alice before Bob, so a fresh database normally gives Bob's CP managed MAC
`02:53:4e:00:00:02`; read the assigned address from the concentrator before
entering it in V4's controller. The Go forwarding policy allows different
owners by default unless a router is paused or either user blocks the other.

Configure only the copied OS/400 guests after they reach Main Menu:

1. Vary V4 controller/device `SNAB` off. Set `CHGNETA LCLNETID(QAALICE)`;
   keep local CP and location `SNAA`. Change controller `SNAB` to remote
   NETID `QABOB`, remote CP `SNAB`, adapter address equal to Bob's assigned
   managed MAC, and `INLCNN(*ANS)` so V4 can answer V5's session. Confirm
   with `DSPNETA` and `DSPCTLD CTLD(SNAB)` before varying it on.
2. Vary V5 device `SNAA00` and controller `ANYTOA` off. Set
   `CHGNETA LCLNETID(QABOB)`; keep local CP and location `SNAB`. Change
   controller `ANYTOA` to remote NETID `QAALICE` and remote CP `SNAA`.
   In `WRKCFGL`/`QAPPNRMT`, replace the remote `SNAA` entry's NETID and
   CP NETID with `QAALICE`, preserving local location `SNAB`. Change only
   the SNA host alias to `SNAA.QAALICE.SNA.IBM.COM` at router A's IP;
   preserve B's system hostname entry and its address. Confirm the host
   table, controller, and remote-location list before varying `ANYTOA` on.
3. Use host IP `10.99.4.11/32` and an on-link host route on `sol9` to reach
   the V5 guest's existing `10.99.4.3` address; bind router A's TCP/UDP 397
   endpoint to `10.99.4.11`.
   Router B uses `sol8` and Bob's server-owned managed MAC toward V4. Both
   routers connect to the same QA WebSocket endpoint with their respective
   bearer tokens. Publish the local CP/LU on each router, then initiate
   `STRPASTHR RMTLOCNAME(SNAA)` from V5.

The current production Rust config accepts a remote WebSocket port only with
an LLC port; it cannot yet configure AnyNet to remote WebSocket conversion.
The native APPN answer side, bidirectional session conversion, and remote
circuit mapping must be ready before running the final test. Do not change
the `SOLNET` regression guests or start the QA concentrator as part of guest
preparation.
