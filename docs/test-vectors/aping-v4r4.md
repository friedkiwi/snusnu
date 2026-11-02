# V4R4 APING application records

On 2026-11-02, `VFYAPPCCNN RMTLOCNAME(SNAB) PKTLEN(16) NBRITER(1)`
completed between the two writable V4R4 lab guests across the existing LLC
relay. The initiating guest reported a successful allocation, remote system
type `OS/400`, and a completed packet iteration. A second run used
`PKTLEN(4) NBRPKT(2) ECHO(*NO)` and completed as well. Both TAP captures remain
outside the repository because they contain guest identities and may contain
application data.

The following decoded mapped records are safe test vectors. `LL` is a
two-byte big-endian length that includes the LL field itself.

| Step | Direction | Record (hex) | Meaning |
| --- | --- | --- | --- |
| Version | requester to APINGD | `000f12ff01022b02d6e261f4f0f000` | `OS/400` in EBCDIC plus NUL |
| Version | APINGD to requester | `000e12ff01022b024f532f343030` | `OS/400` in ASCII |
| Echo | requester to APINGD | `001412ff00000000000000000000000000000000` | 16-byte zero payload |
| Echo | APINGD to requester | same as request | returned record |
| No echo | requester to APINGD | `000812ff00000000` twice | two 4-byte payloads |

The no-echo turn received a positive SNA response with no data record. The
requester then sent its normal close sequence. The captured exchange also
included management BIND, CNOS, user BIND, FMH-5 Attach, pacing, and UNBIND.
The Go packages and concentrator adapter implement these stages and cover
them with a complete synthetic WebSocket circuit test. That test also checks
the V4R4 extended pacing response and the no-echo positive response.

On 2026-11-02, an isolated V4R4 guest connected through the Rust LLC router
to the embedded `SNUSNU.PING` LU in the Go concentrator. A
`VFYAPPCCNN RMTLOCNAME(SNUSNU.PING) PKTLEN(16) NBRITER(1)` run reached
APINGD, displayed the remote system type `OS/400`, and exchanged the 16-byte
echo record. The wire trace then reached CONFIRM, BIS, and UNBIND without a
concentrator reset. The guest's final command result was not captured, so the
trace establishes the protocol exchange rather than a guest-reported pass.
