# Go SNA packages

`github.com/friedkiwi/snusnu/sna` is a separate Go module. It has no socket,
WebSocket, LLC2, or concentrator dependency. A caller supplies complete PIUs,
an authenticated `sna.Peer`, and a transport acknowledgement after each sent
PIU. This lets another application embed the same protocol and APINGD code
with its own transport.

| Package | Responsibility |
| --- | --- |
| `sna/xid3` | XID3 parsing and link activation state |
| `sna/piu` | Bounded FID2 PIU parsing |
| `sna/lu62` | Management and user BIND, CNOS, pacing, Attach, mapped turns, CONFIRM, BIS, and UNBIND |
| `sna/services/apingd` | APINGD version and mapped data records |

The concentrator's adapter in `concentrator/internal/server/local_sna_service.go`
owns route authentication, circuit credit, XID exchange, and PIU delivery. It
passes the server-stamped peer identity into `apingd.NewConversation`. The
APINGD package does not trust any identity claimed inside an application
record and never starts a daemon. The current adapter accepts one complete
mapped data RU per PIU, up to 1496 bytes including TH/RH, and a single
APINGD conversation per circuit. Chained RUs and larger packets need an
explicit reassembly layer before they can be accepted.
