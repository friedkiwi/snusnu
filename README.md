# snusnu

Snusnu connects SNA sites with a Rust router and an optional Go concentrator. Routers handle local links and authenticated WebSocket circuits. The concentrator publishes live CP/LU reachability and embeds an APING responder at `SNUSNU.PING` under `SNUSNU.SVC`.

- [Architecture and current scope](docs/architecture.md)
- [Rust router configuration](docs/router-config.md) and [runtime status](docs/router-runtime.md)
- [Go concentrator setup](concentrator/README.md) and [isolated QA environment](concentrator/QA.md)
- [Reusable Go SNA packages](sna/README.md) and [APING lab evidence](docs/test-vectors/aping-v4r4.md)
- [Route advertisements](docs/route-advertisements.md) and [WebSocket protocol](docs/websocket-protocol.md)
- [LLC2](docs/llc-lab.md), [Enterprise Extender](docs/ee-lab.md), [AnyNet](docs/anynet-lab.md), and [cross-NETID gateway](docs/cross-netid-lab.md) lab records

Enable the repository's staged-tree CI checks in a clone with `git config core.hooksPath .githooks`.
