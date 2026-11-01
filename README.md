# snusnu

snusnu is an early-stage, stateful DLC circuit service for connecting hobbyist SNA LAN sites through a central concentrator. Local routers will terminate LLC2 and carry bounded circuits over authenticated outbound WSS connections; existing SNA and APPN nodes will continue to own sessions, directory services, and resource routing.

- `concentrator/`: Go service, currently a health-only HTTP server.
- `sna_router/`: Rust workspace for the platform-independent router core, Linux link adapter, transport boundary, and executable.

**Early development:** no LLC2 endpoint, WSS circuit transport, authentication, or SNA interoperability is implemented yet.

```sh
cd concentrator && go build ./... && test -z "$(gofmt -l .)" && go vet ./... && go test ./...
cd ../sna_router && cargo build --workspace && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

See [architecture](docs/architecture.md) and [draft protocol](docs/protocol.md).
