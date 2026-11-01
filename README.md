# snusnu

snusnu is an early-stage, stateful DLC circuit service for connecting hobbyist SNA LAN sites through a central concentrator. Local routers will terminate LLC2 and carry bounded circuits over authenticated outbound WSS connections; existing SNA and APPN nodes will continue to own sessions, directory services, and resource routing.

- `concentrator/`: Go web service with SQLite/PostgreSQL storage, accounts, MFA, router onboarding, profiles, a live-export directory scaffold, diagnostics, and read-only client API.
- `sna_router/`: Rust workspace for the router core, Linux packet adapter, transport boundary, and executable. Its two-TAP lab mode terminates LLC2 and relays SNA data between peers.

**Early development:** the LLC2 lab mode passed a V4R4 Solstice-to-Solstice APPC pass-through test. WSS circuit transport, authentication, and production routing are not implemented yet. Directory and connection records are planning data, not live reachability or transport status.

```sh
cd concentrator && go build ./... && test -z "$(gofmt -l .)" && go vet ./... && go test ./...
cd ../sna_router && cargo build --workspace && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

See [architecture](docs/architecture.md) and [draft protocol](docs/protocol.md).

See [LLC lab](docs/llc-lab.md) for the local SNA interoperability setup.

See [concentrator setup](concentrator/README.md) for web service configuration and local development.
