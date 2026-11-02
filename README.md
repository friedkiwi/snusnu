# snusnu

snusnu is an early-stage, stateful DLC circuit service for connecting hobbyist SNA LAN sites through a central concentrator. Local routers will terminate LLC2 and carry bounded circuits over authenticated outbound WSS connections; existing SNA and APPN nodes will continue to own sessions, directory services, and resource routing.

- `concentrator/`: Go web service with SQLite/PostgreSQL storage, accounts, MFA, router onboarding, profiles, a live-export directory scaffold, diagnostics, and read-only client API.
- `sna_router/`: Rust workspace for the router core, Linux packet adapter, transport boundary, and executable. Its two-TAP lab mode terminates LLC2 and relays SNA data between peers.

**Early development:** the LLC2 lab mode passed a V4R4 guest-to-guest APPC pass-through test. WSS circuit transport, authentication, and production routing are not implemented yet. Directory and connection records are planning data, not live reachability or transport status.

Install the repository pre-commit checks once per clone:

```sh
git config core.hooksPath .githooks
```

The hook checks the staged tree with the CI formatting, vet or clippy, test,
and build commands for the Go and Rust paths affected by each commit. Run
`scripts/pre-commit-check.sh` to check the current staged changes manually.

See [architecture](docs/architecture.md) and [draft protocol](docs/protocol.md).

See [LLC lab](docs/llc-lab.md) for the local SNA interoperability setup.

See [concentrator setup](concentrator/README.md) for web service configuration and local development.
