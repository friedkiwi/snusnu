# QA concentrator

Build and run the QA variant from `concentrator/`:

```sh
go build -o snusnu-concentrator-qa ./cmd/snusnu-concentrator-qa
./snusnu-concentrator-qa
```

It serves the same Go application and WebSocket protocol as the normal binary on all interfaces at port 8081 (`:8081`). Set `SNUSNU_LISTEN` or use `-listen` to choose another address and port; the flag takes precedence. The public origin defaults to `http://localhost:8081`; use `-origin` when the browser-facing address changes. Development mode is enabled, so registration and password-reset codes appear in the log. No SMTP, reCAPTCHA or MFA key setup is required. Preloaded accounts have verified emails and a 30-day MFA enrollment reminder deferral; MFA remains optional and can be enrolled through Settings.

For an isolated guest that already uses another NETID, `-alice-netid SOLNET` changes only the Alice QA account's NETID in the new temporary database. Its router token stays the same. Use a separate `-listen` and `-origin` to keep this lab separate from another QA run.

For the 5494 printer wire investigation, `-printer-probe` advertises
`SNUSNU.PRINTER` only in that QA instance. It completes native link XID and
logs incoming FID2 PIUs or session events. The probe does not acknowledge
printer BIND or store output, so use it only to capture the first guest
exchange before enabling the embedded printer service.
Use `-sna-debug` to log full SNA PIUs, circuit credit and internal service
state to stderr in the QA process.

Every launch creates a new private directory under the OS temporary directory and a new `qa.sqlite` database in it. The database path is printed at startup. The QA binary **ignores** `SNUSNU_DB_DRIVER` and `SNUSNU_DB_DSN`, does not accept a database path flag, and creates the file exclusively. It cannot open or overwrite the normal concentrator's configured database. Previous QA databases are retained until removed by the operator or the OS temporary-directory cleanup.

## Accounts

| Role | Email | Password | Username | NETID |
| --- | --- | --- | --- | --- |
| Admin | `admin@qa.snusnu.test` | `qa-admin-password-123` | `qa_admin` | `QAADMIN` |
| User | `alice@qa.snusnu.test` | `qa-alice-password-123` | `qa_alice` | `QAALICE` |
| User | `bob@qa.snusnu.test` | `qa-bob-password-123` | `qa_bob` | `QABOB` |

## Preloaded clients

| Owner | Display name | Bearer token | Intended CP |
| --- | --- | --- | --- |
| Alice | `Alice V4R4` | `qa-alice-router-token-1234567890` | `QAALICE.SNAA` |
| Bob | `Bob V5R4` | `qa-bob-router-token-1234567890` | `QABOB.SNAB` |

Alice's router is LLC-facing; Bob's TCP62 gateway is not. A stable virtual MAC is allocated automatically when either router connects and first advertises its CP; there are no pre-created or user-managed address entries. Each router uses `ws://localhost:8081/router/v1/ws` with its token in the `Authorization: Bearer` header. Native LLC relay tests can use `snusnu.v1`; the cross-NETID LU gateway requires `snusnu.v2` source-route validation. Assigned MACs appear alongside live CPs and hosted LUs in the global directory; administrators also have a read-only allocation view.

The admin account also has a read-only API key named `QA admin API` with token `qa-admin-api-token-1234567890`. Use it for `/api/v1/directory`, `/api/v1/connections` and `/api/v1/flows`; `/openapi.json` contains the generated contract.

These credentials are public test fixtures. For a local-only QA run, set `-listen 127.0.0.1:8081`; otherwise run it only on an isolated QA network.
