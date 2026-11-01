# QA concentrator

Build and run the QA variant from `concentrator/`:

```sh
go build -o snusnu-concentrator-qa ./cmd/snusnu-concentrator-qa
./snusnu-concentrator-qa
```

It serves the same Go application and WebSocket protocol as the normal binary on all interfaces at port 8081 (`:8081`). Set `SNUSNU_LISTEN` or use `-listen` to choose another address and port; the flag takes precedence. The public origin defaults to `http://localhost:8081`; use `-origin` when the browser-facing address changes. Development mode is enabled, so registration and password-reset codes appear in the log. No SMTP, reCAPTCHA or MFA key setup is required. Preloaded accounts have verified emails and a 30-day MFA enrollment reminder deferral; MFA remains optional and can be enrolled through Settings.

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

Alice's router is LLC-facing; Bob's TCP62 gateway is not. Both CPs have managed virtual MAC address-book entries, but they have no live advertisements until they connect and publish a route snapshot. Each router uses `ws://localhost:8081/router/v1/ws` with its token in the `Authorization: Bearer` header. Native LLC relay tests can use `snusnu.v1`; the cross-NETID LU gateway requires `snusnu.v2` source-route validation. The managed MACs can be viewed in the UI.

The admin account also has a read-only API client named `QA admin API` with token `qa-admin-api-token-1234567890`. Use it for `/api/v1/directory` and `/api/v1/connections`.

These credentials are public test fixtures. For a local-only QA run, set `-listen 127.0.0.1:8081`; otherwise run it only on an isolated QA network.
