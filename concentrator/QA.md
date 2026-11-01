# QA concentrator

Build and run the QA variant from `concentrator/`:

```sh
go build -o snusnu-concentrator-qa ./cmd/snusnu-concentrator-qa
./snusnu-concentrator-qa
```

It serves the same Go application and WebSocket protocol as the normal binary at `127.0.0.1:8081`. The public origin defaults to `http://localhost:8081`; use `-listen` and `-origin` together to change it. Development mode is enabled, so registration and password-reset codes appear in the log. No SMTP, reCAPTCHA or MFA key setup is required. Preloaded accounts have verified emails and a 30-day MFA enrollment reminder deferral; MFA remains optional and can be enrolled through Settings.

Every launch creates a new private directory under the OS temporary directory and a new `qa.sqlite` database in it. The database path is printed at startup. The QA binary **ignores** `SNUSNU_DB_DRIVER` and `SNUSNU_DB_DSN`, does not accept a database path flag, and creates the file exclusively. It cannot open or overwrite the normal concentrator's configured database. Previous QA databases are retained until removed by the operator or the OS temporary-directory cleanup.

## Accounts

| Role | Email | Password | Username |
| --- | --- | --- | --- |
| Admin | `admin@qa.snusnu.test` | `qa-admin-password-123` | `qa_admin` |
| User | `alice@qa.snusnu.test` | `qa-alice-password-123` | `qa_alice` |
| User | `bob@qa.snusnu.test` | `qa-bob-password-123` | `qa_bob` |

## Preloaded clients

| Owner | Display name | Bearer token | Intended CP |
| --- | --- | --- | --- |
| Alice | `Alice V4R4` | `qa-alice-router-token-1234567890` | `SOLNET.SNAA` |
| Bob | `Bob V4R4` | `qa-bob-router-token-1234567890` | `SOLNET.SNAB` |

Both router clients are marked LLC-facing. Their CPs have managed virtual MAC address-book entries, but they have no live advertisements until they connect and publish a route snapshot. Each router uses `ws://localhost:8081/router/v1/ws` with its token in the `Authorization: Bearer` header and subprotocol `snusnu.v1`. The managed MACs can be viewed in the UI; Rust's first V4R4 lab may continue using its configured MACs.

The admin account also has a read-only API client named `QA admin API` with token `qa-admin-api-token-1234567890`. Use it for `/api/v1/directory` and `/api/v1/connections`.

These credentials are public test fixtures. Run this binary only on a loopback or isolated QA network.
