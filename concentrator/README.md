# Concentrator web service

The Go binary contains the HTML templates, passkey browser code, and Bootstrap 5.3.8 CSS/JS. It serves them from `/assets/`; no CDN is needed. If reCAPTCHA is enabled, its widget still loads Google's live script, as required by the [reCAPTCHA v2 integration](https://developers.google.com/recaptcha/docs/display).

## Local development

```sh
cd concentrator
export SNUSNU_DEV=1
export SNUSNU_ORIGIN=http://localhost:8080
export SNUSNU_DB_DRIVER=sqlite
export SNUSNU_DB_DSN=snusnu.db
export SNUSNU_MFA_KEY="$(openssl rand -hex 32)"
go run ./cmd/snusnu-concentrator -listen 127.0.0.1:8080
```

Keep `SNUSNU_MFA_KEY` stable across restarts: it encrypts stored TOTP secrets. Register at `http://localhost:8080/register`. In development mode, the six-digit verification code is written to the service log on registration. Codes expire after 10 minutes and allow five attempts.

After verifying a user, promote it with:

```sh
go run ./cmd/snusnu-concentrator -promote-email you@example.com
```

The command uses the same database environment variables and exits without starting the server.

If a user loses every MFA factor, an operator with database access can run `go run ./cmd/snusnu-concentrator -reset-mfa-email user@example.com`. This clears their factors and active sessions so they can sign in and enroll again.

## Configuration

| Variable | Purpose |
| --- | --- |
| `SNUSNU_DB_DRIVER` | `sqlite` (default) or `postgres` |
| `SNUSNU_DB_DSN` | SQLite filename (default `snusnu.db`) or PostgreSQL connection URL |
| `SNUSNU_ORIGIN` | Public origin; HTTPS required outside development |
| `SNUSNU_MFA_KEY` | Persistent 64-character hex key for TOTP secret encryption |
| `SNUSNU_DEV` | Set to `1` for local HTTP and verification-code logging |
| `SNUSNU_SMTP_ADDR` | SMTP host and port with STARTTLS, required outside development |
| `SNUSNU_SMTP_FROM` | Verified sender address, required outside development |
| `SNUSNU_SMTP_USER`, `SNUSNU_SMTP_PASSWORD` | SMTP credentials, when required by the server |
| `SNUSNU_RECAPTCHA_SITE_KEY`, `SNUSNU_RECAPTCHA_SECRET` | Optional reCAPTCHA v2 checkbox keys; supply both or neither |

Use TLS at the reverse proxy and set `SNUSNU_ORIGIN` to its HTTPS origin. The app checks the configured origin for passkeys and sets Secure session cookies on HTTPS origins. The SQLite database is initialized automatically, with WAL and foreign keys enabled. PostgreSQL uses the same versioned migrations through pgx. Run one concentrator process per database until distributed live-presence fencing is implemented; startup clears stale live connection epochs and route advertisements.

## Roles and current records

New accounts have the `user` role and must verify email before login. The dashboard shows the user's named sna_router clients and their live CP/LU exports. Users can onboard a router, name it, pause or resume it, rotate its bearer credential, or remove it. Router credentials are separate from user API client credentials and are hashed at rest. The onboarding page shows the reserved `wss://<host>/router/v1/ws` URL and the token once; router downloads are placeholders. Pausing and token rotation revoke the current connection epoch and withdraw its exports in the database. The future transport must close active sockets and call the policy gate for traffic.

The global directory lists live exports, with owner profile links. Profiles support a username, optional first and last names, an optional PNG/JPEG picture, and an email visibility choice. Users can block another user on that user's profile; the store's forwarding policy denies flows in either direction between the two owners. Admins can inspect all routers and manage user roles and legacy planning records.

Router detail pages and the inbound-flow page search the most recent 100 diagnostic entries by event, node, summary or source IP. The log store accepts structured decoded fields, timestamps, direction, severity and peer identity; records expire after 30 days. No wire decoder or live transport is connected yet, so these pages have no live traffic records. Live route snapshots are validated and replaced atomically by epoch and revision through the store API, but no WebSocket handler calls it yet.

MFA enrollment is optional. Users without an enrolled factor are prompted after login and may defer the reminder for 30 days. Once TOTP or a passkey is enrolled, it is required after the password on each login. User API clients receive a bearer token once at creation; only its SHA-256 hash is stored. Current API access is read-only at `/api/v1/directory` and `/api/v1/connections`. The directory API returns live exports; the connections API remains the older planning-record view.
