# Concentrator web service

For a ready-to-run isolated database with test accounts and router clients, use the [QA binary](QA.md).

The Go binary contains the HTML templates, passkey browser code, and Bootstrap 5.3.8 CSS/JS. It serves them from `/assets/`; no CDN is needed. If reCAPTCHA is enabled, its widget still loads Google's live script, as required by the [reCAPTCHA v2 integration](https://developers.google.com/recaptcha/docs/display).

## Local development

```sh
cd concentrator
export SNUSNU_DEV=1
export SNUSNU_ORIGIN=http://localhost:8080
export SNUSNU_DB_DRIVER=sqlite
export SNUSNU_DB_DSN=snusnu.db
export SNUSNU_MFA_KEY="$(openssl rand -hex 32)"
go run ./cmd/snusnu-concentrator
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
| `SNUSNU_LISTEN` | HTTP listen address and port, default `:8080` (all interfaces); `-listen` overrides it |
| `SNUSNU_DB_DRIVER` | `sqlite` (default) or `postgres` |
| `SNUSNU_DB_DSN` | SQLite filename (default `snusnu.db`) or PostgreSQL connection URL |
| `SNUSNU_ORIGIN` | Public origin; HTTPS required outside development |
| `SNUSNU_MFA_KEY` | Persistent 64-character hex key for TOTP secret encryption |
| `SNUSNU_METRICS_KEY` | Optional bearer key for `GET /metrics`; the endpoint is disabled when unset |
| `SNUSNU_DEV` | Set to `1` for local HTTP and verification-code logging |
| `SNUSNU_SMTP_ADDR` | SMTP host and port with STARTTLS, required outside development |
| `SNUSNU_SMTP_FROM` | Verified sender address, required outside development |
| `SNUSNU_SMTP_USER`, `SNUSNU_SMTP_PASSWORD` | SMTP credentials, when required by the server |
| `SNUSNU_RECAPTCHA_SITE_KEY`, `SNUSNU_RECAPTCHA_SECRET` | Optional reCAPTCHA v2 checkbox keys; supply both or neither |

The default listener binds all network interfaces on port 8080. Use `-listen 127.0.0.1:8080` for loopback only, `-listen 192.0.2.10:8443` for one interface, or set `SNUSNU_LISTEN` to either value. Use TLS at the reverse proxy and set `SNUSNU_ORIGIN` to its HTTPS origin. The app checks the configured origin for passkeys and sets Secure session cookies on HTTPS origins. SQLite is intentionally supported for development, testing, evaluation, and small deployments; its single-writer bottleneck is accepted in exchange for simple operation. PostgreSQL is the production database option and uses the same versioned migrations through pgx.

The concentrator is deliberately single-instance. At startup it acquires and continuously heartbeats an exclusive database lease; a second process using the same database refuses to start. Multi-instance operation is not supported. Startup clears stale live connection epochs and route advertisements only after acquiring that lease.

At startup the concentrator publishes its reserved `SNUSNU.SVC` control point and `SNUSNU.PING` LU 6.2 service. An authenticated router can route APINGD traffic to that LU. The service responds to APING version, echo, no-echo, and orderly deallocation within the concentrator process. The managed CP address is `02:53:4e:ff:ff:ff`; user accounts cannot claim the `SNUSNU` NETID. Current APING support accepts complete mapped data in one SNA PIU, up to 1496 bytes including the nine-byte TH/RH header. Larger APING packets and chained RUs are not yet supported.

The database is a required runtime dependency. Brief asynchronous write failures are retried, but exhausted router-log or SNA-circuit-history writes, sustained heartbeat failure, or loss of the singleton lease make the process unready and trigger its bounded graceful shutdown. The process exits nonzero so its service supervisor can restart it. Production supervisors should use restart-on-failure with backoff while PostgreSQL is unavailable. Unpersisted operational records may be discarded when the shutdown deadline expires; the concentrator does not maintain a separate local durability spool.

## Roles and current records

New accounts have the `user` role and must verify email before login. An administrator can manually verify a pending account from **Admin → Users**; this invalidates its outstanding email verification code. The dashboard shows the user's named sna_router clients and their live CP/LU exports. Users can onboard a router, name it, pause or resume it, rotate its bearer credential, or remove it. Router credentials are separate from user API client credentials and are hashed at rest. The onboarding page shows the `wss://<host>/router/v1/ws` URL and the token once; router downloads are placeholders. Pausing and token rotation revoke the current connection epoch and withdraw its exports. The WebSocket service closes the affected socket on its next policy check.

Users can reset their own password from the sign-in page using a six-digit code sent to their verified email address. Codes expire after 10 minutes and allow five attempts; reset requests are rate limited and require reCAPTCHA when configured. Development mode logs the password reset code, as it does verification codes. Admins can reset a user's password from the Users page or profile: a random temporary password is displayed once to the admin. Both reset paths revoke the user's browser sessions, preserve enrolled MFA, and require the new password for the next sign-in. Admins always see user email addresses, even when a profile has private email visibility.

The global directory lists live exports, with owner profile links. Profiles support a username, optional first and last names, an optional PNG/JPEG picture, and an email visibility choice. Users can block another user on that user's profile; the store's forwarding policy denies flows in either direction between the two owners. Admins can inspect all routers and manage user roles and legacy planning records.

The concentrator automatically allocates managed virtual addresses from `02:53:4E:00:00:01` through `02:53:4E:FF:FF:FF` when CPs are advertised. Users cannot select or retire them. The global directory shows the assigned MAC and SAP for CPs and hosted LUs; administrators have a read-only allocation view. Assignments survive route withdrawal and disconnect. The `02:53:4E` prefix validates an address format, not the identity of a router.

The router detail page has an explicit **LLC-facing** setting. The WebSocket service sends versioned, server-stamped binding snapshots to active, authorized LLC-facing recipients only; the snapshots omit blocked peers and withdrawn routes. Rust-published route snapshots remain MAC-free. The first two-V4R4 WebSocket test can continue using configured MACs independently of this address book.

Router detail pages and the Flows page search the most recent 100 diagnostic entries by event, node, summary or source IP. The WebSocket relay records bounded event summaries, timestamps, direction, peer identity and source IP; records expire after 30 days. Local LLC packet decoding remains with Rust. Live route snapshots are validated and replaced atomically by epoch and revision.

MFA enrollment is optional. Users without an enrolled factor are prompted after login and may defer the reminder for 30 days. Once TOTP or a passkey is enrolled, it is required after the password on each login. The login page offers **Remember me for 30 days**, which creates a persistent session cookie after the normal password and MFA flow; unchecked sessions expire after 12 hours and use a browser-session cookie. The user card in the top-right navigation contains Profile, Settings, API keys, My blocklist and Sign out.

The Flows page shows recent inbound and outbound flow records. Flow logging deliberately records a bounded hexadecimal prefix (up to 128 bytes) of Type 1 and SNA information fields for operational diagnosis; this is payload data and must be covered by the deployment's access-control, privacy, and retention policy. Circuit history itself stores transport metadata and counters, not payload. Admins see records for all users; regular users see only their own routers' records. Admins can search and page through the Users list, inspect all user blocklists, and delete another user after confirming with their own password. Users can inspect and unblock entries on My blocklist or block a peer from its profile. Users can delete their own account from Settings after password confirmation. Deletion revokes sessions and router credentials, cascades account-owned records, and retires managed CP addresses without reusing them. The last admin account cannot be deleted.

User API keys receive a bearer token once at creation; only its SHA-256 hash is stored. Read-only endpoints expose the live global directory, planning connections and flows. Connections and flows use the key owner's current permissions, so administrators see all records while ordinary users see their own. `/openapi.json` is generated from the same route registry and Go response types used by the server.
