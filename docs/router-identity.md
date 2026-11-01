# Router identity and live SNA resource keys

The concentrator owns each Rust router's identity. On onboarding it generates a stable UUID (`router_id`), records the router's owner and optional administrative site, and issues a separate opaque bearer credential. The owner sets a display name. The Rust executable configures only its bearer credential and local routes. After authenticating its WebSocket, it receives `RouterWelcome.router_id` and `RouterWelcome.display_name` from the concentrator and logs/displays both. It never sends a claimed local router ID or chooses one in configuration. On reconnect or credential rotation, the same router receives the same UUID.

Authentication resolves `token hash → credential record → router_id`. A router may have more than one credential during rotation; revoking one credential does not rename the router. Each credential has its own creation, expiry/revocation and purpose. Revocation of an active credential closes or revalidates its WebSocket and withdraws its live routes. The concentrator stamps `router_id` on every relayed snapshot and checks it on circuit opens. The bearer token must travel over TLS and must not appear in logs; any holder can use it while valid ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)).

The current Go `api_clients` table is **user-scoped** and its bearer authentication resolves to a user for read-only APIs. It does not identify a router. Router onboarding therefore needs separate records or an explicitly router-scoped credential type. An illustrative server data model is:

```text
routers(id UUID PRIMARY KEY, owner_id, site_id NULL, display_name, status)
router_credentials(id, router_id REFERENCES routers(id), secret_hash UNIQUE,
                   created_at, expires_at, revoked_at)
```

The Go web service uses a version-2 migration for router records, router-scoped credentials, profiles, blocks and diagnostics. WebSocket authentication and `RouterWelcome` transmission are still pending.

Internally, keep SNA resource keys as structured fields:

```text
CP: (router_id, CP, netid, cp_name)
LU: (router_id, LU, netid, lu_name)  [optional hosting CP]
```

For example, B's V4R4 lab configuration yields `(R, CP, SOLNET, SNAB)` and `(R, LU, SOLNET, SNAB)`: the spelling is equal, but the resource kind differs. The router UUID scopes who advertised each resource. A secondary lookup by `(kind, netid, name)` finds possible routers; multiple matches need explicit preference or an ambiguity error. An SNA network ID can cover several routers and sites, and one router can advertise several CPs and LUs. `SYSNAME`, TCP hostname and the optional snusnu administrative site do not form the SNA resource key.

The live circuit reference remains `(router_id, connection_epoch, route_id, route_generation)`. `route_id` is the origin's opaque handle for a particular export, while the structured SNA key is for discovery and policy. The connection epoch and route generation keep stale opens from binding to a replacement route.
