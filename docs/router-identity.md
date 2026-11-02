# Router identity and live SNA resource keys

The concentrator owns each Rust router's identity. During user registration, each account claims one globally unique SNA NETID; migrated accounts without one must set it on their profile. Router onboarding only generates a stable UUID (`router_id`), records the router's owner and display name, and issues a separate opaque bearer credential. The Rust executable configures only its bearer credential and local routes. After authenticating its WebSocket, it receives `RouterWelcome.router_id`, `RouterWelcome.display_name`, and `RouterWelcome.allowed_netid` from the concentrator and logs/displays them. It never sends a claimed local router ID or chooses its allowed namespace in configuration. On reconnect or credential rotation, the same router receives the same UUID.

Authentication resolves `token hash → credential record → router_id`. A router may have more than one credential during rotation; revoking one credential does not rename the router. Each credential has its own creation, expiry/revocation and purpose. Revocation of an active credential closes or revalidates its WebSocket and withdraws its live routes. The concentrator stamps `router_id` on every relayed snapshot and checks it on circuit opens. The bearer token must travel over TLS and must not appear in logs; any holder can use it while valid ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)).

Go keeps read-only `api_clients` **user-scoped** and `router_credentials` **router-scoped**. The former resolve to a user; the latter authenticate a WebSocket and resolve to a stable row in `routers`. Credential rows hold a secret hash, purpose, creation and optional expiry/revocation times. See the versioned schema in [`concentrator/internal/store/store.go`](../concentrator/internal/store/store.go).

The Go web service uses versioned migrations for router records, router-scoped credentials, profiles, blocks and diagnostics. The WebSocket endpoint authenticates router bearer tokens before upgrade and sends `RouterWelcome` with the server-owned router UUID, display name, owner NETID and fresh connection epoch. A snapshot is rejected if a CP, LU, or hosting CP uses any other NETID. Changing the profile NETID fences all of the user's router epochs and withdraws their advertisements.

Internally, keep SNA resource keys as structured fields:

```text
CP: (router_id, CP, netid, cp_name)
LU: (router_id, LU, netid, lu_name)  [optional hosting CP]
```

For example, B's V4R4 lab configuration yields `(R, CP, SOLNET, SNAB)` and `(R, LU, SOLNET, SNAB)`: the spelling is equal, but the resource kind differs. The router UUID scopes who advertised each resource. A secondary lookup by `(kind, netid, name)` finds possible routers; multiple matches need explicit preference or an ambiguity error. An SNA network ID can cover several routers and sites, and one router can advertise several CPs and LUs. `SYSNAME`, TCP hostname and the optional snusnu administrative site do not form the SNA resource key.

The live circuit reference remains `(router_id, connection_epoch, route_id, route_generation)`. `route_id` is the origin's opaque handle for a particular export, while the structured SNA key is for discovery and policy. The connection epoch and route generation keep stale opens from binding to a replacement route.
