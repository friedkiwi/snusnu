# Address-aware routing and circuit credit

The current Rust router treats a `RoutePort` as one LLC association, one EE or
AnyNet peer, or one WebSocket circuit. `Router::bind_destination` selects one
address route for that port. `poll_source` checks that target's capacity before
the ingress adapter acknowledges information; `release_completed` returns the
target's completed frame count to that same ingress port. The route validator
rejects two source ports sharing one target port. Those choices keep LLC ACKs
and WebSocket allowance tied to one pair of queues.

The address table can hold several `(source port, address) → target port`
entries, but it is not yet a packet-by-packet forwarding table. A source's
selected destination is immutable after binding. Switching it while a frame
is queued or awaiting an LLC ACK could credit the wrong target, and the
current `RoutePort` methods have no circuit key with which to distinguish
those completions. A concentrator-assigned MAC update is a narrow exception:
it changes the address of an existing LLC association while retaining its
target, after the endpoint rejects an update during an active LLC link.

To route several destinations through one physical interface safely:

1. Keep the physical socket as a shared transport, but expose a distinct
   logical `RoutePort` for each LLC `(interface, guest MAC, proxy MAC, SAP)`
   association or WebSocket circuit. The existing multi-LLC runtime already
   follows this pattern for configured peers on one interface.
2. Have ingress parsing return a validated destination selector together
   with the typed unit. Resolve that selector to a **circuit port** before
   accepting an information frame. Unknown or ambiguous selectors must not
   fall back to an unrelated default route.
3. Track queue slots, LLC ACKs, WebSocket allowance, busy state, and close
   state by circuit port. If one transport multiplexes circuits internally,
   its adapter must demultiplex events and completions before they reach the
   router; a single aggregate completion count cannot be shared across
   destinations.
4. Validate the active route graph as one-to-one at the circuit-port level.
   A physical interface or WebSocket connection may serve many circuit
   ports. Route updates that change a circuit's target require draining or
   closing that circuit and opening a new generation before new traffic is
   accepted.

CP/LU exports and managed virtual MACs are control-plane identities. They
choose or advertise a circuit, but do not by themselves provide a data-plane
credit key. The same per-circuit rule applies when LLC, AnyNet, EE, or
WebSocket adapters are added to the routing graph.
