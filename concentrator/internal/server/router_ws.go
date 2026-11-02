package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

const maxWSMessage = 64 * 1024
const maxWSCircuits = 64
const wsPingInterval = 5 * time.Second
const wsReadTimeout = 15 * time.Second
const wsWriteTimeout = 10 * time.Second

// Policy mutations refresh immediately. This slower poll covers expiry and
// changes made outside the application.
const policyFallbackInterval = 30 * time.Second

type outboundMessage struct {
	data           []byte
	circuit        string
	circuitRef     *wsCircuit
	routeOrigin    string
	bindingOrigins []string
	cost           int
}
type routerSession struct {
	mu                             sync.Mutex
	local                          bool
	localInbox                     chan *wire.WsEnvelope
	router                         store.Router
	token, epoch, ip, allowedNetID string
	subprotocol                    string
	conn                           *websocket.Conn
	out                            *dynamicQueue[outboundMessage]
	snapshot                       *wire.RouteSnapshot
	sent                           map[string]routeVersion
	binding                        *wire.ManagedCpBindingSnapshot
	bindingRevision                uint64
	queued                         map[string]int
	pendingRequests                map[uint64]struct{}
	history                        map[uint64]routeSignature
	rateWindow                     time.Time
	rateCount                      int
	connectedAt                    time.Time
	closed                         atomic.Bool
	circuitCount                   atomic.Int32
	done                           chan struct{}
}

func (c *routerSession) routerSnapshot() store.Router {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.router
}

type routeSignature struct {
	generation uint64
	identity   string
}
type routeVersion struct {
	epoch    string
	revision uint64
}
type routerHub struct {
	a               *App
	local           *routerSession
	policyMu        sync.Mutex
	blockMu         sync.Mutex
	blockDenials    sync.Map // owner pair -> temporary denial while policy catches up
	revocationMu    sync.Mutex
	revokedRouters  sync.Map // router ID -> temporary denial while policy catches up
	reconcileMu     sync.Mutex
	clients         sync.Map // router ID -> *routerSession
	circuits        sync.Map // circuit UUID -> *wsCircuit
	tombstones      sync.Map // circuit UUID -> expiry time.Time
	running         atomic.Bool
	policy          atomic.Pointer[routerPolicySnapshot]
	reconciliations atomic.Uint64
	draining        atomic.Bool
	lifecycleMu     sync.Mutex
	sessionWG       sync.WaitGroup
}

func newRouterHub(a *App) *routerHub {
	return &routerHub{a: a}
}
func uuidBytes(value string) []byte {
	id, err := uuid.Parse(value)
	if err != nil {
		return nil
	}
	return append([]byte(nil), id[:]...)
}
func uuidString(value []byte) (string, bool) {
	if len(value) != 16 {
		return "", false
	}
	id, err := uuid.FromBytes(value)
	return id.String(), err == nil
}
func (a *App) routerWebSocket(w http.ResponseWriter, r *http.Request) {
	if a.hub.draining.Load() {
		http.Error(w, "service is draining", http.StatusServiceUnavailable)
		return
	}
	requested := websocket.Subprotocols(r)
	subprotocol := ""
	for _, offered := range requested {
		if offered == "snusnu.v2" || offered == "snusnu.v1" {
			subprotocol = offered
			break
		}
	}
	if subprotocol == "" {
		w.Header().Set("Sec-WebSocket-Protocol", "snusnu.v2, snusnu.v1")
		http.Error(w, "snusnu.v2 or snusnu.v1 subprotocol required", http.StatusUpgradeRequired)
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) < 16 {
		http.Error(w, "router bearer token required", http.StatusUnauthorized)
		return
	}
	router, err := a.DB.RouterByToken(r.Context(), parts[1])
	if err != nil {
		http.Error(w, "invalid router credential", http.StatusUnauthorized)
		return
	}
	owner, err := a.DB.UserByID(r.Context(), router.OwnerID)
	if err != nil || !store.ValidNetID(owner.NetID) {
		http.Error(w, "router owner has no valid NETID", http.StatusForbidden)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && origin != a.Config.Origin {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	upgrader := websocket.Upgrader{Subprotocols: []string{subprotocol}, CheckOrigin: func(*http.Request) bool { return true }, ReadBufferSize: 4096, WriteBufferSize: 4096}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	_ = conn.UnderlyingConn().SetDeadline(time.Time{})
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	epoch, err := a.DB.BeginRouterEpoch(r.Context(), router.ID, host)
	if err != nil {
		conn.Close()
		return
	}
	c := &routerSession{router: router, token: parts[1], epoch: epoch, ip: host, allowedNetID: owner.NetID, subprotocol: conn.Subprotocol(), conn: conn, out: newDynamicQueue[outboundMessage](4096, 32<<20, func(x outboundMessage) int { return len(x.data) }), sent: map[string]routeVersion{}, queued: map[string]int{}, history: map[uint64]routeSignature{}, connectedAt: time.Now(), done: make(chan struct{})}
	h := a.hub
	h.revocationMu.Lock()
	_, policyErr := h.loadPolicy(r.Context())
	if policyErr == nil {
		h.clearRevocations()
	}
	policy := h.policy.Load()
	var value liveRouterPolicy
	authorized := false
	if policyErr == nil && policy != nil {
		value, authorized = policy.routers[router.ID]
	}
	if authorized {
		_, authorized = value.credentials[store.Hash(parts[1])]
		authorized = authorized && !value.paused && value.epoch == epoch && value.ownerID == router.OwnerID && value.netID == owner.NetID
	}
	if policyErr != nil || !authorized {
		h.revocationMu.Unlock()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = a.DB.EndRouterEpoch(cleanupCtx, router.ID, epoch)
		cancel()
		conn.Close()
		return
	}
	h.lifecycleMu.Lock()
	if h.draining.Load() {
		h.lifecycleMu.Unlock()
		h.revocationMu.Unlock()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = a.DB.EndRouterEpoch(cleanupCtx, router.ID, epoch)
		cancel()
		conn.Close()
		return
	}
	h.sessionWG.Add(1)
	h.lifecycleMu.Unlock()
	defer h.sessionWG.Done()
	previous, loaded := h.clients.Swap(router.ID, c)
	h.revocationMu.Unlock()
	if loaded {
		h.remove(previous.(*routerSession))
	}
	h.send(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_Welcome{Welcome: &wire.RouterWelcome{RouterId: uuidBytes(router.ID), ConnectionEpoch: uuidBytes(epoch), MaxMessageBytes: maxWSMessage, MaxCircuits: maxWSCircuits, DisplayName: router.DisplayName, AllowedNetid: owner.NetID}}}, "", 0)
	go h.write(c)
	h.reconcileConnect(c)
	if h.running.CompareAndSwap(false, true) {
		go h.tick()
	}
	h.read(c)
}
func (h *routerHub) tick() {
	expiryTicker := time.NewTicker(time.Second)
	policyTicker := time.NewTicker(policyFallbackInterval)
	defer expiryTicker.Stop()
	defer policyTicker.Stop()
	for {
		select {
		case now := <-expiryTicker.C:
			h.expireCircuits(now)
			if h.sessionCount() == 0 {
				h.running.Store(false)
				if h.sessionCount() != 0 && h.running.CompareAndSwap(false, true) {
					continue
				}
				return
			}
		case <-policyTicker.C:
			if h.sessionCount() == 0 {
				continue
			}
			refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			h.blockMu.Lock()
			h.revocationMu.Lock()
			_, err := h.loadPolicy(refreshCtx)
			cancel()
			if err != nil {
				log.Printf("router policy fallback refresh: %v", err)
			} else {
				// A prior block transaction may have committed while its immediate
				// policy reload failed. The successful reload is authoritative.
				h.blockDenials.Range(func(key, _ any) bool {
					h.blockDenials.Delete(key)
					return true
				})
				h.clearRevocations()
			}
			h.revocationMu.Unlock()
			h.blockMu.Unlock()
			if err == nil {
				h.refresh()
			}
		}
	}
}
func (h *routerHub) write(c *routerSession) {
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-c.out.notify:
			msg, ok := c.out.pop(c.done)
			if !ok {
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if !h.outboundAllowed(c, msg) {
				if msg.cost > 0 {
					c.mu.Lock()
					c.queued[msg.circuit] -= msg.cost
					c.mu.Unlock()
				}
				continue
			}
			if err := c.conn.WriteMessage(websocket.BinaryMessage, msg.data); err != nil {
				h.detach(c)
				return
			}
			if msg.cost > 0 {
				c.mu.Lock()
				c.queued[msg.circuit] -= msg.cost
				c.mu.Unlock()
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				h.detach(c)
				return
			}
		}
	}
}
func (h *routerHub) read(c *routerSession) {
	defer h.detach(c)
	c.conn.SetReadLimit(maxWSMessage)
	c.conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
	c.conn.SetPongHandler(func(string) error { return c.conn.SetReadDeadline(time.Now().Add(wsReadTimeout)) })
	for {
		kind, payload, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		if kind != websocket.BinaryMessage {
			return
		}
		var envelope wire.WsEnvelope
		if err := proto.Unmarshal(payload, &envelope); err != nil {
			return
		}
		if !h.isCurrent(c) {
			return
		}
		err = h.handle(c, &envelope)
		if err != nil {
			log.Printf("router %s protocol: %v", c.router.ID, err)
			h.a.enqueueRouterLog(store.LogEntry{RouterID: c.router.ID, Direction: "system", Level: "error", EventType: "protocol", SourceIP: c.ip, Summary: err.Error()})
			return
		}
	}
}
func (h *routerHub) detach(c *routerSession) {
	if h.clients.CompareAndDelete(c.router.ID, c) {
		h.remove(c)
		h.reconcileDisconnect(c)
	}
}
func (h *routerHub) remove(c *routerSession) {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	close(c.done)
	c.out.close(true)
	h.circuits.Range(func(key, value any) bool {
		id, circuit := key.(string), value.(*wsCircuit)
		circuit.mu.Lock()
		if !circuit.closed && (circuit.source == c || circuit.target == c) {
			circuit.closed = true
			circuit.discardQueued.Store(true)
			releaseCircuitValue(circuit)
			peer := circuit.source
			if peer == c {
				peer = circuit.target
			}
			h.send(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: uuidBytes(id), Reason: wire.ResetReason_RESET_REASON_REMOTE_LINK}}}, "", 0)
			h.archiveCircuitLocked(id, circuit, wire.ResetReason_RESET_REASON_REMOTE_LINK.String(), "system", "")
			h.retireCircuit(id, circuit)
		}
		circuit.mu.Unlock()
		return true
	})
	_ = c.conn.Close()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = h.a.DB.EndRouterEpoch(cleanupCtx, c.router.ID, c.epoch)
	cancel()
}
func (h *routerHub) send(c *routerSession, e *wire.WsEnvelope, circuit string, cost int) bool {
	if c == nil || !h.isCurrent(c) || c.closed.Load() {
		return false
	}
	if c.local {
		select {
		case c.localInbox <- proto.Clone(e).(*wire.WsEnvelope):
			return true
		default:
			return false
		}
	}
	data, err := proto.Marshal(e)
	if err != nil || len(data) > maxWSMessage {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() || cost > 0 && c.queued[circuit]+cost > 64*1024 {
		return false
	}
	msg := outboundMessage{data: data, circuit: circuit, cost: cost}
	if circuit != "" {
		value, ok := h.circuits.Load(circuit)
		if !ok {
			return false
		}
		msg.circuitRef = value.(*wsCircuit)
	}
	if route := e.GetOriginRoutes(); route != nil {
		msg.routeOrigin, _ = uuidString(route.RouterId)
	}
	if bindings := e.GetManagedCpBindings(); bindings != nil {
		for _, binding := range bindings.Bindings {
			for _, candidate := range binding.Candidates {
				origin, ok := uuidString(candidate.RouterId)
				if !ok {
					return false
				}
				msg.bindingOrigins = append(msg.bindingOrigins, origin)
			}
		}
	}
	if c.out.push(msg) {
		c.queued[circuit] += cost
		return true
	}
	// A peer exceeding the explicit dynamic queue limits is unhealthy.
	go c.conn.Close()
	return false
}

// Drop queued data and advertisements if a block arrived after enqueue.
func (h *routerHub) outboundAllowed(recipient *routerSession, msg outboundMessage) bool {
	if msg.routeOrigin != "" {
		return h.allowed(recipient, h.session(msg.routeOrigin))
	}
	for _, origin := range msg.bindingOrigins {
		if !h.allowed(recipient, h.session(origin)) {
			return false
		}
	}
	if msg.circuit != "" {
		circuit := msg.circuitRef
		return circuit != nil && !circuit.discardQueued.Load() &&
			h.allowed(circuit.source, circuit.target) && h.routeValid(circuit)
	}
	return true
}
func (h *routerHub) session(id string) *routerSession {
	if h.local != nil && h.local.router.ID == id {
		return h.local
	}
	value, ok := h.clients.Load(id)
	if !ok {
		return nil
	}
	return value.(*routerSession)
}

func (h *routerHub) isCurrent(c *routerSession) bool {
	if c != nil && c.local {
		return h.local == c && !c.closed.Load()
	}
	return c != nil && !c.closed.Load() && h.session(c.router.ID) == c
}

func (h *routerHub) sessions() []*routerSession {
	var result []*routerSession
	h.clients.Range(func(_, value any) bool {
		result = append(result, value.(*routerSession))
		return true
	})
	return result
}

func (h *routerHub) sessionCount() int {
	n := 0
	h.clients.Range(func(_, _ any) bool { n++; return true })
	return n
}

type publishedRoutes struct {
	session  *routerSession
	epoch    string
	snapshot *wire.RouteSnapshot
}

func (h *routerHub) publishedLocked() map[string]publishedRoutes {
	origins := make(map[string]publishedRoutes)
	if h.local != nil {
		origins[h.local.router.ID] = publishedRoutes{session: h.local, epoch: h.local.epoch, snapshot: h.local.snapshot}
	}
	for _, c := range h.sessions() {
		if !h.current(c) || !h.isCurrent(c) {
			continue
		}
		c.mu.Lock()
		if c.snapshot != nil {
			origins[c.router.ID] = publishedRoutes{session: c, epoch: c.epoch, snapshot: proto.Clone(c.snapshot).(*wire.RouteSnapshot)}
		}
		c.mu.Unlock()
	}
	return origins
}

func (h *routerHub) reconcilePairLocked(recipient *routerSession, originID string, origin publishedRoutes) {
	if !h.isCurrent(recipient) {
		return
	}
	recipient.mu.Lock()
	prior, sent := recipient.sent[originID]
	recipient.mu.Unlock()
	if origin.session != nil && origin.session != recipient && h.allowed(recipient, origin.session) {
		version := routeVersion{origin.epoch, origin.snapshot.Revision}
		if sent && prior.epoch != version.epoch {
			if !h.send(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginWithdraw{OriginWithdraw: &wire.OriginWithdraw{RouterId: uuidBytes(originID), Epoch: uuidBytes(prior.epoch)}}}, "", 0) {
				return
			}
			recipient.mu.Lock()
			delete(recipient.sent, originID)
			recipient.mu.Unlock()
		}
		if !sent || prior != version {
			if h.send(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginRoutes{OriginRoutes: &wire.OriginRouteSnapshot{RouterId: uuidBytes(originID), Snapshot: origin.snapshot}}}, "", 0) {
				recipient.mu.Lock()
				recipient.sent[originID] = version
				recipient.mu.Unlock()
			}
		}
		return
	}
	if sent && h.send(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginWithdraw{OriginWithdraw: &wire.OriginWithdraw{RouterId: uuidBytes(originID), Epoch: uuidBytes(prior.epoch)}}}, "", 0) {
		recipient.mu.Lock()
		if recipient.sent[originID] == prior {
			delete(recipient.sent, originID)
		}
		recipient.mu.Unlock()
	}
}

func (h *routerHub) reconcileOrigin(c *routerSession) {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	h.reconciliations.Add(1)
	if !h.isCurrent(c) || !h.current(c) {
		return
	}
	origins := h.publishedLocked()
	origin := origins[c.router.ID]
	for _, recipient := range h.sessions() {
		if recipient != c {
			h.reconcilePairLocked(recipient, c.router.ID, origin)
			if recipient.routerSnapshot().LLCFacing {
				h.refreshBindings(recipient, origins, h.policy.Load())
			}
		}
	}
	h.invalidateCircuitsLocked(c, "")
}

func (h *routerHub) reconcileConnect(c *routerSession) {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	h.reconciliations.Add(1)
	if !h.isCurrent(c) || !h.current(c) {
		return
	}
	origins := h.publishedLocked()
	for id, origin := range origins {
		h.reconcilePairLocked(c, id, origin)
	}
	// Replacement connections have no snapshot yet; withdraw the previous epoch.
	for _, recipient := range h.sessions() {
		if recipient != c {
			h.reconcilePairLocked(recipient, c.router.ID, publishedRoutes{})
			if recipient.routerSnapshot().LLCFacing {
				h.refreshBindings(recipient, origins, h.policy.Load())
			}
		}
	}
	if c.routerSnapshot().LLCFacing {
		h.refreshBindings(c, origins, h.policy.Load())
	}
}

func (h *routerHub) reconcileDisconnect(c *routerSession) {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	h.reconciliations.Add(1)
	origins := h.publishedLocked()
	for _, recipient := range h.sessions() {
		h.reconcilePairLocked(recipient, c.router.ID, publishedRoutes{})
		if recipient.routerSnapshot().LLCFacing {
			h.refreshBindings(recipient, origins, h.policy.Load())
		}
	}
}

func (h *routerHub) reconcileOwnerPair(ownerA, ownerB string) {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	h.reconciliations.Add(1)
	sessions := h.sessions()
	origins := h.publishedLocked()
	policy := h.policy.Load()
	for _, recipient := range sessions {
		if recipient.router.OwnerID != ownerA && recipient.router.OwnerID != ownerB {
			continue
		}
		otherOwner := ownerA
		if recipient.router.OwnerID == ownerA {
			otherOwner = ownerB
		}
		for _, origin := range sessions {
			if origin.router.OwnerID == otherOwner {
				h.reconcilePairLocked(recipient, origin.router.ID, origins[origin.router.ID])
			}
		}
		if recipient.routerSnapshot().LLCFacing {
			h.refreshBindings(recipient, origins, policy)
		}
	}
	h.circuits.Range(func(key, value any) bool {
		id, circuit := key.(string), value.(*wsCircuit)
		a, b := circuit.source.router.OwnerID, circuit.target.router.OwnerID
		if !(a == ownerA && b == ownerB || a == ownerB && b == ownerA) {
			return true
		}
		circuit.mu.Lock()
		if !h.routeValid(circuit) || !h.allowed(circuit.source, circuit.target) {
			h.resetCircuitValue(id, circuit, wire.ResetReason_RESET_REASON_ROUTE_GONE, "system", "")
		}
		circuit.mu.Unlock()
		return true
	})
}

func (h *routerHub) invalidateCircuitsLocked(router *routerSession, otherOwner string) {
	h.circuits.Range(func(key, value any) bool {
		id, circuit := key.(string), value.(*wsCircuit)
		if router != nil && circuit.source != router && circuit.target != router {
			return true
		}
		if otherOwner != "" && !(circuit.source.router.OwnerID == otherOwner || circuit.target.router.OwnerID == otherOwner) {
			return true
		}
		circuit.mu.Lock()
		if !h.routeValid(circuit) || !h.allowed(circuit.source, circuit.target) {
			h.resetCircuitValue(id, circuit, wire.ResetReason_RESET_REASON_ROUTE_GONE, "system", "")
		}
		circuit.mu.Unlock()
		return true
	})
}

func (h *routerHub) refresh() {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	h.refreshLocked()
}

func (h *routerHub) refreshLocked() {
	h.reconciliations.Add(1)
	sessions := h.sessions()
	for _, c := range sessions {
		if !h.current(c) && h.clients.CompareAndDelete(c.router.ID, c) {
			h.remove(c)
		}
	}
	sessions = h.sessions()
	origins := make(map[string]publishedRoutes, len(sessions))
	if h.local != nil {
		origins[h.local.router.ID] = publishedRoutes{session: h.local, epoch: h.local.epoch, snapshot: h.local.snapshot}
	}
	for _, origin := range sessions {
		origin.mu.Lock()
		if origin.snapshot != nil {
			origins[origin.router.ID] = publishedRoutes{session: origin, epoch: origin.epoch, snapshot: proto.Clone(origin.snapshot).(*wire.RouteSnapshot)}
		}
		origin.mu.Unlock()
	}
	for _, recipient := range sessions {
		for id, origin := range origins {
			h.reconcilePairLocked(recipient, id, origin)
		}
		recipient.mu.Lock()
		sent := make(map[string]routeVersion, len(recipient.sent))
		for id, version := range recipient.sent {
			sent[id] = version
		}
		llcFacing := recipient.router.LLCFacing
		recipient.mu.Unlock()
		for id, version := range sent {
			origin, exists := origins[id]
			if !exists || !h.allowed(recipient, origin.session) || origin.epoch != version.epoch {
				if !h.send(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginWithdraw{OriginWithdraw: &wire.OriginWithdraw{RouterId: uuidBytes(id), Epoch: uuidBytes(version.epoch)}}}, "", 0) {
					continue
				}
				recipient.mu.Lock()
				if recipient.sent[id] == version {
					delete(recipient.sent, id)
				}
				recipient.mu.Unlock()
			}
		}
		if llcFacing {
			h.refreshBindings(recipient, origins, h.policy.Load())
		}
	}
	h.circuits.Range(func(key, value any) bool {
		id, circuit := key.(string), value.(*wsCircuit)
		circuit.mu.Lock()
		if !h.routeValid(circuit) || !h.allowed(circuit.source, circuit.target) {
			h.resetCircuitValue(id, circuit, wire.ResetReason_RESET_REASON_ROUTE_GONE, "system", "")
		}
		circuit.mu.Unlock()
		return true
	})
}

func (h *routerHub) refreshBindings(c *routerSession, origins map[string]publishedRoutes, policy *routerPolicySnapshot) {
	c.mu.Lock()
	revision := c.bindingRevision + 1
	c.mu.Unlock()
	if policy == nil {
		return
	}
	// Index CP exports once for this recipient instead of scanning every route
	// for every managed address.
	candidates := make(map[string][]*wire.RouteReference)
	for originID, origin := range origins {
		originPolicy, ok := policy.routers[originID]
		if origin.session != nil && origin.session.local {
			originPolicy = liveRouterPolicy{ownerID: serviceOwnerID}
			ok = true
		}
		if !ok || !h.allowed(c, origin.session) {
			continue
		}
		for _, route := range origin.snapshot.Routes {
			if cp := route.GetControlPoint(); cp != nil {
				key := originPolicy.ownerID + "\x00" + cp.Netid + "\x00" + cp.Name
				candidates[key] = append(candidates[key], &wire.RouteReference{RouterId: uuidBytes(originID), Epoch: uuidBytes(origin.epoch), RouteId: route.Id, RouteGeneration: route.Generation})
			}
		}
	}
	addresses := policy.managed
	if h.local != nil {
		addresses = append(append([]liveManagedAddress(nil), addresses...), liveManagedAddress{
			id: serviceRouterID, ownerID: serviceOwnerID, netID: "SNUSNU", cpName: "SVC", suffix: serviceMACSuffix,
		})
	}
	bindings := make([]*wire.ManagedCpBinding, 0, len(addresses))
	for _, address := range addresses {
		refs := candidates[address.ownerID+"\x00"+address.netID+"\x00"+address.cpName]
		if len(refs) == 0 {
			continue
		}
		sort.Slice(refs, func(i, j int) bool {
			return string(refs[i].RouterId) < string(refs[j].RouterId) || string(refs[i].RouterId) == string(refs[j].RouterId) && refs[i].RouteId < refs[j].RouteId
		})
		mac := store.ManagedCP{Suffix: address.suffix}.MACBytes()
		bindings = append(bindings, &wire.ManagedCpBinding{AddressId: uuidBytes(address.id), ControlPoint: &wire.SnaName{Netid: address.netID, Name: address.cpName}, VirtualMac: mac[:], Candidates: refs})
	}
	next := &wire.ManagedCpBindingSnapshot{SchemaVersion: 1, RecipientEpoch: uuidBytes(c.epoch), Revision: revision, Bindings: bindings}
	c.mu.Lock()
	if c.binding != nil {
		prior := proto.Clone(c.binding).(*wire.ManagedCpBindingSnapshot)
		prior.Revision = next.Revision
		if proto.Equal(prior, next) {
			c.mu.Unlock()
			return
		}
	}
	c.mu.Unlock()
	if h.send(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_ManagedCpBindings{ManagedCpBindings: next}}, "", 0) {
		c.mu.Lock()
		c.binding = next
		c.bindingRevision = revision
		c.mu.Unlock()
	}
}
func (h *routerHub) handle(c *routerSession, e *wire.WsEnvelope) error {
	if !h.current(c) {
		return errors.New("credential revoked or epoch replaced")
	}
	now := time.Now()
	c.mu.Lock()
	if now.Sub(c.rateWindow) >= time.Second {
		c.rateWindow = now
		c.rateCount = 0
	}
	c.rateCount++
	if c.rateCount > 256 {
		c.mu.Unlock()
		return errors.New("router message rate exceeded")
	}
	c.mu.Unlock()
	switch body := e.Body.(type) {
	case *wire.WsEnvelope_PublishRoutes:
		if body.PublishRoutes == nil {
			return errors.New("empty route snapshot")
		}
		if err := h.publish(c, body.PublishRoutes); err != nil {
			return err
		}
		h.reconcileOrigin(c)
	case *wire.WsEnvelope_OpenRequest:
		if h.draining.Load() {
			return errors.New("service is draining")
		}
		return h.open(c, body.OpenRequest)
	case *wire.WsEnvelope_OpenDecision:
		return h.decision(c, body.OpenDecision)
	case *wire.WsEnvelope_CircuitEvent:
		return h.event(c, body.CircuitEvent)
	case *wire.WsEnvelope_CircuitCredit:
		return h.credit(c, body.CircuitCredit)
	case *wire.WsEnvelope_CircuitClose:
		if body.CircuitClose == nil {
			return errors.New("empty circuit close")
		}
		return h.endCircuit(c, body.CircuitClose.CircuitId, false, 0)
	case *wire.WsEnvelope_CircuitReset:
		if body.CircuitReset == nil {
			return errors.New("empty circuit reset")
		}
		return h.endCircuit(c, body.CircuitReset.CircuitId, true, body.CircuitReset.Reason)
	default:
		return errors.New("message direction or type invalid")
	}
	return nil
}
func (h *routerHub) publish(c *routerSession, snapshot *wire.RouteSnapshot) error {
	c.mu.Lock()
	if len(c.history) > 4096 {
		c.mu.Unlock()
		return errors.New("route ID history limit exceeded")
	}
	history := make(map[uint64]routeSignature, len(c.history))
	for id, signature := range c.history {
		history[id] = signature
	}
	c.mu.Unlock()
	epoch, ok := uuidString(snapshot.Epoch)
	if !ok || epoch != c.epoch {
		return store.ErrStaleEpoch
	}
	exports := make([]store.RouteExport, 0, len(snapshot.Routes))
	updates := map[uint64]routeSignature{}
	for _, r := range snapshot.Routes {
		if r == nil {
			return errors.New("nil route")
		}
		x := store.RouteExport{ID: r.Id, Generation: r.Generation}
		switch v := r.Resource.(type) {
		case *wire.RouteExport_ControlPoint:
			if v.ControlPoint == nil {
				return errors.New("empty CP")
			}
			x.Kind = "CP"
			x.NetID = v.ControlPoint.Netid
			x.Name = v.ControlPoint.Name
			if x.NetID != c.allowedNetID {
				return errors.New("route NETID is not owned by router user")
			}
		case *wire.RouteExport_LogicalUnit:
			if v.LogicalUnit == nil || v.LogicalUnit.Lu == nil {
				return errors.New("empty LU")
			}
			x.Kind = "LU"
			x.NetID = v.LogicalUnit.Lu.Netid
			x.Name = v.LogicalUnit.Lu.Name
			if x.NetID != c.allowedNetID {
				return errors.New("route NETID is not owned by router user")
			}
			seenTypes := map[wire.LuType]bool{}
			for _, luType := range v.LogicalUnit.SupportedTypes {
				label := ""
				switch luType {
				case wire.LuType_LU_TYPE_0:
					label = "LU 0"
				case wire.LuType_LU_TYPE_1:
					label = "LU 1"
				case wire.LuType_LU_TYPE_2:
					label = "LU 2"
				case wire.LuType_LU_TYPE_3:
					label = "LU 3"
				case wire.LuType_LU_TYPE_6_2:
					label = "LU 6.2"
				default:
					return errors.New("unsupported LU type")
				}
				if seenTypes[luType] {
					return errors.New("duplicate LU type")
				}
				seenTypes[luType] = true
				x.LUTypes = append(x.LUTypes, label)
			}
			if v.LogicalUnit.HostingCp != nil {
				x.HostingCPNetID = v.LogicalUnit.HostingCp.Netid
				x.HostingCPName = v.LogicalUnit.HostingCp.Name
				if x.HostingCPNetID != c.allowedNetID {
					return errors.New("hosting CP NETID is not owned by router user")
				}
			}
		default:
			return errors.New("route resource absent")
		}
		exports = append(exports, x)
		identity := x.Kind + ":" + x.NetID + ":" + x.Name + ":" + x.HostingCPNetID + ":" + x.HostingCPName
		if previous, seen := history[x.ID]; seen && (x.Generation < previous.generation || (x.Generation == previous.generation && identity != previous.identity)) {
			return errors.New("route ID retargeted without new generation")
		}
		updates[x.ID] = routeSignature{generation: x.Generation, identity: identity}
	}
	persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := h.a.DB.ReplaceRouterSnapshot(persistCtx, c.router.ID, c.epoch, snapshot.Revision, exports)
	cancel()
	if err != nil {
		return err
	}
	if len(exports) > 0 {
		for _, x := range exports {
			if x.Kind == "CP" {
				policyCtx, policyCancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, policyErr := h.loadPolicy(policyCtx)
				policyCancel()
				if policyErr != nil {
					log.Printf("refresh managed CP policy: %v", policyErr)
				}
				break
			}
		}
	}
	if !h.isCurrent(c) {
		return store.ErrStaleEpoch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = proto.Clone(snapshot).(*wire.RouteSnapshot)
	for id, sig := range updates {
		c.history[id] = sig
	}
	return nil
}
