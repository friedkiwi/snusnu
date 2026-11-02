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

type outboundMessage struct {
	data    []byte
	circuit string
	cost    int
}
type routerSession struct {
	mu                             sync.Mutex
	router                         store.Router
	token, epoch, ip, allowedNetID string
	subprotocol                    string
	conn                           *websocket.Conn
	out                            chan outboundMessage
	snapshot                       *wire.RouteSnapshot
	sent                           map[string]routeVersion
	binding                        *wire.ManagedCpBindingSnapshot
	bindingRevision                uint64
	queued                         map[string]int
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
	policyMu        sync.Mutex
	reconcileMu     sync.Mutex
	clients         sync.Map // router ID -> *routerSession
	circuits        sync.Map // circuit UUID -> *wsCircuit
	tombstones      sync.Map // circuit UUID -> expiry time.Time
	running         atomic.Bool
	policy          atomic.Pointer[routerPolicySnapshot]
	reconciliations atomic.Uint64
	draining        atomic.Bool
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
	c := &routerSession{router: router, token: parts[1], epoch: epoch, ip: host, allowedNetID: owner.NetID, subprotocol: conn.Subprotocol(), conn: conn, out: make(chan outboundMessage, 16), sent: map[string]routeVersion{}, queued: map[string]int{}, history: map[uint64]routeSignature{}, connectedAt: time.Now(), done: make(chan struct{})}
	h := a.hub
	if _, err := h.loadPolicy(r.Context()); err != nil {
		conn.Close()
		return
	}
	if previous, loaded := h.clients.Swap(router.ID, c); loaded {
		h.remove(previous.(*routerSession))
	}
	h.send(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_Welcome{Welcome: &wire.RouterWelcome{RouterId: uuidBytes(router.ID), ConnectionEpoch: uuidBytes(epoch), MaxMessageBytes: maxWSMessage, MaxCircuits: maxWSCircuits, DisplayName: router.DisplayName, AllowedNetid: owner.NetID}}}, "", 0)
	h.refresh()
	if h.running.CompareAndSwap(false, true) {
		go h.tick()
	}
	go h.write(c)
	h.read(c)
}
func (h *routerHub) tick() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.expireCircuits(time.Now())
		if h.sessionCount() == 0 {
			h.running.Store(false)
			if h.sessionCount() != 0 && h.running.CompareAndSwap(false, true) {
				continue
			}
			return
		}
		refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := h.refreshPolicyAndRoutes(refreshCtx)
		cancel()
		if err != nil {
			log.Printf("router policy refresh: %v", err)
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
		case msg := <-c.out:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
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
		h.refresh()
	}
}
func (h *routerHub) remove(c *routerSession) {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	close(c.done)
	h.circuits.Range(func(key, value any) bool {
		id, circuit := key.(string), value.(*wsCircuit)
		circuit.mu.Lock()
		if !circuit.closed && (circuit.source == c || circuit.target == c) {
			circuit.closed = true
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
	data, err := proto.Marshal(e)
	if err != nil || len(data) > maxWSMessage {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() || cost > 0 && c.queued[circuit]+cost > 64*1024 {
		return false
	}
	select {
	case c.out <- outboundMessage{data: data, circuit: circuit, cost: cost}:
		c.queued[circuit] += cost
		return true
	default:
		// A slow receiver must not block route publication or another circuit.
		go c.conn.Close()
		return false
	}
}
func (h *routerHub) session(id string) *routerSession {
	value, ok := h.clients.Load(id)
	if !ok {
		return nil
	}
	return value.(*routerSession)
}

func (h *routerHub) isCurrent(c *routerSession) bool {
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

func (h *routerHub) refresh() {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	h.reconciliations.Add(1)
	sessions := h.sessions()
	for _, c := range sessions {
		if !h.current(c) && h.clients.CompareAndDelete(c.router.ID, c) {
			h.remove(c)
		}
	}
	sessions = h.sessions()
	origins := make(map[string]publishedRoutes, len(sessions))
	for _, origin := range sessions {
		origin.mu.Lock()
		if origin.snapshot != nil {
			origins[origin.router.ID] = publishedRoutes{session: origin, epoch: origin.epoch, snapshot: proto.Clone(origin.snapshot).(*wire.RouteSnapshot)}
		}
		origin.mu.Unlock()
	}
	for _, recipient := range sessions {
		for id, origin := range origins {
			if origin.session == recipient || !h.allowed(recipient, origin.session) {
				continue
			}
			version := routeVersion{origin.epoch, origin.snapshot.Revision}
			recipient.mu.Lock()
			prior := recipient.sent[id]
			recipient.mu.Unlock()
			if prior != version && h.send(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginRoutes{OriginRoutes: &wire.OriginRouteSnapshot{RouterId: uuidBytes(id), Snapshot: origin.snapshot}}}, "", 0) {
				recipient.mu.Lock()
				recipient.sent[id] = version
				recipient.mu.Unlock()
			}
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
				h.send(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginWithdraw{OriginWithdraw: &wire.OriginWithdraw{RouterId: uuidBytes(id), Epoch: uuidBytes(version.epoch)}}}, "", 0)
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
	bindings := make([]*wire.ManagedCpBinding, 0, len(policy.managed))
	for _, address := range policy.managed {
		var refs []*wire.RouteReference
		for originID, origin := range origins {
			originPolicy, ok := policy.routers[originID]
			if !ok || originPolicy.ownerID != address.ownerID || !policy.allows(c.router.ID, originID) {
				continue
			}
			for _, route := range origin.snapshot.Routes {
				cp := route.GetControlPoint()
				if cp != nil && cp.Netid == address.netID && cp.Name == address.cpName {
					refs = append(refs, &wire.RouteReference{RouterId: uuidBytes(originID), Epoch: uuidBytes(origin.epoch), RouteId: route.Id, RouteGeneration: route.Generation})
				}
			}
		}
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
		h.refresh()
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
