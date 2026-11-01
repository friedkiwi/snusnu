package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

const maxWSMessage = 64 * 1024
const maxWSCircuits = 64

type outboundMessage struct {
	data    []byte
	circuit string
	cost    int
}
type routerSession struct {
	router           store.Router
	token, epoch, ip string
	conn             *websocket.Conn
	out              chan outboundMessage
	snapshot         *wire.RouteSnapshot
	sent             map[string]routeVersion
	binding          *wire.ManagedCpBindingSnapshot
	bindingRevision  uint64
	queued           map[string]int
	history          map[uint64]routeSignature
	rateWindow       time.Time
	rateCount        int
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
	a        *App
	mu       sync.Mutex
	clients  map[string]*routerSession
	circuits map[string]*wsCircuit
	running  bool
}

func newRouterHub(a *App) *routerHub {
	return &routerHub{a: a, clients: map[string]*routerSession{}, circuits: map[string]*wsCircuit{}}
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
	if r.Header.Get("Sec-WebSocket-Protocol") != "snusnu.v1" {
		w.Header().Set("Sec-WebSocket-Protocol", "snusnu.v1")
		http.Error(w, "snusnu.v1 subprotocol required", http.StatusUpgradeRequired)
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
	origin := r.Header.Get("Origin")
	if origin != "" && origin != a.Config.Origin {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	upgrader := websocket.Upgrader{Subprotocols: []string{"snusnu.v1"}, CheckOrigin: func(*http.Request) bool { return true }, ReadBufferSize: 4096, WriteBufferSize: 4096}
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
	c := &routerSession{router: router, token: parts[1], epoch: epoch, ip: host, conn: conn, out: make(chan outboundMessage, 16), sent: map[string]routeVersion{}, queued: map[string]int{}, history: map[uint64]routeSignature{}}
	h := a.hub
	h.mu.Lock()
	if previous := h.clients[router.ID]; previous != nil {
		h.removeLocked(previous)
	}
	h.clients[router.ID] = c
	h.sendLocked(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_Welcome{Welcome: &wire.RouterWelcome{RouterId: uuidBytes(router.ID), ConnectionEpoch: uuidBytes(epoch), MaxMessageBytes: maxWSMessage, MaxCircuits: maxWSCircuits, DisplayName: router.DisplayName}}}, "", 0)
	h.refreshLocked()
	if !h.running {
		h.running = true
		go h.tick()
	}
	h.mu.Unlock()
	go h.write(c)
	h.read(c)
}
func (h *routerHub) tick() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		if len(h.clients) == 0 {
			h.running = false
			h.mu.Unlock()
			return
		}
		h.refreshLocked()
		h.mu.Unlock()
	}
}
func (h *routerHub) write(c *routerSession) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg, ok := <-c.out:
			if !ok {
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.BinaryMessage, msg.data); err != nil {
				h.detach(c)
				return
			}
			if msg.cost > 0 {
				h.mu.Lock()
				c.queued[msg.circuit] -= msg.cost
				h.mu.Unlock()
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
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
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error { return c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)) })
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
		h.mu.Lock()
		if h.clients[c.router.ID] != c {
			h.mu.Unlock()
			return
		}
		err = h.handleLocked(c, &envelope)
		h.mu.Unlock()
		if err != nil {
			log.Printf("router %s protocol: %v", c.router.ID, err)
			_ = h.a.DB.AppendRouterLog(context.Background(), store.LogEntry{RouterID: c.router.ID, Direction: "system", Level: "error", EventType: "protocol", SourceIP: c.ip, Summary: err.Error()})
			return
		}
	}
}
func (h *routerHub) detach(c *routerSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.router.ID] == c {
		h.removeLocked(c)
		h.refreshLocked()
	}
}
func (h *routerHub) removeLocked(c *routerSession) {
	if h.clients[c.router.ID] != c {
		return
	}
	delete(h.clients, c.router.ID)
	for id, circuit := range h.circuits {
		if circuit.source == c || circuit.target == c {
			peer := circuit.source
			if peer == c {
				peer = circuit.target
			}
			h.sendLocked(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: uuidBytes(id), Reason: wire.ResetReason_RESET_REASON_REMOTE_LINK}}}, "", 0)
			delete(h.circuits, id)
		}
	}
	_ = h.a.DB.EndRouterEpoch(context.Background(), c.router.ID, c.epoch)
	close(c.out)
	_ = c.conn.Close()
}
func (h *routerHub) sendLocked(c *routerSession, e *wire.WsEnvelope, circuit string, cost int) bool {
	if c == nil || h.clients[c.router.ID] != c {
		return false
	}
	data, err := proto.Marshal(e)
	if err != nil || len(data) > maxWSMessage {
		return false
	}
	if cost > 0 && c.queued[circuit]+cost > 64*1024 {
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
func (h *routerHub) currentLocked(c *routerSession) bool {
	r, err := h.a.DB.RouterByToken(context.Background(), c.token)
	if err != nil || r.ID != c.router.ID {
		return false
	}
	if c.router.LLCFacing && !r.LLCFacing {
		return false
	}
	var epoch string
	if err := h.a.DB.Row(context.Background(), "SELECT epoch FROM router_epochs WHERE router_id=?", c.router.ID).Scan(&epoch); err != nil || epoch != c.epoch {
		return false
	}
	if r.DisplayName != c.router.DisplayName {
		c.router.DisplayName = r.DisplayName
		h.sendLocked(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_IdentityUpdate{IdentityUpdate: &wire.RouterIdentityUpdate{DisplayName: r.DisplayName}}}, "", 0)
	}
	c.router.LLCFacing = r.LLCFacing
	return true
}
func (h *routerHub) refreshLocked() {
	for _, c := range h.clients {
		if !h.currentLocked(c) {
			h.removeLocked(c)
		}
	}
	for _, recipient := range h.clients {
		for id, origin := range h.clients {
			if origin == recipient || origin.snapshot == nil {
				continue
			}
			allowed, err := h.a.DB.CanForward(context.Background(), recipient.router.ID, origin.router.ID)
			if err != nil || !allowed {
				continue
			}
			version := routeVersion{origin.epoch, origin.snapshot.Revision}
			if recipient.sent[id] != version {
				if h.sendLocked(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginRoutes{OriginRoutes: &wire.OriginRouteSnapshot{RouterId: uuidBytes(id), Snapshot: origin.snapshot}}}, "", 0) {
					recipient.sent[id] = version
				}
			}
		}
		for id, version := range recipient.sent {
			origin := h.clients[id]
			allowed := false
			if origin != nil && origin.snapshot != nil {
				allowed, _ = h.a.DB.CanForward(context.Background(), recipient.router.ID, id)
			}
			if origin == nil || origin.snapshot == nil || !allowed || origin.epoch != version.epoch {
				h.sendLocked(recipient, &wire.WsEnvelope{Body: &wire.WsEnvelope_OriginWithdraw{OriginWithdraw: &wire.OriginWithdraw{RouterId: uuidBytes(id), Epoch: uuidBytes(version.epoch)}}}, "", 0)
				delete(recipient.sent, id)
			}
		}
		if recipient.router.LLCFacing {
			h.refreshBindingsLocked(recipient)
		}
	}
	for id, circuit := range h.circuits {
		if !h.routeValidLocked(circuit) || !h.allowedLocked(circuit.source, circuit.target) {
			h.resetCircuitLocked(id, wire.ResetReason_RESET_REASON_ROUTE_GONE)
		}
	}
}
func (h *routerHub) refreshBindingsLocked(c *routerSession) {
	projection, err := h.a.DB.BuildManagedBindingSnapshot(context.Background(), c.router.ID, c.epoch, c.bindingRevision+1)
	if err != nil {
		return
	}
	bindings := make([]*wire.ManagedCpBinding, 0, len(projection.Bindings))
	for _, b := range projection.Bindings {
		refs := make([]*wire.RouteReference, 0, len(b.Candidates))
		for _, ref := range b.Candidates {
			refs = append(refs, &wire.RouteReference{RouterId: uuidBytes(ref.RouterID), Epoch: uuidBytes(ref.Epoch), RouteId: uint64(ref.RouteID), RouteGeneration: uint64(ref.Generation)})
		}
		bindings = append(bindings, &wire.ManagedCpBinding{AddressId: uuidBytes(b.AddressID), ControlPoint: &wire.SnaName{Netid: b.NetID, Name: b.CPName}, VirtualMac: b.MAC[:], Candidates: refs})
	}
	next := &wire.ManagedCpBindingSnapshot{SchemaVersion: 1, RecipientEpoch: uuidBytes(c.epoch), Revision: c.bindingRevision + 1, Bindings: bindings}
	if c.binding != nil {
		prior := proto.Clone(c.binding).(*wire.ManagedCpBindingSnapshot)
		prior.Revision = next.Revision
		if proto.Equal(prior, next) {
			return
		}
	}
	if h.sendLocked(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_ManagedCpBindings{ManagedCpBindings: next}}, "", 0) {
		c.binding = next
		c.bindingRevision++
	}
}
func (h *routerHub) allowedLocked(source, target *routerSession) bool {
	if source == nil || target == nil || h.clients[source.router.ID] != source || h.clients[target.router.ID] != target {
		return false
	}
	allowed, err := h.a.DB.CanForward(context.Background(), source.router.ID, target.router.ID)
	return err == nil && allowed
}
func (h *routerHub) handleLocked(c *routerSession, e *wire.WsEnvelope) error {
	if !h.currentLocked(c) {
		return errors.New("credential revoked or epoch replaced")
	}
	now := time.Now()
	if now.Sub(c.rateWindow) >= time.Second {
		c.rateWindow = now
		c.rateCount = 0
	}
	c.rateCount++
	if c.rateCount > 256 {
		return errors.New("router message rate exceeded")
	}
	switch body := e.Body.(type) {
	case *wire.WsEnvelope_PublishRoutes:
		if body.PublishRoutes == nil {
			return errors.New("empty route snapshot")
		}
		if err := h.publishLocked(c, body.PublishRoutes); err != nil {
			return err
		}
		h.refreshLocked()
	case *wire.WsEnvelope_OpenRequest:
		return h.openLocked(c, body.OpenRequest)
	case *wire.WsEnvelope_OpenDecision:
		return h.decisionLocked(c, body.OpenDecision)
	case *wire.WsEnvelope_CircuitEvent:
		return h.eventLocked(c, body.CircuitEvent)
	case *wire.WsEnvelope_CircuitCredit:
		return h.creditLocked(c, body.CircuitCredit)
	case *wire.WsEnvelope_CircuitClose:
		if body.CircuitClose == nil {
			return errors.New("empty circuit close")
		}
		return h.endCircuitLocked(c, body.CircuitClose.CircuitId, false, 0)
	case *wire.WsEnvelope_CircuitReset:
		if body.CircuitReset == nil {
			return errors.New("empty circuit reset")
		}
		return h.endCircuitLocked(c, body.CircuitReset.CircuitId, true, body.CircuitReset.Reason)
	default:
		return errors.New("message direction or type invalid")
	}
	return nil
}
func (h *routerHub) publishLocked(c *routerSession, snapshot *wire.RouteSnapshot) error {
	if len(c.history) > 4096 {
		return errors.New("route ID history limit exceeded")
	}
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
		case *wire.RouteExport_LogicalUnit:
			if v.LogicalUnit == nil || v.LogicalUnit.Lu == nil {
				return errors.New("empty LU")
			}
			x.Kind = "LU"
			x.NetID = v.LogicalUnit.Lu.Netid
			x.Name = v.LogicalUnit.Lu.Name
			if v.LogicalUnit.HostingCp != nil {
				x.HostingCPNetID = v.LogicalUnit.HostingCp.Netid
				x.HostingCPName = v.LogicalUnit.HostingCp.Name
			}
		default:
			return errors.New("route resource absent")
		}
		exports = append(exports, x)
		identity := x.Kind + ":" + x.NetID + ":" + x.Name + ":" + x.HostingCPNetID + ":" + x.HostingCPName
		if previous, seen := c.history[x.ID]; seen && (x.Generation < previous.generation || (x.Generation == previous.generation && identity != previous.identity)) {
			return errors.New("route ID retargeted without new generation")
		}
		updates[x.ID] = routeSignature{generation: x.Generation, identity: identity}
	}
	if err := h.a.DB.ReplaceRouterSnapshot(context.Background(), c.router.ID, c.epoch, snapshot.Revision, exports); err != nil {
		return err
	}
	c.snapshot = proto.Clone(snapshot).(*wire.RouteSnapshot)
	for id, sig := range updates {
		c.history[id] = sig
	}
	return nil
}
