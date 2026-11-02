package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type wsCircuit struct {
	mu             sync.Mutex
	source, target *routerSession
	requestID      uint64
	targetRef      *wire.RouteReference
	sourceRef      *wire.RouteReference
	pending        bool
	allowance      [2]uint64 // data bytes each side may send
	sent           [2]uint64
	openedAt       time.Time
	activatedAt    time.Time
	lastActivityAt time.Time
	events         [2]uint64
	peakQueued     uint64
	closed         bool
	counted        bool
}

var errCircuitClosed = errors.New("circuit is already closed")

func (h *routerHub) retireCircuit(id string, c *wsCircuit) {
	h.circuits.CompareAndDelete(id, c)
	h.tombstones.Store(id, time.Now().Add(time.Minute))
}

func (h *routerHub) isTombstoned(id string) bool {
	value, ok := h.tombstones.Load(id)
	return ok && time.Now().Before(value.(time.Time))
}

func (h *routerHub) expireCircuits(now time.Time) {
	h.tombstones.Range(func(key, value any) bool {
		if !now.Before(value.(time.Time)) {
			h.tombstones.Delete(key)
		}
		return true
	})
	h.circuits.Range(func(key, value any) bool {
		id, c := key.(string), value.(*wsCircuit)
		c.mu.Lock()
		if !c.closed && c.pending && now.Sub(c.openedAt) >= 10*time.Second {
			h.send(c.source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: c.requestID, Accepted: false, Reason: wire.OpenFailure_OPEN_FAILURE_BUSY}}}, "", 0)
			h.send(c.target, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: uuidBytes(id), Reason: wire.ResetReason_RESET_REASON_REMOTE_LINK}}}, "", 0)
			c.closed = true
			releaseCircuitValue(c)
			h.archiveCircuitLocked(id, c, "open timeout", "system", "")
			h.retireCircuit(id, c)
		}
		c.mu.Unlock()
		return true
	})
}

func (h *routerHub) circuitCount(c *routerSession) int {
	return int(c.circuitCount.Load())
}

func reservePendingRequest(c *routerSession, requestID uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingRequests == nil {
		c.pendingRequests = make(map[uint64]struct{})
	}
	if _, exists := c.pendingRequests[requestID]; exists {
		return false
	}
	c.pendingRequests[requestID] = struct{}{}
	return true
}

func releasePendingRequest(c *routerSession, requestID uint64) {
	c.mu.Lock()
	delete(c.pendingRequests, requestID)
	c.mu.Unlock()
}

// releaseCircuitRequest requires c.mu. Pending circuits own their source
// request reservation from insertion until their opening resolves or teardown.
func releaseCircuitRequest(c *wsCircuit) {
	if !c.pending {
		return
	}
	c.pending = false
	releasePendingRequest(c.source, c.requestID)
}

func reserveCircuit(source, target *routerSession) bool {
	if source.circuitCount.Add(1) > maxWSCircuits {
		source.circuitCount.Add(-1)
		return false
	}
	if target.circuitCount.Add(1) > maxWSCircuits {
		target.circuitCount.Add(-1)
		source.circuitCount.Add(-1)
		return false
	}
	return true
}

// releaseCircuitValue requires c.mu and releases each reservation once.
func releaseCircuitValue(c *wsCircuit) {
	releaseCircuitRequest(c)
	if !c.counted {
		return
	}
	c.counted = false
	c.source.circuitCount.Add(-1)
	c.target.circuitCount.Add(-1)
}
func (h *routerHub) routeValid(c *wsCircuit) bool {
	if h.routeForRef(c.target, c.targetRef) == nil {
		return false
	}
	return c.sourceRef == nil || h.routeForRef(c.source, c.sourceRef) != nil
}

func (h *routerHub) routeForRef(owner *routerSession, ref *wire.RouteReference) *wire.RouteExport {
	if owner == nil || ref == nil ||
		string(ref.RouterId) != string(uuidBytes(owner.router.ID)) ||
		string(ref.Epoch) != string(uuidBytes(owner.epoch)) ||
		ref.RouteId == 0 || ref.RouteGeneration == 0 {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.snapshot == nil {
		return nil
	}
	for _, route := range owner.snapshot.Routes {
		if route.Id == ref.RouteId && route.Generation == ref.RouteGeneration {
			return route
		}
	}
	return nil
}

func sourceLUValid(owner *routerSession, route *wire.RouteExport) bool {
	if owner == nil || route == nil || route.GetLogicalUnit() == nil || route.GetLogicalUnit().Lu == nil {
		return false
	}
	return route.GetLogicalUnit().Lu.Netid == owner.allowedNetID
}
func (h *routerHub) open(source *routerSession, req *wire.OpenRequest) error {
	if req == nil || req.RequestId == 0 || req.Target == nil || req.ReceiveAllowanceBytes == 0 || req.ReceiveAllowanceBytes > 1<<20 {
		return errors.New("invalid open request")
	}
	if !reservePendingRequest(source, req.RequestId) {
		return errors.New("duplicate outstanding request ID")
	}
	requestOwnedByCircuit := false
	defer func() {
		if !requestOwnedByCircuit {
			releasePendingRequest(source, req.RequestId)
		}
	}()
	ref := req.Target
	if source.subprotocol == "snusnu.v1" && req.SourceRoute != nil {
		return errors.New("source route requires snusnu.v2")
	}
	if source.subprotocol == "snusnu.v2" && req.SourceRoute == nil {
		return errors.New("snusnu.v2 open requires source LU route")
	}
	if req.SourceRoute != nil && !sourceLUValid(source, h.routeForRef(source, req.SourceRoute)) {
		h.send(source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: req.RequestId, Accepted: false, Reason: wire.OpenFailure_OPEN_FAILURE_FORBIDDEN}}}, "", 0)
		return nil
	}
	targetID, ok := uuidString(ref.RouterId)
	if !ok || len(ref.Epoch) != 16 || ref.RouteId == 0 || ref.RouteGeneration == 0 {
		return errors.New("invalid route reference")
	}
	target := h.session(targetID)
	reason := wire.OpenFailure_OPEN_FAILURE_ROUTE_GONE
	if target != nil && target != source {
		if !h.allowed(source, target) {
			reason = wire.OpenFailure_OPEN_FAILURE_FORBIDDEN
		} else if req.SourceRoute != nil && (target.subprotocol != "snusnu.v2" || !sourceLUValid(target, h.routeForRef(target, ref))) {
			reason = wire.OpenFailure_OPEN_FAILURE_UNSUPPORTED
		} else if h.circuitCount(source) >= maxWSCircuits || h.circuitCount(target) >= maxWSCircuits {
			reason = wire.OpenFailure_OPEN_FAILURE_BUSY
		} else {
			candidate := &wsCircuit{source: source, target: target, targetRef: proto.Clone(ref).(*wire.RouteReference), openedAt: time.Now(), lastActivityAt: time.Now()}
			if req.SourceRoute != nil {
				candidate.sourceRef = proto.Clone(req.SourceRoute).(*wire.RouteReference)
			}
			if h.routeValid(candidate) {
				if !reserveCircuit(source, target) {
					reason = wire.OpenFailure_OPEN_FAILURE_BUSY
				} else {
					candidate.counted = true
					id := uuid.NewString()
					candidate.requestID = req.RequestId
					candidate.pending = true
					candidate.allowance[1] = req.ReceiveAllowanceBytes
					h.circuits.Store(id, candidate)
					requestOwnedByCircuit = true
					if h.send(target, &wire.WsEnvelope{Body: &wire.WsEnvelope_IncomingOpen{IncomingOpen: &wire.IncomingOpen{CircuitId: uuidBytes(id), SourceRouterId: uuidBytes(source.router.ID), Target: candidate.targetRef, SourceReceiveAllowanceBytes: req.ReceiveAllowanceBytes, SourceRoute: candidate.sourceRef}}}, "", 0) {
						return nil
					}
					h.circuits.CompareAndDelete(id, candidate)
					candidate.mu.Lock()
					releaseCircuitValue(candidate)
					candidate.mu.Unlock()
					reason = wire.OpenFailure_OPEN_FAILURE_BUSY
				}
			}
		}
	}
	h.send(source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: req.RequestId, Accepted: false, Reason: reason}}}, "", 0)
	return nil
}
func (h *routerHub) decision(target *routerSession, decision *wire.OpenDecision) error {
	if decision == nil {
		return errors.New("empty open decision")
	}
	id, ok := uuidString(decision.CircuitId)
	if !ok {
		return errors.New("invalid circuit ID")
	}
	value, found := h.circuits.Load(id)
	if !found {
		if h.isTombstoned(id) {
			return nil
		}
		return errors.New("unexpected open decision")
	}
	c := value.(*wsCircuit)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.target != target || !c.pending {
		return errors.New("unexpected open decision")
	}
	h.circuits.CompareAndDelete(id, c)
	accepted := decision.Accept && decision.ReceiveAllowanceBytes > 0 && decision.ReceiveAllowanceBytes <= 1<<20 && h.routeValid(c) && h.allowed(c.source, target)
	if decision.Accept && !accepted {
		h.send(c.source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: c.requestID, Accepted: false, Reason: wire.OpenFailure_OPEN_FAILURE_PROTOCOL}}}, "", 0)
		c.closed = true
		releaseCircuitValue(c)
		h.archiveCircuitLocked(id, c, "invalid open acceptance", "router", target.router.ID)
		h.retireCircuit(id, c)
		return errors.New("invalid accepted open")
	}
	if accepted {
		releaseCircuitRequest(c)
		c.activatedAt = time.Now()
		c.lastActivityAt = c.activatedAt
		c.allowance[0] = decision.ReceiveAllowanceBytes
		h.circuits.Store(id, c)
		// The target must receive OpenReady before the source can send data.
		h.send(target, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenReady{OpenReady: &wire.OpenReady{CircuitId: decision.CircuitId}}}, "", 0)
	}
	reason := decision.Reason
	if !accepted && reason == wire.OpenFailure_OPEN_FAILURE_UNSPECIFIED {
		reason = wire.OpenFailure_OPEN_FAILURE_PROTOCOL
	}
	if !accepted {
		c.closed = true
		releaseCircuitValue(c)
		h.archiveCircuitLocked(id, c, reason.String(), "router", target.router.ID)
		h.retireCircuit(id, c)
	}
	h.send(c.source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: c.requestID, CircuitId: func() []byte {
		if accepted {
			return decision.CircuitId
		}
		return nil
	}(), Accepted: accepted, PeerReceiveAllowanceBytes: func() uint64 {
		if accepted {
			return decision.ReceiveAllowanceBytes
		}
		return 0
	}(), Reason: reason}}}, "", 0)
	return nil
}

// findCircuit returns a circuit with its mutex held. The caller must unlock it.
func (h *routerHub) findCircuit(sender *routerSession, idBytes []byte) (string, *wsCircuit, int, error) {
	id, ok := uuidString(idBytes)
	if !ok {
		return "", nil, 0, errors.New("invalid circuit ID")
	}
	value, found := h.circuits.Load(id)
	if !found {
		if h.isTombstoned(id) {
			return "", nil, 0, errCircuitClosed
		}
		return "", nil, 0, errors.New("unknown or pending circuit")
	}
	c := value.(*wsCircuit)
	c.mu.Lock()
	if c.closed || c.pending {
		c.mu.Unlock()
		return "", nil, 0, errors.New("unknown or pending circuit")
	}
	if c.source == sender {
		return id, c, 0, nil
	}
	if c.target == sender {
		return id, c, 1, nil
	}
	c.mu.Unlock()
	return "", nil, 0, errors.New("circuit sender mismatch")
}
func (h *routerHub) event(sender *routerSession, event *wire.CircuitEvent) error {
	if event == nil {
		return errors.New("empty circuit event")
	}
	id, c, side, err := h.findCircuit(sender, event.CircuitId)
	if err != nil {
		if errors.Is(err, errCircuitClosed) {
			return nil
		}
		return err
	}
	if !h.routeValid(c) || !h.allowed(c.source, c.target) {
		h.resetCircuitValue(id, c, wire.ResetReason_RESET_REASON_ROUTE_GONE, "system", "")
		c.mu.Unlock()
		return nil
	}
	peer := c.target
	if side == 1 {
		peer = c.source
	}
	cost := 0
	switch value := event.Event.(type) {
	case *wire.CircuitEvent_SnaInformation:
		cost = len(value.SnaInformation)
		if cost == 0 || cost > 16*1024 {
			c.mu.Unlock()
			return errors.New("invalid SNA information size")
		}
		if c.sent[side] > c.allowance[side] || uint64(cost) > c.allowance[side]-c.sent[side] {
			h.resetCircuitValue(id, c, wire.ResetReason_RESET_REASON_CREDIT, "system", "")
			c.mu.Unlock()
			return nil
		}
	case *wire.CircuitEvent_Type1:
		if value.Type1 == nil || len(value.Type1.Information) > 16*1024 || (value.Type1.Kind != wire.Type1Kind_TYPE1_KIND_XID && value.Type1.Kind != wire.Type1Kind_TYPE1_KIND_TEST) || value.Type1.Dsap < 2 || value.Type1.Dsap > 254 || value.Type1.Dsap%2 != 0 || value.Type1.Ssap < 2 || value.Type1.Ssap > 254 || value.Type1.Ssap%2 != 0 {
			c.mu.Unlock()
			return errors.New("invalid DLC type 1 event")
		}
	case *wire.CircuitEvent_LinkReady:
	default:
		c.mu.Unlock()
		return errors.New("invalid circuit event")
	}
	if !h.send(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitEvent{CircuitEvent: event}}, id, cost) {
		h.resetCircuitValue(id, c, wire.ResetReason_RESET_REASON_PROTOCOL, "system", "")
		c.mu.Unlock()
		return nil
	}
	c.sent[side] += uint64(cost)
	c.events[side]++
	c.lastActivityAt = time.Now()
	peer.mu.Lock()
	queued := uint64(peer.queued[id])
	peer.mu.Unlock()
	if queued > c.peakQueued {
		c.peakQueued = queued
	}
	c.mu.Unlock()
	h.logEvent(sender, peer, event)
	return nil
}
func (h *routerHub) credit(sender *routerSession, credit *wire.CircuitCredit) error {
	if credit == nil {
		return errors.New("empty credit")
	}
	id, c, side, err := h.findCircuit(sender, credit.CircuitId)
	if err != nil {
		if errors.Is(err, errCircuitClosed) {
			return nil
		}
		return err
	}
	if !h.routeValid(c) || !h.allowed(c.source, c.target) {
		h.resetCircuitValue(id, c, wire.ResetReason_RESET_REASON_ROUTE_GONE, "system", "")
		c.mu.Unlock()
		return nil
	}
	other := 1 - side
	if credit.AllowanceBytes <= c.allowance[other] || credit.AllowanceBytes > 1<<32 {
		c.mu.Unlock()
		return errors.New("invalid or nonincreasing credit")
	}
	c.allowance[other] = credit.AllowanceBytes
	c.lastActivityAt = time.Now()
	peer := c.target
	if side == 1 {
		peer = c.source
	}
	c.mu.Unlock()
	h.send(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitCredit{CircuitCredit: credit}}, "", 0)
	return nil
}
func (h *routerHub) endCircuit(sender *routerSession, idBytes []byte, reset bool, reason wire.ResetReason) error {
	id, c, side, err := h.findCircuit(sender, idBytes)
	if err != nil {
		if errors.Is(err, errCircuitClosed) {
			return nil
		}
		return err
	}
	peer := c.target
	if side == 1 {
		peer = c.source
	}
	if reset {
		h.send(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: idBytes, Reason: reason}}}, "", 0)
	} else {
		h.send(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitClose{CircuitClose: &wire.CircuitClose{CircuitId: idBytes}}}, "", 0)
	}
	h.archiveCircuitLocked(id, c, func() string {
		if reset {
			return reason.String()
		}
		return "normal close"
	}(), "router", sender.router.ID)
	c.closed = true
	releaseCircuitValue(c)
	h.retireCircuit(id, c)
	c.mu.Unlock()
	return nil
}
func (h *routerHub) resetCircuit(id string, reason wire.ResetReason) {
	h.resetCircuitBy(id, reason, "system", "")
}

func (h *routerHub) resetCircuitBy(id string, reason wire.ResetReason, actorType, actorID string, historyReason ...string) {
	value, found := h.circuits.Load(id)
	if !found {
		return
	}
	c := value.(*wsCircuit)
	c.mu.Lock()
	defer c.mu.Unlock()
	h.resetCircuitValue(id, c, reason, actorType, actorID, historyReason...)
}

// resetCircuitValue requires c.mu to be held.
func (h *routerHub) resetCircuitValue(id string, c *wsCircuit, reason wire.ResetReason, actorType, actorID string, historyReason ...string) {
	if c.closed {
		return
	}
	c.closed = true
	releaseCircuitValue(c)
	for _, peer := range []*routerSession{c.source, c.target} {
		h.send(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: uuidBytes(id), Reason: reason}}}, "", 0)
	}
	archivedReason := reason.String()
	if len(historyReason) != 0 && historyReason[0] != "" {
		archivedReason = historyReason[0]
	}
	h.archiveCircuitLocked(id, c, archivedReason, actorType, actorID)
	h.retireCircuit(id, c)
}
func (h *routerHub) logEvent(sender, peer *routerSession, event *wire.CircuitEvent) {
	// Keep previews bounded. The LLC endpoints own full SNA packet decoding.
	kind := "SNA information"
	size := 0
	details := map[string]any{"circuit_id": uuidBytesString(event.CircuitId)}
	switch v := event.Event.(type) {
	case *wire.CircuitEvent_Type1:
		kind = "DLC type 1"
		size = len(v.Type1.Information)
		details["type1_kind"] = v.Type1.Kind.String()
		details["response"] = v.Type1.Response
		details["poll_final"] = v.Type1.PollFinal
		details["dsap"] = v.Type1.Dsap
		details["ssap"] = v.Type1.Ssap
		details["information_hex_prefix"] = hexPrefix(v.Type1.Information)
	case *wire.CircuitEvent_LinkReady:
		kind = "link ready"
	case *wire.CircuitEvent_SnaInformation:
		size = len(v.SnaInformation)
		details["information_hex_prefix"] = hexPrefix(v.SnaInformation)
	}
	details["bytes"] = size
	encoded, _ := json.Marshal(details)
	for _, x := range []struct {
		router, peer *routerSession
		direction    string
	}{{sender, peer, "outbound"}, {peer, sender, "inbound"}} {
		entry := storeLog(x.router, x.peer, x.direction, kind, string(encoded))
		entry.SourceIP = sender.ip
		h.a.enqueueRouterLog(entry)
	}
}

func hexPrefix(data []byte) string {
	if len(data) > 128 {
		data = data[:128]
	}
	return hex.EncodeToString(data)
}
func uuidBytesString(value []byte) string { id, _ := uuidString(value); return id }
func storeLog(router, peer *routerSession, direction, kind, details string) store.LogEntry {
	return store.LogEntry{RouterID: router.router.ID, PeerUserID: peer.router.OwnerID, Direction: direction, Level: "info", EventType: kind, SourceIP: router.ip, Summary: kind + " relayed through concentrator", DetailsJSON: details}
}
