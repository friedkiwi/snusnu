package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type wsCircuit struct {
	source, target *routerSession
	requestID      uint64
	targetRef      *wire.RouteReference
	sourceRef      *wire.RouteReference
	pending        bool
	allowance      [2]uint64 // data bytes each side may send
	sent           [2]uint64
}

func (h *routerHub) circuitCountLocked(c *routerSession) int {
	n := 0
	for _, v := range h.circuits {
		if v.source == c || v.target == c {
			n++
		}
	}
	return n
}
func (h *routerHub) routeValidLocked(c *wsCircuit) bool {
	if h.routeForRefLocked(c.target, c.targetRef) == nil {
		return false
	}
	return c.sourceRef == nil || h.routeForRefLocked(c.source, c.sourceRef) != nil
}

func (h *routerHub) routeForRefLocked(owner *routerSession, ref *wire.RouteReference) *wire.RouteExport {
	if owner == nil || owner.snapshot == nil || ref == nil ||
		string(ref.RouterId) != string(uuidBytes(owner.router.ID)) ||
		string(ref.Epoch) != string(uuidBytes(owner.epoch)) ||
		ref.RouteId == 0 || ref.RouteGeneration == 0 {
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
func (h *routerHub) openLocked(source *routerSession, req *wire.OpenRequest) error {
	if req == nil || req.RequestId == 0 || req.Target == nil || req.ReceiveAllowanceBytes == 0 || req.ReceiveAllowanceBytes > 1<<20 {
		return errors.New("invalid open request")
	}
	for _, v := range h.circuits {
		if v.source == source && v.pending && v.requestID == req.RequestId {
			return errors.New("duplicate outstanding request ID")
		}
	}
	ref := req.Target
	if source.subprotocol == "snusnu.v1" && req.SourceRoute != nil {
		return errors.New("source route requires snusnu.v2")
	}
	if source.subprotocol == "snusnu.v2" && req.SourceRoute == nil {
		return errors.New("snusnu.v2 open requires source LU route")
	}
	if req.SourceRoute != nil && !sourceLUValid(source, h.routeForRefLocked(source, req.SourceRoute)) {
		h.sendLocked(source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: req.RequestId, Accepted: false, Reason: wire.OpenFailure_OPEN_FAILURE_FORBIDDEN}}}, "", 0)
		return nil
	}
	targetID, ok := uuidString(ref.RouterId)
	if !ok || len(ref.Epoch) != 16 || ref.RouteId == 0 || ref.RouteGeneration == 0 {
		return errors.New("invalid route reference")
	}
	target := h.clients[targetID]
	reason := wire.OpenFailure_OPEN_FAILURE_ROUTE_GONE
	if target != nil && target != source {
		if !h.allowedLocked(source, target) {
			reason = wire.OpenFailure_OPEN_FAILURE_FORBIDDEN
		} else if req.SourceRoute != nil && (target.subprotocol != "snusnu.v2" || !sourceLUValid(target, h.routeForRefLocked(target, ref))) {
			reason = wire.OpenFailure_OPEN_FAILURE_UNSUPPORTED
		} else if h.circuitCountLocked(source) >= maxWSCircuits || h.circuitCountLocked(target) >= maxWSCircuits {
			reason = wire.OpenFailure_OPEN_FAILURE_BUSY
		} else {
			candidate := &wsCircuit{source: source, target: target, targetRef: proto.Clone(ref).(*wire.RouteReference)}
			if req.SourceRoute != nil {
				candidate.sourceRef = proto.Clone(req.SourceRoute).(*wire.RouteReference)
			}
			if h.routeValidLocked(candidate) {
				id := uuid.NewString()
				candidate.requestID = req.RequestId
				candidate.pending = true
				candidate.allowance[1] = req.ReceiveAllowanceBytes
				h.circuits[id] = candidate
				if h.sendLocked(target, &wire.WsEnvelope{Body: &wire.WsEnvelope_IncomingOpen{IncomingOpen: &wire.IncomingOpen{CircuitId: uuidBytes(id), SourceRouterId: uuidBytes(source.router.ID), Target: candidate.targetRef, SourceReceiveAllowanceBytes: req.ReceiveAllowanceBytes, SourceRoute: candidate.sourceRef}}}, "", 0) {
					return nil
				}
				delete(h.circuits, id)
				reason = wire.OpenFailure_OPEN_FAILURE_BUSY
			}
		}
	}
	h.sendLocked(source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: req.RequestId, Accepted: false, Reason: reason}}}, "", 0)
	return nil
}
func (h *routerHub) decisionLocked(target *routerSession, decision *wire.OpenDecision) error {
	if decision == nil {
		return errors.New("empty open decision")
	}
	id, ok := uuidString(decision.CircuitId)
	if !ok {
		return errors.New("invalid circuit ID")
	}
	c := h.circuits[id]
	if c == nil || c.target != target || !c.pending {
		return errors.New("unexpected open decision")
	}
	delete(h.circuits, id)
	accepted := decision.Accept && decision.ReceiveAllowanceBytes > 0 && decision.ReceiveAllowanceBytes <= 1<<20 && h.routeValidLocked(c) && h.allowedLocked(c.source, target)
	if decision.Accept && !accepted {
		return errors.New("invalid accepted open")
	}
	if accepted {
		c.pending = false
		c.allowance[0] = decision.ReceiveAllowanceBytes
		h.circuits[id] = c
		// The target must receive OpenReady before the source can send data.
		h.sendLocked(target, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenReady{OpenReady: &wire.OpenReady{CircuitId: decision.CircuitId}}}, "", 0)
	}
	reason := decision.Reason
	if !accepted && reason == wire.OpenFailure_OPEN_FAILURE_UNSPECIFIED {
		reason = wire.OpenFailure_OPEN_FAILURE_PROTOCOL
	}
	h.sendLocked(c.source, &wire.WsEnvelope{Body: &wire.WsEnvelope_OpenResult{OpenResult: &wire.OpenResult{RequestId: c.requestID, CircuitId: func() []byte {
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
func (h *routerHub) findCircuitLocked(sender *routerSession, idBytes []byte) (string, *wsCircuit, int, error) {
	id, ok := uuidString(idBytes)
	if !ok {
		return "", nil, 0, errors.New("invalid circuit ID")
	}
	c := h.circuits[id]
	if c == nil || c.pending {
		return "", nil, 0, errors.New("unknown or pending circuit")
	}
	if c.source == sender {
		return id, c, 0, nil
	}
	if c.target == sender {
		return id, c, 1, nil
	}
	return "", nil, 0, errors.New("circuit sender mismatch")
}
func (h *routerHub) eventLocked(sender *routerSession, event *wire.CircuitEvent) error {
	if event == nil {
		return errors.New("empty circuit event")
	}
	id, c, side, err := h.findCircuitLocked(sender, event.CircuitId)
	if err != nil {
		return err
	}
	if !h.routeValidLocked(c) || !h.allowedLocked(c.source, c.target) {
		h.resetCircuitLocked(id, wire.ResetReason_RESET_REASON_ROUTE_GONE)
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
			return errors.New("invalid SNA information size")
		}
		if c.sent[side] > c.allowance[side] || uint64(cost) > c.allowance[side]-c.sent[side] {
			h.resetCircuitLocked(id, wire.ResetReason_RESET_REASON_CREDIT)
			return nil
		}
	case *wire.CircuitEvent_Type1:
		if value.Type1 == nil || len(value.Type1.Information) > 16*1024 || (value.Type1.Kind != wire.Type1Kind_TYPE1_KIND_XID && value.Type1.Kind != wire.Type1Kind_TYPE1_KIND_TEST) || value.Type1.Dsap < 2 || value.Type1.Dsap > 254 || value.Type1.Dsap%2 != 0 || value.Type1.Ssap < 2 || value.Type1.Ssap > 254 || value.Type1.Ssap%2 != 0 {
			return errors.New("invalid DLC type 1 event")
		}
	case *wire.CircuitEvent_LinkReady:
	default:
		return errors.New("invalid circuit event")
	}
	if !h.sendLocked(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitEvent{CircuitEvent: event}}, id, cost) {
		h.resetCircuitLocked(id, wire.ResetReason_RESET_REASON_PROTOCOL)
		return nil
	}
	c.sent[side] += uint64(cost)
	h.logEventLocked(sender, peer, event)
	return nil
}
func (h *routerHub) creditLocked(sender *routerSession, credit *wire.CircuitCredit) error {
	if credit == nil {
		return errors.New("empty credit")
	}
	id, c, side, err := h.findCircuitLocked(sender, credit.CircuitId)
	if err != nil {
		return err
	}
	if !h.routeValidLocked(c) || !h.allowedLocked(c.source, c.target) {
		h.resetCircuitLocked(id, wire.ResetReason_RESET_REASON_ROUTE_GONE)
		return nil
	}
	other := 1 - side
	if credit.AllowanceBytes <= c.allowance[other] || credit.AllowanceBytes > 1<<32 {
		return errors.New("invalid or nonincreasing credit")
	}
	c.allowance[other] = credit.AllowanceBytes
	peer := c.target
	if side == 1 {
		peer = c.source
	}
	h.sendLocked(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitCredit{CircuitCredit: credit}}, "", 0)
	return nil
}
func (h *routerHub) endCircuitLocked(sender *routerSession, idBytes []byte, reset bool, reason wire.ResetReason) error {
	id, c, side, err := h.findCircuitLocked(sender, idBytes)
	if err != nil {
		return err
	}
	peer := c.target
	if side == 1 {
		peer = c.source
	}
	if reset {
		h.sendLocked(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: idBytes, Reason: reason}}}, "", 0)
	} else {
		h.sendLocked(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitClose{CircuitClose: &wire.CircuitClose{CircuitId: idBytes}}}, "", 0)
	}
	delete(h.circuits, id)
	return nil
}
func (h *routerHub) resetCircuitLocked(id string, reason wire.ResetReason) {
	c := h.circuits[id]
	if c == nil {
		return
	}
	for _, peer := range []*routerSession{c.source, c.target} {
		h.sendLocked(peer, &wire.WsEnvelope{Body: &wire.WsEnvelope_CircuitReset{CircuitReset: &wire.CircuitReset{CircuitId: uuidBytes(id), Reason: reason}}}, "", 0)
	}
	delete(h.circuits, id)
}
func (h *routerHub) logEventLocked(sender, peer *routerSession, event *wire.CircuitEvent) {
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
		_ = h.a.DB.AppendRouterLog(context.Background(), entry)
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
