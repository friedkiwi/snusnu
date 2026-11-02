package server

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/google/uuid"
)

const serviceRouterID = "00000000-0000-4000-8000-000000000001"
const serviceOwnerID = "concentrator"
const serviceMACSuffix = 0xffffff

// LocalPeer is stamped from the authenticated router session and its live LU
// advertisement. Services can use OwnerID to keep per-user data isolated.
type LocalPeer struct {
	RouterID, OwnerID, NetID, CP, LU string
}

func (p LocalPeer) SNAPeer() sna.Peer {
	return sna.Peer{Principal: p.OwnerID, NetID: p.NetID, CP: p.CP, LU: p.LU}
}

type localDelivery struct {
	Envelope *wire.WsEnvelope
	Peer     LocalPeer
}

// localService is a concentrator-owned LU hosted by SNUSNU.SVC. The handler
// decides an incoming open synchronously and receives subsequent events for
// that circuit. Source authorization is specific to the service and profile.
type localService struct {
	LU           string
	Types        []wire.LuType
	AcceptSource func(*wire.RouteExport, wire.CircuitProfile) bool
	Handle       func(*wire.WsEnvelope, LocalPeer)
}

type localServiceRegistry struct {
	hub       *routerHub
	byRoute   map[uint64]localService
	byCircuit map[string]uint64 // Accessed only by the local-delivery goroutine.
}

func localLUTypeLabel(kind wire.LuType) string {
	switch kind {
	case wire.LuType_LU_TYPE_0:
		return "LU 0"
	case wire.LuType_LU_TYPE_1:
		return "LU 1"
	case wire.LuType_LU_TYPE_2:
		return "LU 2"
	case wire.LuType_LU_TYPE_3:
		return "LU 3"
	case wire.LuType_LU_TYPE_4:
		return "LU 4"
	case wire.LuType_LU_TYPE_6_1:
		return "LU 6.1"
	case wire.LuType_LU_TYPE_6_2:
		return "LU 6.2"
	case wire.LuType_LU_TYPE_7:
		return "LU 7"
	default:
		return ""
	}
}

func (s *localServiceRegistry) accepts(ref *wire.RouteReference, source *wire.RouteExport, profile wire.CircuitProfile) bool {
	if ref == nil {
		return false
	}
	service, ok := s.byRoute[ref.RouteId]
	return ok && service.AcceptSource(source, profile)
}

func (s *localServiceRegistry) handle(envelope *wire.WsEnvelope, peer LocalPeer) {
	if envelope == nil {
		return
	}
	if open := envelope.GetIncomingOpen(); open != nil {
		service, ok := s.byRoute[open.Target.GetRouteId()]
		if !ok {
			_ = s.hub.decision(s.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Reason: wire.OpenFailure_OPEN_FAILURE_UNSUPPORTED})
			return
		}
		id, ok := uuidString(open.CircuitId)
		if !ok {
			return
		}
		service.Handle(envelope, peer)
		if value, active := s.hub.circuits.Load(id); active {
			c := value.(*wsCircuit)
			c.mu.Lock()
			pending := c.pending
			c.mu.Unlock()
			if pending {
				_ = s.hub.decision(s.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Reason: wire.OpenFailure_OPEN_FAILURE_UNSUPPORTED})
				return
			}
			s.byCircuit[id] = open.Target.RouteId
		}
		return
	}
	var idBytes []byte
	switch body := envelope.Body.(type) {
	case *wire.WsEnvelope_OpenReady:
		idBytes = body.OpenReady.CircuitId
	case *wire.WsEnvelope_CircuitEvent:
		idBytes = body.CircuitEvent.CircuitId
	case *wire.WsEnvelope_CircuitCredit:
		idBytes = body.CircuitCredit.CircuitId
	case *wire.WsEnvelope_CircuitClose:
		idBytes = body.CircuitClose.CircuitId
	case *wire.WsEnvelope_CircuitReset:
		idBytes = body.CircuitReset.CircuitId
	default:
		return
	}
	id, ok := uuidString(idBytes)
	if !ok {
		return
	}
	routeID, ok := s.byCircuit[id]
	if !ok {
		return
	}
	if envelope.GetCircuitClose() != nil || envelope.GetCircuitReset() != nil {
		delete(s.byCircuit, id)
	}
	s.byRoute[routeID].Handle(envelope, peer)
}

var localServiceName = regexp.MustCompile(`^[A-Z@#$][A-Z0-9@#$]{0,7}$`)

// registerLocalServices publishes a CP and its service LUs as one local route
// origin. Register all services before accepting router connections; ctx must
// remain live for the hub's lifetime. Route IDs follow declaration order.
func (h *routerHub) registerLocalServices(ctx context.Context, services ...localService) error {
	if h.local != nil || ctx == nil || len(services) == 0 || len(services) > 255 {
		return errors.New("local services already registered or absent")
	}
	registry := &localServiceRegistry{hub: h, byRoute: make(map[uint64]localService), byCircuit: make(map[string]uint64)}
	epoch := uuid.NewString()
	name := func(value string) *wire.SnaName { return &wire.SnaName{Netid: "SNUSNU", Name: value} }
	routes := []*wire.RouteExport{{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: name("SVC")}}}
	seen := map[string]bool{}
	for i, service := range services {
		if !localServiceName.MatchString(service.LU) || service.LU == "SVC" || seen[service.LU] || len(service.Types) == 0 || service.AcceptSource == nil || service.Handle == nil {
			return errors.New("invalid or duplicate local service")
		}
		types := map[wire.LuType]bool{}
		for _, kind := range service.Types {
			if localLUTypeLabel(kind) == "" || types[kind] {
				return errors.New("invalid or duplicate local service LU type")
			}
			types[kind] = true
		}
		seen[service.LU] = true
		id := uint64(i + 2)
		registry.byRoute[id] = service
		routes = append(routes, &wire.RouteExport{Id: id, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: name(service.LU), HostingCp: name("SVC"), SupportedTypes: append([]wire.LuType(nil), service.Types...)}}})
	}
	local := &routerSession{
		local:      true,
		localInbox: make(chan localDelivery, 256),
		router:     store.Router{ID: serviceRouterID, OwnerID: serviceOwnerID, DisplayName: "SNUSNU services"},
		epoch:      epoch, allowedNetID: "SNUSNU", subprotocol: "snusnu.v2",
		queued: make(map[string]int), connectedAt: time.Now(),
		snapshot: &wire.RouteSnapshot{Epoch: uuidBytes(epoch), Revision: 1, Routes: routes},
	}
	h.local = local
	h.localServices = registry
	go func() {
		for {
			select {
			case delivery := <-local.localInbox:
				registry.handle(delivery.Envelope, delivery.Peer)
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}
