package server

import (
	"context"
	"errors"
	"regexp"
	"sync"
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
	byCircuit map[string]uint64
	mu        sync.Mutex
	nextID    uint64
	pending   map[uint64]uint64 // request ID -> service route ID
}

// openFrom starts a circuit as a concentrator-owned LU. The result and later
// events are delivered to that service's Handle callback. The target must be
// a live router LU route; the hub validates its owner and generation.
func (s *localServiceRegistry) openFrom(serviceRouteID uint64, target *wire.RouteReference, profile wire.CircuitProfile) (uint64, error) {
	if s == nil || s.hub == nil || s.hub.local == nil || target == nil || serviceRouteID < 2 {
		return 0, errors.New("invalid local service open")
	}
	service, ok := s.byRoute[serviceRouteID]
	if !ok {
		return 0, errors.New("unknown local service")
	}
	if profile == wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1 {
		supports62 := false
		for _, kind := range service.Types {
			supports62 = supports62 || kind == wire.LuType_LU_TYPE_6_2
		}
		if !supports62 {
			return 0, errors.New("session circuit requires LU 6.2 service")
		}
	}
	s.mu.Lock()
	s.nextID++
	requestID := s.nextID
	s.pending[requestID] = serviceRouteID
	s.mu.Unlock()
	source := &wire.RouteReference{RouterId: uuidBytes(serviceRouterID), Epoch: uuidBytes(s.hub.local.epoch), RouteId: serviceRouteID, RouteGeneration: 1}
	err := s.hub.open(s.hub.local, &wire.OpenRequest{RequestId: requestID, SourceRoute: source, Target: target, Profile: profile, ReceiveAllowanceBytes: 1500})
	if err != nil {
		s.mu.Lock()
		delete(s.pending, requestID)
		s.mu.Unlock()
		return 0, err
	}
	return requestID, nil
}

func (s *localServiceRegistry) pendingRoute(requestID uint64) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.pending[requestID]
	return id, ok
}

func (s *localServiceRegistry) bindCircuit(requestID uint64, circuitID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	routeID, ok := s.pending[requestID]
	if ok {
		s.byCircuit[circuitID] = routeID
	}
	return ok
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
	if result := envelope.GetOpenResult(); result != nil {
		s.mu.Lock()
		routeID, ok := s.pending[result.RequestId]
		delete(s.pending, result.RequestId)
		s.mu.Unlock()
		if !ok {
			return
		}
		if result.Accepted {
			if id, valid := uuidString(result.CircuitId); valid {
				s.mu.Lock()
				s.byCircuit[id] = routeID
				s.mu.Unlock()
			}
		}
		s.byRoute[routeID].Handle(envelope, peer)
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
			s.mu.Lock()
			s.byCircuit[id] = open.Target.RouteId
			s.mu.Unlock()
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
	s.mu.Lock()
	routeID, ok := s.byCircuit[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	if envelope.GetCircuitClose() != nil || envelope.GetCircuitReset() != nil {
		delete(s.byCircuit, id)
	}
	s.mu.Unlock()
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
	registry := &localServiceRegistry{hub: h, byRoute: make(map[uint64]localService), byCircuit: make(map[string]uint64), pending: make(map[uint64]uint64)}
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
