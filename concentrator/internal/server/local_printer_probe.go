package server

import (
	"fmt"
	"log"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/friedkiwi/snusnu/sna/piu"
	"github.com/friedkiwi/snusnu/sna/xid3"
)

type printerProbeCircuit struct {
	peer      sna.Peer
	xid       *xid3.Activation
	profile   wire.CircuitProfile
	allowance uint64
}

type localPrinterProbe struct {
	hub      *routerHub
	circuits map[string]*printerProbeCircuit
}

func newLocalPrinterProbe(h *routerHub) *localPrinterProbe {
	return &localPrinterProbe{hub: h, circuits: make(map[string]*printerProbeCircuit)}
}

func (h *routerHub) findLocalProbeTarget(netID, lu string) *wire.RouteReference {
	var target *wire.RouteReference
	h.clients.Range(func(_, value any) bool {
		session := value.(*routerSession)
		session.mu.Lock()
		defer session.mu.Unlock()
		if session.snapshot == nil || session.closed.Load() {
			return true
		}
		for _, route := range session.snapshot.Routes {
			unit := route.GetLogicalUnit()
			if unit == nil || unit.Lu == nil || unit.Lu.Netid != netID || unit.Lu.Name != lu || !sourceLUSupports62(route) {
				continue
			}
			target = &wire.RouteReference{RouterId: uuidBytes(session.router.ID), Epoch: uuidBytes(session.epoch), RouteId: route.Id, RouteGeneration: route.Generation}
			return false
		}
		return true
	})
	return target
}

func (p *localPrinterProbe) handle(envelope *wire.WsEnvelope, source LocalPeer) {
	if envelope == nil {
		return
	}
	if result := envelope.GetOpenResult(); result != nil {
		log.Printf("printer probe outbound result: request=%d accepted=%t reason=%s circuit=%x peer=%s.%s", result.RequestId, result.Accepted, result.Reason, result.CircuitId, source.NetID, source.LU)
		if result.Accepted {
			p.acceptOutbound(result, source)
		}
		return
	}
	if open := envelope.GetIncomingOpen(); open != nil {
		p.open(open, source)
		return
	}
	var idBytes []byte
	switch body := envelope.Body.(type) {
	case *wire.WsEnvelope_CircuitEvent:
		idBytes = body.CircuitEvent.CircuitId
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
	c := p.circuits[id]
	if c == nil {
		return
	}
	p.hub.a.debugSNA("printer probe circuit=%s before_event state=%+v xid=%+v", id, c, c.xid)
	defer func() { p.hub.a.debugSNA("printer probe circuit=%s after_event state=%+v xid=%+v", id, c, c.xid) }()
	if envelope.GetCircuitClose() != nil || envelope.GetCircuitReset() != nil {
		log.Printf("printer probe circuit closed: %s", id)
		delete(p.circuits, id)
		return
	}
	event := envelope.GetCircuitEvent()
	if event == nil {
		return
	}
	var err error
	switch value := event.Event.(type) {
	case *wire.CircuitEvent_Type1:
		err = p.type1(id, c, value.Type1)
	case *wire.CircuitEvent_LinkReady:
		log.Printf("printer probe link ready: circuit=%s peer=%s.%s", id, c.peer.NetID, c.peer.CP)
	case *wire.CircuitEvent_SnaInformation:
		parsed, parseErr := piu.ParseFID2(value.SnaInformation)
		if parseErr != nil {
			err = parseErr
		} else {
			log.Printf("printer probe PIU: circuit=%s th=%x rh=%x ru=%x", id, parsed.TH, parsed.RH, parsed.RU)
			c.allowance += uint64(len(value.SnaInformation))
			err = p.hub.credit(p.hub.local, &wire.CircuitCredit{CircuitId: idBytes, AllowanceBytes: c.allowance})
		}
	case *wire.CircuitEvent_SessionEvent:
		cost, wireErr := validateSessionWireEvent(value.SessionEvent)
		if wireErr != nil {
			err = wireErr
		} else {
			log.Printf("printer probe session: circuit=%s event=%s", id, value.SessionEvent.String())
			if cost > 0 {
				c.allowance += uint64(cost)
				err = p.hub.credit(p.hub.local, &wire.CircuitCredit{CircuitId: idBytes, AllowanceBytes: c.allowance})
			}
		}
	}
	if err != nil {
		log.Printf("printer probe circuit %s error: %v", id, err)
		delete(p.circuits, id)
		p.hub.resetCircuit(id, wire.ResetReason_RESET_REASON_PROTOCOL)
	}
}

func (p *localPrinterProbe) acceptOutbound(result *wire.OpenResult, source LocalPeer) {
	id, ok := uuidString(result.CircuitId)
	peer := source.SNAPeer()
	if !ok || !peer.Valid() || len(p.circuits) >= 64 {
		return
	}
	local, err := xid3.NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x46}, 1, xid3.Secondary)
	if err != nil {
		return
	}
	xid, err := xid3.NewActivation(local)
	if err != nil {
		return
	}
	p.circuits[id] = &printerProbeCircuit{peer: peer, xid: xid, profile: wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1, allowance: 1500}
}

func (p *localPrinterProbe) open(open *wire.IncomingOpen, source LocalPeer) {
	id, ok := uuidString(open.CircuitId)
	peer := source.SNAPeer()
	if !ok || !peer.Valid() || open.Target == nil || open.Target.RouteId != 3 || len(p.circuits) >= 64 ||
		(open.Profile != wire.CircuitProfile_CIRCUIT_PROFILE_NATIVE_DLC && open.Profile != wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1) {
		_ = p.hub.decision(p.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Reason: wire.OpenFailure_OPEN_FAILURE_FORBIDDEN})
		return
	}
	local, err := xid3.NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x46}, 1, xid3.Secondary)
	if err != nil {
		log.Printf("printer probe XID: %v", err)
		return
	}
	xid, err := xid3.NewActivation(local)
	if err != nil {
		log.Printf("printer probe activation: %v", err)
		return
	}
	p.circuits[id] = &printerProbeCircuit{peer: peer, xid: xid, profile: open.Profile, allowance: 1500}
	if err := p.hub.decision(p.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Accept: true, ReceiveAllowanceBytes: 1500}); err != nil {
		delete(p.circuits, id)
		return
	}
	log.Printf("printer probe open: circuit=%s peer=%s.%s profile=%s", id, peer.NetID, peer.CP, open.Profile)
}

func (p *localPrinterProbe) type1(id string, c *printerProbeCircuit, input *wire.DlcType1) error {
	if c.profile != wire.CircuitProfile_CIRCUIT_PROFILE_NATIVE_DLC || input == nil || input.Dsap != 4 || input.Ssap != 4 {
		return fmt.Errorf("invalid printer probe type-1 event")
	}
	var out []byte
	var err error
	switch input.Kind {
	case wire.Type1Kind_TYPE1_KIND_XID:
		if len(input.Information) == 0 {
			out, err = c.xid.OnNull()
		} else {
			out, err = c.xid.OnPeer(input.Information)
		}
	case wire.Type1Kind_TYPE1_KIND_TEST:
		if input.Response {
			return nil
		}
		out = append([]byte(nil), input.Information...)
	default:
		return fmt.Errorf("unsupported printer probe type-1 event")
	}
	if err != nil {
		return err
	}
	response := &wire.DlcType1{Kind: input.Kind, Response: !input.Response, PollFinal: input.PollFinal, Dsap: 4, Ssap: 4, Information: out}
	if err := p.hub.event(p.hub.local, &wire.CircuitEvent{CircuitId: uuidBytes(id), Event: &wire.CircuitEvent_Type1{Type1: response}}); err != nil {
		return err
	}
	if input.Kind == wire.Type1Kind_TYPE1_KIND_XID {
		return c.xid.ConfirmSent(out)
	}
	return nil
}
