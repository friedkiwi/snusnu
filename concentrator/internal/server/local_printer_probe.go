package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"sync"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/friedkiwi/snusnu/sna/lu62"
	"github.com/friedkiwi/snusnu/sna/piu"
	"github.com/friedkiwi/snusnu/sna/xid3"
)

type printerProbeCircuit struct {
	peer              sna.Peer
	xid               *xid3.Activation
	profile           wire.CircuitProfile
	allowance         uint64
	xidReadyReplySent bool
	linkReadySent     bool
	initiated         bool
	managementPhase   uint8
	fqpcid            []byte
	peerIPR           bool
}

type localPrinterProbe struct {
	hub      *routerHub
	circuits map[string]*printerProbeCircuit
	mu       sync.Mutex
	outbound LocalPeer
}

func newLocalPrinterProbe(h *routerHub) *localPrinterProbe {
	return &localPrinterProbe{hub: h, circuits: make(map[string]*printerProbeCircuit)}
}

func (h *routerHub) findLocalProbeTarget(netID, lu string) (*wire.RouteReference, LocalPeer) {
	var target *wire.RouteReference
	var peer LocalPeer
	h.clients.Range(func(_, value any) bool {
		session := value.(*routerSession)
		session.mu.Lock()
		defer session.mu.Unlock()
		if session.snapshot == nil || session.closed.Load() {
			return true
		}
		for _, route := range session.snapshot.Routes {
			unit := route.GetLogicalUnit()
			if unit == nil || unit.Lu == nil || unit.HostingCp == nil || unit.Lu.Netid != netID || unit.Lu.Name != lu || !sourceLUSupports62(route) {
				continue
			}
			target = &wire.RouteReference{RouterId: uuidBytes(session.router.ID), Epoch: uuidBytes(session.epoch), RouteId: route.Id, RouteGeneration: route.Generation}
			peer = LocalPeer{RouterID: session.router.ID, OwnerID: session.router.OwnerID, NetID: unit.Lu.Netid, CP: unit.HostingCp.Name, LU: unit.Lu.Name}
			return false
		}
		return true
	})
	return target, peer
}

func (p *localPrinterProbe) setOutboundPeer(peer LocalPeer) {
	p.mu.Lock()
	p.outbound = peer
	p.mu.Unlock()
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
			if err == nil && c.initiated {
				err = p.managementInformation(id, c, value.SnaInformation)
			}
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
	if !source.SNAPeer().Valid() {
		p.mu.Lock()
		source = p.outbound
		p.mu.Unlock()
	}
	peer := source.SNAPeer()
	if !ok || !peer.Valid() || len(p.circuits) >= 64 {
		return
	}
	local, err := xid3.NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x46}, 1, xid3.Primary)
	if err != nil {
		return
	}
	xid, err := xid3.NewActivation(local)
	if err != nil {
		return
	}
	p.circuits[id] = &printerProbeCircuit{peer: peer, xid: xid, profile: wire.CircuitProfile_CIRCUIT_PROFILE_NATIVE_DLC, allowance: 1500, initiated: true}
}

func (p *localPrinterProbe) open(open *wire.IncomingOpen, source LocalPeer) {
	id, ok := uuidString(open.CircuitId)
	peer := source.SNAPeer()
	if !ok || !peer.Valid() || open.Target == nil || open.Target.RouteId != 3 || len(p.circuits) >= 64 ||
		(open.Profile != wire.CircuitProfile_CIRCUIT_PROFILE_NATIVE_DLC && open.Profile != wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1) {
		_ = p.hub.decision(p.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Reason: wire.OpenFailure_OPEN_FAILURE_FORBIDDEN})
		return
	}
	local, err := xid3.NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x46}, 1, xid3.Primary)
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
		if c.xid.Ready() && (input.Response || c.xidReadyReplySent) {
			return nil
		}
		if c.xid.Ready() {
			c.xidReadyReplySent = true
		}
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
		if err := c.xid.ConfirmSent(out); err != nil {
			return err
		}
		if c.xid.Ready() && c.xidReadyReplySent && !c.linkReadySent {
			c.linkReadySent = true
			if err := p.hub.event(p.hub.local, &wire.CircuitEvent{CircuitId: uuidBytes(id), Event: &wire.CircuitEvent_LinkReady{LinkReady: &wire.LinkReady{}}}); err != nil {
				return err
			}
			if c.initiated {
				return p.beginManagement(id, c)
			}
		}
	}
	return nil
}

func (p *localPrinterProbe) beginManagement(id string, c *printerProbeCircuit) error {
	var random [14]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	var instance [8]byte
	copy(instance[:], random[:8])
	var token [7]byte
	token[0] = 0x23
	copy(token[1:], random[8:])
	bind, err := lu62.CandidateManagementBind("SNUSNU.SVC", c.peer.NetID+"."+c.peer.CP, 1, 2, instance, token)
	if err != nil {
		return err
	}
	log.Printf("printer probe management BIND: circuit=%s piu=%x", id, bind)
	if err := p.sendInformation(id, bind); err != nil {
		return err
	}
	c.fqpcid, err = lu62.RequestFQPCID(bind)
	if err != nil {
		return err
	}
	c.managementPhase = 1
	return nil
}

func (p *localPrinterProbe) sendInformation(id string, data []byte) error {
	return p.hub.event(p.hub.local, &wire.CircuitEvent{CircuitId: uuidBytes(id), Event: &wire.CircuitEvent_SnaInformation{SnaInformation: data}})
}

func (p *localPrinterProbe) managementInformation(id string, c *printerProbeCircuit, data []byte) error {
	switch c.managementPhase {
	case 1:
		if len(data) < 37 || data[6] != 0xeb || data[9] != 0x31 || data[2] != 2 || data[3] != 1 {
			return nil
		}
		gds, err := lu62.EncodeCNOS(lu62.CNOS{Service: 2, SessionLimit: 8, SourceWinners: 4, TargetWinners: 4, ModeWidth: 8})
		if err != nil {
			return err
		}
		attach := []byte{0x2e, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20, 12, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1}
		attach = append(attach, gds...)
		log.Printf("printer probe management CNOS: circuit=%s piu=%x", id, attach)
		if err := p.sendInformation(id, attach); err != nil {
			return err
		}
		c.managementPhase = 2
	case 2:
		if len(data) < 13 || data[6] != 3 || data[7] != 0x91 || data[8] != 1 {
			return nil
		}
		if _, err := lu62.ParseCNOS(data[9:]); err != nil {
			return err
		}
		if err := p.sendInformation(id, []byte{0x2e, 0, 1, 2, 0, 0, 0x83, 1, 0}); err != nil {
			return err
		}
		if err := p.sendInformation(id, []byte{0x2e, 0, 1, 2, 0, 2, 0x4b, 0x91, 0, 0x70}); err != nil {
			return err
		}
		log.Printf("printer probe management CNOS accepted: circuit=%s", id)
		c.managementPhase = 3
	case 3:
		if len(data) == 9 && data[6] == 0x83 {
			c.peerIPR = true
			return nil
		}
		if len(data) != 10 || data[6] != 0x4b || data[9] != 0x70 || !c.peerIPR {
			return nil
		}
		runbind := []byte{0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}
		runbind = append(runbind, c.fqpcid...)
		if err := p.sendInformation(id, runbind); err != nil {
			return err
		}
		log.Printf("printer probe management BIS accepted: circuit=%s", id)
		c.managementPhase = 4
	case 4:
		if len(data) == 10 && data[6] == 0xeb && data[9] == 0x32 {
			c.managementPhase = 5
			log.Printf("printer probe management complete: circuit=%s", id)
			var pcid [8]byte
			if _, err := rand.Read(pcid[:]); err != nil {
				return err
			}
			bind, err := lu62.Candidate5494ControllerBind("SNUSNU.PRINTER", c.peer.NetID+"."+c.peer.LU, "SNUSNU.SVC", 1, 2, 0x86, pcid)
			if err != nil {
				return err
			}
			log.Printf("printer probe controller BIND: circuit=%s piu=%x", id, bind)
			return p.sendInformation(id, bind)
		}
	case 5:
		if len(data) < 36 || data[6] != 0xeb || data[9] != 0x31 || data[2] != 2 || data[3] != 1 {
			return nil
		}
		// VG10's controller Attach carries a fixed QND5MAIN TPN and one
		// length-qualified PIP GDS. The byte after the 03 20 prefix is a
		// runtime controller value; zero probes the documented boundary.
		attach := []byte{
			0x2e, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20,
			0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4,
			0x30, 0xf0, 0xf6, 0xf6, 0, 0, 0,
			0, 0x12, 0x12, 0xf5, 0, 0x0e, 0x12, 0xe2,
			3, 0x20, 1, 0, 0x38, 4, 4, 0xd4, 7, 0x30,
		}
		log.Printf("printer probe controller Attach: circuit=%s piu=%x", id, attach)
		c.managementPhase = 6
		return p.sendInformation(id, attach)
	}
	return nil
}
