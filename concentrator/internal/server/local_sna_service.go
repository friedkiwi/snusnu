package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"time"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/friedkiwi/snusnu/sna/lu62"
	"github.com/friedkiwi/snusnu/sna/piu"
	"github.com/friedkiwi/snusnu/sna/services/apingd"
	"github.com/friedkiwi/snusnu/sna/xid3"
)

var errLocalSNA = errors.New("local SNA service protocol error")
var errLocalEarly = errors.New("local SNA PIU awaits an earlier acknowledgement")

type localSNAAck struct {
	end uint64
	fn  func() error
}

type localSNACircuit struct {
	id               string
	peer             sna.Peer
	profile          wire.CircuitProfile
	xid              *xid3.Activation
	linkReady        bool
	management       *lu62.ManagementSession
	user             *lu62.UserSession
	aping            *apingd.Conversation
	appVersioned     bool
	inboundAllowance uint64
	outboundBase     uint64
	outboundSent     uint64
	acks             []localSNAAck
	early            [][]byte
	earlySession     []*wire.SessionEvent
}

// localSNAService is invoked by the hub's one local-delivery goroutine. Its
// circuit map has the same lifetime as the registered local route origin.
type localSNAService struct {
	hub      *routerHub
	circuits map[string]*localSNACircuit
}

func newLocalSNAService(h *routerHub) *localSNAService {
	return &localSNAService{hub: h, circuits: make(map[string]*localSNACircuit)}
}

// StartLocalSNA publishes the concentrator's registered services for the
// lifetime of ctx. Call it before accepting router connections.
func (a *App) StartLocalSNA(ctx context.Context) error {
	aping := newLocalSNAService(a.hub)
	return a.hub.registerLocalServices(ctx, localService{
		LU: "PING", Types: []wire.LuType{wire.LuType_LU_TYPE_6_2},
		AcceptSource: func(route *wire.RouteExport, _ wire.CircuitProfile) bool { return sourceLUSupports62(route) },
		Handle:       aping.handle,
	})
}

// StartLocalSNAPrinterProbe is for the QA binary's wire investigation. It
// publishes PRINTER and records its first native/session events without
// presenting an incomplete printer service in production.
func (a *App) StartLocalSNAPrinterProbe(ctx context.Context) error {
	aping := newLocalSNAService(a.hub)
	probe := newLocalPrinterProbe(a.hub)
	return a.hub.registerLocalServices(ctx,
		localService{LU: "PING", Types: []wire.LuType{wire.LuType_LU_TYPE_6_2},
			AcceptSource: func(route *wire.RouteExport, _ wire.CircuitProfile) bool { return sourceLUSupports62(route) },
			Handle:       aping.handle},
		localService{LU: "PRINTER", Types: []wire.LuType{wire.LuType_LU_TYPE_6_2},
			AcceptSource: func(route *wire.RouteExport, _ wire.CircuitProfile) bool { return sourceLUSupports62(route) },
			Handle:       probe.handle})
}

// DialLocalSNAPrinterProbe makes one QA-only outbound session attempt once a
// named authenticated LU appears. It is useful for observing whether the
// router can originate the 5494 controller session toward a guest.
func (a *App) DialLocalSNAPrinterProbe(ctx context.Context, netID, lu string) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if target := a.hub.findLocalProbeTarget(netID, lu); target != nil {
				requestID, err := a.hub.localServices.openFrom(3, target, wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1)
				log.Printf("printer probe outbound open: target=%s.%s request=%d err=%v", netID, lu, requestID, err)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *localSNAService) handle(envelope *wire.WsEnvelope, source LocalPeer) {
	if envelope == nil {
		return
	}
	if open := envelope.GetIncomingOpen(); open != nil {
		s.open(open, source)
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
	c := s.circuits[id]
	if c == nil {
		return
	}
	s.debugState(c, "before_event")
	defer s.debugState(c, "after_event")
	if envelope.GetCircuitClose() != nil || envelope.GetCircuitReset() != nil {
		delete(s.circuits, id)
		return
	}
	var err error
	if event := envelope.GetCircuitEvent(); event != nil {
		switch value := event.Event.(type) {
		case *wire.CircuitEvent_Type1:
			err = s.type1(c, value.Type1)
		case *wire.CircuitEvent_LinkReady:
			err = s.linkReady(c)
		case *wire.CircuitEvent_SnaInformation:
			err = s.information(c, value.SnaInformation)
		case *wire.CircuitEvent_SessionEvent:
			err = s.sessionEvent(c, value.SessionEvent)
		default:
			err = errLocalSNA
		}
	}
	if credit := envelope.GetCircuitCredit(); credit != nil {
		err = s.credit(c, credit.AllowanceBytes)
	}
	if err != nil {
		log.Printf("local SNA circuit %s reset: %v (XID ready=%t, link ready=%t, management phase=%d, user active=%t)", id, err, c.xid.Ready(), c.linkReady, c.management.Phase(), c.user != nil)
		delete(s.circuits, id)
		s.hub.resetCircuit(id, wire.ResetReason_RESET_REASON_PROTOCOL)
	}
}

func (s *localSNAService) open(open *wire.IncomingOpen, source LocalPeer) {
	id, ok := uuidString(open.CircuitId)
	peer := source.SNAPeer()
	reject := func() {
		_ = s.hub.decision(s.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Reason: wire.OpenFailure_OPEN_FAILURE_FORBIDDEN})
	}
	if !ok || !peer.Valid() || open.Target == nil || open.Target.RouteId != 2 || open.SourceRoute == nil || len(s.circuits) >= 256 {
		reject()
		return
	}
	localXID, err := xid3.NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x45}, 1, xid3.Secondary)
	if err != nil {
		reject()
		return
	}
	activation, err := xid3.NewActivation(localXID)
	if err != nil {
		reject()
		return
	}
	management, err := lu62.NewManagementSession(peer.NetID+"."+peer.CP, "SNUSNU.SVC")
	if err != nil {
		reject()
		return
	}
	c := &localSNACircuit{id: id, peer: peer, profile: open.Profile, xid: activation, management: management, inboundAllowance: 1500, outboundBase: open.SourceReceiveAllowanceBytes}
	s.circuits[id] = c
	s.debugState(c, "open")
	if err := s.hub.decision(s.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Accept: true, ReceiveAllowanceBytes: c.inboundAllowance}); err != nil {
		delete(s.circuits, id)
	}
}

func (s *localSNAService) type1(c *localSNACircuit, input *wire.DlcType1) error {
	if input == nil || c.linkReady || input.Dsap != 4 || input.Ssap != 4 || len(input.Information) > 255 {
		return errLocalSNA
	}
	var info []byte
	response := !input.Response
	switch input.Kind {
	case wire.Type1Kind_TYPE1_KIND_XID:
		var err error
		if len(input.Information) == 0 {
			info, err = c.xid.OnNull()
		} else {
			info, err = c.xid.OnPeer(input.Information)
		}
		if err != nil {
			return err
		}
	case wire.Type1Kind_TYPE1_KIND_TEST:
		if input.Response {
			return nil
		}
		info = append([]byte(nil), input.Information...)
	default:
		return errLocalSNA
	}
	output := &wire.DlcType1{Kind: input.Kind, Response: response, PollFinal: input.PollFinal, Dsap: 4, Ssap: 4, Information: info}
	if err := s.hub.event(s.hub.local, &wire.CircuitEvent{CircuitId: uuidBytes(c.id), Event: &wire.CircuitEvent_Type1{Type1: output}}); err != nil {
		return err
	}
	if _, present := s.hub.circuits.Load(c.id); !present {
		return errLocalSNA
	}
	if input.Kind == wire.Type1Kind_TYPE1_KIND_XID {
		return c.xid.ConfirmSent(info)
	}
	return nil
}

func (s *localSNAService) linkReady(c *localSNACircuit) error {
	if c.linkReady || !c.xid.Ready() || c.xid.PeerName() != c.peer.NetID+"."+c.peer.CP {
		return errLocalSNA
	}
	c.linkReady = true
	return nil
}

func (s *localSNAService) sendInformation(c *localSNACircuit, data []byte, ack func() error) error {
	if len(data) < 9 || len(data) > 1496 || ack == nil {
		return errLocalSNA
	}
	if err := s.hub.event(s.hub.local, &wire.CircuitEvent{CircuitId: uuidBytes(c.id), Event: &wire.CircuitEvent_SnaInformation{SnaInformation: data}}); err != nil {
		return err
	}
	if _, present := s.hub.circuits.Load(c.id); !present {
		return errLocalSNA
	}
	c.outboundSent += uint64(len(data))
	c.acks = append(c.acks, localSNAAck{end: c.outboundSent, fn: ack})
	return nil
}

func (s *localSNAService) grantInbound(c *localSNACircuit, size int) error {
	if size <= 0 || c.inboundAllowance+uint64(size) > 1<<32 {
		return errLocalSNA
	}
	c.inboundAllowance += uint64(size)
	return s.hub.credit(s.hub.local, &wire.CircuitCredit{CircuitId: uuidBytes(c.id), AllowanceBytes: c.inboundAllowance})
}

func (s *localSNAService) credit(c *localSNACircuit, allowance uint64) error {
	if allowance < c.outboundBase || allowance-c.outboundBase > c.outboundSent {
		return errLocalSNA
	}
	completed := allowance - c.outboundBase
	for len(c.acks) != 0 && c.acks[0].end <= completed {
		ack := c.acks[0]
		c.acks = c.acks[1:]
		if err := ack.fn(); err != nil {
			return err
		}
	}
	if c.profile == wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1 {
		return s.drainSessionEarly(c)
	}
	return s.drainEarly(c)
}

func (s *localSNAService) information(c *localSNACircuit, data []byte) error {
	if !c.linkReady || len(data) < 9 || len(data) > 1496 {
		return errLocalSNA
	}
	if _, err := piu.ParseFID2(data); err != nil {
		return err
	}
	if len(c.acks) != 0 && !isLocalIPR(data) {
		return s.queueEarly(c, data)
	}
	if err := s.dispatch(c, data); err != nil {
		if errors.Is(err, errLocalEarly) {
			return s.queueEarly(c, data)
		}
		return err
	}
	return s.grantInbound(c, len(data))
}

func (s *localSNAService) queueEarly(c *localSNACircuit, data []byte) error {
	if len(c.early) >= 4 {
		return errLocalSNA
	}
	c.early = append(c.early, append([]byte(nil), data...))
	return nil
}

func (s *localSNAService) drainEarly(c *localSNACircuit) error {
	for len(c.acks) == 0 && len(c.early) != 0 {
		data := c.early[0]
		if err := s.dispatch(c, data); err != nil {
			if errors.Is(err, errLocalEarly) {
				return nil
			}
			return err
		}
		c.early = c.early[1:]
		if err := s.grantInbound(c, len(data)); err != nil {
			return err
		}
	}
	return nil
}

func isLocalIPR(data []byte) bool {
	return lu62.IsPacingResponse(data)
}

func (s *localSNAService) dispatch(c *localSNACircuit, data []byte) error {
	if isLocalIPR(data) {
		if c.management.ReceiveIPR(data) == nil {
			return nil
		}
		if c.user != nil && c.user.ReceiveIPR(data) == nil {
			return nil
		}
		return errLocalSNA
	}
	bind, err := lu62.ParseBind(data)
	if err != nil {
		return err
	}
	if bind != nil {
		if bind.Management {
			// V4R4 addresses SNASVCMG to the selected remote location LU
			// when that LU differs from the adjacent CP.
			if c.management.Phase() == lu62.ManagementAwaitBind && bind.SLU == "SNUSNU.PING" {
				management, err := lu62.NewManagementSession(c.peer.NetID+"."+c.peer.CP, bind.SLU)
				if err != nil {
					return err
				}
				c.management = management
			}
			response, err := c.management.PrepareBind(data)
			if err != nil {
				return err
			}
			if err := s.sendInformation(c, response, c.management.AckBind); err != nil {
				return err
			}
			return c.management.MarkBindSent(response)
		}
		if c.management.Phase() < lu62.ManagementBISComplete {
			return errLocalEarly
		}
		if c.user != nil {
			return errLocalSNA
		}
		user, err := lu62.NewUserSession(c.peer.NetID+"."+c.peer.LU, "SNUSNU.PING", c.management.FQPCID())
		if err != nil {
			return err
		}
		response, err := user.PrepareBind(data)
		if err != nil {
			log.Printf("local SNA user BIND rejected: %v (peer=%s.%s, PLU=%s, SLU=%s, mode=%q)", err, c.peer.NetID, c.peer.LU, bind.PLU, bind.SLU, bind.Mode)
			return err
		}
		c.user = user
		if err := s.sendInformation(c, response, user.AckBind); err != nil {
			return err
		}
		return user.MarkBindSent(response)
	}
	if len(data) < 10 {
		return errLocalSNA
	}
	if data[6] == 0x6b && data[9] == 0x32 {
		if c.user != nil && c.user.Phase() == lu62.UserBISComplete && len(data) >= 15 && bytes.Equal(data[15:], c.user.FQPCID()) {
			response, err := c.user.PrepareUnbind(data)
			if err != nil {
				return err
			}
			if err := s.sendInformation(c, response, c.user.AckUnbind); err != nil {
				return err
			}
			return c.user.MarkUnbindSent(response)
		}
		if c.management.Phase() != lu62.ManagementBISComplete {
			return errLocalEarly
		}
		response, err := c.management.PrepareUnbind(data)
		if err != nil {
			return err
		}
		if err := s.sendInformation(c, response, c.management.AckUnbind); err != nil {
			return err
		}
		return c.management.MarkUnbindSent(response)
	}
	if c.management.Phase() == lu62.ManagementAwaitCNOS && data[6] == 0x0b {
		ipr, response, err := c.management.PrepareCNOS(data)
		if err != nil {
			return err
		}
		if err := s.sendInformation(c, ipr, c.management.AckCNOS); err != nil {
			return err
		}
		if err := s.sendInformation(c, response, c.management.AckCNOS); err != nil {
			return err
		}
		return c.management.MarkCNOSSent(ipr, response)
	}
	if c.management.Phase() == lu62.ManagementCNOSComplete && data[6] == 0x4b {
		ipr, response, err := c.management.PrepareBIS(data, 2, true)
		if err != nil {
			return err
		}
		if err := s.sendInformation(c, ipr, c.management.AckBIS); err != nil {
			return err
		}
		if err := s.sendInformation(c, response, c.management.AckBIS); err != nil {
			return err
		}
		return c.management.MarkBISSent(ipr, response)
	}
	if c.user == nil {
		return errLocalEarly
	}
	if c.user.Phase() == lu62.UserAwaitAttach {
		attach, grant, err := c.user.PrepareAttach(data)
		if err != nil || attach.TPName != "APINGD" {
			return errLocalSNA
		}
		app, err := apingd.NewConversation(c.peer, "OS/400")
		if err != nil {
			return err
		}
		c.aping = app
		if err := s.sendInformation(c, grant, func() error { return nil }); err != nil {
			return err
		}
		return c.user.MarkAttachGrantSent(grant)
	}
	if c.user.Phase() == lu62.UserActive {
		if len(data) >= 12 && data[6] == 0x4b && data[7]&^byte(1) == 0xa0 && data[8] == 1 {
			grant, response, err := c.user.PrepareConfirm(data)
			if err != nil {
				return err
			}
			if len(grant) != 0 {
				if err := s.sendInformation(c, grant, c.user.AckConfirm); err != nil {
					return err
				}
			}
			if err := s.sendInformation(c, response, c.user.AckConfirm); err != nil {
				return err
			}
			return c.user.MarkConfirmSent(grant, response)
		}
		var responseRU []byte
		if !c.appVersioned {
			responseRU, err = c.aping.Version(data[9:])
			if err == nil {
				c.appVersioned = true
			}
		} else {
			noEcho := data[7]&0x20 != 0
			var records [][]byte
			records, err = c.aping.Data(data[9:], !noEcho)
			for _, record := range records {
				responseRU = append(responseRU, record...)
			}
		}
		if err != nil {
			return err
		}
		grant, response, err := c.user.PrepareMappedTurn(data, responseRU)
		if err != nil {
			return err
		}
		if len(grant) != 0 {
			if err := s.sendInformation(c, grant, c.user.AckTurn); err != nil {
				return err
			}
		}
		if len(response) != 0 {
			if err := s.sendInformation(c, response, c.user.AckTurn); err != nil {
				return err
			}
		}
		return c.user.MarkTurnSent(grant, response)
	}
	if c.user.Phase() == lu62.UserConfirmed {
		grant, response, err := c.user.PrepareBIS(data)
		if err != nil {
			return err
		}
		if err := s.sendInformation(c, grant, c.user.AckBIS); err != nil {
			return err
		}
		if err := s.sendInformation(c, response, c.user.AckBIS); err != nil {
			return err
		}
		return c.user.MarkBISSent(grant, response)
	}
	return errLocalEarly
}
