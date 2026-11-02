package server

import (
	"errors"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna/lu62"
	"github.com/friedkiwi/snusnu/sna/services/apingd"
	"google.golang.org/protobuf/proto"
)

// The APING implementation in sna/lu62 owns FID2 address fields internally.
// This private adapter allocates a fixed, isolated address pair for one
// session circuit; neither address is sent on the neutral wire. The source
// and target LU identities come from authenticated OPEN route references.
const virtualFID2DAF = 1
const virtualFID2OAF = 2

func virtualFID2(unit []byte, expedited bool) ([]byte, error) {
	if len(unit) < 5 || len(unit) > 1492 {
		return nil, errLocalSNA
	}
	format := byte(0x2e)
	if expedited {
		format = 0x2f
	}
	piu := []byte{format, 0, virtualFID2DAF, virtualFID2OAF}
	piu = append(piu, unit...)
	return piu, nil
}

func reducedFromVirtual(piu []byte) ([]byte, error) {
	if len(piu) < 9 || len(piu) > 1496 || piu[1] != 0 || piu[2] != virtualFID2OAF || piu[3] != virtualFID2DAF {
		return nil, errLocalSNA
	}
	return append([]byte(nil), piu[4:]...), nil
}

func (s *localSNAService) sendSession(c *localSNACircuit, event *wire.SessionEvent, ack func() error) error {
	cost, err := validateSessionWireEvent(event)
	if err != nil || (cost > 0 && ack == nil) {
		return errLocalSNA
	}
	if err := s.hub.event(s.hub.local, &wire.CircuitEvent{CircuitId: uuidBytes(c.id), Event: &wire.CircuitEvent_SessionEvent{SessionEvent: event}}); err != nil {
		return err
	}
	if _, present := s.hub.circuits.Load(c.id); !present {
		return errLocalSNA
	}
	if cost > 0 {
		c.outboundSent += uint64(cost)
		c.acks = append(c.acks, localSNAAck{end: c.outboundSent, fn: ack})
	}
	return nil
}

func (s *localSNAService) sendSessionPIU(c *localSNACircuit, piu []byte, ack func() error) error {
	reduced, err := reducedFromVirtual(piu)
	if err != nil {
		return err
	}
	return s.sendSession(c, &wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{Expedited: piu[0]&1 != 0, ReducedUnit: reduced}}}, ack)
}

func (s *localSNAService) sendSessionGrant(c *localSNACircuit, piu []byte) error {
	if len(piu) == 0 {
		return nil
	}
	if len(piu) != 9 || !lu62.IsPacingResponse(piu) {
		return errLocalSNA
	}
	return s.sendSession(c, &wire.SessionEvent{Event: &wire.SessionEvent_PacingCredit{PacingCredit: &wire.SessionPacingCredit{Normal: 1}}}, nil)
}

func (s *localSNAService) sessionEvent(c *localSNACircuit, event *wire.SessionEvent) error {
	if c.profile != wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1 {
		return errLocalSNA
	}
	cost, err := validateSessionWireEvent(event)
	if err != nil {
		return err
	}
	if len(c.acks) != 0 {
		if len(c.earlySession) >= 4 {
			return errLocalSNA
		}
		c.earlySession = append(c.earlySession, proto.Clone(event).(*wire.SessionEvent))
		return nil
	}
	if err := s.dispatchSession(c, event); err != nil {
		return err
	}
	if cost > 0 {
		return s.grantInbound(c, cost)
	}
	return nil
}

func (s *localSNAService) drainSessionEarly(c *localSNACircuit) error {
	for len(c.acks) == 0 && len(c.earlySession) != 0 {
		event := c.earlySession[0]
		c.earlySession = c.earlySession[1:]
		cost, err := validateSessionWireEvent(event)
		if err != nil {
			return err
		}
		if err := s.dispatchSession(c, event); err != nil {
			return err
		}
		if cost > 0 {
			if err := s.grantInbound(c, cost); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *localSNAService) dispatchSession(c *localSNACircuit, event *wire.SessionEvent) error {
	switch value := event.Event.(type) {
	case *wire.SessionEvent_BindRequest:
		if c.user != nil || c.management.Phase() != lu62.ManagementAwaitBind {
			return errLocalSNA
		}
		request, err := virtualFID2(value.BindRequest, true)
		if err != nil {
			return err
		}
		bind, err := lu62.ParseBind(request)
		if err != nil || bind == nil {
			return errLocalSNA
		}
		if bind.Mode == "SNASVCMG" {
			management, err := lu62.NewStandaloneManagementSession(c.peer.NetID+"."+c.peer.CP, "SNUSNU.PING")
			if err != nil {
				return err
			}
			response, err := management.PrepareBind(request)
			if err != nil {
				return err
			}
			reduced, err := reducedFromVirtual(response)
			if err != nil {
				return err
			}
			c.management = management
			if err := s.sendSession(c, &wire.SessionEvent{Event: &wire.SessionEvent_BindResult{BindResult: &wire.SessionBindResult{Accepted: true, ReducedUnit: reduced}}}, management.AckBind); err != nil {
				return err
			}
			return management.MarkBindSent(response)
		}
		user, err := lu62.NewStandaloneUserSession(c.peer.NetID+"."+c.peer.LU, "SNUSNU.PING")
		if err != nil {
			return err
		}
		response, err := user.PrepareBind(request)
		if err != nil {
			return err
		}
		reduced, err := reducedFromVirtual(response)
		if err != nil {
			return err
		}
		c.user = user
		if err := s.sendSession(c, &wire.SessionEvent{Event: &wire.SessionEvent_BindResult{BindResult: &wire.SessionBindResult{Accepted: true, ReducedUnit: reduced}}}, user.AckBind); err != nil {
			return err
		}
		return user.MarkBindSent(response)
	case *wire.SessionEvent_Information:
		request, err := virtualFID2(value.Information.ReducedUnit, value.Information.Expedited)
		if err != nil {
			return err
		}
		if c.management.Phase() == lu62.ManagementAwaitCNOS {
			return s.sessionCNOS(c, request)
		}
		if c.management.Phase() == lu62.ManagementCNOSComplete {
			return s.sessionManagementBIS(c, request)
		}
		if c.user == nil {
			return errLocalSNA
		}
		return s.sessionInformation(c, request)
	case *wire.SessionEvent_PacingCredit:
		if value.PacingCredit.Expedited != 0 {
			return errLocalSNA
		}
		if c.management.Phase() == lu62.ManagementAwaitCNOSAck || c.management.Phase() == lu62.ManagementCNOSComplete {
			if value.PacingCredit.Normal != 7 {
				return errLocalSNA
			}
			return c.management.ReceiveIPR([]byte{0x2e, 0, virtualFID2DAF, virtualFID2OAF, 0, 0, 0x83, 1, 0})
		}
		if c.user == nil || value.PacingCredit.Normal != 1 {
			return errLocalSNA
		}
		return c.user.ReceiveIPR([]byte{0x2f, 0, virtualFID2DAF, virtualFID2OAF, 0, 0, 0x83, 1, 0})
	case *wire.SessionEvent_Unbind:
		request, err := virtualFID2(value.Unbind, true)
		if err != nil {
			return err
		}
		if c.management.Phase() == lu62.ManagementBISComplete {
			response, err := c.management.PrepareUnbind(request)
			if err != nil {
				return err
			}
			reduced, err := reducedFromVirtual(response)
			if err != nil {
				return err
			}
			if err := s.sendSession(c, &wire.SessionEvent{Event: &wire.SessionEvent_Unbind{Unbind: reduced}}, c.management.AckUnbind); err != nil {
				return err
			}
			return c.management.MarkUnbindSent(response)
		}
		if c.user == nil {
			return errLocalSNA
		}
		response, err := c.user.PrepareUnbind(request)
		if err != nil {
			return err
		}
		reduced, err := reducedFromVirtual(response)
		if err != nil {
			return err
		}
		if err := s.sendSession(c, &wire.SessionEvent{Event: &wire.SessionEvent_Unbind{Unbind: reduced}}, c.user.AckUnbind); err != nil {
			return err
		}
		return c.user.MarkUnbindSent(response)
	default:
		return errLocalSNA
	}
}

// The neutral session wire omits the carrier's pacing-indicator bit. The
// management responder uses a virtual FID2 PI to generate its local grant;
// the router applies the actual carrier pacing on egress.
func (s *localSNAService) sessionCNOS(c *localSNACircuit, request []byte) error {
	if len(request) < 9 || request[6] != 0x0b || request[7]&^byte(1) != 0x90 || request[8] != 0x20 {
		return errLocalSNA
	}
	request[7] |= 1
	grant, response, err := c.management.PrepareCNOS(request)
	if err != nil {
		return err
	}
	if err := s.sendSessionGrant(c, grant); err != nil {
		return err
	}
	if err := s.sendSessionPIU(c, response, c.management.AckCNOS); err != nil {
		return err
	}
	if err := c.management.MarkCNOSSent(grant, response); err != nil {
		return err
	}
	return c.management.AckCNOS()
}

func (s *localSNAService) sessionManagementBIS(c *localSNACircuit, request []byte) error {
	if len(request) != 10 || request[6] != 0x4b || request[7]&^byte(1) != 0x90 || request[8] != 0 || request[9] != 0x70 {
		return errLocalSNA
	}
	request[7] |= 1
	grant, response, err := c.management.PrepareBIS(request, 2, true)
	if err != nil {
		return err
	}
	if err := s.sendSessionGrant(c, grant); err != nil {
		return err
	}
	if err := s.sendSessionPIU(c, response, c.management.AckBIS); err != nil {
		return err
	}
	if err := c.management.MarkBISSent(grant, response); err != nil {
		return err
	}
	return c.management.AckBIS()
}

func (s *localSNAService) sessionInformation(c *localSNACircuit, request []byte) error {
	if c.user.Phase() == lu62.UserAwaitAttach {
		attach, grant, err := c.user.PrepareAttach(request)
		if err != nil || attach.TPName != "APINGD" {
			return errLocalSNA
		}
		app, err := apingd.NewConversation(c.peer, "OS/400")
		if err != nil {
			return err
		}
		c.aping = app
		if err := s.sendSessionGrant(c, grant); err != nil {
			return err
		}
		return c.user.MarkAttachGrantSent(grant)
	}
	if c.user.Phase() == lu62.UserActive {
		if len(request) >= 12 && request[6] == 0x4b && request[7]&^byte(1) == 0xa0 && request[8] == 1 {
			grant, reply, err := c.user.PrepareConfirm(request)
			if err != nil {
				return err
			}
			if err := s.sendSessionGrant(c, grant); err != nil {
				return err
			}
			if err := s.sendSessionPIU(c, reply, c.user.AckConfirm); err != nil {
				return err
			}
			if err := c.user.MarkConfirmSent(grant, reply); err != nil {
				return err
			}
			if len(grant) != 0 {
				return c.user.AckConfirm()
			}
			return nil
		}
		var responseRU []byte
		var err error
		if !c.appVersioned {
			responseRU, err = c.aping.Version(request[9:])
			if err == nil {
				c.appVersioned = true
			}
		} else {
			noEcho := request[7]&0x20 != 0
			var records [][]byte
			records, err = c.aping.Data(request[9:], !noEcho)
			for _, record := range records {
				responseRU = append(responseRU, record...)
			}
		}
		if err != nil {
			return err
		}
		grant, reply, err := c.user.PrepareMappedTurn(request, responseRU)
		if err != nil {
			return err
		}
		if err := s.sendSessionGrant(c, grant); err != nil {
			return err
		}
		if err := s.sendSessionPIU(c, reply, c.user.AckTurn); err != nil {
			return err
		}
		if err := c.user.MarkTurnSent(grant, reply); err != nil {
			return err
		}
		if len(grant) != 0 {
			return c.user.AckTurn()
		}
		return nil
	}
	if c.user.Phase() == lu62.UserConfirmed {
		grant, reply, err := c.user.PrepareBIS(request)
		if err != nil {
			return err
		}
		if err := s.sendSessionGrant(c, grant); err != nil {
			return err
		}
		if err := s.sendSessionPIU(c, reply, c.user.AckBIS); err != nil {
			return err
		}
		if err := c.user.MarkBISSent(grant, reply); err != nil {
			return err
		}
		return c.user.AckBIS()
	}
	return errors.New("session information in invalid APING phase")
}
