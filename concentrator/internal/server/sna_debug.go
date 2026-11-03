package server

import (
	"log"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna/piu"
)

// debugSNA writes to the process logger, which defaults to stderr. It is
// deliberately separate from persistent router logs: full RUs can contain
// application data and are only emitted when the operator enables tracing.
func (a *App) debugSNA(format string, args ...any) {
	if a.Config.SNADebug {
		log.Printf("SNA debug: "+format, args...)
	}
}

func (h *routerHub) debugCircuitState(id, action string, c *wsCircuit) {
	if !h.a.Config.SNADebug {
		return
	}
	h.a.debugSNA("circuit=%s action=%s source=%s target=%s source_peer=%+v target_peer=%+v request_id=%d source_route=%v target_route=%v profile=%s pending=%t closed=%t counted=%t discard_queued=%t allowance=%v sent=%v events=%v queued_peak=%d opened_at=%s activated_at=%s last_activity_at=%s",
		id, action, c.source.router.ID, c.target.router.ID,
		c.sourcePeer, c.targetPeer, c.requestID, c.sourceRef, c.targetRef,
		c.profile, c.pending, c.closed, c.counted, c.discardQueued.Load(), c.allowance, c.sent, c.events, c.peakQueued,
		c.openedAt.Format("2006-01-02T15:04:05.000000000Z07:00"), c.activatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"), c.lastActivityAt.Format("2006-01-02T15:04:05.000000000Z07:00"))
}

func (h *routerHub) debugCircuitEvent(id string, side int, event *wire.CircuitEvent) {
	if !h.a.Config.SNADebug {
		return
	}
	switch value := event.Event.(type) {
	case *wire.CircuitEvent_Type1:
		v := value.Type1
		if v == nil {
			h.a.debugSNA("circuit=%s side=%d type1=nil", id, side)
			return
		}
		h.a.debugSNA("circuit=%s side=%d type1 kind=%s response=%t poll_final=%t dsap=%d ssap=%d data=%x",
			id, side, v.Kind, v.Response, v.PollFinal, v.Dsap, v.Ssap, v.Information)
	case *wire.CircuitEvent_LinkReady:
		h.a.debugSNA("circuit=%s side=%d link_ready", id, side)
	case *wire.CircuitEvent_SnaInformation:
		parsed, err := piu.ParseFID2(value.SnaInformation)
		if err != nil {
			h.a.debugSNA("circuit=%s side=%d fid2_parse_error=%v data=%x", id, side, err, value.SnaInformation)
		} else {
			h.a.debugSNA("circuit=%s side=%d fid2 th=%x rh=%x ru=%x", id, side, parsed.TH, parsed.RH, parsed.RU)
		}
	case *wire.CircuitEvent_SessionEvent:
		h.a.debugSNA("circuit=%s side=%d session_event=%v", id, side, value.SessionEvent)
	default:
		h.a.debugSNA("circuit=%s side=%d unsupported_event=%T", id, side, event.Event)
	}
}

func (s *localSNAService) debugState(c *localSNACircuit, action string) {
	if !s.hub.a.Config.SNADebug {
		return
	}
	userPhase := -1
	userFQPCID := []byte(nil)
	if c.user != nil {
		userPhase = int(c.user.Phase())
		userFQPCID = c.user.FQPCID()
	}
	s.hub.a.debugSNA("local circuit=%s action=%s peer=%s.%s.%s profile=%s xid_ready=%t link_ready=%t management_phase=%d management_fqpcid=%x user_phase=%d user_fqpcid=%x app_versioned=%t inbound_allowance=%d outbound_base=%d outbound_sent=%d pending_acks=%d queued_pius=%d queued_sessions=%d",
		c.id, action, c.peer.NetID, c.peer.CP, c.peer.LU, c.profile, c.xid.Ready(), c.linkReady,
		c.management.Phase(), c.management.FQPCID(), userPhase, userFQPCID, c.appVersioned,
		c.inboundAllowance, c.outboundBase, c.outboundSent, len(c.acks), len(c.early), len(c.earlySession))
	s.hub.a.debugSNA("local circuit=%s action=%s xid=%+v management=%+v user=%+v application=%+v",
		c.id, action, c.xid, c.management, c.user, c.aping)
	for i, queued := range c.early {
		s.hub.a.debugSNA("local circuit=%s action=%s queued_piu=%d data=%x", c.id, action, i, queued)
	}
	for i, queued := range c.earlySession {
		s.hub.a.debugSNA("local circuit=%s action=%s queued_session=%d event=%+v", c.id, action, i, queued)
	}
	for i, ack := range c.acks {
		s.hub.a.debugSNA("local circuit=%s action=%s pending_ack=%d end=%d", c.id, action, i, ack.end)
	}
}
