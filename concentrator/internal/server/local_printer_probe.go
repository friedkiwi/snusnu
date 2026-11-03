package server

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/friedkiwi/snusnu/sna/lu62"
	"github.com/friedkiwi/snusnu/sna/piu"
	"github.com/friedkiwi/snusnu/sna/services/printer"
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
	management        *lu62.ManagementSession
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
			if err == nil {
				if c.initiated {
					err = p.managementInformation(id, c, value.SnaInformation)
				} else {
					err = p.passiveManagementInformation(id, c, value.SnaInformation)
				}
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
	if !ok || !peer.Valid() || open.Target == nil || (open.Target.RouteId != 3 && open.Target.RouteId != 4) || len(p.circuits) >= 64 ||
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
	copy(token[1:5], random[8:12])
	token[5] = 0x80
	remoteLU := c.peer.CP
	if os.Getenv("SNUSNU_PRINTER_PROBE_SOURCE_QRMTWSC") == "1" {
		remoteLU = c.peer.LU
	}
	bindDAF := byte(1)
	if os.Getenv("SNUSNU_PRINTER_PROBE_SOURCE_QRMTWSC") == "1" {
		bindDAF = 0 // 5494 first source-assigned LFSID 0200: DAF=SIDL, OAF=SIDH.
	}
	bind, err := lu62.CandidateManagementBind("SNUSNU.SVC", c.peer.NetID+"."+remoteLU, bindDAF, 2, instance, token)
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

func (p *localPrinterProbe) passiveManagementInformation(id string, c *printerProbeCircuit, data []byte) error {
	if len(data) >= 12 && data[6] == 0x6b && data[9] == 0x0d {
		responseRU, err := printer.ACTLUResponseRU(data[9:])
		if err != nil {
			return err
		}
		th := [6]byte{data[0], data[1], data[3], data[2], data[4], data[5]}
		response, err := (piu.FID2{TH: th, RH: [3]byte{0xeb, data[7], 0}, RU: responseRU}).Bytes()
		if err != nil {
			return err
		}
		log.Printf("printer probe ACTLU response: circuit=%s piu=%x", id, response)
		return p.sendInformation(id, response)
	}
	bind, err := lu62.ParseBind(data)
	if err != nil {
		return err
	}
	if bind != nil && bind.Management && c.management == nil {
		if bind.PLU != c.peer.NetID+"."+c.peer.LU || (bind.SLU != "SNUSNU.PRINTER" && bind.SLU != "SNUSNU.SVC") {
			return fmt.Errorf("printer probe management BIND identity mismatch: %s to %s", bind.PLU, bind.SLU)
		}
		mode, sessions := "", uint16(8)
		if os.Getenv("SNUSNU_PRINTER_PROBE_PASSIVE_QRMTWSC") == "1" || os.Getenv("SNUSNU_PRINTER_PROBE_PASSIVE_SOURCE_BIND") == "1" {
			mode, sessions = "QRMTWSC", 57
		}
		management, err := lu62.NewManagementSessionWithMode(bind.PLU, bind.SLU, mode, sessions)
		if err != nil {
			return err
		}
		response, err := management.PrepareBind(data)
		if err != nil {
			return err
		}
		if err := p.sendInformation(id, response); err != nil {
			return err
		}
		if err := management.MarkBindSent(response); err != nil {
			return err
		}
		if err := management.AckBind(); err != nil {
			return err
		}
		c.management = management
		log.Printf("printer probe passive management BIND: circuit=%s plu=%s slu=%s", id, bind.PLU, bind.SLU)
		return nil
	}
	if c.management == nil {
		return nil
	}
	if lu62.IsPacingResponse(data) {
		return c.management.ReceiveIPR(data)
	}
	switch c.management.Phase() {
	case lu62.ManagementAwaitCNOS:
		if len(data) < 10 || data[6] != 0x0b {
			return nil
		}
		ipr, reply, err := c.management.PrepareCNOS(data)
		if err != nil {
			return err
		}
		if err := p.sendInformation(id, ipr); err != nil {
			return err
		}
		if err := p.sendInformation(id, reply); err != nil {
			return err
		}
		if err := c.management.MarkCNOSSent(ipr, reply); err != nil {
			return err
		}
		if err := c.management.AckCNOS(); err != nil {
			return err
		}
		if err := c.management.AckCNOS(); err != nil {
			return err
		}
		if os.Getenv("SNUSNU_PRINTER_PROBE_NMVT") == "1" {
			return p.sendExperimentalNMVT(id)
		}
		return nil
	case lu62.ManagementCNOSComplete:
		if len(data) != 10 || data[6] != 0x4b {
			return nil
		}
		ipr, reply, err := c.management.PrepareBIS(data, 2, true)
		if err != nil {
			return err
		}
		if err := p.sendInformation(id, ipr); err != nil {
			return err
		}
		if err := p.sendInformation(id, reply); err != nil {
			return err
		}
		if err := c.management.MarkBISSent(ipr, reply); err != nil {
			return err
		}
		if err := c.management.AckBIS(); err != nil {
			return err
		}
		if err := c.management.AckBIS(); err != nil {
			return err
		}
		return nil
	case lu62.ManagementBISComplete:
		if len(data) < 10 || data[6] != 0x6b || data[9] != 0x32 {
			return nil
		}
		reply, err := c.management.PrepareUnbind(data)
		if err != nil {
			return err
		}
		if err := p.sendInformation(id, reply); err != nil {
			return err
		}
		if err := c.management.MarkUnbindSent(reply); err != nil {
			return err
		}
		if err := c.management.AckUnbind(); err != nil {
			return err
		}
		if os.Getenv("SNUSNU_PRINTER_PROBE_PASSIVE_SOURCE_BIND") == "1" {
			var pcid [8]byte
			if _, err := rand.Read(pcid[:]); err != nil {
				return err
			}
			bind, err := lu62.Candidate5494ControllerBind("SNUSNU.SVC", c.peer.NetID+"."+c.peer.LU, "SNUSNU.SVC", 2, 2, 0x86, pcid)
			if err != nil {
				return err
			}
			log.Printf("printer probe post-management controller BIND: circuit=%s piu=%x", id, bind)
			c.initiated = true
			c.managementPhase = 5
			return p.sendInformation(id, bind)
		}
		return nil
	}
	return nil
}

// sendExperimentalNMVT is a QA-only wire probe. The VPD and address-list
// fields below are lab placeholders; a real printer service must obtain them
// from its attached device and maintain the independent SSCP-PU flow.
func (p *localPrinterProbe) sendExperimentalNMVT(id string) error {
	psid := printer.ReplyPSID{
		ProcedureID: 1,
		Address:     1, Station: 1,
		VPD: printer.HardwarePSID{
			MachineType: [4]byte{0xf3, 0xf8, 0xf1, 0xf2},
			Model:       [3]byte{0xf0, 0xf0, 0xf1},
			Plant:       [2]byte{0xf0, 0xf0},
			Serial:      [7]byte{0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf1},
		},
		DateTime: [6]byte{0x26, 11, 3, 14, 0, 0},
	}
	out, err := psid.EncodeNMVTPIU([6]byte{0x2c, 0xff, 0, 0, 0, 1}, 0x80, 0)
	if err != nil {
		return err
	}
	log.Printf("printer probe experimental NMVT: circuit=%s piu=%x", id, out)
	return p.sendInformation(id, out)
}

func (p *localPrinterProbe) managementInformation(id string, c *printerProbeCircuit, data []byte) error {
	// The first 5494-assigned source LFSID is 0200. On BIND-direction PIUs
	// its SIDL is DAF=00 and SIDH is OAF=02; responses reverse the pair.
	sourceDAF := byte(1)
	if os.Getenv("SNUSNU_PRINTER_PROBE_SOURCE_QRMTWSC") == "1" {
		sourceDAF = 0
	}
	switch c.managementPhase {
	case 1:
		if len(data) < 37 || data[6] != 0xeb || data[9] != 0x31 || data[2] != 2 || data[3] != sourceDAF {
			return nil
		}
		cnos := lu62.CNOS{Service: 2, SessionLimit: 8, SourceWinners: 4, TargetWinners: 4, ModeWidth: 8}
		if os.Getenv("SNUSNU_PRINTER_PROBE_SOURCE_QRMTWSC") == "1" {
			var err error
			cnos, err = lu62.New5494ControllerCNOS(56)
			if err != nil {
				return err
			}
		}
		gds, err := lu62.EncodeCNOS(cnos)
		if err != nil {
			return err
		}
		attach := []byte{0x2e, 0, sourceDAF, 2, 0, 1, 0x0b, 0x91, 0x20, 12, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1}
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
		if err := p.sendInformation(id, []byte{0x2e, 0, sourceDAF, 2, 0, 0, 0x83, 1, 0}); err != nil {
			return err
		}
		if err := p.sendInformation(id, []byte{0x2e, 0, sourceDAF, 2, 0, 2, 0x4b, 0x91, 0, 0x70}); err != nil {
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
		runbind := []byte{0x2f, 0, sourceDAF, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0}
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
			bind, err := lu62.Candidate5494ControllerBind("SNUSNU.SVC", c.peer.NetID+"."+c.peer.LU, "SNUSNU.SVC", 1, 2, 0x86, pcid)
			if err != nil {
				return err
			}
			log.Printf("printer probe controller BIND: circuit=%s piu=%x", id, bind)
			return p.sendInformation(id, bind)
		}
	case 5:
		wantDAF, wantOAF := byte(2), byte(1)
		if os.Getenv("SNUSNU_PRINTER_PROBE_PASSIVE_SOURCE_BIND") == "1" {
			wantOAF = 2
		}
		if len(data) < 36 || data[6] != 0xeb || data[9] != 0x31 || data[2] != wantDAF || data[3] != wantOAF {
			return nil
		}
		// VG10's controller Attach carries a fixed QND5MAIN TPN and one
		// length-qualified PIP GDS. The byte after the 03 20 prefix is a
		// runtime controller value; zero probes the documented boundary.
		pipByte := byte(0)
		if raw := os.Getenv("SNUSNU_PRINTER_PROBE_PIP_BYTE"); raw != "" {
			value, err := strconv.ParseUint(raw, 0, 8)
			if err != nil {
				return fmt.Errorf("invalid printer probe PIP byte %q: %w", raw, err)
			}
			pipByte = byte(value)
		}
		attach := []byte{
			0x2e, 0, wantOAF, wantDAF, 0, 1, 0x0b, 0x91, 0x20,
			0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4,
			0x30, 0xf0, 0xf6, 0xf6, 0, 0, 0,
			0, 0x12, 0x12, 0xf5, 0, 0x0e, 0x12, 0xe2,
			3, 0x20, 1, pipByte, 0x38, 4, 4, 0xd4, 7, 0x30,
		}
		log.Printf("printer probe controller Attach: circuit=%s piu=%x", id, attach)
		c.managementPhase = 6
		return p.sendInformation(id, attach)
	case 6:
		outer, err := piu.ParseFID2(data)
		if err != nil {
			return nil
		}
		if os.Getenv("SNUSNU_PRINTER_PROBE_LU7_QUERY") == "1" && outer.TH[0]&1 != 0 &&
			outer.RH == [3]byte{0x4b, 0x80, 0} && bytes.Equal(outer.RU, []byte{0xc9, 0, 1, 0, 1}) {
			th := [6]byte{outer.TH[0], outer.TH[1], outer.TH[3], outer.TH[2], outer.TH[4], outer.TH[5]}
			response, err := (piu.FID2{TH: th, RH: [3]byte{0xcb, 0x80, 0}}).Bytes()
			if err != nil {
				return err
			}
			log.Printf("printer probe SIGNAL response: circuit=%s piu=%x", id, response)
			return p.sendInformation(id, response)
		}
		inner, err := printer.ParseControllerDeviceGDS(outer.RU)
		if err != nil || inner.Address != 56 || len(inner.RU) < 3 {
			return nil
		}
		var ru []byte
		queryReply := false
		switch {
		case inner.Session == printer.LU4SystemSession && inner.RU[0] == 0x0d:
			ru, err = printer.ACTLUResponseRU(inner.RU)
		case inner.Session == printer.LU4PrintSession && inner.RU[0] == 0x31 && len(inner.RU) == 26 && inner.RU[14] == 7:
			ru = append([]byte(nil), inner.RU...)
		case os.Getenv("SNUSNU_PRINTER_PROBE_LU7_QUERY") == "1" && inner.Session == printer.LU4PrintSession &&
			bytes.Equal(inner.RU, []byte{4, 0xf3, 0, 5, 0xd8, 0x20, 2}):
			// VG03's D820/02 handler copies this 26-byte 5250 Query reply.
			// Bytes 20-21 are runtime capability fields; the disk default is
			// only a probe value until the device configuration is known.
			ru = []byte{0, 0, 0x88, 0, 0x17, 0xd8, 0x21, 2, 0, 0x12, 1, 1, 0, 0x0e, 2, 1, 0, 0x0a, 3, 3, 3, 0x10, 0, 4, 0x40, 0xff}
			queryReply = true
		case os.Getenv("SNUSNU_PRINTER_PROBE_LU7_QUERY") == "1" && inner.Session == printer.LU4PrintSession &&
			bytes.Equal(inner.RU, []byte{4, 0xf3, 0, 0x17, 0xd8, 0x21, 0x10, 0, 0x12, 1, 1, 0, 0x0e, 2, 1, 0, 0x0a, 3, 3, 3, 0x10, 0, 4, 0x40, 0xff}):
			// VG03's D821/10 handler emits its eight-byte station-state
			// reply template, including the 5250 structured-field AID.
			ru = []byte{0, 0, 0x88, 0, 5, 0xd8, 0x20, 0x10}
			queryReply = true
		default:
			return nil
		}
		if err != nil {
			return err
		}
		var response printer.LU4PIU
		if queryReply {
			response = printer.LU4PIU{Address: inner.Address, Session: inner.Session, RH: [3]byte{0x03, 0x80, 0x20}, RU: ru}
		} else {
			response, err = printer.PositiveLU4Response(inner, ru)
			if err != nil {
				return err
			}
		}
		gds, err := printer.EncodeControllerDeviceGDS(response)
		if err != nil {
			return err
		}
		reply := piu.FID2{TH: [6]byte{0x2e, 0, outer.TH[3], outer.TH[2], outer.TH[4], outer.TH[5]}, RH: [3]byte{0x03, 0x91, 0x20}, RU: gds}
		packet, err := reply.Bytes()
		if err != nil {
			return err
		}
		log.Printf("printer probe controller device response: circuit=%s address=%d command=%02x piu=%x", id, inner.Address, inner.RU[0], packet)
		return p.sendInformation(id, packet)
	}
	return nil
}
