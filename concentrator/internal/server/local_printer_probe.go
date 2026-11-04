package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/friedkiwi/snusnu/sna/lu62"
	"github.com/friedkiwi/snusnu/sna/piu"
	"github.com/friedkiwi/snusnu/sna/services/printer"
	"github.com/friedkiwi/snusnu/sna/xid3"
)

type printerProbeCircuit struct {
	peer               sna.Peer
	source             LocalPeer
	xid                *xid3.Activation
	profile            wire.CircuitProfile
	allowance          uint64
	xidReadyReplySent  bool
	linkReadySent      bool
	initiated          bool
	managementPhase    uint8
	nmvtSent           bool
	management         *lu62.ManagementSession
	fqpcid             []byte
	peerIPR            bool
	device             *printer.LU4Device
	chain              *printer.ChainAssembler
	lu7WSFBytes        int
	lu7UnbindAwaitAck  bool
	psidRequestPending bool
	psidNodeAwaitAck   bool
	psidDeviceAwaitAck bool
	psidRequestID      uint16
	psidRequestTH      [6]byte
	nmvtSequence       uint16
	controllerSequence uint16
	spool              probePrinterSpool
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
		c.spool.close()
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
				if parsed.RH[0] == 0x6b && len(parsed.RU) > 0 && parsed.RU[0] == 0x0e {
					th := [6]byte{parsed.TH[0], parsed.TH[1], parsed.TH[3], parsed.TH[2], parsed.TH[4], parsed.TH[5]}
					response, responseErr := (piu.FID2{TH: th, RH: [3]byte{0xeb, parsed.RH[1], 0}, RU: []byte{0x0e}}).Bytes()
					if responseErr != nil {
						err = responseErr
					} else {
						log.Printf("printer probe DACTLU response: circuit=%s piu=%x", id, response)
						err = p.sendInformation(id, response)
					}
				} else if c.initiated {
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
		c.spool.close()
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
	local, err := printerProbeXID()
	if err != nil {
		return
	}
	xid, err := xid3.NewActivation(local)
	if err != nil {
		return
	}
	p.circuits[id] = &printerProbeCircuit{peer: peer, source: source, xid: xid, profile: wire.CircuitProfile_CIRCUIT_PROFILE_NATIVE_DLC, allowance: 1500, initiated: true}
}

func (p *localPrinterProbe) open(open *wire.IncomingOpen, source LocalPeer) {
	id, ok := uuidString(open.CircuitId)
	peer := source.SNAPeer()
	if !ok || !peer.Valid() || open.Target == nil || (open.Target.RouteId != 3 && open.Target.RouteId != 4) || len(p.circuits) >= 64 ||
		(open.Profile != wire.CircuitProfile_CIRCUIT_PROFILE_NATIVE_DLC && open.Profile != wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1) {
		_ = p.hub.decision(p.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Reason: wire.OpenFailure_OPEN_FAILURE_FORBIDDEN})
		return
	}
	local, err := printerProbeXID()
	if err != nil {
		log.Printf("printer probe XID: %v", err)
		return
	}
	xid, err := xid3.NewActivation(local)
	if err != nil {
		log.Printf("printer probe activation: %v", err)
		return
	}
	p.circuits[id] = &printerProbeCircuit{peer: peer, source: source, xid: xid, profile: open.Profile, allowance: 1500}
	if err := p.hub.decision(p.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Accept: true, ReceiveAllowanceBytes: 1500}); err != nil {
		delete(p.circuits, id)
		return
	}
	log.Printf("printer probe open: circuit=%s peer=%s.%s profile=%s", id, peer.NetID, peer.CP, open.Profile)
}

func printerProbeXID() (xid3.XID, error) {
	local, err := xid3.NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x46}, 1, xid3.Secondary)
	if err != nil || os.Getenv("SNUSNU_PRINTER_PROBE_5494_XID") != "1" {
		return local, err
	}
	// VG0F's XID3 Product Set ID: hardware 5494 model 002. Keep the
	// configured CP identity and link node ID, which are independent fields.
	local.Vectors[2].Data = []byte{
		0, 0x16, 0x11, 1, 0x13, 0, 0x12,
		0xf5, 0xf4, 0xf9, 0xf4, 0xf0, 0xf0, 0xf2, 0xf0, 0xf0,
		0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf1,
	}
	local.Fixed[1] = byte(len(local.Fixed))
	for _, vector := range local.Vectors {
		local.Fixed[1] += byte(2 + len(vector.Data))
	}
	return local, local.Validate()
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
				if os.Getenv("SNUSNU_PRINTER_PROBE_BIND_AFTER_ACTLU") == "1" {
					return nil
				}
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
	remoteName := c.peer.NetID + "." + remoteLU
	if os.Getenv("SNUSNU_PRINTER_PROBE_SOURCE_UNQUALIFIED") == "1" {
		remoteName = remoteLU
	}
	bind, err := lu62.CandidateManagementBind("SNUSNU.SVC", remoteName, bindDAF, 2, instance, token)
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
	if os.Getenv("SNUSNU_PRINTER_PROBE_TRACK_SOURCE_SEQUENCE") == "1" &&
		len(data) >= 9 && data[0]&0xfc == 0x2c && data[2] == 1 && data[3] == 2 &&
		data[6]&0x80 == 0 && (data[4] != 0 || data[5] != 0) {
		if c := p.circuits[id]; c != nil {
			c.controllerSequence++
			data = append([]byte(nil), data...)
			data[4], data[5] = byte(c.controllerSequence>>8), byte(c.controllerSequence)
			log.Printf("printer probe controller source sequence: circuit=%s sequence=%04x piu=%x", id, c.controllerSequence, data)
		}
	}
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
		if os.Getenv("SNUSNU_PRINTER_PROBE_NMVT") == "1" && os.Getenv("SNUSNU_PRINTER_PROBE_NMVT_AFTER_ATTACH") != "1" {
			return p.sendExperimentalNMVT(id, c)
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
		if os.Getenv("SNUSNU_PRINTER_PROBE_PASSIVE_THEN_SOURCE") == "1" {
			c.initiated = true
			c.management = nil
			return p.beginManagement(id, c)
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
func (c *printerProbeCircuit) nextNMVTTH() [6]byte {
	c.nmvtSequence++
	if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_SS_LU") == "1" {
		return [6]byte{0x2c, 0, 0, 1, byte(c.nmvtSequence >> 8), byte(c.nmvtSequence)}
	}
	if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_DIRECT_CONTROLLER") == "1" {
		return [6]byte{0x2e, 0, 1, 2, byte(c.nmvtSequence >> 8), byte(c.nmvtSequence)}
	}
	return [6]byte{0x2e, 0, 0, 0, byte(c.nmvtSequence >> 8), byte(c.nmvtSequence)}
}

func (p *localPrinterProbe) sendExperimentalNMVT(id string, c *printerProbeCircuit) error {
	psid := experimentalPrinterPSID()
	out, err := psid.EncodeNMVTPIU(c.nextNMVTTH(), 0x80, 0)
	if err != nil {
		return err
	}
	log.Printf("printer probe experimental NMVT: circuit=%s piu=%x", id, out)
	return p.sendInformation(id, out)
}

func experimentalPrinterPSID() printer.ReplyPSID {
	now := time.Now()
	return printer.ReplyPSID{
		ProcedureID: 0,
		Address:     1, Station: 1,
		VPD: printer.HardwarePSID{
			MachineType: [4]byte{0xf3, 0xf8, 0xf1, 0xf2},
			Model:       [3]byte{0xf0, 0xf0, 0xf1},
			Plant:       [2]byte{0xf0, 0xf0},
			Serial:      [7]byte{0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf1},
		},
		DateTime: [6]byte{
			byte(now.Year() % 100), byte(now.Month()), byte(now.Day()),
			byte(now.Hour()), byte(now.Minute()), byte(now.Second()),
		},
	}
}

func (p *localPrinterProbe) sendSolicitedPrinterPSID(id string, c *printerProbeCircuit) error {
	psid := experimentalPrinterPSID()
	psid.Solicited = true
	psid.ProcedureID = c.psidRequestID
	if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_DIRECT") == "1" ||
		os.Getenv("SNUSNU_PRINTER_PROBE_PSID_DIRECT_CONTROLLER") == "1" ||
		os.Getenv("SNUSNU_PRINTER_PROBE_PSID_SS_LU") == "1" {
		out, err := psid.EncodeNMVTPIU(c.nextNMVTTH(), 0x80, 0)
		if err != nil {
			return err
		}
		log.Printf("printer probe solicited direct PSID: circuit=%s piu=%x", id, out)
		c.psidDeviceAwaitAck = true
		return p.sendInformation(id, out)
	}
	ru, err := psid.EncodeNMVT()
	if err != nil {
		return err
	}
	inner := printer.LU4PIU{Address: 0, Session: printer.LU4PhysicalSession,
		RH: [3]byte{0x0b, 0x80, 0}, RU: ru}
	gds, err := printer.EncodeControllerDeviceGDS(inner)
	if err != nil {
		return err
	}
	th := c.psidRequestTH
	th[2], th[3] = th[3], th[2]
	th[5]++
	rh0 := byte(0x03)
	rh1 := byte(0x91)
	if os.Getenv("SNUSNU_PRINTER_PROBE_CHAIN_PSID") == "1" {
		rh0 = 0x01 // last in the controller FMD chain
	}
	if os.Getenv("SNUSNU_PRINTER_PROBE_NO_PACING_INDICATOR") == "1" {
		rh1 = 0x90
	}
	out, err := (piu.FID2{TH: th, RH: [3]byte{rh0, rh1, 0x20}, RU: gds}).Bytes()
	if err != nil {
		return err
	}
	log.Printf("printer probe solicited controller PSID: circuit=%s piu=%x", id, out)
	return p.sendInformation(id, out)
}

// The VG15 node reply is emitted before attached-device replies for an 83
// Request PSID. This QA fixture keeps the firmware's 46-byte major vector and
// uses the lab's synthetic controller VPD where runtime 5494 fields would go.
func solicitedNodePSIDRU(c *printerProbeCircuit) ([]byte, error) {
	tail := []byte{
		0, 0, byte(c.psidRequestID >> 8), byte(c.psidRequestID), 0x80,
		0, 0x2e, 0, 0x90, 0x23, 0x10, 0, 0x20, 0x11, 1, 0x13,
		0, 0x12, 0xf5, 0xf4, 0xf9, 0xf4,
		0xf0, 0xf0, 0xf2, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
		0xf0, 0xf0, 0xf0, 0xf1, 0x0a, 0x0b, 0, 0, 0, 0, 0xf0,
		0xf0, 0, 0, 0x07, 0x42, 0xef, 0, 0, 0, 0,
	}
	if len(tail) != 51 {
		return nil, fmt.Errorf("node PSID tail length %d", len(tail))
	}
	// VG15:0x567 copies the fixed 03 20 subfield from its 0x14A6
	// template into the node reply at offsets 36 and 37.
	tail[36], tail[37] = 0x03, 0x20
	return append([]byte{0x41, 3, 0x8d}, tail...), nil
}

func (p *localPrinterProbe) sendSolicitedNodePSID(id string, c *printerProbeCircuit) error {
	ru, err := solicitedNodePSIDRU(c)
	if err != nil {
		return err
	}
	out, err := (piu.FID2{TH: c.nextNMVTTH(), RH: [3]byte{0x0b, 0x80, 0}, RU: ru}).Bytes()
	if err != nil {
		return err
	}
	log.Printf("printer probe solicited node PSID: circuit=%s piu=%x", id, out)
	c.psidNodeAwaitAck = true
	return p.sendInformation(id, out)
}

func (p *localPrinterProbe) sendSolicitedNestedNodePSID(id string, c *printerProbeCircuit) error {
	ru, err := solicitedNodePSIDRU(c)
	if err != nil {
		return err
	}
	gds, err := printer.EncodeControllerDeviceGDS(printer.LU4PIU{
		Address: 0, Session: printer.LU4PhysicalSession,
		RH: [3]byte{0x0b, 0x80, 0}, RU: ru,
	})
	if err != nil {
		return err
	}
	th := c.psidRequestTH
	th[2], th[3] = th[3], th[2]
	th[5]++
	out, err := (piu.FID2{TH: th, RH: [3]byte{0x03, 0x90, 0x20}, RU: gds}).Bytes()
	if err != nil {
		return err
	}
	log.Printf("printer probe solicited nested node PSID: circuit=%s piu=%x", id, out)
	return p.sendInformation(id, out)
}

func (p *localPrinterProbe) sendControllerPrinterPower(id string, c *printerProbeCircuit) error {
	var gds []byte
	if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_FID2_NESTED") == "1" {
		inner, err := experimentalPrinterPSID().EncodeNMVTPIU(c.nextNMVTTH(), 0x80, 0)
		if err != nil {
			return err
		}
		gds = make([]byte, 4, len(inner)+4)
		binary.BigEndian.PutUint16(gds[:2], uint16(len(inner)+4))
		gds[2], gds[3] = 0xd8, 0x24
		gds = append(gds, inner...)
	} else {
		ru, err := experimentalPrinterPSID().EncodeNMVT()
		if err != nil {
			return err
		}
		inner := printer.LU4PIU{Address: 0, Session: printer.LU4PhysicalSession,
			RH: [3]byte{0x0b, 0x80, 0}, RU: ru}
		gds, err = printer.EncodeControllerDeviceGDS(inner)
		if err != nil {
			return err
		}
	}
	th := c.psidRequestTH
	th[2], th[3] = th[3], th[2]
	// The preceding PSID response used this controller-session sequence.
	// Continue the same source stream for the unsolicited power-on request.
	sequence := uint16(th[4])<<8 | uint16(th[5])
	sequence++
	th[4], th[5] = byte(sequence>>8), byte(sequence)
	out, err := (piu.FID2{TH: th, RH: [3]byte{0x03, 0x90, 0x20}, RU: gds}).Bytes()
	if err != nil {
		return err
	}
	log.Printf("printer probe controller power-on PSID: circuit=%s piu=%x", id, out)
	return p.sendInformation(id, out)
}

func (p *localPrinterProbe) managementInformation(id string, c *printerProbeCircuit, data []byte) error {
	if c.managementPhase == 0 && len(data) >= 12 && data[6] == 0x6b && data[9] == 0x0d &&
		os.Getenv("SNUSNU_PRINTER_PROBE_BIND_AFTER_ACTLU") == "1" {
		responseRU, err := printer.ACTLUResponseRU(data[9:])
		if err != nil {
			return err
		}
		th := [6]byte{data[0], data[1], data[3], data[2], data[4], data[5]}
		response, err := (piu.FID2{TH: th, RH: [3]byte{0xeb, data[7], 0}, RU: responseRU}).Bytes()
		if err != nil {
			return err
		}
		if err := p.sendInformation(id, response); err != nil {
			return err
		}
		log.Printf("printer probe ACTLU response before source BIND: circuit=%s piu=%x", id, response)
		return p.beginManagement(id, c)
	}
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
		if len(data) < 13 || data[6] != 3 || data[7]&0xfe != 0x90 || data[8] != 1 {
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
		if len(data) >= 10 && data[6] == 0xeb && data[7]&0xef == 0x80 &&
			(data[9] == 0x32 || data[len(data)-1] == 0x32) {
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
		if c.lu7UnbindAwaitAck && outer.RH == [3]byte{0x83, 0x01, 0} &&
			os.Getenv("SNUSNU_PRINTER_PROBE_NMVT_AFTER_LU7") == "1" {
			c.lu7UnbindAwaitAck = false
			c.nmvtSent = true
			return p.sendExperimentalNMVT(id, c)
		}
		if c.psidRequestPending && outer.RH == [3]byte{0x83, 0x01, 0} {
			c.psidRequestPending = false
			if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_NODE") == "1" {
				return p.sendSolicitedNodePSID(id, c)
			}
			return p.sendSolicitedPrinterPSID(id, c)
		}
		if c.psidNodeAwaitAck && outer.RH == [3]byte{0x8b, 0x80, 0} {
			c.psidNodeAwaitAck = false
			return p.sendSolicitedPrinterPSID(id, c)
		}
		if c.psidDeviceAwaitAck && outer.RH == [3]byte{0x8b, 0x80, 0} {
			c.psidDeviceAwaitAck = false
			if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_POWER_NESTED") == "1" ||
				os.Getenv("SNUSNU_PRINTER_PROBE_PSID_FID2_NESTED") == "1" {
				return p.sendControllerPrinterPower(id, c)
			}
			if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_POWER_AFTER_REPLY") == "1" {
				return p.sendExperimentalNMVT(id, c)
			}
		}
		if !c.nmvtSent && os.Getenv("SNUSNU_PRINTER_PROBE_NMVT_AFTER_ATTACH") == "1" &&
			len(outer.RU) >= 4 && outer.RU[2] == 0xd8 && outer.RU[3] == 0x22 {
			c.nmvtSent = true
			return p.sendExperimentalNMVT(id, c)
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
		if err != nil || (inner.Address != 56 && inner.Address != 1 && inner.Address != 0) || len(inner.RU) == 0 {
			return nil
		}
		if inner.Address == 0 {
			if os.Getenv("SNUSNU_PRINTER_PROBE_CONTROLLER_PSID") != "1" ||
				inner.Session != printer.LU4PhysicalSession || len(inner.RU) != 17 ||
				!bytes.Equal(inner.RU[:5], []byte{0x41, 3, 0x8d, 0, 0}) ||
				!bytes.Equal(inner.RU[7:], []byte{0, 0, 9, 0x80, 0x90, 2, 0x83, 3, 0x85, 1}) {
				return nil
			}
			c.psidRequestID = uint16(inner.RU[5])<<8 | uint16(inner.RU[6])
			c.psidRequestTH = outer.TH
			response, err := printer.PositiveLU4Response(inner, []byte{0x41, 3, 0x8d})
			if err != nil {
				return err
			}
			gds, err := printer.EncodeControllerDeviceGDS(response)
			if err != nil {
				return err
			}
			// Keep the controller's send turn until the solicited Reply PSID
			// follows this positive inner response. The final record returns CD.
			responseRH0, responseRH2 := byte(0x03), byte(0x20)
			if os.Getenv("SNUSNU_PRINTER_PROBE_KEEP_PSID_DIRECTION") == "1" {
				responseRH2 = 0
			}
			if os.Getenv("SNUSNU_PRINTER_PROBE_CHAIN_PSID") == "1" {
				responseRH0, responseRH2 = 0x02, 0 // first in chain, keep direction
			}
			responseRH1 := byte(0x91)
			if os.Getenv("SNUSNU_PRINTER_PROBE_NO_PACING_INDICATOR") == "1" {
				responseRH1 = 0x90
			}
			packet, err := (piu.FID2{TH: [6]byte{0x2e, 0, outer.TH[3], outer.TH[2], outer.TH[4], outer.TH[5]},
				RH: [3]byte{responseRH0, responseRH1, responseRH2}, RU: gds}).Bytes()
			if err != nil {
				return err
			}
			c.psidRequestPending = os.Getenv("SNUSNU_PRINTER_PROBE_CHAIN_PSID") != "1" &&
				os.Getenv("SNUSNU_PRINTER_PROBE_NO_PACING_INDICATOR") != "1"
			log.Printf("printer probe controller PSID request response: circuit=%s piu=%x", id, packet)
			if err := p.sendInformation(id, packet); err != nil {
				return err
			}
			if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_ACK_ONLY") == "1" {
				return nil
			}
			if os.Getenv("SNUSNU_PRINTER_PROBE_PSID_NODE_NESTED") == "1" {
				return p.sendSolicitedNestedNodePSID(id, c)
			}
			if os.Getenv("SNUSNU_PRINTER_PROBE_CHAIN_PSID") == "1" ||
				os.Getenv("SNUSNU_PRINTER_PROBE_NO_PACING_INDICATOR") == "1" {
				return p.sendSolicitedPrinterPSID(id, c)
			}
			return nil
		}
		if inner.Address == 1 {
			return p.printerDeviceInformation(id, c, outer, inner)
		}
		if len(inner.RU) == 0 {
			return nil
		}
		var ru []byte
		queryReply := false
		if os.Getenv("SNUSNU_PRINTER_PROBE_LU7_WSF") == "1" && inner.Session == printer.LU4PrintSession {
			chainPosition := inner.RH[0] & 0x03
			if chainPosition == 3 && len(inner.RU) >= 7 &&
				bytes.Equal(inner.RU[4:7], []byte{0xd8, 0x22, 2}) &&
				((int(inner.RU[2])<<8)|int(inner.RU[3])) == len(inner.RU)-2 {
				// VG03's D822/02 path also accepts a complete WSF in
				// one PIU, following the long chained setup request.
				ru = []byte{0, 0, 0x88, 0, 5, 0xd8, 0x22, 0x10}
				queryReply = true
			}
			if chainPosition == 2 && bytes.HasPrefix(inner.RU, []byte{4, 0xf3, 3, 0x18, 0xd8, 0x22, 2}) {
				c.lu7WSFBytes = len(inner.RU)
				notice := piu.FID2{
					TH: [6]byte{0x2e, 0, outer.TH[3], outer.TH[2], outer.TH[4], outer.TH[5]},
					RH: [3]byte{0x03, 0x91, 0x20},
					RU: []byte{0, 5, 0xd8, 0x23, 2},
				}
				packet, err := notice.Bytes()
				if err != nil {
					return err
				}
				log.Printf("printer probe LU7 WSF first-fragment notice: circuit=%s piu=%x", id, packet)
				return p.sendInformation(id, packet)
			}
			if c.lu7WSFBytes != 0 {
				c.lu7WSFBytes += len(inner.RU)
				if chainPosition != 1 {
					return nil
				}
				length := c.lu7WSFBytes
				c.lu7WSFBytes = 0
				if length != 794 {
					return fmt.Errorf("printer probe LU7 WSF chain length %d, want 794", length)
				}
				// VG03 image 0x17E41 copies the D822/10 reply template
				// after the final fragment of this structured field.
				ru = []byte{0, 0, 0x88, 0, 5, 0xd8, 0x22, 0x10}
				queryReply = true
			}
		}
		if ru == nil {
			switch {
			case inner.Session == printer.LU4SystemSession && inner.RU[0] == 0x0d:
				ru, err = printer.ACTLUResponseRU(inner.RU)
				if err == nil && inner.Address == 56 {
					ru[5] = 0x80 // LU7 display: type bits 10 in the ACTLU status byte.
				}
			case inner.Session == printer.LU4SystemSession && inner.RU[0] == 0x0e && len(inner.RU) == 1:
				ru = []byte{0x0e}
			case inner.Session == printer.LU4PrintSession && inner.RU[0] == 0x31 && len(inner.RU) == 26 && (inner.RU[14] == 7 || inner.RU[14] == 4):
				ru = append([]byte(nil), inner.RU...)
			case inner.Session == printer.LU4PrintSession && inner.RU[0] == 0x32 && len(inner.RU) == 2:
				ru = append([]byte(nil), inner.RU...)
				c.lu7UnbindAwaitAck = true
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

func (p *localPrinterProbe) printerDeviceInformation(id string, c *printerProbeCircuit, outer piu.FID2, inner printer.LU4PIU) error {
	if c.device == nil {
		device, err := printer.NewLU4Device(1, 0x86)
		if err != nil {
			return err
		}
		c.device = device
	}
	var responseBytes []byte
	var err error
	if c.device.Phase() == printer.DeviceBound {
		if c.chain == nil {
			c.chain, err = printer.NewChainAssembler(printer.MaxJobBytes)
			if err != nil {
				return err
			}
		}
		scs, complete, err := c.chain.Feed(inner)
		if err != nil || !complete {
			return err
		}
		responseBytes, err = c.device.PrepareFMDChain(outer.RU[4:], scs, func(data []byte) error {
			if err := c.spool.append(p.hub.a.printDir, data); err != nil {
				return err
			}
			if inner.RH[2]&0x20 != 0 {
				return c.spool.finish(context.Background(), p.hub.a, c.source)
			}
			return nil
		})
	} else {
		responseBytes, err = c.device.Prepare(outer.RU[4:])
	}
	if err != nil {
		return err
	}
	if len(responseBytes) == 0 {
		log.Printf("printer probe LU4 chain accepted without positive response: circuit=%s", id)
		return nil
	}
	response, err := printer.ParseLU4PIU(responseBytes)
	if err != nil {
		return err
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
	log.Printf("printer probe LU4 response: circuit=%s phase=%d piu=%x", id, c.device.Phase(), packet)
	if err := p.sendInformation(id, packet); err != nil {
		return err
	}
	return c.device.MarkSent(responseBytes)
}
