package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna/lu62"
	"github.com/friedkiwi/snusnu/sna/xid3"
)

func managementBindForLocalService() []byte {
	plu := []byte{0xd7, 0xc5, 0xc5, 0xd9, 0xd5, 0xc5, 0xe3, 0x4b, 0xc3, 0xd7} // PEERNET.CP
	slu := []byte{0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4, 0x4b, 0xe2, 0xe5, 0xc3} // SNUSNU.SVC
	fixed := []byte{0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0}
	user := []byte{0, 9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7, 9, 3, 1}
	user = append(user, bytes.Repeat([]byte{0}, 7)...)
	user = append(user, byte(1+len(plu)), 4)
	user = append(user, plu...)
	user = append(user, 10, 0x13)
	user = append(user, bytes.Repeat([]byte{0}, 9)...)
	ru := append([]byte(nil), fixed...)
	ru = append(ru, byte(len(plu)))
	ru = append(ru, plu...)
	ru = append(ru, byte(len(user)))
	ru = append(ru, user...)
	ru = append(ru, 0, byte(len(slu)))
	ru = append(ru, slu...)
	ru = append(ru, 0x60, byte(9+len(plu)))
	ru = append(ru, bytes.Repeat([]byte{0x11}, 8)...)
	ru = append(ru, byte(len(plu)))
	ru = append(ru, plu...)
	ru = append(ru, 0x2c, 0x0a)
	ru = append(ru, bytes.Repeat([]byte{0}, 10)...)
	return append([]byte{0x2f, 0, 1, 2, 0, 0, 0x6b, 0x85, 0}, ru...)
}

func userBindForLocalService() []byte {
	plu := []byte{0xd7, 0xc5, 0xc5, 0xd9, 0xd5, 0xc5, 0xe3, 0x4b, 0xd3, 0xe4}       // PEERNET.LU
	slu := []byte{0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4, 0x4b, 0xd7, 0xc9, 0xd5, 0xc7} // SNUSNU.PING
	fixed := []byte{0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 3, 0x83, 0xc7, 0xc7, 0x83, 3, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0}
	user := append([]byte{0, 9, 2}, bytes.Repeat([]byte{0x40}, 8)...)
	user = append(user, 9, 3, 1)
	user = append(user, bytes.Repeat([]byte{0}, 7)...)
	user = append(user, byte(1+len(plu)), 4)
	user = append(user, plu...)
	user = append(user, 10, 0x13)
	user = append(user, bytes.Repeat([]byte{0}, 9)...)
	ru := append([]byte(nil), fixed...)
	ru = append(ru, byte(len(plu)))
	ru = append(ru, plu...)
	ru = append(ru, byte(len(user)))
	ru = append(ru, user...)
	ru = append(ru, 0, byte(len(slu)))
	ru = append(ru, slu...)
	ru = append(ru, 0x60, byte(9+len(plu)))
	ru = append(ru, bytes.Repeat([]byte{0x22}, 8)...)
	ru = append(ru, byte(len(plu)))
	ru = append(ru, plu...)
	ru = append(ru, 0x2c, 0x0a)
	ru = append(ru, bytes.Repeat([]byte{0}, 10)...)
	return append([]byte{0x2f, 0, 2, 2, 0, 0, 0x6b, 0x85, 0}, ru...)
}

func TestLocalSNAAdapterActivatesStampedPeer(t *testing.T) {
	a := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.StartLocalSNA(ctx); err != nil {
		t.Fatal(err)
	}
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "sna-peer@example.com", "unused", store.Now(), "PEERNET"); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.DB.CreateRouter(ctx, owner, "Peer")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	conn, welcome := connectTestRouterVersion(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/router/v1/ws", token, "snusnu.v2")
	routes := expectTestBody(t, conn, "routes").GetOriginRoutes()
	sourceSnapshot := &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{
		{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "PEERNET", Name: "CP"}}},
		{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: &wire.SnaName{Netid: "PEERNET", Name: "LU"}, HostingCp: &wire.SnaName{Netid: "PEERNET", Name: "CP"}, SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
	}}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: sourceSnapshot})
	source := &wire.RouteReference{RouterId: welcome.RouterId, Epoch: welcome.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	target := &wire.RouteReference{RouterId: uuidBytes(serviceRouterID), Epoch: routes.Snapshot.Epoch, RouteId: 2, RouteGeneration: 1}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 1, Target: target, SourceRoute: source, ReceiveAllowanceBytes: 1500}})
	result := expectTestBody(t, conn, "result").GetOpenResult()
	if !result.Accepted {
		t.Fatalf("local SNA open rejected: %+v", result)
	}
	sendType1 := func(info []byte) {
		sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_Type1{Type1: &wire.DlcType1{Kind: wire.Type1Kind_TYPE1_KIND_XID, Dsap: 4, Ssap: 4, PollFinal: true, Information: info}}}})
	}
	readXID := func(want xid3.State) {
		event := expectTestBody(t, conn, "event").GetCircuitEvent()
		if event.GetType1() == nil || !event.GetType1().Response {
			t.Fatalf("missing XID response: %+v", event)
		}
		x, err := xid3.Parse(event.GetType1().Information)
		if err != nil {
			t.Fatal(err)
		}
		name, err := x.CPName()
		if err != nil || name != "SNUSNU.SVC" || x.Role() != xid3.Primary || x.State() != want {
			t.Fatalf("local XID: %s %v %v", name, x.State(), err)
		}
	}
	sendType1(nil)
	readXID(xid3.Prenegotiation)
	peer, err := xid3.NewLocal("PEERNET.CP", "CP", [4]byte{0xff, 0xf2, 0x34, 0x56}, 1, xid3.Secondary)
	if err != nil {
		t.Fatal(err)
	}
	peerXIDBytes, _ := peer.Bytes()
	sendType1(peerXIDBytes)
	readXID(xid3.Proceeding)
	if err := peer.SetState(xid3.Proceeding); err != nil {
		t.Fatal(err)
	}
	peerXIDBytes, _ = peer.Bytes()
	sendType1(peerXIDBytes)
	readXID(xid3.Proceeding)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_LinkReady{LinkReady: &wire.LinkReady{}}}})
	bind := managementBindForLocalService()
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: bind}}})
	bindResponse := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if len(bindResponse) < 10 || bindResponse[6] != 0xeb || bindResponse[9] != 0x31 {
		t.Fatalf("management BIND response: %x", bindResponse)
	}
	if credit := expectTestBody(t, conn, "credit").GetCircuitCredit(); credit.AllowanceBytes != 1500+uint64(len(bind)) {
		t.Fatalf("management inbound credit: %+v", credit)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(len(bindResponse))}})
	cnos, _ := hex.DecodeString("2e00010200010b91200c0502ff0003d000000206f100191210020000000000080004000400084040404040404040")
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: cnos}}})
	cnosIPR := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	cnosReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if !bytes.Equal(cnosIPR, []byte{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0}) || len(cnosReply) < 9 || cnosReply[6] != 3 {
		t.Fatalf("CNOS replies: %x %x", cnosIPR, cnosReply)
	}
	if credit := expectTestBody(t, conn, "credit").GetCircuitCredit(); credit.AllowanceBytes != 1500+uint64(len(bind)+len(cnos)) {
		t.Fatalf("CNOS inbound credit: %+v", credit)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(len(bindResponse)+len(cnosIPR)+len(cnosReply))}})
	bis, _ := hex.DecodeString("2e00010200024b910070")
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: bis}}})
	bisIPR := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	bisReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if !bytes.Equal(bisIPR, []byte{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0}) || !bytes.Equal(bisReply, []byte{0x2e, 0, 2, 1, 0, 2, 0x4b, 0xb0, 0, 0x70}) {
		t.Fatalf("BIS replies: %x %x", bisIPR, bisReply)
	}
	expectTestBody(t, conn, "credit")
	outbound := len(bindResponse) + len(cnosIPR) + len(cnosReply) + len(bisIPR) + len(bisReply)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	userBind := userBindForLocalService()
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: userBind}}})
	userResponse := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if len(userResponse) < 10 || userResponse[6] != 0xeb || userResponse[9] != 0x31 {
		t.Fatalf("user BIND response: %x", userResponse)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(userResponse)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	fq, err := lu62.RequestFQPCID(bind)
	if err != nil {
		t.Fatal(err)
	}
	managementUnbind := append([]byte{0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}, fq...)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: managementUnbind}}})
	unbindResponse := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if !bytes.Equal(unbindResponse, []byte{0x2f, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x32}) {
		t.Fatalf("management UNBIND response: %x", unbindResponse)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(unbindResponse)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	attach := []byte{0x2e, 0, 2, 2, 0, 1, 0x0a, 0x91, 0}
	ru := []byte{0x2f, 5, 2, 0xff, 0, 3, 0xd1, 0, 0x40, 6, 0xc1, 0xd7, 0xc9, 0xd5, 0xc7, 0xc4}
	for len(ru) < 47 {
		ru = append(ru, 0)
	}
	attach = append(attach, ru...)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: attach}}})
	attachGrant := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if !bytes.Equal(attachGrant, []byte{0x2f, 0, 2, 2, 0, 0, 0x83, 1, 0}) {
		t.Fatalf("APINGD Attach grant: %x", attachGrant)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(attachGrant)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	version, _ := hex.DecodeString("000f12ff01022b02d6e261f4f0f000")
	versionRequest := append([]byte{0x2e, 0, 2, 2, 0, 2, 1, 0x95, 0x20}, version...)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: versionRequest}}})
	versionGrant := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	versionReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	wantVersion, _ := hex.DecodeString("000e12ff01022b024f532f343030")
	if !bytes.Equal(versionGrant, attachGrant) || len(versionReply) < 9 || !bytes.Equal(versionReply[:9], []byte{0x2e, 0, 2, 2, 0, 1, 3, 0x91, 0x20}) || !bytes.Equal(versionReply[9:], wantVersion) {
		t.Fatalf("APINGD version: %x %x", versionGrant, versionReply)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(versionGrant) + len(versionReply)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	// V4R4 may include the three-byte pacing parameter after the RH.
	iprWithParameter := []byte{0x2f, 0, 2, 2, 0, 0, 0x83, 1, 0, 0, 0, 6}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: iprWithParameter}}})
	expectTestBody(t, conn, "credit")
	packet, _ := hex.DecodeString("001412ff00000000000000000000000000000000")
	echoRequest := append([]byte{0x2e, 0, 2, 2, 0, 3, 3, 0x91, 0x20}, packet...)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: echoRequest}}})
	echoGrant := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	echoReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSnaInformation()
	if !bytes.Equal(echoGrant, attachGrant) || len(echoReply) < 9 || !bytes.Equal(echoReply[:9], []byte{0x2e, 0, 2, 2, 0, 2, 3, 0x90, 0x20}) || !bytes.Equal(echoReply[9:], packet) {
		t.Fatalf("APINGD echo: %x %x", echoGrant, echoReply)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(echoGrant) + len(echoReply)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	userFQ, err := lu62.RequestFQPCID(userBind)
	if err != nil {
		t.Fatal(err)
	}
	sendInfo := func(data []byte) {
		sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: data}}})
	}
	readInfo := func() []byte {
		event := expectTestBody(t, conn, "event").GetCircuitEvent()
		if event == nil {
			t.Fatal("missing SNA event")
		}
		return event.GetSnaInformation()
	}
	noEcho, _ := hex.DecodeString("000812ff00000000000812ff00000000")
	sendInfo(append([]byte{0x2e, 0, 2, 2, 0, 4, 3, 0xa1, 0}, noEcho...))
	noEchoGrant := readInfo()
	if !bytes.Equal(noEchoGrant, attachGrant) {
		t.Fatalf("no-echo grant: %x", noEchoGrant)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(noEchoGrant)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	sendInfo([]byte{0x2e, 0, 2, 2, 0, 5, 0x4b, 0xa0, 1, 4, 0, 6})
	confirmReply := readInfo()
	if !bytes.Equal(confirmReply, []byte{0x2e, 0, 2, 2, 0x80, 0, 0xcb, 0xa0, 0, 4}) {
		t.Fatalf("CONFIRM reply: %x", confirmReply)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(confirmReply)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	sendInfo([]byte{0x2e, 0, 2, 2, 0, 6, 0x4b, 0x91, 0, 0x70})
	userBISGrant, userBISReply := readInfo(), readInfo()
	if !bytes.Equal(userBISGrant, attachGrant) || !bytes.Equal(userBISReply, []byte{0x2e, 0, 2, 2, 0, 3, 0x4b, 0xb0, 0, 0x70}) {
		t.Fatalf("user BIS replies: %x %x", userBISGrant, userBISReply)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(userBISGrant) + len(userBISReply)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	userUnbind := append([]byte{0x2f, 0, 2, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}, userFQ...)
	sendInfo(userUnbind)
	userUnbindReply := readInfo()
	if !bytes.Equal(userUnbindReply, []byte{0x2f, 0, 2, 2, 0, 0, 0xeb, 0x80, 0, 0x32}) {
		t.Fatalf("user UNBIND reply: %x", userUnbindReply)
	}
	expectTestBody(t, conn, "credit")
	outbound += len(userUnbindReply)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(outbound)}})
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: []byte{1, 2, 3}}}})
	if reset := readTestEnvelope(t, conn).GetCircuitReset(); reset == nil || reset.Reason != wire.ResetReason_RESET_REASON_PROTOCOL {
		t.Fatalf("malformed SNA PIU did not reset circuit: %+v", reset)
	}
}
