package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna/lu62"
)

func TestLocalAPINGSessionProfileVersionAndEcho(t *testing.T) {
	a := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.StartLocalSNA(ctx); err != nil {
		t.Fatal(err)
	}
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "ee-session@example.com", "unused", store.Now(), "PEERNET"); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.DB.CreateRouter(ctx, owner, "EE session router")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	conn, welcome := connectTestRouterVersion(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/router/v1/ws", token, "snusnu.v2")
	routes := expectTestBody(t, conn, "routes").GetOriginRoutes()
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{
		{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "PEERNET", Name: "CP"}}},
		{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: &wire.SnaName{Netid: "PEERNET", Name: "LU"}, HostingCp: &wire.SnaName{Netid: "PEERNET", Name: "CP"}, SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
	}}})
	source := &wire.RouteReference{RouterId: welcome.RouterId, Epoch: welcome.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	target := &wire.RouteReference{RouterId: uuidBytes(serviceRouterID), Epoch: routes.Snapshot.Epoch, RouteId: 2, RouteGeneration: 1}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 1, Target: target, SourceRoute: source, ReceiveAllowanceBytes: 1500, Profile: wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1}})
	result := expectTestBody(t, conn, "result").GetOpenResult()
	if !result.Accepted {
		t.Fatalf("session open rejected: %+v", result)
	}
	send := func(event *wire.SessionEvent) {
		sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: event}}})
	}
	read := func() *wire.SessionEvent {
		event := expectTestBody(t, conn, "event").GetCircuitEvent()
		if event.GetSessionEvent() == nil {
			t.Fatalf("missing session event: %+v", event)
		}
		return event.GetSessionEvent()
	}
	ack := func(total uint64) {
		sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + total}})
	}
	bind := userBindForLocalService()[4:]
	send(&wire.SessionEvent{Event: &wire.SessionEvent_BindRequest{BindRequest: bind}})
	bindResult := read().GetBindResult()
	if bindResult == nil || !bindResult.Accepted || len(bindResult.ReducedUnit) < 6 || bindResult.ReducedUnit[5] != 0x31 {
		t.Fatalf("user BIND result: %+v", bindResult)
	}
	if credit := expectTestBody(t, conn, "credit").GetCircuitCredit(); credit.AllowanceBytes != 1500+uint64(len(bind)) {
		t.Fatalf("BIND inbound credit: %+v", credit)
	}
	outbound := uint64(len(bindResult.ReducedUnit))
	ack(outbound)
	attach := []byte{0, 1, 0x0a, 0x90, 0}
	// Carrier-neutral form of the live V5R4 EE APINGD FMH-5 Attach.
	ru, _ := hex.DecodeString("2f0502ff0003d1004006c1d7c9d5c7c400140be2d6d3d5c5e34be2d5c1c2e385edf404aa000108b024ee8df83c8000")
	attach = append(attach, ru...)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: attach}}})
	if grant := read().GetPacingCredit(); grant == nil || grant.Normal != 1 {
		t.Fatalf("Attach grant: %+v", grant)
	}
	expectTestBody(t, conn, "credit")
	version, _ := hex.DecodeString("000e12ff01022b0289f561d6e200")
	request := append([]byte{0, 2, 1, 0x94, 0x20}, version...)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: request}}})
	if grant := read().GetPacingCredit(); grant == nil || grant.Normal != 1 {
		t.Fatalf("version grant: %+v", grant)
	}
	reply := read().GetInformation()
	wantVersion, _ := hex.DecodeString("000e12ff01022b024f532f343030")
	if reply == nil || !bytes.Equal(reply.ReducedUnit[5:], wantVersion) {
		t.Fatalf("version reply: %+v", reply)
	}
	expectTestBody(t, conn, "credit")
	outbound += uint64(len(reply.ReducedUnit))
	ack(outbound)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_PacingCredit{PacingCredit: &wire.SessionPacingCredit{Normal: 3}}})
	packet, _ := hex.DecodeString("001412ff00000000000000000000000000000000")
	request = append([]byte{0, 3, 3, 0x90, 0x20}, packet...)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: request}}})
	if grant := read().GetPacingCredit(); grant == nil || grant.Normal != 1 {
		t.Fatalf("echo grant: %+v", grant)
	}
	reply = read().GetInformation()
	if reply == nil || !bytes.Equal(reply.ReducedUnit[5:], packet) {
		t.Fatalf("echo reply: %+v", reply)
	}
	expectTestBody(t, conn, "credit")
	outbound += uint64(len(reply.ReducedUnit))
	ack(outbound)
	noEcho, _ := hex.DecodeString("000812ff00000000000812ff00000000")
	request = append([]byte{0, 4, 3, 0xa0, 0}, noEcho...)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: request}}})
	if grant := read().GetPacingCredit(); grant == nil || grant.Normal != 1 {
		t.Fatalf("no-echo grant: %+v", grant)
	}
	reply = read().GetInformation()
	if reply == nil || !bytes.Equal(reply.ReducedUnit, []byte{0x80, 0, 0x83, 0xa0, 0}) {
		t.Fatalf("no-echo positive response: %+v", reply)
	}
	expectTestBody(t, conn, "credit")
	outbound += uint64(len(reply.ReducedUnit))
	ack(outbound)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: []byte{0, 5, 0x4b, 0xa0, 1, 4, 0, 6}}}})
	reply = read().GetInformation()
	if reply == nil || !bytes.Equal(reply.ReducedUnit, []byte{0x80, 0, 0xcb, 0xa0, 0, 4}) {
		t.Fatalf("CONFIRM reply: %+v", reply)
	}
	expectTestBody(t, conn, "credit")
	outbound += uint64(len(reply.ReducedUnit))
	ack(outbound)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: []byte{0, 6, 0x4b, 0x90, 0, 0x70}}}})
	if grant := read().GetPacingCredit(); grant == nil || grant.Normal != 1 {
		t.Fatalf("BIS grant: %+v", grant)
	}
	reply = read().GetInformation()
	if reply == nil || !bytes.Equal(reply.ReducedUnit, []byte{0, 3, 0x4b, 0xb0, 0, 0x70}) {
		t.Fatalf("BIS reply: %+v", reply)
	}
	expectTestBody(t, conn, "credit")
	outbound += uint64(len(reply.ReducedUnit))
	ack(outbound)
	fq, err := lu62.RequestFQPCID(userBindForLocalService())
	if err != nil {
		t.Fatal(err)
	}
	unbind := append([]byte{0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}, fq...)
	send(&wire.SessionEvent{Event: &wire.SessionEvent_Unbind{Unbind: unbind}})
	unbindReply := read().GetUnbind()
	if !bytes.Equal(unbindReply, []byte{0, 0, 0xeb, 0x80, 0, 0x32}) {
		t.Fatalf("UNBIND reply: %x", unbindReply)
	}
	expectTestBody(t, conn, "credit")
}

func TestLocalAPINGSessionAcceptsSanitizedV5R4EEBind(t *testing.T) {
	encoded, err := os.ReadFile("../../../sna/lu62/testdata/v5r4_ee_bind_request.hex")
	if err != nil {
		t.Fatal(err)
	}
	reduced, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	a := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.StartLocalSNA(ctx); err != nil {
		t.Fatal(err)
	}
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "v5-ee-bind@example.com", "unused", store.Now(), "NETAAA"); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.DB.CreateRouter(ctx, owner, "V5 EE router")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	conn, welcome := connectTestRouterVersion(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/router/v1/ws", token, "snusnu.v2")
	routes := expectTestBody(t, conn, "routes").GetOriginRoutes()
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{
		{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "NETAAA", Name: "CPAA"}}},
		{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: &wire.SnaName{Netid: "NETAAA", Name: "LUAA"}, HostingCp: &wire.SnaName{Netid: "NETAAA", Name: "CPAA"}, SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
	}}})
	source := &wire.RouteReference{RouterId: welcome.RouterId, Epoch: welcome.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	target := &wire.RouteReference{RouterId: uuidBytes(serviceRouterID), Epoch: routes.Snapshot.Epoch, RouteId: 2, RouteGeneration: 1}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 1, Target: target, SourceRoute: source, ReceiveAllowanceBytes: 1500, Profile: wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1}})
	result := expectTestBody(t, conn, "result").GetOpenResult()
	if !result.Accepted {
		t.Fatalf("V5 session open rejected: %+v", result)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: &wire.SessionEvent{Event: &wire.SessionEvent_BindRequest{BindRequest: reduced}}}}})
	response := expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetBindResult()
	if response == nil || !response.Accepted || len(response.ReducedUnit) < 32 || response.ReducedUnit[2] != 0xeb || response.ReducedUnit[5] != 0x31 {
		t.Fatalf("V5 BIND rejected or malformed: %+v", response)
	}
	if response.ReducedUnit[15] != 0x8c || response.ReducedUnit[16] != 0x8c {
		t.Fatalf("V5 normal-flow RU size lost: %x", response.ReducedUnit[5:22])
	}
	if credit := expectTestBody(t, conn, "credit").GetCircuitCredit(); credit.AllowanceBytes != 1500+uint64(len(reduced)) {
		t.Fatalf("V5 BIND inbound credit: %+v", credit)
	}
}

func TestLocalAPINGSessionAcceptsV5R4EESNASVCMGPingBind(t *testing.T) {
	encoded, err := os.ReadFile("../../../sna/lu62/testdata/v5r4_ee_snasvcmg_ping_bind.hex")
	if err != nil {
		t.Fatal(err)
	}
	reduced, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	a := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.StartLocalSNA(ctx); err != nil {
		t.Fatal(err)
	}
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "v5-snasvcmg@example.com", "unused", store.Now(), "SOLNET"); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.DB.CreateRouter(ctx, owner, "V5 EE SNASVCMG router")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	conn, welcome := connectTestRouterVersion(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/router/v1/ws", token, "snusnu.v2")
	routes := expectTestBody(t, conn, "routes").GetOriginRoutes()
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{
		{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "SOLNET", Name: "SNAB"}}},
		{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: &wire.SnaName{Netid: "SOLNET", Name: "SNAB"}, HostingCp: &wire.SnaName{Netid: "SOLNET", Name: "SNAB"}, SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
	}}})
	source := &wire.RouteReference{RouterId: welcome.RouterId, Epoch: welcome.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	target := &wire.RouteReference{RouterId: uuidBytes(serviceRouterID), Epoch: routes.Snapshot.Epoch, RouteId: 2, RouteGeneration: 1}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 1, Target: target, SourceRoute: source, ReceiveAllowanceBytes: 1500, Profile: wire.CircuitProfile_CIRCUIT_PROFILE_SESSION_V1}})
	result := expectTestBody(t, conn, "result").GetOpenResult()
	if !result.Accepted {
		t.Fatalf("SNASVCMG PING session open rejected: %+v", result)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: &wire.SessionEvent{Event: &wire.SessionEvent_BindRequest{BindRequest: reduced}}}}})
	response := expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetBindResult()
	if response == nil || !response.Accepted || len(response.ReducedUnit) < 35 || response.ReducedUnit[2] != 0xeb || response.ReducedUnit[5] != 0x31 {
		t.Fatalf("SNASVCMG PING BIND rejected or malformed: %+v", response)
	}
	if !bytes.Equal(response.ReducedUnit[5+23:5+26], []byte{0x94, 0x43, 0x40}) {
		t.Fatalf("SNASVCMG PING BIND profile changed: %x", response.ReducedUnit[5:32])
	}
	if response.ReducedUnit[5+8] != 7 || response.ReducedUnit[5+9] != 1 || response.ReducedUnit[5+13] != 7 {
		t.Fatalf("SNASVCMG PING management pacing window differs from accepted V5R4 profile: %x", response.ReducedUnit[5:32])
	}
	if credit := expectTestBody(t, conn, "credit").GetCircuitCredit(); credit.AllowanceBytes != 1500+uint64(len(reduced)) {
		t.Fatalf("SNASVCMG PING BIND inbound credit: %+v", credit)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + uint64(len(response.ReducedUnit))}})
	// The live V5R4 guest sends this CNOS control-operator Attach after the
	// SNASVCMG BIND. The neutral wire has already removed the carrier PI bit.
	cnos, err := hex.DecodeString("00010b90200c0502ff0003d000000206f100191210020000000000080004000400084040404040404040")
	if err != nil {
		t.Fatal(err)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: &wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: cnos}}}}}})
	grant := expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetPacingCredit()
	if grant == nil || grant.Normal != 1 || grant.Expedited != 0 {
		t.Fatalf("CNOS pacing grant: %+v", grant)
	}
	cnosReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetInformation()
	if cnosReply == nil || !bytes.Equal(cnosReply.ReducedUnit[5:10], []byte{0, 0x19, 0x12, 0x10, 0x0a}) {
		t.Fatalf("CNOS accepted-pending reply: %+v", cnosReply)
	}
	if credit := expectTestBody(t, conn, "credit").GetCircuitCredit(); credit.AllowanceBytes != 1500+uint64(len(reduced)+len(cnos)) {
		t.Fatalf("CNOS inbound credit: %+v", credit)
	}
	outbound := uint64(len(response.ReducedUnit) + len(cnosReply.ReducedUnit))
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + outbound}})
	// V5R4 acknowledges the accepted-pending CNOS response with an IPR
	// before sending its bilateral shutdown request.
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: &wire.SessionEvent{Event: &wire.SessionEvent_PacingCredit{PacingCredit: &wire.SessionPacingCredit{Normal: 7}}}}}})
	bis := []byte{0, 2, 0x4b, 0x90, 0, 0x70}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: &wire.SessionEvent{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: bis}}}}}})
	grant = expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetPacingCredit()
	if grant == nil || grant.Normal != 1 {
		t.Fatalf("BIS pacing grant: %+v", grant)
	}
	bisReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetInformation()
	if bisReply == nil || !bytes.Equal(bisReply.ReducedUnit, []byte{0, 2, 0x4b, 0xb0, 0, 0x70}) {
		t.Fatalf("BIS reply: %+v", bisReply)
	}
	expectTestBody(t, conn, "credit")
	outbound += uint64(len(bisReply.ReducedUnit))
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: result.CircuitId, AllowanceBytes: 1500 + outbound}})
	fq, err := lu62.RequestFQPCID(append([]byte{0x2f, 0, 1, 2}, reduced...))
	if err != nil {
		t.Fatal(err)
	}
	unbind := append([]byte{0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}, fq...)
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_SessionEvent{SessionEvent: &wire.SessionEvent{Event: &wire.SessionEvent_Unbind{Unbind: unbind}}}}})
	unbindReply := expectTestBody(t, conn, "event").GetCircuitEvent().GetSessionEvent().GetUnbind()
	if !bytes.Equal(unbindReply, []byte{0, 0, 0xeb, 0x80, 0, 0x32}) {
		t.Fatalf("management UNBIND reply: %x", unbindReply)
	}
	expectTestBody(t, conn, "credit")
}
