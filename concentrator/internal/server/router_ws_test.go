package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func connectTestRouter(t *testing.T, url, token string) (*websocket.Conn, *wire.RouterWelcome) {
	return connectTestRouterVersion(t, url, token, "snusnu.v1")
}
func connectTestRouterVersion(t *testing.T, url, token, version string) (*websocket.Conn, *wire.RouterWelcome) {
	t.Helper()
	headers := http.Header{"Authorization": []string{"Bearer " + token}, "Sec-WebSocket-Protocol": []string{version}}
	conn, response, err := websocket.DefaultDialer.Dial(url, headers)
	if err != nil {
		if response != nil {
			t.Fatalf("dial: %v status %d", err, response.StatusCode)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if conn.Subprotocol() != version {
		t.Fatalf("selected subprotocol %q, wanted %q", conn.Subprotocol(), version)
	}
	envelope := readTestEnvelope(t, conn)
	welcome := envelope.GetWelcome()
	if welcome == nil || len(welcome.RouterId) != 16 || len(welcome.ConnectionEpoch) != 16 || welcome.DisplayName == "" || !store.ValidNetID(welcome.AllowedNetid) {
		t.Fatalf("bad welcome: %+v", envelope)
	}
	return conn, welcome
}
func readTestEnvelope(t *testing.T, conn *websocket.Conn) *wire.WsEnvelope {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	kind, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if kind != websocket.BinaryMessage {
		t.Fatalf("non-binary frame %d", kind)
	}
	var envelope wire.WsEnvelope
	if err := proto.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	return &envelope
}
func sendTestEnvelope(t *testing.T, conn *websocket.Conn, body any) {
	t.Helper()
	envelope := &wire.WsEnvelope{}
	switch b := body.(type) {
	case *wire.WsEnvelope_PublishRoutes:
		envelope.Body = b
	case *wire.WsEnvelope_OpenRequest:
		envelope.Body = b
	case *wire.WsEnvelope_OpenDecision:
		envelope.Body = b
	case *wire.WsEnvelope_CircuitEvent:
		envelope.Body = b
	case *wire.WsEnvelope_CircuitCredit:
		envelope.Body = b
	case *wire.WsEnvelope_CircuitClose:
		envelope.Body = b
	default:
		t.Fatalf("unsupported test body %T", body)
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
}
func expectTestBody(t *testing.T, conn *websocket.Conn, kind string) *wire.WsEnvelope {
	t.Helper()
	for i := 0; i < 5; i++ {
		envelope := readTestEnvelope(t, conn)
		if envelope.GetManagedCpBindings() != nil {
			continue
		}
		switch kind {
		case "routes":
			if envelope.GetOriginRoutes() != nil {
				return envelope
			}
		case "open":
			if envelope.GetIncomingOpen() != nil {
				return envelope
			}
		case "result":
			if envelope.GetOpenResult() != nil {
				return envelope
			}
		case "ready":
			if envelope.GetOpenReady() != nil {
				return envelope
			}
		case "event":
			if envelope.GetCircuitEvent() != nil {
				return envelope
			}
		case "credit":
			if envelope.GetCircuitCredit() != nil {
				return envelope
			}
		case "close":
			if envelope.GetCircuitClose() != nil {
				return envelope
			}
		case "withdraw":
			if envelope.GetOriginWithdraw() != nil {
				return envelope
			}
		}
		t.Fatalf("wanted %s, got %T", kind, envelope.Body)
	}
	t.Fatalf("missing %s", kind)
	return nil
}
func TestRouterWebSocketSoftwareIdentityAndUpdate(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	ownerID := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", ownerID, "software@example.com", "unused", store.Now(), "SWTEST"); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.DB.CreateRouter(ctx, ownerID, "Software test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/router/v1/ws"
	dial := func(name, version string) *wire.RouterWelcome {
		t.Helper()
		headers := http.Header{"Authorization": []string{"Bearer " + token}, "Sec-WebSocket-Protocol": []string{"snusnu.v2"}, softwareNameHeader: []string{name}, softwareVersionHeader: []string{version}}
		conn, response, err := websocket.DefaultDialer.Dial(url, headers)
		if err != nil {
			t.Fatalf("dial %s %s: %v, response %+v", name, version, err, response)
		}
		defer conn.Close()
		welcome := readTestEnvelope(t, conn).GetWelcome()
		if welcome == nil {
			t.Fatal("missing welcome")
		}
		return welcome
	}
	if update := dial("sna_router", "0.0.1").GetSoftwareUpdateAvailable(); update == nil || update.LatestVersion != latestSnaRouterVersion {
		t.Fatalf("older first-party router missing update: %+v", update)
	}
	if update := dial("sna_router", "999.0.0").GetSoftwareUpdateAvailable(); update != nil {
		t.Fatalf("newer router rejected or given update: %+v", update)
	}
	if update := dial("independent-router", "0.0.1").GetSoftwareUpdateAvailable(); update != nil {
		t.Fatalf("third-party router given first-party update: %+v", update)
	}
	previousPolicy := snaRouterPolicy
	snaRouterPolicy = softwarePolicy{minimumVersion: "0.1.0", blockedVersions: map[string]bool{"0.1.0": true}}
	defer func() { snaRouterPolicy = previousPolicy }()
	for _, version := range []string{"0.0.1", "0.1.0"} {
		headers := http.Header{"Authorization": []string{"Bearer " + token}, "Sec-WebSocket-Protocol": []string{"snusnu.v2"}, softwareNameHeader: []string{"sna_router"}, softwareVersionHeader: []string{version}}
		conn, response, err := websocket.DefaultDialer.Dial(url, headers)
		if conn != nil {
			conn.Close()
		}
		if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
			t.Fatalf("blocked version %s: error %v, response %+v", version, err, response)
		}
	}
}

func TestRouterWebSocketTwoPeerCircuit(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	ids := []string{store.RandomUUID(), store.RandomUUID()}
	for i, id := range ids {
		if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", id, []string{"ws-a@example.com", "ws-b@example.com"}[i], "unused", store.Now(), []string{"NETA", "NETB"}[i]); err != nil {
			t.Fatal(err)
		}
	}
	first, firstToken, err := a.DB.CreateRouter(ctx, ids[0], "Router A")
	if err != nil {
		t.Fatal(err)
	}
	second, secondToken, err := a.DB.CreateRouter(ctx, ids[1], "Router B")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/router/v1/ws"
	_, response, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer invalid"}, "Sec-WebSocket-Protocol": []string{"snusnu.v1"}})
	if err == nil || response == nil || response.StatusCode != 401 {
		t.Fatalf("invalid token accepted: %v %+v", err, response)
	}
	ca, wa := connectTestRouter(t, wsURL, firstToken)
	cb, wb := connectTestRouter(t, wsURL, secondToken)
	if string(wa.RouterId) != string(uuidBytes(first.ID)) || string(wb.RouterId) != string(uuidBytes(second.ID)) {
		t.Fatal("welcome identity mismatch")
	}
	cp := func(netid, name string) *wire.SnaName { return &wire.SnaName{Netid: netid, Name: name} }
	snapshot := func(epoch []byte, netid, name string) *wire.RouteSnapshot {
		return &wire.RouteSnapshot{Epoch: epoch, Revision: 1, Routes: []*wire.RouteExport{{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: cp(netid, name)}}}}
	}
	sendTestEnvelope(t, ca, &wire.WsEnvelope_PublishRoutes{PublishRoutes: snapshot(wa.ConnectionEpoch, "NETA", "SNAA")})
	sendTestEnvelope(t, cb, &wire.WsEnvelope_PublishRoutes{PublishRoutes: snapshot(wb.ConnectionEpoch, "NETB", "SNAB")})
	ra := expectTestBody(t, ca, "routes").GetOriginRoutes()
	rb := expectTestBody(t, cb, "routes").GetOriginRoutes()
	if string(ra.RouterId) != string(wb.RouterId) || string(rb.RouterId) != string(wa.RouterId) {
		t.Fatal("origin identities not server-stamped")
	}
	ref := &wire.RouteReference{RouterId: wb.RouterId, Epoch: wb.ConnectionEpoch, RouteId: 1, RouteGeneration: 1}
	sendTestEnvelope(t, ca, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 1, Target: ref, ReceiveAllowanceBytes: 2000}})
	incoming := expectTestBody(t, cb, "open").GetIncomingOpen()
	if string(incoming.SourceRouterId) != string(wa.RouterId) || string(incoming.Target.RouterId) != string(wb.RouterId) {
		t.Fatal("bad incoming open")
	}
	sendTestEnvelope(t, cb, &wire.WsEnvelope_OpenDecision{OpenDecision: &wire.OpenDecision{CircuitId: incoming.CircuitId, Accept: true, ReceiveAllowanceBytes: 1500}})
	if string(expectTestBody(t, cb, "ready").GetOpenReady().CircuitId) != string(incoming.CircuitId) {
		t.Fatal("missing ready")
	}
	result := expectTestBody(t, ca, "result").GetOpenResult()
	if !result.Accepted || result.PeerReceiveAllowanceBytes != 1500 {
		t.Fatalf("open result %+v", result)
	}
	sendTestEnvelope(t, ca, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: incoming.CircuitId, Event: &wire.CircuitEvent_SnaInformation{SnaInformation: []byte{1, 2, 3}}}})
	if got := expectTestBody(t, cb, "event").GetCircuitEvent().GetSnaInformation(); len(got) != 3 {
		t.Fatalf("forwarded data %v", got)
	}
	sendTestEnvelope(t, cb, &wire.WsEnvelope_CircuitCredit{CircuitCredit: &wire.CircuitCredit{CircuitId: incoming.CircuitId, AllowanceBytes: 3000}})
	if got := expectTestBody(t, ca, "credit").GetCircuitCredit().AllowanceBytes; got != 3000 {
		t.Fatalf("credit %d", got)
	}
	sendTestEnvelope(t, ca, &wire.WsEnvelope_CircuitClose{CircuitClose: &wire.CircuitClose{CircuitId: incoming.CircuitId}})
	expectTestBody(t, cb, "close")
	if err := a.setBlock(ctx, ids[0], ids[1], true); err != nil {
		t.Fatal(err)
	}
	expectTestBody(t, ca, "withdraw")
	expectTestBody(t, cb, "withdraw")
	if err := a.setBlock(ctx, ids[0], ids[1], false); err != nil {
		t.Fatal(err)
	}
	expectTestBody(t, ca, "routes")
	expectTestBody(t, cb, "routes")
}

func TestRouterWebSocketManagedBindingsAndRevocation(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	owner, recipientOwner := store.RandomUUID(), store.RandomUUID()
	for _, x := range []struct{ id, email, netid string }{{owner, "cp-owner@example.com", "SOLNET"}, {recipientOwner, "llc-owner@example.com", "LLCNET"}} {
		if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", x.id, x.email, "unused", store.Now(), x.netid); err != nil {
			t.Fatal(err)
		}
	}
	origin, originToken, err := a.DB.CreateRouter(ctx, owner, "CP origin")
	if err != nil {
		t.Fatal(err)
	}
	recipient, recipientToken, err := a.DB.CreateRouter(ctx, recipientOwner, "LLC recipient")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.DB.SetRouterLLCFacing(ctx, recipient.ID, true); err != nil {
		t.Fatal(err)
	}
	cp, err := a.DB.AllocateManagedCP(ctx, owner, "SOLNET", "SNAB")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/router/v1/ws"
	llc, wl := connectTestRouter(t, url, recipientToken)
	initial := readTestEnvelope(t, llc).GetManagedCpBindings()
	if initial == nil || initial.SchemaVersion != 1 || len(initial.Bindings) != 0 {
		t.Fatalf("initial bindings %+v", initial)
	}
	source, ws := connectTestRouter(t, url, originToken)
	sendTestEnvelope(t, source, &wire.WsEnvelope_PublishRoutes{PublishRoutes: &wire.RouteSnapshot{Epoch: ws.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "SOLNET", Name: "SNAB"}}}}}})
	expectTestBody(t, llc, "routes")
	binding := readTestEnvelope(t, llc).GetManagedCpBindings()
	if binding == nil || binding.Revision <= initial.Revision || len(binding.Bindings) != 1 {
		t.Fatalf("published bindings %+v", binding)
	}
	entry := binding.Bindings[0]
	mac := cp.MACBytes()
	if string(entry.AddressId) != string(uuidBytes(cp.ID)) || string(entry.VirtualMac) != string(mac[:]) || len(entry.Candidates) != 1 || string(entry.Candidates[0].RouterId) != string(uuidBytes(origin.ID)) {
		t.Fatalf("incorrect binding %+v", entry)
	}
	if err := a.setBlock(ctx, recipientOwner, owner, true); err != nil {
		t.Fatal(err)
	}
	expectTestBody(t, llc, "withdraw")
	empty := readTestEnvelope(t, llc).GetManagedCpBindings()
	if empty == nil || len(empty.Bindings) != 0 || empty.Revision <= binding.Revision {
		t.Fatalf("block did not withdraw binding %+v", empty)
	}
	if _, err := a.DB.RotateRouterToken(ctx, recipient.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.hub.refreshPolicyAndRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	llc.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := llc.ReadMessage(); err == nil {
		t.Fatal("revoked router socket remained open")
	}
	if _, err := a.DB.RouterByToken(ctx, recipientToken); err == nil {
		t.Fatal("old token still valid")
	}
	_ = wl
}

func TestRouterWebSocketRejectsRetargetWithoutGeneration(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "retarget@example.com", "unused", store.Now(), "SOLNET"); err != nil {
		t.Fatal(err)
	}
	_, token, err := a.DB.CreateRouter(ctx, owner, "Route publisher")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/router/v1/ws"
	conn, welcome := connectTestRouter(t, url, token)
	makeSnapshot := func(revision uint64, name string) *wire.RouteSnapshot {
		return &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: revision, Routes: []*wire.RouteExport{{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "SOLNET", Name: name}}}}}
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: makeSnapshot(1, "SNAA")})
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: makeSnapshot(2, "SNAB")})
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("retargeted route accepted without new generation")
	}
}

func TestRouterWebSocketRejectsUnownedNETID(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "namespace@example.com", "unused", store.Now(), "OWNNET"); err != nil {
		t.Fatal(err)
	}
	router, token, err := a.DB.CreateRouter(ctx, owner, "Namespace publisher")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/router/v1/ws"
	conn, welcome := connectTestRouter(t, url, token)
	if welcome.AllowedNetid != "OWNNET" {
		t.Fatalf("welcome NETID: %q", welcome.AllowedNetid)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "OTHER", Name: "SNAA"}}}}}})
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("unowned NETID publication kept connection open")
	}
	var count int
	if err = a.DB.Row(ctx, "SELECT COUNT(*) FROM router_advertisements WHERE router_id=?", router.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unowned advertisement persisted: %d %v", count, err)
	}
}

func TestRouterWebSocketV2SourceLUBinding(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	owners := []string{store.RandomUUID(), store.RandomUUID()}
	tokens := make([]string, 2)
	for i, owner := range owners {
		if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, []string{"v2-a@example.com", "v2-b@example.com"}[i], "unused", store.Now(), []string{"NETA", "NETB"}[i]); err != nil {
			t.Fatal(err)
		}
		_, token, err := a.DB.CreateRouter(ctx, owner, "V2 router")
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = token
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/router/v1/ws"
	ca, wa := connectTestRouterVersion(t, url, tokens[0], "snusnu.v2")
	cb, wb := connectTestRouterVersion(t, url, tokens[1], "snusnu.v2")
	name := func(netid, value string) *wire.SnaName { return &wire.SnaName{Netid: netid, Name: value} }
	snapshot := func(epoch []byte, netid, cp, lu string) *wire.RouteSnapshot {
		return &wire.RouteSnapshot{Epoch: epoch, Revision: 1, Routes: []*wire.RouteExport{
			{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: name(netid, cp)}},
			{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: name(netid, lu), HostingCp: name(netid, cp), SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
		}}
	}
	sendTestEnvelope(t, ca, &wire.WsEnvelope_PublishRoutes{PublishRoutes: snapshot(wa.ConnectionEpoch, "NETA", "SNAA", "LUA")})
	sendTestEnvelope(t, cb, &wire.WsEnvelope_PublishRoutes{PublishRoutes: snapshot(wb.ConnectionEpoch, "NETB", "SNAB", "LUB")})
	expectTestBody(t, ca, "routes")
	expectTestBody(t, cb, "routes")
	source := &wire.RouteReference{RouterId: wa.RouterId, Epoch: wa.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	target := &wire.RouteReference{RouterId: wb.RouterId, Epoch: wb.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	open := func(id uint64, ref *wire.RouteReference) {
		sendTestEnvelope(t, ca, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: id, Target: target, SourceRoute: ref, ReceiveAllowanceBytes: 1500}})
	}
	for id, forged := range []*wire.RouteReference{
		{RouterId: wb.RouterId, Epoch: wa.ConnectionEpoch, RouteId: 2, RouteGeneration: 1},
		{RouterId: wa.RouterId, Epoch: make([]byte, 16), RouteId: 2, RouteGeneration: 1},
		{RouterId: wa.RouterId, Epoch: wa.ConnectionEpoch, RouteId: 1, RouteGeneration: 1},
	} {
		open(uint64(id+1), forged)
		result := expectTestBody(t, ca, "result").GetOpenResult()
		if result.Accepted || result.Reason != wire.OpenFailure_OPEN_FAILURE_FORBIDDEN {
			t.Fatalf("forged source %d accepted: %+v", id, result)
		}
	}
	open(4, source)
	incoming := expectTestBody(t, cb, "open").GetIncomingOpen()
	if !proto.Equal(incoming.SourceRoute, source) || !proto.Equal(incoming.Target, target) || string(incoming.SourceRouterId) != string(wa.RouterId) {
		t.Fatalf("v2 source LU was not server stamped and relayed: %+v", incoming)
	}
	sendTestEnvelope(t, cb, &wire.WsEnvelope_OpenDecision{OpenDecision: &wire.OpenDecision{CircuitId: incoming.CircuitId, Accept: true, ReceiveAllowanceBytes: 1500}})
	expectTestBody(t, cb, "ready")
	if !expectTestBody(t, ca, "result").GetOpenResult().Accepted {
		t.Fatal("valid v2 LU circuit rejected")
	}
	// Withdrawal of the exact source LU invalidates the established circuit.
	sendTestEnvelope(t, ca, &wire.WsEnvelope_PublishRoutes{PublishRoutes: &wire.RouteSnapshot{
		Epoch: wa.ConnectionEpoch, Revision: 2,
		Routes: []*wire.RouteExport{{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: name("NETA", "SNAA")}}},
	}})
	for i := 0; i < 3; i++ {
		message := readTestEnvelope(t, cb)
		if message.GetCircuitReset() != nil {
			if message.GetCircuitReset().Reason != wire.ResetReason_RESET_REASON_ROUTE_GONE {
				t.Fatalf("wrong source withdrawal reset: %+v", message.GetCircuitReset())
			}
			return
		}
		if message.GetOriginRoutes() == nil {
			t.Fatalf("unexpected source withdrawal message: %T", message.Body)
		}
	}
	t.Fatal("source LU withdrawal did not reset v2 circuit")
}
