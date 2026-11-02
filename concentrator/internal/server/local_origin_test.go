package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"google.golang.org/protobuf/proto"
)

func TestLocalServiceRouteAndStampedSource(t *testing.T) {
	a := testApp(t)
	owner := store.RandomUUID()
	serviceCtx, cancelService := context.WithCancel(context.Background())
	t.Cleanup(cancelService)
	incoming := make(chan *wire.IncomingOpen, 1)
	events := make(chan *wire.CircuitEvent, 1)
	if err := a.hub.registerLocalService(serviceCtx, func(envelope *wire.WsEnvelope, peer LocalPeer) {
		if open := envelope.GetIncomingOpen(); open != nil {
			if peer.OwnerID != owner || peer.NetID != "PEERNET" || peer.CP != "CP" || peer.LU != "LU" {
				t.Errorf("wrong local peer: %+v", peer)
			}
			if stamped := peer.SNAPeer(); !stamped.Valid() || stamped.Principal != owner || stamped.NetID != "PEERNET" || stamped.CP != "CP" || stamped.LU != "LU" {
				t.Errorf("wrong SNA peer: %+v", stamped)
			}
			incoming <- open
			_ = a.hub.decision(a.hub.local, &wire.OpenDecision{CircuitId: open.CircuitId, Accept: true, ReceiveAllowanceBytes: 1500})
		}
		if event := envelope.GetCircuitEvent(); event != nil {
			events <- event
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.hub.registerLocalService(serviceCtx, func(*wire.WsEnvelope, LocalPeer) {}); err == nil {
		t.Fatal("duplicate local origin")
	}
	ctx := context.Background()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", owner, "local-peer@example.com", "unused", store.Now(), "PEERNET"); err != nil {
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
	if string(routes.RouterId) != string(uuidBytes(serviceRouterID)) || len(routes.Snapshot.Routes) != 2 || routes.Snapshot.Routes[1].GetLogicalUnit().Lu.Netid != "SNUSNU" {
		t.Fatalf("local routes: %+v", routes)
	}
	sourceSnapshot := &wire.RouteSnapshot{Epoch: welcome.ConnectionEpoch, Revision: 1, Routes: []*wire.RouteExport{
		{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: &wire.SnaName{Netid: "PEERNET", Name: "CP"}}},
		{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: &wire.SnaName{Netid: "PEERNET", Name: "LU"}, HostingCp: &wire.SnaName{Netid: "PEERNET", Name: "CP"}, SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
		{Id: 3, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: &wire.SnaName{Netid: "PEERNET", Name: "LU0"}, HostingCp: &wire.SnaName{Netid: "PEERNET", Name: "CP"}, SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_0}}}},
	}}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_PublishRoutes{PublishRoutes: sourceSnapshot})
	source := &wire.RouteReference{RouterId: welcome.RouterId, Epoch: welcome.ConnectionEpoch, RouteId: 2, RouteGeneration: 1}
	target := &wire.RouteReference{RouterId: uuidBytes(serviceRouterID), Epoch: routes.Snapshot.Epoch, RouteId: 2, RouteGeneration: 1}
	nonAppc := proto.Clone(source).(*wire.RouteReference)
	nonAppc.RouteId = 3
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 8, Target: target, SourceRoute: nonAppc, ReceiveAllowanceBytes: 1500}})
	unsupported := expectTestBody(t, conn, "result").GetOpenResult()
	if unsupported.Accepted || unsupported.Reason != wire.OpenFailure_OPEN_FAILURE_UNSUPPORTED {
		t.Fatalf("non-LU 6.2 source accepted: %+v", unsupported)
	}
	forged := proto.Clone(source).(*wire.RouteReference)
	forged.RouteId = 1 // The peer's CP is not a source LU.
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 9, Target: target, SourceRoute: forged, ReceiveAllowanceBytes: 1500}})
	denied := expectTestBody(t, conn, "result").GetOpenResult()
	if denied.Accepted || denied.Reason != wire.OpenFailure_OPEN_FAILURE_FORBIDDEN {
		t.Fatalf("forged local source accepted: %+v", denied)
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_OpenRequest{OpenRequest: &wire.OpenRequest{RequestId: 1, Target: target, SourceRoute: source, ReceiveAllowanceBytes: 1500}})
	result := expectTestBody(t, conn, "result").GetOpenResult()
	if !result.Accepted {
		t.Fatalf("local open rejected: %+v", result)
	}
	select {
	case open := <-incoming:
		if string(open.SourceRouterId) != string(welcome.RouterId) || !proto.Equal(open.SourceRoute, source) {
			t.Fatalf("unstamped source: %+v", open)
		}
	case <-time.After(time.Second):
		t.Fatal("local handler missed open")
	}
	sendTestEnvelope(t, conn, &wire.WsEnvelope_CircuitEvent{CircuitEvent: &wire.CircuitEvent{CircuitId: result.CircuitId, Event: &wire.CircuitEvent_LinkReady{LinkReady: &wire.LinkReady{}}}})
	select {
	case event := <-events:
		if event.GetLinkReady() == nil {
			t.Fatalf("wrong local event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("local handler missed circuit event")
	}
}
