package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func insertCircuitHistory(t *testing.T, a *App, record circuitHistoryRecord) {
	t.Helper()
	_, err := a.DB.Exec(context.Background(), `INSERT INTO sna_circuit_history(id,source_router_id,source_router_name,source_owner_id,target_router_id,target_router_name,target_owner_id,profile,opened_at,activated_at,closed_at,state,close_reason,source_bytes,target_bytes,source_events,target_events,peak_queued_bytes,actor_type,actor_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.ID, record.SourceRouterID, record.SourceRouterName, record.SourceOwnerID, record.TargetRouterID, record.TargetRouterName, record.TargetOwnerID, record.Profile, record.OpenedAt, record.ActivatedAt, record.ClosedAt, record.State, record.CloseReason, record.SourceBytes, record.TargetBytes, record.SourceEvents, record.TargetEvents, record.PeakQueuedBytes, record.ActorType, record.ActorID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCircuitHistorySearchPagingAndOwnerScope(t *testing.T) {
	a := testApp(t)
	owner, other := store.RandomUUID(), store.RandomUUID()
	for i := 0; i < 3; i++ {
		insertCircuitHistory(t, a, circuitHistoryRecord{ID: store.RandomUUID(), SourceRouterID: store.RandomUUID(), SourceRouterName: fmt.Sprintf("Needle router %d", i), SourceOwnerID: owner, TargetRouterID: store.RandomUUID(), TargetRouterName: "Peer", TargetOwnerID: other, Profile: snaCircuitProfile, OpenedAt: 10, ActivatedAt: 11, ClosedAt: int64(20 + i), State: "reset", CloseReason: "operator reset", ActorType: "admin", ActorID: "admin@example.com"})
	}
	insertCircuitHistory(t, a, circuitHistoryRecord{ID: store.RandomUUID(), SourceRouterID: store.RandomUUID(), SourceRouterName: "Unrelated", SourceOwnerID: other, TargetRouterID: store.RandomUUID(), TargetRouterName: "Peer", TargetOwnerID: other, Profile: snaCircuitProfile, OpenedAt: 10, ClosedAt: 30, State: "closed", CloseReason: "normal close"})
	page := circuitHistoryPage{Search: "needle", State: "reset", Page: 2, PageSize: 2}
	if err := a.circuitHistoryRows(context.Background(), owner, false, &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Pages != 2 || page.Page != 2 || len(page.Items) != 1 || page.PrevURL == "" || page.NextURL != "" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestPendingCircuitHistoryRemainsVisibleAndScoped(t *testing.T) {
	a := testApp(t)
	owner, other := store.RandomUUID(), store.RandomUUID()
	record := circuitHistoryRecord{ID: store.RandomUUID(), SourceRouterID: store.RandomUUID(), SourceRouterName: "Queued source", SourceOwnerID: owner, TargetRouterID: store.RandomUUID(), TargetRouterName: "Queued target", TargetOwnerID: other, State: "reset", CloseReason: "queue test", ClosedAt: store.Now()}
	a.historyPending[record.ID] = pendingCircuitHistory{Record: record, Status: "writing"}
	items := a.pendingCircuitHistory(owner, false, circuitHistoryPage{Search: "queue test"})
	if len(items) != 1 || items[0].Persistence != "writing" {
		t.Fatalf("pending history: %+v", items)
	}
	if items = a.pendingCircuitHistory(store.RandomUUID(), false, circuitHistoryPage{}); len(items) != 0 {
		t.Fatalf("unrelated owner saw pending history: %+v", items)
	}
}
