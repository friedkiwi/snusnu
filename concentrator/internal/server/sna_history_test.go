package server

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func insertCircuitHistory(t *testing.T, a *App, record circuitHistoryRecord) {
	t.Helper()
	_, err := a.DB.Exec(context.Background(), `INSERT INTO sna_circuit_history(id,source_router_id,source_router_name,source_owner_id,target_router_id,target_router_name,target_owner_id,profile,opened_at,activated_at,closed_at,state,close_reason,source_bytes,target_bytes,source_events,target_events,peak_queued_bytes,actor_type,actor_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.ID, record.SourceRouterID, record.SourceRouterName, record.SourceOwnerID, record.TargetRouterID, record.TargetRouterName, record.TargetOwnerID, record.Profile, record.OpenedAt, record.ActivatedAt, record.ClosedAt, record.State, record.CloseReason, record.SourceBytes, record.TargetBytes, record.SourceEvents, record.TargetEvents, record.PeakQueuedBytes, record.ActorType, record.ActorID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCircuitHistoryWriteFailureTriggersFatalDrain(t *testing.T) {
	a := testApp(t)
	if err := a.DB.DB.Close(); err != nil {
		t.Fatal(err)
	}
	record := circuitHistoryRecord{ID: store.RandomUUID(), SourceRouterID: store.RandomUUID(), SourceOwnerID: store.RandomUUID(), TargetRouterID: store.RandomUUID(), TargetOwnerID: store.RandomUUID(), Profile: snaCircuitProfile, ClosedAt: store.Now(), State: "reset"}
	a.historyPending[record.ID] = pendingCircuitHistory{Record: record, Status: "writing"}
	a.persistCircuitHistory(record)
	select {
	case err := <-a.Fatal():
		if err == nil || !a.hub.draining.Load() {
			t.Fatalf("fatal state: %v draining=%v", err, a.hub.draining.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("history persistence failure did not trigger fatal shutdown")
	}
	if pending := a.historyPending[record.ID]; pending.Status != "failed" {
		t.Fatalf("pending status: %+v", pending)
	}
}

func TestCircuitHistorySearchPagingAndOwnerScope(t *testing.T) {
	a := testApp(t)
	owner, other := store.RandomUUID(), store.RandomUUID()
	var inserted []string
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", i+1)
		inserted = append(inserted, id)
		insertCircuitHistory(t, a, circuitHistoryRecord{ID: id, SourceRouterID: store.RandomUUID(), SourceRouterName: fmt.Sprintf("Needle router %d", i), SourceOwnerID: owner, TargetRouterID: store.RandomUUID(), TargetRouterName: "Peer", TargetOwnerID: other, Profile: snaCircuitProfile, OpenedAt: 10, ActivatedAt: 11, ClosedAt: 20, State: "reset", CloseReason: "operator reset", ActorType: "admin", ActorID: "admin@example.com"})
	}
	insertCircuitHistory(t, a, circuitHistoryRecord{ID: store.RandomUUID(), SourceRouterID: store.RandomUUID(), SourceRouterName: "Unrelated", SourceOwnerID: other, TargetRouterID: store.RandomUUID(), TargetRouterName: "Peer", TargetOwnerID: other, Profile: snaCircuitProfile, OpenedAt: 10, ClosedAt: 30, State: "closed", CloseReason: "normal close"})
	page := circuitHistoryPage{Search: "needle", State: "reset", PageSize: 2}
	if err := a.circuitHistoryRows(context.Background(), owner, false, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != inserted[2] || page.Items[1].ID != inserted[1] || page.PrevURL != "" || page.NextURL == "" {
		t.Fatalf("unexpected page: %+v", page)
	}

	request := httptest.NewRequest("GET", "/circuits"+page.NextURL, nil)
	next := circuitHistoryFilter(request)
	if err := a.circuitHistoryRows(context.Background(), owner, false, &next); err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 1 || next.Items[0].ID != inserted[0] || next.PrevURL == "" || next.NextURL != "" {
		t.Fatalf("unexpected next page: %+v", next)
	}

	request = httptest.NewRequest("GET", "/circuits"+next.PrevURL, nil)
	previous := circuitHistoryFilter(request)
	if err := a.circuitHistoryRows(context.Background(), owner, false, &previous); err != nil {
		t.Fatal(err)
	}
	if len(previous.Items) != 2 || previous.Items[0].ID != inserted[2] || previous.Items[1].ID != inserted[1] || previous.PrevURL != "" || previous.NextURL == "" {
		t.Fatalf("unexpected previous page: %+v", previous)
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
