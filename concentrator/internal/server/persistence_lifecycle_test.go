package server

import (
	"context"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func TestSignalCancellationDoesNotStopPersistenceWorkersBeforeDrain(t *testing.T) {
	a := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	a.StartMaintenance(ctx)
	defer func() {
		shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = a.ShutdownBackground(shutdownCtx)
	}()
	owner := store.RandomUUID()
	if _, err := a.DB.Exec(context.Background(), "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", owner, "shutdown-worker@example.com", "unused", store.Now()); err != nil {
		t.Fatal(err)
	}
	router, _, err := a.DB.CreateRouter(context.Background(), owner, "Shutdown worker")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	a.enqueueRouterLog(store.LogEntry{RouterID: router.ID, Direction: "system", Level: "info", EventType: "shutdown", Summary: "queued after signal cancellation"})
	deadline := time.Now().Add(time.Second)
	for {
		var count int
		err = a.DB.Row(context.Background(), "SELECT COUNT(*) FROM router_logs WHERE router_id=?", router.ID).Scan(&count)
		if err == nil && count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("post-signal record was not persisted: count=%d err=%v", count, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRemovedRouterLogIsDiscardedWithoutFatalShutdown(t *testing.T) {
	a := testApp(t)
	entry := store.LogEntry{RouterID: store.RandomUUID(), Direction: "system", Level: "info", EventType: "stale", Summary: "removed router"}
	a.persistRouterLog(entry)
	if got := a.routerLogStale.Load(); got != 1 {
		t.Fatalf("stale discard count: %d", got)
	}
	select {
	case err := <-a.Fatal():
		t.Fatalf("stale record triggered fatal shutdown: %v", err)
	default:
	}
	if a.hub.draining.Load() {
		t.Fatal("stale record marked concentrator draining")
	}
}
