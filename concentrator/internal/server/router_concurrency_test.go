package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func cachedTestSession(id, owner, token, epoch string) *routerSession {
	return &routerSession{
		router: store.Router{ID: id, OwnerID: owner, DisplayName: id}, token: token, epoch: epoch, allowedNetID: "SOLNET",
		out: newDynamicQueue[outboundMessage](4096, 32<<20, func(x outboundMessage) int { return len(x.data) }), done: make(chan struct{}), sent: map[string]routeVersion{}, queued: map[string]int{}, history: map[uint64]routeSignature{},
	}
}

func TestPendingRequestReservationIsPerSessionAndConcurrent(t *testing.T) {
	session := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "source-token", store.RandomUUID())
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reservePendingRequest(session, 42) {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := won.Load(); got != 1 {
		t.Fatalf("reservation winners: %d", got)
	}
	other := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "other-token", store.RandomUUID())
	if !reservePendingRequest(other, 42) {
		t.Fatal("request IDs should be scoped to one router session")
	}
	releasePendingRequest(session, 42)
	if !reservePendingRequest(session, 42) {
		t.Fatal("released request ID could not be reused")
	}
}

func TestCircuitTeardownReleasesPendingRequestOnce(t *testing.T) {
	source := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "source-token", store.RandomUUID())
	target := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "target-token", store.RandomUUID())
	if !reservePendingRequest(source, 7) {
		t.Fatal("initial reservation failed")
	}
	circuit := &wsCircuit{source: source, target: target, requestID: 7, pending: true, counted: true}
	source.circuitCount.Store(1)
	target.circuitCount.Store(1)
	releaseCircuitValue(circuit)
	releaseCircuitValue(circuit)
	if !reservePendingRequest(source, 7) {
		t.Fatal("circuit teardown retained request reservation")
	}
	if source.circuitCount.Load() != 0 || target.circuitCount.Load() != 0 {
		t.Fatalf("circuit reservations were released more than once: %d %d", source.circuitCount.Load(), target.circuitCount.Load())
	}
}

func installTestPolicy(h *routerHub, sessions ...*routerSession) {
	policy := &routerPolicySnapshot{version: 1, routers: make(map[string]liveRouterPolicy), blocks: make(map[string]struct{})}
	for _, session := range sessions {
		policy.routers[session.router.ID] = liveRouterPolicy{ownerID: session.router.OwnerID, netID: session.allowedNetID, displayName: session.router.DisplayName, epoch: session.epoch, credentials: map[string]struct{}{store.Hash(session.token): {}}}
		h.clients.Store(session.router.ID, session)
	}
	h.policy.Store(policy)
}

func TestPolicyChecksUseMemorySnapshot(t *testing.T) {
	a := testApp(t)
	source := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "source-token", store.RandomUUID())
	target := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "target-token", store.RandomUUID())
	installTestPolicy(a.hub, source, target)
	if err := a.DB.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if !a.hub.allowed(source, target) {
		t.Fatal("cached policy denied an allowed pair after database became unavailable")
	}
}

func TestOneCircuitLockDoesNotBlockAnother(t *testing.T) {
	a := testApp(t)
	source := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "source-token", store.RandomUUID())
	target := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "target-token", store.RandomUUID())
	installTestPolicy(a.hub, source, target)
	blocked := &wsCircuit{source: source, target: target, openedAt: time.Now()}
	independent := &wsCircuit{source: source, target: target, openedAt: time.Now()}
	blockedID, independentID := store.RandomUUID(), store.RandomUUID()
	a.hub.circuits.Store(blockedID, blocked)
	a.hub.circuits.Store(independentID, independent)
	blocked.mu.Lock()
	defer blocked.mu.Unlock()
	done := make(chan struct{})
	go func() {
		a.hub.resetCircuit(independentID, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("an unrelated circuit mutex blocked circuit teardown")
	}
}

func TestPendingCircuitExpiresAndLeavesTombstone(t *testing.T) {
	a := testApp(t)
	source := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "source-token", store.RandomUUID())
	target := cachedTestSession(store.RandomUUID(), store.RandomUUID(), "target-token", store.RandomUUID())
	installTestPolicy(a.hub, source, target)
	id := store.RandomUUID()
	circuit := &wsCircuit{source: source, target: target, pending: true, counted: true, requestID: 7, openedAt: time.Now().Add(-11 * time.Second)}
	source.circuitCount.Store(1)
	target.circuitCount.Store(1)
	a.hub.circuits.Store(id, circuit)
	a.hub.expireCircuits(time.Now())
	if _, found := a.hub.circuits.Load(id); found {
		t.Fatal("expired pending circuit remains active")
	}
	if !a.hub.isTombstoned(id) {
		t.Fatal("expired pending circuit has no late-message tombstone")
	}
	if source.circuitCount.Load() != 0 || target.circuitCount.Load() != 0 {
		t.Fatal("expired circuit did not release endpoint reservations")
	}
}
