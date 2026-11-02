package server

import "testing"

func TestDynamicQueueGrowsAndTracksPressure(t *testing.T) {
	q := newDynamicQueue[string](128, 1024, func(value string) int { return len(value) })
	for i := 0; i < 64; i++ {
		if !q.push("payload") {
			t.Fatalf("push %d rejected", i)
		}
	}
	stats := q.stats()
	if stats.Depth != 64 || stats.HighWater != 64 || stats.Bytes != 7*64 || stats.Dropped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	for i := 0; i < 64; i++ {
		if _, ok := q.pop(make(chan struct{})); !ok {
			t.Fatalf("pop %d failed", i)
		}
	}
	if stats = q.stats(); stats.Depth != 0 || stats.HighWater != 64 {
		t.Fatalf("unexpected drained stats: %+v", stats)
	}
}

func TestDynamicQueueEnforcesLimitsAndCanDiscard(t *testing.T) {
	q := newDynamicQueue[string](2, 8, func(value string) int { return len(value) })
	if !q.push("1234") || !q.push("5678") || q.push("x") {
		t.Fatal("queue did not enforce its limits")
	}
	q.close(true)
	stats := q.stats()
	if stats.Depth != 0 || stats.Bytes != 0 || stats.Dropped != 1 {
		t.Fatalf("unexpected discard stats: %+v", stats)
	}
}
