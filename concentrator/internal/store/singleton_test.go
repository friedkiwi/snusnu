package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestInstanceLeaseRejectsSecondProcess(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "singleton.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	first, second := RandomUUID(), RandomUUID()
	if err := s.AcquireInstance(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireInstance(ctx, second); !errors.Is(err, ErrInstanceActive) {
		t.Fatalf("second instance: %v", err)
	}
	if err := s.HeartbeatInstance(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseInstance(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireInstance(ctx, second); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}
