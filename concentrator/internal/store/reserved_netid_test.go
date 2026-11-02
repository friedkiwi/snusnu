package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceNetIDCannotBeClaimed(t *testing.T) {
	if ValidNetID("SNUSNU") || !ValidNetID("ALICE") {
		t.Fatal("service namespace validation")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reserved.db")
	s, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,netid) VALUES(?,?,?,'user',?)", RandomUUID(), "reserved@example.com", "unused", "SNUSNU")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, "sqlite", path); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected startup conflict: %v", err)
	}
}
