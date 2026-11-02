package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRoleChangesPreserveAnAdminAndRecheckActor(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	a, b := RandomUUID(), RandomUUID()
	for _, x := range []struct{ id, email string }{{a, "admin-a@example.com"}, {b, "admin-b@example.com"}} {
		if _, err := s.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'admin',?)", x.id, x.email, "unused", Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetUserRole(ctx, a, b, "user"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserRole(ctx, b, a, "user"); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("demoted actor retained admin authority: %v", err)
	}
	if err := s.SetUserRole(ctx, a, a, "user"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin demotion: %v", err)
	}
	if err := s.DeleteUser(ctx, a); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin deletion: %v", err)
	}
}
