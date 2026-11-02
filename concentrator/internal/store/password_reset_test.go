package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestPasswordResetAttemptLimitAndSessionRevocation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "reset.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	user := addMACUser(t, s, "reset@example.com")
	if err := s.IssuePasswordReset(ctx, user, "123456"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s.CompletePasswordReset(ctx, user, "000000", "new-hash"); !errors.Is(err, ErrInvalidResetCode) {
			t.Fatalf("wrong code attempt %d: %v", i+1, err)
		}
	}
	if err := s.CompletePasswordReset(ctx, user, "123456", "new-hash"); !errors.Is(err, ErrInvalidResetCode) {
		t.Fatalf("code accepted after five attempts: %v", err)
	}
	if err := s.IssuePasswordReset(ctx, user, "654321"); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.NewSession(ctx, user, "full")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompletePasswordReset(ctx, user, "654321", "new-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, token); err == nil {
		t.Fatal("session survived reset")
	}
	if err := s.CompletePasswordReset(ctx, user, "654321", "another-hash"); !errors.Is(err, ErrInvalidResetCode) {
		t.Fatalf("code reused: %v", err)
	}
}

func TestVerifiedFifthResetAttemptCanComplete(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "fifth-reset.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	user := addMACUser(t, s, "fifth-reset@example.com")
	if err := s.IssuePasswordReset(ctx, user, "123456"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := s.VerifyPasswordResetCode(ctx, user, "000000"); !errors.Is(err, ErrInvalidResetCode) {
			t.Fatalf("wrong code attempt %d: %v", i+1, err)
		}
	}
	if err := s.VerifyPasswordResetCode(ctx, user, "123456"); err != nil {
		t.Fatalf("valid fifth attempt: %v", err)
	}
	if err := s.CompletePasswordResetVerified(ctx, user, "123456", "new-hash"); err != nil {
		t.Fatalf("verified fifth attempt could not complete: %v", err)
	}
	if err := s.CompletePasswordResetVerified(ctx, user, "123456", "another-hash"); !errors.Is(err, ErrInvalidResetCode) {
		t.Fatalf("reused code: %v", err)
	}
}
