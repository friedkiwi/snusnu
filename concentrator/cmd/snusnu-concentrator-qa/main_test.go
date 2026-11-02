package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/qa"
	"golang.org/x/crypto/bcrypt"
)

func TestQAStoreIsFreshAndIgnoresProductionDSN(t *testing.T) {
	production := filepath.Join(t.TempDir(), "production.db")
	if err := os.WriteFile(production, []byte("production marker"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNUSNU_DB_DRIVER", "postgres")
	t.Setenv("SNUSNU_DB_DSN", production)
	ctx := context.Background()
	first, firstPath, err := createQAStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.DB.Close()
	if err := qa.Seed(ctx, first); err != nil {
		t.Fatal(err)
	}
	if firstPath == production {
		t.Fatal("QA path equals production path")
	}
	for _, account := range qa.Accounts {
		user, err := first.UserByEmail(ctx, account.Email)
		if err != nil || user.Role != account.Role || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(account.Password)) != nil {
			t.Fatalf("QA account %s: %+v %v", account.Email, user, err)
		}
	}
	for _, router := range qa.Routers {
		client, err := first.RouterByToken(ctx, router.Token)
		if err != nil || client.LLCFacing != router.LLCFacing || client.DisplayName != router.Name {
			t.Fatalf("QA router: %+v %v", client, err)
		}
	}
	second, secondPath, err := createQAStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.DB.Close()
	if firstPath == secondPath {
		t.Fatal("QA database reused across runs")
	}
	var count int
	if err := second.Row(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil || count != 0 {
		t.Fatalf("new QA database not empty: %d %v", count, err)
	}
	data, err := os.ReadFile(production)
	if err != nil || string(data) != "production marker" {
		t.Fatalf("production database changed: %q %v", data, err)
	}
}
