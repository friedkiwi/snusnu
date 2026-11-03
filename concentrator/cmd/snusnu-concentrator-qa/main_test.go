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

func TestQAStoreExplicitReusePreservesTokensAndManagedMAC(t *testing.T) {
	ctx := context.Background()
	first, path, err := createQAStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = qa.Seed(ctx, first); err != nil {
		t.Fatal(err)
	}
	owner, err := first.UserByEmail(ctx, qa.Accounts[1].Email)
	if err != nil {
		t.Fatal(err)
	}
	address, err := first.AllocateManagedCP(ctx, owner.ID, owner.NetID, "SNAA")
	if err != nil {
		t.Fatal(err)
	}
	if err = first.DB.Close(); err != nil {
		t.Fatal(err)
	}
	second, reused, fresh, err := openQAStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.DB.Close()
	if fresh || reused != path {
		t.Fatalf("QA database was not reused: fresh=%t path=%q", fresh, reused)
	}
	if err = second.ResetLiveState(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = second.RouterByToken(ctx, qa.Routers[0].Token); err != nil {
		t.Fatalf("router token lost: %v", err)
	}
	retained, err := second.ManagedCPByID(ctx, address.ID)
	if err != nil || retained.Suffix != address.Suffix {
		t.Fatalf("managed MAC lost: %+v %v", retained, err)
	}
	if _, _, _, err = openQAStore(ctx, filepath.Join(t.TempDir(), "missing.sqlite")); err == nil {
		t.Fatal("missing reuse database was created")
	}
}
