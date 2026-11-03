package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func addMACUser(t *testing.T, s *Store, email string) string {
	t.Helper()
	id := RandomUUID()
	if _, err := s.Exec(context.Background(), "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", id, email, "hash", Now()); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestManagedMACAllocationRetentionAndRetirement(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mac.db")
	s, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	owner := addMACUser(t, s, "owner@example.com")
	const count = 48
	results := make(chan ManagedCP, count)
	failures := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cp, err := s.AllocateManagedCP(ctx, owner, "SOLNET", fmt.Sprintf("CP%05d", i))
			if err != nil {
				failures <- err
				return
			}
			results <- cp
		}(i)
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	var first ManagedCP
	for cp := range results {
		if seen[cp.Suffix] {
			t.Fatalf("duplicate suffix %d", cp.Suffix)
		}
		seen[cp.Suffix] = true
		if first.ID == "" {
			first = cp
		}
	}
	if len(seen) != count {
		t.Fatalf("allocated %d, want %d", len(seen), count)
	}
	if first.MACColon() != "02:53:4E:"+first.ADPTADR()[6:8]+":"+first.ADPTADR()[8:10]+":"+first.ADPTADR()[10:12] {
		t.Fatalf("format mismatch: %s %s", first.MACColon(), first.ADPTADR())
	}
	if got, err := ParseManagedMAC(first.MACColon()); err != nil || got != first.MACBytes() {
		t.Fatalf("colon parse: %v %v", got, err)
	}
	if got, err := ParseManagedMAC(first.ADPTADR()); err != nil || got != first.MACBytes() {
		t.Fatalf("ADPTADR parse: %v %v", got, err)
	}
	for _, bad := range []string{"00:53:4E:00:00:01", "02:53:4E:00:00:00", "02:53:4E:GG:00:01", "025:34:E0:00:00:01"} {
		if _, err := ParseManagedMAC(bad); err == nil {
			t.Fatalf("accepted invalid managed MAC %q", bad)
		}
	}
	if err = s.RetireManagedCP(ctx, first.ID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AllocateManagedCP(ctx, owner, first.NetID, first.CPName); !errors.Is(err, ErrRetiredCP) {
		t.Fatalf("retired CP reallocated: %v", err)
	}
	s.DB.Close()
	s, err = Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	retired, err := s.ManagedCPByID(ctx, first.ID)
	if err != nil || retired.RetiredAt == 0 || retired.Suffix != first.Suffix {
		t.Fatalf("tombstone lost: %+v %v", retired, err)
	}
	next, err := s.AllocateManagedCP(ctx, owner, "SOLNET", "NEWCP")
	if err != nil {
		t.Fatal(err)
	}
	if seen[next.Suffix] {
		t.Fatalf("retired or existing MAC reused: %d", next.Suffix)
	}
}

func TestManagedBindingAuthorizationAndPublication(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "bindings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	owner := addMACUser(t, s, "target@example.com")
	recipientOwner := addMACUser(t, s, "llc@example.com")
	origin, _, err := s.CreateRouter(ctx, owner, "CP origin")
	if err != nil {
		t.Fatal(err)
	}
	recipient, _, err := s.CreateRouter(ctx, recipientOwner, "LLC edge")
	if err != nil {
		t.Fatal(err)
	}
	ipOnly, _, err := s.CreateRouter(ctx, recipientOwner, "IP edge")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetRouterLLCFacing(ctx, recipient.ID, true); err != nil {
		t.Fatal(err)
	}
	originEpoch, err := s.BeginRouterEpoch(ctx, origin.ID, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	recipientEpoch, err := s.BeginRouterEpoch(ctx, recipient.ID, "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	ipEpoch, err := s.BeginRouterEpoch(ctx, ipOnly.ID, "192.0.2.12")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReplaceRouterSnapshot(ctx, origin.ID, originEpoch, 1, []RouteExport{{ID: 1, Generation: 1, Kind: "CP", NetID: "SOLNET", Name: "SNAB"}, {ID: 2, Generation: 1, Kind: "LU", NetID: "SOLNET", Name: "PAYROLL", HostingCPNetID: "SOLNET", HostingCPName: "SNAB"}}); err != nil {
		t.Fatal(err)
	}
	result, err := s.BuildManagedBindingSnapshot(ctx, recipient.ID, recipientEpoch, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.RecipientEpoch != recipientEpoch || len(result.Bindings) != 1 {
		t.Fatalf("downstream snapshot: %+v", result)
	}
	cp, err := s.managedCPByName(ctx, owner, "SOLNET", "SNAB")
	if err != nil {
		t.Fatal(err)
	}
	b := result.Bindings[0]
	if b.AddressID != cp.ID || b.MAC != cp.MACBytes() || b.CPName != "SNAB" || len(b.Candidates) != 1 || b.Candidates[0].RouterID != origin.ID {
		t.Fatalf("incorrect server-stamped binding: %+v", b)
	}
	if _, err = s.BuildManagedBindingSnapshot(ctx, ipOnly.ID, ipEpoch, 1); !errors.Is(err, ErrBindingRecipient) {
		t.Fatalf("IP-only recipient accepted: %v", err)
	}
	if err = s.SetBlock(ctx, recipientOwner, owner, true); err != nil {
		t.Fatal(err)
	}
	result, err = s.BuildManagedBindingSnapshot(ctx, recipient.ID, recipientEpoch, 3)
	if err != nil || len(result.Bindings) != 0 {
		t.Fatalf("blocked binding published: %+v %v", result, err)
	}
	if err = s.SetBlock(ctx, recipientOwner, owner, false); err != nil {
		t.Fatal(err)
	}
	if err = s.SetManagedCPEnabled(ctx, cp.ID, owner, false); err != nil {
		t.Fatal(err)
	}
	result, err = s.BuildManagedBindingSnapshot(ctx, recipient.ID, recipientEpoch, 4)
	if err != nil || len(result.Bindings) != 0 {
		t.Fatalf("disabled binding published: %+v %v", result, err)
	}
	if err = s.SetManagedCPEnabled(ctx, cp.ID, owner, true); err != nil {
		t.Fatal(err)
	}
	if err = s.EndRouterEpoch(ctx, origin.ID, originEpoch); err != nil {
		t.Fatal(err)
	}
	result, err = s.BuildManagedBindingSnapshot(ctx, recipient.ID, recipientEpoch, 5)
	if err != nil || len(result.Bindings) != 1 || len(result.Bindings[0].Candidates) != 0 {
		t.Fatalf("address ownership disappeared or retained a withdrawn route: %+v %v", result, err)
	}
	still, err := s.ManagedCPByID(ctx, cp.ID)
	if err != nil || still.Suffix != cp.Suffix || still.RetiredAt != 0 {
		t.Fatalf("withdrawal lost assignment: %+v %v", still, err)
	}
	if err = s.RetireManagedCP(ctx, cp.ID, owner); err != nil {
		t.Fatal(err)
	}
	if err = s.SetManagedCPEnabled(ctx, cp.ID, owner, true); err == nil {
		t.Fatal("retired CP re-enabled")
	}
}
