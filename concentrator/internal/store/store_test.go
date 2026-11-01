package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradeFromVersionOne(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema {
		if _, err = db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO schema_migrations(version) VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var version int
	if err = s.Row(ctx, "SELECT version FROM schema_migrations WHERE version=2").Scan(&version); err != nil || version != 2 {
		t.Fatalf("migration version: %d %v", version, err)
	}
	var count int
	if err = s.Row(ctx, "SELECT COUNT(*) FROM routers").Scan(&count); err != nil {
		t.Fatal(err)
	}
}

func TestRouterCredentialsPauseAndBlocks(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "routers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	owner := RandomUUID()
	peer := RandomUUID()
	for _, x := range []struct{ id, email string }{{owner, "owner@example.com"}, {peer, "peer@example.com"}} {
		if _, err = s.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", x.id, x.email, "hash", Now()); err != nil {
			t.Fatal(err)
		}
	}
	r, token, err := s.CreateRouter(ctx, owner, "Lab gateway")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.RouterByToken(ctx, token); err != nil || got.ID != r.ID || got.DisplayName != "Lab gateway" {
		t.Fatalf("token lookup: %+v %v", got, err)
	}
	other, _, err := s.CreateRouter(ctx, peer, "Remote gateway")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := s.CanForward(ctx, other.ID, r.ID)
	if err != nil || !allowed {
		t.Fatalf("initial policy: %t %v", allowed, err)
	}
	if err = s.SetBlock(ctx, owner, peer, true); err != nil {
		t.Fatal(err)
	}
	allowed, err = s.CanForward(ctx, other.ID, r.ID)
	if err != nil || allowed {
		t.Fatalf("block policy: %t %v", allowed, err)
	}
	allowed, err = s.CanForward(ctx, r.ID, other.ID)
	if err != nil || allowed {
		t.Fatalf("reverse block policy: %t %v", allowed, err)
	}
	if err = s.SetBlock(ctx, owner, peer, false); err != nil {
		t.Fatal(err)
	}
	if err = s.SetRouterPaused(ctx, r.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RouterByToken(ctx, token); !errors.Is(err, ErrPaused) {
		t.Fatalf("paused token: %v", err)
	}
	allowed, err = s.CanForward(ctx, other.ID, r.ID)
	if err != nil || allowed {
		t.Fatalf("pause policy: %t %v", allowed, err)
	}
	if err = s.SetRouterPaused(ctx, r.ID, false); err != nil {
		t.Fatal(err)
	}
	newToken, err := s.RotateRouterToken(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RouterByToken(ctx, token); err == nil {
		t.Fatal("old token still valid")
	}
	if _, err = s.RouterByToken(ctx, newToken); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteRouter(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RouterByToken(ctx, newToken); err == nil {
		t.Fatal("deleted router token still valid")
	}
}

func TestRouterLogsAndInboundFlowSearch(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	owner := RandomUUID()
	peer := RandomUUID()
	for _, x := range []struct{ id, email string }{{owner, "owner@example.com"}, {peer, "peer@example.com"}} {
		if _, err = s.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", x.id, x.email, "hash", Now()); err != nil {
			t.Fatal(err)
		}
	}
	r, _, err := s.CreateRouter(ctx, owner, "My router")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AppendRouterLog(ctx, LogEntry{RouterID: r.ID, PeerUserID: peer, Direction: "inbound", Level: "info", EventType: "PIU", NetID: "SOLNET", NodeName: "SNAB", SourceIP: "192.0.2.10", Summary: "received test event", DetailsJSON: `{"kind":"PIU"}`}); err != nil {
		t.Fatal(err)
	}
	logs, err := s.SearchRouterLogs(ctx, r.ID, "192.0.2.10")
	if err != nil || len(logs) != 1 {
		t.Fatalf("router search: %d %v", len(logs), err)
	}
	flows, err := s.SearchInboundFlows(ctx, owner, "SNAB")
	if err != nil || len(flows) != 1 || flows[0].PeerUserID != peer {
		t.Fatalf("flow search: %+v %v", flows, err)
	}
	flows, err = s.SearchInboundFlows(ctx, peer, "")
	if err != nil || len(flows) != 0 {
		t.Fatalf("foreign flows exposed: %+v %v", flows, err)
	}
}

func TestRouterSnapshotEpochFencing(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "snapshots.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	owner := RandomUUID()
	if _, err = s.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", owner, "owner@example.com", "hash", Now()); err != nil {
		t.Fatal(err)
	}
	r, _, err := s.CreateRouter(ctx, owner, "Router")
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := s.BeginRouterEpoch(ctx, r.ID, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	exports := []RouteExport{{ID: 1, Generation: 1, Kind: "CP", NetID: "SOLNET", Name: "SNAB"}, {ID: 2, Generation: 1, Kind: "LU", NetID: "SOLNET", Name: "SNAB", HostingCPNetID: "SOLNET", HostingCPName: "SNAB"}}
	if err = s.ReplaceRouterSnapshot(ctx, r.ID, epoch, 1, exports); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListExports(ctx, owner)
	if err != nil || len(got) != 2 {
		t.Fatalf("distinct CP and LU: %+v %v", got, err)
	}
	if err = s.ReplaceRouterSnapshot(ctx, r.ID, epoch, 1, exports); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("replayed revision: %v", err)
	}
	if err = s.ReplaceRouterSnapshot(ctx, r.ID, epoch, 2, []RouteExport{{ID: 1, Generation: 1, Kind: "CP", NetID: "SOLNET", Name: "SNAB"}, {ID: 2, Generation: 1, Kind: "CP", NetID: "SOLNET", Name: "SNAB"}}); err == nil {
		t.Fatal("duplicate resource accepted")
	}
	if err = s.ReplaceRouterSnapshot(ctx, r.ID, epoch, 2, []RouteExport{{ID: 3, Generation: 1, Kind: "CP", NetID: "1BAD", Name: "SNAB"}}); err == nil {
		t.Fatal("invalid SNA name accepted")
	}
	newEpoch, err := s.BeginRouterEpoch(ctx, r.ID, "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EndRouterEpoch(ctx, r.ID, epoch); err != nil {
		t.Fatal(err)
	}
	if err = s.ReplaceRouterSnapshot(ctx, r.ID, epoch, 3, exports); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale epoch: %v", err)
	}
	if err = s.ReplaceRouterSnapshot(ctx, r.ID, newEpoch, 1, exports[:1]); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListExports(ctx, owner)
	if err != nil || len(got) != 1 {
		t.Fatalf("replacement lost: %+v %v", got, err)
	}
	if err = s.SetRouterPaused(ctx, r.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListExports(ctx, owner)
	if err != nil || len(got) != 0 {
		t.Fatalf("pause did not withdraw: %+v %v", got, err)
	}
}

func TestBackends(t *testing.T) {
	cases := []struct{ name, dsn string }{{"sqlite", filepath.Join(t.TempDir(), "store.db")}}
	if dsn := os.Getenv("SNUSNU_TEST_POSTGRES_DSN"); dsn != "" {
		cases = append(cases, struct{ name, dsn string }{"postgres", dsn})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(context.Background(), tc.name, tc.dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.DB.Close()
			id, err := Random()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Exec(context.Background(), "INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,'user')", id, id+"@example.com", "hash"); err != nil {
				t.Fatal(err)
			}
			u, err := s.UserByEmail(context.Background(), id+"@example.com")
			if err != nil || u.ID != id {
				t.Fatalf("lookup: %+v %v", u, err)
			}
			session, _, err := s.NewSession(context.Background(), id, "full")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Session(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Exec(context.Background(), "UPDATE users SET username=?,picture=?,picture_type=? WHERE id=?", "backend-"+id[:8], []byte{1, 2, 3}, "image/png", id); err != nil {
				t.Fatal(err)
			}
			var picture []byte
			if err = s.Row(context.Background(), "SELECT picture FROM users WHERE id=?", id).Scan(&picture); err != nil || len(picture) != 3 {
				t.Fatalf("profile picture storage: %v %v", picture, err)
			}
			router, routerToken, err := s.CreateRouter(context.Background(), id, "Backend check")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.RouterByToken(context.Background(), routerToken); err != nil {
				t.Fatal(err)
			}
			epoch, err := s.BeginRouterEpoch(context.Background(), router.ID, "192.0.2.3")
			if err != nil {
				t.Fatal(err)
			}
			if err = s.ReplaceRouterSnapshot(context.Background(), router.ID, epoch, 1, []RouteExport{{ID: 1, Generation: 1, Kind: "CP", NetID: "SOLNET", Name: "SNAB"}}); err != nil {
				t.Fatal(err)
			}
			if err = s.AppendRouterLog(context.Background(), LogEntry{RouterID: router.ID, Direction: "system", Level: "info", EventType: "snapshot", SourceIP: "192.0.2.3", Summary: "one route"}); err != nil {
				t.Fatal(err)
			}
			if logs, err := s.SearchRouterLogs(context.Background(), router.ID, "snapshot"); err != nil || len(logs) != 1 {
				t.Fatalf("backend log search: %+v %v", logs, err)
			}
			cp, err := s.AllocateManagedCP(context.Background(), id, "SOLNET", "SNAB")
			if err != nil || cp.Suffix < 1 || cp.MACColon() == "" {
				t.Fatalf("managed CP allocation: %+v %v", cp, err)
			}
			if err := s.RetireManagedCP(context.Background(), cp.ID, id); err != nil {
				t.Fatal(err)
			}
			if _, err := s.AllocateManagedCP(context.Background(), id, "SOLNET", "SNAB"); !errors.Is(err, ErrRetiredCP) {
				t.Fatalf("retired CP reused: %v", err)
			}
			if err := s.IssuePasswordReset(context.Background(), id, "123456"); err != nil {
				t.Fatal(err)
			}
			if err := s.CompletePasswordReset(context.Background(), id, "123456", "new-hash"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
