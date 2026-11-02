package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Store struct {
	DB       *sql.DB
	postgres bool
}

func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	var name string
	switch driver {
	case "sqlite":
		name = "sqlite"
	case "postgres":
		name = "pgx"
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
	db, err := sql.Open(name, dsn)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(10)
	}
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{DB: db, postgres: driver == "postgres"}
	if driver == "sqlite" {
		if _, err = db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			db.Close()
			return nil, err
		}
		if _, err = db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
			db.Close()
			return nil, err
		}
		if _, err = db.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	i := 1
	for _, c := range query {
		if c == '?' {
			fmt.Fprintf(&b, "$%d", i)
			i++
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (s *Store) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.DB.ExecContext(ctx, s.Q(query), args...)
}
func (s *Store) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.DB.QueryContext(ctx, s.Q(query), args...)
}
func (s *Store) Row(ctx context.Context, query string, args ...any) *sql.Row {
	return s.DB.QueryRowContext(ctx, s.Q(query), args...)
}

func Random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func RandomUUID() string       { return uuid.NewString() }
func Hash(token string) string { h := sha256.Sum256([]byte(token)); return hex.EncodeToString(h[:]) }
func Now() int64               { return time.Now().UTC().Unix() }

func (s *Store) Prune(ctx context.Context) error {
	_, err := s.CleanupExpired(ctx)
	if err != nil {
		return err
	}
	_, err = s.CleanupRouterLogs(ctx)
	return err
}

// CleanupExpired removes short-lived authentication and ceremony records.
// It returns the number of deleted rows so scheduled and manual runs can be
// inspected through the operations UI.
func (s *Store) CleanupExpired(ctx context.Context) (int64, error) {
	var deleted int64
	for _, q := range []string{"DELETE FROM sessions WHERE expires_at<?", "DELETE FROM email_tokens WHERE expires_at<?", "DELETE FROM password_reset_tokens WHERE expires_at<?", "DELETE FROM ceremonies WHERE expires_at<?", "DELETE FROM auth_attempts WHERE reset_at<?"} {
		result, err := s.Exec(ctx, q, Now())
		if err != nil {
			return deleted, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return deleted, err
		}
		deleted += n
	}
	return deleted, nil
}

// CleanupRouterLogs applies the thirty-day operational log retention policy.
func (s *Store) CleanupRouterLogs(ctx context.Context) (int64, error) {
	result, err := s.Exec(ctx, "DELETE FROM router_logs WHERE occurred_at<?", Now()-30*24*3600)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// CleanupCircuitHistory applies the ninety-day SNA circuit summary retention policy.
func (s *Store) CleanupCircuitHistory(ctx context.Context) (int64, error) {
	result, err := s.Exec(ctx, "DELETE FROM sna_circuit_history WHERE closed_at<?", Now()-90*24*3600)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) ResetMFA(ctx context.Context, email string) error {
	u, err := s.UserByEmail(ctx, email)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{
		"DELETE FROM sessions WHERE user_id=?",
		"DELETE FROM passkeys WHERE user_id=?",
		"UPDATE users SET totp_secret='',pending_totp='',remind_after=0 WHERE id=?",
	} {
		if _, err = tx.ExecContext(ctx, s.Q(query), u.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type User struct {
	ID, Email, PasswordHash, Role, TOTPSecret, PendingTOTP string
	VerifiedAt, RemindAfter                                int64
	Username, FirstName, LastName, NetID                   string
	PublicEmail                                            bool
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var public int
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.VerifiedAt, &u.RemindAfter, &u.TOTPSecret, &u.PendingTOTP, &u.Username, &u.FirstName, &u.LastName, &public, &u.NetID)
	u.PublicEmail = public != 0
	return u, err
}

const userColumns = "id,email,password_hash,role,verified_at,remind_after,totp_secret,pending_totp,username,first_name,last_name,public_email,netid"

func ValidNetID(value string) bool { return snaName.MatchString(value) }

// UpdateProfile changes profile fields and fences every owned live router when
// the NETID changes so no advertisement from the previous namespace survives.
func (s *Store) UpdateProfile(ctx context.Context, userID, username, first, last, netid string, public bool) error {
	if !ValidNetID(netid) {
		return errors.New("invalid NETID")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	publicValue := 0
	if public {
		publicValue = 1
	}
	var previous string
	if err = tx.QueryRowContext(ctx, s.Q("SELECT netid FROM users WHERE id=?"), userID).Scan(&previous); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, s.Q("UPDATE users SET username=?,first_name=?,last_name=?,public_email=?,netid=? WHERE id=?"), username, first, last, publicValue, netid, userID)
	if err != nil {
		return err
	}
	updated, _ := res.RowsAffected()
	if updated == 0 {
		return sql.ErrNoRows
	}
	if previous != netid {
		if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_advertisements WHERE router_id IN (SELECT id FROM routers WHERE owner_id=?)"), userID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_epochs WHERE router_id IN (SELECT id FROM routers WHERE owner_id=?)"), userID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.Q("UPDATE managed_cp_addresses SET netid=? WHERE owner_id=?"), netid, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.Row(ctx, "SELECT "+userColumns+" FROM users WHERE email=?", strings.ToLower(email)))
}
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.Row(ctx, "SELECT "+userColumns+" FROM users WHERE id=?", id))
}

type Session struct {
	ID, UserID, CSRF, State string
	Expires                 int64
	Remember                bool
}

func (s *Store) Session(ctx context.Context, token string) (Session, error) {
	var v Session
	var remember int
	err := s.Row(ctx, "SELECT id,user_id,csrf,state,expires_at,remember FROM sessions WHERE id=? AND expires_at>?", Hash(token), Now()).Scan(&v.ID, &v.UserID, &v.CSRF, &v.State, &v.Expires, &remember)
	v.Remember = remember != 0
	return v, err
}
func (s *Store) NewSession(ctx context.Context, userID, state string) (string, Session, error) {
	return s.NewSessionWithRemember(ctx, userID, state, false)
}
func (s *Store) NewSessionWithRemember(ctx context.Context, userID, state string, remember bool) (string, Session, error) {
	token, err := Random()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := Random()
	if err != nil {
		return "", Session{}, err
	}
	duration := int64(12 * 3600)
	rememberValue := 0
	if remember {
		duration = 30 * 24 * 3600
		rememberValue = 1
	}
	v := Session{ID: Hash(token), UserID: userID, CSRF: csrf, State: state, Expires: Now() + duration, Remember: remember}
	_, err = s.Exec(ctx, "INSERT INTO sessions(id,user_id,csrf,state,expires_at,remember) VALUES(?,?,?,?,?,?)", v.ID, v.UserID, v.CSRF, v.State, v.Expires, rememberValue)
	return token, v, err
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for i, statements := range [][]string{schema, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6, schemaV7, schemaV8, schemaV9, schemaV10, schemaV11} {
		version := i + 1
		var found int
		err := s.DB.QueryRowContext(ctx, s.Q("SELECT version FROM schema_migrations WHERE version=?"), version).Scan(&found)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("migrate version %d: %w", version, err)
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrate version %d: %w", version, err)
		}
		for _, stmt := range statements {
			if _, err = tx.ExecContext(ctx, stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migrate version %d: %w", version, err)
			}
		}
		if _, err = tx.ExecContext(ctx, s.Q("INSERT INTO schema_migrations(version) VALUES(?)"), version); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate version %d: %w", version, err)
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("migrate version %d: %w", version, err)
		}
	}
	return nil
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')), verified_at BIGINT NOT NULL DEFAULT 0, remind_after BIGINT NOT NULL DEFAULT 0, totp_secret TEXT NOT NULL DEFAULT '', pending_totp TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('full','mfa','enroll')), expires_at BIGINT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS email_tokens (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, code_hash TEXT NOT NULL, expires_at BIGINT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS auth_attempts (id TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at BIGINT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, credential TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS ceremonies (session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE, kind TEXT NOT NULL, data TEXT NOT NULL, expires_at BIGINT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS api_clients (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE, created_at BIGINT NOT NULL, revoked_at BIGINT NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS directory (id TEXT PRIMARY KEY, site TEXT NOT NULL, mac TEXT NOT NULL, sap TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', owner_id TEXT REFERENCES users(id) ON DELETE SET NULL, UNIQUE(site,mac,sap))`,
	`CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, remote_site TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'planned', notes TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_api_clients_user ON api_clients(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_connections_owner ON connections(owner_id)`,
}

var schemaV2 = []string{
	`ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN public_email INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN picture BYTEA`,
	`ALTER TABLE users ADD COLUMN picture_type TEXT NOT NULL DEFAULT ''`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username<>''`,
	`CREATE TABLE routers (id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,display_name TEXT NOT NULL,paused INTEGER NOT NULL DEFAULT 0,created_at BIGINT NOT NULL,last_seen_at BIGINT NOT NULL DEFAULT 0,last_ip TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX idx_routers_owner ON routers(owner_id)`,
	`CREATE TABLE router_credentials (id TEXT PRIMARY KEY,router_id TEXT NOT NULL REFERENCES routers(id) ON DELETE CASCADE,secret_hash TEXT NOT NULL UNIQUE,purpose TEXT NOT NULL DEFAULT 'router',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL DEFAULT 0,revoked_at BIGINT NOT NULL DEFAULT 0)`,
	`CREATE INDEX idx_router_credentials_router ON router_credentials(router_id)`,
	`CREATE TABLE router_epochs (router_id TEXT PRIMARY KEY REFERENCES routers(id) ON DELETE CASCADE,epoch TEXT NOT NULL,revision BIGINT NOT NULL DEFAULT 0,connected_at BIGINT NOT NULL,source_ip TEXT NOT NULL)`,
	`CREATE TABLE router_advertisements (router_id TEXT NOT NULL REFERENCES routers(id) ON DELETE CASCADE,route_id BIGINT NOT NULL,generation BIGINT NOT NULL,epoch TEXT NOT NULL,revision BIGINT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('CP','LU')),netid TEXT NOT NULL,name TEXT NOT NULL,hosting_cp_netid TEXT NOT NULL DEFAULT '',hosting_cp_name TEXT NOT NULL DEFAULT '',PRIMARY KEY(router_id,route_id))`,
	`CREATE INDEX idx_router_advertisements_name ON router_advertisements(kind,netid,name)`,
	`CREATE TABLE user_blocks (owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,blocked_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at BIGINT NOT NULL,PRIMARY KEY(owner_id,blocked_user_id),CHECK(owner_id<>blocked_user_id))`,
	`CREATE TABLE router_logs (id TEXT PRIMARY KEY,router_id TEXT NOT NULL REFERENCES routers(id) ON DELETE CASCADE,owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,peer_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound','system')),level TEXT NOT NULL CHECK(level IN ('info','warning','error')),event_type TEXT NOT NULL,netid TEXT NOT NULL DEFAULT '',node_name TEXT NOT NULL DEFAULT '',source_ip TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL,details_json TEXT NOT NULL DEFAULT '',occurred_at BIGINT NOT NULL)`,
	`CREATE INDEX idx_router_logs_router_time ON router_logs(router_id,occurred_at)`,
	`CREATE INDEX idx_router_logs_owner_time ON router_logs(owner_id,occurred_at)`,
}

var schemaV3 = []string{
	`ALTER TABLE routers ADD COLUMN llc_facing INTEGER NOT NULL DEFAULT 0`,
	`CREATE TABLE mac_pool_state (id INTEGER PRIMARY KEY CHECK(id=1), next_suffix BIGINT NOT NULL)`,
	`INSERT INTO mac_pool_state(id,next_suffix) VALUES(1,1)`,
	`CREATE TABLE managed_cp_addresses (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, netid TEXT NOT NULL, cp_name TEXT NOT NULL, mac_suffix BIGINT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, retired_at BIGINT NOT NULL DEFAULT 0, UNIQUE(owner_id,netid,cp_name))`,
	`CREATE INDEX idx_managed_cp_addresses_owner ON managed_cp_addresses(owner_id)`,
}

var schemaV4 = []string{
	`CREATE TABLE password_reset_tokens (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, code_hash TEXT NOT NULL, expires_at BIGINT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)`,
}

var schemaV5 = []string{
	`ALTER TABLE sessions ADD COLUMN remember INTEGER NOT NULL DEFAULT 0`,
}

var schemaV6 = []string{
	`ALTER TABLE router_advertisements ADD COLUMN lu_types TEXT NOT NULL DEFAULT '[]'`,
}

var schemaV7 = []string{
	`ALTER TABLE users ADD COLUMN netid TEXT NOT NULL DEFAULT ''`,
	`CREATE UNIQUE INDEX idx_users_netid ON users(netid) WHERE netid<>''`,
}

var schemaV8 = []string{
	`CREATE TABLE maintenance_runs (task_name TEXT PRIMARY KEY, started_at BIGINT NOT NULL, finished_at BIGINT NOT NULL DEFAULT 0, status TEXT NOT NULL CHECK(status IN ('running','success','failed')), trigger_kind TEXT NOT NULL CHECK(trigger_kind IN ('scheduled','manual')), triggered_by TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '')`,
}

var schemaV9 = []string{
	`CREATE TABLE sna_circuit_history (id TEXT PRIMARY KEY,source_router_id TEXT NOT NULL,source_router_name TEXT NOT NULL,source_owner_id TEXT NOT NULL,target_router_id TEXT NOT NULL,target_router_name TEXT NOT NULL,target_owner_id TEXT NOT NULL,profile TEXT NOT NULL,opened_at BIGINT NOT NULL,activated_at BIGINT NOT NULL DEFAULT 0,closed_at BIGINT NOT NULL,state TEXT NOT NULL,close_reason TEXT NOT NULL DEFAULT '',source_bytes BIGINT NOT NULL DEFAULT 0,target_bytes BIGINT NOT NULL DEFAULT 0,source_events BIGINT NOT NULL DEFAULT 0,target_events BIGINT NOT NULL DEFAULT 0,peak_queued_bytes BIGINT NOT NULL DEFAULT 0,actor_type TEXT NOT NULL DEFAULT 'system',actor_id TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX idx_sna_circuit_history_source_time ON sna_circuit_history(source_owner_id,closed_at)`,
	`CREATE INDEX idx_sna_circuit_history_target_time ON sna_circuit_history(target_owner_id,closed_at)`,
	`CREATE INDEX idx_sna_circuit_history_closed ON sna_circuit_history(closed_at)`,
}

var schemaV10 = []string{
	`CREATE TABLE concentrator_instance (id INTEGER PRIMARY KEY CHECK(id=1),instance_id TEXT NOT NULL,heartbeat_at BIGINT NOT NULL)`,
}

var schemaV11 = []string{
	`CREATE INDEX idx_sna_circuit_history_closed_id ON sna_circuit_history(closed_at,id)`,
	`CREATE INDEX idx_sna_circuit_history_state_closed_id ON sna_circuit_history(state,closed_at,id)`,
	`CREATE INDEX idx_sna_circuit_history_source_closed_id ON sna_circuit_history(source_owner_id,closed_at,id)`,
	`CREATE INDEX idx_sna_circuit_history_target_closed_id ON sna_circuit_history(target_owner_id,closed_at,id)`,
	`CREATE INDEX idx_sna_circuit_history_source_router ON sna_circuit_history(source_router_id)`,
	`CREATE INDEX idx_sna_circuit_history_target_router ON sna_circuit_history(target_router_id)`,
}

var ErrNotFound = errors.New("not found")
