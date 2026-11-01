package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var ErrPaused = errors.New("router paused")

type Router struct {
	ID, OwnerID, DisplayName, LastIP string
	Paused, Connected                bool
	CreatedAt, LastSeenAt            int64
}

func scanRouter(row *sql.Row) (Router, error) {
	var r Router
	var paused, connected int
	err := row.Scan(&r.ID, &r.OwnerID, &r.DisplayName, &paused, &r.CreatedAt, &r.LastSeenAt, &r.LastIP, &connected)
	r.Paused = paused != 0
	r.Connected = connected != 0
	return r, err
}

const routerColumns = "id,owner_id,display_name,paused,created_at,last_seen_at,last_ip"

func (s *Store) RouterByID(ctx context.Context, id string) (Router, error) {
	return scanRouter(s.Row(ctx, "SELECT "+routerColumns+",CASE WHEN EXISTS(SELECT 1 FROM router_epochs e WHERE e.router_id=routers.id) THEN 1 ELSE 0 END FROM routers WHERE id=?", id))
}
func (s *Store) RouterByToken(ctx context.Context, token string) (Router, error) {
	r, err := scanRouter(s.Row(ctx, "SELECT r."+strings.ReplaceAll(routerColumns, ",", ",r.")+",CASE WHEN EXISTS(SELECT 1 FROM router_epochs e WHERE e.router_id=r.id) THEN 1 ELSE 0 END FROM routers r JOIN router_credentials c ON c.router_id=r.id WHERE c.secret_hash=? AND c.revoked_at=0 AND c.purpose='router' AND (c.expires_at=0 OR c.expires_at>?)", Hash(token), Now()))
	if err != nil {
		return r, err
	}
	if r.Paused {
		return r, ErrPaused
	}
	return r, nil
}
func (s *Store) CreateRouter(ctx context.Context, ownerID, name string) (Router, string, error) {
	id := RandomUUID()
	token, err := Random()
	if err != nil {
		return Router{}, "", err
	}
	credentialID := RandomUUID()
	now := Now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Router{}, "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.Q("INSERT INTO routers(id,owner_id,display_name,created_at) VALUES(?,?,?,?)"), id, ownerID, name, now); err != nil {
		return Router{}, "", err
	}
	if _, err = tx.ExecContext(ctx, s.Q("INSERT INTO router_credentials(id,router_id,secret_hash,created_at) VALUES(?,?,?,?)"), credentialID, id, Hash(token), now); err != nil {
		return Router{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return Router{}, "", err
	}
	return Router{ID: id, OwnerID: ownerID, DisplayName: name, CreatedAt: now}, token, nil
}
func (s *Store) RotateRouterToken(ctx context.Context, id string) (string, error) {
	token, err := Random()
	if err != nil {
		return "", err
	}
	now := Now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.Q("UPDATE router_credentials SET revoked_at=? WHERE router_id=? AND revoked_at=0"), now, id)
	if err != nil {
		return "", err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, s.Q("INSERT INTO router_credentials(id,router_id,secret_hash,created_at) VALUES(?,?,?,?)"), RandomUUID(), id, Hash(token), now); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_advertisements WHERE router_id=?"), id); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_epochs WHERE router_id=?"), id); err != nil {
		return "", err
	}
	return token, tx.Commit()
}
func (s *Store) SetRouterPaused(ctx context.Context, id string, paused bool) error {
	value := 0
	if paused {
		value = 1
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.Q("UPDATE routers SET paused=? WHERE id=?"), value, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	if paused {
		if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_advertisements WHERE router_id=?"), id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_epochs WHERE router_id=?"), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) DeleteRouter(ctx context.Context, id string) error {
	res, err := s.Exec(ctx, "DELETE FROM routers WHERE id=?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CanForward is the policy gate the future transport must call for each route or circuit.
// A block by either owner rejects traffic in both directions.
func (s *Store) CanForward(ctx context.Context, sourceID, targetID string) (bool, error) {
	var srcOwner, dstOwner string
	var srcPaused, dstPaused int
	err := s.Row(ctx, "SELECT a.owner_id,b.owner_id,a.paused,b.paused FROM routers a JOIN routers b ON b.id=? WHERE a.id=?", targetID, sourceID).Scan(&srcOwner, &dstOwner, &srcPaused, &dstPaused)
	if err != nil {
		return false, err
	}
	if srcPaused != 0 || dstPaused != 0 {
		return false, nil
	}
	var count int
	err = s.Row(ctx, "SELECT COUNT(*) FROM user_blocks WHERE (owner_id=? AND blocked_user_id=?) OR (owner_id=? AND blocked_user_id=?)", dstOwner, srcOwner, srcOwner, dstOwner).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
func (s *Store) CheckRouterOwner(ctx context.Context, id, ownerID string) (Router, error) {
	r, err := s.RouterByID(ctx, id)
	if err != nil {
		return r, err
	}
	if r.OwnerID != ownerID {
		return Router{}, fmt.Errorf("router ownership: %w", ErrNotFound)
	}
	return r, nil
}
