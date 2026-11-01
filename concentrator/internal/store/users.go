package store

import (
	"context"
	"database/sql"
	"errors"
)

var ErrLastAdmin = errors.New("cannot delete the last admin account")

// DeleteUser retires server-owned address assignments before removing the
// account. Other account-owned records cascade through their foreign keys.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize admin deletion checks across both supported databases.
	if _, err = tx.ExecContext(ctx, "UPDATE users SET role=role WHERE role='admin'"); err != nil {
		return err
	}
	var role string
	if err = tx.QueryRowContext(ctx, s.Q("SELECT role FROM users WHERE id=?"), userID).Scan(&role); err != nil {
		return err
	}
	if role == "admin" {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin'").Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err = tx.ExecContext(ctx, s.Q("UPDATE managed_cp_addresses SET enabled=0,retired_at=? WHERE owner_id=? AND retired_at=0"), Now(), userID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, s.Q("DELETE FROM users WHERE id=?"), userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}
