package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
)

var ErrInvalidResetCode = errors.New("invalid or expired password reset code")

func resetCodeHash(userID, code string) string {
	return Hash("password-reset:" + userID + ":" + code)
}

func (s *Store) IssuePasswordReset(ctx context.Context, userID, code string) error {
	_, err := s.Exec(ctx, `INSERT INTO password_reset_tokens(user_id,code_hash,expires_at,attempts) VALUES(?,?,?,0)
		ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0`, userID, resetCodeHash(userID, code), Now()+600)
	return err
}

// VerifyPasswordResetCode counts an attempt before any password hashing work.
func (s *Store) VerifyPasswordResetCode(ctx context.Context, userID, code string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored string
	err = tx.QueryRowContext(ctx, s.Q(`UPDATE password_reset_tokens SET attempts=attempts+1
		WHERE user_id=? AND attempts<5 AND expires_at>? RETURNING code_hash`), userID, Now()).Scan(&stored)
	if err == sql.ErrNoRows {
		return ErrInvalidResetCode
	}
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(resetCodeHash(userID, code))) != 1 {
		if err := tx.Commit(); err != nil {
			return err
		}
		return ErrInvalidResetCode
	}
	return tx.Commit()
}

// CompletePasswordResetVerified consumes a previously verified code once,
// changes the password, and revokes browser sessions atomically.
func (s *Store) CompletePasswordResetVerified(ctx context.Context, userID, code, passwordHash string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stored := resetCodeHash(userID, code)
	res, err := tx.ExecContext(ctx, s.Q("DELETE FROM password_reset_tokens WHERE user_id=? AND code_hash=? AND expires_at>?"), userID, stored, Now())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return ErrInvalidResetCode
	}
	if err := updatePasswordAndSessions(ctx, s, tx, userID, passwordHash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompletePasswordReset(ctx context.Context, userID, code, passwordHash string) error {
	if err := s.VerifyPasswordResetCode(ctx, userID, code); err != nil {
		return err
	}
	return s.CompletePasswordResetVerified(ctx, userID, code, passwordHash)
}

func (s *Store) AdminResetPassword(ctx context.Context, userID, passwordHash string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = updatePasswordAndSessions(ctx, s, tx, userID, passwordHash); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM password_reset_tokens WHERE user_id=?"), userID); err != nil {
		return err
	}
	return tx.Commit()
}

func updatePasswordAndSessions(ctx context.Context, s *Store, tx *sql.Tx, userID, passwordHash string) error {
	res, err := tx.ExecContext(ctx, s.Q("UPDATE users SET password_hash=? WHERE id=?"), passwordHash, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	_, err = tx.ExecContext(ctx, s.Q("DELETE FROM sessions WHERE user_id=?"), userID)
	return err
}
