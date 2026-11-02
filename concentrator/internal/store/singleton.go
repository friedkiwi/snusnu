package store

import (
	"context"
	"errors"
)

var ErrInstanceActive = errors.New("another concentrator instance is active for this database")

func (s *Store) AcquireInstance(ctx context.Context, instanceID string) error {
	now := Now()
	result, err := s.Exec(ctx, `INSERT INTO concentrator_instance(id,instance_id,heartbeat_at) VALUES(1,?,?)
		ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,heartbeat_at=excluded.heartbeat_at
		WHERE concentrator_instance.instance_id=excluded.instance_id OR concentrator_instance.heartbeat_at<?`, instanceID, now, now-30)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInstanceActive
	}
	return nil
}

func (s *Store) HeartbeatInstance(ctx context.Context, instanceID string) error {
	result, err := s.Exec(ctx, "UPDATE concentrator_instance SET heartbeat_at=? WHERE id=1 AND instance_id=?", Now(), instanceID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInstanceActive
	}
	return nil
}

func (s *Store) ReleaseInstance(ctx context.Context, instanceID string) error {
	_, err := s.Exec(ctx, "DELETE FROM concentrator_instance WHERE id=1 AND instance_id=?", instanceID)
	return err
}
