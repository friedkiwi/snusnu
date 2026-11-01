package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const maxManagedSuffix = 0xFFFFFF

var ErrRetiredCP = errors.New("CP address is retired")
var ErrMACPoolExhausted = errors.New("managed MAC pool exhausted")

type ManagedCP struct {
	ID, OwnerID, NetID, CPName string
	Suffix                     int64
	Enabled, Online            bool
	CreatedAt, RetiredAt       int64
	Advertisers                []string
}

func (cp ManagedCP) MACBytes() [6]byte {
	return [6]byte{0x02, 0x53, 0x4e, byte(cp.Suffix >> 16), byte(cp.Suffix >> 8), byte(cp.Suffix)}
}
func (cp ManagedCP) MACColon() string {
	b := cp.MACBytes()
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}
func (cp ManagedCP) ADPTADR() string {
	b := cp.MACBytes()
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// ParseManagedMAC validates a managed address's local prefix and nonzero pool
// suffix. It does not authenticate the sender of an address claim.
func ParseManagedMAC(input string) ([6]byte, error) {
	var out [6]byte
	compact := input
	if strings.Contains(input, ":") {
		if len(input) != 17 || input[2] != ':' || input[5] != ':' || input[8] != ':' || input[11] != ':' || input[14] != ':' {
			return out, errors.New("managed MAC must use six colon-separated octets")
		}
		compact = strings.ReplaceAll(input, ":", "")
	}
	if len(compact) != 12 {
		return out, errors.New("managed MAC must contain six octets")
	}
	b, err := hex.DecodeString(compact)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	if out[0] != 0x02 || out[1] != 0x53 || out[2] != 0x4e || (out[3] == 0 && out[4] == 0 && out[5] == 0) {
		return [6]byte{}, errors.New("address outside snusnu local MAC pool")
	}
	return out, nil
}

func scanManagedCP(row *sql.Row) (ManagedCP, error) {
	var x ManagedCP
	var enabled, online int
	err := row.Scan(&x.ID, &x.OwnerID, &x.NetID, &x.CPName, &x.Suffix, &enabled, &x.CreatedAt, &x.RetiredAt, &online)
	x.Enabled = enabled != 0
	x.Online = online != 0
	return x, err
}

const managedCPColumns = "m.id,m.owner_id,m.netid,m.cp_name,m.mac_suffix,m.enabled,m.created_at,m.retired_at,CASE WHEN EXISTS(SELECT 1 FROM router_advertisements e JOIN routers r ON r.id=e.router_id JOIN router_epochs ep ON ep.router_id=r.id AND ep.epoch=e.epoch WHERE e.kind='CP' AND e.netid=m.netid AND e.name=m.cp_name AND r.owner_id=m.owner_id AND r.paused=0) THEN 1 ELSE 0 END"

func (s *Store) ManagedCPByID(ctx context.Context, id string) (ManagedCP, error) {
	return scanManagedCP(s.Row(ctx, "SELECT "+managedCPColumns+" FROM managed_cp_addresses m WHERE m.id=?", id))
}
func (s *Store) managedCPByName(ctx context.Context, owner, netid, name string) (ManagedCP, error) {
	return scanManagedCP(s.Row(ctx, "SELECT "+managedCPColumns+" FROM managed_cp_addresses m WHERE m.owner_id=? AND m.netid=? AND m.cp_name=?", owner, netid, name))
}

// AllocateManagedCP uses one transactional counter row across SQLite and
// PostgreSQL. Its unique suffix constraint also protects against collisions.
func (s *Store) AllocateManagedCP(ctx context.Context, owner, netid, name string) (ManagedCP, error) {
	if !snaName.MatchString(netid) || !snaName.MatchString(name) {
		return ManagedCP{}, errors.New("invalid qualified CP name")
	}
	if existing, err := s.managedCPByName(ctx, owner, netid, name); err == nil {
		if existing.RetiredAt != 0 {
			return ManagedCP{}, ErrRetiredCP
		}
		return existing, nil
	} else if err != sql.ErrNoRows {
		return ManagedCP{}, err
	}
	var ownerExists int
	if err := s.Row(ctx, "SELECT COUNT(*) FROM users WHERE id=?", owner).Scan(&ownerExists); err != nil {
		return ManagedCP{}, err
	}
	if ownerExists != 1 {
		return ManagedCP{}, sql.ErrNoRows
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedCP{}, err
	}
	defer tx.Rollback()
	var suffix int64
	err = tx.QueryRowContext(ctx, "UPDATE mac_pool_state SET next_suffix=next_suffix+1 WHERE id=1 AND next_suffix<=16777215 RETURNING next_suffix-1").Scan(&suffix)
	if err == sql.ErrNoRows {
		return ManagedCP{}, ErrMACPoolExhausted
	}
	if err != nil {
		return ManagedCP{}, err
	}
	x := ManagedCP{ID: uuid.NewString(), OwnerID: owner, NetID: netid, CPName: name, Suffix: suffix, Enabled: true, CreatedAt: Now()}
	_, err = tx.ExecContext(ctx, s.Q("INSERT INTO managed_cp_addresses(id,owner_id,netid,cp_name,mac_suffix,enabled,created_at) VALUES(?,?,?,?,?,1,?)"), x.ID, x.OwnerID, x.NetID, x.CPName, x.Suffix, x.CreatedAt)
	if err != nil {
		tx.Rollback()
		if existing, lookupErr := s.managedCPByName(ctx, owner, netid, name); lookupErr == nil {
			if existing.RetiredAt != 0 {
				return ManagedCP{}, ErrRetiredCP
			}
			return existing, nil
		}
		return ManagedCP{}, err
	}
	if err = tx.Commit(); err != nil {
		return ManagedCP{}, err
	}
	return x, nil
}

func (s *Store) SetManagedCPEnabled(ctx context.Context, id, owner string, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	res, err := s.Exec(ctx, "UPDATE managed_cp_addresses SET enabled=? WHERE id=? AND owner_id=? AND retired_at=0", value, id, owner)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) RetireManagedCP(ctx context.Context, id, owner string) error {
	res, err := s.Exec(ctx, "UPDATE managed_cp_addresses SET retired_at=?,enabled=0 WHERE id=? AND owner_id=? AND retired_at=0", Now(), id, owner)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) ListManagedCP(ctx context.Context, owner string) ([]ManagedCP, error) {
	q := "SELECT " + managedCPColumns + " FROM managed_cp_addresses m"
	args := []any{}
	if owner != "" {
		q += " WHERE m.owner_id=?"
		args = append(args, owner)
	}
	q += " ORDER BY m.netid,m.cp_name,m.created_at"
	rows, err := s.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var out []ManagedCP
	for rows.Next() {
		var x ManagedCP
		var enabled, online int
		if err = rows.Scan(&x.ID, &x.OwnerID, &x.NetID, &x.CPName, &x.Suffix, &enabled, &x.CreatedAt, &x.RetiredAt, &online); err != nil {
			rows.Close()
			return nil, err
		}
		x.Enabled = enabled != 0
		x.Online = online != 0
		out = append(out, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Online {
			names, err := s.managedCPAdvertisers(ctx, out[i])
			if err != nil {
				return nil, err
			}
			out[i].Advertisers = names
		}
	}
	return out, nil
}
func (s *Store) managedCPAdvertisers(ctx context.Context, x ManagedCP) ([]string, error) {
	rows, err := s.Query(ctx, "SELECT DISTINCT r.display_name FROM router_advertisements e JOIN routers r ON r.id=e.router_id JOIN router_epochs ep ON ep.router_id=r.id AND ep.epoch=e.epoch WHERE e.kind='CP' AND e.netid=? AND e.name=? AND r.owner_id=? AND r.paused=0 ORDER BY r.display_name", x.NetID, x.CPName, x.OwnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
