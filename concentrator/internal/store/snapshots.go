package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"

	"github.com/google/uuid"
)

var ErrStaleEpoch = errors.New("stale router connection epoch or revision")

// IBM's SNA Type A names require an alphabetic or national first character.
// https://www.ibm.com/docs/en/personal-communications/15.0.0?topic=l03pk-lu-name
var snaName = regexp.MustCompile(`^[A-Z@#$][A-Z0-9@#$]{0,7}$`)

type RouteExport struct {
	ID, Generation                                   uint64
	Kind, NetID, Name, HostingCPNetID, HostingCPName string
	LUTypes                                          []string
}

// BeginRouterEpoch is called only after router-scoped bearer authentication.
// It fences the previous connection and withdraws that connection's exports.
func (s *Store) BeginRouterEpoch(ctx context.Context, routerID, sourceIP string) (string, error) {
	if sourceIP != "" && net.ParseIP(sourceIP) == nil {
		return "", errors.New("invalid source IP")
	}
	epoch := uuid.NewString()
	now := Now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.Q("UPDATE routers SET last_seen_at=?,last_ip=? WHERE id=? AND paused=0"), now, sourceIP, routerID)
	if err != nil {
		return "", err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", ErrPaused
	}
	if _, err = tx.ExecContext(ctx, s.Q("INSERT INTO router_epochs(router_id,epoch,revision,connected_at,source_ip) VALUES(?,?,0,?,?) ON CONFLICT(router_id) DO UPDATE SET epoch=excluded.epoch,revision=0,connected_at=excluded.connected_at,source_ip=excluded.source_ip"), routerID, epoch, now, sourceIP); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_advertisements WHERE router_id=?"), routerID); err != nil {
		return "", err
	}
	return epoch, tx.Commit()
}

// ReplaceRouterSnapshot installs one complete validated export set for the current epoch.
func (s *Store) ReplaceRouterSnapshot(ctx context.Context, routerID, epoch string, revision uint64, exports []RouteExport) error {
	if _, err := uuid.Parse(epoch); err != nil {
		return errors.New("invalid epoch")
	}
	if revision == 0 || revision > math.MaxInt64 || len(exports) > 256 {
		return errors.New("invalid snapshot size or revision")
	}
	ids := make(map[uint64]bool, len(exports))
	resources := make(map[string]bool, len(exports))
	for _, x := range exports {
		if x.ID == 0 || x.ID > math.MaxInt64 || x.Generation == 0 || x.Generation > math.MaxInt64 || !snaName.MatchString(x.NetID) || !snaName.MatchString(x.Name) || (x.Kind != "CP" && x.Kind != "LU") {
			return errors.New("invalid route export")
		}
		if x.Kind == "CP" && (x.HostingCPNetID != "" || x.HostingCPName != "") {
			return errors.New("CP cannot have hosting CP")
		}
		if (x.HostingCPNetID == "") != (x.HostingCPName == "") {
			return errors.New("incomplete hosting CP")
		}
		if x.HostingCPNetID != "" && (!snaName.MatchString(x.HostingCPNetID) || !snaName.MatchString(x.HostingCPName)) {
			return errors.New("invalid hosting CP")
		}
		if x.Kind == "CP" && len(x.LUTypes) != 0 {
			return errors.New("CP cannot have LU types")
		}
		seenTypes := map[string]bool{}
		for _, luType := range x.LUTypes {
			if (luType != "LU 0" && luType != "LU 1" && luType != "LU 2" && luType != "LU 3" && luType != "LU 6.2") || seenTypes[luType] {
				return errors.New("invalid or duplicate LU type")
			}
			seenTypes[luType] = true
		}
		resource := x.Kind + ":" + x.NetID + ":" + x.Name
		if ids[x.ID] || resources[resource] {
			return errors.New("duplicate route ID or resource")
		}
		ids[x.ID] = true
		resources[resource] = true
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.Q("UPDATE router_epochs SET revision=? WHERE router_id=? AND epoch=? AND revision<?"), int64(revision), routerID, epoch, int64(revision))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrStaleEpoch
	}
	if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_advertisements WHERE router_id=?"), routerID); err != nil {
		return err
	}
	for _, x := range exports {
		luTypes, _ := json.Marshal(x.LUTypes)
		_, err = tx.ExecContext(ctx, s.Q("INSERT INTO router_advertisements(router_id,route_id,generation,epoch,revision,kind,netid,name,hosting_cp_netid,hosting_cp_name,lu_types) VALUES(?,?,?,?,?,?,?,?,?,?,?)"), routerID, int64(x.ID), int64(x.Generation), epoch, int64(revision), x.Kind, x.NetID, x.Name, x.HostingCPNetID, x.HostingCPName, string(luTypes))
		if err != nil {
			return fmt.Errorf("insert route export: %w", err)
		}
	}
	return tx.Commit()
}

// EndRouterEpoch withdraws only the named connection's routes.
func (s *Store) EndRouterEpoch(ctx context.Context, routerID, epoch string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.Q("DELETE FROM router_epochs WHERE router_id=? AND epoch=?"), routerID, epoch)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil
	}
	if _, err = tx.ExecContext(ctx, s.Q("DELETE FROM router_advertisements WHERE router_id=?"), routerID); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetLiveState prevents a restarted single-process concentrator from
// displaying stale connections or advertisements as live.
func (s *Store) ResetLiveState(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM router_advertisements"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM router_epochs"); err != nil {
		return err
	}
	return tx.Commit()
}
