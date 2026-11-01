package store

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
)

type Export struct {
	RouterID, RouterName, OwnerID, OwnerUsername, Kind, NetID, Name, HostingCPNetID, HostingCPName string
	RouteID, Generation, Revision                                                                  int64
	ManagedMAC, ADPTADR                                                                            string
}

func (s *Store) ListRouters(ctx context.Context, ownerID string) ([]Router, error) {
	q := "SELECT " + routerColumns + ",CASE WHEN EXISTS(SELECT 1 FROM router_epochs e WHERE e.router_id=routers.id) THEN 1 ELSE 0 END FROM routers"
	args := []any{}
	if ownerID != "" {
		q += " WHERE owner_id=?"
		args = append(args, ownerID)
	}
	q += " ORDER BY created_at DESC"
	rows, err := s.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Router
	for rows.Next() {
		var r Router
		var paused, connected, llcFacing int
		if err = rows.Scan(&r.ID, &r.OwnerID, &r.DisplayName, &paused, &r.CreatedAt, &r.LastSeenAt, &r.LastIP, &llcFacing, &connected); err != nil {
			return nil, err
		}
		r.Paused = paused != 0
		r.Connected = connected != 0
		r.LLCFacing = llcFacing != 0
		items = append(items, r)
	}
	return items, rows.Err()
}
func (s *Store) ListExports(ctx context.Context, ownerID string) ([]Export, error) {
	return s.listExports(ctx, ownerID, "")
}
func (s *Store) listExports(ctx context.Context, ownerID, routerID string) ([]Export, error) {
	q := "SELECT e.router_id,r.display_name,r.owner_id,u.username,e.kind,e.netid,e.name,e.hosting_cp_netid,e.hosting_cp_name,e.route_id,e.generation,e.revision,COALESCE(m.mac_suffix,0) FROM router_advertisements e JOIN routers r ON r.id=e.router_id JOIN users u ON u.id=r.owner_id LEFT JOIN managed_cp_addresses m ON m.owner_id=r.owner_id AND m.netid=e.netid AND m.cp_name=e.name AND e.kind='CP' AND m.enabled=1 AND m.retired_at=0 WHERE r.paused=0"
	args := []any{}
	if ownerID != "" {
		q += " AND r.owner_id=?"
		args = append(args, ownerID)
	}
	if routerID != "" {
		q += " AND r.id=?"
		args = append(args, routerID)
	}
	q += " ORDER BY e.netid,e.name,e.kind,r.display_name"
	rows, err := s.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Export
	for rows.Next() {
		var x Export
		var suffix int64
		if err = rows.Scan(&x.RouterID, &x.RouterName, &x.OwnerID, &x.OwnerUsername, &x.Kind, &x.NetID, &x.Name, &x.HostingCPNetID, &x.HostingCPName, &x.RouteID, &x.Generation, &x.Revision, &suffix); err != nil {
			return nil, err
		}
		if suffix != 0 {
			cp := ManagedCP{Suffix: suffix}
			x.ManagedMAC = cp.MACColon()
			x.ADPTADR = cp.ADPTADR()
		}
		items = append(items, x)
	}
	return items, rows.Err()
}
func (s *Store) ListRouterExports(ctx context.Context, routerID string) ([]Export, error) {
	return s.listExports(ctx, "", routerID)
}
func (s *Store) SetBlock(ctx context.Context, ownerID, blockedID string, blocked bool) error {
	if ownerID == blockedID {
		return errors.New("cannot block yourself")
	}
	if blocked {
		_, err := s.Exec(ctx, "INSERT INTO user_blocks(owner_id,blocked_user_id,created_at) VALUES(?,?,?) ON CONFLICT(owner_id,blocked_user_id) DO NOTHING", ownerID, blockedID, Now())
		return err
	}
	_, err := s.Exec(ctx, "DELETE FROM user_blocks WHERE owner_id=? AND blocked_user_id=?", ownerID, blockedID)
	return err
}
func (s *Store) IsBlocked(ctx context.Context, ownerID, blockedID string) (bool, error) {
	var count int
	err := s.Row(ctx, "SELECT COUNT(*) FROM user_blocks WHERE owner_id=? AND blocked_user_id=?", ownerID, blockedID).Scan(&count)
	return count > 0, err
}

type LogEntry struct {
	ID, RouterID, OwnerID, PeerUserID, Direction, Level, EventType, NetID, NodeName, SourceIP, Summary, DetailsJSON string
	OccurredAt                                                                                                      int64
}

func (s *Store) AppendRouterLog(ctx context.Context, x LogEntry) error {
	if x.Direction != "inbound" && x.Direction != "outbound" && x.Direction != "system" {
		return errors.New("invalid log direction")
	}
	if x.Level != "info" && x.Level != "warning" && x.Level != "error" {
		return errors.New("invalid log level")
	}
	if len(x.Summary) > 2000 || len(x.DetailsJSON) > 8192 || len(x.EventType) > 80 || len(x.SourceIP) > 64 {
		return errors.New("log entry too large")
	}
	if x.SourceIP != "" && net.ParseIP(x.SourceIP) == nil {
		return errors.New("invalid source IP")
	}
	if x.DetailsJSON != "" && !json.Valid([]byte(x.DetailsJSON)) {
		return errors.New("invalid decoded JSON")
	}
	r, err := s.RouterByID(ctx, x.RouterID)
	if err != nil {
		return err
	}
	if x.OwnerID != "" && x.OwnerID != r.OwnerID {
		return errors.New("log owner mismatch")
	}
	var peer any
	if x.PeerUserID != "" {
		peer = x.PeerUserID
	}
	_, err = s.Exec(ctx, "INSERT INTO router_logs(id,router_id,owner_id,peer_user_id,direction,level,event_type,netid,node_name,source_ip,summary,details_json,occurred_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", RandomUUID(), x.RouterID, r.OwnerID, peer, x.Direction, x.Level, x.EventType, x.NetID, x.NodeName, x.SourceIP, x.Summary, x.DetailsJSON, Now())
	return err
}
func (s *Store) SearchRouterLogs(ctx context.Context, routerID, q string) ([]LogEntry, error) {
	return s.searchLogs(ctx, "l.router_id=?", routerID, q)
}
func (s *Store) SearchInboundFlows(ctx context.Context, ownerID, q string) ([]LogEntry, error) {
	return s.searchLogs(ctx, "l.owner_id=? AND l.direction='inbound' AND l.peer_user_id IS NOT NULL AND l.peer_user_id<>l.owner_id", ownerID, q)
}
func (s *Store) searchLogs(ctx context.Context, filter, arg, q string) ([]LogEntry, error) {
	query := "SELECT l.id,l.router_id,l.owner_id,COALESCE(l.peer_user_id,''),l.direction,l.level,l.event_type,l.netid,l.node_name,l.source_ip,l.summary,l.details_json,l.occurred_at FROM router_logs l WHERE " + filter
	args := []any{arg}
	if q = strings.TrimSpace(q); q != "" {
		if len(q) > 100 {
			q = q[:100]
		}
		query += " AND (LOWER(l.summary) LIKE LOWER(?) OR LOWER(l.event_type) LIKE LOWER(?) OR LOWER(l.source_ip) LIKE LOWER(?) OR LOWER(l.netid) LIKE LOWER(?) OR LOWER(l.node_name) LIKE LOWER(?) OR LOWER(l.details_json) LIKE LOWER(?))"
		for range 6 {
			args = append(args, "%"+q+"%")
		}
	}
	query += " ORDER BY l.occurred_at DESC,l.id DESC LIMIT 100"
	rows, err := s.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []LogEntry
	for rows.Next() {
		var x LogEntry
		if err = rows.Scan(&x.ID, &x.RouterID, &x.OwnerID, &x.PeerUserID, &x.Direction, &x.Level, &x.EventType, &x.NetID, &x.NodeName, &x.SourceIP, &x.Summary, &x.DetailsJSON, &x.OccurredAt); err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	return items, rows.Err()
}
