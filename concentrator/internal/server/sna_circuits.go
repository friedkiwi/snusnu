package server

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
)

const snaCircuitProfile = "Native DLC/PIU"

type circuitHistoryRecord struct {
	ID, SourceRouterID, SourceRouterName, SourceOwnerID  string
	TargetRouterID, TargetRouterName, TargetOwnerID      string
	Profile, State, CloseReason, ActorType, ActorID      string
	OpenedAt, ActivatedAt, ClosedAt                      int64
	SourceBytes, TargetBytes, SourceEvents, TargetEvents uint64
	PeakQueuedBytes                                      uint64
}

type circuitView struct {
	ID, SourceRouterID, SourceRouterName, SourceOwnerID  string
	TargetRouterID, TargetRouterName, TargetOwnerID      string
	Profile, State, CloseReason, ActorType, ActorID      string
	OpenedAt, ActivatedAt, ClosedAt, LastActivityAt      int64
	SourceBytes, TargetBytes, SourceEvents, TargetEvents uint64
	SourceAllowance, TargetAllowance, PeakQueuedBytes    uint64
	Historical, CanReset                                 bool
}

func (h *routerHub) archiveCircuitLocked(id string, c *wsCircuit, reason, actorType, actorID string) {
	state := "closed"
	if reason != "normal close" {
		state = "reset"
	}
	sourceRouter, targetRouter := c.source.routerSnapshot(), c.target.routerSnapshot()
	record := circuitHistoryRecord{
		ID: id, SourceRouterID: sourceRouter.ID, SourceRouterName: sourceRouter.DisplayName, SourceOwnerID: sourceRouter.OwnerID,
		TargetRouterID: targetRouter.ID, TargetRouterName: targetRouter.DisplayName, TargetOwnerID: targetRouter.OwnerID,
		Profile: snaCircuitProfile, State: state, CloseReason: reason, ActorType: actorType, ActorID: actorID,
		OpenedAt: c.openedAt.Unix(), ActivatedAt: unixTime(c.activatedAt), ClosedAt: store.Now(),
		SourceBytes: c.sent[0], TargetBytes: c.sent[1], SourceEvents: c.events[0], TargetEvents: c.events[1], PeakQueuedBytes: c.peakQueued,
	}
	h.a.queueMu.RLock()
	defer h.a.queueMu.RUnlock()
	if !h.a.queuesOpen {
		h.a.historyDrops.Add(1)
		return
	}
	select {
	case h.a.circuitHistory <- record:
	default:
		h.a.historyDrops.Add(1)
		log.Printf("SNA circuit history queue full; summary for %s was not persisted", id)
	}
}

func unixTime(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func (a *App) startCircuitHistoryWriter(ctx context.Context) {
	a.queueMu.Lock()
	a.queuesOpen = true
	a.queueMu.Unlock()
	a.workersWG.Add(1)
	go func() {
		defer a.workersWG.Done()
		for {
			select {
			case <-ctx.Done():
				for {
					select {
					case record := <-a.circuitHistory:
						a.persistCircuitHistory(record)
					default:
						return
					}
				}
			case record := <-a.circuitHistory:
				a.persistCircuitHistory(record)
			}
		}
	}()
}

func (a *App) persistCircuitHistory(record circuitHistoryRecord) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = a.DB.Exec(writeCtx, `INSERT INTO sna_circuit_history(id,source_router_id,source_router_name,source_owner_id,target_router_id,target_router_name,target_owner_id,profile,opened_at,activated_at,closed_at,state,close_reason,source_bytes,target_bytes,source_events,target_events,peak_queued_bytes,actor_type,actor_id)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, record.ID, record.SourceRouterID, record.SourceRouterName, record.SourceOwnerID, record.TargetRouterID, record.TargetRouterName, record.TargetOwnerID, record.Profile, record.OpenedAt, record.ActivatedAt, record.ClosedAt, record.State, record.CloseReason, record.SourceBytes, record.TargetBytes, record.SourceEvents, record.TargetEvents, record.PeakQueuedBytes, record.ActorType, record.ActorID)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
	}
	a.writeFailures.Add(1)
	log.Printf("persist SNA circuit history %s after retries: %v", record.ID, err)
}

func (h *routerHub) liveCircuits(ownerID string, all bool) []circuitView {
	var items []circuitView
	h.circuits.Range(func(key, value any) bool {
		id, c := key.(string), value.(*wsCircuit)
		c.mu.Lock()
		defer c.mu.Unlock()
		sourceRouter, targetRouter := c.source.routerSnapshot(), c.target.routerSnapshot()
		if !all && sourceRouter.OwnerID != ownerID && targetRouter.OwnerID != ownerID {
			return true
		}
		state := "Active"
		if c.pending {
			state = "Opening"
		}
		items = append(items, circuitView{
			ID: id, SourceRouterID: sourceRouter.ID, SourceRouterName: sourceRouter.DisplayName, SourceOwnerID: sourceRouter.OwnerID,
			TargetRouterID: targetRouter.ID, TargetRouterName: targetRouter.DisplayName, TargetOwnerID: targetRouter.OwnerID,
			Profile: snaCircuitProfile, State: state, OpenedAt: c.openedAt.Unix(), ActivatedAt: unixTime(c.activatedAt), LastActivityAt: unixTime(c.lastActivityAt),
			SourceBytes: c.sent[0], TargetBytes: c.sent[1], SourceEvents: c.events[0], TargetEvents: c.events[1], SourceAllowance: c.allowance[0], TargetAllowance: c.allowance[1], PeakQueuedBytes: c.peakQueued, CanReset: true,
		})
		return true
	})
	return items
}

func (a *App) circuitHistoryRows(ctx context.Context, ownerID string, all bool, limit int) ([]circuitView, error) {
	query := "SELECT id,source_router_id,source_router_name,source_owner_id,target_router_id,target_router_name,target_owner_id,profile,opened_at,activated_at,closed_at,state,close_reason,source_bytes,target_bytes,source_events,target_events,peak_queued_bytes,actor_type,actor_id FROM sna_circuit_history"
	args := []any{}
	if !all {
		query += " WHERE source_owner_id=? OR target_owner_id=?"
		args = append(args, ownerID, ownerID)
	}
	query += " ORDER BY closed_at DESC LIMIT ?"
	args = append(args, limit)
	rows, err := a.DB.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []circuitView
	for rows.Next() {
		var x circuitView
		if err = rows.Scan(&x.ID, &x.SourceRouterID, &x.SourceRouterName, &x.SourceOwnerID, &x.TargetRouterID, &x.TargetRouterName, &x.TargetOwnerID, &x.Profile, &x.OpenedAt, &x.ActivatedAt, &x.ClosedAt, &x.State, &x.CloseReason, &x.SourceBytes, &x.TargetBytes, &x.SourceEvents, &x.TargetEvents, &x.PeakQueuedBytes, &x.ActorType, &x.ActorID); err != nil {
			return nil, err
		}
		x.Historical = true
		items = append(items, x)
	}
	return items, rows.Err()
}

func historyLimit(r *http.Request) int {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func (a *App) renderSNACircuits(w http.ResponseWriter, r *http.Request, u store.User, s store.Session, all bool) {
	history, err := a.circuitHistoryRows(r.Context(), u.ID, all, historyLimit(r))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		dbError(w, err)
		return
	}
	a.render(w, "sna_circuits", map[string]any{"User": u, "CSRF": s.CSRF, "Active": a.hub.liveCircuits(u.ID, all), "History": history, "All": all})
}

func (a *App) snaCircuits(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	a.renderSNACircuits(w, r, u, s, false)
}

func (a *App) adminSNACircuits(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	a.renderSNACircuits(w, r, u, s, true)
}

func (a *App) resetCircuitFor(w http.ResponseWriter, r *http.Request, u store.User, admin bool) bool {
	id := r.PathValue("id")
	value, found := a.hub.circuits.Load(id)
	if !found {
		http.Error(w, "SNA circuit is no longer active", http.StatusConflict)
		return false
	}
	c := value.(*wsCircuit)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		http.Error(w, "SNA circuit is no longer active", http.StatusConflict)
		return false
	}
	sourceRouter, targetRouter := c.source.routerSnapshot(), c.target.routerSnapshot()
	if !admin && sourceRouter.OwnerID != u.ID && targetRouter.OwnerID != u.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	a.hub.resetCircuitValue(id, c, wire.ResetReason_RESET_REASON_LOCAL_LINK, func() string {
		if admin {
			return "admin"
		}
		return "user"
	}(), u.Email, "manual reset")
	return true
}

func (a *App) resetSNACircuit(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if a.resetCircuitFor(w, r, u, false) {
		http.Redirect(w, r, "/circuits", http.StatusSeeOther)
	}
}

func (a *App) adminResetSNACircuit(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if a.resetCircuitFor(w, r, u, true) {
		http.Redirect(w, r, "/admin/circuits", http.StatusSeeOther)
	}
}
