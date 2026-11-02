package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/google/uuid"
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

type pendingCircuitHistory struct {
	Record circuitHistoryRecord
	Status string
}

type circuitView struct {
	ID, SourceRouterID, SourceRouterName, SourceOwnerID  string
	TargetRouterID, TargetRouterName, TargetOwnerID      string
	Profile, State, CloseReason, ActorType, ActorID      string
	OpenedAt, ActivatedAt, ClosedAt, LastActivityAt      int64
	SourceBytes, TargetBytes, SourceEvents, TargetEvents uint64
	SourceAllowance, TargetAllowance, PeakQueuedBytes    uint64
	Historical, CanReset                                 bool
	Persistence                                          string
}

type circuitHistoryPage struct {
	Items, Pending                  []circuitView
	Search, State, Reason, From, To string
	CursorID, Direction             string
	CursorClosed                    int64
	PageSize                        int
	PrevURL, NextURL                string
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
	h.a.historyArchived.Add(1)
	h.a.historyMu.Lock()
	h.a.historyPending[id] = pendingCircuitHistory{Record: record, Status: "queued"}
	h.a.historyMu.Unlock()
	if !h.a.circuitHistory.push(record) {
		h.a.historyFailed.Add(1)
		h.a.historyMu.Lock()
		h.a.historyPending[id] = pendingCircuitHistory{Record: record, Status: "failed"}
		h.a.historyMu.Unlock()
		log.Printf("SNA circuit history queue full; summary for %s was not persisted", id)
		h.a.signalFatal(errors.New("SNA circuit history queue exhausted"))
	}
}

func unixTime(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func (a *App) startCircuitHistoryWriter(ctx context.Context) {
	a.workersWG.Add(1)
	go func() {
		defer a.workersWG.Done()
		for {
			record, ok := a.circuitHistory.pop(ctx.Done())
			if !ok {
				return
			}
			a.historyMu.Lock()
			a.historyPending[record.ID] = pendingCircuitHistory{Record: record, Status: "writing"}
			a.historyMu.Unlock()
			a.persistCircuitHistory(record)
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
			a.historyPersisted.Add(1)
			a.historyMu.Lock()
			delete(a.historyPending, record.ID)
			a.historyMu.Unlock()
			return
		}
		if attempt != 2 {
			a.historyRetries.Add(1)
		}
		time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
	}
	a.writeFailures.Add(1)
	a.historyFailed.Add(1)
	a.historyMu.Lock()
	a.historyPending[record.ID] = pendingCircuitHistory{Record: record, Status: "failed"}
	a.historyMu.Unlock()
	log.Printf("persist SNA circuit history %s after retries: %v", record.ID, err)
	a.signalFatal(fmt.Errorf("database unavailable while persisting SNA circuit history: %w", err))
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

func circuitHistoryFilter(r *http.Request) circuitHistoryPage {
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size < 10 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	state := r.URL.Query().Get("state")
	if state != "closed" && state != "reset" {
		state = ""
	}
	direction := r.URL.Query().Get("direction")
	if direction != "older" && direction != "newer" {
		direction = ""
	}
	cursorClosed, _ := strconv.ParseInt(r.URL.Query().Get("cursor_closed"), 10, 64)
	cursorID := r.URL.Query().Get("cursor_id")
	if cursorClosed <= 0 || len(cursorID) > 64 || cursorID == "" {
		cursorClosed, cursorID, direction = 0, "", ""
	}
	return circuitHistoryPage{Search: strings.TrimSpace(r.URL.Query().Get("q")), State: state, Reason: strings.TrimSpace(r.URL.Query().Get("reason")), From: r.URL.Query().Get("from"), To: r.URL.Query().Get("to"), CursorClosed: cursorClosed, CursorID: cursorID, Direction: direction, PageSize: size}
}

func historyWhere(filter circuitHistoryPage, ownerID string, all bool) (string, []any) {
	var clauses []string
	var args []any
	if !all {
		clauses = append(clauses, "(h.source_owner_id=? OR h.target_owner_id=?)")
		args = append(args, ownerID, ownerID)
	}
	if filter.State != "" {
		clauses = append(clauses, "h.state=?")
		args = append(args, filter.State)
	}
	if filter.Reason != "" {
		clauses = append(clauses, "LOWER(h.close_reason) LIKE ?")
		args = append(args, "%"+strings.ToLower(filter.Reason)+"%")
	}
	if filter.Search != "" {
		if _, err := uuid.Parse(filter.Search); err == nil {
			clauses = append(clauses, `(h.id=? OR h.source_router_id=? OR h.source_owner_id=? OR h.target_router_id=? OR h.target_owner_id=?)`)
			for i := 0; i < 5; i++ {
				args = append(args, filter.Search)
			}
		} else {
			like := "%" + strings.ToLower(filter.Search) + "%"
			clauses = append(clauses, `(LOWER(h.id) LIKE ? OR LOWER(h.source_router_id) LIKE ? OR LOWER(h.source_router_name) LIKE ? OR LOWER(h.source_owner_id) LIKE ? OR LOWER(h.target_router_id) LIKE ? OR LOWER(h.target_router_name) LIKE ? OR LOWER(h.target_owner_id) LIKE ? OR LOWER(h.close_reason) LIKE ? OR LOWER(h.actor_id) LIKE ? OR LOWER(COALESCE(su.email,'')) LIKE ? OR LOWER(COALESCE(tu.email,'')) LIKE ?)`)
			for i := 0; i < 11; i++ {
				args = append(args, like)
			}
		}
	}
	if value, err := time.Parse("2006-01-02", filter.From); err == nil {
		clauses = append(clauses, "h.closed_at>=?")
		args = append(args, value.Unix())
	}
	if value, err := time.Parse("2006-01-02", filter.To); err == nil {
		clauses = append(clauses, "h.closed_at<?")
		args = append(args, value.Add(24*time.Hour).Unix())
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (a *App) circuitHistoryRows(ctx context.Context, ownerID string, all bool, page *circuitHistoryPage) error {
	from := " FROM sna_circuit_history h LEFT JOIN users su ON su.id=h.source_owner_id LEFT JOIN users tu ON tu.id=h.target_owner_id"
	where, args := historyWhere(*page, ownerID, all)
	if page.CursorID != "" {
		operator := "<"
		if page.Direction == "newer" {
			operator = ">"
		}
		clause := fmt.Sprintf("(h.closed_at%s? OR (h.closed_at=? AND h.id%s?))", operator, operator)
		if where == "" {
			where = " WHERE " + clause
		} else {
			where += " AND " + clause
		}
		args = append(args, page.CursorClosed, page.CursorClosed, page.CursorID)
	}
	order := "DESC"
	if page.Direction == "newer" {
		order = "ASC"
	}
	query := "SELECT h.id,h.source_router_id,h.source_router_name,h.source_owner_id,h.target_router_id,h.target_router_name,h.target_owner_id,h.profile,h.opened_at,h.activated_at,h.closed_at,h.state,h.close_reason,h.source_bytes,h.target_bytes,h.source_events,h.target_events,h.peak_queued_bytes,h.actor_type,h.actor_id" + from + where + " ORDER BY h.closed_at " + order + ",h.id " + order + " LIMIT ?"
	queryArgs := append(append([]any{}, args...), page.PageSize+1)
	rows, err := a.DB.Query(ctx, query, queryArgs...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var x circuitView
		if err = rows.Scan(&x.ID, &x.SourceRouterID, &x.SourceRouterName, &x.SourceOwnerID, &x.TargetRouterID, &x.TargetRouterName, &x.TargetOwnerID, &x.Profile, &x.OpenedAt, &x.ActivatedAt, &x.ClosedAt, &x.State, &x.CloseReason, &x.SourceBytes, &x.TargetBytes, &x.SourceEvents, &x.TargetEvents, &x.PeakQueuedBytes, &x.ActorType, &x.ActorID); err != nil {
			return err
		}
		x.Historical = true
		x.Persistence = "persisted"
		page.Items = append(page.Items, x)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	hasMore := len(page.Items) > page.PageSize
	if hasMore {
		page.Items = page.Items[:page.PageSize]
	}
	if page.Direction == "newer" {
		for left, right := 0, len(page.Items)-1; left < right; left, right = left+1, right-1 {
			page.Items[left], page.Items[right] = page.Items[right], page.Items[left]
		}
	}
	values := rValues(*page)
	if len(page.Items) != 0 && ((page.Direction == "older" && page.CursorID != "") || (page.Direction == "newer" && hasMore)) {
		values.Set("direction", "newer")
		values.Set("cursor_closed", strconv.FormatInt(page.Items[0].ClosedAt, 10))
		values.Set("cursor_id", page.Items[0].ID)
		page.PrevURL = "?" + values.Encode()
	}
	if len(page.Items) != 0 && ((page.Direction == "newer" && page.CursorID != "") || (page.Direction != "newer" && hasMore)) {
		values.Set("direction", "older")
		values.Set("cursor_closed", strconv.FormatInt(page.Items[len(page.Items)-1].ClosedAt, 10))
		values.Set("cursor_id", page.Items[len(page.Items)-1].ID)
		page.NextURL = "?" + values.Encode()
	}
	return nil
}

func rValues(page circuitHistoryPage) url.Values {
	v := url.Values{"page_size": {strconv.Itoa(page.PageSize)}}
	if page.Search != "" {
		v.Set("q", page.Search)
	}
	if page.State != "" {
		v.Set("state", page.State)
	}
	if page.Reason != "" {
		v.Set("reason", page.Reason)
	}
	if page.From != "" {
		v.Set("from", page.From)
	}
	if page.To != "" {
		v.Set("to", page.To)
	}
	return v
}

func historyRecordView(record circuitHistoryRecord, persistence string) circuitView {
	return circuitView{ID: record.ID, SourceRouterID: record.SourceRouterID, SourceRouterName: record.SourceRouterName, SourceOwnerID: record.SourceOwnerID, TargetRouterID: record.TargetRouterID, TargetRouterName: record.TargetRouterName, TargetOwnerID: record.TargetOwnerID, Profile: record.Profile, State: record.State, CloseReason: record.CloseReason, ActorType: record.ActorType, ActorID: record.ActorID, OpenedAt: record.OpenedAt, ActivatedAt: record.ActivatedAt, ClosedAt: record.ClosedAt, SourceBytes: record.SourceBytes, TargetBytes: record.TargetBytes, SourceEvents: record.SourceEvents, TargetEvents: record.TargetEvents, PeakQueuedBytes: record.PeakQueuedBytes, Historical: true, Persistence: persistence}
}

func pendingMatches(record circuitHistoryRecord, ownerID string, all bool, filter circuitHistoryPage) bool {
	if !all && record.SourceOwnerID != ownerID && record.TargetOwnerID != ownerID {
		return false
	}
	if filter.State != "" && record.State != filter.State {
		return false
	}
	if filter.Reason != "" && !strings.Contains(strings.ToLower(record.CloseReason), strings.ToLower(filter.Reason)) {
		return false
	}
	if value, err := time.Parse("2006-01-02", filter.From); err == nil && record.ClosedAt < value.Unix() {
		return false
	}
	if value, err := time.Parse("2006-01-02", filter.To); err == nil && record.ClosedAt >= value.Add(24*time.Hour).Unix() {
		return false
	}
	if filter.Search != "" {
		haystack := strings.ToLower(strings.Join([]string{record.ID, record.SourceRouterID, record.SourceRouterName, record.SourceOwnerID, record.TargetRouterID, record.TargetRouterName, record.TargetOwnerID, record.CloseReason, record.ActorID}, " "))
		if !strings.Contains(haystack, strings.ToLower(filter.Search)) {
			return false
		}
	}
	return true
}

func (a *App) pendingCircuitHistory(ownerID string, all bool, filter circuitHistoryPage) []circuitView {
	a.historyMu.Lock()
	defer a.historyMu.Unlock()
	items := make([]circuitView, 0, len(a.historyPending))
	for _, pending := range a.historyPending {
		if pendingMatches(pending.Record, ownerID, all, filter) {
			items = append(items, historyRecordView(pending.Record, pending.Status))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ClosedAt > items[j].ClosedAt || items[i].ClosedAt == items[j].ClosedAt && items[i].ID > items[j].ID
	})
	return items
}

func (a *App) renderSNACircuits(w http.ResponseWriter, r *http.Request, u store.User, s store.Session, all bool) {
	history := circuitHistoryFilter(r)
	err := a.circuitHistoryRows(r.Context(), u.ID, all, &history)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		dbError(w, err)
		return
	}
	history.Pending = a.pendingCircuitHistory(u.ID, all, history)
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
