package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

type maintenanceDefinition struct {
	Name, Title, Description, Schedule string
	Run                                func(context.Context) (string, error)
}

type maintenanceRun struct {
	Name, Title, Description, Schedule   string
	StartedAt, FinishedAt                int64
	Status, Trigger, TriggeredBy, Result string
}

type maintenanceManager struct {
	a       *App
	mu      sync.Mutex
	running map[string]bool
	tasks   map[string]maintenanceDefinition
}

func newMaintenanceManager(a *App) *maintenanceManager {
	m := &maintenanceManager{a: a, running: make(map[string]bool), tasks: make(map[string]maintenanceDefinition)}
	m.tasks["expired-records"] = maintenanceDefinition{
		Name: "expired-records", Title: "Expired authentication records", Schedule: "Hourly",
		Description: "Remove expired sessions, verification and password-reset tokens, WebAuthn ceremonies, and rate-limit records.",
		Run: func(ctx context.Context) (string, error) {
			n, err := a.DB.CleanupExpired(ctx)
			return fmt.Sprintf("Deleted %d expired records.", n), err
		},
	}
	m.tasks["router-log-retention"] = maintenanceDefinition{
		Name: "router-log-retention", Title: "Router log retention", Schedule: "Hourly",
		Description: "Delete router flow and operational log records older than 30 days.",
		Run: func(ctx context.Context) (string, error) {
			n, err := a.DB.CleanupRouterLogs(ctx)
			return fmt.Sprintf("Deleted %d expired router log records.", n), err
		},
	}
	m.tasks["sna-circuit-history"] = maintenanceDefinition{
		Name: "sna-circuit-history", Title: "SNA circuit history retention", Schedule: "Hourly",
		Description: "Delete completed SNA circuit summaries older than 90 days.",
		Run: func(ctx context.Context) (string, error) {
			n, err := a.DB.CleanupCircuitHistory(ctx)
			return fmt.Sprintf("Deleted %d expired SNA circuit summaries.", n), err
		},
	}
	return m
}

// StartMaintenance runs the same registered tasks exposed in the admin panel.
// Calling it more than once is harmless only when the caller owns one App.
func (a *App) StartMaintenance(ctx context.Context) {
	a.workersOnce.Do(func() {
		a.workersRunning.Store(true)
		workerCtx, cancel := context.WithCancel(context.Background())
		a.workerCancel = cancel
		schedulerCtx, schedulerCancel := context.WithCancel(ctx)
		a.schedulerCancel = schedulerCancel
		a.startCircuitHistoryWriter(workerCtx)
		a.startRouterLogWriter(workerCtx)
		a.workersWG.Add(1)
		go func() {
			defer a.workersWG.Done()
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-schedulerCtx.Done():
					return
				case <-ticker.C:
					for name := range a.maintenance.tasks {
						runCtx, cancel := context.WithTimeout(schedulerCtx, 10*time.Minute)
						_, _ = a.maintenance.run(runCtx, name, "scheduled", "")
						cancel()
					}
				}
			}
		}()
	})
}

// ShutdownBackground fences producers before waiting for both persistence
// queues and the maintenance scheduler to stop.
func (a *App) ShutdownBackground(ctx context.Context) error {
	if a.schedulerCancel != nil {
		a.schedulerCancel()
	}
	a.routerLogs.close(false)
	a.circuitHistory.close(false)
	done := make(chan struct{})
	go func() { a.workersWG.Wait(); close(done) }()
	select {
	case <-done:
		a.workersRunning.Store(false)
		return nil
	case <-ctx.Done():
		a.routerLogs.close(true)
		a.circuitHistory.close(true)
		if a.workerCancel != nil {
			a.workerCancel()
		}
		return ctx.Err()
	}
}

var errMaintenanceRunning = errors.New("maintenance task is already running")

func (m *maintenanceManager) run(ctx context.Context, name, trigger, actor string) (string, error) {
	def, ok := m.tasks[name]
	if !ok {
		return "", store.ErrNotFound
	}
	m.mu.Lock()
	if m.running[name] {
		m.mu.Unlock()
		return "", errMaintenanceRunning
	}
	m.running[name] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.running, name)
		m.mu.Unlock()
	}()

	started := store.Now()
	claim, err := m.a.DB.Exec(ctx, `INSERT INTO maintenance_runs(task_name,started_at,finished_at,status,trigger_kind,triggered_by,result)
		VALUES(?,?,0,'running',?,?,'')
		ON CONFLICT(task_name) DO UPDATE SET started_at=excluded.started_at,finished_at=0,status='running',trigger_kind=excluded.trigger_kind,triggered_by=excluded.triggered_by,result=''
		WHERE maintenance_runs.status<>'running' OR maintenance_runs.started_at<?`, name, started, trigger, actor, started-3600)
	if err != nil {
		return "", err
	}
	claimed, err := claim.RowsAffected()
	if err != nil {
		return "", err
	}
	if claimed == 0 {
		return "", errMaintenanceRunning
	}
	result, runErr := def.Run(ctx)
	status := "success"
	if runErr != nil {
		status = "failed"
		if result != "" {
			result += " "
		}
		result += runErr.Error()
	}
	// Use a fresh bounded context so cancellation of the task does not leave a
	// permanently displayed running state.
	finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, finishErr := m.a.DB.Exec(finishCtx, "UPDATE maintenance_runs SET finished_at=?,status=?,result=? WHERE task_name=?", store.Now(), status, result, name)
	if runErr != nil {
		return result, runErr
	}
	return result, finishErr
}

func (m *maintenanceManager) list(ctx context.Context) ([]maintenanceRun, error) {
	rows, err := m.a.DB.Query(ctx, "SELECT task_name,started_at,finished_at,status,trigger_kind,triggered_by,result FROM maintenance_runs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byName := make(map[string]maintenanceRun)
	for rows.Next() {
		var run maintenanceRun
		if err = rows.Scan(&run.Name, &run.StartedAt, &run.FinishedAt, &run.Status, &run.Trigger, &run.TriggeredBy, &run.Result); err != nil {
			return nil, err
		}
		if run.Status == "running" && run.StartedAt < store.Now()-3600 {
			run.Status = "failed"
			run.FinishedAt = store.Now()
			run.Result = "The previous run did not complete; its worker may have stopped."
		}
		byName[run.Name] = run
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	result := make([]maintenanceRun, 0, len(m.tasks))
	for name, def := range m.tasks {
		run := byName[name]
		run.Name, run.Title, run.Description, run.Schedule = name, def.Title, def.Description, def.Schedule
		result = append(result, run)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Title < result[j].Title })
	return result, nil
}

type adminRouterSession struct {
	ID, Name, IP, Protocol, Epoch                                               string
	ConnectedAt                                                                 int64
	RouteCount                                                                  int
	RouteRevision                                                               uint64
	OutboundQueued, OutboundLimit, OutboundBytes, OutboundHighWater, DataQueued int
	OutboundDropped                                                             uint64
}

func (h *routerHub) adminRouterSessions() []adminRouterSession {
	routers := make([]adminRouterSession, 0, h.sessionCount())
	for _, c := range h.sessions() {
		c.mu.Lock()
		queue := c.out.stats()
		item := adminRouterSession{ID: c.router.ID, Name: c.router.DisplayName, IP: c.ip, Protocol: c.subprotocol, Epoch: c.epoch, ConnectedAt: c.connectedAt.Unix(), OutboundQueued: queue.Depth, OutboundLimit: queue.Limit, OutboundBytes: queue.Bytes, OutboundHighWater: queue.HighWater, OutboundDropped: queue.Dropped}
		if c.snapshot != nil {
			item.RouteCount = len(c.snapshot.Routes)
			item.RouteRevision = c.snapshot.Revision
		}
		for _, bytes := range c.queued {
			item.DataQueued += bytes
		}
		c.mu.Unlock()
		routers = append(routers, item)
	}
	sort.Slice(routers, func(i, j int) bool {
		if routers[i].Name == routers[j].Name {
			return routers[i].ID < routers[j].ID
		}
		return routers[i].Name < routers[j].Name
	})
	return routers
}

func (a *App) adminOperations(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	tasks, err := a.maintenance.list(r.Context())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		dbError(w, err)
		return
	}
	policyVersion, policyRouters, policyBlocks := uint64(0), 0, 0
	if policy := a.hub.policy.Load(); policy != nil {
		policyVersion, policyRouters, policyBlocks = policy.version, len(policy.routers), len(policy.blocks)
	}
	logs, history := a.routerLogs.stats(), a.circuitHistory.stats()
	a.historyMu.Lock()
	pendingHistory := len(a.historyPending)
	a.historyMu.Unlock()
	a.render(w, "admin_operations", map[string]any{"User": u, "CSRF": s.CSRF, "Tasks": tasks, "PolicyVersion": policyVersion, "PolicyRouters": policyRouters, "PolicyBlocks": policyBlocks, "RouterLogQueue": logs, "HistoryQueue": history, "WriteFailures": a.writeFailures.Load(), "RouterLogStale": a.routerLogStale.Load(), "HistoryPending": pendingHistory, "HistoryArchived": a.historyArchived.Load(), "HistoryPersisted": a.historyPersisted.Load(), "HistoryRetries": a.historyRetries.Load(), "HistoryFailed": a.historyFailed.Load(), "HeartbeatFailures": a.heartbeatFailures.Load(), "LastHeartbeat": a.lastHeartbeat.Load(), "Draining": a.hub.draining.Load()})
}

func (a *App) runMaintenanceTask(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	_, err := a.maintenance.run(ctx, r.PathValue("task"), "manual", u.Email)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, errMaintenanceRunning) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Failures are persisted and displayed on the destination page.
	http.Redirect(w, r, "/admin/operations", http.StatusSeeOther)
}
