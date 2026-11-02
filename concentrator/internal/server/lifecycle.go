package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
)

func (a *App) StartInstanceHeartbeat(ctx context.Context, instanceID string) {
	a.leaseHealthy.Store(true)
	a.lastHeartbeat.Store(time.Now().Unix())
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastSuccess := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hbCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				err := a.DB.HeartbeatInstance(hbCtx, instanceID)
				cancel()
				if err == nil {
					lastSuccess = time.Now()
					a.lastHeartbeat.Store(lastSuccess.Unix())
					a.leaseHealthy.Store(true)
					continue
				}
				a.heartbeatFailures.Add(1)
				a.leaseHealthy.Store(false)
				log.Printf("instance heartbeat failed; retrying: %v", err)
				if errors.Is(err, store.ErrInstanceActive) || time.Since(lastSuccess) >= 20*time.Second {
					a.hub.draining.Store(true)
					select {
					case a.fatal <- fmt.Errorf("instance lease lost: %w", err):
					default:
					}
					return
				}
			}
		}
	}()
}

func (a *App) Fatal() <-chan error { return a.fatal }

func (a *App) liveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "ok\n")
}

func (a *App) readiness(w http.ResponseWriter, r *http.Request) {
	ready := !a.hub.draining.Load() && a.workersRunning.Load() && a.leaseHealthy.Load() && a.hub.policy.Load() != nil
	if ready {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		ready = a.DB.DB.PingContext(ctx) == nil
		cancel()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "not ready\n")
		return
	}
	fmt.Fprint(w, "ready\n")
}

func (a *App) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	policyVersion := uint64(0)
	if p := a.hub.policy.Load(); p != nil {
		policyVersion = p.version
	}
	draining := 0
	if a.hub.draining.Load() {
		draining = 1
	}
	logs, history := a.routerLogs.stats(), a.circuitHistory.stats()
	fmt.Fprintf(w, "# TYPE snusnu_connected_routers gauge\nsnusnu_connected_routers %d\n# TYPE snusnu_active_circuits gauge\nsnusnu_active_circuits %d\n", a.hub.sessionCount(), a.hub.activeCircuitCount())
	fmt.Fprintf(w, "snusnu_queue_depth{queue=\"router_logs\"} %d\nsnusnu_queue_depth{queue=\"circuit_history\"} %d\nsnusnu_queue_high_water{queue=\"router_logs\"} %d\nsnusnu_queue_high_water{queue=\"circuit_history\"} %d\nsnusnu_queue_limit{queue=\"router_logs\"} %d\nsnusnu_queue_limit{queue=\"circuit_history\"} %d\nsnusnu_queue_dropped_total{queue=\"router_logs\"} %d\nsnusnu_queue_dropped_total{queue=\"circuit_history\"} %d\n", logs.Depth, history.Depth, logs.HighWater, history.HighWater, logs.Limit, history.Limit, logs.Dropped, history.Dropped)
	fmt.Fprintf(w, "snusnu_queue_bytes{queue=\"router_logs\"} %d\nsnusnu_queue_bytes_limit{queue=\"router_logs\"} %d\nsnusnu_async_write_failures_total %d\nsnusnu_instance_heartbeat_failures_total %d\nsnusnu_instance_last_heartbeat_seconds %d\nsnusnu_policy_version %d\nsnusnu_route_reconciliations_total %d\nsnusnu_draining %d\n", logs.Bytes, logs.ByteLimit, a.writeFailures.Load(), a.heartbeatFailures.Load(), a.lastHeartbeat.Load(), policyVersion, a.hub.reconciliations.Load(), draining)
	for _, session := range a.hub.sessions() {
		stats := session.out.stats()
		fmt.Fprintf(w, "snusnu_router_outbound_queue_depth{router_id=\"%s\"} %d\nsnusnu_router_outbound_queue_bytes{router_id=\"%s\"} %d\nsnusnu_router_outbound_queue_high_water{router_id=\"%s\"} %d\nsnusnu_router_outbound_queue_dropped_total{router_id=\"%s\"} %d\n", session.router.ID, stats.Depth, session.router.ID, stats.Bytes, session.router.ID, stats.HighWater, session.router.ID, stats.Dropped)
	}
}

func (a *App) metricsAuthenticated(w http.ResponseWriter, r *http.Request) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || parts[0] != "Bearer" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="snusnu-metrics"`)
		http.Error(w, "metrics bearer key required", http.StatusUnauthorized)
		return
	}
	want, got := sha256.Sum256([]byte(a.Config.MetricsKey)), sha256.Sum256([]byte(parts[1]))
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="snusnu-metrics"`)
		http.Error(w, "invalid metrics bearer key", http.StatusUnauthorized)
		return
	}
	a.metrics(w, r)
}

func (h *routerHub) activeCircuitCount() int {
	n := 0
	h.circuits.Range(func(_, _ any) bool { n++; return true })
	return n
}

// BeginDrain rejects new sessions and circuits, gives active circuits their
// grace period, then closes every WebSocket so hijacked connections cannot
// outlive HTTP shutdown.
func (a *App) BeginDrain(ctx context.Context) bool {
	a.hub.lifecycleMu.Lock()
	a.hub.draining.Store(true)
	a.hub.lifecycleMu.Unlock()
	grace := 7 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if available := time.Until(deadline) - 3*time.Second; available < grace {
			grace = available
		}
	}
	if grace < 0 {
		grace = 0
	}
	graceTimer := time.NewTimer(grace)
	defer graceTimer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for a.hub.activeCircuitCount() != 0 {
		select {
		case <-ctx.Done():
			goto force
		case <-graceTimer.C:
			goto force
		case <-ticker.C:
		}
	}
force:
	a.hub.circuits.Range(func(key, _ any) bool {
		a.hub.resetCircuitBy(key.(string), wire.ResetReason_RESET_REASON_LOCAL_LINK, "system", "", "concentrator shutdown")
		return true
	})
	a.hub.clients.Range(func(_, value any) bool { _ = value.(*routerSession).conn.Close(); return true })
	done := make(chan struct{})
	go func() { a.hub.sessionWG.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}
