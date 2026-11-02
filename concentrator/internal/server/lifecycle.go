package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func (a *App) StartInstanceHeartbeat(ctx context.Context, instanceID string) {
	a.leaseHealthy.Store(true)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hbCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				err := a.DB.HeartbeatInstance(hbCtx, instanceID)
				cancel()
				if err != nil {
					a.leaseHealthy.Store(false)
					a.hub.draining.Store(true)
					return
				}
			}
		}
	}()
}

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
	fmt.Fprintf(w, "snusnu_connected_routers %d\nsnusnu_active_circuits %d\nsnusnu_router_log_queue %d\nsnusnu_circuit_history_queue %d\nsnusnu_router_log_dropped_total %d\nsnusnu_circuit_history_dropped_total %d\nsnusnu_async_write_failures_total %d\nsnusnu_policy_version %d\nsnusnu_route_reconciliations_total %d\nsnusnu_draining %d\n", a.hub.sessionCount(), a.hub.activeCircuitCount(), len(a.routerLogs), len(a.circuitHistory), a.routerLogDrops.Load(), a.historyDrops.Load(), a.writeFailures.Load(), policyVersion, a.hub.reconciliations.Load(), draining)
}

func (h *routerHub) activeCircuitCount() int {
	n := 0
	h.circuits.Range(func(_, _ any) bool { n++; return true })
	return n
}

// BeginDrain rejects new sessions and circuits, gives active circuits their
// grace period, then closes every WebSocket so hijacked connections cannot
// outlive HTTP shutdown.
func (a *App) BeginDrain(ctx context.Context) {
	a.hub.draining.Store(true)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for a.hub.activeCircuitCount() != 0 {
		select {
		case <-ctx.Done():
			goto closeConnections
		case <-ticker.C:
		}
	}
closeConnections:
	a.hub.clients.Range(func(_, value any) bool { _ = value.(*routerSession).conn.Close(); return true })
}
