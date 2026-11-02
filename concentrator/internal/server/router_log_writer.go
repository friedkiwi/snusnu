package server

import (
	"context"
	"log"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func (a *App) enqueueRouterLog(entry store.LogEntry) {
	a.queueMu.RLock()
	defer a.queueMu.RUnlock()
	if !a.queuesOpen {
		a.routerLogDrops.Add(1)
		return
	}
	select {
	case a.routerLogs <- entry:
	default:
		a.routerLogDrops.Add(1)
		log.Printf("router log queue full; dropping %s event for router %s", entry.EventType, entry.RouterID)
	}
}

func (a *App) startRouterLogWriter(ctx context.Context) {
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
					case entry := <-a.routerLogs:
						a.persistRouterLog(entry)
					default:
						return
					}
				}
			case entry := <-a.routerLogs:
				a.persistRouterLog(entry)
			}
		}
	}()
}

func (a *App) persistRouterLog(entry store.LogEntry) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = a.DB.AppendRouterLog(writeCtx, entry)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
	}
	a.writeFailures.Add(1)
	log.Printf("persist router log for %s after retries: %v", entry.RouterID, err)
}
