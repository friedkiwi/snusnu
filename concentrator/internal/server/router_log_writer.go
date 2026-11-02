package server

import (
	"context"
	"log"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func (a *App) enqueueRouterLog(entry store.LogEntry) {
	if !a.routerLogs.push(entry) {
		log.Printf("router log queue full; dropping %s event for router %s", entry.EventType, entry.RouterID)
	}
}

func (a *App) startRouterLogWriter(ctx context.Context) {
	a.workersWG.Add(1)
	go func() {
		defer a.workersWG.Done()
		for {
			entry, ok := a.routerLogs.pop(ctx.Done())
			if !ok {
				return
			}
			a.persistRouterLog(entry)
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
