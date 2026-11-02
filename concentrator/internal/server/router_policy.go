package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
)

type liveRouterPolicy struct {
	ownerID, netID, displayName, epoch string
	paused, llcFacing                  bool
	credentials                        map[string]struct{}
}

type routerPolicySnapshot struct {
	version uint64
	routers map[string]liveRouterPolicy
	blocks  map[string]struct{}
	managed []liveManagedAddress
}

type liveManagedAddress struct {
	id, ownerID, netID, cpName string
	suffix                     int64
}

func ownerPair(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}

func (p *routerPolicySnapshot) allows(sourceID, targetID string) bool {
	if p == nil || sourceID == targetID {
		return false
	}
	source, sourceOK := p.routers[sourceID]
	target, targetOK := p.routers[targetID]
	if !sourceOK || !targetOK || source.paused || target.paused {
		return false
	}
	_, blocked := p.blocks[ownerPair(source.ownerID, target.ownerID)]
	return !blocked
}

func (h *routerHub) loadPolicy(ctx context.Context) (bool, error) {
	h.policyMu.Lock()
	defer h.policyMu.Unlock()
	previous := h.policy.Load()
	next := &routerPolicySnapshot{routers: make(map[string]liveRouterPolicy), blocks: make(map[string]struct{})}
	if previous != nil {
		next.version = previous.version + 1
	} else {
		next.version = 1
	}
	tx, err := h.a.DB.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, h.a.DB.Q(`SELECT r.id,r.owner_id,r.display_name,r.paused,r.llc_facing,u.netid,COALESCE(e.epoch,'')
		FROM routers r JOIN users u ON u.id=r.owner_id LEFT JOIN router_epochs e ON e.router_id=r.id`))
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var id string
		var value liveRouterPolicy
		var paused, llcFacing int
		if err = rows.Scan(&id, &value.ownerID, &value.displayName, &paused, &llcFacing, &value.netID, &value.epoch); err != nil {
			rows.Close()
			return false, err
		}
		value.paused, value.llcFacing = paused != 0, llcFacing != 0
		value.credentials = make(map[string]struct{})
		next.routers[id] = value
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, h.a.DB.Q("SELECT router_id,secret_hash FROM router_credentials WHERE revoked_at=0 AND (expires_at=0 OR expires_at>?)"), store.Now())
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var routerID, hash string
		if err = rows.Scan(&routerID, &hash); err != nil {
			rows.Close()
			return false, err
		}
		value, ok := next.routers[routerID]
		if ok {
			value.credentials[hash] = struct{}{}
			next.routers[routerID] = value
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, "SELECT owner_id,blocked_user_id FROM user_blocks")
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var a, b string
		if err = rows.Scan(&a, &b); err != nil {
			rows.Close()
			return false, err
		}
		next.blocks[ownerPair(a, b)] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, "SELECT id,owner_id,netid,cp_name,mac_suffix FROM managed_cp_addresses WHERE enabled=1 AND retired_at=0 ORDER BY id")
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var value liveManagedAddress
		if err = rows.Scan(&value.id, &value.ownerID, &value.netID, &value.cpName, &value.suffix); err != nil {
			rows.Close()
			return false, err
		}
		next.managed = append(next.managed, value)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	if err = tx.Commit(); err != nil {
		return false, err
	}
	if policySnapshotsEqual(previous, next) {
		return false, nil
	}
	h.policy.Store(next)
	return true, nil
}

func policySnapshotsEqual(a, b *routerPolicySnapshot) bool {
	if a == nil || b == nil || len(a.routers) != len(b.routers) || len(a.blocks) != len(b.blocks) || len(a.managed) != len(b.managed) {
		return false
	}
	for id, left := range a.routers {
		right, ok := b.routers[id]
		if !ok || left.ownerID != right.ownerID || left.netID != right.netID || left.displayName != right.displayName || left.epoch != right.epoch || left.paused != right.paused || left.llcFacing != right.llcFacing || len(left.credentials) != len(right.credentials) {
			return false
		}
		for hash := range left.credentials {
			if _, ok := right.credentials[hash]; !ok {
				return false
			}
		}
	}
	for pair := range a.blocks {
		if _, ok := b.blocks[pair]; !ok {
			return false
		}
	}
	for i := range a.managed {
		if a.managed[i] != b.managed[i] {
			return false
		}
	}
	return true
}

func (h *routerHub) current(c *routerSession) bool {
	policy := h.policy.Load()
	if policy == nil || c.closed.Load() {
		return false
	}
	if _, denied := h.revokedRouters.Load(c.router.ID); denied {
		return false
	}
	c.mu.Lock()
	routerID, ownerID, displayName, wasLLCFacing := c.router.ID, c.router.OwnerID, c.router.DisplayName, c.router.LLCFacing
	c.mu.Unlock()
	value, ok := policy.routers[routerID]
	if !ok || value.paused || value.ownerID != ownerID || value.netID != c.allowedNetID || value.epoch != c.epoch {
		return false
	}
	if _, ok = value.credentials[store.Hash(c.token)]; !ok {
		return false
	}
	if wasLLCFacing && !value.llcFacing {
		return false
	}
	if value.displayName != displayName {
		c.mu.Lock()
		c.router.DisplayName = value.displayName
		c.mu.Unlock()
		h.send(c, &wire.WsEnvelope{Body: &wire.WsEnvelope_IdentityUpdate{IdentityUpdate: &wire.RouterIdentityUpdate{DisplayName: value.displayName}}}, "", 0)
	}
	c.mu.Lock()
	c.router.LLCFacing = value.llcFacing
	c.mu.Unlock()
	return true
}

func (h *routerHub) allowed(source, target *routerSession) bool {
	if source == nil || target == nil || !h.isCurrent(source) || !h.isCurrent(target) {
		return false
	}
	if _, denied := h.revokedRouters.Load(source.router.ID); denied {
		return false
	}
	if _, denied := h.revokedRouters.Load(target.router.ID); denied {
		return false
	}
	if _, denied := h.blockDenials.Load(ownerPair(source.router.OwnerID, target.router.OwnerID)); denied {
		return false
	}
	return h.policy.Load().allows(source.router.ID, target.router.ID)
}

func (h *routerHub) clearRevocations() {
	h.revokedRouters.Range(func(key, _ any) bool {
		h.revokedRouters.Delete(key)
		return true
	})
}

// Revoke a live router before the database change, then keep the denial until
// a policy snapshot that includes the committed change has been loaded.
func (a *App) revokeRouter(id string, mutate func() error) error {
	return a.revokeRouters(func() []string { return []string{id} }, mutate)
}

func (a *App) revokeOwnerRouters(ownerID string, mutate func() error) error {
	return a.revokeRouters(func() []string {
		var ids []string
		for _, session := range a.hub.sessions() {
			if session.router.OwnerID == ownerID {
				ids = append(ids, session.router.ID)
			}
		}
		return ids
	}, mutate)
}

func (a *App) revokeRouters(selectIDs func() []string, mutate func() error) error {
	h := a.hub
	h.revocationMu.Lock()
	ids := selectIDs()
	priorDenials := make(map[string]bool, len(ids))
	for _, id := range ids {
		_, priorDenials[id] = h.revokedRouters.Load(id)
		h.revokedRouters.Store(id, struct{}{})
	}
	if err := mutate(); err != nil {
		for _, id := range ids {
			if !priorDenials[id] {
				h.revokedRouters.Delete(id)
			}
		}
		h.revocationMu.Unlock()
		return err
	}
	for _, id := range ids {
		if session := h.session(id); session != nil && session.conn != nil {
			_ = session.conn.Close()
		}
	}
	refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := h.loadPolicy(refreshCtx)
	cancel()
	if err == nil {
		for _, id := range ids {
			h.revokedRouters.Delete(id)
		}
	}
	h.revocationMu.Unlock()
	if err != nil {
		log.Printf("refresh router policy after revocation: %v", err)
		return nil
	}
	h.refresh()
	return nil
}

// setBlock installs a fast denial before the database transaction. A failed
// transaction removes it; a successful one retains it until policy is loaded.
func (a *App) setBlock(ctx context.Context, ownerID, targetID string, blocked bool) error {
	h := a.hub
	h.blockMu.Lock()
	defer h.blockMu.Unlock()
	pair := ownerPair(ownerID, targetID)
	_, priorDenial := h.blockDenials.Load(pair)
	if blocked {
		h.blockDenials.Store(pair, struct{}{})
	}
	if err := a.DB.SetBlock(ctx, ownerID, targetID, blocked); err != nil {
		if blocked && !priorDenial {
			h.blockDenials.Delete(pair)
		}
		return err
	}
	if _, err := h.loadPolicy(ctx); err != nil {
		// A denial stays active until a later successful policy refresh.
		return err
	}
	h.blockDenials.Delete(pair)
	h.reconcileOwnerPair(ownerID, targetID)
	return nil
}

func (h *routerHub) refreshPolicyAndRoutes(ctx context.Context) error {
	changed, err := h.loadPolicy(ctx)
	if err != nil {
		return fmt.Errorf("load router policy: %w", err)
	}
	if changed {
		h.refresh()
	}
	return nil
}

func (a *App) routerPolicyChanged(ctx context.Context) {
	if err := a.hub.refreshPolicyAndRoutes(ctx); err != nil {
		log.Printf("refresh router policy: %v", err)
	}
}

// InitializeRouterPolicy loads the first immutable control-plane snapshot
// before the process can report ready.
func (a *App) InitializeRouterPolicy(ctx context.Context) error {
	_, err := a.hub.loadPolicy(ctx)
	return err
}
