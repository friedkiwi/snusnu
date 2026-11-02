package server

import (
	"context"
	"errors"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
	"github.com/friedkiwi/snusnu/sna"
	"github.com/google/uuid"
)

const serviceRouterID = "00000000-0000-4000-8000-000000000001"
const serviceOwnerID = "concentrator"
const serviceMACSuffix = 0xffffff

// LocalPeer is stamped from the authenticated router session and its live LU
// advertisement. Services can use OwnerID to keep per-user data isolated.
type LocalPeer struct {
	RouterID, OwnerID, NetID, CP, LU string
}

func (p LocalPeer) SNAPeer() sna.Peer {
	return sna.Peer{Principal: p.OwnerID, NetID: p.NetID, CP: p.CP, LU: p.LU}
}

type localDelivery struct {
	Envelope *wire.WsEnvelope
	Peer     LocalPeer
}

// registerLocalService installs a server-owned route origin after its handler
// is ready. It must be called before accepting router WebSocket connections,
// and ctx must remain live for the entire router-hub lifetime.
// The callback receives the same server-stamped envelopes as a remote router.
func (h *routerHub) registerLocalService(ctx context.Context, handle func(*wire.WsEnvelope, LocalPeer)) error {
	if h.local != nil || handle == nil || ctx == nil {
		return errors.New("local service already registered or handler absent")
	}
	epoch := uuid.NewString()
	name := func(value string) *wire.SnaName { return &wire.SnaName{Netid: "SNUSNU", Name: value} }
	local := &routerSession{
		local:      true,
		localInbox: make(chan localDelivery, 256),
		router:     store.Router{ID: serviceRouterID, OwnerID: serviceOwnerID, DisplayName: "SNUSNU services"},
		epoch:      epoch, allowedNetID: "SNUSNU", subprotocol: "snusnu.v2",
		queued: make(map[string]int), connectedAt: time.Now(),
		snapshot: &wire.RouteSnapshot{Epoch: uuidBytes(epoch), Revision: 1, Routes: []*wire.RouteExport{
			{Id: 1, Generation: 1, Resource: &wire.RouteExport_ControlPoint{ControlPoint: name("SVC")}},
			{Id: 2, Generation: 1, Resource: &wire.RouteExport_LogicalUnit{LogicalUnit: &wire.LuReachability{Lu: name("PING"), HostingCp: name("SVC"), SupportedTypes: []wire.LuType{wire.LuType_LU_TYPE_6_2}}}},
		}},
	}
	h.local = local
	go func() {
		for {
			select {
			case delivery := <-local.localInbox:
				handle(delivery.Envelope, delivery.Peer)
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}
