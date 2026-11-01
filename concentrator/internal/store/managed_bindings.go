package store

import (
	"context"
	"errors"
)

var ErrBindingRecipient = errors.New("router is not an active LLC-facing binding recipient")

type ManagedRouteReference struct {
	RouterID, Epoch     string
	RouteID, Generation int64
}
type ManagedBinding struct {
	AddressID, OwnerID, NetID, CPName string
	MAC                               [6]byte
	Candidates                        []ManagedRouteReference
}
type ManagedBindingSnapshot struct {
	SchemaVersion  uint32
	RecipientEpoch string
	Revision       uint64
	Bindings       []ManagedBinding
}

// BuildManagedBindingSnapshot is the server-stamped downstream projection for
// one authenticated LLC-facing recipient. The future WebSocket publisher
// serializes it as ManagedCpBindingSnapshot and owns revision sequencing.
func (s *Store) BuildManagedBindingSnapshot(ctx context.Context, recipientID, recipientEpoch string, revision uint64) (ManagedBindingSnapshot, error) {
	result := ManagedBindingSnapshot{SchemaVersion: 1, RecipientEpoch: recipientEpoch, Revision: revision}
	if revision == 0 {
		return result, errors.New("binding revision must be nonzero")
	}
	recipient, err := s.RouterByID(ctx, recipientID)
	if err != nil {
		return result, err
	}
	if recipient.Paused || !recipient.Connected || !recipient.LLCFacing {
		return result, ErrBindingRecipient
	}
	var currentEpoch string
	if err = s.Row(ctx, "SELECT epoch FROM router_epochs WHERE router_id=?", recipientID).Scan(&currentEpoch); err != nil {
		return result, err
	}
	if currentEpoch != recipientEpoch {
		return result, ErrStaleEpoch
	}
	type candidate struct {
		addressID, ownerID, netid, cpName, originID, epoch string
		suffix, routeID, generation                        int64
	}
	rows, err := s.Query(ctx, `SELECT m.id,m.owner_id,m.netid,m.cp_name,m.mac_suffix,o.id,e.epoch,e.route_id,e.generation
		FROM managed_cp_addresses m
		JOIN routers o ON o.owner_id=m.owner_id AND o.paused=0
		JOIN router_advertisements e ON e.router_id=o.id AND e.kind='CP' AND e.netid=m.netid AND e.name=m.cp_name
		JOIN router_epochs ep ON ep.router_id=o.id AND ep.epoch=e.epoch
		WHERE m.enabled=1 AND m.retired_at=0 AND o.id<>?
		ORDER BY m.id,o.id,e.route_id`, recipientID)
	if err != nil {
		return result, err
	}
	var candidates []candidate
	for rows.Next() {
		var x candidate
		if err = rows.Scan(&x.addressID, &x.ownerID, &x.netid, &x.cpName, &x.suffix, &x.originID, &x.epoch, &x.routeID, &x.generation); err != nil {
			rows.Close()
			return result, err
		}
		candidates = append(candidates, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	index := map[string]int{}
	for _, x := range candidates {
		allowed, err := s.CanForward(ctx, recipientID, x.originID)
		if err != nil {
			return result, err
		}
		if !allowed {
			continue
		}
		i, ok := index[x.addressID]
		if !ok {
			i = len(result.Bindings)
			index[x.addressID] = i
			cp := ManagedCP{Suffix: x.suffix}
			result.Bindings = append(result.Bindings, ManagedBinding{AddressID: x.addressID, OwnerID: x.ownerID, NetID: x.netid, CPName: x.cpName, MAC: cp.MACBytes()})
		}
		result.Bindings[i].Candidates = append(result.Bindings[i].Candidates, ManagedRouteReference{RouterID: x.originID, Epoch: x.epoch, RouteID: x.routeID, Generation: x.generation})
	}
	return result, nil
}
