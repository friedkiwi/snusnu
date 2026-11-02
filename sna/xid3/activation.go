package xid3

import (
	"bytes"
	"errors"
)

var ErrActivation = errors.New("APPN XID3 activation failed")

// Activation exchanges a locally owned fixed-role XID3 with one adjacent
// station. The caller still owns DLC framing, retries, and SABME/UA.
type Activation struct {
	local              XID
	awaiting           []byte
	peerName           string
	peerID             [4]byte
	seenPeer           bool
	sentProceeding     bool
	receivedProceeding bool
}

func NewActivation(local XID) (*Activation, error) {
	name, err := local.CPName()
	if err != nil || name == "" || local.Validate() != nil || local.State() != Prenegotiation ||
		(local.Role() != Primary && local.Role() != Secondary) || local.Fixed[19]&0x40 == 0 {
		return nil, ErrActivation
	}
	return &Activation{local: clone(local)}, nil
}

func (a *Activation) Ready() bool                 { return a.sentProceeding && a.receivedProceeding }
func (a *Activation) PeerName() string            { return a.peerName }
func (a *Activation) PeerNodeID() ([4]byte, bool) { return a.peerID, a.seenPeer }

// OnNull responds to a null XID. ConfirmSent must follow successful transport
// transmission of the returned bytes.
func (a *Activation) OnNull() ([]byte, error) {
	if a.Ready() {
		return nil, ErrActivation
	}
	out := clone(a.local)
	if a.seenPeer {
		_ = out.SetState(Proceeding)
	}
	return a.prepare(out)
}

// OnPeer validates one complete peer XID and prepares a locally owned reply.
func (a *Activation) OnPeer(data []byte) ([]byte, error) {
	peer, err := Parse(data)
	if err != nil || peer.Fixed[19]&0x40 == 0 || (peer.State() != Prenegotiation && peer.State() != Proceeding) {
		return nil, ErrActivation
	}
	expected := Primary
	if a.local.Role() == Primary {
		expected = Secondary
	}
	if peer.Role() != expected && peer.Role() != Negotiable {
		return nil, ErrActivation
	}
	if a.Ready() && (peer.State() != Proceeding || peer.Role() != expected) {
		return nil, ErrActivation
	}
	name, err := peer.CPName()
	if err != nil && !errors.Is(err, ErrNoCPName) {
		return nil, ErrActivation
	}
	localName, _ := a.local.CPName()
	if name != "" && (name == localName || a.peerName != "" && a.peerName != name) {
		return nil, ErrActivation
	}
	if a.seenPeer && a.peerID != peer.NodeID() {
		return nil, ErrActivation
	}
	if name != "" {
		a.peerName = name
	}
	a.peerID, a.seenPeer = peer.NodeID(), true
	if peer.State() == Proceeding && peer.Role() == expected {
		a.receivedProceeding = true
	}
	out := clone(a.local)
	_ = out.SetState(Proceeding)
	return a.prepare(out)
}

func (a *Activation) prepare(x XID) ([]byte, error) {
	data, err := x.Bytes()
	if err != nil {
		return nil, err
	}
	a.awaiting = append(a.awaiting[:0], data...)
	return append([]byte(nil), data...), nil
}

// ConfirmSent records that the exact prepared XID reached the DLC sender.
func (a *Activation) ConfirmSent(data []byte) error {
	if !bytes.Equal(data, a.awaiting) || len(a.awaiting) == 0 {
		return ErrActivation
	}
	a.awaiting = nil
	if len(data) > 9 && data[9]&0x0c == byte(Proceeding) {
		a.sentProceeding = true
	}
	return nil
}

func clone(x XID) XID {
	y := x
	y.Vectors = make([]Vector, len(x.Vectors))
	for i, v := range x.Vectors {
		y.Vectors[i] = Vector{Key: v.Key, Data: append([]byte(nil), v.Data...)}
	}
	return y
}
