package xid3

import "testing"

func TestFixedRoleActivation(t *testing.T) {
	local, err := NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x45}, 1, Secondary)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewActivation(local)
	if err != nil {
		t.Fatal(err)
	}
	nullReply, err := a.OnNull()
	if err != nil || a.ConfirmSent(nullReply) != nil || a.Ready() {
		t.Fatalf("null exchange: %v", err)
	}
	peer, err := NewLocal("SOLNET.SNAA", "SNAA", [4]byte{0xff, 0xf2, 0x34, 0x56}, 1, Primary)
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.SetRole(Negotiable)
	first, _ := peer.Bytes()
	reply, err := a.OnPeer(first)
	if err != nil || a.ConfirmSent(reply) != nil || a.Ready() {
		t.Fatalf("prenegotiation: %v", err)
	}
	_ = peer.SetRole(Primary)
	_ = peer.SetState(Proceeding)
	second, _ := peer.Bytes()
	reply, err = a.OnPeer(second)
	if err != nil || a.ConfirmSent(reply) != nil || !a.Ready() || a.PeerName() != "SOLNET.SNAA" {
		t.Fatalf("proceeding: %v", err)
	}
	if _, err := a.OnNull(); err == nil {
		t.Fatal("accepted null XID after activation")
	}
}
