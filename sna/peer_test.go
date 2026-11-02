package sna

import "testing"

func TestPeerValidatesStampedSNAIdentity(t *testing.T) {
	p := Peer{Principal: "owner", NetID: "SOLNET", CP: "SNAA", LU: "LU1"}
	if !p.Valid() {
		t.Fatal("valid peer rejected")
	}
	for _, malformed := range []Peer{
		{NetID: p.NetID, CP: p.CP, LU: p.LU},
		{Principal: p.Principal, NetID: "9OLNET", CP: p.CP, LU: p.LU},
		{Principal: p.Principal, NetID: p.NetID, CP: "LOWERcase", LU: p.LU},
		{Principal: p.Principal, NetID: p.NetID, CP: p.CP, LU: "LONGNAME9"},
	} {
		if malformed.Valid() {
			t.Fatalf("malformed peer accepted: %+v", malformed)
		}
	}
}
