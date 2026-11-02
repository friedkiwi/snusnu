package xid3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestSanitizedV4R4ProceedingXID(t *testing.T) {
	data, _ := hex.DecodeString("322ffff12345000000b4c0000000008001010b500005d80000000007000e0cf4e2d6d3d5c5e34be2d5c1c210021101")
	x, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	name, err := x.CPName()
	if err != nil || name != "SOLNET.SNAB" || x.Role() != Primary || x.State() != Proceeding {
		t.Fatalf("captured shape: %+v %q %v", x, name, err)
	}
	out, err := x.Bytes()
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("round trip: %x %v", out, err)
	}
}

func TestLocalProfileRoundTrip(t *testing.T) {
	x, err := NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x45}, 1, Secondary)
	if err != nil {
		t.Fatal(err)
	}
	data, err := x.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	name, err := parsed.CPName()
	if err != nil || name != "SNUSNU.SVC" || parsed.NodeID() != [4]byte{0xff, 0xf1, 0x23, 0x45} || parsed.Role() != Secondary || parsed.State() != Prenegotiation {
		t.Fatalf("parsed local XID: %+v %s %v", parsed, name, err)
	}
	parsed.SetState(Proceeding)
	proceeding, err := parsed.Bytes()
	if err != nil || bytes.Equal(proceeding, data) {
		t.Fatalf("state change: %x, %v", proceeding, err)
	}
	data[1]--
	if _, err := Parse(data); !errors.Is(err, ErrXID) {
		t.Fatalf("length gate: %v", err)
	}
}

func TestRejectPeerIdentityAsLocal(t *testing.T) {
	if _, err := NewLocal("SNUSNU.SVC", "SVC", [4]byte{5, 0x63, 0x39, 0x50}, 1, Primary); !errors.Is(err, ErrXID) {
		t.Fatalf("IBM product node ID: %v", err)
	}
	if _, err := NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf0, 0, 0}, 1, Primary); !errors.Is(err, ErrXID) {
		t.Fatalf("zero role value: %v", err)
	}
	if _, err := NewLocal("SNUSNU.SVC", "SVC", [4]byte{0xff, 0xf1, 0x23, 0x45}, 1, Negotiable); !errors.Is(err, ErrXID) {
		t.Fatalf("unsupported role: %v", err)
	}
}
