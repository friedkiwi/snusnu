package printer

import (
	"bytes"
	"testing"
)

func TestChainAssemblerReassemblesCaptured5494FragmentShape(t *testing.T) {
	a, err := NewChainAssembler(1024)
	if err != nil {
		t.Fatal(err)
	}
	// The V5R4 station-56 WSF was 04 F3 followed by a 0x0318-byte field.
	// Its three D824 records carried 50, 503, and 241 RU bytes.
	want := append([]byte{0x04, 0xf3, 0x03, 0x18}, bytes.Repeat([]byte{0x40}, 790)...)
	parts := [][]byte{want[:50], want[50:553], want[553:]}
	flags := [][3]byte{{0x02, 0x90, 0}, {0x00, 0x90, 0}, {0x01, 0x90, 0x20}}
	for i, part := range parts {
		wire, err := EncodeControllerDeviceGDS(LU4PIU{Address: 56, Session: LU4PrintSession, RH: flags[i], RU: part})
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseControllerDeviceGDS(wire)
		if err != nil {
			t.Fatal(err)
		}
		got, done, err := a.Feed(p)
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 && (done || got != nil || !a.Active()) {
			t.Fatalf("fragment %d completed early", i)
		}
		if i == 2 && (!done || !bytes.Equal(got, want) || a.Active()) {
			t.Fatal("complete structured field was not reassembled")
		}
	}
}

func TestChainAssemblerRejectsIdentityChangeAndOversize(t *testing.T) {
	a, err := NewChainAssembler(5)
	if err != nil {
		t.Fatal(err)
	}
	first := LU4PIU{Address: 1, Session: LU4PrintSession, RH: [3]byte{2, 0x90, 0}, RU: []byte{1, 2, 3}}
	if _, done, err := a.Feed(first); err != nil || done {
		t.Fatal("first fragment rejected")
	}
	changed := LU4PIU{Address: 2, Session: LU4PrintSession, RH: [3]byte{1, 0x90, 0}, RU: []byte{4}}
	if _, _, err := a.Feed(changed); err != ErrChain || a.Active() {
		t.Fatal("identity change did not discard the partial chain")
	}
	if _, done, err := a.Feed(first); err != nil || done {
		t.Fatal("fresh first fragment rejected")
	}
	last := LU4PIU{Address: 1, Session: LU4PrintSession, RH: [3]byte{1, 0x90, 0}, RU: []byte{4, 5, 6}}
	if _, _, err := a.Feed(last); err != ErrChain || a.Active() {
		t.Fatal("oversized chain was accepted")
	}
}
