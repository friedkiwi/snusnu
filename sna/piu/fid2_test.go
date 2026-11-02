package piu

import (
	"bytes"
	"errors"
	"testing"
)

func TestFID2RoundTripAndBoundaries(t *testing.T) {
	in := []byte{0x2d, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x31, 0}
	p, err := ParseFID2(in)
	if err != nil {
		t.Fatal(err)
	}
	in[9] = 0xff
	out, err := p.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0x2d, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x31, 0}) {
		t.Fatalf("round trip: %x", out)
	}
	if _, err := ParseFID2(out[:8]); !errors.Is(err, ErrShort) {
		t.Fatalf("short: %v", err)
	}
	out[0] = 0x0d
	if _, err := ParseFID2(out); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("format: %v", err)
	}
}
