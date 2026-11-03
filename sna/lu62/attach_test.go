package lu62

import (
	"bytes"
	"errors"
	"testing"
)

func TestFirstAttachSelectsAPINGD(t *testing.T) {
	piu := []byte{0x2e, 0, 2, 2, 0, 1, 0x0a, 0x91, 0}
	ru := []byte{0x2f, 5, 2, 0xff, 0, 3, 0xd1, 0, 0x40, 6, 0xc1, 0xd7, 0xc9, 0xd5, 0xc7, 0xc4}
	for len(ru) < 47 {
		ru = append(ru, 0)
	}
	piu = append(piu, ru...)
	attach, err := ParseFirstAttach(piu)
	if err != nil || attach.TPName != "APINGD" || attach.Sequence != 1 {
		t.Fatalf("attach: %+v, %v", attach, err)
	}
	piu[9+9] = 65
	if _, err := ParseFirstAttach(piu); !errors.Is(err, ErrAttach) {
		t.Fatalf("bad name length: %v", err)
	}
}

func TestFirstArchitectureAttachKeepsBinaryTPN(t *testing.T) {
	piu := []byte{0x2e, 0, 2, 2, 0, 1, 0x0a, 0x91, 0,
		14, 5, 2, 0xff, 0, 3, 0xd1, 0, 0x40, 4, 0x30, 0xf0, 0xf6, 0xf6}
	got, err := ParseFirstArchitectureAttach(piu)
	if err != nil || got == nil || got.TPN != [4]byte{0x30, 0xf0, 0xf6, 0xf6} ||
		got.DAF != 2 || got.OAF != 2 || got.Sequence != 1 ||
		!bytes.Equal(got.Raw, piu[9:]) {
		t.Fatalf("architecture Attach: %+v %v", got, err)
	}
	if named, err := ParseFirstAttach(piu); !errors.Is(err, ErrAttach) || named != nil {
		t.Fatalf("binary TPN parsed as EBCDIC name: %+v %v", named, err)
	}
	basic := append([]byte(nil), piu...)
	basic[15] = 0xd0
	if parsed, err := ParseFirstArchitectureAttach(basic); err != nil || parsed == nil || parsed.TPN != got.TPN {
		t.Fatalf("basic conversation Attach: %+v %v", parsed, err)
	}
	// This FMH-5 body occurs in the 5494 R3.2 VG10 firmware. It is an
	// architecture TP template with PIP indicated, not the QND5MAIN TPN.
	firmware := append([]byte{0x2e, 0, 2, 2, 0, 1, 0x0a, 0x91, 0},
		[]byte{0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4, 0x30, 0xf0, 0xf5, 0xf1, 0, 0, 0}...)
	if parsed, err := ParseFirstArchitectureAttach(firmware); err != nil || parsed == nil ||
		!parsed.PIPPresent || parsed.TPN != [4]byte{0x30, 0xf0, 0xf5, 0xf1} {
		t.Fatalf("firmware architecture Attach: %+v %v", parsed, err)
	}
	bad := append([]byte(nil), piu...)
	bad[18] = 5
	if _, err := ParseFirstArchitectureAttach(bad); !errors.Is(err, ErrAttach) {
		t.Fatalf("invalid TPN length accepted: %v", err)
	}
}
