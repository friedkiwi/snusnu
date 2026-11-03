package lu62

import (
	"bytes"
	"testing"
)

func Test5494ControllerAttachCandidateAndAllocation(t *testing.T) {
	// The PIP attribute and unchanged DIA work-area bytes are candidate
	// fixtures; the TPN overwrite and length-prefixed append are firmware facts.
	allocation := Encode5494ControllerPIP(0x55)
	ru, err := Candidate5494ControllerAttachRU(allocation)
	wantPrefix := []byte{0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4,
		0x30, 0xf0, 0xf6, 0xf6, 0, 0, 0}
	if err != nil || !bytes.Equal(ru[:17], wantPrefix) || !bytes.Equal(ru[17:], allocation) {
		t.Fatalf("controller Attach: %x %v", ru, err)
	}
	piu := append([]byte{0x2e, 0, 1, 2, 0, 1, 0x0a, 0x91, 0}, ru...)
	parsed, err := ParseFirstArchitectureAttach(piu)
	if err != nil || parsed == nil || parsed.TPN != [4]byte{0x30, 0xf0, 0xf6, 0xf6} ||
		!parsed.PIPPresent || !bytes.Equal(parsed.Raw, ru) {
		t.Fatalf("controller Attach roundtrip: %+v %v", parsed, err)
	}
	allocation[1] = 5
	if _, err := Candidate5494ControllerAttachRU(allocation); err == nil {
		t.Fatal("allocation length mismatch accepted")
	}
}
