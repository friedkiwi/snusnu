package lu62

import (
	"bytes"
	"testing"
)

func Test5494ControllerAttachPrefixAndAllocation(t *testing.T) {
	// The allocation bytes are a synthetic framing fixture. Only the fixed
	// FMH-5 prefix is established by the Release 3.2 sender image.
	allocation := []byte{0, 4, 0x12, 0x34}
	ru, err := Encode5494ControllerAttachRU(allocation)
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
	if _, err := Encode5494ControllerAttachRU(allocation); err == nil {
		t.Fatal("allocation length mismatch accepted")
	}
}
