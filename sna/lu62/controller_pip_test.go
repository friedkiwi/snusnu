package lu62

import (
	"bytes"
	"testing"
)

func Test5494ControllerPIPFirmwareLayout(t *testing.T) {
	// The attribute is a synthetic fixture. All other bytes come from VG0F's
	// runtime 0x1BC1..0x1C01 construction path.
	pip := Encode5494ControllerPIP(0x55)
	want := []byte{0, 0x12, 0x12, 0xf5, 0, 0x0e, 0x12, 0xe2,
		3, 0x20, 1, 0x55, 0x38, 4, 4, 0xd4, 7, 0x30}
	if !bytes.Equal(pip, want) {
		t.Fatalf("5494 allocation/PIP: %x", pip)
	}
}
