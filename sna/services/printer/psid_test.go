package printer

import (
	"bytes"
	"testing"
)

func TestReplyPSIDAddress01FirmwareLayout(t *testing.T) {
	// The address/status header is firmware-derived. VPD and SNA address
	// values here are synthetic fixtures, not a captured 3812 printer.
	p := ReplyPSID{ProcedureID: 0x1234, AddressList: [6]byte{1, 2, 3, 4, 5, 6},
		Address: 1, Port: 0, Station: 1,
		VPD: HardwarePSID{MachineType: [4]byte{0xf3, 0xf8, 0xf1, 0xf2},
			Model: [3]byte{0xf0, 0xf0, 0xf1}, Plant: [2]byte{0xc1, 0xc2},
			Serial: [7]byte{0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7}},
		DateTime: [6]byte{0x26, 0x11, 3, 9, 0, 0}}
	ru, err := p.EncodeNMVT()
	if err != nil || len(ru) != 66 || !bytes.Equal(ru[:12], []byte{0x41, 3, 0x8d, 0, 0, 0x12, 0x34, 0x10, 0, 0x3a, 0, 0x90}) ||
		!bytes.Equal(ru[12:22], []byte{0x0a, 4, 1, 1, 2, 3, 4, 5, 6, 1}) ||
		!bytes.Equal(ru[22:31], []byte{9, 0x82, 4, 0x10, 0, 1, 3, 0x20, 1}) ||
		!bytes.Equal(ru[31:40], []byte{0x19, 0x10, 0, 0x16, 0x11, 1, 0x13, 0, 0x12}) ||
		!bytes.Equal(ru[56:60], []byte{0x0a, 1, 8, 0x10}) {
		t.Fatalf("address-01 Reply PSID: %x %v", ru, err)
	}
	p.Station = 2
	if _, err := p.EncodeNMVT(); err == nil {
		t.Fatal("wrong address-01 port/station accepted")
	}
	p.Station = 1
	p.VPD.Serial = [7]byte{}
	if _, err := p.EncodeNMVT(); err == nil {
		t.Fatal("missing device VPD accepted")
	}
}
