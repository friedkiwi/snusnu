package printer

import "errors"

// ErrPSID means a 5494 Reply Product Set ID cannot be constructed from the
// supplied runtime identity. The caller must obtain VPD and SNA addressing
// from its actual controller/device state rather than inventing defaults.
var ErrPSID = errors.New("invalid 5494 printer Product Set ID")

// HardwarePSID identifies one attached hardware printer. Values are EBCDIC
// bytes as supplied by twinax VPD, not host-side spool metadata.
type HardwarePSID struct {
	MachineType [4]byte
	Model       [3]byte
	Plant       [2]byte
	Serial      [7]byte
}

// ReplyPSID holds the runtime fields of the 5494 short, hardware-only NMVT
// Reply Product Set ID. AddressList is the six-byte SNA address prefix which
// precedes the final linear workstation address in the Address List.
type ReplyPSID struct {
	ProcedureID uint16
	AddressList [6]byte
	Address     byte
	Port        byte
	Station     byte
	VPD         HardwarePSID
	DateTime    [6]byte // yy, month, day, hour, minute, second as SNA bytes
}

// EncodeNMVT builds the NMVT network-services RU observed in the IBM 5494
// Release 3.2 sender. It intentionally does not add an LU 6.2 GDS wrapper or
// make assumptions about IBM i's response. This is the short product branch;
// an emulator product ID requires the separate extended branch.
func (p ReplyPSID) EncodeNMVT() ([]byte, error) {
	if p.ProcedureID == 0 || p.Address == 0 || p.Address > 63 || p.Port > 63 ||
		p.Station == 0 || p.Station > 7 ||
		(p.Address == 1 && (p.Port != 0 || p.Station != 1)) ||
		!ebcdicDigits(p.VPD.MachineType[:]) ||
		!ebcdicVPD(p.VPD.Model[:]) || !ebcdicVPD(p.VPD.Plant[:]) ||
		!ebcdicVPD(p.VPD.Serial[:]) {
		return nil, ErrPSID
	}
	ru := []byte{0x41, 0x03, 0x8d, 0, 0, byte(p.ProcedureID >> 8), byte(p.ProcedureID),
		0x10, 0, 0x3a, 0, 0x90, 0x0a, 4, 1}
	ru = append(ru, p.AddressList[:]...)
	ru = append(ru, p.Address)
	ru = append(ru, 9, 0x82, 4, 0x10, p.Port, p.Station, 3, 0x20, 1)
	ru = append(ru, 0x19, 0x10, 0, 0x16, 0x11, 1, 0x13, 0, 0x12)
	ru = append(ru, p.VPD.MachineType[:]...)
	ru = append(ru, p.VPD.Model[:]...)
	ru = append(ru, p.VPD.Plant[:]...)
	ru = append(ru, p.VPD.Serial[:]...)
	ru = append(ru, 0x0a, 1, 8, 0x10)
	ru = append(ru, p.DateTime[:]...)
	if len(ru) != 66 {
		return nil, ErrPSID
	}
	return ru, nil
}

func ebcdicDigits(b []byte) bool {
	for _, x := range b {
		if x < 0xf0 || x > 0xf9 {
			return false
		}
	}
	return true
}

func ebcdicVPD(b []byte) bool {
	for _, x := range b {
		if x != 0x40 && !(x >= 0xc1 && x <= 0xc9) &&
			!(x >= 0xd1 && x <= 0xd9) && !(x >= 0xe2 && x <= 0xe9) &&
			!(x >= 0xf0 && x <= 0xf9) {
			return false
		}
	}
	return true
}
