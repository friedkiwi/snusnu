package printer

import (
	"errors"

	"github.com/friedkiwi/snusnu/sna/piu"
)

// ErrPSID means a 5494 Reply Product Set ID cannot be constructed from the
// supplied runtime identity. The caller must obtain VPD and SNA addressing
// from its actual controller/device state rather than inventing defaults.
var ErrPSID = errors.New("invalid 5494 printer Product Set ID")

// HardwarePSID identifies one attached hardware printer. MachineType is
// converted to EBCDIC decimal digits by the 5494; the remaining fields are
// copied from twinax VPD bytes, not host-side spool metadata.
type HardwarePSID struct {
	MachineType [4]byte
	Model       [3]byte
	Plant       [2]byte
	Serial      [7]byte
}

// ReplyPSID holds the runtime fields of the 5494 short, hardware-only NMVT
// Reply Product Set ID. AddressList is the six-byte SNA address prefix which
// precedes the final linear workstation address in the Address List. Port's
// high two bits select a shared session; its low six bits and Station must
// match the address divided by seven.
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
	// VG15 divides the six-bit linear address by seven. The low six port
	// bits carry the quotient; the top two bits select a shared session.
	if p.ProcedureID == 0 || p.Address == 0 || p.Address > 63 ||
		p.Port&0x3f != p.Address/7 || p.Station != p.Address%7 ||
		!ebcdicDigits(p.VPD.MachineType[:]) || p.VPD.Model == [3]byte{} ||
		p.VPD.Plant == [2]byte{} || p.VPD.Serial == [7]byte{} {
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

// EncodeNMVTPIU adds the firmware-observed FID2 and RH envelope. The caller
// supplies the resolved session's TH and runtime RH1/RH2; the firmware fixes
// RH0 at 0B. No LU 6.2 GDS or LLID surrounds this network-management PIU.
func (p ReplyPSID) EncodeNMVTPIU(th [6]byte, rh1, rh2 byte) ([]byte, error) {
	ru, err := p.EncodeNMVT()
	if err != nil {
		return nil, err
	}
	return (piu.FID2{TH: th, RH: [3]byte{0x0b, rh1, rh2}, RU: ru}).Bytes()
}

func ebcdicDigits(b []byte) bool {
	for _, x := range b {
		if x < 0xf0 || x > 0xf9 {
			return false
		}
	}
	return true
}
