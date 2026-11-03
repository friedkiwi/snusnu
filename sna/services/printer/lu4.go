package printer

import "errors"

// ErrLU4 means an encapsulated 5494 LU 4 PIU is malformed or unsupported.
var ErrLU4 = errors.New("invalid 5494 LU 4 PIU")

// LU4PIU is the FID3 PIU carried inside a 5494 LU 6.2 device session.
// The enclosing APPC GDS is deliberately outside this type: its private
// layout is not established by the published 5494 reference.
type LU4PIU struct {
	Address   byte
	Session   LU4Session
	Expedited bool
	Response  bool
	RH        [3]byte
	RU        []byte
}

type LU4Session byte

const (
	LU4SystemSession LU4Session = 1 // SS-LU, LSID bits 01
	LU4PrintSession  LU4Session = 3 // LU-LU, LSID bits 11
)

// ParseLU4PIU validates the IBM 5494 FID3 header and copies the RU.
// Station addresses are six bits; the enclosing controller application must
// correlate the address with an authenticated printer device.
func ParseLU4PIU(data []byte) (LU4PIU, error) {
	if len(data) < 5 || len(data) > 1029 || (data[0] != 0x3c && data[0] != 0x3d) ||
		(data[1]&0xc0 != 0x40 && data[1]&0xc0 != 0xc0) || data[2]&0x08 != 0 || data[4]&^byte(0x20) != 0 {
		return LU4PIU{}, ErrLU4
	}
	if data[2]&0x80 != 0 && data[2]&3 != 3 {
		return LU4PIU{}, ErrLU4
	}
	return LU4PIU{Address: data[1] & 0x3f, Session: LU4Session(data[1] >> 6), Expedited: data[0] == 0x3d,
		Response: data[2]&0x80 != 0, RH: [3]byte{data[2], data[3], data[4]}, RU: append([]byte(nil), data[5:]...)}, nil
}

// Encode reproduces one validated FID3 PIU. Callers must preserve the
// request's shared-address and pacing bits when constructing responses.
func (p LU4PIU) Encode() ([]byte, error) {
	if p.Address > 63 || (p.Session != LU4SystemSession && p.Session != LU4PrintSession) ||
		p.RH[0]&0x08 != 0 || p.RH[2]&^byte(0x20) != 0 || (p.Response && p.RH[0]&0x83 != 0x83) || len(p.RU) > 1024 {
		return nil, ErrLU4
	}
	first := byte(0x3c)
	if p.Expedited {
		first = 0x3d
	}
	return append([]byte{first, byte(p.Session)<<6 | p.Address, p.RH[0], p.RH[1], p.RH[2]}, p.RU...), nil
}

// ACTLUResponseRU is the IBM-defined positive response for an available
// printer. It identifies an LU 4 device, not a display, to the host.
func ACTLUResponseRU(request []byte) ([]byte, error) {
	if len(request) != 3 || request[0] != 0x0d || (request[1] != 1 && request[1] != 2) || request[2] != 1 {
		return nil, ErrLU4
	}
	return []byte{0x0d, 1, 1, 0, 0x84, 0, 0, 0}, nil
}

// IsPrinterBind reports whether a complete inner LU 4 BIND has the base
// printer profile documented by the 5494. Full negotiation still belongs
// to the device-session state machine.
func IsPrinterBind(p LU4PIU) bool {
	if p.Session != LU4PrintSession || !p.Expedited || p.Response || p.RH[0]&0xe0 != 0x60 || len(p.RU) < 26 {
		return false
	}
	r := p.RU
	return r[0] == 0x31 && r[1] == 0 && r[2] == 7 && r[3] == 7 && r[14] == 4 && r[15]&0xc0 == 0xc0 && r[23] == 0x80
}
