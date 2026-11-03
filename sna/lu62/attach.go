package lu62

import (
	"errors"

	"github.com/friedkiwi/snusnu/sna/piu"
)

var ErrAttach = errors.New("invalid LU 6.2 FMH-5 Attach")

type Attach struct {
	TPName   string
	DAF, OAF byte
	Sequence uint16
	Raw      []byte
}

// ArchitectureAttach identifies an FMH-5 Attach whose TP name is a four-byte
// SNA architecture TPN. Such names are binary, rather than EBCDIC text.
type ArchitectureAttach struct {
	TPN      [4]byte
	DAF, OAF byte
	Sequence uint16
	Raw      []byte
}

// ParseFirstArchitectureAttach recognizes the same first-conversation FMH-5
// framing as ParseFirstAttach, but retains a binary architecture TPN. In
// particular, the candidate 5494 controller TP is X'30F0F6F6'. This parser
// does not establish that a particular controller used that TP in a trace.
func ParseFirstArchitectureAttach(data []byte) (*ArchitectureAttach, error) {
	p, err := piu.ParseFID2(data)
	if err != nil {
		return nil, err
	}
	if len(p.RU) < 2 || p.RU[1] != 5 {
		return nil, nil
	}
	if p.RH != [3]byte{0x0a, 0x91, 0} || p.TH[4] != 0 || p.TH[5] != 1 ||
		len(p.RU) < 14 || int(p.RU[0]) > len(p.RU) || int(p.RU[0]) < 14 ||
		p.RU[2] != 2 || p.RU[3] != 0xff || p.RU[4] != 0 || p.RU[5] != 3 ||
		(p.RU[6] != 0xd0 && p.RU[6] != 0xd1) || p.RU[7] != 0 || p.RU[8] != 0x40 || p.RU[9] != 4 {
		return nil, ErrAttach
	}
	var tpn [4]byte
	copy(tpn[:], p.RU[10:14])
	return &ArchitectureAttach{TPN: tpn, DAF: p.TH[2], OAF: p.TH[3],
		Sequence: uint16(p.TH[4])<<8 | uint16(p.TH[5]), Raw: append([]byte(nil), p.RU...)}, nil
}

// ParseFirstAttach recognizes the first normal-flow FMH-5 Attach observed
// after an accepted LU 6.2 BIND. It does not acknowledge or authorize the
// conversation; the caller must correlate its session and source LU.
func ParseFirstAttach(data []byte) (*Attach, error) {
	p, err := piu.ParseFID2(data)
	if err != nil {
		return nil, err
	}
	if len(p.RU) < 2 || p.RU[1] != 5 {
		return nil, nil
	}
	if p.RH != [3]byte{0x0a, 0x91, 0} || p.TH[4] != 0 || p.TH[5] != 1 ||
		len(p.RU) < 16 || int(p.RU[0]) > len(p.RU) || int(p.RU[0]) < 16 ||
		p.RU[1] != 5 || p.RU[2] != 2 || p.RU[3] != 0xff || p.RU[4] != 0 || p.RU[5] != 3 || p.RU[6] != 0xd1 ||
		p.RU[7] != 0 || p.RU[8] != 0x40 {
		return nil, ErrAttach
	}
	n := int(p.RU[9])
	if n < 1 || n > 64 || 10+n > int(p.RU[0]) {
		return nil, ErrAttach
	}
	name, err := decodeName(p.RU[10:10+n], false)
	if err != nil || name == "" {
		return nil, ErrAttach
	}
	return &Attach{TPName: name, DAF: p.TH[2], OAF: p.TH[3], Sequence: uint16(p.TH[4])<<8 | uint16(p.TH[5]), Raw: append([]byte(nil), p.RU...)}, nil
}
