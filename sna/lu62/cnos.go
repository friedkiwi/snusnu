package lu62

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/friedkiwi/snusnu/sna/piu"
)

var ErrCNOS = errors.New("invalid CNOS set-limits exchange")

type CNOS struct {
	Service, Modifier                          byte
	SessionLimit, SourceWinners, TargetWinners uint16
	Mode                                       string
	ModeWidth                                  byte
}

func ParseCNOS(data []byte) (CNOS, error) {
	var c CNOS
	if len(data) < 17 || len(data) > 25 || int(binary.BigEndian.Uint16(data[:2])) != len(data) ||
		data[2] != 0x12 || data[3] != 0x10 || data[6] != 0 || data[7] != 0 || data[8]&^byte(1) != 0 ||
		data[15] != 0 || data[16] > 8 || len(data) != 17+int(data[16]) {
		return c, ErrCNOS
	}
	c.Service, c.Modifier = data[4], data[5]
	if (c.Service != 2 && c.Service != 0x0a && c.Service != 8) ||
		(c.Service == 2 && c.Modifier != 0) ||
		(c.Service != 2 && c.Modifier != 0 && c.Modifier != 1 && c.Modifier != 2 && c.Modifier != 4 && c.Modifier != 5) {
		return c, ErrCNOS
	}
	c.SessionLimit = binary.BigEndian.Uint16(data[9:11])
	c.SourceWinners = binary.BigEndian.Uint16(data[11:13])
	c.TargetWinners = binary.BigEndian.Uint16(data[13:15])
	if c.SessionLimit&0x8000 != 0 || c.SourceWinners&0x8000 != 0 || c.TargetWinners&0x8000 != 0 ||
		uint32(c.SourceWinners)+uint32(c.TargetWinners) > uint32(c.SessionLimit) {
		return CNOS{}, ErrCNOS
	}
	c.ModeWidth = data[16]
	mode, err := decodeName(data[17:], false)
	if err != nil {
		return CNOS{}, ErrCNOS
	}
	c.Mode = mode
	return c, nil
}

type CNOSResponder struct {
	phase       byte
	mode        string
	maxSessions uint16
	pending     []byte
	Negotiated  CNOS
}

func NewCNOSResponder(mode string, maxSessions uint16) (*CNOSResponder, error) {
	if len(mode) > 8 || maxSessions == 0 || maxSessions > 0x7fff {
		return nil, ErrCNOS
	}
	for i := range mode {
		c := mode[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '@' || c == '#' || c == '$') {
			return nil, ErrCNOS
		}
	}
	return &CNOSResponder{mode: mode, maxSessions: maxSessions}, nil
}

// AcceptAttach recognizes the observed V4R4 SNASVCMG control-operator Attach
// and returns its accepted-pending reply. MarkReplyTransmitted must follow the
// transport's successful send before the negotiated limits can be used.
func (r *CNOSResponder) AcceptAttach(data []byte) ([]byte, error) {
	if r.phase != 0 {
		return nil, ErrCNOS
	}
	p, err := piu.ParseFID2(data)
	if err != nil || len(p.RU) < 12 || (p.TH[0] != 0x2c && p.TH[0] != 0x2e) || p.TH[1] != 0 ||
		p.TH[2] == 0 || p.TH[3] == 0 || p.TH[2] == p.TH[3] ||
		p.RH != [3]byte{0x0b, 0x91, 0x20} ||
		!bytes.Equal(p.RU[:12], []byte{0x0c, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1}) {
		return nil, ErrCNOS
	}
	c, err := ParseCNOS(p.RU[12:])
	if err != nil || c.Service != 2 || c.Mode != r.mode || c.SessionLimit == 0 || c.SessionLimit > r.maxSessions {
		return nil, ErrCNOS
	}
	r.Negotiated = c
	replyGDS := append([]byte(nil), p.RU[12:]...)
	replyGDS[4] = 0x0a
	reply := []byte{p.TH[0], 0, p.TH[3], p.TH[2], 0, 1, 3, 0x91, 1}
	reply = append(reply, replyGDS...)
	r.pending = append([]byte(nil), reply...)
	r.phase = 1
	return reply, nil
}

func (r *CNOSResponder) MarkReplyTransmitted(data []byte) error {
	if r.phase != 1 || !bytes.Equal(data, r.pending) {
		return ErrCNOS
	}
	r.pending = nil
	r.phase = 2
	return nil
}

func (r *CNOSResponder) Complete() bool { return r.phase == 2 }
