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

// New5494ControllerCNOS requests one 5494-controlled controller session and
// host-controlled device sessions. VG10's source-CNOS builder uses this
// contention-winner direction for QRMTWSC; the eight-byte mode field includes
// the EBCDIC space following its seven letters.
func New5494ControllerCNOS(deviceSessions uint16) (CNOS, error) {
	if deviceSessions == 0 || deviceSessions > 56 {
		return CNOS{}, ErrCNOS
	}
	return CNOS{Service: 2, SessionLimit: deviceSessions + 1,
		SourceWinners: 1, TargetWinners: deviceSessions,
		Mode: "QRMTWSC", ModeWidth: 8}, nil
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

// EncodeCNOS encodes an IBM LU 6.2 CNOS GDS. For a 5494 controller the
// caller supplies QRMTWSC and the configured local/remote winner limits;
// session negotiation still requires an active SNASVCMG conversation.
func EncodeCNOS(c CNOS) ([]byte, error) {
	if c.Service != 2 || c.Modifier != 0 || c.SessionLimit == 0 || c.SessionLimit > 0x7fff ||
		c.SourceWinners > c.SessionLimit || c.TargetWinners > c.SessionLimit ||
		uint32(c.SourceWinners)+uint32(c.TargetWinners) > uint32(c.SessionLimit) ||
		c.ModeWidth > 8 || len(c.Mode) > int(c.ModeWidth) {
		return nil, ErrCNOS
	}
	data := make([]byte, 17+int(c.ModeWidth))
	binary.BigEndian.PutUint16(data[:2], uint16(len(data)))
	data[2], data[3], data[4] = 0x12, 0x10, c.Service
	binary.BigEndian.PutUint16(data[9:11], c.SessionLimit)
	binary.BigEndian.PutUint16(data[11:13], c.SourceWinners)
	binary.BigEndian.PutUint16(data[13:15], c.TargetWinners)
	data[16] = c.ModeWidth
	for i := 17; i < len(data); i++ {
		data[i] = 0x40
	}
	for i := range c.Mode {
		value := c.Mode[i]
		switch {
		case value >= 'A' && value <= 'I':
			data[17+i] = 0xc1 + value - 'A'
		case value >= 'J' && value <= 'R':
			data[17+i] = 0xd1 + value - 'J'
		case value >= 'S' && value <= 'Z':
			data[17+i] = 0xe2 + value - 'S'
		case value >= '0' && value <= '9':
			data[17+i] = 0xf0 + value - '0'
		case value == '@':
			data[17+i] = 0x7c
		case value == '#':
			data[17+i] = 0x7b
		case value == '$':
			data[17+i] = 0x5b
		default:
			return nil, ErrCNOS
		}
	}
	if _, err := ParseCNOS(data); err != nil {
		return nil, err
	}
	return data, nil
}

// CandidateCNOSAttach wraps a source CNOS request in the 15-byte LU 6.2
// control-operator FMH-5 Attach observed in the 5494 firmware. The caller must have an active management
// session and must handle pacing, CONFIRM, and the accepted-pending reply.
func CandidateCNOSAttach(daf, oaf byte, sequence uint16, c CNOS) ([]byte, error) {
	if oaf == 0 || sequence == 0 {
		return nil, ErrCNOS
	}
	gds, err := EncodeCNOS(c)
	if err != nil {
		return nil, err
	}
	piu := []byte{0x2e, 0, daf, oaf, byte(sequence >> 8), byte(sequence), 0x0b, 0x91, 0x20,
		0x0f, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1, 0, 0, 0}
	return append(piu, gds...), nil
}

func cnosAttachLength(ru []byte) int {
	if len(ru) < 12 || !bytes.Equal(ru[1:12], []byte{5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1}) {
		return 0
	}
	if ru[0] == 0x0c {
		return 12 // captured V4R4 compact form
	}
	if ru[0] == 0x0f && len(ru) >= 15 && bytes.Equal(ru[12:15], []byte{0, 0, 0}) {
		return 15 // 5494 Release 3.2 firmware form
	}
	return 0
}

// ValidateCNOSReply checks the accepted-pending GDS returned for an outbound
// source CNOS Attach. The caller still owns pacing, confirmation, and the
// decision to proceed with a controller BIND.
func ValidateCNOSReply(request, reply []byte) (CNOS, error) {
	var empty CNOS
	req, err := piu.ParseFID2(request)
	attachLength := cnosAttachLength(req.RU)
	if err != nil || attachLength == 0 || req.RH != [3]byte{0x0b, 0x91, 0x20} {
		return empty, ErrCNOS
	}
	requested, err := ParseCNOS(req.RU[attachLength:])
	if err != nil || requested.Service != 2 {
		return empty, ErrCNOS
	}
	rsp, err := piu.ParseFID2(reply)
	if err != nil || rsp.TH[2] != req.TH[3] || rsp.TH[3] != req.TH[2] ||
		rsp.RH != [3]byte{3, 0x91, 1} {
		return empty, ErrCNOS
	}
	accepted, err := ParseCNOS(rsp.RU)
	if err != nil || accepted.Service != 0x0a || accepted.Modifier != 0 ||
		accepted.Mode != requested.Mode || accepted.ModeWidth != requested.ModeWidth ||
		accepted.SessionLimit > requested.SessionLimit ||
		accepted.SourceWinners > requested.SourceWinners || accepted.TargetWinners > requested.TargetWinners {
		return empty, ErrCNOS
	}
	return accepted, nil
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
	attachLength := cnosAttachLength(p.RU)
	if err != nil || attachLength == 0 || (p.TH[0] != 0x2c && p.TH[0] != 0x2e) || p.TH[1] != 0 ||
		p.TH[3] == 0 ||
		p.RH != [3]byte{0x0b, 0x91, 0x20} {
		return nil, ErrCNOS
	}
	c, err := ParseCNOS(p.RU[attachLength:])
	if err != nil || c.Service != 2 || c.Mode != r.mode || c.SessionLimit == 0 || c.SessionLimit > r.maxSessions {
		return nil, ErrCNOS
	}
	r.Negotiated = c
	replyGDS := append([]byte(nil), p.RU[attachLength:]...)
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
