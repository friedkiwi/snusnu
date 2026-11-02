// Package xid3 handles bounded APPN format-3 exchange identification fields.
// It operates on the XID information field, independently of LLC framing.
package xid3

import (
	"errors"
	"strings"
)

var ErrXID = errors.New("invalid SNA XID3")

const fixedBytes = 29

type Role byte

const (
	Secondary  Role = 0
	Primary    Role = 0x10
	Negotiable Role = 0x30
)

type State byte

const (
	Unsupported    State = 0
	Proceeding     State = 0x04
	Prenegotiation State = 0x08
	Nonactivation  State = 0x0c
)

type Vector struct {
	Key  byte
	Data []byte
}

type XID struct {
	Fixed   [fixedBytes]byte
	Vectors []Vector
}

func Parse(data []byte) (XID, error) {
	var x XID
	if len(data) < fixedBytes || len(data) > 255 || data[0] != 0x32 || int(data[1]) != len(data) {
		return x, ErrXID
	}
	copy(x.Fixed[:], data[:fixedBytes])
	for o := fixedBytes; o < len(data); {
		if o+2 > len(data) {
			return XID{}, ErrXID
		}
		n := int(data[o+1])
		o += 2
		if o+n > len(data) {
			return XID{}, ErrXID
		}
		x.Vectors = append(x.Vectors, Vector{Key: data[o-2], Data: append([]byte(nil), data[o:o+n]...)})
		o += n
	}
	if err := x.Validate(); err != nil {
		return XID{}, err
	}
	return x, nil
}

func (x XID) Bytes() ([]byte, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}
	data := make([]byte, 0, int(x.Fixed[1]))
	data = append(data, x.Fixed[:]...)
	for _, v := range x.Vectors {
		data = append(data, v.Key, byte(len(v.Data)))
		data = append(data, v.Data...)
	}
	return data, nil
}

func (x XID) Validate() error {
	if x.Fixed[0] != 0x32 || x.Role() == 0x20 || x.Fixed[21] == 0 && x.Fixed[22] == 0 || x.Fixed[27]&0x7f == 0 {
		return ErrXID
	}
	n := fixedBytes
	for _, v := range x.Vectors {
		if len(v.Data) > 255 || v.Key == 0x10 && len(v.Data) > 60 {
			return ErrXID
		}
		n += 2 + len(v.Data)
	}
	if n > 255 || int(x.Fixed[1]) != n {
		return ErrXID
	}
	_, err := x.CPName()
	if err != nil && !errors.Is(err, ErrNoCPName) {
		return err
	}
	return nil
}

var ErrNoCPName = errors.New("XID3 has no CP name")

func (x XID) CPName() (string, error) {
	name := ""
	for _, v := range x.Vectors {
		if v.Key != 0x0e || len(v.Data) == 0 || v.Data[0] != 0xf4 {
			continue
		}
		if name != "" {
			return "", ErrXID
		}
		decoded, err := decode(v.Data[1:])
		if err != nil || !validCP(decoded) {
			return "", ErrXID
		}
		name = decoded
	}
	if name == "" {
		return "", ErrNoCPName
	}
	return name, nil
}

func (x XID) Role() Role { return Role(x.Fixed[19] & 0x30) }
func (x *XID) SetRole(role Role) error {
	if role != Primary && role != Secondary && role != Negotiable {
		return ErrXID
	}
	x.Fixed[19] = x.Fixed[19]&^byte(0x30) | byte(role)
	return nil
}
func (x XID) State() State { return State(x.Fixed[9] & 0x0c) }
func (x *XID) SetState(state State) error {
	if state != Unsupported && state != Proceeding && state != Prenegotiation && state != Nonactivation {
		return ErrXID
	}
	x.Fixed[9] = x.Fixed[9]&^byte(0x0c) | byte(state)
	return nil
}
func (x XID) NodeID() [4]byte { var out [4]byte; copy(out[:], x.Fixed[2:6]); return out }

func NewLocal(cp, station string, nodeID [4]byte, tg byte, role Role) (XID, error) {
	var x XID
	block := uint16(nodeID[0])<<4 | uint16(nodeID[1])>>4
	if !validCP(cp) || len(station) == 0 || len(station) > 8 || station[0] < 'A' || station[0] > 'Z' ||
		strings.Contains(station, ".") || (block != 0 && block != 0xfff) ||
		(nodeID[1]&0x0f == 0 && nodeID[2] == 0 && nodeID[3] == 0) ||
		(role != Primary && role != Secondary) {
		return x, ErrXID
	}
	stationBytes, err := encode(station)
	if err != nil {
		return x, err
	}
	cpBytes, err := encode(cp)
	if err != nil {
		return x, err
	}
	x.Fixed[0] = 0x32
	copy(x.Fixed[2:6], nodeID[:])
	x.Fixed[8], x.Fixed[9] = 0xb0, 0x88
	x.Fixed[16], x.Fixed[17], x.Fixed[18] = tg, 1, 0x0b
	x.Fixed[19] = 0x40 | byte(role)
	x.Fixed[21], x.Fixed[22], x.Fixed[27] = 0x05, 0xd8, 1 // 1496-byte BTU; one I-frame ACK window.
	x.Vectors = []Vector{
		{Key: 0x0e, Data: append([]byte{0xf4}, cpBytes...)},
		{Key: 0x0e, Data: append([]byte{0xf7}, stationBytes...)},
		{Key: 0x10, Data: []byte{0, 0x0b, 0x11, 0x0c, 8, 6, 0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4}},
	}
	n := fixedBytes
	for _, v := range x.Vectors {
		n += 2 + len(v.Data)
	}
	if n > 255 {
		return XID{}, ErrXID
	}
	x.Fixed[1] = byte(n)
	return x, x.Validate()
}

func validCP(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 8 || len(parts[1]) == 0 || len(parts[1]) > 8 {
		return false
	}
	_, err := encode(value)
	return err == nil
}

func encode(value string) ([]byte, error) {
	out := make([]byte, len(value))
	for i := range value {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'I':
			out[i] = 0xc1 + c - 'A'
		case c >= 'J' && c <= 'R':
			out[i] = 0xd1 + c - 'J'
		case c >= 'S' && c <= 'Z':
			out[i] = 0xe2 + c - 'S'
		case c >= '0' && c <= '9':
			out[i] = 0xf0 + c - '0'
		case c == '.':
			out[i] = 0x4b
		case c == '@':
			out[i] = 0x7c
		case c == '#':
			out[i] = 0x7b
		case c == '$':
			out[i] = 0x5b
		default:
			return nil, ErrXID
		}
	}
	return out, nil
}

func decode(data []byte) (string, error) {
	out := make([]byte, len(data))
	for i, c := range data {
		switch {
		case c >= 0xc1 && c <= 0xc9:
			out[i] = 'A' + c - 0xc1
		case c >= 0xd1 && c <= 0xd9:
			out[i] = 'J' + c - 0xd1
		case c >= 0xe2 && c <= 0xe9:
			out[i] = 'S' + c - 0xe2
		case c >= 0xf0 && c <= 0xf9:
			out[i] = '0' + c - 0xf0
		case c == 0x4b:
			out[i] = '.'
		case c == 0x7c:
			out[i] = '@'
		case c == 0x7b:
			out[i] = '#'
		case c == 0x5b:
			out[i] = '$'
		default:
			return "", ErrXID
		}
	}
	return string(out), nil
}
