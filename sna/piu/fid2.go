// Package piu decodes complete SNA FID2 path information units. A transport
// supplies PIU boundaries; LLC, AnyNet, and WebSocket framing stay outside it.
package piu

import (
	"errors"
	"fmt"
)

var ErrShort = errors.New("short FID2 PIU")
var ErrUnsupported = errors.New("unsupported FID2 PIU")

// FID2 is a complete, unsegmented path information unit.
type FID2 struct {
	TH [6]byte
	RH [3]byte
	RU []byte
}

func ParseFID2(data []byte) (FID2, error) {
	var p FID2
	if len(data) < 9 {
		return p, ErrShort
	}
	if data[0]>>4 != 2 || data[0]&0x0c != 0x0c || len(data) > 64*1024 {
		return p, ErrUnsupported
	}
	copy(p.TH[:], data[:6])
	copy(p.RH[:], data[6:9])
	p.RU = append([]byte(nil), data[9:]...)
	return p, nil
}

func (p FID2) Bytes() ([]byte, error) {
	if p.TH[0]>>4 != 2 || p.TH[0]&0x0c != 0x0c || len(p.RU) > 64*1024-9 {
		return nil, ErrUnsupported
	}
	data := make([]byte, 9+len(p.RU))
	copy(data[:6], p.TH[:])
	copy(data[6:9], p.RH[:])
	copy(data[9:], p.RU)
	return data, nil
}

func (p FID2) String() string {
	return fmt.Sprintf("FID2 daf=%02x oaf=%02x rh=%02x%02x%02x ru=%d", p.TH[2], p.TH[3], p.RH[0], p.RH[1], p.RH[2], len(p.RU))
}
