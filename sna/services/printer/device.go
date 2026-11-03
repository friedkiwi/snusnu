package printer

import (
	"bytes"
	"errors"
)

// ErrDeviceState means an inner LU 4 request arrived out of order or the
// previously prepared response was not acknowledged by the transport.
var ErrDeviceState = errors.New("invalid LU 4 printer device state")

type DevicePhase uint8

const (
	DeviceAwaitACTLU DevicePhase = iota
	DeviceAwaitACTLUAck
	DeviceAwaitBind
	DeviceAwaitBindAck
	DeviceBound
	DeviceAwaitDataAck
)

// LU4Device handles the architected ACTLU and printer BIND inside one 5494
// device session. Its caller owns the private LU 6.2 envelope, pacing, and
// correlation with the authenticated printer announcement.
type LU4Device struct {
	address byte
	maxRU   byte
	phase   DevicePhase
	pending []byte
}

// PrepareFMD accepts one complete, definite-response printer data chain.
// appendSCS must durably accept the raw SCS bytes before this method can
// return a positive response, and must deduplicate retransmissions using the
// enclosing LU 6.2 session's sequence/correlation state. A caller may
// concatenate multiple chains into one spool file; the LU 4 stream itself
// does not identify a spool boundary.
func (d *LU4Device) PrepareFMD(input []byte, appendSCS func([]byte) error) ([]byte, error) {
	if d == nil || d.phase != DeviceBound || len(d.pending) != 0 || appendSCS == nil {
		return nil, ErrDeviceState
	}
	p, err := ParseLU4PIU(input)
	if err != nil || p.Address != d.address || p.Session != LU4PrintSession || p.Expedited || p.Response ||
		p.RH[0]&0xe3 != 0x03 || len(p.RU) == 0 || p.RH[1]&0xa0 == 0 {
		return nil, ErrDeviceState
	}
	response, err := PositiveLU4Response(p, nil)
	if err != nil {
		return nil, err
	}
	encoded, err := response.Encode()
	if err != nil {
		return nil, err
	}
	if err := appendSCS(append([]byte(nil), p.RU...)); err != nil {
		return nil, err
	}
	d.pending = encoded
	d.phase = DeviceAwaitDataAck
	return append([]byte(nil), encoded...), nil
}

func NewLU4Device(address, maxRU byte) (*LU4Device, error) {
	if address == 0 || address > 63 || maxRU < 0x85 || maxRU > 0x87 {
		return nil, ErrDeviceState
	}
	return &LU4Device{address: address, maxRU: maxRU}, nil
}

func (d *LU4Device) Phase() DevicePhase { return d.phase }

// Prepare responds to one complete inner PIU. The transport must deliver the
// returned bytes and then call MarkSent with those exact bytes.
func (d *LU4Device) Prepare(input []byte) ([]byte, error) {
	if d == nil || len(d.pending) != 0 {
		return nil, ErrDeviceState
	}
	p, err := ParseLU4PIU(input)
	if err != nil || p.Address != d.address || p.Response {
		return nil, ErrDeviceState
	}
	var ru []byte
	switch d.phase {
	case DeviceAwaitACTLU:
		if p.Session != LU4SystemSession || !p.Expedited {
			return nil, ErrDeviceState
		}
		ru, err = ACTLUResponseRU(p.RU)
	case DeviceAwaitBind:
		ru, err = CandidatePrinterBindResponseRU(p, d.maxRU)
	default:
		return nil, ErrDeviceState
	}
	if err != nil {
		return nil, err
	}
	response, err := PositiveLU4Response(p, ru)
	if err != nil {
		return nil, err
	}
	encoded, err := response.Encode()
	if err != nil {
		return nil, err
	}
	d.pending = encoded
	if d.phase == DeviceAwaitACTLU {
		d.phase = DeviceAwaitACTLUAck
	} else {
		d.phase = DeviceAwaitBindAck
	}
	return append([]byte(nil), encoded...), nil
}

func (d *LU4Device) MarkSent(response []byte) error {
	if d == nil || len(d.pending) == 0 || !bytes.Equal(response, d.pending) {
		return ErrDeviceState
	}
	switch d.phase {
	case DeviceAwaitACTLUAck:
		d.phase = DeviceAwaitBind
	case DeviceAwaitBindAck:
		d.phase = DeviceBound
	case DeviceAwaitDataAck:
		d.phase = DeviceBound
	default:
		return ErrDeviceState
	}
	d.pending = nil
	return nil
}
