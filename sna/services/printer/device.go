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
	DeviceAwaitUnbindAck
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

// PrepareFMD accepts a one-PIU printer data chain.
// For a multi-PIU chain, use ChainAssembler and PrepareFMDChain.
func (d *LU4Device) PrepareFMD(input []byte, appendSCS func([]byte) error) ([]byte, error) {
	p, err := ParseLU4PIU(input)
	if err != nil || p.RH[0]&3 != 3 {
		return nil, ErrDeviceState
	}
	return d.PrepareFMDChain(input, p.RU, appendSCS)
}

// PrepareFMDChain accepts a completed printer data chain. last is its final
// FID3 PIU and scs is the RU assembled by ChainAssembler. appendSCS must
// durably accept the raw bytes before a positive response can be returned.
// For exception-response requests, it returns no response after acceptance.
// The caller owns LU 6.2 sequence deduplication and spool-job boundaries.
func (d *LU4Device) PrepareFMDChain(last, scs []byte, appendSCS func([]byte) error) ([]byte, error) {
	if d == nil || d.phase != DeviceBound || len(d.pending) != 0 || appendSCS == nil {
		return nil, ErrDeviceState
	}
	p, err := ParseLU4PIU(last)
	if err != nil || p.Address != d.address || p.Session != LU4PrintSession || p.Expedited || p.Response ||
		p.RH[0]&0xe0 != 0 || len(p.RU) == 0 || len(scs) == 0 || len(scs) > MaxJobBytes ||
		(p.RH[0]&3 != 1 && p.RH[0]&3 != 3) || p.RH[1]&0xa0 == 0 ||
		!bytes.HasSuffix(scs, p.RU) ||
		(p.RH[0]&3 == 3 && len(scs) != len(p.RU)) ||
		(p.RH[0]&3 == 1 && len(scs) <= len(p.RU)) {
		return nil, ErrDeviceState
	}
	var encoded []byte
	if p.RH[1]&0x10 == 0 {
		response, err := PositiveLU4Response(p, nil)
		if err != nil {
			return nil, err
		}
		encoded, err = response.Encode()
		if err != nil {
			return nil, err
		}
	}
	if err := appendSCS(append([]byte(nil), scs...)); err != nil {
		return nil, err
	}
	if len(encoded) == 0 {
		return nil, nil
	}
	d.pending = encoded
	d.phase = DeviceAwaitDataAck
	return append([]byte(nil), encoded...), nil
}

func NewLU4Device(address, maxRU byte) (*LU4Device, error) {
	if address == 0 || address > 63 || !validPrinterBindRUSize(maxRU) || printerBindRUSize(maxRU) > MaxFID3PIUBytes {
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
	case DeviceBound:
		if p.Session != LU4PrintSession || !p.Expedited || len(p.RU) < 2 || p.RU[0] != 0x32 {
			return nil, ErrDeviceState
		}
		ru = []byte{0x32}
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
	} else if d.phase == DeviceAwaitBind {
		d.phase = DeviceAwaitBindAck
	} else {
		d.phase = DeviceAwaitUnbindAck
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
	case DeviceAwaitUnbindAck:
		d.phase = DeviceAwaitBind
	default:
		return ErrDeviceState
	}
	d.pending = nil
	return nil
}
