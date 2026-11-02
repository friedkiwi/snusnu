package lu62

import (
	"bytes"
	"errors"
)

var ErrPacing = errors.New("invalid fixed SNA pacing")

// IsPacingResponse recognizes the empty form and the three-byte pacing
// parameter observed from V4R4. Session code validates the FID2 addresses.
func IsPacingResponse(data []byte) bool {
	return len(data) == 9 && bytes.Equal(data[6:], []byte{0x83, 1, 0}) ||
		len(data) == 12 && bytes.Equal(data[6:], []byte{0x83, 1, 0, 0, 0, 6})
}

// FixedPacing tracks one-stage session pacing in both directions. The caller
// validates FID2 addresses and commits grants only after transport egress.
type FixedPacing struct {
	sendWindow, receiveWindow                     byte
	sendLeft, receiveLeft                         byte
	sendFirst, receiveFirst                       bool
	awaiting, nextSend, grantPending, nextReceive bool
	pendingSend, pendingPI                        bool
}

func NewFixedPacing(sendWindow, receiveWindow byte) (*FixedPacing, error) {
	if sendWindow < 1 || sendWindow > 63 || receiveWindow < 1 || receiveWindow > 63 {
		return nil, ErrPacing
	}
	return &FixedPacing{sendWindow: sendWindow, receiveWindow: receiveWindow, sendLeft: sendWindow, receiveLeft: receiveWindow, sendFirst: true, receiveFirst: true}, nil
}

// PrepareSendRequest selects the PI bit without consuming pacing credit.
// MarkRequestSent follows a successful transport send of that request.
func (p *FixedPacing) PrepareSendRequest() (bool, error) {
	if p.pendingSend || p.sendLeft == 0 && !p.nextSend {
		return false, ErrPacing
	}
	p.pendingPI = p.sendFirst || p.sendLeft == 0
	p.pendingSend = true
	return p.pendingPI, nil
}

func (p *FixedPacing) MarkRequestSent(pi bool) error {
	if !p.pendingSend || pi != p.pendingPI {
		return ErrPacing
	}
	if p.sendLeft == 0 {
		p.nextSend, p.sendLeft = false, p.sendWindow
	}
	p.pendingSend = false
	p.sendFirst = false
	p.sendLeft--
	if pi {
		p.awaiting = true
	}
	return nil
}

func (p *FixedPacing) CancelPreparedRequest() {
	p.pendingSend = false
}

func (p *FixedPacing) ReceiveIPR() error {
	if !p.awaiting || p.nextSend {
		return ErrPacing
	}
	p.awaiting, p.nextSend = false, true
	return nil
}

func (p *FixedPacing) ReceiveRequest(pi bool) error {
	next := p.receiveLeft == 0
	if next && !p.nextReceive {
		return ErrPacing
	}
	first := next || p.receiveFirst
	if first != pi {
		return ErrPacing
	}
	if next {
		p.nextReceive, p.receiveLeft = false, p.receiveWindow
	}
	p.receiveFirst = false
	p.receiveLeft--
	if pi {
		p.grantPending = true
	}
	return nil
}

func (p *FixedPacing) GrantReceiveWindow() error {
	if !p.grantPending || p.nextReceive {
		return ErrPacing
	}
	p.grantPending, p.nextReceive = false, true
	return nil
}

func (p *FixedPacing) GrantPending() bool     { return p.grantPending }
func (p *FixedPacing) SendRemaining() byte    { return p.sendLeft }
func (p *FixedPacing) ReceiveRemaining() byte { return p.receiveLeft }
