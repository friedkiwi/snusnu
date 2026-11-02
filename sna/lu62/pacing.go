package lu62

import "errors"

var ErrPacing = errors.New("invalid fixed SNA pacing")

// FixedPacing tracks one-stage session pacing in both directions. The caller
// validates FID2 addresses and commits grants only after transport egress.
type FixedPacing struct {
	sendWindow, receiveWindow                     byte
	sendLeft, receiveLeft                         byte
	sendFirst, receiveFirst                       bool
	awaiting, nextSend, grantPending, nextReceive bool
}

func NewFixedPacing(sendWindow, receiveWindow byte) (*FixedPacing, error) {
	if sendWindow < 1 || sendWindow > 63 || receiveWindow < 1 || receiveWindow > 63 {
		return nil, ErrPacing
	}
	return &FixedPacing{sendWindow: sendWindow, receiveWindow: receiveWindow, sendLeft: sendWindow, receiveLeft: receiveWindow, sendFirst: true, receiveFirst: true}, nil
}

func (p *FixedPacing) SendRequest() (bool, error) {
	if p.sendLeft == 0 {
		if !p.nextSend {
			return false, ErrPacing
		}
		p.nextSend, p.sendLeft, p.sendFirst = false, p.sendWindow, true
	}
	pi := p.sendFirst
	p.sendFirst = false
	p.sendLeft--
	if pi {
		p.awaiting = true
	}
	return pi, nil
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
