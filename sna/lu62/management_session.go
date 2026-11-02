package lu62

import (
	"bytes"
	"errors"
)

var ErrManagementState = errors.New("invalid LU 6.2 management state")

type ManagementPhase uint8

const (
	ManagementAwaitBind ManagementPhase = iota
	ManagementBindPrepared
	ManagementAwaitBindAck
	ManagementAwaitCNOS
	ManagementCNOSPrepared
	ManagementAwaitCNOSAck
	ManagementCNOSComplete
)

// ManagementSession owns one responder-side SNASVCMG BIND and CNOS exchange.
// A transport adapter must call the Mark and Ack methods only after exact
// outbound PIUs have been accepted and then acknowledged by its link.
type ManagementSession struct {
	remoteCP, localCP string
	phase             ManagementPhase
	bindRequest       []byte
	bindResponse      []byte
	bindFQPCID        []byte
	cnos              *CNOSResponder
	pacing            *FixedPacing
	cnosIPR           []byte
	cnosReply         []byte
	cnosAcks          uint8
}

func NewManagementSession(remoteCP, localCP string) (*ManagementSession, error) {
	if _, err := encodeLUName(remoteCP); err != nil {
		return nil, err
	}
	if _, err := encodeLUName(localCP); err != nil || remoteCP == localCP {
		return nil, ErrManagementState
	}
	return &ManagementSession{remoteCP: remoteCP, localCP: localCP}, nil
}

func (s *ManagementSession) Phase() ManagementPhase { return s.phase }

func (s *ManagementSession) FQPCID() []byte {
	return append([]byte(nil), s.bindFQPCID...)
}

func (s *ManagementSession) PrepareBind(request []byte) ([]byte, error) {
	if s.phase != ManagementAwaitBind {
		return nil, ErrManagementState
	}
	response, err := CandidateManagementResponse(request, s.remoteCP, s.localCP, 1)
	if err != nil {
		return nil, err
	}
	fq, err := RequestFQPCID(request)
	if err != nil {
		return nil, err
	}
	s.bindRequest = append([]byte(nil), request...)
	s.bindResponse = response
	s.bindFQPCID = fq
	s.phase = ManagementBindPrepared
	return append([]byte(nil), response...), nil
}

func (s *ManagementSession) MarkBindSent(response []byte) error {
	if s.phase != ManagementBindPrepared || !bytes.Equal(response, s.bindResponse) {
		return ErrManagementState
	}
	s.phase = ManagementAwaitBindAck
	return nil
}

func (s *ManagementSession) AckBind() error {
	if s.phase != ManagementAwaitBindAck {
		return ErrManagementState
	}
	pacing, err := NewFixedPacing(7, 1)
	if err != nil {
		return err
	}
	s.pacing = pacing
	s.bindResponse = nil
	s.phase = ManagementAwaitCNOS
	return nil
}

// PrepareCNOS validates one captured V4R4 CNOS Attach and returns the IPR
// grant followed by its accepted-pending reply. Neither may be skipped.
func (s *ManagementSession) PrepareCNOS(request []byte) ([]byte, []byte, error) {
	if s.phase != ManagementAwaitCNOS || len(request) < 9 || request[0]&2 != s.bindRequest[0]&2 ||
		request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] {
		return nil, nil, ErrManagementState
	}
	trial := *s.pacing
	if err := trial.ReceiveRequest(request[7]&1 != 0); err != nil {
		return nil, nil, err
	}
	responder, err := NewCNOSResponder("", 8)
	if err != nil {
		return nil, nil, err
	}
	reply, err := responder.AcceptAttach(request)
	if err != nil {
		return nil, nil, err
	}
	pi, err := trial.PrepareSendRequest()
	if err != nil || !pi || reply[7]&1 == 0 {
		return nil, nil, ErrManagementState
	}
	ipr := []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0x83, 1, 0}
	s.cnosIPR = ipr
	s.cnosReply = reply
	s.cnos = responder
	s.pacing = &trial
	s.phase = ManagementCNOSPrepared
	return append([]byte(nil), ipr...), append([]byte(nil), reply...), nil
}

func (s *ManagementSession) MarkCNOSSent(ipr, reply []byte) error {
	if s.phase != ManagementCNOSPrepared || !bytes.Equal(ipr, s.cnosIPR) || !bytes.Equal(reply, s.cnosReply) {
		return ErrManagementState
	}
	if err := s.cnos.MarkReplyTransmitted(reply); err != nil {
		return err
	}
	if err := s.pacing.GrantReceiveWindow(); err != nil {
		return err
	}
	if err := s.pacing.MarkRequestSent(true); err != nil {
		return err
	}
	s.phase = ManagementAwaitCNOSAck
	return nil
}

func (s *ManagementSession) AckCNOS() error {
	if s.phase != ManagementAwaitCNOSAck || s.cnosAcks >= 2 {
		return ErrManagementState
	}
	s.cnosAcks++
	if s.cnosAcks == 2 {
		s.cnosIPR, s.cnosReply = nil, nil
		s.phase = ManagementCNOSComplete
	}
	return nil
}

func (s *ManagementSession) ReceiveIPR(data []byte) error {
	if s.phase != ManagementAwaitCNOSAck && s.phase != ManagementCNOSComplete {
		return ErrManagementState
	}
	if len(data) != 9 || data[0] != s.bindRequest[0] || data[1] != 0 || data[2] != s.bindRequest[2] || data[3] != s.bindRequest[3] ||
		!bytes.Equal(data[6:], []byte{0x83, 1, 0}) {
		return ErrManagementState
	}
	return s.pacing.ReceiveIPR()
}
