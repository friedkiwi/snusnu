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
	ManagementBISPrepared
	ManagementAwaitBISAck
	ManagementBISComplete
	ManagementUnbindPrepared
	ManagementAwaitUnbindAck
	ManagementClosed
)

// ManagementSession owns one responder-side SNASVCMG BIND and CNOS exchange.
// A transport adapter must call the Mark and Ack methods only after exact
// outbound PIUs have been accepted and then acknowledged by its link.
type ManagementSession struct {
	remoteCP, localCP string
	mode              string
	maxSessions       uint16
	standalone        bool
	primaryWindow     byte
	phase             ManagementPhase
	bindRequest       []byte
	bindResponse      []byte
	bindFQPCID        []byte
	cnos              *CNOSResponder
	pacing            *FixedPacing
	cnosIPR           []byte
	cnosReply         []byte
	cnosAcks          uint8
	cnosTH0           byte
	bisIPR, bisReply  []byte
	bisPI             bool
	bisAcks           uint8
	unbindReply       []byte
}

func NewManagementSession(remoteCP, localCP string) (*ManagementSession, error) {
	return NewManagementSessionWithMode(remoteCP, localCP, "", 8)
}

// NewManagementSessionWithMode serves a specifically configured CNOS mode.
// The 5494 controller uses QRMTWSC with 57 sessions; ordinary management
// sessions retain the blank-mode default through NewManagementSession.
func NewManagementSessionWithMode(remoteCP, localCP, mode string, maxSessions uint16) (*ManagementSession, error) {
	if _, err := encodeLUName(remoteCP); err != nil {
		return nil, err
	}
	if _, err := encodeLUName(localCP); err != nil || remoteCP == localCP {
		return nil, ErrManagementState
	}
	if _, err := NewCNOSResponder(mode, maxSessions); err != nil {
		return nil, err
	}
	return &ManagementSession{remoteCP: remoteCP, localCP: localCP, mode: mode, maxSessions: maxSessions, primaryWindow: 7}, nil
}

// NewStandaloneManagementSession serves an application LU after the carrier
// adapter has established CP control flow. The caller authorizes localLU;
// this session is distinct from any later user session.
func NewStandaloneManagementSession(remoteCP, localLU string) (*ManagementSession, error) {
	s, err := NewManagementSession(remoteCP, localLU)
	if err != nil {
		return nil, err
	}
	s.standalone = true
	return s, nil
}

func (s *ManagementSession) Phase() ManagementPhase { return s.phase }

func (s *ManagementSession) FQPCID() []byte {
	return append([]byte(nil), s.bindFQPCID...)
}

func (s *ManagementSession) PrepareBind(request []byte) ([]byte, error) {
	if s.phase != ManagementAwaitBind {
		return nil, ErrManagementState
	}
	var response []byte
	var err error
	if s.standalone {
		bind, parseErr := ParseBind(request)
		if parseErr != nil || bind == nil || bind.Mode != "SNASVCMG" {
			return nil, ErrManagementState
		}
		response, err = CandidateStandaloneUserResponse(request, s.remoteCP, s.localCP, 1)
	} else {
		response, err = CandidateManagementResponse(request, s.remoteCP, s.localCP, 1)
	}
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
	pacing, err := NewFixedPacing(s.primaryWindow, 1)
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
	responder, err := NewCNOSResponder(s.mode, s.maxSessions)
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
	s.cnosTH0 = request[0]
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
	// V4R4 may return the IPR on the normal-flow TH used by CNOS,
	// rather than the expedited-flow TH used by the BIND.
	if !IsPacingResponse(data) || data[0]&^byte(1) != s.bindRequest[0]&^byte(1) || data[1] != 0 || data[2] != s.bindRequest[2] || data[3] != s.bindRequest[3] || data[4] != 0 || data[5] != 0 {
		return ErrManagementState
	}
	return s.pacing.ReceiveIPR()
}

// PrepareBIS accepts the remote bilateral shutdown request after CNOS. The
// local bracket must be empty and the caller chooses its own nonzero sequence.
func (s *ManagementSession) PrepareBIS(request []byte, localSequence uint16, bracketFree bool) ([]byte, []byte, error) {
	if s.phase != ManagementCNOSComplete || !bracketFree || localSequence == 0 || len(request) != 10 ||
		request[0] != s.cnosTH0 || request[1] != 0 || request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] ||
		request[4] == 0 && request[5] == 0 || !bytes.Equal(request[6:], []byte{0x4b, 0x91, 0, 0x70}) {
		return nil, nil, ErrManagementState
	}
	trial := *s.pacing
	if err := trial.ReceiveRequest(true); err != nil {
		return nil, nil, err
	}
	pi, err := trial.PrepareSendRequest()
	if err != nil {
		return nil, nil, err
	}
	ipr := []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0x83, 1, 0}
	reply := []byte{s.cnosTH0, 0, s.bindRequest[3], s.bindRequest[2], byte(localSequence >> 8), byte(localSequence), 0x4b, 0xb0, 0, 0x70}
	if pi {
		reply[7] |= 1
	}
	s.pacing = &trial
	s.bisIPR, s.bisReply, s.bisPI = ipr, reply, pi
	s.phase = ManagementBISPrepared
	return append([]byte(nil), ipr...), append([]byte(nil), reply...), nil
}

func (s *ManagementSession) MarkBISSent(ipr, reply []byte) error {
	if s.phase != ManagementBISPrepared || !bytes.Equal(ipr, s.bisIPR) || !bytes.Equal(reply, s.bisReply) {
		return ErrManagementState
	}
	if err := s.pacing.GrantReceiveWindow(); err != nil {
		return err
	}
	if err := s.pacing.MarkRequestSent(s.bisPI); err != nil {
		return err
	}
	s.phase = ManagementAwaitBISAck
	return nil
}

func (s *ManagementSession) AckBIS() error {
	if s.phase != ManagementAwaitBISAck || s.bisAcks >= 2 {
		return ErrManagementState
	}
	s.bisAcks++
	if s.bisAcks == 2 {
		s.bisIPR, s.bisReply = nil, nil
		s.phase = ManagementBISComplete
	}
	return nil
}

func (s *ManagementSession) PrepareUnbind(request []byte) ([]byte, error) {
	if s.phase != ManagementBISComplete || len(request) != 15+len(s.bindFQPCID) ||
		request[0] != s.bindRequest[0] || request[1] != 0 || request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] ||
		!bytes.Equal(request[4:15], []byte{0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}) ||
		!bytes.Equal(request[15:], s.bindFQPCID) {
		return nil, ErrManagementState
	}
	s.unbindReply = []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0xeb, 0x80, 0, 0x32}
	s.phase = ManagementUnbindPrepared
	return append([]byte(nil), s.unbindReply...), nil
}

func (s *ManagementSession) MarkUnbindSent(reply []byte) error {
	if s.phase != ManagementUnbindPrepared || !bytes.Equal(reply, s.unbindReply) {
		return ErrManagementState
	}
	s.phase = ManagementAwaitUnbindAck
	return nil
}

func (s *ManagementSession) AckUnbind() error {
	if s.phase != ManagementAwaitUnbindAck {
		return ErrManagementState
	}
	s.unbindReply = nil
	s.phase = ManagementClosed
	return nil
}
