package lu62

import (
	"bytes"
	"errors"
)

var ErrUserState = errors.New("invalid LU 6.2 user session state")

type UserPhase uint8

const (
	UserAwaitBind UserPhase = iota
	UserBindPrepared
	UserAwaitBindAck
	UserAwaitAttach
	UserAttachGrantPrepared
	UserActive
)

// UserSession owns a single inbound LU 6.2 BIND and first FMH-5 Attach.
// The caller admits the named transaction program and owns conversation data.
type UserSession struct {
	remoteLU, localLU string
	managementFQ      []byte
	phase             UserPhase
	bindRequest       []byte
	bindResponse      []byte
	bindFQPCID        []byte
	pacing            *FixedPacing
	attachGrant       []byte
	attachTP          string
}

func NewUserSession(remoteLU, localLU string, managementFQPCID []byte) (*UserSession, error) {
	if _, err := encodeLUName(remoteLU); err != nil {
		return nil, err
	}
	if _, err := encodeLUName(localLU); err != nil || remoteLU == localLU || len(managementFQPCID) == 0 {
		return nil, ErrUserState
	}
	return &UserSession{remoteLU: remoteLU, localLU: localLU, managementFQ: append([]byte(nil), managementFQPCID...)}, nil
}

func (s *UserSession) Phase() UserPhase { return s.phase }
func (s *UserSession) TPName() string   { return s.attachTP }
func (s *UserSession) FQPCID() []byte   { return append([]byte(nil), s.bindFQPCID...) }

func (s *UserSession) PrepareBind(request []byte) ([]byte, error) {
	if s.phase != UserAwaitBind {
		return nil, ErrUserState
	}
	response, err := CandidateUserResponse(request, s.remoteLU, s.localLU, s.managementFQ, 1)
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
	s.phase = UserBindPrepared
	return append([]byte(nil), response...), nil
}

func (s *UserSession) MarkBindSent(response []byte) error {
	if s.phase != UserBindPrepared || !bytes.Equal(response, s.bindResponse) {
		return ErrUserState
	}
	s.phase = UserAwaitBindAck
	return nil
}

func (s *UserSession) AckBind() error {
	if s.phase != UserAwaitBindAck {
		return ErrUserState
	}
	pacing, err := NewFixedPacing(3, 1)
	if err != nil {
		return err
	}
	s.pacing = pacing
	s.bindResponse = nil
	s.phase = UserAwaitAttach
	return nil
}

// PrepareAttach validates the first FMH-5 and prepares an IPR for its
// one-frame receive window. The adapter authorizes TPName before sending it.
func (s *UserSession) PrepareAttach(request []byte) (*Attach, []byte, error) {
	if s.phase != UserAwaitAttach || len(request) < 9 || request[0]&2 != s.bindRequest[0]&2 {
		return nil, nil, ErrUserState
	}
	attach, err := ParseFirstAttach(request)
	if err != nil || attach == nil || attach.DAF != s.bindRequest[2] || attach.OAF != s.bindRequest[3] {
		return nil, nil, ErrUserState
	}
	trial := *s.pacing
	if err := trial.ReceiveRequest(request[7]&1 != 0); err != nil {
		return nil, nil, err
	}
	s.attachGrant = []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0x83, 1, 0}
	s.attachTP = attach.TPName
	s.pacing = &trial
	s.phase = UserAttachGrantPrepared
	return attach, append([]byte(nil), s.attachGrant...), nil
}

func (s *UserSession) MarkAttachGrantSent(grant []byte) error {
	if s.phase != UserAttachGrantPrepared || !bytes.Equal(grant, s.attachGrant) {
		return ErrUserState
	}
	if err := s.pacing.GrantReceiveWindow(); err != nil {
		return err
	}
	s.attachGrant = nil
	s.phase = UserActive
	return nil
}
