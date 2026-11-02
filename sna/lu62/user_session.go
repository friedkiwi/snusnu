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
	UserTurnPrepared
	UserAwaitTurnAck
	UserConfirmPrepared
	UserAwaitConfirmAck
	UserConfirmed
	UserBISPrepared
	UserAwaitBISAck
	UserBISComplete
	UserUnbindPrepared
	UserAwaitUnbindAck
	UserClosed
)

// UserSession owns a single inbound LU 6.2 BIND and first FMH-5 Attach.
// The caller admits the named transaction program and owns conversation data.
type UserSession struct {
	remoteLU, localLU  string
	managementFQ       []byte
	standalone         bool
	phase              UserPhase
	bindRequest        []byte
	bindResponse       []byte
	bindFQPCID         []byte
	pacing             *FixedPacing
	attachGrant        []byte
	attachTP           string
	remoteSequence     uint16
	localSequence      uint16
	turnGrant          []byte
	turnReply          []byte
	turnPI             bool
	turnPositive       bool
	turnAcks           uint8
	turnAckGoal        uint8
	confirmGrant       []byte
	confirmReply       []byte
	confirmAcks        uint8
	bisGrant, bisReply []byte
	bisPI              bool
	bisAcks            uint8
	unbindReply        []byte
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

// NewStandaloneUserSession admits an LU session after its carrier adapter
// has completed CP/control-flow activation. Its BIND is still validated and
// correlated, but it has no native SNASVCMG FQPCID to compare against.
func NewStandaloneUserSession(remoteLU, localLU string) (*UserSession, error) {
	if _, err := encodeLUName(remoteLU); err != nil {
		return nil, err
	}
	if _, err := encodeLUName(localLU); err != nil || remoteLU == localLU {
		return nil, ErrUserState
	}
	return &UserSession{remoteLU: remoteLU, localLU: localLU, standalone: true}, nil
}

func (s *UserSession) Phase() UserPhase { return s.phase }
func (s *UserSession) TPName() string   { return s.attachTP }
func (s *UserSession) FQPCID() []byte   { return append([]byte(nil), s.bindFQPCID...) }

func (s *UserSession) PrepareBind(request []byte) ([]byte, error) {
	if s.phase != UserAwaitBind {
		return nil, ErrUserState
	}
	var response []byte
	var err error
	if s.standalone {
		response, err = CandidateStandaloneUserResponse(request, s.remoteLU, s.localLU, 1)
	} else {
		response, err = CandidateUserResponse(request, s.remoteLU, s.localLU, s.managementFQ, 1)
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
	s.remoteSequence = attachSequenceOne
	s.phase = UserActive
	return nil
}

const attachSequenceOne = 1

// PrepareMappedTurn handles one complete mapped-data PIU. The application
// validates its RU and supplies a response RU, or nil for a no-echo turn.
// A nil response is accepted only for the observed no-echo RH shape.
func (s *UserSession) PrepareMappedTurn(request, responseRU []byte) ([]byte, []byte, error) {
	if s.phase != UserActive || len(request) < 10 || len(request) > 1496 ||
		request[0]&2 != s.bindRequest[0]&2 || request[1] != 0 ||
		request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] ||
		uint16(request[4])<<8|uint16(request[5]) != s.remoteSequence+1 ||
		(request[6] != 1 && request[6] != 3) {
		return nil, nil, ErrUserState
	}
	noEcho := responseRU == nil
	if noEcho {
		if request[6] != 3 || request[7]&^byte(1) != 0xa0 || request[8] != 0 {
			return nil, nil, ErrUserState
		}
	} else if len(responseRU) == 0 || len(responseRU) > 1496-9 || request[7]&^byte(5) != 0x90 || request[8] != 0x20 {
		return nil, nil, ErrUserState
	}
	trial := *s.pacing
	if err := trial.ReceiveRequest(request[7]&1 != 0); err != nil {
		return nil, nil, err
	}
	var grant []byte
	if trial.GrantPending() {
		grant = []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0x83, 1, 0}
	}
	var reply []byte
	var pi bool
	if noEcho {
		reply = []byte{request[0], 0, s.bindRequest[3], s.bindRequest[2], 0x80, 0, 0x83, 0xa0, 0}
	} else {
		var err error
		pi, err = trial.PrepareSendRequest()
		if err != nil {
			return nil, nil, err
		}
		sequence := s.localSequence + 1
		reply = []byte{request[0], 0, s.bindRequest[3], s.bindRequest[2], byte(sequence >> 8), byte(sequence), 3, 0x90, 0x20}
		if pi {
			reply[7] |= 1
		}
		reply = append(reply, responseRU...)
	}
	s.pacing = &trial
	s.turnGrant, s.turnReply, s.turnPI, s.turnPositive = grant, reply, pi, noEcho
	s.phase = UserTurnPrepared
	return append([]byte(nil), grant...), append([]byte(nil), reply...), nil
}

func (s *UserSession) MarkTurnSent(grant, reply []byte) error {
	if s.phase != UserTurnPrepared || !bytes.Equal(grant, s.turnGrant) || !bytes.Equal(reply, s.turnReply) {
		return ErrUserState
	}
	if len(grant) != 0 {
		if err := s.pacing.GrantReceiveWindow(); err != nil {
			return err
		}
	}
	if len(reply) != 0 && !s.turnPositive {
		if err := s.pacing.MarkRequestSent(s.turnPI); err != nil {
			return err
		}
		s.localSequence++
	}
	s.remoteSequence++
	s.turnAckGoal = uint8(0)
	if len(grant) != 0 {
		s.turnAckGoal++
	}
	if len(reply) != 0 {
		s.turnAckGoal++
	}
	s.phase = UserAwaitTurnAck
	return nil
}

func (s *UserSession) AckTurn() error {
	if s.phase != UserAwaitTurnAck || s.turnAcks >= s.turnAckGoal {
		return ErrUserState
	}
	s.turnAcks++
	if s.turnAcks == s.turnAckGoal {
		s.turnGrant, s.turnReply = nil, nil
		s.turnPositive = false
		s.turnAcks, s.turnAckGoal = 0, 0
		s.phase = UserActive
	}
	return nil
}

func (s *UserSession) ReceiveIPR(data []byte) error {
	if s.phase != UserActive && s.phase != UserAwaitTurnAck {
		return ErrUserState
	}
	if !IsPacingResponse(data) || data[0]&^byte(1) != s.bindRequest[0]&^byte(1) || data[1] != 0 ||
		data[2] != s.bindRequest[2] || data[3] != s.bindRequest[3] ||
		data[4] != 0 || data[5] != 0 {
		return ErrUserState
	}
	return s.pacing.ReceiveIPR()
}

// PrepareConfirm answers the observed APPC CONFIRM/deallocate request only
// after every mapped-data response has drained from the transport.
func (s *UserSession) PrepareConfirm(request []byte) ([]byte, []byte, error) {
	if s.phase != UserActive || (len(request) != 12 && len(request) != 14) || request[0]&2 != s.bindRequest[0]&2 || request[1] != 0 ||
		request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] ||
		uint16(request[4])<<8|uint16(request[5]) != s.remoteSequence+1 ||
		request[6] != 0x4b || request[7]&^byte(1) != 0xa0 || request[8] != 1 ||
		!bytes.Equal(request[9:12], []byte{4, 0, 6}) ||
		(len(request) == 14 && !bytes.Equal(request[12:], []byte{0, 0})) {
		return nil, nil, ErrUserState
	}
	if request[7]&1 != 0 {
		trial := *s.pacing
		if err := trial.ReceiveRequest(true); err != nil {
			return nil, nil, err
		}
		if trial.GrantPending() {
			s.confirmGrant = []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0x83, 1, 0}
		}
		s.pacing = &trial
	}
	s.confirmReply = []byte{request[0], 0, s.bindRequest[3], s.bindRequest[2], 0x80, 0, 0xcb, 0xa0, 0, 4}
	s.phase = UserConfirmPrepared
	return append([]byte(nil), s.confirmGrant...), append([]byte(nil), s.confirmReply...), nil
}

func (s *UserSession) MarkConfirmSent(grant, reply []byte) error {
	if s.phase != UserConfirmPrepared || !bytes.Equal(grant, s.confirmGrant) || !bytes.Equal(reply, s.confirmReply) {
		return ErrUserState
	}
	if len(grant) != 0 {
		if err := s.pacing.GrantReceiveWindow(); err != nil {
			return err
		}
	}
	s.remoteSequence++
	s.phase = UserAwaitConfirmAck
	return nil
}

func (s *UserSession) AckConfirm() error {
	if s.phase != UserAwaitConfirmAck || s.confirmAcks >= 1+uint8(len(s.confirmGrant)/9) {
		return ErrUserState
	}
	s.confirmAcks++
	if s.confirmAcks == 1+uint8(len(s.confirmGrant)/9) {
		s.confirmGrant, s.confirmReply = nil, nil
		s.confirmAcks = 0
		s.phase = UserConfirmed
	}
	return nil
}

func (s *UserSession) PrepareBIS(request []byte) ([]byte, []byte, error) {
	if s.phase != UserConfirmed || len(request) != 10 || request[0]&2 != s.bindRequest[0]&2 || request[1] != 0 ||
		request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] ||
		uint16(request[4])<<8|uint16(request[5]) != s.remoteSequence+1 ||
		!bytes.Equal(request[6:], []byte{0x4b, 0x91, 0, 0x70}) {
		return nil, nil, ErrUserState
	}
	trial := *s.pacing
	if err := trial.ReceiveRequest(true); err != nil {
		return nil, nil, err
	}
	pi, err := trial.PrepareSendRequest()
	if err != nil {
		return nil, nil, err
	}
	sequence := s.localSequence + 1
	grant := []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0x83, 1, 0}
	reply := []byte{request[0], 0, s.bindRequest[3], s.bindRequest[2], byte(sequence >> 8), byte(sequence), 0x4b, 0xb0, 0, 0x70}
	if pi {
		reply[7] |= 1
	}
	s.pacing = &trial
	s.bisGrant, s.bisReply, s.bisPI = grant, reply, pi
	s.phase = UserBISPrepared
	return append([]byte(nil), grant...), append([]byte(nil), reply...), nil
}

func (s *UserSession) MarkBISSent(grant, reply []byte) error {
	if s.phase != UserBISPrepared || !bytes.Equal(grant, s.bisGrant) || !bytes.Equal(reply, s.bisReply) {
		return ErrUserState
	}
	if err := s.pacing.GrantReceiveWindow(); err != nil {
		return err
	}
	if err := s.pacing.MarkRequestSent(s.bisPI); err != nil {
		return err
	}
	s.remoteSequence++
	s.localSequence++
	s.phase = UserAwaitBISAck
	return nil
}

func (s *UserSession) AckBIS() error {
	if s.phase != UserAwaitBISAck || s.bisAcks >= 2 {
		return ErrUserState
	}
	s.bisAcks++
	if s.bisAcks == 2 {
		s.bisGrant, s.bisReply = nil, nil
		s.phase = UserBISComplete
	}
	return nil
}

func (s *UserSession) PrepareUnbind(request []byte) ([]byte, error) {
	if s.phase != UserBISComplete || len(request) != 15+len(s.bindFQPCID) ||
		request[0] != s.bindRequest[0] || request[1] != 0 || request[2] != s.bindRequest[2] || request[3] != s.bindRequest[3] ||
		!bytes.Equal(request[4:15], []byte{0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}) ||
		!bytes.Equal(request[15:], s.bindFQPCID) {
		return nil, ErrUserState
	}
	s.unbindReply = []byte{s.bindRequest[0], 0, s.bindRequest[3], s.bindRequest[2], 0, 0, 0xeb, 0x80, 0, 0x32}
	s.phase = UserUnbindPrepared
	return append([]byte(nil), s.unbindReply...), nil
}

func (s *UserSession) MarkUnbindSent(reply []byte) error {
	if s.phase != UserUnbindPrepared || !bytes.Equal(reply, s.unbindReply) {
		return ErrUserState
	}
	s.phase = UserAwaitUnbindAck
	return nil
}

func (s *UserSession) AckUnbind() error {
	if s.phase != UserAwaitUnbindAck {
		return ErrUserState
	}
	s.unbindReply = nil
	s.phase = UserClosed
	return nil
}
