package lu62

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestUserSessionGatesFirstAttachOnBindAck(t *testing.T) {
	bind, _ := hex.DecodeString("2f00020200006b800031001307b0b051330383c7c78303060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301000000000000000c04e2d6d3d5c5e34be2d5c1c10a13000000000000000000000be2d6d3d5c5e34be2d5c1c2601422222222222222220b22222222222222222222222c0a01087bc3d6d5d5c5c3e3")
	management, _ := hex.DecodeString("601411111111111111110b1111111111111111111111")
	attach := []byte{0x2e, 0, 2, 2, 0, 1, 0x0a, 0x91, 0}
	ru := []byte{0x2f, 5, 2, 0xff, 0, 3, 0xd1, 0, 0x40, 6, 0xc1, 0xd7, 0xc9, 0xd5, 0xc7, 0xc4}
	for len(ru) < 47 {
		ru = append(ru, 0)
	}
	attach = append(attach, ru...)
	s, err := NewUserSession("SOLNET.SNAA", "SOLNET.SNAB", management)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.PrepareBind(bind)
	if err != nil || s.Phase() != UserBindPrepared {
		t.Fatalf("bind: %x %v", reply, err)
	}
	if _, _, err := s.PrepareAttach(attach); !errors.Is(err, ErrUserState) {
		t.Fatalf("early attach: %v", err)
	}
	if err := s.MarkBindSent(reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckBind(); err != nil {
		t.Fatal(err)
	}
	got, grant, err := s.PrepareAttach(attach)
	if err != nil || got.TPName != "APINGD" || !bytes.Equal(grant, []byte{0x2f, 0, 2, 2, 0, 0, 0x83, 1, 0}) {
		t.Fatalf("attach: %+v %x %v", got, grant, err)
	}
	bad := append([]byte(nil), grant...)
	bad[3]++
	if err := s.MarkAttachGrantSent(bad); !errors.Is(err, ErrUserState) {
		t.Fatalf("wrong grant: %v", err)
	}
	if err := s.MarkAttachGrantSent(grant); err != nil || s.Phase() != UserActive || s.TPName() != "APINGD" {
		t.Fatalf("active: %v", err)
	}
	version, _ := hex.DecodeString("000f12ff01022b02d6e261f4f0f000")
	request := append([]byte{0x2e, 0, 2, 2, 0, 2, 1, 0x95, 0x20}, version...)
	responseRU, _ := hex.DecodeString("000e12ff01022b024f532f343030")
	grant, reply, err = s.PrepareMappedTurn(request, responseRU)
	if err != nil || !bytes.Equal(grant, []byte{0x2f, 0, 2, 2, 0, 0, 0x83, 1, 0}) ||
		!bytes.Equal(reply, append([]byte{0x2e, 0, 2, 2, 0, 1, 3, 0x91, 0x20}, responseRU...)) {
		t.Fatalf("version turn: %x %x %v", grant, reply, err)
	}
	if err := s.MarkTurnSent(grant, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckTurn(); err != nil {
		t.Fatal(err)
	}
	if err := s.AckTurn(); err != nil || s.Phase() != UserActive {
		t.Fatalf("turn ACK: %v", err)
	}
	if err := s.ReceiveIPR([]byte{0x2e, 0, 2, 2, 0, 0, 0x83, 1, 0}); err != nil {
		t.Fatal(err)
	}
	packet, _ := hex.DecodeString("001412ff00000000000000000000000000000000")
	request = append([]byte{0x2e, 0, 2, 2, 0, 3, 3, 0x91, 0x20}, packet...)
	grant, reply, err = s.PrepareMappedTurn(request, packet)
	if err != nil || len(grant) != 9 || !bytes.Equal(reply, append([]byte{0x2e, 0, 2, 2, 0, 2, 3, 0x90, 0x20}, packet...)) {
		t.Fatalf("echo turn: %x %x %v", grant, reply, err)
	}
	if err := s.MarkTurnSent(grant, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckTurn(); err != nil {
		t.Fatal(err)
	}
	if err := s.AckTurn(); err != nil {
		t.Fatal(err)
	}
	noEcho, _ := hex.DecodeString("000812ff00000000000812ff00000000")
	request = append([]byte{0x2e, 0, 2, 2, 0, 4, 3, 0xa1, 0}, noEcho...)
	grant, reply, err = s.PrepareMappedTurn(request, nil)
	if err != nil || len(grant) != 9 || !bytes.Equal(reply, []byte{0x2e, 0, 2, 2, 0x80, 0, 0x83, 0xa0, 0}) {
		t.Fatalf("no-echo turn: %x %x %v", grant, reply, err)
	}
	if err := s.MarkTurnSent(grant, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckTurn(); err != nil {
		t.Fatal(err)
	}
	if err := s.AckTurn(); err != nil || s.Phase() != UserActive {
		t.Fatalf("no-echo ACK: %v", err)
	}
	confirm := []byte{0x2e, 0, 2, 2, 0, 5, 0x4b, 0xa0, 1, 4, 0, 6}
	grant, reply, err = s.PrepareConfirm(confirm)
	if err != nil || len(grant) != 0 || !bytes.Equal(reply, []byte{0x2e, 0, 2, 2, 0x80, 0, 0xcb, 0xa0, 0, 4}) {
		t.Fatalf("confirm: %x %x %v", grant, reply, err)
	}
	if err := s.MarkConfirmSent(grant, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckConfirm(); err != nil || s.Phase() != UserConfirmed {
		t.Fatalf("confirm ACK: %v", err)
	}
	bis := []byte{0x2e, 0, 2, 2, 0, 6, 0x4b, 0x91, 0, 0x70}
	grant, reply, err = s.PrepareBIS(bis)
	if err != nil || len(grant) != 9 || !bytes.Equal(reply, []byte{0x2e, 0, 2, 2, 0, 3, 0x4b, 0xb0, 0, 0x70}) {
		t.Fatalf("BIS: %x %x %v", grant, reply, err)
	}
	if err := s.MarkBISSent(grant, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckBIS(); err != nil {
		t.Fatal(err)
	}
	if err := s.AckBIS(); err != nil || s.Phase() != UserBISComplete {
		t.Fatalf("BIS ACK: %v", err)
	}
	unbind := append([]byte{0x2f, 0, 2, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}, s.FQPCID()...)
	reply, err = s.PrepareUnbind(unbind)
	if err != nil || !bytes.Equal(reply, []byte{0x2f, 0, 2, 2, 0, 0, 0xeb, 0x80, 0, 0x32}) {
		t.Fatalf("UNBIND: %x %v", reply, err)
	}
	if err := s.MarkUnbindSent(reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckUnbind(); err != nil || s.Phase() != UserClosed {
		t.Fatalf("UNBIND ACK: %v", err)
	}
}

func TestUserConfirmWithPacingAndExtendedClose(t *testing.T) {
	pacing, err := NewFixedPacing(3, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := &UserSession{phase: UserActive, bindRequest: []byte{0x2d, 0, 2, 2}, pacing: pacing, remoteSequence: 3}
	request := []byte{0x2c, 0, 2, 2, 0, 4, 0x4b, 0xa1, 1, 4, 0, 6, 0, 0}
	grant, reply, err := s.PrepareConfirm(request)
	if err != nil || !bytes.Equal(grant, []byte{0x2d, 0, 2, 2, 0, 0, 0x83, 1, 0}) ||
		!bytes.Equal(reply, []byte{0x2c, 0, 2, 2, 0x80, 0, 0xcb, 0xa0, 0, 4}) {
		t.Fatalf("extended confirm: %x %x %v", grant, reply, err)
	}
	if err := s.MarkConfirmSent(grant, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckConfirm(); err != nil || s.Phase() != UserAwaitConfirmAck {
		t.Fatalf("grant acknowledgement: %v", err)
	}
	if err := s.AckConfirm(); err != nil || s.Phase() != UserConfirmed {
		t.Fatalf("confirm acknowledgement: %v", err)
	}
}
