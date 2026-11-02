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
}
