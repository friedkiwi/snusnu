package lu62

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestManagementSessionRequiresAcknowledgedEgress(t *testing.T) {
	bind, _ := hex.DecodeString("2f00010200006b850031001307b0b05133078786868707060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c7090301000000000000000c04e2d6d3d5c5e34be2d5c1c10a13000000000000000000000be2d6d3d5c5e34be2d5c1c2601411111111111111110b11111111111111111111112c0a00000000000000000000")
	cnos, _ := hex.DecodeString("2e00010200010b91200c0502ff0003d000000206f100191210020000000000080004000400084040404040404040")
	s, err := NewManagementSession("SOLNET.SNAA", "SOLNET.SNAB")
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.PrepareBind(bind)
	if err != nil || s.Phase() != ManagementBindPrepared {
		t.Fatalf("bind: %x %v", response, err)
	}
	if _, _, err := s.PrepareCNOS(cnos); !errors.Is(err, ErrManagementState) {
		t.Fatalf("early CNOS: %v", err)
	}
	wrong := append([]byte(nil), response...)
	wrong[2]++
	if err := s.MarkBindSent(wrong); !errors.Is(err, ErrManagementState) {
		t.Fatalf("wrong bind egress: %v", err)
	}
	if err := s.MarkBindSent(response); err != nil {
		t.Fatal(err)
	}
	if err := s.AckBind(); err != nil {
		t.Fatal(err)
	}
	ipr, reply, err := s.PrepareCNOS(cnos)
	if err != nil || !bytes.Equal(ipr, []byte{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0}) || len(reply) < 9 {
		t.Fatalf("CNOS: %x %x %v", ipr, reply, err)
	}
	if err := s.ReceiveIPR([]byte{0x2f, 0, 1, 2, 0, 0, 0x83, 1, 0}); !errors.Is(err, ErrManagementState) {
		t.Fatalf("pre-send IPR: %v", err)
	}
	if err := s.MarkCNOSSent(ipr, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.ReceiveIPR([]byte{0x2e, 0, 1, 2, 0, 0, 0x83, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if err := s.AckCNOS(); err != nil || s.Phase() != ManagementAwaitCNOSAck {
		t.Fatalf("first ACK: %v", err)
	}
	if err := s.AckCNOS(); err != nil || s.Phase() != ManagementCNOSComplete {
		t.Fatalf("second ACK: %v", err)
	}
	bis, _ := hex.DecodeString("2e00010200024b910070")
	if _, _, err := s.PrepareBIS(bis, 2, false); !errors.Is(err, ErrManagementState) {
		t.Fatalf("busy bracket: %v", err)
	}
	ipr, reply, err = s.PrepareBIS(bis, 2, true)
	if err != nil || !bytes.Equal(ipr, []byte{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0}) || !bytes.Equal(reply, []byte{0x2e, 0, 2, 1, 0, 2, 0x4b, 0xb0, 0, 0x70}) {
		t.Fatalf("BIS: %x %x %v", ipr, reply, err)
	}
	if err := s.MarkBISSent(ipr, reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckBIS(); err != nil {
		t.Fatal(err)
	}
	if err := s.AckBIS(); err != nil || s.Phase() != ManagementBISComplete {
		t.Fatalf("BIS ACK: %v", err)
	}
	unbind := append([]byte{0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0}, s.FQPCID()...)
	wrongUnbind := append([]byte(nil), unbind...)
	wrongUnbind[len(wrongUnbind)-1] ^= 1
	if _, err := s.PrepareUnbind(wrongUnbind); !errors.Is(err, ErrManagementState) {
		t.Fatalf("wrong FQPCID: %v", err)
	}
	reply, err = s.PrepareUnbind(unbind)
	if err != nil || !bytes.Equal(reply, []byte{0x2f, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x32}) {
		t.Fatalf("UNBIND: %x %v", reply, err)
	}
	if err := s.MarkUnbindSent(reply); err != nil {
		t.Fatal(err)
	}
	if err := s.AckUnbind(); err != nil || s.Phase() != ManagementClosed {
		t.Fatalf("UNBIND ACK: %v", err)
	}
}
