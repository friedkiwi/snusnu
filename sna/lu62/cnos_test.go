package lu62

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCapturedCNOSSetLimits(t *testing.T) {
	request, _ := hex.DecodeString("2e00010200010b91200c0502ff0003d000000206f100191210020000000000080004000400084040404040404040")
	want, _ := hex.DecodeString("2e0002010001039101001912100a0000000000080004000400084040404040404040")
	r, err := NewCNOSResponder("", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.AcceptAttach(request)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("CNOS reply: %x, %v", got, err)
	}
	if r.Complete() {
		t.Fatal("pending reply counted as complete")
	}
	if err := r.MarkReplyTransmitted(got); err != nil || !r.Complete() {
		t.Fatalf("completion: %v", err)
	}
	if _, err := r.AcceptAttach(request); err == nil {
		t.Fatal("duplicate CNOS")
	}
}

func TestOutboundQRMTWSCCNOSReply(t *testing.T) {
	want, err := New5494ControllerCNOS(56)
	if err != nil {
		t.Fatal(err)
	}
	request, err := CandidateCNOSAttach(1, 2, 1, want)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewCNOSResponder("QRMTWSC", 57)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := responder.AcceptAttach(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateCNOSReply(request, reply)
	if err != nil || got.SessionLimit != 57 || got.SourceWinners != 1 || got.TargetWinners != 56 || got.Mode != "QRMTWSC" {
		t.Fatalf("CNOS acceptance: %+v %v", got, err)
	}
	if got.Service != 0x0a || got.ModeWidth != 8 || !bytes.Equal(request[9:24], []byte{0x0f, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1, 0, 0, 0}) ||
		!bytes.Equal(request[24:41], []byte{0, 0x19, 0x12, 0x10, 2, 0, 0, 0, 0, 0, 57, 0, 1, 0, 56, 0, 8}) {
		t.Fatalf("5494 source CNOS fields: %x %+v", request, got)
	}
	if _, err := New5494ControllerCNOS(57); err == nil {
		t.Fatal("more than 56 device sessions accepted")
	}
	badRoute := append([]byte(nil), reply...)
	badRoute[2] = 3
	if _, err := ValidateCNOSReply(request, badRoute); err == nil {
		t.Fatal("reply from a different session accepted")
	}
	badAttach := append([]byte(nil), request...)
	badAttach[23] = 1
	if _, err := ValidateCNOSReply(badAttach, reply); err == nil {
		t.Fatal("malformed firmware Attach accepted")
	}
	badLimit := append([]byte(nil), reply...)
	badLimit[9+9], badLimit[9+10] = 0, 58
	if _, err := ValidateCNOSReply(request, badLimit); err == nil {
		t.Fatal("expanded session limit accepted")
	}
}
