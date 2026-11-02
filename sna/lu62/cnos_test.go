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
