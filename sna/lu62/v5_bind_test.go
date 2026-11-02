package lu62

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// This is a V5R4 EE whole-BIU BIND reduced to SNF/RH/RU. Site names,
// session instance, and PCID were replaced with deterministic test values.
func TestSanitizedV5R4EEBindNegotiatesFixedPacing(t *testing.T) {
	encoded, err := os.ReadFile("testdata/v5r4_ee_bind_request.hex")
	if err != nil {
		t.Fatal(err)
	}
	reduced, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{0x2f, 0, 1, 2}, reduced...)
	bind, err := ParseBind(request)
	if err != nil || bind == nil || bind.PLU != "NETAAA.LUAA" || bind.SLU != "SNUSNU.PING" || bind.Mode != "" {
		t.Fatalf("sanitized V5 BIND classification: %+v, %v", bind, err)
	}
	if _, err := CandidateUserResponse(request, bind.PLU, bind.SLU, []byte{1}, 1); err != ErrUserBind {
		t.Fatalf("native V4 profile accepted V5 EE BIND: %v", err)
	}
	user, err := NewStandaloneUserSession(bind.PLU, bind.SLU)
	if err != nil {
		t.Fatal(err)
	}
	response, err := user.PrepareBind(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) < 40 || response[6] != 0xeb || response[9] != 0x31 || response[24] != 2 {
		t.Fatalf("invalid V5 RSP(BIND) envelope; bytes=%d", len(response))
	}
	// The responder selects fixed pacing and a bounded normal-flow RU size.
	ru := response[9:]
	if ru[8] != 3 || ru[9] != 1 || ru[10] != 0x8c || ru[11] != 0x8c || ru[12] != 0x81 || ru[13] != 3 || ru[25] != 0 {
		t.Fatalf("unexpected V5 pacing/security negotiation: %x", ru[:27])
	}
	if err := user.MarkBindSent(response); err != nil {
		t.Fatal(err)
	}
	if err := user.AckBind(); err != nil {
		t.Fatal(err)
	}
}
