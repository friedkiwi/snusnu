package lu62

import (
	"bytes"
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

func TestLiveV5R4EESNASVCMGPingBindIsStandaloneOnly(t *testing.T) {
	encoded, err := os.ReadFile("testdata/v5r4_ee_snasvcmg_ping_bind.hex")
	if err != nil {
		t.Fatal(err)
	}
	reduced, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{0x2f, 0, 1, 2}, reduced...)
	bind, err := ParseBind(request)
	if err != nil || bind == nil || bind.PLU != "SOLNET.SNAB" || bind.SLU != "SNUSNU.PING" || bind.Mode != "SNASVCMG" {
		t.Fatalf("live EE BIND identity: %+v, %v", bind, err)
	}
	if _, err := CandidateUserResponse(request, bind.PLU, bind.SLU, []byte{1}, 1); err != ErrUserBind {
		t.Fatalf("native user path admitted SNASVCMG: %v", err)
	}
	if _, err := CandidateStandaloneUserResponse(request, bind.PLU, "SNUSNU.OTHER", 1); err != ErrUserBind {
		t.Fatalf("non-PING standalone path admitted SNASVCMG: %v", err)
	}
	cpBind := append([]byte(nil), request...)
	modeAt := bytes.Index(cpBind, snaSvcMode)
	if modeAt < 0 {
		t.Fatal("live BIND lacks mode field")
	}
	copy(cpBind[modeAt:modeAt+len(snaSvcMode)], []byte{0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7, 0x40}) // CPSVCMG
	if _, err := CandidateStandaloneUserResponse(cpBind, bind.PLU, bind.SLU, 1); err != ErrUserBind {
		t.Fatalf("standalone PING path admitted CPSVCMG: %v", err)
	}
	response, err := CandidateStandaloneUserResponse(request, bind.PLU, bind.SLU, 1)
	if err != nil {
		t.Fatal(err)
	}
	if response[6] != 0xeb || response[9] != 0x31 || response[9+9] != 1 || response[9+12] != 0x81 ||
		!bytes.Equal(response[9+23:9+26], []byte{0x94, 0x43, 0x40}) || response[2] != 2 || response[3] != 1 {
		t.Fatalf("invalid PING RSP(BIND) profile: %x", response)
	}
	if !bytes.Contains(response, snaSvcMode) || !bytes.Contains(response, []byte{0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4, 0x4b, 0xd7, 0xc9, 0xd5, 0xc7}) {
		t.Fatalf("PING RSP(BIND) lost mode or SLU: %x", response)
	}
	user, err := NewStandaloneUserSession(bind.PLU, bind.SLU)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.PrepareBind(request); err != nil {
		t.Fatalf("standalone PING session rejected live BIND: %v", err)
	}
}
