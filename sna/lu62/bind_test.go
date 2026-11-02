package lu62

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestCapturedManagementBindShape(t *testing.T) {
	// Sanitized V4R4 management BIND vector from the native router lab.
	data, err := hex.DecodeString("2d00010200006b800031001307b0b05133078786868707060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c7090301000000000000000c04e2d6d3d5c5e34be2d5c1c10a13000000000000000000000be2d6d3d5c5e34be2d5c1c2601411111111111111110b11111111111111111111112c0a00000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBind(data)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || b.PLU != "SOLNET.SNAA" || b.SLU != "SOLNET.SNAB" || b.Mode != "SNASVCMG" || !b.Management {
		t.Fatalf("unexpected classification: %+v", b)
	}
	data[9+26] = 1
	if _, err := ParseBind(data); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("cryptography gate: %v", err)
	}
}

func TestUserBindAndNonBind(t *testing.T) {
	data, err := hex.DecodeString("2d00020200006b800031001307b0b051330383c7c78303060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301000000000000000c04e2d6d3d5c5e34be2d5c1c10a13000000000000000000000be2d6d3d5c5e34be2d5c1c2601422222222222222220b22222222222222222222222c0a01087bc3d6d5d5c5c3e3")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBind(data)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || b.Management || b.Mode != "" || b.PLU != "SOLNET.SNAA" || b.SLU != "SOLNET.SNAB" {
		t.Fatalf("unexpected user BIND: %+v", b)
	}
	data[9] = 0x32
	b, err = ParseBind(data)
	if err != nil || b != nil {
		t.Fatalf("non-BIND: %+v, %v", b, err)
	}
}

func TestCandidateManagementResponse(t *testing.T) {
	request, _ := hex.DecodeString("2d00010200006b800031001307b0b05133078786868707060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c7090301000000000000000c04e2d6d3d5c5e34be2d5c1c10a13000000000000000000000be2d6d3d5c5e34be2d5c1c2601411111111111111110b11111111111111111111112c0a00000000000000000000")
	response, err := CandidateManagementResponse(request, "SOLNET.SNAA", "SOLNET.SNAB", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != 89 || response[2] != 2 || response[3] != 1 || response[6] != 0xeb || response[9] != 0x31 {
		t.Fatalf("response envelope: %x", response)
	}
	if _, err := CandidateManagementResponse(request, "OTHER.SNAA", "SOLNET.SNAB", 1); !errors.Is(err, ErrManagement) {
		t.Fatalf("identity gate: %v", err)
	}
}
