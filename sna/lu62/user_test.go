package lu62

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestCandidateUserResponse(t *testing.T) {
	request, _ := hex.DecodeString("2d00020200006b800031001307b0b051330383c7c78303060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301000000000000000c04e2d6d3d5c5e34be2d5c1c10a13000000000000000000000be2d6d3d5c5e34be2d5c1c2601422222222222222220b22222222222222222222222c0a01087bc3d6d5d5c5c3e3")
	management, _ := hex.DecodeString("601411111111111111110b1111111111111111111111")
	response, err := CandidateUserResponse(request, "SOLNET.SNAA", "SOLNET.SNAB", management, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != 89 || response[2] != 2 || response[3] != 2 || response[6] != 0xeb || response[9] != 0x31 {
		t.Fatalf("response envelope: %x", response)
	}
	fq, err := RequestFQPCID(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CandidateUserResponse(request, "SOLNET.SNAA", "SOLNET.SNAB", fq, 1); !errors.Is(err, ErrUserBind) {
		t.Fatalf("reused management FQPCID: %v", err)
	}
	if _, err := CandidateUserResponse(request, "SOLNET.SNAA", "SOLNET.SNAB", management, 4); !errors.Is(err, ErrUserBind) {
		t.Fatalf("unsupported pacing: %v", err)
	}
}
