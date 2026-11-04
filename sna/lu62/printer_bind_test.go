package lu62

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Captured from the disposable V5R4 guest after its solicited 3812 Reply-PSID.
// The guest advanced to FMH-5 Attach only after receiving this response profile.
func TestCandidate5494DeviceResponseV5R4(t *testing.T) {
	request, err := hex.DecodeString("2d00010200006b800031001307b0b051330787c7c78707060200000000000000944340000fe2d6d3d5c5e34be2f1f0f5f4f5f0f430000802d8d9d4e3e6e2c3090301277e1ce3ad00001004e2d6d3d5c5e34be2f1f0f5f4f5f0f40a1300b0277e1ce3ad0000000ae2d5e4e2d5e44be2e5c36018d35b3e4ae16488820fe2d6d3d5c5e34bd7d9e3c7e4c5e2e32c0a01087bc3d6d5d5c5c3e3")
	if err != nil {
		t.Fatal(err)
	}
	response, err := Candidate5494DeviceResponse(request, "SOLNET.S1054504", "SNUSNU.SVC", 1)
	if err != nil {
		t.Fatal(err)
	}
	if response[2] != 2 || response[3] != 1 || response[9+23] != 0x90 || response[9+24] != 0x23 ||
		response[9+28] != 25 || response[9+30] != 8 {
		t.Fatalf("unexpected V5R4 device response: %x", response)
	}
	fq, err := RequestFQPCID(request)
	if err != nil || len(response) < len(fq) ||
		!bytes.Equal(response[len(response)-len(fq):], fq) {
		t.Fatalf("response lost FQPCID: %x %v", response, err)
	}
}
