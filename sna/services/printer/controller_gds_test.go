package printer

import (
	"bytes"
	"testing"
)

func TestControllerDeviceGDSCapturedACTLU(t *testing.T) {
	request := []byte{0, 12, 0xd8, 0x24, 0x3d, 0x78, 0x6b, 0x80, 0, 0x0d, 1, 1}
	p, err := ParseControllerDeviceGDS(request)
	if err != nil || p.Address != 56 || p.Session != LU4SystemSession || !p.Expedited || !bytes.Equal(p.RU, []byte{0x0d, 1, 1}) {
		t.Fatalf("captured controller ACTLU: %+v %v", p, err)
	}
	encoded, err := EncodeControllerDeviceGDS(p)
	if err != nil || !bytes.Equal(encoded, request) {
		t.Fatalf("controller GDS round trip: %x %v", encoded, err)
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[1]-- },
		func(b []byte) { b[3] = 0x22 },
		func(b []byte) { b[4] = 0x2e },
	} {
		bad := append([]byte(nil), request...)
		change(bad)
		if _, err := ParseControllerDeviceGDS(bad); err == nil {
			t.Fatalf("invalid controller GDS accepted: %x", bad)
		}
	}
}

func TestControllerGDSCapturedRequestPSID(t *testing.T) {
	request := []byte{0, 0x1a, 0xd8, 0x24, 0x3c, 0, 0x0b, 0x80, 0,
		0x41, 3, 0x8d, 0, 0, 0, 1, 0, 0, 9, 0x80, 0x90, 2, 0x83, 3, 0x85, 1}
	p, err := ParseControllerDeviceGDS(request)
	if err != nil || p.Address != 0 || p.Session != LU4PhysicalSession || p.Response ||
		!bytes.Equal(p.RU, request[9:]) {
		t.Fatalf("captured Request PSID: %+v %v", p, err)
	}
	encoded, err := EncodeControllerDeviceGDS(p)
	if err != nil || !bytes.Equal(encoded, request) {
		t.Fatalf("Request PSID round trip: %x %v", encoded, err)
	}
	response, err := PositiveLU4Response(p, []byte{0x41, 3, 0x8d})
	if err != nil || response.RH != [3]byte{0x8b, 0x80, 0} {
		t.Fatalf("Request PSID positive response: %+v %v", response, err)
	}
}

func TestControllerDeviceGDSV5R4PrintRecord(t *testing.T) {
	// V5R4 sends a 1408-byte D824 record after accepting its B7/B7 BIND.
	raw := make([]byte, 1399)
	raw[0] = 0x2b
	raw[1] = 0xd1
	p := LU4PIU{Address: 1, Session: LU4PrintSession, RH: [3]byte{0x03, 0x80, 0}, RU: raw}
	encoded, err := EncodeControllerDeviceGDS(p)
	if err != nil || len(encoded) != 1408 {
		t.Fatalf("encode V5R4-sized print record: len=%d err=%v", len(encoded), err)
	}
	decoded, err := ParseControllerDeviceGDS(encoded)
	if err != nil || !bytes.Equal(decoded.RU, raw) {
		t.Fatalf("decode V5R4-sized print record: len=%d err=%v", len(decoded.RU), err)
	}
}
