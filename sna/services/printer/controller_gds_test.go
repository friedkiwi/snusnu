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
