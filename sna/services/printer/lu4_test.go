package printer

import (
	"bytes"
	"testing"
)

func TestLU4PrinterAddressAndACTLU(t *testing.T) {
	for _, tc := range []struct {
		wire    []byte
		address byte
		session LU4Session
	}{
		{[]byte{0x3d, 0x41, 0x73, 0x80, 0, 0x0d, 1, 1}, 1, LU4SystemSession},
		{[]byte{0x3d, 0x78, 0x6b, 0x80, 0, 0x0d, 1, 1}, 56, LU4SystemSession},
		{[]byte{0x3d, 0xc1, 0x73, 0x80, 0, 0x31}, 1, LU4PrintSession},
		{[]byte{0x3c, 0xc2, 0x03, 0x80, 0x20, 0xc8}, 2, LU4PrintSession},
	} {
		piu, err := ParseLU4PIU(tc.wire)
		if err != nil || piu.Address != tc.address || piu.Session != tc.session {
			t.Fatalf("parse %x: %+v %v", tc.wire, piu, err)
		}
		encoded, err := piu.Encode()
		if err != nil || !bytes.Equal(encoded, tc.wire) {
			t.Fatalf("roundtrip %x: %x %v", tc.wire, encoded, err)
		}
	}
	response, err := ACTLUResponseRU([]byte{0x0d, 1, 1})
	if err != nil || !bytes.Equal(response, []byte{0x0d, 1, 1, 0, 0x84, 0, 0, 0}) {
		t.Fatalf("ACTLU: %x %v", response, err)
	}
	if _, err := ACTLUResponseRU([]byte{0x0d, 1, 2}); err == nil {
		t.Fatal("unsupported ACTLU accepted")
	}
}

func TestLU4RejectsInvalidHeader(t *testing.T) {
	for _, data := range [][]byte{
		{0x3c, 0xc1, 0x03, 0x80},
		{0x2c, 0xc1, 0x03, 0x80, 0},
		{0x3c, 0x81, 0x03, 0x80, 0},
		{0x3c, 0xc1, 0x0b, 0x80, 0},
		{0x3c, 0xc1, 0x03, 0x80, 0x10},
	} {
		if _, err := ParseLU4PIU(data); err == nil {
			t.Fatalf("accepted %x", data)
		}
	}
}

func TestLU4PrinterBindClassification(t *testing.T) {
	piu := LU4PIU{Address: 1, Session: LU4PrintSession, Expedited: true, RH: [3]byte{0x73, 0x80, 0}}
	piu.RU = []byte{0x31, 0, 7, 7, 0xf0, 0xb0, 0x10, 0x81, 0, 7, 0x85, 0x85, 0, 7, 4, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0}
	if !IsPrinterBind(piu) {
		t.Fatal("IBM 5494 LU4 printer BIND not classified")
	}
	response, err := CandidatePrinterBindResponseRU(piu, 0x86)
	if err != nil || response[9] != 7 || response[10] != 0x85 || response[11] != 0x85 || response[25] != 0 {
		t.Fatalf("printer BIND response: %x %v", response, err)
	}
	positive, err := PositiveLU4Response(piu, response)
	if err != nil || !positive.Response || positive.RH != [3]byte{0xf3, 0x80, 0} || positive.Address != 1 {
		t.Fatalf("positive BIND response: %+v %v", positive, err)
	}
	if _, err := positive.Encode(); err != nil {
		t.Fatalf("encode positive BIND response: %v", err)
	}
	last := LU4PIU{Address: 1, Session: LU4PrintSession, RH: [3]byte{1, 0x80, 0x20}, RU: []byte{0xc8}}
	if reply, err := PositiveLU4Response(last, nil); err != nil || reply.RH != [3]byte{0x83, 0x80, 0} {
		t.Fatalf("last-of-chain response: %+v %v", reply, err)
	}
	piu.RU[14] = 7
	if IsPrinterBind(piu) {
		t.Fatal("display BIND classified as printer")
	}
}
