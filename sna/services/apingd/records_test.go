package apingd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestV4R4APINGVersionAndEcho(t *testing.T) {
	request, _ := hex.DecodeString("000f12ff01022b02d6e261f4f0f000")
	want, _ := hex.DecodeString("000e12ff01022b024f532f343030")
	got, err := VersionResponse(request, "OS/400")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("version: %x, %v", got, err)
	}
	packet, _ := hex.DecodeString("001412ff00000000000000000000000000000000")
	result, err := Echo([][]byte{packet})
	if err != nil || !bytes.Equal(result[0], packet) {
		t.Fatalf("echo: %x, %v", result, err)
	}
	packet[3] = 0
	if result[0][3] != 0xff {
		t.Fatal("echo aliases caller buffer")
	}
}

func TestRejectMalformedRecords(t *testing.T) {
	for _, input := range [][]byte{{}, {0}, {0, 4, 1}, {0, 2, 0}} {
		if _, err := Echo([][]byte{input}); !errors.Is(err, ErrRecord) {
			t.Fatalf("%x: %v", input, err)
		}
	}
	if _, err := VersionResponse([]byte{0, 2}, "SNUSNU"); !errors.Is(err, ErrRecord) {
		t.Fatal(err)
	}
}
