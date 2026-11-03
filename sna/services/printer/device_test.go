package printer

import (
	"bytes"
	"testing"
)

func TestLU4DeviceACTLUAndPrinterBind(t *testing.T) {
	d, err := NewLU4Device(1, 0x86)
	if err != nil {
		t.Fatal(err)
	}
	actlu := []byte{0x3d, 0x41, 0x73, 0x80, 0, 0x0d, 1, 1}
	wrongAddress := append([]byte(nil), actlu...)
	wrongAddress[1] = 0x42
	if _, err := d.Prepare(wrongAddress); err == nil {
		t.Fatal("another printer address was accepted")
	}
	response, err := d.Prepare(actlu)
	if err != nil || !bytes.Equal(response, []byte{0x3d, 0x41, 0xf3, 0x80, 0, 0x0d, 1, 1, 0, 0x84, 0, 0, 0}) {
		t.Fatalf("ACTLU response: %x %v", response, err)
	}
	if _, err := d.Prepare(actlu); err == nil || d.Phase() != DeviceAwaitACTLUAck {
		t.Fatal("advanced before ACTLU response was sent")
	}
	if err := d.MarkSent(response); err != nil || d.Phase() != DeviceAwaitBind {
		t.Fatalf("ACTLU send: %v", err)
	}
	bind := []byte{0x3d, 0xc1, 0x73, 0x80, 0,
		0x31, 0, 7, 7, 0xf0, 0xb0, 0x10, 0x81, 0, 7, 0x85, 0x85, 0, 7, 4, 0xc0,
		0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0}
	response, err = d.Prepare(bind)
	if err != nil || len(response) != len(bind) || response[2] != 0xf3 || d.Phase() != DeviceAwaitBindAck {
		t.Fatalf("printer BIND response: %x %v", response, err)
	}
	if err := d.MarkSent(response); err != nil || d.Phase() != DeviceBound {
		t.Fatalf("printer BIND send: %v", err)
	}
	fmd := []byte{0x3c, 0xc1, 0x03, 0x80, 0, 0xc1, 0xc2, 0x0c}
	if _, err := d.PrepareFMD(fmd, func([]byte) error { return ErrSCS }); err != ErrSCS || d.Phase() != DeviceBound {
		t.Fatalf("failed durable write acknowledged: phase=%d err=%v", d.Phase(), err)
	}
	var stored []byte
	response, err = d.PrepareFMD(fmd, func(data []byte) error { stored = append(stored, data...); return nil })
	if err != nil || !bytes.Equal(stored, fmd[5:]) || !bytes.Equal(response, []byte{0x3c, 0xc1, 0x83, 0x80, 0}) || d.Phase() != DeviceAwaitDataAck {
		t.Fatalf("printer FMD response before durable storage: response=%x stored=%x phase=%d err=%v", response, stored, d.Phase(), err)
	}
	if _, err := d.PrepareFMD(fmd, func([]byte) error { t.Fatal("duplicate chain accepted"); return nil }); err == nil {
		t.Fatal("next chain accepted before the response was sent")
	}
	if err := d.MarkSent(response); err != nil || d.Phase() != DeviceBound {
		t.Fatalf("printer FMD send: %v", err)
	}
}
