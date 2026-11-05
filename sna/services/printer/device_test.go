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

func TestLU4DeviceV5R4PrinterBind(t *testing.T) {
	d, err := NewLU4Device(1, 0xb7)
	if err != nil {
		t.Fatal(err)
	}
	actlu, err := d.Prepare([]byte{0x3d, 0x41, 0x6b, 0x80, 0, 0x0d, 1, 1})
	if err != nil || d.MarkSent(actlu) != nil {
		t.Fatalf("ACTLU setup: %x %v", actlu, err)
	}
	// Captured from the V5R4 writer after its paced ACTLU exchange.
	bind := []byte{0x3d, 0xc1, 0x6b, 0x80, 0,
		0x31, 0, 7, 7, 0xb0, 0xb0, 0x10, 0x81, 0, 7, 0xb7, 0xb7, 0, 0, 4, 0xc0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	response, err := d.Prepare(bind)
	if err != nil {
		t.Fatal(err)
	}
	if response[2] != 0xeb || response[9] != 0xb0 || response[15] != 0xb7 || response[16] != 0xb7 || response[28] != 0 {
		t.Fatalf("unexpected BIND negotiation: %x", response)
	}
	if err := d.MarkSent(response); err != nil || d.Phase() != DeviceBound {
		t.Fatalf("BIND send: %v", err)
	}
	unbind, err := d.Prepare([]byte{0x3d, 0xc1, 0x63, 0x80, 0, 0x32, 0x06})
	if err != nil || !bytes.Equal(unbind, []byte{0x3d, 0xc1, 0xe3, 0x80, 0, 0x32}) {
		t.Fatalf("UNBIND response: %x %v", unbind, err)
	}
	if err := d.MarkSent(unbind); err != nil || d.Phase() != DeviceAwaitBind {
		t.Fatalf("UNBIND send: %v", err)
	}
}

func TestLU4DeviceMultiPIUPrintChainWaitsForDurableWrite(t *testing.T) {
	d, err := NewLU4Device(1, 0x86)
	if err != nil {
		t.Fatal(err)
	}
	actlu, err := d.Prepare([]byte{0x3d, 0x41, 0x73, 0x80, 0, 0x0d, 1, 1})
	if err != nil || d.MarkSent(actlu) != nil {
		t.Fatal("ACTLU setup failed")
	}
	bind := []byte{0x3d, 0xc1, 0x73, 0x80, 0,
		0x31, 0, 7, 7, 0xf0, 0xb0, 0x10, 0x81, 0, 7, 0x85, 0x85, 0, 7, 4, 0xc0,
		0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0}
	bound, err := d.Prepare(bind)
	if err != nil || d.MarkSent(bound) != nil {
		t.Fatal("BIND setup failed")
	}
	assembler, err := NewChainAssembler(32)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte{0x3c, 0xc1, 0x02, 0, 0, 0xc1, 0xc2}
	last := []byte{0x3c, 0xc1, 0x01, 0x80, 0, 0x0c}
	for i, piu := range [][]byte{first, last} {
		parsed, err := ParseLU4PIU(piu)
		if err != nil {
			t.Fatal(err)
		}
		scs, done, err := assembler.Feed(parsed)
		if err != nil || done != (i == 1) {
			t.Fatalf("chain fragment %d: done=%t err=%v", i, done, err)
		}
		if !done {
			continue
		}
		if _, err := d.PrepareFMD(last, func([]byte) error { t.Fatal("partial chain accepted"); return nil }); err == nil {
			t.Fatal("accepted last PIU as a complete chain")
		}
		if _, err := d.PrepareFMDChain(last, []byte{0xc1, 0x0d}, func([]byte) error { t.Fatal("wrong chain accepted"); return nil }); err == nil {
			t.Fatal("accepted mismatched chain data")
		}
		if _, err := d.PrepareFMDChain(last, scs, func([]byte) error { return ErrSCS }); err != ErrSCS || d.Phase() != DeviceBound {
			t.Fatalf("failed write acknowledged: phase=%d err=%v", d.Phase(), err)
		}
		var stored []byte
		response, err := d.PrepareFMDChain(last, scs, func(data []byte) error { stored = append(stored, data...); return nil })
		if err != nil || !bytes.Equal(stored, []byte{0xc1, 0xc2, 0x0c}) || !bytes.Equal(response, []byte{0x3c, 0xc1, 0x83, 0x80, 0}) {
			t.Fatalf("chain response: response=%x stored=%x err=%v", response, stored, err)
		}
		if err := d.MarkSent(response); err != nil || d.Phase() != DeviceBound {
			t.Fatalf("chain response send: phase=%d err=%v", d.Phase(), err)
		}
	}
	// An exception-response chain asks for a response only on failure. It
	// still has to reach durable storage before the device accepts it.
	exception := []byte{0x3c, 0xc1, 0x03, 0x90, 0x20, 0xc3, 0x0c}
	if _, err := d.PrepareFMD(exception, func([]byte) error { return ErrSCS }); err != ErrSCS || d.Phase() != DeviceBound {
		t.Fatalf("exception-response write failure: phase=%d err=%v", d.Phase(), err)
	}
	var stored []byte
	response, err := d.PrepareFMD(exception, func(data []byte) error { stored = append(stored, data...); return nil })
	if err != nil || len(response) != 0 || !bytes.Equal(stored, []byte{0xc3, 0x0c}) || d.Phase() != DeviceBound {
		t.Fatalf("exception-response acceptance: response=%x stored=%x phase=%d err=%v", response, stored, d.Phase(), err)
	}
}
