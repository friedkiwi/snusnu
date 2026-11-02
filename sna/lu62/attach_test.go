package lu62

import (
	"errors"
	"testing"
)

func TestFirstAttachSelectsAPINGD(t *testing.T) {
	piu := []byte{0x2e, 0, 2, 2, 0, 1, 0x0a, 0x91, 0}
	ru := []byte{0x2f, 5, 2, 0xff, 0, 3, 0xd1, 0, 0x40, 6, 0xc1, 0xd7, 0xc9, 0xd5, 0xc7, 0xc4}
	for len(ru) < 47 {
		ru = append(ru, 0)
	}
	piu = append(piu, ru...)
	attach, err := ParseFirstAttach(piu)
	if err != nil || attach.TPName != "APINGD" || attach.Sequence != 1 {
		t.Fatalf("attach: %+v, %v", attach, err)
	}
	piu[9+9] = 65
	if _, err := ParseFirstAttach(piu); !errors.Is(err, ErrAttach) {
		t.Fatalf("bad name length: %v", err)
	}
}
