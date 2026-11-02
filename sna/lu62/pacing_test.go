package lu62

import "testing"

func TestPacingResponseForms(t *testing.T) {
	for _, data := range [][]byte{
		{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0},
		{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0, 0, 0, 3},
		{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0, 0, 0, 6},
	} {
		if !IsPacingResponse(data) {
			t.Fatalf("rejected observed pacing response: %x", data)
		}
	}
	for _, data := range [][]byte{
		{0x2f, 0, 2, 1, 0, 0, 0x83, 1},
		{0x2f, 0, 2, 1, 0, 0, 0x83, 1, 0, 0, 0, 7},
	} {
		if IsPacingResponse(data) {
			t.Fatalf("accepted malformed pacing response: %x", data)
		}
	}
}

func TestFixedPacingNeedsExplicitWindowGrants(t *testing.T) {
	p, err := NewFixedPacing(3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ReceiveRequest(false); err == nil {
		t.Fatal("accepted missing PI")
	}
	if err := p.ReceiveRequest(true); err != nil {
		t.Fatal(err)
	}
	if err := p.ReceiveRequest(true); err == nil {
		t.Fatal("accepted without grant")
	}
	if err := p.GrantReceiveWindow(); err != nil {
		t.Fatal(err)
	}
	if err := p.ReceiveRequest(true); err != nil {
		t.Fatal(err)
	}
	pi, err := p.PrepareSendRequest()
	if err != nil || !pi {
		t.Fatalf("first send PI: %v %v", pi, err)
	}
	if p.SendRemaining() != 3 || p.ReceiveIPR() == nil {
		t.Fatal("uncommitted request consumed credit")
	}
	if err := p.MarkRequestSent(pi); err != nil {
		t.Fatal(err)
	}
	if err := p.ReceiveIPR(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		pi, err = p.PrepareSendRequest()
		if err != nil || pi {
			t.Fatalf("send %d: %v %v", i, pi, err)
		}
		if err := p.MarkRequestSent(pi); err != nil {
			t.Fatal(err)
		}
	}
	pi, err = p.PrepareSendRequest()
	if err != nil || !pi {
		t.Fatalf("next window: %v %v", pi, err)
	}
	if err := p.MarkRequestSent(false); err == nil || p.SendRemaining() != 0 {
		t.Fatal("mismatched PI committed")
	}
	p.CancelPreparedRequest()
	pi, err = p.PrepareSendRequest()
	if err != nil || !pi {
		t.Fatalf("retry: %v %v", pi, err)
	}
	if err := p.MarkRequestSent(pi); err != nil {
		t.Fatal(err)
	}
}
