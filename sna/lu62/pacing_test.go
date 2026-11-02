package lu62

import "testing"

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
	pi, err := p.SendRequest()
	if err != nil || !pi {
		t.Fatalf("first send PI: %v %v", pi, err)
	}
	if err := p.ReceiveIPR(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		pi, err = p.SendRequest()
		if err != nil || pi {
			t.Fatalf("send %d: %v %v", i, pi, err)
		}
	}
	pi, err = p.SendRequest()
	if err != nil || !pi {
		t.Fatalf("next window: %v %v", pi, err)
	}
}
