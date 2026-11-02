package apingd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/friedkiwi/snusnu/sna"
)

func TestConversationVersionEchoAndNoEcho(t *testing.T) {
	if _, err := NewConversation(sna.Peer{Principal: "user-1", NetID: "SOLNET", LU: "SNAA"}, "BAD\x00XX"); !errors.Is(err, ErrConversation) {
		t.Fatalf("invalid system type: %v", err)
	}
	peer := sna.Peer{Principal: "user-1", NetID: "SOLNET", LU: "SNAA"}
	c, err := NewConversation(peer, "OS/400")
	if err != nil || c.Peer() != peer {
		t.Fatalf("peer: %+v %v", c, err)
	}
	data, _ := hex.DecodeString("001412ff00000000000000000000000000000000")
	if _, err := c.Data(data, true); !errors.Is(err, ErrConversation) {
		t.Fatalf("pre-version data: %v", err)
	}
	version, _ := hex.DecodeString("000f12ff01022b02d6e261f4f0f000")
	if _, err := c.Version(version); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Version(version); !errors.Is(err, ErrConversation) {
		t.Fatalf("duplicate version: %v", err)
	}
	reply, err := c.Data(data, true)
	if err != nil || len(reply) != 1 || !bytes.Equal(reply[0], data) {
		t.Fatalf("echo: %x %v", reply, err)
	}
	noEcho, _ := hex.DecodeString("000812ff00000000000812ff00000000")
	reply, err = c.Data(noEcho, false)
	if err != nil || reply != nil || c.packets != 3 {
		t.Fatalf("no echo: %x %v", reply, err)
	}
	c.Close()
	if _, err := c.Data(data, true); !errors.Is(err, ErrConversation) {
		t.Fatalf("post-close data: %v", err)
	}
}
