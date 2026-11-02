package apingd

import (
	"errors"

	"github.com/friedkiwi/snusnu/sna"
)

var ErrConversation = errors.New("invalid APING conversation state")

// Conversation implements the APINGD application turn. The caller owns APPC
// Attach, pacing, CONFIRM, deallocation, and transport delivery.
type Conversation struct {
	peer       sna.Peer
	systemType string
	versioned  bool
	closed     bool
	packets    uint32
}

func NewConversation(peer sna.Peer, systemType string) (*Conversation, error) {
	if !peer.Valid() || len(systemType) != 6 {
		return nil, ErrConversation
	}
	for i := range systemType {
		if systemType[i] < 0x20 || systemType[i] > 0x7e {
			return nil, ErrConversation
		}
	}
	return &Conversation{peer: peer, systemType: systemType}, nil
}

func (c *Conversation) Peer() sna.Peer { return c.peer }

func (c *Conversation) Version(request []byte) ([]byte, error) {
	if c.closed || c.versioned {
		return nil, ErrConversation
	}
	response, err := VersionResponse(request, c.systemType)
	if err != nil {
		return nil, err
	}
	c.versioned = true
	return response, nil
}

// Data validates a complete mapped-data RU and optionally echoes its records.
// The APPC adapter determines whether the current turn requests an echo.
func (c *Conversation) Data(ru []byte, echo bool) ([][]byte, error) {
	if c.closed || !c.versioned {
		return nil, ErrConversation
	}
	records, err := ParseMappedRecords(ru)
	if err != nil || c.packets+uint32(len(records)) > 32767 {
		return nil, ErrRecord
	}
	c.packets += uint32(len(records))
	if !echo {
		return nil, nil
	}
	return records, nil
}

func (c *Conversation) Close() { c.closed = true }
