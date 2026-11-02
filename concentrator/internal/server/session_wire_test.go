package server

import (
	"testing"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
)

func TestSessionWireEventBoundsAndKinds(t *testing.T) {
	unit := []byte{0, 1, 3, 0x90, 0x20, 0x31}
	for _, event := range []*wire.SessionEvent{
		{Event: &wire.SessionEvent_BindRequest{BindRequest: unit}},
		{Event: &wire.SessionEvent_BindResult{BindResult: &wire.SessionBindResult{Accepted: true, ReducedUnit: unit}}},
		{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: unit}}},
		{Event: &wire.SessionEvent_Unbind{Unbind: unit}},
	} {
		if got, err := validateSessionWireEvent(event); err != nil || got != len(unit) {
			t.Fatalf("event %T: cost=%d err=%v", event.Event, got, err)
		}
	}
	if got, err := validateSessionWireEvent(&wire.SessionEvent{Event: &wire.SessionEvent_PacingCredit{PacingCredit: &wire.SessionPacingCredit{Normal: 1}}}); err != nil || got != 0 {
		t.Fatalf("pacing credit cost=%d err=%v", got, err)
	}
	for _, event := range []*wire.SessionEvent{
		nil,
		{},
		{Event: &wire.SessionEvent_BindRequest{BindRequest: unit[:5]}},
		{Event: &wire.SessionEvent_Information{Information: &wire.SessionInformation{ReducedUnit: unit[:4]}}},
		{Event: &wire.SessionEvent_PacingCredit{PacingCredit: &wire.SessionPacingCredit{Normal: maxSessionGrant + 1}}},
		{Event: &wire.SessionEvent_Unbind{Unbind: make([]byte, maxReducedSessionUnit+1)}},
	} {
		if _, err := validateSessionWireEvent(event); err == nil {
			t.Fatalf("accepted invalid event %+v", event)
		}
	}
}
