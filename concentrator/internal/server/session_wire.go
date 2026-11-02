package server

import (
	"errors"

	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
)

const maxReducedSessionUnit = 16 * 1024
const maxSessionGrant = 1 << 20

// validateSessionWireEvent only checks the relay's bounded, carrier-neutral
// envelope. The destination owns BIND and LU protocol validation; the hub
// must not infer identity from an untrusted session unit.
func validateSessionWireEvent(event *wire.SessionEvent) (int, error) {
	if event == nil {
		return 0, errors.New("missing session event")
	}
	check := func(unit []byte, needsRU bool) (int, error) {
		if len(unit) < 5 || len(unit) > maxReducedSessionUnit || (needsRU && len(unit) == 5) {
			return 0, errors.New("invalid reduced session unit size")
		}
		return len(unit), nil
	}
	switch value := event.Event.(type) {
	case *wire.SessionEvent_BindRequest:
		return check(value.BindRequest, true)
	case *wire.SessionEvent_BindResult:
		if value.BindResult == nil {
			return 0, errors.New("missing BIND result")
		}
		return check(value.BindResult.ReducedUnit, true)
	case *wire.SessionEvent_Information:
		if value.Information == nil {
			return 0, errors.New("missing session information")
		}
		return check(value.Information.ReducedUnit, false)
	case *wire.SessionEvent_PacingCredit:
		if value.PacingCredit == nil || value.PacingCredit.Normal > maxSessionGrant || value.PacingCredit.Expedited > maxSessionGrant || value.PacingCredit.Normal+value.PacingCredit.Expedited == 0 {
			return 0, errors.New("invalid session pacing credit")
		}
		return 0, nil
	case *wire.SessionEvent_Unbind:
		return check(value.Unbind, true)
	default:
		return 0, errors.New("unsupported session event")
	}
}

func sessionEventKind(event *wire.SessionEvent) string {
	if event == nil {
		return "invalid"
	}
	switch event.Event.(type) {
	case *wire.SessionEvent_BindRequest:
		return "bind request"
	case *wire.SessionEvent_BindResult:
		return "bind result"
	case *wire.SessionEvent_Information:
		return "information"
	case *wire.SessionEvent_PacingCredit:
		return "pacing credit"
	case *wire.SessionEvent_Unbind:
		return "unbind"
	default:
		return "invalid"
	}
}
