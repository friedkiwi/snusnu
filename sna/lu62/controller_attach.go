package lu62

import "encoding/binary"

// controllerAttachTPN is the architecture transaction program name copied
// into the IBM 5494 Release 3.2 controller Attach at runtime.
var controllerAttachTPN = [4]byte{0x30, 0xf0, 0xf6, 0xf6}

// Encode5494ControllerAttachRU reproduces the 17-byte FMH-5 prefix observed
// in the 5494 controller sender and appends the caller's allocation/PIP data.
// The buffer begins with a big-endian length that includes those two bytes.
// Its contents remain runtime-specific. The caller supplies the session TH/RH,
// pacing and confirmation; this function does not emit a complete PIU.
func Encode5494ControllerAttachRU(allocation []byte) ([]byte, error) {
	if len(allocation) < 2 || len(allocation) > 1024 ||
		int(binary.BigEndian.Uint16(allocation[:2])) != len(allocation) {
		return nil, ErrAttach
	}
	ru := []byte{0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4,
		controllerAttachTPN[0], controllerAttachTPN[1], controllerAttachTPN[2], controllerAttachTPN[3],
		0, 0, 0}
	return append(ru, allocation...), nil
}
