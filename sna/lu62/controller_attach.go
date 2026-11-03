package lu62

import "encoding/binary"

// controllerAttachTPN is the architecture transaction program name copied
// into the IBM 5494 Release 3.2 controller Attach at runtime.
var controllerAttachTPN = [4]byte{0x30, 0xf0, 0xf6, 0xf6}

// Candidate5494ControllerAttachRU copies the 17-byte DIA-initialized FMH-5
// work area after the 5494 overwrites its TPN with 30F0F6F6, then appends the
// caller's allocation/PIP data. Firmware proves the TPN overwrite and append
// boundary, but does not prove that all other initialized bytes reach the wire.
// The buffer begins with a big-endian length that includes those two bytes.
// Its contents remain runtime-specific. The caller supplies the session TH/RH,
// pacing and confirmation; this function does not emit a complete PIU.
func Candidate5494ControllerAttachRU(allocation []byte) ([]byte, error) {
	if len(allocation) < 2 || len(allocation) > 1024 ||
		int(binary.BigEndian.Uint16(allocation[:2])) != len(allocation) {
		return nil, ErrAttach
	}
	ru := []byte{0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4,
		controllerAttachTPN[0], controllerAttachTPN[1], controllerAttachTPN[2], controllerAttachTPN[3],
		0, 0, 0}
	return append(ru, allocation...), nil
}
