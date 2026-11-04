package lu62

import "bytes"

var v5PrinterDeviceFixed = []byte{
	0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0xc7, 0xc7, 0x87, 7, 6, 2,
	0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0,
}

// Candidate5494DeviceResponse negotiates the V5R4 QRMTWSC LU 6.2 device
// BIND observed after a solicited 5494 printer Reply-PSID. The controller
// application must already have authorized this parallel session.
func Candidate5494DeviceResponse(request []byte, expectedPLU, expectedSLU string, receiveWindow byte) ([]byte, error) {
	bind, err := ParseBind(request)
	if err != nil || bind == nil || bind.Mode != "QRMTWSC" || bind.PLU != expectedPLU || bind.SLU != expectedSLU ||
		receiveWindow < 1 || receiveWindow > 7 || len(request) < 9+28 ||
		(request[0] != 0x2d && request[0] != 0x2f) || request[6] != 0x6b || request[7] != 0x80 || request[8] != 0 ||
		!bytes.Equal(request[9:9+27], v5PrinterDeviceFixed) {
		return nil, ErrUserBind
	}
	fq, err := RequestFQPCID(request)
	if err != nil {
		return nil, ErrUserBind
	}
	slu, err := encodeLUName(expectedSLU)
	if err != nil {
		return nil, err
	}
	user := []byte{0, 8, 2, 0xd8, 0xd9, 0xd4, 0xe3, 0xe6, 0xe2, 0xc3, 2, 3, 2, byte(1 + len(slu)), 5}
	user = append(user, slu...)
	fixed := append([]byte(nil), v5PrinterDeviceFixed...)
	fixed[8], fixed[9], fixed[12], fixed[13] = 7, receiveWindow, 0x80|receiveWindow, 7
	fixed[23], fixed[24] = 0x90, 0x23
	response := []byte{request[0], 0, bind.OAF, bind.DAF, 0, 0, 0xeb, 0x80, 0}
	response = append(response, fixed...)
	response = append(response, 0, byte(len(user)))
	response = append(response, user...)
	response = append(response, 0, 0)
	return append(response, fq...), nil
}
