package lu62

import (
	"bytes"
	"errors"
)

var ErrUserBind = errors.New("unsupported user LU 6.2 BIND")

var v4UserFixed = []byte{
	0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 3, 0x83, 0xc7, 0xc7, 0x83, 3, 6, 2,
	0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0,
}

// RequestFQPCID returns the fully qualified procedure correlation ID from a
// validated BIND. A session manager must retain this value until UNBIND.
func RequestFQPCID(request []byte) ([]byte, error) {
	b, err := ParseBind(request)
	if err != nil || b == nil {
		return nil, ErrUserBind
	}
	ru := request[9:]
	o := 27
	for i := 0; i < 4; i++ {
		if o >= len(ru) {
			return nil, ErrUserBind
		}
		n := int(ru[o])
		o++
		if o+n > len(ru) {
			return nil, ErrUserBind
		}
		o += n
	}
	if len(ru[o:]) < 14 || ru[o] != 0x60 || int(ru[o+1]) < 12 || int(ru[o+1]) > 26 || o+2+int(ru[o+1]) > len(ru) {
		return nil, ErrUserBind
	}
	v := ru[o : o+2+int(ru[o+1])]
	if int(v[10])+9 != int(v[1]) {
		return nil, ErrUserBind
	}
	return append([]byte(nil), v...), nil
}

// CandidateUserResponse builds a fixed-pacing response for the captured V4R4
// blank-mode user BIND. It must not be sent before management, pacing, APPC
// Attach, and all local transport conditions have been negotiated.
func CandidateUserResponse(request []byte, expectedPLU, expectedSLU string, managementFQPCID []byte, receiveWindow byte) ([]byte, error) {
	return candidateUserResponse(request, expectedPLU, expectedSLU, managementFQPCID, receiveWindow, false)
}

// CandidateStandaloneUserResponse also accepts the captured V5R4 EE BIND
// profile after an HPR adapter has established its own control plane. The
// native FID2 service keeps the older strict candidate profile above.
func CandidateStandaloneUserResponse(request []byte, expectedPLU, expectedSLU string, receiveWindow byte) ([]byte, error) {
	// OS/400 uses SNASVCMG for the APING session addressed to the server's
	// PING LU. The carrier adapter has already established CP control flow;
	// this BIND is admitted only for that exact local service identity. Keep
	// native user sessions and CPSVCMG control sessions on their own paths.
	if expectedSLU == "SNUSNU.PING" {
		bind, err := ParseBind(request)
		if err == nil && bind != nil && bind.Mode == "SNASVCMG" {
			response, err := CandidateManagementResponse(request, expectedPLU, expectedSLU, receiveWindow)
			if err != nil {
				return nil, ErrUserBind
			}
			// The guest accepts the CP response when these negotiated profile
			// bytes retain its supported security, synchronization, and
			// limited-resource settings. The response still selects a bounded
			// receive window in CandidateManagementResponse.
			copy(response[9+23:9+26], request[9+23:9+26])
			// This circuit uses the standalone user's three-frame primary
			// window, rather than the seven-frame management-session window.
			response[9+8], response[9+13] = 3, 3
			return response, nil
		}
	}
	return candidateUserResponse(request, expectedPLU, expectedSLU, nil, receiveWindow, true)
}

func candidateUserResponse(request []byte, expectedPLU, expectedSLU string, managementFQPCID []byte, receiveWindow byte, allowV5 bool) ([]byte, error) {
	b, err := ParseBind(request)
	if err != nil || b == nil || b.Management || b.Mode != "" || b.PLU != expectedPLU || b.SLU != expectedSLU || receiveWindow < 1 || receiveWindow > 3 {
		return nil, ErrUserBind
	}
	if len(request) < 9+28 || (request[0] != 0x2d && request[0] != 0x2f) || request[1] != 0 || request[6] != 0x6b ||
		(request[7] != 0x80 && request[7] != 0x85) || request[8] != 0 || b.DAF == 0 || b.OAF == 0 {
		return nil, ErrUserBind
	}
	ru := request[9:]
	// V5R4 EE uses the same LU 6.2 default-mode BIND with a larger normal
	// flow RU encoding (X'8C') and no compression in byte 25. IBM SNA Formats
	// permits the SLU to negotiate the pacing and supported synchronization
	// fields in RSP(BIND). Keep the older V4R4 profile strict and distinct.
	v5UserFixed := append([]byte(nil), v4UserFixed...)
	v5UserFixed[10], v5UserFixed[11], v5UserFixed[25] = 0x8c, 0x8c, 0
	if !bytes.Equal(ru[:27], v4UserFixed) && !(allowV5 && bytes.Equal(ru[:27], v5UserFixed)) {
		return nil, ErrUserBind
	}
	plu, err := encodeLUName(expectedPLU)
	if err != nil || len(ru) < 28+len(plu) || int(ru[27]) != len(plu) || !bytes.Equal(ru[28:28+len(plu)], plu) {
		return nil, ErrUserBind
	}
	o := 28 + len(plu)
	if o >= len(ru) {
		return nil, ErrUserBind
	}
	n := int(ru[o])
	o++
	if o+n >= len(ru) || n != 34+len(plu) {
		return nil, ErrUserBind
	}
	user := ru[o : o+n]
	if !bytes.Equal(user[:11], []byte{0, 9, 2, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40}) ||
		!bytes.Equal(user[11:14], []byte{9, 3, 1}) || user[21] != byte(1+len(plu)) || user[22] != 4 ||
		!bytes.Equal(user[23:23+len(plu)], plu) || !bytes.Equal(user[23+len(plu):25+len(plu)], []byte{10, 0x13}) {
		return nil, ErrUserBind
	}
	o += n
	slu, err := encodeLUName(expectedSLU)
	if err != nil || o+2+len(slu) > len(ru) || ru[o] != 0 || ru[o+1] != byte(len(slu)) || !bytes.Equal(ru[o+2:o+2+len(slu)], slu) {
		return nil, ErrUserBind
	}
	o += 2 + len(slu)
	fq, err := RequestFQPCID(request)
	if err != nil || (len(managementFQPCID) != 0 && bytes.Equal(fq, managementFQPCID)) || o+len(fq)+12 != len(ru) || !bytes.Equal(ru[o:o+len(fq)], fq) || ru[o+len(fq)] != 0x2c || ru[o+len(fq)+1] != 0x0a {
		return nil, ErrUserBind
	}
	responseUser := []byte{0, 9, 2, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 2, 3, 2, byte(1 + len(slu)), 5}
	responseUser = append(responseUser, slu...)
	fixed := append([]byte(nil), ru[:27]...)
	fixed[8], fixed[9], fixed[12], fixed[13] = 3, receiveWindow, 0x80|receiveWindow, 3
	fixed[23], fixed[24] = 0, 0x23
	response := []byte{request[0], 0, b.OAF, b.DAF, 0, 0, 0xeb, 0x80, 0}
	response = append(response, fixed...)
	response = append(response, 0, byte(len(responseUser)))
	response = append(response, responseUser...)
	response = append(response, 0, 0)
	response = append(response, fq...)
	return response, nil
}
