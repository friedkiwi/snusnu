package lu62

import (
	"bytes"
	"errors"
	"strings"
)

var ErrManagement = errors.New("unsupported management BIND")

var v4ManagementFixed = []byte{
	0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2,
	0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0,
}
var managementResponseFixed = []byte{
	0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 0, 0x80, 0x86, 0x86, 0x80, 0, 6, 2,
	0, 0, 0, 0, 0, 0, 0, 0, 0x23, 0x40, 0,
}
var snaSvcMode = []byte{0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7}

// CandidateManagementResponse builds the narrow V4R4 SNASVCMG BIND response.
// A node must negotiate pacing, CNOS, parallel sessions, and CONFIRM before
// transmitting this response. This function alone never activates a session.
func CandidateManagementResponse(request []byte, remotePLU, localSLU string) ([]byte, error) {
	b, err := ParseBind(request)
	if err != nil || b == nil || !b.Management || b.Mode != "SNASVCMG" || b.PLU != remotePLU || b.SLU != localSLU {
		return nil, ErrManagement
	}
	if len(request) < 9+28 || request[1] != 0 || request[4] != 0 || request[5] != 0 || request[6] != 0x6b ||
		(request[7] != 0x80 && request[7] != 0x85) || request[8] != 0 {
		return nil, ErrManagement
	}
	ru := request[9:]
	if !bytes.Equal(ru[:27], v4ManagementFixed) {
		return nil, ErrManagement
	}
	pluName, err := encodeLUName(remotePLU)
	if err != nil || len(ru) < 28+len(pluName) || int(ru[27]) != len(pluName) || !bytes.Equal(ru[28:28+len(pluName)], pluName) {
		return nil, ErrManagement
	}
	_, offset, err := nameAt(ru, 27, true)
	if err != nil || offset >= len(ru) {
		return nil, ErrManagement
	}
	userLen := int(ru[offset])
	offset++
	if offset+userLen >= len(ru) {
		return nil, ErrManagement
	}
	user := ru[offset : offset+userLen]
	if len(user) < 1 || user[0] != 0 {
		return nil, ErrManagement
	}
	var instance, identity bool
	for cursor := 1; cursor < len(user); {
		n := int(user[cursor])
		if n < 1 || cursor+1+n > len(user) {
			return nil, ErrManagement
		}
		field := user[cursor+1 : cursor+1+n]
		switch field[0] {
		case 2:
			if n != 9 || !bytes.Equal(field[1:], snaSvcMode) {
				return nil, ErrManagement
			}
		case 3:
			if n != 9 || field[1] != 1 {
				return nil, ErrManagement
			}
			instance = true
		case 4:
			if !bytes.Equal(field[1:], pluName) {
				return nil, ErrManagement
			}
			identity = true
		case 0x13:
			if n != 10 {
				return nil, ErrManagement
			}
		default:
			return nil, ErrManagement
		}
		cursor += 1 + n
	}
	if !instance || !identity {
		return nil, ErrManagement
	}
	offset += userLen
	if ru[offset] != 0 {
		return nil, ErrManagement
	}
	_, offset, err = nameAt(ru, offset+1, true)
	if err != nil || len(ru[offset:]) < 2 {
		return nil, ErrManagement
	}
	fq := ru[offset:]
	if fq[0] != 0x60 || int(fq[1]) < 12 || int(fq[1]) > 26 || len(fq) < 2+int(fq[1]) {
		return nil, ErrManagement
	}
	vectorEnd := 2 + int(fq[1])
	if tail := fq[vectorEnd:]; len(tail) != 0 && (len(tail) != 12 || tail[0] != 0x2c || tail[1] != 0x0a) {
		return nil, ErrManagement
	}
	fq = fq[:vectorEnd]
	if int(fq[10])+9 != int(fq[1]) {
		return nil, ErrManagement
	}
	sluName, err := encodeLUName(localSLU)
	if err != nil {
		return nil, err
	}
	userResponse := []byte{0, 9, 2}
	userResponse = append(userResponse, snaSvcMode...)
	userResponse = append(userResponse, 2, 3, 2, byte(1+len(sluName)), 5)
	userResponse = append(userResponse, sluName...)
	response := []byte{request[0], 0, b.OAF, b.DAF, 0, 0, 0xeb, 0x80, 0}
	response = append(response, managementResponseFixed...)
	response = append(response, 0, byte(len(userResponse)))
	response = append(response, userResponse...)
	response = append(response, 0, 0)
	response = append(response, fq...)
	return response, nil
}

func encodeLUName(name string) ([]byte, error) {
	parts := strings.Split(name, ".")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 8 || len(parts[1]) == 0 || len(parts[1]) > 8 {
		return nil, ErrManagement
	}
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'I':
			out = append(out, 0xc1+c-'A')
		case c >= 'J' && c <= 'R':
			out = append(out, 0xd1+c-'J')
		case c >= 'S' && c <= 'Z':
			out = append(out, 0xe2+c-'S')
		case c >= '0' && c <= '9':
			out = append(out, 0xf0+c-'0')
		case c == '.':
			out = append(out, 0x4b)
		default:
			return nil, ErrManagement
		}
	}
	return out, nil
}
