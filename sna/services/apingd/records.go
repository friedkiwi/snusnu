// Package apingd implements the application records used by IBM APINGD.
// A caller supplies the LU 6.2 conversation and its authenticated peer.
// The package never opens a socket or starts a daemon.
package apingd

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var ErrRecord = errors.New("invalid APING record")

// MaxRecord is the largest mapped record accepted by IBM APING's packet size.
const MaxRecord = 32763 + 2

var versionRequestPrefix = []byte{0x12, 0xff, 0x01, 0x02, 0x2b, 0x02}

// VersionResponse validates the observed APING version exchange and returns
// the local six-byte system type. The request system type is opaque; accepting
// it does not authenticate the source LU.
func VersionResponse(request []byte, systemType string) ([]byte, error) {
	if err := validateRecord(request); err != nil || len(request) != 15 ||
		!bytes.Equal(request[2:8], versionRequestPrefix) || request[14] != 0 {
		return nil, ErrRecord
	}
	if len(systemType) != 6 {
		return nil, ErrRecord
	}
	for i := 0; i < 6; i++ {
		if systemType[i] < 0x20 || systemType[i] > 0x7e {
			return nil, ErrRecord
		}
	}
	response := make([]byte, 14)
	binary.BigEndian.PutUint16(response[:2], uint16(len(response)))
	copy(response[2:8], versionRequestPrefix)
	copy(response[8:], systemType)
	return response, nil
}

// Echo copies complete mapped records for an echo turn. The LU 6.2 layer owns
// Prepare-to-Receive, CONFIRM, pacing, and orderly deallocation.
func Echo(records [][]byte) ([][]byte, error) {
	if len(records) == 0 || len(records) > 32767 {
		return nil, ErrRecord
	}
	out := make([][]byte, len(records))
	for i, record := range records {
		if err := validateRecord(record); err != nil {
			return nil, err
		}
		out[i] = append([]byte(nil), record...)
	}
	return out, nil
}

func validateRecord(record []byte) error {
	if len(record) < 2 || len(record) > MaxRecord || int(binary.BigEndian.Uint16(record[:2])) != len(record) {
		return ErrRecord
	}
	return nil
}
