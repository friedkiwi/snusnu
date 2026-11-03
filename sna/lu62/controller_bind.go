package lu62

import (
	"errors"
	"strings"
)

var ErrControllerBind = errors.New("invalid 5494 controller BIND parameters")

var qrmtwscMode = []byte{0xd8, 0xd9, 0xd4, 0xe3, 0xe6, 0xe2, 0xc3} // QRMTWSC

// Candidate5494ControllerBind constructs the IBM-defined LU 6.2 controller
// BIND with mode QRMTWSC. The 5494 controller application must first complete
// CNOS and must use fresh PCID bytes. The private controller Attach and device
// notification are outside this function and remain unverified.
func Candidate5494ControllerBind(localLU, remoteLU, localCP string, daf, oaf, maxRU byte, pcid [8]byte) ([]byte, error) {
	if daf == 0 || oaf == 0 || daf == oaf || maxRU < 0x85 || maxRU > 0x87 || pcid == [8]byte{} {
		return nil, ErrControllerBind
	}
	plu, err := encodeLUName(localLU)
	if err != nil {
		return nil, ErrControllerBind
	}
	slu, err := encodeLUName(remoteLU)
	if err != nil || localLU == remoteLU {
		return nil, ErrControllerBind
	}
	cp, err := encodeLUName(localCP)
	if err != nil {
		return nil, ErrControllerBind
	}
	// The controlling CP and LU share a NETID; their resource names may differ.
	if strings.SplitN(localLU, ".", 2)[0] != strings.SplitN(localCP, ".", 2)[0] {
		return nil, ErrControllerBind
	}
	ru := []byte{0x31, 0, 0x13, 7, 0xb0, 0xb0, 0xd0, 0xb3, 0, 0, maxRU, maxRU, 0x80, 0, 6, 2,
		0, 0, 0, 0, 0, 0, 0, 0, 0x23, 0, 0}
	ru = append(ru, byte(len(plu)))
	ru = append(ru, plu...)
	user := []byte{0, 8, 2}
	user = append(user, qrmtwscMode...)
	user = append(user, byte(len(plu)+1), 4)
	user = append(user, plu...)
	ru = append(ru, byte(len(user)))
	ru = append(ru, user...)
	ru = append(ru, 0, byte(len(slu))) // no URC, then SLU name
	ru = append(ru, slu...)
	ru = append(ru, 0x60, byte(9+len(cp)))
	ru = append(ru, pcid[:]...)
	ru = append(ru, byte(len(cp)))
	ru = append(ru, cp...)
	piu := append([]byte{0x2f, 0, daf, oaf, 0, 0, 0x6b, 0x80, 0}, ru...)
	bind, err := ParseBind(piu)
	if err != nil || bind == nil || bind.PLU != localLU || bind.SLU != remoteLU || bind.Mode != "QRMTWSC" {
		return nil, ErrControllerBind
	}
	return piu, nil
}
