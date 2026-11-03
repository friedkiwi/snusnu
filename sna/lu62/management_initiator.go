package lu62

import "errors"

var ErrManagementRequest = errors.New("invalid LU 6.2 management request")

var managementRequestFixed = []byte{
	0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2,
	0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0,
}

// CandidateManagementBind constructs an active SNASVCMG BIND for a native
// FID2 association. The caller must generate fresh instance and token bytes,
// await a correlated positive response, and complete CNOS before user traffic.
func CandidateManagementBind(localCP, remoteCP string, daf, oaf byte, instance [8]byte, token [7]byte) ([]byte, error) {
	if daf == 0 || oaf == 0 || instance == [8]byte{} || token[0] != 0x23 || token[5] != 0x80 || token[6] != 0 ||
		token[1] == 0 && token[2] == 0 && token[3] == 0 && token[4] == 0 {
		return nil, ErrManagementRequest
	}
	local, err := encodeLUName(localCP)
	if err != nil {
		return nil, ErrManagementRequest
	}
	remote, err := encodeLUName(remoteCP)
	if err != nil || localCP == remoteCP {
		return nil, ErrManagementRequest
	}
	fqpcid := []byte{0x60, byte(9 + len(local))}
	fqpcid = append(fqpcid, instance[:]...)
	fqpcid = append(fqpcid, byte(len(local)))
	fqpcid = append(fqpcid, local...)
	user := []byte{0, 9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7, 9, 3, 1}
	user = append(user, token[:]...)
	user = append(user, byte(1+len(local)), 4)
	user = append(user, local...)
	user = append(user, 10, 0x13, 0, 0xb0)
	user = append(user, token[:]...)
	piu := []byte{0x2f, 0, daf, oaf, 0, 0, 0x6b, 0x85, 0}
	piu = append(piu, managementRequestFixed...)
	piu = append(piu, byte(len(local)))
	piu = append(piu, local...)
	piu = append(piu, byte(len(user)))
	piu = append(piu, user...)
	piu = append(piu, 0, byte(len(remote)))
	piu = append(piu, remote...)
	piu = append(piu, fqpcid...)
	piu = append(piu, 0x2c, 0x0a, 4, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3)
	bind, err := ParseBind(piu)
	if err != nil || bind == nil || !bind.Management || bind.PLU != localCP || bind.SLU != remoteCP {
		return nil, ErrManagementRequest
	}
	return piu, nil
}
