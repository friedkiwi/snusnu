package printer

import "encoding/binary"

// ParseControllerDeviceGDS decodes the private D824 controller record observed
// in a V5R4 5494 device conversation. Its payload is one complete FID3 PIU.
// The caller must still validate the outer LU 6.2 session and device identity.
func ParseControllerDeviceGDS(data []byte) (LU4PIU, error) {
	if len(data) < 9 || len(data) > 1033 || int(binary.BigEndian.Uint16(data[:2])) != len(data) ||
		data[2] != 0xd8 || data[3] != 0x24 {
		return LU4PIU{}, ErrLU4
	}
	return ParseLU4PIU(data[4:])
}

// EncodeControllerDeviceGDS wraps one validated FID3 PIU in the observed
// D824 record. The GDS length includes its four-byte length/key header.
func EncodeControllerDeviceGDS(p LU4PIU) ([]byte, error) {
	inner, err := p.Encode()
	if err != nil {
		return nil, err
	}
	if len(inner) < 5 || len(inner) > 1029 {
		return nil, ErrLU4
	}
	data := make([]byte, 4, len(inner)+4)
	binary.BigEndian.PutUint16(data[:2], uint16(len(inner)+4))
	data[2], data[3] = 0xd8, 0x24
	return append(data, inner...), nil
}
