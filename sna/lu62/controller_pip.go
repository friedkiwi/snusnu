package lu62

// Encode5494ControllerPIP builds the 18-byte allocation/PIP record assembled
// by VG0F before its controller Attach event is delivered to VG10. Attribute
// is the runtime byte copied from the firmware's controller table; its exact
// meaning and value for a virtual 3812 remain capture dependent. The final
// 04 D4 07 30 subvector identifies the 5494 controller family, not a printer
// address.
func Encode5494ControllerPIP(attribute byte) []byte {
	return []byte{0, 0x12, 0x12, 0xf5, 0, 0x0e, 0x12, 0xe2,
		3, 0x20, 1, attribute, 0x38, 4, 4, 0xd4, 7, 0x30}
}
