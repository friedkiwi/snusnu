//! Frames observed from a V4R4M0 guest on Solstice 0.4.1, TAP sol5.
//! Only the 802.3 header and declared LLC data are retained; capture padding
//! and unrelated traffic are excluded.

use router_core::llc::{parse_8023, Control};
use router_core::llc_type1::response_for;

const XID_COMMAND: [u8; 20] = [
    0x02, 0x00, 0x35, 0x27, 0x23, 0x01, 0x02, 0x00, 0x35, 0x27, 0x23, 0x99, 0x00, 0x06, 0x04, 0x04,
    0xaf, 0x81, 0x01, 0x00,
];
const XID_RESPONSE: [u8; 20] = [
    0x02, 0x00, 0x35, 0x27, 0x23, 0x99, 0x02, 0x00, 0x35, 0x27, 0x23, 0x01, 0x00, 0x06, 0x04, 0x05,
    0xaf, 0x81, 0x03, 0x00,
];
const TEST_COMMAND: [u8; 17] = [
    0x02, 0x00, 0x35, 0x27, 0x23, 0x01, 0x02, 0x00, 0x35, 0x27, 0x23, 0x99, 0x00, 0x03, 0x04, 0x04,
    0xe3,
];
const TEST_RESPONSE: [u8; 17] = [
    0x02, 0x00, 0x35, 0x27, 0x23, 0x99, 0x02, 0x00, 0x35, 0x27, 0x23, 0x01, 0x00, 0x03, 0x04, 0x05,
    0xe3,
];

#[test]
fn solstice_v4r4_ieee_xid_exchange() {
    let command = parse_8023(&XID_COMMAND).unwrap();
    let response = parse_8023(&XID_RESPONSE).unwrap();
    assert!(command.is_sna());
    assert!(response.is_sna());
    assert!(!command.is_response());
    assert!(response.is_response());
    assert_eq!(command.control, Control::Unnumbered { byte: 0xaf });
    assert_eq!(response.control, Control::Unnumbered { byte: 0xaf });
    assert_eq!(command.information, [0x81, 0x01, 0x00]);
    assert_eq!(response.information, [0x81, 0x03, 0x00]);
    let generated = response_for(&command, command.destination, 4, Some(&[0x81, 0x03, 0x00]))
        .unwrap()
        .unwrap();
    assert_eq!(&generated[..XID_RESPONSE.len()], XID_RESPONSE);
}

#[test]
fn solstice_v4r4_test_exchange() {
    let command = parse_8023(&TEST_COMMAND).unwrap();
    let response = parse_8023(&TEST_RESPONSE).unwrap();
    assert_eq!(command.control, Control::Unnumbered { byte: 0xe3 });
    assert_eq!(response.control, Control::Unnumbered { byte: 0xe3 });
    assert!(command.information.is_empty());
    assert!(response.information.is_empty());
    assert!(!command.is_response());
    assert!(response.is_response());
    let generated = response_for(&command, command.destination, 4, None)
        .unwrap()
        .unwrap();
    assert_eq!(&generated[..TEST_RESPONSE.len()], TEST_RESPONSE);
}
