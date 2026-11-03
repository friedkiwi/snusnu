use std::collections::HashSet;

use crate::auto_llc::classify_offer;

fn frame(destination: [u8; 6], source: [u8; 6], pdu: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(14 + pdu.len());
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&(pdu.len() as u16).to_be_bytes());
    bytes.extend_from_slice(pdu);
    bytes
}

#[test]
fn stale_session_frames_do_not_create_a_new_llc_offer() {
    let guest = [0x02, 0, 0, 0, 0, 1];
    let proxy = [0x06, 0x53, 0x4e, 0, 0, 1];
    let allowed = HashSet::from([proxy]);
    let active = HashSet::new();

    // All of these can arrive late from a previous association. In particular,
    // an RR must not reserve the proxy MAC and block a fresh dialout XID.
    for pdu in [
        &[4, 4, 0x01, 0x00][..], // RR
        &[4, 4, 0x00, 0x00][..], // I frame
        &[4, 5, 0x73][..],       // UA
        &[4, 4, 0x6f][..],       // SABME before identity proof
        &[4, 5, 0xaf][..],       // XID response
    ] {
        assert_eq!(
            classify_offer(&frame(proxy, guest, pdu), guest, &allowed, &active).unwrap(),
            None,
            "unexpected offer from {pdu:02x?}"
        );
    }
    assert_eq!(
        classify_offer(
            &frame(proxy, guest, &[4, 4, 0xaf]),
            guest,
            &allowed,
            &active
        )
        .unwrap(),
        Some((proxy, None)),
    );
}

#[test]
fn type_one_test_is_a_valid_dialout_bootstrap_but_wrong_sap_is_not() {
    let guest = [0x02, 0, 0, 0, 0, 1];
    let proxy = [0x06, 0x53, 0x4e, 0, 0, 1];
    let allowed = HashSet::from([proxy]);
    let active = HashSet::new();

    assert_eq!(
        classify_offer(
            &frame(proxy, guest, &[4, 4, 0xe3]),
            guest,
            &allowed,
            &active
        )
        .unwrap(),
        Some((proxy, None)),
    );
    assert_eq!(
        classify_offer(
            &frame(proxy, guest, &[5, 4, 0xe3]),
            guest,
            &allowed,
            &active
        )
        .unwrap(),
        None,
    );
}
