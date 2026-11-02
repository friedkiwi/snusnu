//! Pure admission gate for the captured V5R4 reverse SNASVCMG Connect.
//!
//! TCP62 removes FID2 DAF/OAF/ODAI from Connect's BIND image. Synthetic
//! nonzero FID2 addresses below exist only to reuse the strict LU 6.2 BIND
//! parser; they are never returned or used for a native session. This module
//! can construct a response candidate but does not establish a management
//! session or authorize transmitting that candidate.

use std::io;

use router_core::fid2_bind::{classify_bind, BindClass};

use crate::{
    mptn_bind_negotiation::{fqpcid_at, validate_positive_response},
    mptn_compensations::{required_from_connect, CompensationSet},
    mptn_connect::{Connect, Direction},
};

const V5_MANAGEMENT_FIXED: [u8; 27] = [
    0x31, 0x00, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33, 0x07, 0x87, 0x86, 0x86, 0x87, 0x07, 0x06, 0x02,
    0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0, 0,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReverseManagementConnect {
    /// The complete, validated request is retained for response correlation.
    /// Owning it does not authorize a positive response.
    request: Connect,
    fqpcid: Vec<u8>,
}

impl ReverseManagementConnect {
    pub fn request(&self) -> &Connect {
        &self.request
    }

    pub fn fqpcid(&self) -> &[u8] {
        &self.fqpcid
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn ebcdic_lu(name: &str) -> io::Result<Vec<u8>> {
    let Some((netid, cp)) = name.split_once('.') else {
        return Err(invalid("invalid network-qualified LU policy"));
    };
    if netid.is_empty() || netid.len() > 8 || cp.is_empty() || cp.len() > 8 || cp.contains('.') {
        return Err(invalid("invalid network-qualified LU policy"));
    }
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => return Err(invalid("invalid network-qualified LU policy")),
            })
        })
        .collect()
}

/// Accept only a complete reverse SNASVCMG BIND with the fixed V5R4 profile
/// observed in the sixth isolated capture. `forbidden_fqpcid` is an optional
/// known active session instance; a duplicate would alias two LU 6.2 sessions.
pub fn classify_reverse_management_connect(
    request: Connect,
    expected_peer_lu: &str,
    expected_local_lu: &str,
    forbidden_fqpcid: Option<&[u8]>,
) -> io::Result<ReverseManagementConnect> {
    request.encode()?; // also validates public fields on constructed values
    if request.direction != Direction::Request
        || request.correlator.len() != 8
        || request.source.node != ebcdic_lu(expected_peer_lu)?
        || request.destination.node != ebcdic_lu(expected_local_lu)?
    {
        return Err(invalid(
            "reverse management Connect identity or correlator mismatch",
        ));
    }
    let required = required_from_connect(&request)
        .map_err(|_| invalid("reverse management Connect compensation field is invalid"))?;
    if !required.is_complete_tcp62() {
        return Err(invalid(
            "reverse management Connect lacks required TCP62 compensations",
        ));
    }
    let data = request.connection_data();
    if data.len() < 100 || data[..5] != [0, 0, 0x6b, 0x80, 0] || data[5..32] != V5_MANAGEMENT_FIXED
    {
        return Err(invalid(
            "reverse management BIND fixed profile is unsupported",
        ));
    }
    let mut synthetic_piu = Vec::with_capacity(data.len() + 4);
    synthetic_piu.extend_from_slice(&[0x2d, 0, 1, 2]);
    synthetic_piu.extend_from_slice(data);
    let bind = classify_bind(&synthetic_piu)
        .map_err(|_| invalid("reverse management BIND structure invalid"))?
        .ok_or_else(|| invalid("reverse management Connect lacks BIND"))?;
    if bind.class
        != (BindClass::Management {
            mode: "SNASVCMG".into(),
        })
        || bind.plu != expected_peer_lu
        || bind.slu != expected_local_lu
    {
        return Err(invalid("reverse management BIND mode or LU pair invalid"));
    }
    let source = &request.source.node;
    let destination = &request.destination.node;
    let mut cursor = 32;
    if data[cursor] as usize != source.len()
        || data[cursor + 1..cursor + 1 + source.len()] != *source
    {
        return Err(invalid("reverse management PLU mismatch"));
    }
    cursor += 1 + source.len();
    let user_len = 34 + source.len();
    if data[cursor] as usize != user_len {
        return Err(invalid("reverse management user length unsupported"));
    }
    cursor += 1;
    let user = &data[cursor..cursor + user_len];
    if user[..11] != [0, 9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]
        || user[11..14] != [9, 3, 1]
        // V5R4 has emitted both X'23' and X'24' PLU-generated session
        // instances. The matching X'13' copy below still binds the token.
        || !matches!(user[14], 0x23 | 0x24)
        // Both X'80' (earlier reverse capture) and X'00' (QABOB-initiated
        // cross-NETID capture) occur in this dynamic token flag.
        || !matches!(user[19], 0 | 0x80)
        || user[20] != 0
        || user[21] as usize != source.len() + 1
        || user[22] != 4
        || user[23..23 + source.len()] != *source
        || user[23 + source.len()..27 + source.len()] != [10, 0x13, 0, 0xb0]
        || user[27 + source.len()..34 + source.len()] != user[14..21]
    {
        return Err(invalid("reverse management user subfields unsupported"));
    }
    cursor += user_len;
    if data[cursor] != 0
        || data[cursor + 1] as usize != destination.len()
        || data[cursor + 2..cursor + 2 + destination.len()] != *destination
    {
        return Err(invalid("reverse management SLU mismatch"));
    }
    cursor += 2 + destination.len();
    let fqpcid =
        fqpcid_at(data, cursor).map_err(|_| invalid("reverse management FQPCID invalid"))?;
    if fqpcid[11..] != *source
        || data.get(cursor + fqpcid.len()..)
            != Some(
                &[
                    0x2c, 0x0a, 4, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
                ][..],
            )
    {
        return Err(invalid("reverse management FQPCID or trailer invalid"));
    }
    if forbidden_fqpcid.is_some_and(|known| fqpcid == known) {
        return Err(invalid("reverse management FQPCID reuses native session"));
    }
    let fqpcid = fqpcid.to_vec();
    Ok(ReverseManagementConnect { request, fqpcid })
}

/// Build a structural positive-response *candidate* for the admitted V5R4
/// SNASVCMG BIND. The caller must independently implement all six required
/// TCP62 compensations, fixed one-stage pacing, CONFIRM, and management FM
/// before this could be sent. Current runtime does not satisfy that contract.
///
/// GA27-3136 and SC31-6808 permit the secondary to clear adaptive pacing:
/// primary receive/send = 7/1 and secondary receive/send = 1/7. Security and
/// SYNCPT are declined. TCP62 draft §5.3.1.1.3/5 clear unsupported SON and
/// keepalive options in the response rather than echoing their request values.
pub fn candidate_positive_management_response(
    admitted: &ReverseManagementConnect,
    available: CompensationSet,
) -> io::Result<Connect> {
    let request = &admitted.request;
    let required = required_from_connect(request)
        .map_err(|_| invalid("reverse management compensations are invalid"))?;
    if !required.is_complete_tcp62() || !required.missing_from(available).is_empty() {
        return Err(invalid("required TCP62 compensation is unavailable"));
    }
    // The classifier validates the BIND. These option checks additionally
    // prevent silently accepting a service mode or extension we cannot honor.
    if request.options.len() != 5
        || request
            .options
            .iter()
            .map(|field| field.kind)
            .collect::<Vec<_>>()
            != [0x05, 0x0a, 0x18, 0x19, 0x1a]
        || request.options[0].value != [1, 1]
        || request.options[2].value != [1]
        || request.options[4].value != [0x84]
    {
        return Err(invalid("unsupported reverse management Connect option"));
    }

    let mut fixed = V5_MANAGEMENT_FIXED;
    fixed[8] = 7; // primary receive
    fixed[9] = 1; // primary send
    fixed[12] = 0x81; // secondary receive, one-stage pacing
    fixed[13] = 7; // secondary send
    fixed[23] = 0; // no conversation security or password substitution
    fixed[24] = 0x23; // CONFIRM, not SYNCPT

    let slu = &request.destination.node;
    let mut user = vec![0, 9, 2];
    user.extend_from_slice(&[0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]); // SNASVCMG
    user.extend_from_slice(&[2, 3, 2]); // FQPCID session-instance selector
    user.push((slu.len() + 1) as u8);
    user.push(5);
    user.extend_from_slice(slu);

    let mut data = vec![0, 0, 0xeb, 0x80, 0]; // reduced SNF/RH, positive RSP(BIND)
    data.extend_from_slice(&fixed);
    data.extend_from_slice(&[0, user.len() as u8]); // no outer PLU
    data.extend_from_slice(&user);
    data.extend_from_slice(&[0, 0]); // no URC or outer SLU
    data.extend_from_slice(&admitted.fqpcid);

    let mut response = request.clone();
    response.direction = Direction::PositiveResponse;
    response.processing = 0x8a;
    response.options[1].value = data;
    response.options[2].value = vec![0]; // no SON
    response.options[4].value = vec![0]; // no keepalive
    let response = Connect::decode(&response.encode()?)?;
    if !request.matches_response(&response)
        || validate_positive_response(request.connection_data(), response.connection_data())
            .is_err()
    {
        return Err(invalid("reverse management response correlation failed"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{Address, OptionalField, TransportRequirements};
    use crate::mptn_management_initiator::ManagementInitiator;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn classifies_qa_cross_netid_management_bind() {
        let source = ebcdic_lu("QAALICE.SNAA").unwrap();
        let mut fqpcid = vec![0x60, (9 + source.len()) as u8];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(source.len() as u8);
        fqpcid.extend_from_slice(&source);
        let initiated = ManagementInitiator::new(
            "QAALICE.SNAA",
            "QABOB.SNAB",
            fqpcid.clone(),
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let request = Connect::decode(initiated.connect_request()).unwrap();
        let admitted =
            classify_reverse_management_connect(request, "QAALICE.SNAA", "QABOB.SNAB", None)
                .unwrap();
        assert_eq!(admitted.fqpcid(), fqpcid);
        let response = candidate_positive_management_response(
            &admitted,
            CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).unwrap(),
        )
        .unwrap();
        assert!(admitted.request().matches_response(&response));
        assert_eq!(response.connection_data().len(), 85);
    }

    #[test]
    fn admits_live_bob_initiated_zero_token_flag() {
        // The first QABOB→router Connect on the isolated clone carried
        // 23 xx xx xx xx 00 00 in both X'03' and X'13' token subfields.
        // The earlier same-NETID reverse capture had 80 00 instead.
        let source = ebcdic_lu("QABOB.SNAB").unwrap();
        let mut fqpcid = vec![0x60, (9 + source.len()) as u8];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(source.len() as u8);
        fqpcid.extend_from_slice(&source);
        let initiated = ManagementInitiator::new(
            "QABOB.SNAB",
            "QAALICE.SNAA",
            fqpcid.clone(),
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let mut request = Connect::decode(initiated.connect_request()).unwrap();
        let data = &mut request.options[1].value;
        let user_start = 32 + 1 + source.len() + 1;
        data[user_start + 19] = 0;
        data[user_start + 32 + source.len()] = 0;
        let admitted =
            classify_reverse_management_connect(request, "QABOB.SNAB", "QAALICE.SNAA", None)
                .unwrap();
        assert_eq!(admitted.fqpcid(), fqpcid);
    }

    #[test]
    fn admits_captured_bob_management_token_24_with_matching_repeated_token() {
        // Sanitized 2026-11-02 Solstice management Connect shape: the live
        // PLU generated X'24', its dynamic flag was 00, and X'13' repeated
        // the seven-byte token exactly. All other fixed fields are generated
        // by the same validated V5R4 management request constructor.
        let source = ebcdic_lu("QABOB.SNAB").unwrap();
        let mut fqpcid = vec![0x60, (9 + source.len()) as u8];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(source.len() as u8);
        fqpcid.extend_from_slice(&source);
        let initiated = ManagementInitiator::new(
            "QABOB.SNAB",
            "QAALICE.SNAA",
            fqpcid,
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let mut request = Connect::decode(initiated.connect_request()).unwrap();
        let user_start = 32 + 1 + source.len() + 1;
        {
            let data = &mut request.options[1].value;
            data[user_start + 14] = 0x24;
            data[user_start + 19] = 0;
            data[user_start + 27 + source.len()] = 0x24;
            data[user_start + 32 + source.len()] = 0;
        }
        assert!(classify_reverse_management_connect(
            request.clone(),
            "QABOB.SNAB",
            "QAALICE.SNAA",
            None
        )
        .is_ok());
        request.options[1].value[user_start + 27 + source.len()] = 0x23;
        assert!(
            classify_reverse_management_connect(request, "QABOB.SNAB", "QAALICE.SNAA", None)
                .is_err()
        );
    }

    fn captured_shape() -> Connect {
        // Sixth V5R4 reverse Connect: correlator, session instance, and
        // FQPCID token replaced with fixed non-secret test values. All
        // static BIND fields and option order/processing are preserved.
        let reduced_bind = hex(concat!(
            "00006b800031001307b0b0513307878686870706020000000000000094430000",
            "0be2d6d3d5c5e34be2d5c1c22d000902e2d5c1e2e5c3d4c7",
            "090301231111111180000c04e2d6d3d5c5e34be2d5c1c2",
            "0a1300b023111111118000000be2d6d3d5c5e34be2d5c1c1",
            "601422222222222222220be2d6d3d5c5e34be2d5c1c2",
            "2c0a04087bc3d6d5d5c5c3e3"
        ));
        assert_eq!(reduced_bind.len(), 137);
        let request = Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            destination: Address {
                node: ebcdic_lu("SOLNET.SNAA").unwrap(),
            },
            source: Address {
                node: ebcdic_lu("SOLNET.SNAB").unwrap(),
            },
            correlator: vec![0x11; 8],
            requirements: TransportRequirements {
                max_record: 0x0205,
                max_expedited: 0x76,
                max_termination: 0x76,
            },
            options: vec![
                OptionalField {
                    kind: 0x05,
                    processing: 0x08,
                    value: vec![1, 1],
                },
                OptionalField {
                    kind: 0x0a,
                    processing: 0x02,
                    value: reduced_bind,
                },
                OptionalField {
                    kind: 0x18,
                    processing: 0,
                    value: vec![1],
                },
                OptionalField {
                    kind: 0x19,
                    processing: 0x0a,
                    value: vec![0, 0x20, 1, 3, 0x10, 0x83],
                },
                OptionalField {
                    kind: 0x1a,
                    processing: 0,
                    value: vec![0x84],
                },
            ],
        };
        let wire = request.encode().unwrap();
        assert_eq!(wire.len(), 230);
        Connect::decode(&wire).unwrap()
    }

    fn classify(request: Connect) -> io::Result<ReverseManagementConnect> {
        classify_reverse_management_connect(request, "SOLNET.SNAB", "SOLNET.SNAA", None)
    }

    fn bind_data_mut(request: &mut Connect) -> &mut Vec<u8> {
        &mut request
            .options
            .iter_mut()
            .find(|option| option.kind == 0x0a)
            .unwrap()
            .value
    }

    #[test]
    fn sixth_trace_shape_is_classified_without_preparing_a_response() {
        let request = captured_shape();
        let admitted = classify(request.clone()).unwrap();
        assert_eq!(admitted.request, request);
        assert_eq!(
            &admitted.fqpcid[..10],
            &[0x60, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]
        );
        assert!(classify_reverse_management_connect(
            request,
            "SOLNET.SNAB",
            "SOLNET.SNAA",
            Some(&admitted.fqpcid),
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_direction_lu_pair_and_correlator_shape() {
        let mut request = captured_shape();
        request.direction = Direction::PositiveResponse;
        request.processing = 0x8a;
        assert!(classify(request).is_err());

        let request = captured_shape();
        assert!(
            classify_reverse_management_connect(request, "SOLNET.OTHER", "SOLNET.SNAA", None,)
                .is_err()
        );

        let mut request = captured_shape();
        request.correlator.pop();
        assert!(classify(request).is_err());
    }

    #[test]
    fn rejects_wrong_mode_profile_truncation_and_missing_compensation() {
        let mut request = captured_shape();
        bind_data_mut(&mut request)[48] ^= 1; // SNASVCMG mode byte
        assert!(classify(request).is_err());

        let mut request = captured_shape();
        bind_data_mut(&mut request)[30] = 0x40; // V4 limited-resource profile
        assert!(classify(request).is_err());

        let mut request = captured_shape();
        bind_data_mut(&mut request)[103] = 0; // FQPCID control-vector key
        assert!(classify(request).is_err());

        let mut request = captured_shape();
        bind_data_mut(&mut request).pop();
        assert!(classify(request).is_err());

        let mut request = captured_shape();
        request
            .options
            .iter_mut()
            .find(|option| option.kind == 0x19)
            .unwrap()
            .value
            .pop();
        assert!(classify(request).is_err());
    }

    #[test]
    fn candidate_correlates_exactly_and_declines_unsupported_features() {
        let admitted = classify(captured_shape()).unwrap();
        let available = required_from_connect(admitted.request()).unwrap();
        let response = candidate_positive_management_response(&admitted, available).unwrap();
        let request = admitted.request();
        assert!(request.matches_response(&response));
        assert_eq!(response.direction, Direction::PositiveResponse);
        assert_eq!(response.processing, 0x8a);
        assert_eq!(response.correlator, request.correlator);
        assert_eq!(response.destination, request.destination);
        assert_eq!(response.source, request.source);
        assert_eq!(response.options[0], request.options[0]);
        assert_eq!(response.options[3], request.options[3]);
        assert_eq!(response.options[2].value, [0]);
        assert_eq!(response.options[4].value, [0]);

        let data = response.connection_data();
        assert_eq!(&data[..5], &[0, 0, 0xeb, 0x80, 0]);
        assert_eq!(&data[5..13], &request.connection_data()[5..13]);
        assert_eq!(&data[13..19], &[7, 1, 0x86, 0x86, 0x81, 7]);
        assert_eq!(&data[28..32], &[0, 0x23, 0, 0]);
        assert_eq!(&data[data.len() - 22..], admitted.fqpcid());
        assert_eq!(
            validate_positive_response(request.connection_data(), data),
            Ok(())
        );
        assert_ne!(data, request.connection_data());
    }

    #[test]
    fn candidate_requires_every_compensation_and_rejects_extra_options() {
        let admitted = classify(captured_shape()).unwrap();
        let incomplete = CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20]).unwrap();
        assert!(candidate_positive_management_response(&admitted, incomplete).is_err());

        let mut request = captured_shape();
        request.options[0].value = vec![2, 1]; // unhandled MPTN service mode
        let admitted = classify(request).unwrap();
        let complete = required_from_connect(admitted.request()).unwrap();
        assert!(candidate_positive_management_response(&admitted, complete).is_err());

        let mut request = captured_shape();
        request.options.push(OptionalField {
            kind: 0x1c,
            processing: 0,
            value: vec![1, 2],
        });
        let admitted = classify(request).unwrap();
        assert!(candidate_positive_management_response(&admitted, complete).is_err());

        let mut request = captured_shape();
        request.options[2].value = vec![1, 1]; // unhandled multiple SON values
        let admitted = classify(request).unwrap();
        assert!(candidate_positive_management_response(&admitted, complete).is_err());
    }

    #[test]
    fn candidate_uses_the_current_request_session_instance() {
        let first = classify(captured_shape()).unwrap();
        let mut second_request = captured_shape();
        let data = bind_data_mut(&mut second_request);
        let fqpcid_offset = data
            .windows(2)
            .position(|bytes| bytes == [0x60, 0x14])
            .unwrap();
        data[fqpcid_offset + 3] ^= 1;
        second_request.correlator[0] ^= 1;
        let second = classify(second_request).unwrap();
        let complete = required_from_connect(first.request()).unwrap();
        let first_response = candidate_positive_management_response(&first, complete).unwrap();
        let second_response = candidate_positive_management_response(&second, complete).unwrap();
        assert_ne!(first.fqpcid(), second.fqpcid());
        assert_ne!(first_response.correlator, second_response.correlator);
        assert_ne!(
            first_response.connection_data(),
            second_response.connection_data()
        );
        assert!(validate_positive_response(
            first.request().connection_data(),
            second_response.connection_data()
        )
        .is_err());
    }
}
