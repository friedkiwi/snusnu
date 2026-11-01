//! Pure admission gate for the captured V5R4 reverse SNASVCMG Connect.
//!
//! TCP62 removes FID2 DAF/OAF/ODAI from Connect's BIND image. Synthetic
//! nonzero FID2 addresses below exist only to reuse the strict LU 6.2 BIND
//! parser; they are never returned or used for a native session. This module
//! does not produce a BIND response or establish a management session.

use std::io;

use router_core::fid2_session_control::ManagementBind;

use crate::{
    mptn_compensations::required_from_connect,
    mptn_connect::{Connect, Direction},
};

const V5_MANAGEMENT_FIXED: [u8; 27] = [
    0x31, 0x00, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33, 0x07, 0x87, 0x86, 0x86, 0x87, 0x07, 0x06, 0x02,
    0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0, 0,
];
const REDUCED_BIND_BYTES: usize = 137;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReverseManagementConnect {
    /// The complete, validated request is retained for response correlation.
    /// Owning it does not authorize a positive response.
    pub request: Connect,
    pub fqpcid: [u8; 22],
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn ebcdic_lu(name: &str) -> io::Result<Vec<u8>> {
    if name.len() < 3 || name.len() > 17 || name.matches('.').count() != 1 {
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
    forbidden_fqpcid: Option<&[u8; 22]>,
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
    if data.len() != REDUCED_BIND_BYTES
        || data[..5] != [0, 0, 0x6b, 0x80, 0]
        || data[5..32] != V5_MANAGEMENT_FIXED
    {
        return Err(invalid(
            "reverse management BIND fixed profile is unsupported",
        ));
    }
    let mut synthetic_piu = Vec::with_capacity(data.len() + 4);
    synthetic_piu.extend_from_slice(&[0x2d, 0, 1, 2]);
    synthetic_piu.extend_from_slice(data);
    let bind = ManagementBind::from_request(&synthetic_piu, expected_peer_lu, expected_local_lu)
        .map_err(|_| invalid("reverse management BIND mode, LU pair, or FQPCID invalid"))?;
    if forbidden_fqpcid.is_some_and(|known| bind.fqpcid() == known) {
        return Err(invalid("reverse management FQPCID reuses native session"));
    }
    Ok(ReverseManagementConnect {
        request,
        fqpcid: *bind.fqpcid(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{Address, OptionalField, TransportRequirements};

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
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
        assert_eq!(reduced_bind.len(), REDUCED_BIND_BYTES);
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
}
