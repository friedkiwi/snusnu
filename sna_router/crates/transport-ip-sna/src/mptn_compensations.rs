//! Capability gate for the X'19' TCP62 Compensations Required option.
//!
//! IBM's TCP62 draft, section 5.3.1.1.4, assigns six compensation codes to
//! LU 6.2 over TCP. The V5R4 AnyNet Connect request and positive response
//! both carry all six, in the order `[00, 20, 01, 03, 10, 83]`. A gateway
//! must not accept this option unless it can perform every required mapping.

use crate::mptn_connect::Connect;
use std::{error::Error, fmt};

pub const TCP62_REQUIRED: [u8; 6] = [0x00, 0x01, 0x03, 0x10, 0x20, 0x83];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompensationError {
    MissingRequiredField,
    DuplicateRequiredField,
    InvalidRequiredCode,
    DuplicateCode,
}

impl fmt::Display for CompensationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid TCP62 required compensations: {self:?}")
    }
}

impl Error for CompensationError {}

/// Each supported code represents actual implemented behavior, not merely a
/// parser that recognizes the code in an MPTN Connect record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompensationSet(u8);

impl CompensationSet {
    pub fn from_codes(codes: &[u8]) -> Result<Self, CompensationError> {
        let mut bits = 0u8;
        for &code in codes {
            let bit = code_bit(code).ok_or(CompensationError::InvalidRequiredCode)?;
            if bits & bit != 0 {
                return Err(CompensationError::DuplicateCode);
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }

    pub fn supports(&self, code: u8) -> bool {
        code_bit(code).is_some_and(|bit| self.0 & bit != 0)
    }

    pub fn is_complete_tcp62(&self) -> bool {
        self.0 == 0x3f
    }

    pub fn missing_from(&self, available: Self) -> Vec<u8> {
        TCP62_REQUIRED
            .into_iter()
            .filter(|&code| self.supports(code) && !available.supports(code))
            .collect()
    }
}

fn code_bit(code: u8) -> Option<u8> {
    match code {
        0x00 => Some(1 << 0), // record boundary marker
        0x01 => Some(1 << 1), // expedited message
        0x03 => Some(1 << 2), // expedited acknowledgement
        0x10 => Some(1 << 3), // duplex abortive termination
        0x20 => Some(1 << 4), // segmented message
        0x83 => Some(1 << 5), // datagram out-of-band data
        _ => None,
    }
}

/// Extract a required set from a decoded MPTN Connect. The optional field is
/// architecturally required when any compensation is required; TCP62 requires
/// all six for full interoperability. This remains separate from `Connect`
/// framing so callers can explicitly test their implemented capabilities.
pub fn required_from_connect(connect: &Connect) -> Result<CompensationSet, CompensationError> {
    let mut matching = connect.options.iter().filter(|field| field.kind == 0x19);
    let field = matching
        .next()
        .ok_or(CompensationError::MissingRequiredField)?;
    if matching.next().is_some() {
        return Err(CompensationError::DuplicateRequiredField);
    }
    CompensationSet::from_codes(&field.value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{Address, Direction, OptionalField, TransportRequirements};

    fn captured_v5r4_options() -> Connect {
        // Sanitized option values from direct-anynet-sol6.pcap p7/p9.
        Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            destination: Address {
                node: vec![0xc1; 11],
            },
            source: Address {
                node: vec![0xc2; 11],
            },
            correlator: vec![1],
            requirements: TransportRequirements {
                max_record: 0x8005,
                max_expedited: 0x76,
                max_termination: 0x76,
            },
            options: vec![
                OptionalField {
                    kind: 0x05,
                    processing: 0x08,
                    value: vec![0x01, 0x01],
                },
                OptionalField {
                    kind: 0x0a,
                    processing: 0x02,
                    value: vec![0x31],
                },
                OptionalField {
                    kind: 0x18,
                    processing: 0x00,
                    value: vec![0x01],
                },
                OptionalField {
                    kind: 0x19,
                    processing: 0x0a,
                    value: vec![0x00, 0x20, 0x01, 0x03, 0x10, 0x83],
                },
                OptionalField {
                    kind: 0x1a,
                    processing: 0x00,
                    value: vec![0x84],
                },
            ],
        }
    }

    #[test]
    fn captures_all_six_required_compensations() {
        let request = captured_v5r4_options();
        let required = required_from_connect(&request).unwrap();
        assert!(required.is_complete_tcp62());
        assert_eq!(required.missing_from(required), []);
        let only_normal = CompensationSet::from_codes(&[0x00]).unwrap();
        assert_eq!(
            required.missing_from(only_normal),
            [0x01, 0x03, 0x10, 0x20, 0x83]
        );
        let mut response = request;
        response.direction = Direction::PositiveResponse;
        response.processing = 0x8a;
        assert_eq!(required_from_connect(&response), Ok(required));
    }

    #[test]
    fn malformed_or_missing_required_codes_fail_closed() {
        let mut request = captured_v5r4_options();
        request.options.retain(|option| option.kind != 0x19);
        assert_eq!(
            required_from_connect(&request),
            Err(CompensationError::MissingRequiredField)
        );
        request.options.push(OptionalField {
            kind: 0x19,
            processing: 0x0a,
            value: vec![0x00, 0x00],
        });
        assert_eq!(
            required_from_connect(&request),
            Err(CompensationError::DuplicateCode)
        );
        request.options.last_mut().unwrap().value = vec![0xff];
        assert_eq!(
            required_from_connect(&request),
            Err(CompensationError::InvalidRequiredCode)
        );
        request.options.last_mut().unwrap().value = vec![0x00];
        let duplicate = request.options.last().unwrap().clone();
        request.options.push(duplicate);
        assert_eq!(
            required_from_connect(&request),
            Err(CompensationError::DuplicateRequiredField)
        );
    }
}
