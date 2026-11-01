//! Bounded LU 6.2 CNOS GDS processing for an APPN management session.
//!
//! IBM documents the X'1210' variable in the SNA Programmer's LU 6.2 Guide:
//! https://www.ibm.com/docs/en/zos/3.2.0?topic=sessions-cnos-general-data-stream-gds-variable
//! A reply service flag X'0A' means *accepted but not yet completed*. This
//! module therefore never declares a native APPN adjacency ready. Its caller
//! must manage the FMH-5 conversation, bracket state, and session completion.

use std::{error::Error, fmt};

pub const MAX_GDS_BYTES: usize = 25;
const GDS_ID: [u8; 2] = [0x12, 0x10];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    Request,
    AcceptedPending,
    AbnormalReply,
}

impl Service {
    fn from_wire(value: u8) -> Result<Self, CnosError> {
        match value {
            0x02 => Ok(Self::Request),
            0x0a => Ok(Self::AcceptedPending),
            0x08 => Ok(Self::AbnormalReply),
            _ => Err(CnosError::Unsupported),
        }
    }

    fn wire(self) -> u8 {
        match self {
            Self::Request => 0x02,
            Self::AcceptedPending => 0x0a,
            Self::AbnormalReply => 0x08,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CnosGds {
    pub service: Service,
    pub modifier: u8,
    pub session_limit: u16,
    pub source_winners: u16,
    pub target_winners: u16,
    /// Empty string means the SNA-defined default mode.
    pub mode: String,
    /// Encoded field width, including right-padding. A blank default mode
    /// can be represented by zero or by eight EBCDIC blanks.
    pub mode_field_length: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CnosError {
    Truncated,
    InvalidStructure,
    Unsupported,
    UnexpectedState,
    PolicyDenied,
}

impl fmt::Display for CnosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid CNOS management exchange: {self:?}")
    }
}

impl Error for CnosError {}

impl CnosGds {
    /// Parse one complete X'1210' GDS variable, excluding FMH-5 and PIU
    /// framing. The caller must bound the containing LU6.2 conversation.
    pub fn decode(bytes: &[u8]) -> Result<Self, CnosError> {
        if bytes.len() < 17 {
            return Err(CnosError::Truncated);
        }
        if bytes.len() > MAX_GDS_BYTES
            || usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) != bytes.len()
            || bytes[2..4] != GDS_ID
            || bytes[6] != 0 // Set limits only; close has different semantics.
            || bytes[7] != 0
            || bytes[8] & !1 != 0
            || bytes[15] != 0
            || bytes[16] > 8
            || bytes.len() != 17 + usize::from(bytes[16])
        {
            return Err(CnosError::InvalidStructure);
        }
        let service = Service::from_wire(bytes[4])?;
        let modifier = bytes[5];
        if (service == Service::Request && modifier != 0)
            || (service != Service::Request && !matches!(modifier, 0 | 1 | 2 | 4 | 5))
        {
            return Err(CnosError::InvalidStructure);
        }
        let session_limit = u16::from_be_bytes([bytes[9], bytes[10]]);
        let source_winners = u16::from_be_bytes([bytes[11], bytes[12]]);
        let target_winners = u16::from_be_bytes([bytes[13], bytes[14]]);
        if session_limit & 0x8000 != 0
            || source_winners & 0x8000 != 0
            || target_winners & 0x8000 != 0
            || usize::from(source_winners) + usize::from(target_winners)
                > usize::from(session_limit)
        {
            return Err(CnosError::InvalidStructure);
        }
        let mode = decode_mode(&bytes[17..])?;
        Ok(Self {
            service,
            modifier,
            session_limit,
            source_winners,
            target_winners,
            mode,
            mode_field_length: bytes[16],
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CnosError> {
        if self.session_limit & 0x8000 != 0
            || self.source_winners & 0x8000 != 0
            || self.target_winners & 0x8000 != 0
            || usize::from(self.source_winners) + usize::from(self.target_winners)
                > usize::from(self.session_limit)
            || self.mode.len() > 8
            || usize::from(self.mode_field_length) > 8
            || self.mode.len() > usize::from(self.mode_field_length)
            || (self.service == Service::Request && self.modifier != 0)
            || (self.service != Service::Request && !matches!(self.modifier, 0 | 1 | 2 | 4 | 5))
        {
            return Err(CnosError::InvalidStructure);
        }
        let mut mode = encode_mode(&self.mode)?;
        mode.resize(usize::from(self.mode_field_length), 0x40);
        let len = 17 + mode.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u16).to_be_bytes());
        bytes.extend_from_slice(&GDS_ID);
        bytes.extend_from_slice(&[self.service.wire(), self.modifier, 0, 0, 0]);
        bytes.extend_from_slice(&self.session_limit.to_be_bytes());
        bytes.extend_from_slice(&self.source_winners.to_be_bytes());
        bytes.extend_from_slice(&self.target_winners.to_be_bytes());
        bytes.extend_from_slice(&[0, mode.len() as u8]);
        bytes.extend_from_slice(&mode);
        Ok(bytes)
    }
}

fn decode_mode(bytes: &[u8]) -> Result<String, CnosError> {
    let mut name = String::new();
    let mut padded = false;
    for &byte in bytes {
        if byte == 0x40 {
            padded = true;
            continue;
        }
        if padded {
            return Err(CnosError::InvalidStructure);
        }
        let character = match byte {
            0xc1..=0xc9 => b'A' + byte - 0xc1,
            0xd1..=0xd9 => b'J' + byte - 0xd1,
            0xe2..=0xe9 => b'S' + byte - 0xe2,
            0xf0..=0xf9 => b'0' + byte - 0xf0,
            0x7c => b'@',
            0x7b => b'#',
            0x5b => b'$',
            _ => return Err(CnosError::InvalidStructure),
        };
        name.push(char::from(character));
    }
    Ok(name)
}

fn encode_mode(name: &str) -> Result<Vec<u8>, CnosError> {
    let mut result = Vec::with_capacity(name.len());
    for byte in name.bytes() {
        result.push(match byte {
            b'A'..=b'I' => 0xc1 + (byte - b'A'),
            b'J'..=b'R' => 0xd1 + (byte - b'J'),
            b'S'..=b'Z' => 0xe2 + (byte - b'S'),
            b'0'..=b'9' => 0xf0 + (byte - b'0'),
            b'@' => 0x7c,
            b'#' => 0x7b,
            b'$' => 0x5b,
            _ => return Err(CnosError::InvalidStructure),
        });
    }
    Ok(result)
}

/// A negotiated request is only *pending* after the positive CNOS reply.
/// APPN bracket and session completion must be established by another
/// component before it permits user-session activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeState {
    AwaitingRequest,
    AcceptedPending,
    Complete,
}

pub struct CnosResponder {
    state: ExchangeState,
    expected_mode: String,
    maximum_sessions: u16,
}

impl CnosResponder {
    pub fn new(expected_mode: String, maximum_sessions: u16) -> Result<Self, CnosError> {
        if expected_mode.len() > 8 || maximum_sessions == 0 || maximum_sessions > 0x7fff {
            return Err(CnosError::InvalidStructure);
        }
        encode_mode(&expected_mode)?;
        Ok(Self {
            state: ExchangeState::AwaitingRequest,
            expected_mode,
            maximum_sessions,
        })
    }

    pub fn state(&self) -> ExchangeState {
        self.state
    }

    pub fn accept_request(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CnosError> {
        if self.state != ExchangeState::AwaitingRequest {
            return Err(CnosError::UnexpectedState);
        }
        let request = CnosGds::decode(bytes)?;
        if request.service != Service::Request {
            return Err(CnosError::UnexpectedState);
        }
        if request.mode != self.expected_mode
            || request.session_limit == 0
            || request.session_limit > self.maximum_sessions
        {
            return Err(CnosError::PolicyDenied);
        }
        let reply = CnosGds {
            service: Service::AcceptedPending,
            modifier: 0,
            ..request
        };
        let encoded = reply.encode()?;
        self.state = ExchangeState::AcceptedPending;
        Ok(encoded)
    }

    /// Called only after the separate APPN conversation/bracket engine has
    /// established that the accepted operation actually completed. Receipt
    /// of BIS alone is insufficient for this transition.
    pub fn mark_completed(&mut self) -> Result<(), CnosError> {
        if self.state != ExchangeState::AcceptedPending {
            return Err(CnosError::UnexpectedState);
        }
        self.state = ExchangeState::Complete;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized V4R4 X'1210' request/reply from SNASVCMG. The eight EBCDIC
    // blanks designate the default mode; these are independent wire vectors.
    const REQUEST: [u8; 25] = [
        0, 25, 0x12, 0x10, 0x02, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40,
    ];
    const ACCEPTED_PENDING: [u8; 25] = [
        0, 25, 0x12, 0x10, 0x0a, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40,
    ];

    #[test]
    fn parses_observed_request_and_preserves_pending_semantics() {
        let request = CnosGds::decode(&REQUEST).unwrap();
        assert_eq!(request.service, Service::Request);
        assert_eq!(request.mode, "");
        assert_eq!(request.session_limit, 8);
        assert_eq!(request.source_winners, 4);
        assert_eq!(request.target_winners, 4);
        let mut responder = CnosResponder::new(String::new(), 8).unwrap();
        assert_eq!(
            responder.accept_request(&REQUEST).unwrap(),
            ACCEPTED_PENDING
        );
        assert_eq!(responder.state(), ExchangeState::AcceptedPending);
        assert_eq!(
            CnosGds::decode(&ACCEPTED_PENDING).unwrap().service,
            Service::AcceptedPending
        );
    }

    #[test]
    fn never_implicitly_completes_on_pending_reply() {
        let mut responder = CnosResponder::new(String::new(), 8).unwrap();
        responder.accept_request(&REQUEST).unwrap();
        assert_eq!(responder.state(), ExchangeState::AcceptedPending);
        responder.mark_completed().unwrap();
        assert_eq!(responder.state(), ExchangeState::Complete);
        assert_eq!(responder.mark_completed(), Err(CnosError::UnexpectedState));
    }

    #[test]
    fn rejects_malformed_or_unsupported_request() {
        assert_eq!(CnosGds::decode(&REQUEST[..16]), Err(CnosError::Truncated));
        let mut malformed = REQUEST;
        malformed[0] = 1;
        assert_eq!(
            CnosGds::decode(&malformed),
            Err(CnosError::InvalidStructure)
        );
        malformed = REQUEST;
        malformed[13..15].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            CnosGds::decode(&malformed),
            Err(CnosError::InvalidStructure)
        );
        malformed = REQUEST;
        malformed[6] = 2;
        assert_eq!(
            CnosGds::decode(&malformed),
            Err(CnosError::InvalidStructure)
        );
        let mut responder = CnosResponder::new("APPTEST".into(), 8).unwrap();
        assert_eq!(
            responder.accept_request(&REQUEST),
            Err(CnosError::PolicyDenied)
        );
        assert_eq!(responder.state(), ExchangeState::AwaitingRequest);
    }
}
