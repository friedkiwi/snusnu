//! Bounded structural parser and correlation for TCP62 UDP/397 `X'83'`.
//!
//! IBM's TCP62 draft section 5.3.3 defines this command. No V5R4 `X'83'`
//! packet was observed in the direct V5R4 lab captures, so this module does
//! not generate datagrams, interpret SNA payloads, or enable the required
//! compensation. A caller still needs a session map, OOB response/retry
//! timers, and deduplication against expedited data carried on TCP.

use std::{collections::VecDeque, io};

use crate::{
    anynet::MAX_RECORD,
    mptn_connect::{Connect, Direction},
};

const REC_HEADER: usize = 4;
const COMMON_PREFIX: usize = 4;
const MIN_SNA_HEADER: usize = 5;
const RECENT_SEQUENCES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Request,
    PositiveResponse,
    NegativeResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compensation {
    Expedited,
    Abort,
}

#[derive(Debug, Eq, PartialEq)]
pub struct OptionField<'a> {
    pub kind: u8,
    pub processing: u8,
    pub value: &'a [u8],
}

#[derive(Debug, Eq, PartialEq)]
pub struct Datagram<'a> {
    pub kind: Kind,
    pub sequence: u16,
    /// EBCDIC network-qualified LU name of the original Connect initiator.
    pub correlator_node: &'a [u8],
    pub correlator_suffix: &'a [u8],
    pub options: Vec<OptionField<'a>>,
    pub compensation: Option<Compensation>,
    /// Reduced TH/RH/RU on a request; empty on a response.
    pub user_data: &'a [u8],
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl<'a> Datagram<'a> {
    pub fn decode(bytes: &'a [u8]) -> io::Result<Self> {
        if !(19..=MAX_RECORD).contains(&bytes.len())
            || u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize != bytes.len()
            || bytes[4] != 0x83
        {
            return Err(invalid("invalid TCP62 OOB record length or type"));
        }
        let kind = match bytes[5] {
            0x02 => Kind::Request,
            0x82 => Kind::PositiveResponse,
            0xc2 => Kind::NegativeResponse,
            _ => return Err(invalid("unsupported TCP62 OOB processing flags")),
        };
        let command_len = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
        let end = REC_HEADER
            .checked_add(command_len)
            .ok_or_else(|| invalid("TCP62 OOB command length overflow"))?;
        // The shortest LU address is qualifier + mode + a four-byte node
        // address (including its length byte) + null local address.
        if command_len < COMMON_PREFIX + 2 + 7 + 2 || end > bytes.len() {
            return Err(invalid("TCP62 OOB command length mismatch"));
        }
        let sequence = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
        let mut cursor = 12;
        if bytes[cursor..end].len() < 4 || bytes[cursor] != 0x0b || bytes[cursor + 1] != 0x01 {
            return Err(invalid("unsupported TCP62 OOB correlator address"));
        }
        let node_len = bytes[cursor + 2] as usize;
        if !(4..=18).contains(&node_len) || cursor + 3 + node_len > end {
            return Err(invalid("TCP62 OOB correlator node length is invalid"));
        }
        let correlator_node = &bytes[cursor + 3..cursor + 2 + node_len];
        cursor += 2 + node_len;
        if bytes[cursor] != 0x01 {
            return Err(invalid("TCP62 OOB correlator local address is not null"));
        }
        cursor += 1;
        if cursor >= end {
            return Err(invalid("TCP62 OOB correlator suffix missing"));
        }
        let suffix_len = bytes[cursor] as usize;
        if !(2..=9).contains(&suffix_len) || cursor + suffix_len > end {
            return Err(invalid("TCP62 OOB correlator suffix length is invalid"));
        }
        let correlator_suffix = &bytes[cursor + 1..cursor + suffix_len];
        cursor += suffix_len;
        let mut options = Vec::new();
        while cursor < end {
            if end - cursor < COMMON_PREFIX {
                return Err(invalid("truncated TCP62 OOB optional field"));
            }
            let kind = bytes[cursor];
            let processing = bytes[cursor + 1];
            let len =
                u16::from_be_bytes(bytes[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
            if len < COMMON_PREFIX || cursor + len > end {
                return Err(invalid("invalid TCP62 OOB optional field length"));
            }
            if !matches!(kind, 0x28 | 0x29 | 0x2e | 0xf0) {
                return Err(invalid("unsupported TCP62 OOB optional field"));
            }
            let value = &bytes[cursor + COMMON_PREFIX..cursor + len];
            if matches!(kind, 0x28 | 0x29) && (value.len() < 5 || value[..2] != [0x7f, 0x01]) {
                return Err(invalid("unsupported TCP62 OOB connection alias"));
            }
            if kind == 0x2e && value.len() != 4 {
                return Err(invalid("invalid TCP62 OOB datagram size option"));
            }
            if kind == 0xf0 && value.len() < 14 {
                return Err(invalid("invalid TCP62 OOB diagnostics"));
            }
            options.push(OptionField {
                kind,
                processing,
                value,
            });
            cursor += len;
        }
        let (compensation, user_data) = match kind {
            Kind::Request => {
                let header = *bytes
                    .get(end)
                    .ok_or_else(|| invalid("TCP62 OOB request lacks MPTN header"))?;
                let compensation = match header {
                    0x01 => Compensation::Expedited,
                    0x10 => Compensation::Abort,
                    _ => return Err(invalid("unsupported TCP62 OOB compensation")),
                };
                let user_data = &bytes[end + 1..];
                if (compensation == Compensation::Expedited && user_data.len() < MIN_SNA_HEADER)
                    || (!user_data.is_empty() && user_data.len() < MIN_SNA_HEADER)
                {
                    return Err(invalid("TCP62 OOB SNA header is truncated"));
                }
                (Some(compensation), user_data)
            }
            Kind::PositiveResponse | Kind::NegativeResponse => {
                if end != bytes.len() {
                    return Err(invalid("TCP62 OOB response has payload"));
                }
                (None, &bytes[end..])
            }
        };
        Ok(Self {
            kind,
            sequence,
            correlator_node,
            correlator_suffix,
            options,
            compensation,
            user_data,
        })
    }

    /// The correlator address and suffix name the original MPTN Connect
    /// requester even when an OOB response travels in the reverse direction.
    pub fn matches_connect(&self, request: &Connect) -> bool {
        request.direction == Direction::Request
            && self.correlator_node == request.source.node
            && self.correlator_suffix == request.correlator
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arrival {
    New,
    Duplicate,
}

/// Bounded per-connection sequence bookkeeping. It only deduplicates recent
/// UDP requests and correlates replies; it cannot deduplicate against TCP
/// expedited records without the owning session's separate sequence state.
#[derive(Default)]
pub struct SequenceState {
    recent_requests: VecDeque<u16>,
    pending_responses: VecDeque<u16>,
}

impl SequenceState {
    pub fn receive_request(&mut self, sequence: u16) -> Arrival {
        if self.recent_requests.contains(&sequence) {
            return Arrival::Duplicate;
        }
        if self.recent_requests.len() == RECENT_SEQUENCES {
            self.recent_requests.pop_front();
        }
        self.recent_requests.push_back(sequence);
        Arrival::New
    }

    pub fn sent_request(&mut self, sequence: u16) -> io::Result<()> {
        if self.pending_responses.contains(&sequence) {
            return Err(invalid("duplicate pending TCP62 OOB sequence"));
        }
        if self.pending_responses.len() == RECENT_SEQUENCES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP62 OOB response window full",
            ));
        }
        self.pending_responses.push_back(sequence);
        Ok(())
    }

    pub fn receive_response(&mut self, sequence: u16) -> io::Result<()> {
        let index = self
            .pending_responses
            .iter()
            .position(|&pending| pending == sequence)
            .ok_or_else(|| invalid("unsolicited TCP62 OOB response"))?;
        self.pending_responses.remove(index);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{Address, TransportRequirements};

    fn message(processing: u8, sequence: u16, payload: &[u8]) -> Vec<u8> {
        // Synthetic, privacy-safe LU address and suffix with the same wire
        // shape as the V5R4 MPTN Connect correlator.
        let mut bytes = vec![0; 4];
        bytes.extend_from_slice(&[0x83, processing, 0, 0, 0, 0]);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&[0x0b, 0x01, 0x05, 0xc1, 0x4b, 0xc2, 0xc3, 0x01]);
        bytes.extend_from_slice(&[0x02, 0x44]);
        let command_len = (bytes.len() - 4) as u32;
        bytes[6..10].copy_from_slice(&command_len.to_be_bytes());
        bytes.extend_from_slice(payload);
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_request_and_response_with_connect_identity() {
        let request = message(0x02, 7, &[0x01, 0, 1, 0x03, 0, 0, 0xaa]);
        let parsed = Datagram::decode(&request).unwrap();
        assert_eq!(parsed.kind, Kind::Request);
        assert_eq!(parsed.sequence, 7);
        assert_eq!(parsed.compensation, Some(Compensation::Expedited));
        assert_eq!(parsed.user_data.len(), 6);
        let connect = Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 1,
            destination: Address {
                node: vec![0xc4; 4],
            },
            source: Address {
                node: vec![0xc1, 0x4b, 0xc2, 0xc3],
            },
            correlator: vec![0x44],
            requirements: TransportRequirements {
                max_record: 1024,
                max_expedited: 100,
                max_termination: 100,
            },
            options: vec![],
        };
        assert!(parsed.matches_connect(&connect));
        let response = message(0x82, 7, &[]);
        assert_eq!(
            Datagram::decode(&response).unwrap().kind,
            Kind::PositiveResponse
        );
    }

    #[test]
    fn rejects_bad_lengths_and_response_payload() {
        let mut bad = message(0x02, 1, &[0x10]);
        bad[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Datagram::decode(&bad).is_err());
        bad = message(0x82, 1, &[0x01, 0, 1, 0x03, 0, 0]);
        assert!(Datagram::decode(&bad).is_err());
        bad = message(0x02, 1, &[0x01, 0, 1]);
        assert!(Datagram::decode(&bad).is_err());
        bad = message(0x02, 1, &[0x10]);
        bad[12] = 0x7f;
        assert!(Datagram::decode(&bad).is_err());
    }

    #[test]
    fn bounds_recent_requests_and_correlates_replies() {
        let mut state = SequenceState::default();
        assert_eq!(state.receive_request(65535), Arrival::New);
        assert_eq!(state.receive_request(65535), Arrival::Duplicate);
        assert_eq!(state.receive_request(0), Arrival::New);
        state.sent_request(7).unwrap();
        assert!(state.sent_request(7).is_err());
        assert!(state.receive_response(8).is_err());
        state.receive_response(7).unwrap();
        assert!(state.receive_response(7).is_err());
        for seq in 1..=64 {
            state.sent_request(seq).unwrap();
        }
        assert_eq!(
            state.sent_request(65).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
