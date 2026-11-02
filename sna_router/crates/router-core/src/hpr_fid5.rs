//! Receive-only framing of a complete HPR FID5 whole-BIU message.
//!
//! IBM *SNA Formats* GA27-3136-20, FID5 TH chapter, defines a 12-byte
//! transmission header followed by a 3-byte request/response header (RH) and
//! an optional request/response unit (RU). The caller must first establish an
//! RTP connection and reassemble one complete RTP message. This module does
//! not assign a session address or accept a BIND. Once framing is validated,
//! it can classify a BIND's LU names and mode for route policy.

use crate::fid2_bind::{classify_reduced_bind, BindError, BindIdentity};
use crate::session::{Flow, SessionError, SessionUnit};

const FID5_TH_LEN: usize = 12;
const RH_LEN: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fid5Error {
    Truncated,
    WrongFormat,
    SegmentedBiu,
    NonzeroReserved,
    InvalidSessionAddress,
}

/// Form a whole-BIU FID5 message for a session whose directional address has
/// already been established by the HPR session adapter. This does not assign
/// an address or transmit an RTP packet. The first bit of the address is the
/// assignor indicator; its second bit is reserved (IBM SNA Formats, p. 4-15).
pub fn encode_whole_biu(
    session_address: [u8; 8],
    flow: Flow,
    unit: &SessionUnit,
) -> Result<Vec<u8>, Fid5Error> {
    if session_address[0] & 0x40 != 0 {
        return Err(Fid5Error::InvalidSessionAddress);
    }
    let mut message = Vec::with_capacity(FID5_TH_LEN + RH_LEN + unit.ru().len());
    message.push(0x5c | u8::from(flow == Flow::Expedited));
    message.push(0);
    message.extend_from_slice(unit.snf());
    message.extend_from_slice(&session_address);
    message.extend_from_slice(unit.rh());
    message.extend_from_slice(unit.ru());
    Ok(message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fid5WholeBiu<'a> {
    /// Complete 12-byte FID5 transmission header.
    pub th: &'a [u8],
    /// Two-byte FID5 sequence number field (SNF), in network byte order.
    pub sequence_number: u16,
    /// Eight-byte directional session address. It is opaque until RTP and
    /// session setup have established its owner and meaning.
    pub session_address: [u8; 8],
    pub expedited: bool,
    /// Complete three-byte SNA request/response header. Its bits are left
    /// uninterpreted by this framing layer.
    pub rh: [u8; RH_LEN],
    /// May be empty, as seen in a V5R4 whole-BIU control message.
    pub ru: &'a [u8],
}

impl<'a> Fid5WholeBiu<'a> {
    /// Preserve the SNA sequence field, RH, and RU for the carrier-neutral
    /// session boundary. The caller must already have verified the RTP
    /// connection and directional session-address ownership.
    pub fn session_unit(&self) -> Result<SessionUnit, SessionError> {
        let mut reduced = Vec::with_capacity(2 + RH_LEN + self.ru.len());
        reduced.extend_from_slice(&self.th[2..4]);
        reduced.extend_from_slice(&self.rh);
        reduced.extend_from_slice(self.ru);
        SessionUnit::from_reduced(&reduced)
    }

    /// Extract LU 6.2 BIND identity from a complete whole BIU. The FID5
    /// session address stays opaque; this only interprets RH and RU.
    pub fn classify_bind(&self) -> Result<Option<BindIdentity>, BindError> {
        classify_reduced_bind(&self.rh, self.ru)
    }

    /// Parse exactly one already-reassembled RTP message containing a whole
    /// FID5 BIU. FID5 segmentation (MPF 00/01/10) needs separate state and is
    /// rejected here. This method cannot prove the RTP message is complete;
    /// the caller must use a validated receive stream.
    pub fn parse_complete(message: &'a [u8]) -> Result<Self, Fid5Error> {
        if message.len() < FID5_TH_LEN + RH_LEN {
            return Err(Fid5Error::Truncated);
        }
        if message[0] >> 4 != 0x05 {
            return Err(Fid5Error::WrongFormat);
        }
        if message[0] & 0x0c != 0x0c {
            return Err(Fid5Error::SegmentedBiu);
        }
        if message[0] & 0x02 != 0 || message[1] != 0 {
            return Err(Fid5Error::NonzeroReserved);
        }
        Ok(Self {
            th: &message[..FID5_TH_LEN],
            sequence_number: u16::from_be_bytes(message[2..4].try_into().unwrap()),
            session_address: message[4..12].try_into().unwrap(),
            expedited: message[0] & 1 != 0,
            rh: message[12..15].try_into().unwrap(),
            ru: &message[15..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_v5r4_bind_shape() -> Vec<u8> {
        // The successful V5R4 medium-priority setup carried 147 FID5 data
        // bytes: 12 TH + 3 RH + 132 RU. All fields here are synthetic.
        let mut message = vec![0; 147];
        message[0] = 0x5d; // FID5, whole BIU, expedited.
        message[2..4].copy_from_slice(&0x8001u16.to_be_bytes());
        message[4..12].copy_from_slice(b"SESSION1");
        message[12..15].copy_from_slice(&[0x6b, 0x80, 0]);
        message[15] = 0x31; // BIND-like control opcode, not parsed here.
        message
    }

    #[test]
    fn frames_sanitized_v5r4_whole_biu_shape() {
        let message = synthetic_v5r4_bind_shape();
        let fid5 = Fid5WholeBiu::parse_complete(&message).unwrap();
        assert_eq!(fid5.th.len(), 12);
        assert_eq!(fid5.sequence_number, 0x8001);
        assert_eq!(fid5.session_address, *b"SESSION1");
        assert!(fid5.expedited);
        assert_eq!(fid5.rh, [0x6b, 0x80, 0]);
        assert_eq!(fid5.ru.len(), 132);
        assert_eq!(fid5.ru[0], 0x31);
        let unit = fid5.session_unit().unwrap();
        assert_eq!(unit.snf(), &[0x80, 0x01]);
        assert_eq!(unit.rh(), &[0x6b, 0x80, 0]);
        assert_eq!(unit.ru(), fid5.ru);
    }

    #[test]
    fn accepts_observed_empty_ru_whole_biu_shape() {
        let mut message = synthetic_v5r4_bind_shape();
        message.truncate(15);
        message[0] = 0x5c; // Normal flow.
        let fid5 = Fid5WholeBiu::parse_complete(&message).unwrap();
        assert!(!fid5.expedited);
        assert!(fid5.ru.is_empty());
    }

    #[test]
    fn rejects_truncated_non_fid5_segmented_and_reserved_headers() {
        let original = synthetic_v5r4_bind_shape();
        assert_eq!(
            Fid5WholeBiu::parse_complete(&original[..14]),
            Err(Fid5Error::Truncated)
        );
        let mut message = original.clone();
        message[0] = 0x2d;
        assert_eq!(
            Fid5WholeBiu::parse_complete(&message),
            Err(Fid5Error::WrongFormat)
        );
        for mapping in [0x00, 0x04, 0x08] {
            message = original.clone();
            message[0] = 0x50 | mapping;
            assert_eq!(
                Fid5WholeBiu::parse_complete(&message),
                Err(Fid5Error::SegmentedBiu)
            );
        }
        message = original.clone();
        message[0] |= 0x02;
        assert_eq!(
            Fid5WholeBiu::parse_complete(&message),
            Err(Fid5Error::NonzeroReserved)
        );
        message = original;
        message[1] = 1;
        assert_eq!(
            Fid5WholeBiu::parse_complete(&message),
            Err(Fid5Error::NonzeroReserved)
        );
    }

    #[test]
    fn whole_biu_roundtrips_normal_and_expedited_units() {
        let unit = SessionUnit::from_reduced(&[0x80, 0x01, 0x6b, 0x80, 0, 0x31]).unwrap();
        let address = [0x01, 0, 0, 0, 0, 0, 0, 1];
        for flow in [Flow::Normal, Flow::Expedited] {
            let encoded = encode_whole_biu(address, flow, &unit).unwrap();
            let decoded = Fid5WholeBiu::parse_complete(&encoded).unwrap();
            assert_eq!(decoded.session_address, address);
            assert_eq!(decoded.expedited, flow == Flow::Expedited);
            assert_eq!(decoded.session_unit().unwrap(), unit);
        }
    }

    #[test]
    fn rejects_reserved_session_address_bit() {
        let unit = SessionUnit::from_reduced(&[0, 1, 0x6b, 0x80, 0]).unwrap();
        assert_eq!(
            encode_whole_biu([0x40, 0, 0, 0, 0, 0, 0, 1], Flow::Normal, &unit),
            Err(Fid5Error::InvalidSessionAddress)
        );
    }
}
