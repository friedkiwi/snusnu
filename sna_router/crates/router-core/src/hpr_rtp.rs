//! Strict receive-side framing for one HPR RTP network-layer packet (NLP).
//!
//! IBM *SNA Formats* GA27-3136, HPR Headers chapter, defines the ANR NHDR
//! delimiter and THDR offset, data length, byte sequence number, and EOM bit.
//! This module reads those fields and frames optional RTP segments without
//! acknowledging bytes, retransmitting, or offering an RTP endpoint. It is
//! suitable for diagnostics and for a future, separately validated RTP layer.

const MIN_THDR: usize = 20;
const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpError {
    Truncated,
    TooLarge,
    NotAnr,
    MissingAnrLabel,
    MissingAnrTerminator,
    NonzeroNhdrReserved,
    InvalidDataOffset,
    DataLengthMismatch,
    UnsupportedConnectionQualifier,
    InvalidOptionalSegments,
}

/// A word-aligned RTP optional segment. The payload includes any segment
/// padding; interpreting it requires the format for this particular key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpOptionalSegment<'a> {
    pub key: u8,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpPacket<'a> {
    pub nhdr: &'a [u8],
    pub thdr: &'a [u8],
    pub data: &'a [u8],
    /// Four-byte transport connection identifier. A high-order bit of one
    /// means a separate connection qualifier is required by the RTP setup.
    pub tcid: u32,
    pub byte_sequence_number: u32,
    pub start_of_message: bool,
    pub end_of_message: bool,
}

impl<'a> RtpPacket<'a> {
    /// Parse the NLP after the 3-byte 802.2 UI header. The caller validates
    /// the EE UDP port and directional SAPs before invoking this parser.
    pub fn parse(nlp: &'a [u8]) -> Result<Self, RtpError> {
        if nlp.len() > MAX_UDP_PAYLOAD {
            return Err(RtpError::TooLarge);
        }
        if nlp.len() < 2 + 1 + 1 + 1 + MIN_THDR {
            return Err(RtpError::Truncated);
        }
        if nlp[0] & 0xe0 != 0xc0 {
            return Err(RtpError::NotAnr);
        }
        let delimiter = nlp[2..]
            .iter()
            .position(|byte| *byte == 0xff)
            .map(|offset| offset + 2)
            .ok_or(RtpError::MissingAnrTerminator)?;
        if delimiter == 2 {
            return Err(RtpError::MissingAnrLabel);
        }
        let thdr_start = delimiter + 2;
        if nlp.get(delimiter + 1) != Some(&0) {
            return Err(RtpError::NonzeroNhdrReserved);
        }
        let thdr = nlp.get(thdr_start..).ok_or(RtpError::Truncated)?;
        if thdr.len() < MIN_THDR {
            return Err(RtpError::Truncated);
        }
        let offset = u16::from_be_bytes([thdr[10], thdr[11]]) as usize * 4;
        if offset < MIN_THDR || offset > thdr.len() {
            return Err(RtpError::InvalidDataOffset);
        }
        let data_len = u32::from_be_bytes(thdr[12..16].try_into().unwrap()) as usize;
        if thdr.len() - offset != data_len {
            return Err(RtpError::DataLengthMismatch);
        }
        let byte_sequence_number = u32::from_be_bytes(thdr[16..20].try_into().unwrap());
        Ok(Self {
            nhdr: &nlp[..thdr_start],
            thdr: &thdr[..offset],
            data: &thdr[offset..],
            tcid: u32::from_be_bytes(thdr[..4].try_into().unwrap()),
            byte_sequence_number,
            start_of_message: thdr[8] & 0x20 != 0,
            end_of_message: thdr[8] & 0x10 != 0,
        })
    }

    /// Each data byte consumes one BSN; EOM consumes one more even for an
    /// empty data field. This is only the next expected position, not an ACK.
    pub fn next_byte_sequence_number(self) -> u32 {
        self.byte_sequence_number
            .wrapping_add(self.data.len() as u32)
            .wrapping_add(self.end_of_message as u32)
    }

    /// Frame the THDR optional segments. IBM SNA Formats GA27-3136-20,
    /// pp. 2-11–2-13, gives a one-byte length in four-byte words and a
    /// one-byte key for each segment. The connection qualifier precedes the
    /// segments and requires its own CV parser, so this method rejects it.
    /// No segment body, including ARB (X'22'), is interpreted here.
    pub fn optional_segments(self) -> Result<Vec<RtpOptionalSegment<'a>>, RtpError> {
        // Byte 9 bits 3–4 indicate a connection qualifier. Its X'05' CV
        // cannot safely be mistaken for a segment's length/key pair.
        if self.thdr[9] & 0x18 != 0 {
            return Err(RtpError::UnsupportedConnectionQualifier);
        }
        let mut remaining = &self.thdr[MIN_THDR..];
        if self.thdr[9] & 0x04 == 0 {
            return if remaining.is_empty() {
                Ok(Vec::new())
            } else {
                Err(RtpError::InvalidOptionalSegments)
            };
        }
        if remaining.is_empty() {
            return Err(RtpError::InvalidOptionalSegments);
        }
        let mut segments = Vec::new();
        while !remaining.is_empty() {
            let length = usize::from(remaining[0]) * 4;
            if length < 4 || length > remaining.len() {
                return Err(RtpError::InvalidOptionalSegments);
            }
            segments.push(RtpOptionalSegment {
                key: remaining[1],
                data: &remaining[2..length],
            });
            remaining = &remaining[length..];
        }
        Ok(segments)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceObservation {
    Initial,
    InOrder,
    Gap { expected: u32, observed: u32 },
    OldOrDuplicate { expected: u32, observed: u32 },
    WrongConnection,
    QualifiedConnectionUnsupported,
}

/// A diagnostic position tracker for one directional RTP connection. It does
/// not resequence, acknowledge, or implement retransmission/ARB. Gap and old
/// packets never advance the position, so future in-order data can still be
/// observed. A caller must track each direction and connection separately.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RtpPosition {
    tcid: Option<u32>,
    next: Option<u32>,
}

impl RtpPosition {
    pub fn observe(&mut self, packet: RtpPacket<'_>) -> SequenceObservation {
        // Qualified TCIDs need the source identifier from RTP setup. Do not
        // merge two streams solely because their numeric TCIDs match.
        if packet.tcid & 0x8000_0000 != 0 {
            return SequenceObservation::QualifiedConnectionUnsupported;
        }
        match (self.tcid, self.next) {
            (None, None) => {
                self.tcid = Some(packet.tcid);
                self.next = Some(packet.next_byte_sequence_number());
                SequenceObservation::Initial
            }
            (Some(tcid), Some(_expected)) if tcid != packet.tcid => {
                SequenceObservation::WrongConnection
            }
            (Some(_), Some(expected)) if packet.byte_sequence_number == expected => {
                self.next = Some(packet.next_byte_sequence_number());
                SequenceObservation::InOrder
            }
            (Some(_), Some(expected)) => {
                let distance = packet.byte_sequence_number.wrapping_sub(expected);
                if distance < 0x8000_0000 {
                    SequenceObservation::Gap {
                        expected,
                        observed: packet.byte_sequence_number,
                    }
                } else {
                    SequenceObservation::OldOrDuplicate {
                        expected,
                        observed: packet.byte_sequence_number,
                    }
                }
            }
            _ => unreachable!("connection and position are set together"),
        }
    }

    pub fn next_expected(self) -> Option<u32> {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured_header_with_synthetic_data() -> Vec<u8> {
        // Direct V5R4 EE UDP/12003 ANR+RTP *header* only; the 55 application
        // bytes from the capture are replaced with synthetic zeros.
        let mut nlp = [
            0xc2, 0x08, 0xa4, 0x00, 0xff, 0x00, 0x00, 0x16, 0xa4, 0xa1, 0x40, 0x00, 0x00, 0x28,
            0x3c, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x02, 0xef, 0x03, 0x22,
            0x80, 0x00, 0x01, 0x5d, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00,
        ]
        .to_vec();
        nlp.extend_from_slice(&[0; 55]);
        nlp
    }

    #[test]
    fn parses_real_header_boundaries_and_eom_sequence_consumption() {
        let nlp = captured_header_with_synthetic_data();
        let packet = RtpPacket::parse(&nlp).unwrap();
        assert_eq!(packet.nhdr.len(), 6);
        assert_eq!(packet.thdr.len(), 32);
        assert_eq!(packet.data.len(), 55);
        assert_eq!(packet.byte_sequence_number, 751);
        assert_eq!(packet.tcid, 0x0016_a4a1);
        assert!(packet.start_of_message && packet.end_of_message);
        assert_eq!(packet.next_byte_sequence_number(), 807);
    }

    #[test]
    fn rejects_bad_offsets_lengths_and_anr_delimiter() {
        let mut nlp = captured_header_with_synthetic_data();
        nlp[0] = 0xa2;
        assert_eq!(RtpPacket::parse(&nlp), Err(RtpError::NotAnr));
        nlp[0] = 0xc2;
        nlp[4] = 0;
        assert_eq!(RtpPacket::parse(&nlp), Err(RtpError::MissingAnrTerminator));
        nlp[4] = 0xff;
        nlp[17] = 0;
        assert_eq!(RtpPacket::parse(&nlp), Err(RtpError::InvalidDataOffset));
        nlp[17] = 8;
        nlp[21] = 54;
        assert_eq!(RtpPacket::parse(&nlp), Err(RtpError::DataLengthMismatch));
    }

    #[test]
    fn tracks_positions_without_acknowledging_or_accepting_gaps() {
        let first = captured_header_with_synthetic_data();
        let first_packet = RtpPacket::parse(&first).unwrap();
        let mut position = RtpPosition::default();
        assert_eq!(position.observe(first_packet), SequenceObservation::Initial);
        assert_eq!(position.next_expected(), Some(807));
        assert_eq!(
            position.observe(first_packet),
            SequenceObservation::OldOrDuplicate {
                expected: 807,
                observed: 751
            }
        );
        let mut next = first.clone();
        next[24..26].copy_from_slice(&807u16.to_be_bytes());
        // The captured same-direction stream varies THDR bytes 4-7 while
        // retaining its unqualified TCID; they are not a connection key.
        next[10] = 0x42;
        next[13] = 0x38;
        let next_packet = RtpPacket::parse(&next).unwrap();
        assert_eq!(position.observe(next_packet), SequenceObservation::InOrder);
        assert_eq!(position.next_expected(), Some(863));
        next[6] = 0x80;
        assert_eq!(
            position.observe(RtpPacket::parse(&next).unwrap()),
            SequenceObservation::QualifiedConnectionUnsupported
        );
    }

    #[test]
    fn empty_end_of_message_consumes_one_sequence_position() {
        let mut nlp = captured_header_with_synthetic_data();
        nlp.truncate(38); // NHDR 6 + THDR data offset 32, no data.
        nlp[18..22].copy_from_slice(&0u32.to_be_bytes());
        nlp[22..26].copy_from_slice(&u32::MAX.to_be_bytes());
        let packet = RtpPacket::parse(&nlp).unwrap();
        assert_eq!(packet.data.len(), 0);
        assert!(packet.end_of_message);
        assert_eq!(packet.next_byte_sequence_number(), 0);
    }

    #[test]
    fn frames_captured_v5r4_adaptive_rate_segment() {
        let nlp = captured_header_with_synthetic_data();
        let packet = RtpPacket::parse(&nlp).unwrap();
        assert_eq!(
            packet.optional_segments().unwrap(),
            [RtpOptionalSegment {
                key: 0x22,
                data: &[0x80, 0x00, 0x01, 0x5d, 0x81, 0x80, 0, 0, 0, 0],
            }]
        );
    }

    #[test]
    fn optional_segment_framing_rejects_invalid_flags_and_lengths() {
        let mut nlp = captured_header_with_synthetic_data();
        nlp[15] = 0; // THDR byte 9: OSI off while 12 segment bytes remain.
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().optional_segments(),
            Err(RtpError::InvalidOptionalSegments)
        );
        nlp[15] = 0x04;
        nlp[26] = 0; // zero-word segment
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().optional_segments(),
            Err(RtpError::InvalidOptionalSegments)
        );
        nlp[26] = 4; // segment exceeds the THDR boundary
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().optional_segments(),
            Err(RtpError::InvalidOptionalSegments)
        );
        nlp[26] = 3;
        nlp[15] = 0x0c; // connection qualifier indicator
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().optional_segments(),
            Err(RtpError::UnsupportedConnectionQualifier)
        );
    }
}
