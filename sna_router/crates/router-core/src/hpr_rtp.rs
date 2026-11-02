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
    InvalidConnectionQualifier,
    InvalidOptionalSegments,
    InvalidConnectionIdentifierExchange,
    DuplicateConnectionIdentifierExchange,
}

/// A word-aligned RTP optional segment. The payload includes any segment
/// padding; interpreting it requires the format for this particular key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpOptionalSegment<'a> {
    pub key: u8,
    pub data: &'a [u8],
}

/// The receive-side Network Address (X'05') CV carried by an originator's
/// qualified TCID. Identifiers remain in their on-wire encoding; this is not
/// an RTP connection key or an accepted connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpConnectionQualifier<'a> {
    pub network_id: &'a [u8],
    pub node_id: &'a [u8],
    pub nce_id: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpPacket<'a> {
    pub nhdr: &'a [u8],
    pub thdr: &'a [u8],
    pub data: &'a [u8],
    /// Eight-byte transport connection identifier. A high-order bit of one
    /// means a separate connection qualifier is required by the RTP setup.
    pub tcid: u64,
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
            tcid: u64::from_be_bytes(thdr[..8].try_into().unwrap()),
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

    /// Parse the qualified TCID's Network Address (X'05') CV. IBM SNA
    /// Formats GA27-3136-20, pp. 2-11–2-13, places this CV ahead of the
    /// optional segments. This only checks framing and required identifiers;
    /// it does not establish, acknowledge, or identify an RTP connection.
    pub fn connection_qualifier(self) -> Result<Option<RtpConnectionQualifier<'a>>, RtpError> {
        self.qualifier_and_segments()
            .map(|(qualifier, _)| qualifier)
    }

    fn qualifier_and_segments(
        self,
    ) -> Result<(Option<RtpConnectionQualifier<'a>>, &'a [u8]), RtpError> {
        let indicator = self.thdr[9] & 0x18;
        if indicator == 0 {
            return Ok((None, &self.thdr[MIN_THDR..]));
        }
        // CQFI=01 means ORIGIN. Other nonzero values are reserved.
        if indicator != 0x08 {
            return Err(RtpError::UnsupportedConnectionQualifier);
        }
        let field = &self.thdr[MIN_THDR..];
        if field.len() < 4 || field[1] != 0x05 {
            return Err(RtpError::InvalidConnectionQualifier);
        }
        let length = usize::from(field[0]);
        let aligned_length = length.div_ceil(4) * 4;
        if length < 4 || aligned_length > field.len() {
            return Err(RtpError::InvalidConnectionQualifier);
        }
        let (cv, rest) = field.split_at(aligned_length);
        if cv[length..].iter().any(|byte| *byte != 0) {
            return Err(RtpError::InvalidConnectionQualifier);
        }
        // The Network Address CV has two fixed bytes before nested CVs.
        let mut nested = &cv[4..length];
        let mut network_id = None;
        let mut node_id = None;
        let mut nce_id = None;
        while !nested.is_empty() {
            if nested.len() < 2 {
                return Err(RtpError::InvalidConnectionQualifier);
            }
            let nested_length = usize::from(nested[0]);
            let aligned = nested_length.div_ceil(4) * 4;
            if nested_length < 2 || nested_length > nested.len() {
                return Err(RtpError::InvalidConnectionQualifier);
            }
            // The final nested CV may end at the parent CV's exact byte
            // boundary; its word padding then belongs to the parent.
            let consumed = aligned.min(nested.len());
            if consumed != aligned && nested_length != nested.len() {
                return Err(RtpError::InvalidConnectionQualifier);
            }
            if nested[nested_length..consumed]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(RtpError::InvalidConnectionQualifier);
            }
            let value = &nested[2..nested_length];
            let destination = match nested[1] {
                0x03 => Some(&mut network_id),
                0x00 => Some(&mut node_id),
                0x26 => Some(&mut nce_id),
                _ => None,
            };
            if let Some(destination) = destination {
                if destination.replace(value).is_some() || value.is_empty() {
                    return Err(RtpError::InvalidConnectionQualifier);
                }
            }
            nested = &nested[consumed..];
        }
        let qualifier = RtpConnectionQualifier {
            network_id: network_id.ok_or(RtpError::InvalidConnectionQualifier)?,
            node_id: node_id.ok_or(RtpError::InvalidConnectionQualifier)?,
            nce_id: nce_id.ok_or(RtpError::InvalidConnectionQualifier)?,
        };
        Ok((Some(qualifier), rest))
    }

    /// Frame the THDR optional segments. Each segment has a one-byte length
    /// in four-byte words and a one-byte key. No segment body, including ARB
    /// (X'22'), is interpreted here.
    pub fn optional_segments(self) -> Result<Vec<RtpOptionalSegment<'a>>, RtpError> {
        let (_, mut remaining) = self.qualifier_and_segments()?;
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

    /// Read the optional Connection Identifier Exchange (X'10') segment, if
    /// present. IBM SNA Formats GA27-3136-20, p. 2-18, defines its 12-byte
    /// shape and full 64-bit assigned TCID. This is evidence only: it neither
    /// correlates a connection nor accepts the assignment or sends a reply.
    pub fn connection_identifier_exchange(self) -> Result<Option<u64>, RtpError> {
        let mut assigned = None;
        for segment in self.optional_segments()? {
            if segment.key != 0x10 {
                continue;
            }
            if assigned.is_some() {
                return Err(RtpError::DuplicateConnectionIdentifierExchange);
            }
            if segment.data.len() != 10 || segment.data[..2] != [0, 0] {
                return Err(RtpError::InvalidConnectionIdentifierExchange);
            }
            let tcid = u64::from_be_bytes(segment.data[2..10].try_into().unwrap());
            // CIE carries a sender-assigned TCID (bit 0 set); bit 1 is
            // reserved. Those are the two high-order bits of the 64-bit ID.
            if tcid & 0xc000_0000_0000_0000 != 0x8000_0000_0000_0000 {
                return Err(RtpError::InvalidConnectionIdentifierExchange);
            }
            assigned = Some(tcid);
        }
        Ok(assigned)
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
    tcid: Option<u64>,
    next: Option<u32>,
}

impl RtpPosition {
    pub fn observe(&mut self, packet: RtpPacket<'_>) -> SequenceObservation {
        // Qualified TCIDs need the source identifier from RTP setup. Do not
        // merge two streams solely because their numeric TCIDs match.
        if packet.tcid & (1u64 << 63) != 0 {
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

/// A diagnostic upper bound for one assembled RTP message. An endpoint would
/// negotiate and enforce its own limits independently of this receive helper.
pub const MAX_ASSEMBLED_MESSAGE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    InvalidLimit,
    QualifiedConnectionUnsupported,
    WrongConnection,
    MissingStart,
    UnexpectedStart,
    MessageTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssemblyObservation {
    /// No data or EOM in this packet; status and other optional segments are
    /// not interpreted or acted upon.
    ControlOnly,
    Incomplete,
    Complete(Vec<u8>),
    Gap {
        expected: u32,
        observed: u32,
    },
    OldOrDuplicate {
        expected: u32,
        observed: u32,
    },
}

/// Reassembles one already-identified, unqualified, directional RTP data
/// stream. The caller must establish the connection and keep each priority
/// separate, and validate optional segments before passing a packet; numeric
/// TCID alone does not prove peer identity. This helper
/// never ACKs, requests retransmission, interprets ARB, or accepts a qualified
/// setup packet. Gaps and duplicates leave the buffered message untouched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMessageAssembler {
    tcid: u64,
    max_message_bytes: usize,
    next: Option<u32>,
    partial: Option<Vec<u8>>,
}

impl RtpMessageAssembler {
    pub fn new(tcid: u64, max_message_bytes: usize) -> Result<Self, AssemblyError> {
        if tcid & (1u64 << 63) != 0 {
            return Err(AssemblyError::QualifiedConnectionUnsupported);
        }
        if max_message_bytes == 0 || max_message_bytes > MAX_ASSEMBLED_MESSAGE {
            return Err(AssemblyError::InvalidLimit);
        }
        Ok(Self {
            tcid,
            max_message_bytes,
            next: None,
            partial: None,
        })
    }

    pub fn observe(&mut self, packet: RtpPacket<'_>) -> Result<AssemblyObservation, AssemblyError> {
        if packet.tcid & (1u64 << 63) != 0 {
            return Err(AssemblyError::QualifiedConnectionUnsupported);
        }
        if packet.tcid != self.tcid {
            return Err(AssemblyError::WrongConnection);
        }
        if let Some(expected) = self.next {
            if packet.byte_sequence_number != expected {
                let distance = packet.byte_sequence_number.wrapping_sub(expected);
                return Ok(if distance < 0x8000_0000 {
                    AssemblyObservation::Gap {
                        expected,
                        observed: packet.byte_sequence_number,
                    }
                } else {
                    AssemblyObservation::OldOrDuplicate {
                        expected,
                        observed: packet.byte_sequence_number,
                    }
                });
            }
        }
        if packet.start_of_message && self.partial.is_some() {
            return Err(AssemblyError::UnexpectedStart);
        }
        if !packet.start_of_message
            && self.partial.is_none()
            && (!packet.data.is_empty() || packet.end_of_message)
        {
            return Err(AssemblyError::MissingStart);
        }
        let current_len = self.partial.as_ref().map_or(0, Vec::len);
        if packet.data.len() > self.max_message_bytes - current_len {
            return Err(AssemblyError::MessageTooLarge);
        }
        if packet.start_of_message {
            self.partial = Some(Vec::new());
        }
        self.next = Some(packet.next_byte_sequence_number());
        if let Some(partial) = self.partial.as_mut() {
            partial.extend_from_slice(packet.data);
            if packet.end_of_message {
                return Ok(AssemblyObservation::Complete(self.partial.take().unwrap()));
            }
            return Ok(AssemblyObservation::Incomplete);
        }
        Ok(AssemblyObservation::ControlOnly)
    }

    pub fn next_expected(&self) -> Option<u32> {
        self.next
    }

    /// Discard position and incomplete data after an external connection
    /// reset or explicit diagnostic restart. This emits no wire signal.
    pub fn reset(&mut self) {
        self.next = None;
        self.partial = None;
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

    fn sanitized_qualified_setup_header() -> Vec<u8> {
        // Same structural lengths and keys as the V5R4 setup header. The
        // network, node, NCE, other control fields, and data are synthetic.
        let mut nlp = vec![0xc2, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = vec![0; 20];
        thdr[..8].copy_from_slice(&0x8015_f7e9_0000_0000u64.to_be_bytes());
        thdr[8] = 0x40;
        thdr[9] = 0x0c;
        thdr[10..12].copy_from_slice(&43u16.to_be_bytes());
        nlp.extend_from_slice(&thdr);
        nlp.extend_from_slice(&[
            30, 0x05, 0x80, 0, 8, 0x03, b'N', b'E', b'T', b'0', b'0', b'1', 6, 0x00, b'N', b'O',
            b'D', b'E', 0, 0, 4, 0x26, 0x12, 0x34, 6, 0x39, 0, 0, 0, 4, 0, 0,
        ]);
        for (words, key) in [(11, 0x0d), (14, 0x14), (5, 0x22)] {
            nlp.extend_from_slice(&[words, key]);
            nlp.resize(nlp.len() + usize::from(words) * 4 - 2, 0);
        }
        assert_eq!(nlp.len(), 6 + 172);
        nlp
    }

    fn synthetic_fragment(tcid: u64, bsn: u32, som: bool, eom: bool, data: &[u8]) -> Vec<u8> {
        let mut nlp = vec![0xc2, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&tcid.to_be_bytes());
        thdr[8] = (u8::from(som) << 5) | (u8::from(eom) << 4);
        thdr[10..12].copy_from_slice(&5u16.to_be_bytes());
        thdr[12..16].copy_from_slice(&(data.len() as u32).to_be_bytes());
        thdr[16..20].copy_from_slice(&bsn.to_be_bytes());
        nlp.extend_from_slice(&thdr);
        nlp.extend_from_slice(data);
        nlp
    }

    fn fragment<'a>(bytes: &'a [u8]) -> RtpPacket<'a> {
        RtpPacket::parse(bytes).unwrap()
    }

    fn synthetic_cie_header(segments: &[u8]) -> Vec<u8> {
        assert_eq!(segments.len() % 4, 0);
        let mut nlp = vec![0xc2, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&0x0015_f7e9_1300_0040u64.to_be_bytes());
        thdr[9] = 0x04; // OSI
        thdr[10..12].copy_from_slice(&((20 + segments.len()) as u16 / 4).to_be_bytes());
        nlp.extend_from_slice(&thdr);
        nlp.extend_from_slice(segments);
        nlp
    }

    fn synthetic_cie(tcid: u64) -> [u8; 12] {
        let mut segment = [0u8; 12];
        segment[..2].copy_from_slice(&[3, 0x10]);
        segment[4..12].copy_from_slice(&tcid.to_be_bytes());
        segment
    }

    #[test]
    fn parses_real_header_boundaries_and_eom_sequence_consumption() {
        let nlp = captured_header_with_synthetic_data();
        let packet = RtpPacket::parse(&nlp).unwrap();
        assert_eq!(packet.nhdr.len(), 6);
        assert_eq!(packet.thdr.len(), 32);
        assert_eq!(packet.data.len(), 55);
        assert_eq!(packet.byte_sequence_number, 751);
        assert_eq!(packet.tcid, 0x0016_a4a1_4000_0028);
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
    fn frames_sanitized_qualified_setup_without_accepting_connection() {
        let nlp = sanitized_qualified_setup_header();
        let packet = RtpPacket::parse(&nlp).unwrap();
        let qualifier = packet.connection_qualifier().unwrap().unwrap();
        assert_eq!(qualifier.network_id, b"NET001");
        assert_eq!(qualifier.node_id, b"NODE");
        assert_eq!(qualifier.nce_id, &[0x12, 0x34]);
        assert_eq!(
            packet
                .optional_segments()
                .unwrap()
                .iter()
                .map(|s| s.key)
                .collect::<Vec<_>>(),
            [0x0d, 0x14, 0x22]
        );
        assert_eq!(
            RtpPosition::default().observe(packet),
            SequenceObservation::QualifiedConnectionUnsupported
        );
    }

    #[test]
    fn rejects_bad_qualifier_framing_and_reserved_indicator() {
        let original = sanitized_qualified_setup_header();
        let mut nlp = original.clone();
        nlp[27] = 0x06; // expected Network Address CV X'05'
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().connection_qualifier(),
            Err(RtpError::InvalidConnectionQualifier)
        );
        nlp = original.clone();
        nlp[26] = 33; // CV exceeds its word-aligned area before segments
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().connection_qualifier(),
            Err(RtpError::InvalidConnectionQualifier)
        );
        nlp = original.clone();
        nlp[31] = 0; // missing Network ID CV X'03'
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().connection_qualifier(),
            Err(RtpError::InvalidConnectionQualifier)
        );
        nlp = original.clone();
        nlp[45] = 0xff; // nonzero nested CV word pad
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().connection_qualifier(),
            Err(RtpError::InvalidConnectionQualifier)
        );
        nlp = original.clone();
        nlp[56] = 0xff; // nonzero parent CV word pad
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().connection_qualifier(),
            Err(RtpError::InvalidConnectionQualifier)
        );
        nlp = original;
        nlp[15] = 0x14; // reserved CQFI=10
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().connection_qualifier(),
            Err(RtpError::UnsupportedConnectionQualifier)
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
        nlp[15] = 0x1c; // reserved connection qualifier indicator
        assert_eq!(
            RtpPacket::parse(&nlp).unwrap().optional_segments(),
            Err(RtpError::UnsupportedConnectionQualifier)
        );
    }

    #[test]
    fn assembles_in_order_synthetic_fragments_and_ignores_control_only() {
        let tcid = 0x0016_a4a1_4000_0028;
        let mut assembler = RtpMessageAssembler::new(tcid, 8).unwrap();
        let control = synthetic_fragment(tcid, 100, false, false, &[]);
        assert_eq!(
            assembler.observe(fragment(&control)),
            Ok(AssemblyObservation::ControlOnly)
        );
        assert_eq!(assembler.next_expected(), Some(100));
        let start = synthetic_fragment(tcid, 100, true, false, b"AB");
        assert_eq!(
            assembler.observe(fragment(&start)),
            Ok(AssemblyObservation::Incomplete)
        );
        let middle = synthetic_fragment(tcid, 102, false, false, b"CD");
        assert_eq!(
            assembler.observe(fragment(&middle)),
            Ok(AssemblyObservation::Incomplete)
        );
        let end = synthetic_fragment(tcid, 104, false, true, b"E");
        assert_eq!(
            assembler.observe(fragment(&end)),
            Ok(AssemblyObservation::Complete(b"ABCDE".to_vec()))
        );
        assert_eq!(assembler.next_expected(), Some(106)); // EOM consumes one BSN.
    }

    #[test]
    fn gaps_and_duplicates_preserve_partial_message() {
        let tcid = 0x0016_a4a1_4000_0028;
        let mut assembler = RtpMessageAssembler::new(tcid, 8).unwrap();
        let start = synthetic_fragment(tcid, 10, true, false, b"AB");
        let missing = synthetic_fragment(tcid, 12, false, false, b"CD");
        let future = synthetic_fragment(tcid, 14, false, true, b"E");
        assert_eq!(
            assembler.observe(fragment(&start)),
            Ok(AssemblyObservation::Incomplete)
        );
        assert_eq!(
            assembler.observe(fragment(&future)),
            Ok(AssemblyObservation::Gap {
                expected: 12,
                observed: 14
            })
        );
        assert_eq!(assembler.next_expected(), Some(12));
        assert_eq!(
            assembler.observe(fragment(&start)),
            Ok(AssemblyObservation::OldOrDuplicate {
                expected: 12,
                observed: 10
            })
        );
        assert_eq!(
            assembler.observe(fragment(&missing)),
            Ok(AssemblyObservation::Incomplete)
        );
        assert_eq!(
            assembler.observe(fragment(&future)),
            Ok(AssemblyObservation::Complete(b"ABCDE".to_vec()))
        );
    }

    #[test]
    fn assembly_counts_eom_across_bsn_wraparound() {
        let tcid = 0x0016_a4a1_4000_0028;
        let mut assembler = RtpMessageAssembler::new(tcid, 8).unwrap();
        let start = synthetic_fragment(tcid, u32::MAX - 1, true, false, b"AB");
        let end = synthetic_fragment(tcid, 0, false, true, b"C");
        assert_eq!(
            assembler.observe(fragment(&start)),
            Ok(AssemblyObservation::Incomplete)
        );
        assert_eq!(
            assembler.observe(fragment(&end)),
            Ok(AssemblyObservation::Complete(b"ABC".to_vec()))
        );
        assert_eq!(assembler.next_expected(), Some(2));
    }

    #[test]
    fn assembly_enforces_limit_and_reset_without_advancing_on_error() {
        let tcid = 0x0016_a4a1_4000_0028;
        assert_eq!(
            RtpMessageAssembler::new(tcid, 0),
            Err(AssemblyError::InvalidLimit)
        );
        assert_eq!(
            RtpMessageAssembler::new(tcid, MAX_ASSEMBLED_MESSAGE + 1),
            Err(AssemblyError::InvalidLimit)
        );
        assert_eq!(
            RtpMessageAssembler::new(tcid | (1u64 << 63), 8),
            Err(AssemblyError::QualifiedConnectionUnsupported)
        );
        let mut assembler = RtpMessageAssembler::new(tcid, 3).unwrap();
        let start = synthetic_fragment(tcid, 7, true, false, b"AB");
        let over = synthetic_fragment(tcid, 9, false, true, b"CD");
        assert_eq!(
            assembler.observe(fragment(&start)),
            Ok(AssemblyObservation::Incomplete)
        );
        assert_eq!(
            assembler.observe(fragment(&over)),
            Err(AssemblyError::MessageTooLarge)
        );
        assert_eq!(assembler.next_expected(), Some(9));
        let wrong = synthetic_fragment(tcid + 1, 9, false, true, b"C");
        assert_eq!(
            assembler.observe(fragment(&wrong)),
            Err(AssemblyError::WrongConnection)
        );
        let end = synthetic_fragment(tcid, 9, false, true, b"C");
        assert_eq!(
            assembler.observe(fragment(&end)),
            Ok(AssemblyObservation::Complete(b"ABC".to_vec()))
        );
        let next_start = synthetic_fragment(tcid, 11, true, false, b"X");
        assert_eq!(
            assembler.observe(fragment(&next_start)),
            Ok(AssemblyObservation::Incomplete)
        );
        assembler.reset();
        assert_eq!(assembler.next_expected(), None);
        assert_eq!(
            assembler.observe(fragment(&end)),
            Err(AssemblyError::MissingStart)
        );
        assert_eq!(assembler.next_expected(), None);
    }

    #[test]
    fn assembly_rejects_unexpected_start_and_qualified_packet() {
        let tcid = 0x0016_a4a1_4000_0028;
        let mut assembler = RtpMessageAssembler::new(tcid, 8).unwrap();
        let start = synthetic_fragment(tcid, 0, true, false, b"A");
        let another = synthetic_fragment(tcid, 1, true, true, b"B");
        assert_eq!(
            assembler.observe(fragment(&start)),
            Ok(AssemblyObservation::Incomplete)
        );
        assert_eq!(
            assembler.observe(fragment(&another)),
            Err(AssemblyError::UnexpectedStart)
        );
        assert_eq!(assembler.next_expected(), Some(1));
        let qualified = synthetic_fragment(tcid | (1u64 << 63), 1, false, true, b"B");
        assert_eq!(
            assembler.observe(fragment(&qualified)),
            Err(AssemblyError::QualifiedConnectionUnsupported)
        );
    }

    #[test]
    fn tcids_with_identical_upper_32_bits_are_distinct() {
        let tcid = 0x0016_a4a1_4000_0028u64;
        let collision = 0x0016_a4a1_4000_0048u64;
        let first = synthetic_fragment(tcid, 0, true, true, b"A");
        let other = synthetic_fragment(collision, 2, true, true, b"B");
        let mut position = RtpPosition::default();
        assert_eq!(
            position.observe(fragment(&first)),
            SequenceObservation::Initial
        );
        assert_eq!(
            position.observe(fragment(&other)),
            SequenceObservation::WrongConnection
        );
        let mut assembler = RtpMessageAssembler::new(tcid, 8).unwrap();
        assert_eq!(
            assembler.observe(fragment(&first)),
            Ok(AssemblyObservation::Complete(b"A".to_vec()))
        );
        assert_eq!(
            assembler.observe(fragment(&other)),
            Err(AssemblyError::WrongConnection)
        );
    }

    #[test]
    fn reads_full_cie_tcid_from_sanitized_v5r4_reply_shape() {
        // The capture's first reverse packet has a 20-byte STATUS segment
        // followed by a 12-byte CIE. All IDs and segment bodies here are
        // synthetic; no application data is retained.
        let assigned = 0x8000_0001_0000_0002u64;
        let mut segments = vec![5, 0x0e];
        segments.resize(20, 0);
        segments.extend_from_slice(&synthetic_cie(assigned));
        let nlp = synthetic_cie_header(&segments);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Ok(Some(assigned))
        );
        let no_cie = synthetic_cie_header(&segments[..20]);
        assert_eq!(fragment(&no_cie).connection_identifier_exchange(), Ok(None));
    }

    #[test]
    fn cie_rejects_truncation_reserved_fields_and_duplicates() {
        let assigned = 0x8000_0001_0000_0002u64;
        let mut segment = synthetic_cie(assigned);
        segment[0] = 4; // Claims four words but THDR contains three.
        let nlp = synthetic_cie_header(&segment);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Err(RtpError::InvalidOptionalSegments)
        );
        let nlp = synthetic_cie_header(&[2, 0x10, 0, 0, 0x80, 0, 0, 1]);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Err(RtpError::InvalidConnectionIdentifierExchange)
        );
        let mut segment = synthetic_cie(assigned);
        segment[2] = 1;
        let nlp = synthetic_cie_header(&segment);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Err(RtpError::InvalidConnectionIdentifierExchange)
        );
        let segment = synthetic_cie(0xc000_0001_0000_0002);
        let nlp = synthetic_cie_header(&segment);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Err(RtpError::InvalidConnectionIdentifierExchange)
        );
        let segment = synthetic_cie(0x0000_0001_0000_0002);
        let nlp = synthetic_cie_header(&segment);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Err(RtpError::InvalidConnectionIdentifierExchange)
        );
        let mut segments = synthetic_cie(assigned).to_vec();
        segments.extend_from_slice(&synthetic_cie(assigned));
        let nlp = synthetic_cie_header(&segments);
        assert_eq!(
            fragment(&nlp).connection_identifier_exchange(),
            Err(RtpError::DuplicateConnectionIdentifierExchange)
        );
    }
}
