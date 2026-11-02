//! Bounded reliable RTP receive accounting for one validated connection.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 2-12, 2-15–2-16 defines BSN,
//! RSEQ, and acknowledged byte span pairs (ABSP). This window retains
//! out-of-order fragments before advertising their spans. It does not
//! validate the RTP peer, send STATUS, retransmit, process ARB, or establish
//! a connection. The caller supplies an already validated connection and
//! its initial expected BSN, then keeps each generation/direction separate.

use std::collections::BTreeMap;

use crate::{hpr_rtp::RtpPacket, ConnectionGeneration};

const MAX_BUFFER_BYTES: usize = 1_048_576;
const MAX_FRAGMENTS: usize = 64;
const ASSIGNOR: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    InvalidLimit,
    WrongGeneration,
    WrongConnection,
    QualifiedPacket,
    Overlap,
    BufferFull,
    TooManyFragments,
    SequenceAmbiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedFragment {
    pub data: Vec<u8>,
    pub start_of_message: bool,
    pub end_of_message: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveResult {
    /// Fragments are in BSN order and may now be passed to message assembly.
    Delivered(Vec<ReceivedFragment>),
    Buffered,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgedSpan {
    pub begin: u32,
    pub end: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveStatus {
    /// First byte or EOM not yet received in order (RSEQ).
    pub rseq: u32,
    /// Retained out-of-order byte/EOM ranges. An empty span can report an
    /// observed ahead-of-RSEQ empty control packet per IBM p. 2-16.
    pub spans: Vec<AcknowledgedSpan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Buffered {
    end: u64,
    fragment: ReceivedFragment,
}

/// Retains up to 64 out-of-order fragments and a caller-selected memory cap.
/// At least two distinct gaps are supported, as the RTP STATUS format requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliableReceiveWindow {
    generation: ConnectionGeneration,
    tcid: u64,
    initial_bsn: u32,
    cursor: u64,
    buffered: BTreeMap<u64, Buffered>,
    buffered_bytes: usize,
    max_buffer_bytes: usize,
}

impl ReliableReceiveWindow {
    pub fn new(
        generation: ConnectionGeneration,
        tcid: u64,
        initial_expected_bsn: u32,
        max_buffer_bytes: usize,
    ) -> Result<Self, ReceiveError> {
        if tcid & ASSIGNOR != 0 || max_buffer_bytes == 0 || max_buffer_bytes > MAX_BUFFER_BYTES {
            return Err(ReceiveError::InvalidLimit);
        }
        Ok(Self {
            generation,
            tcid,
            initial_bsn: initial_expected_bsn,
            cursor: 0,
            buffered: BTreeMap::new(),
            buffered_bytes: 0,
            max_buffer_bytes,
        })
    }

    /// Accept a parsed packet only after the caller has validated EE peer,
    /// priority port, SAP, route, and RTP connection setup. Old/replayed
    /// packets do not alter RSEQ or retained spans.
    pub fn observe(
        &mut self,
        generation: ConnectionGeneration,
        packet: RtpPacket<'_>,
    ) -> Result<ReceiveResult, ReceiveError> {
        if generation != self.generation {
            return Err(ReceiveError::WrongGeneration);
        }
        if packet.tcid & ASSIGNOR != 0 || packet.thdr[9] & 0x18 != 0 {
            return Err(ReceiveError::QualifiedPacket);
        }
        if packet.tcid != self.tcid {
            return Err(ReceiveError::WrongConnection);
        }
        // The signed half-range comparison is unambiguous for a window below
        // 2^31 bytes and continues across 32-bit BSN wraparound.
        let expected = self.initial_bsn.wrapping_add(self.cursor as u32);
        let delta = packet.byte_sequence_number.wrapping_sub(expected) as i32;
        let consumed = packet.data.len() as u64 + u64::from(packet.end_of_message);
        if delta < 0 {
            if consumed > delta.unsigned_abs() as u64 {
                return Err(ReceiveError::Overlap);
            }
            return Ok(ReceiveResult::Duplicate);
        }
        if delta as u64 + consumed >= (1u64 << 31) {
            return Err(ReceiveError::SequenceAmbiguous);
        }
        let start = self
            .cursor
            .checked_add(delta as u64)
            .ok_or(ReceiveError::SequenceAmbiguous)?;
        let end = start
            .checked_add(consumed)
            .ok_or(ReceiveError::SequenceAmbiguous)?;
        let fragment = ReceivedFragment {
            data: packet.data.to_vec(),
            start_of_message: packet.start_of_message,
            end_of_message: packet.end_of_message,
        };
        if start == self.cursor {
            if self.buffered.iter().any(|(&other_start, other)| {
                other.end > other_start && start < other.end && end > other_start
            }) {
                return Err(ReceiveError::Overlap);
            }
            let mut delivered = vec![fragment];
            self.cursor = end;
            // Empty ABSP hints acknowledge no bytes. A newly contiguous
            // packet can pass their positions without waiting for them.
            self.buffered
                .retain(|&position, entry| entry.end != position || position >= self.cursor);
            while let Some(buffered) = self.buffered.remove(&self.cursor) {
                self.buffered_bytes -=
                    buffered.fragment.data.len() + usize::from(buffered.fragment.end_of_message);
                self.cursor = buffered.end;
                delivered.push(buffered.fragment);
            }
            return Ok(ReceiveResult::Delivered(delivered));
        }
        // Empty control packets ahead of RSEQ are retained as zero-length
        // ABSP hints; actual data at that BSN replaces the hint.
        let mut candidate = self.buffered.clone();
        if consumed > 0
            && candidate
                .get(&start)
                .is_some_and(|entry| entry.end == start)
        {
            candidate.remove(&start);
        }
        for (&other_start, other) in &candidate {
            if start == other_start && end == other.end && fragment == other.fragment {
                return Ok(ReceiveResult::Duplicate);
            }
            if consumed > 0 && other.end > other_start && start < other.end && end > other_start {
                return Err(ReceiveError::Overlap);
            }
            if consumed == 0 && other_start == start {
                return Ok(ReceiveResult::Duplicate);
            }
        }
        candidate.insert(start, Buffered { end, fragment });
        if candidate.len() > MAX_FRAGMENTS {
            return Err(ReceiveError::TooManyFragments);
        }
        let new_bytes: usize = candidate
            .values()
            .map(|item| item.fragment.data.len() + usize::from(item.fragment.end_of_message))
            .sum();
        if new_bytes > self.max_buffer_bytes {
            return Err(ReceiveError::BufferFull);
        }
        self.buffered = candidate;
        self.buffered_bytes = new_bytes;
        Ok(ReceiveResult::Buffered)
    }

    pub fn status(&self) -> ReceiveStatus {
        let mut spans: Vec<AcknowledgedSpan> = Vec::new();
        for (&start, entry) in &self.buffered {
            let begin = self.initial_bsn.wrapping_add(start as u32);
            let end = self.initial_bsn.wrapping_add(entry.end as u32);
            if let Some(previous) = spans.last_mut() {
                if previous.begin != previous.end && begin != end && previous.end == begin {
                    previous.end = end;
                    continue;
                }
            }
            spans.push(AcknowledgedSpan { begin, end });
        }
        ReceiveStatus {
            rseq: self.initial_bsn.wrapping_add(self.cursor as u32),
            spans,
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCID: u64 = 0x0016_0002_0000_0040;

    fn generation(n: u64) -> ConnectionGeneration {
        ConnectionGeneration::new(n).unwrap()
    }

    fn packet(bsn: u32, data: &[u8], eom: bool) -> Vec<u8> {
        let mut nlp = vec![0xc6, 0, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&TCID.to_be_bytes());
        thdr[8] = 0x20 | if eom { 0x10 } else { 0 };
        thdr[10..12].copy_from_slice(&5u16.to_be_bytes());
        thdr[12..16].copy_from_slice(&(data.len() as u32).to_be_bytes());
        thdr[16..20].copy_from_slice(&bsn.to_be_bytes());
        nlp.extend_from_slice(&thdr);
        nlp.extend_from_slice(data);
        nlp
    }

    fn observe(
        window: &mut ReliableReceiveWindow,
        bsn: u32,
        data: &[u8],
        eom: bool,
    ) -> ReceiveResult {
        let bytes = packet(bsn, data, eom);
        window
            .observe(generation(1), RtpPacket::parse(&bytes).unwrap())
            .unwrap()
    }

    #[test]
    fn contiguous_ack_and_wraparound() {
        let mut window =
            ReliableReceiveWindow::new(generation(1), TCID, u32::MAX - 1, 1024).unwrap();
        assert!(matches!(
            observe(&mut window, u32::MAX - 1, b"AB", true),
            ReceiveResult::Delivered(_)
        ));
        assert_eq!(window.status().rseq, 1);
        assert!(matches!(
            observe(&mut window, 1, b"CD", true),
            ReceiveResult::Delivered(_)
        ));
        assert_eq!(window.status().rseq, 4);
        assert!(window.status().spans.is_empty());
    }

    #[test]
    fn retains_two_gaps_then_releases_in_order_and_rejects_replay() {
        let mut window = ReliableReceiveWindow::new(generation(1), TCID, 10, 1024).unwrap();
        assert_eq!(
            observe(&mut window, 21, b"XY", true),
            ReceiveResult::Buffered
        );
        assert_eq!(
            observe(&mut window, 31, b"Z", true),
            ReceiveResult::Buffered
        );
        assert_eq!(window.status().rseq, 10);
        assert_eq!(
            window.status().spans,
            vec![
                AcknowledgedSpan { begin: 21, end: 24 },
                AcknowledgedSpan { begin: 31, end: 33 }
            ]
        );
        assert_eq!(
            observe(&mut window, 21, b"XY", true),
            ReceiveResult::Duplicate
        );
        assert!(matches!(
            observe(&mut window, 10, &[0; 11], false),
            ReceiveResult::Delivered(_)
        ));
        assert_eq!(window.status().rseq, 24);
        assert_eq!(
            window.status().spans,
            vec![AcknowledgedSpan { begin: 31, end: 33 }]
        );
        assert!(matches!(
            observe(&mut window, 24, &[0; 7], false),
            ReceiveResult::Delivered(_)
        ));
        assert_eq!(window.status().rseq, 33);
        assert!(window.status().spans.is_empty());
        assert_eq!(window.buffered_bytes(), 0);
        assert_eq!(
            observe(&mut window, 21, b"XY", true),
            ReceiveResult::Duplicate
        );
    }

    #[test]
    fn overlap_cap_and_generation_reject_without_ack_change() {
        let mut window = ReliableReceiveWindow::new(generation(1), TCID, 0, 3).unwrap();
        assert_eq!(
            observe(&mut window, 5, b"AB", false),
            ReceiveResult::Buffered
        );
        let overlap = packet(6, b"CD", false);
        assert_eq!(
            window.observe(generation(1), RtpPacket::parse(&overlap).unwrap()),
            Err(ReceiveError::Overlap)
        );
        let too_large = packet(10, b"CD", false);
        assert_eq!(
            window.observe(generation(1), RtpPacket::parse(&too_large).unwrap()),
            Err(ReceiveError::BufferFull)
        );
        assert_eq!(
            window.observe(generation(2), RtpPacket::parse(&too_large).unwrap()),
            Err(ReceiveError::WrongGeneration)
        );
        assert_eq!(window.status().rseq, 0);
        assert_eq!(
            window.status().spans,
            vec![AcknowledgedSpan { begin: 5, end: 7 }]
        );
        let straddle = packet(0, &[0; 6], false);
        assert_eq!(
            window.observe(generation(1), RtpPacket::parse(&straddle).unwrap()),
            Err(ReceiveError::Overlap)
        );
        assert_eq!(window.status().rseq, 0);
    }

    #[test]
    fn packet_straddling_rseq_is_not_discarded_as_duplicate() {
        let mut window = ReliableReceiveWindow::new(generation(1), TCID, 10, 1024).unwrap();
        let old = packet(9, b"A", false);
        assert_eq!(
            window.observe(generation(1), RtpPacket::parse(&old).unwrap()),
            Ok(ReceiveResult::Duplicate)
        );
        let straddling = packet(9, b"ABC", false);
        assert_eq!(
            window.observe(generation(1), RtpPacket::parse(&straddling).unwrap()),
            Err(ReceiveError::Overlap)
        );
        assert_eq!(window.status().rseq, 10);
        assert!(window.status().spans.is_empty());
    }

    #[test]
    fn empty_ahead_packet_gives_empty_span_hint() {
        let mut window = ReliableReceiveWindow::new(generation(1), TCID, 10, 1024).unwrap();
        assert_eq!(
            observe(&mut window, 21, b"", false),
            ReceiveResult::Buffered
        );
        assert_eq!(
            window.status().spans,
            vec![AcknowledgedSpan { begin: 21, end: 21 }]
        );
        assert!(matches!(
            observe(&mut window, 10, &[0; 11], false),
            ReceiveResult::Delivered(_)
        ));
        assert_eq!(window.status().rseq, 21);
        assert!(window.status().spans.is_empty());
        assert_eq!(
            observe(&mut window, 24, b"", false),
            ReceiveResult::Buffered
        );
        assert!(matches!(
            observe(&mut window, 21, b"ABCD", false),
            ReceiveResult::Delivered(_)
        ));
        assert_eq!(window.status().rseq, 25);
        assert!(window.status().spans.is_empty());
    }
}
