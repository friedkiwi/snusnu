//! Bounded reliable RTP send accounting for one validated direction.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 2-12, 2-15–2-16 defines BSN,
//! cumulative RSEQ, and selective acknowledged byte span pairs (ABSP).
//! This ledger retains transmitted NLPs, releases only fully acknowledged
//! packets, and identifies retransmissions only for gaps explicitly reported
//! in a valid STATUS. It does not transmit, set timers, implement ARB, or
//! establish an RTP connection.

use std::collections::VecDeque;

use crate::{hpr_rtp::RtpPacket, ConnectionGeneration};

const ASSIGNOR: u64 = 1 << 63;
const MAX_RETAINED_BYTES: usize = 1_048_576;
const MAX_RETAINED_PACKETS: usize = 256;
const MAX_SYNC_HISTORY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    InvalidLimit,
    WrongGeneration,
    WrongSendConnection,
    WrongStatusConnection,
    WrongBsn,
    EmptyUserPacket,
    BufferFull,
    TooManyPackets,
    InvalidStatus,
    DuplicateStatus,
    StaleStatus,
    WrongEcho,
    StaleRseq,
    AcknowledgesUnsent,
    InvalidSpan,
    SequenceAmbiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckSpan {
    pub begin: u32,
    pub end: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerStatus {
    pub sync: u16,
    pub echo: u16,
    pub rseq: u32,
    pub spans: Vec<AckSpan>,
}

/// Parse exactly one RTP STATUS segment. Zero-length ABSP is permitted for
/// the empty ahead-of-RSEQ packet described by IBM on p. 2-16.
pub fn parse_peer_status(packet: RtpPacket<'_>) -> Result<PeerStatus, SendError> {
    let mut status = None;
    for segment in packet
        .optional_segments()
        .map_err(|_| SendError::InvalidStatus)?
    {
        if segment.key != 0x0e {
            continue;
        }
        if status.is_some() {
            return Err(SendError::InvalidStatus);
        }
        let body = segment.data;
        if body.len() < 18 || (body.len() - 18) % 8 != 0 {
            return Err(SendError::InvalidStatus);
        }
        let count = usize::from(body[1]);
        let gap = body[0] & 0x80 != 0;
        if body[0] & !0xc0 != 0
            || gap != (count > 0)
            || count != (body.len() - 18) / 8
            || body[10..18].iter().any(|byte| *byte != 0)
        {
            return Err(SendError::InvalidStatus);
        }
        let mut spans = Vec::with_capacity(count);
        for item in body[18..].chunks_exact(8) {
            spans.push(AckSpan {
                begin: u32::from_be_bytes(item[..4].try_into().unwrap()),
                end: u32::from_be_bytes(item[4..].try_into().unwrap()),
            });
        }
        status = Some(PeerStatus {
            sync: u16::from_be_bytes(body[2..4].try_into().unwrap()),
            echo: u16::from_be_bytes(body[4..6].try_into().unwrap()),
            rseq: u32::from_be_bytes(body[6..10].try_into().unwrap()),
            spans,
        });
    }
    status.ok_or(SendError::InvalidStatus)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SentPacket {
    start: u64,
    end: u64,
    nlp: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusEffect {
    pub acknowledged_packets: usize,
    /// Exact retained NLPs intersecting reported missing byte ranges. The
    /// caller may retransmit them after its own path/timer/ARB checks.
    pub retransmit_nlps: Vec<Vec<u8>>,
    pub next_unacknowledged_bsn: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliableSendWindow {
    generation: ConnectionGeneration,
    outbound_tcid: u64,
    inbound_status_tcid: u64,
    initial_bsn: u32,
    next_abs: u64,
    ack_abs: u64,
    retained: VecDeque<SentPacket>,
    retained_bytes: usize,
    max_retained_bytes: usize,
    last_peer_sync: Option<u16>,
    last_echo: Option<u16>,
    local_syncs: VecDeque<u16>,
}

impl ReliableSendWindow {
    pub fn new(
        generation: ConnectionGeneration,
        outbound_tcid: u64,
        inbound_status_tcid: u64,
        initial_bsn: u32,
        max_retained_bytes: usize,
    ) -> Result<Self, SendError> {
        if outbound_tcid & ASSIGNOR != 0
            || inbound_status_tcid & ASSIGNOR != 0
            || max_retained_bytes == 0
            || max_retained_bytes > MAX_RETAINED_BYTES
        {
            return Err(SendError::InvalidLimit);
        }
        Ok(Self {
            generation,
            outbound_tcid,
            inbound_status_tcid,
            initial_bsn,
            next_abs: 0,
            ack_abs: 0,
            retained: VecDeque::new(),
            retained_bytes: 0,
            max_retained_bytes,
            last_peer_sync: None,
            last_echo: None,
            local_syncs: VecDeque::new(),
        })
    }

    pub fn next_bsn(&self) -> u32 {
        self.initial_bsn.wrapping_add(self.next_abs as u32)
    }

    /// Record a local STATUS SYNC only after the caller has transmitted it.
    /// Values must increment by one, including at the 16-bit wrap.
    pub fn record_local_sync(
        &mut self,
        generation: ConnectionGeneration,
        sync: u16,
    ) -> Result<(), SendError> {
        self.check_generation(generation)?;
        if self
            .local_syncs
            .back()
            .is_some_and(|last| sync != last.wrapping_add(1))
        {
            return Err(SendError::WrongEcho);
        }
        self.local_syncs.push_back(sync);
        if self.local_syncs.len() > MAX_SYNC_HISTORY {
            self.local_syncs.pop_front();
        }
        Ok(())
    }

    /// Advance BSN and retain a packet only after successful transmission.
    /// Status-only packets consume no user byte and are not recorded here.
    pub fn record_transmitted(
        &mut self,
        generation: ConnectionGeneration,
        packet: RtpPacket<'_>,
    ) -> Result<(), SendError> {
        self.check_generation(generation)?;
        if packet.tcid != self.outbound_tcid {
            return Err(SendError::WrongSendConnection);
        }
        if packet.byte_sequence_number != self.next_bsn() {
            return Err(SendError::WrongBsn);
        }
        let consumed = packet.data.len() + usize::from(packet.end_of_message);
        if consumed == 0 {
            return Err(SendError::EmptyUserPacket);
        }
        if self.retained.len() >= MAX_RETAINED_PACKETS {
            return Err(SendError::TooManyPackets);
        }
        let nlp_len = packet.nhdr.len() + packet.thdr.len() + packet.data.len();
        if nlp_len > self.max_retained_bytes - self.retained_bytes {
            return Err(SendError::BufferFull);
        }
        let end = self
            .next_abs
            .checked_add(consumed as u64)
            .ok_or(SendError::SequenceAmbiguous)?;
        if end - self.ack_abs >= (1u64 << 31) {
            return Err(SendError::SequenceAmbiguous);
        }
        let mut nlp = Vec::with_capacity(nlp_len);
        nlp.extend_from_slice(packet.nhdr);
        nlp.extend_from_slice(packet.thdr);
        nlp.extend_from_slice(packet.data);
        self.retained.push_back(SentPacket {
            start: self.next_abs,
            end,
            nlp,
        });
        self.retained_bytes += nlp_len;
        self.next_abs = end;
        Ok(())
    }

    /// Validate a peer STATUS and update the send ledger. A fresh SYNC and a
    /// known, monotonic ECHO are required. The caller still owns timers,
    /// path selection, actual retransmission, and ARB pacing.
    pub fn observe_status(
        &mut self,
        generation: ConnectionGeneration,
        packet: RtpPacket<'_>,
    ) -> Result<StatusEffect, SendError> {
        self.check_generation(generation)?;
        if packet.tcid != self.inbound_status_tcid {
            return Err(SendError::WrongStatusConnection);
        }
        let status = parse_peer_status(packet)?;
        if let Some(last) = self.last_peer_sync {
            let advance = status.sync.wrapping_sub(last) as i16;
            if advance == 0 {
                return Err(SendError::DuplicateStatus);
            }
            if advance < 0 {
                return Err(SendError::StaleStatus);
            }
        }
        if self.local_syncs.is_empty() {
            if status.echo != 0 {
                return Err(SendError::WrongEcho);
            }
        } else if !self.local_syncs.contains(&status.echo) {
            return Err(SendError::WrongEcho);
        }
        if let Some(last) = self.last_echo {
            if (status.echo.wrapping_sub(last) as i16) < 0 {
                return Err(SendError::WrongEcho);
            }
        }
        let ack_wire = self.initial_bsn.wrapping_add(self.ack_abs as u32);
        let ack_advance = status.rseq.wrapping_sub(ack_wire) as i32;
        if ack_advance < 0 {
            return Err(SendError::StaleRseq);
        }
        let ack_abs = self
            .ack_abs
            .checked_add(ack_advance as u64)
            .ok_or(SendError::SequenceAmbiguous)?;
        if ack_abs > self.next_abs {
            return Err(SendError::AcknowledgesUnsent);
        }
        let mut spans = Vec::with_capacity(status.spans.len());
        let mut previous_end = ack_abs;
        for span in &status.spans {
            let begin_delta = span.begin.wrapping_sub(status.rseq) as i32;
            let end_delta = span.end.wrapping_sub(status.rseq) as i32;
            if begin_delta < 0 || end_delta < begin_delta {
                return Err(SendError::InvalidSpan);
            }
            let begin = ack_abs
                .checked_add(begin_delta as u64)
                .ok_or(SendError::SequenceAmbiguous)?;
            let end = ack_abs
                .checked_add(end_delta as u64)
                .ok_or(SendError::SequenceAmbiguous)?;
            if begin <= ack_abs || begin < previous_end || end > self.next_abs {
                return Err(SendError::InvalidSpan);
            }
            spans.push((begin, end));
            previous_end = end;
        }
        let mut retransmit_nlps = Vec::new();
        if !spans.is_empty() {
            let mut gap_start = ack_abs;
            for &(gap_end, span_end) in &spans {
                if gap_start < gap_end {
                    for saved in &self.retained {
                        if saved.start < gap_end
                            && saved.end > gap_start
                            && !retransmit_nlps.contains(&saved.nlp)
                        {
                            retransmit_nlps.push(saved.nlp.clone());
                        }
                    }
                }
                gap_start = span_end;
            }
        }
        let before = self.retained.len();
        self.retained.retain(|saved| {
            let cumulative = saved.end <= ack_abs;
            let selective = spans
                .iter()
                .any(|&(begin, end)| saved.start >= begin && saved.end <= end);
            !(cumulative || selective)
        });
        self.retained_bytes = self.retained.iter().map(|saved| saved.nlp.len()).sum();
        self.ack_abs = ack_abs;
        self.last_peer_sync = Some(status.sync);
        self.last_echo = Some(status.echo);
        Ok(StatusEffect {
            acknowledged_packets: before - self.retained.len(),
            retransmit_nlps,
            next_unacknowledged_bsn: self.initial_bsn.wrapping_add(ack_abs as u32),
        })
    }

    pub fn retained_packets(&self) -> usize {
        self.retained.len()
    }

    /// The oldest unacknowledged NLP for a caller-owned retransmission
    /// timer. This does not authorize transmission or advance sequence state.
    pub fn oldest_retained_nlp(&self) -> Option<&[u8]> {
        self.retained.front().map(|packet| packet.nlp.as_slice())
    }

    fn check_generation(&self, generation: ConnectionGeneration) -> Result<(), SendError> {
        if generation == self.generation {
            Ok(())
        } else {
            Err(SendError::WrongGeneration)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEND: u64 = 0x0015_0001_0000_0040;
    const STATUS: u64 = 0x0016_0002_0000_0040;

    fn generation(n: u64) -> ConnectionGeneration {
        ConnectionGeneration::new(n).unwrap()
    }

    fn user_packet(bsn: u32, data: &[u8], eom: bool) -> Vec<u8> {
        let mut nlp = vec![0xc6, 0, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&SEND.to_be_bytes());
        thdr[8] = 0x20 | if eom { 0x10 } else { 0 };
        thdr[10..12].copy_from_slice(&5u16.to_be_bytes());
        thdr[12..16].copy_from_slice(&(data.len() as u32).to_be_bytes());
        thdr[16..20].copy_from_slice(&bsn.to_be_bytes());
        nlp.extend_from_slice(&thdr);
        nlp.extend_from_slice(data);
        nlp
    }

    fn status_packet(sync: u16, echo: u16, rseq: u32, spans: &[AckSpan]) -> Vec<u8> {
        let mut nlp = vec![0xc6, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&STATUS.to_be_bytes());
        thdr[9] = 4;
        let status_len = 20 + 8 * spans.len();
        thdr[10..12].copy_from_slice(&(((20 + status_len) / 4) as u16).to_be_bytes());
        nlp.extend_from_slice(&thdr);
        nlp.push((status_len / 4) as u8);
        nlp.push(0x0e);
        nlp.push(if spans.is_empty() { 0 } else { 0x80 });
        nlp.push(spans.len() as u8);
        nlp.extend_from_slice(&sync.to_be_bytes());
        nlp.extend_from_slice(&echo.to_be_bytes());
        nlp.extend_from_slice(&rseq.to_be_bytes());
        nlp.extend_from_slice(&[0; 8]);
        for span in spans {
            nlp.extend_from_slice(&span.begin.to_be_bytes());
            nlp.extend_from_slice(&span.end.to_be_bytes());
        }
        nlp
    }

    fn sent(window: &mut ReliableSendWindow, bsn: u32, data: &[u8], eom: bool) {
        let bytes = user_packet(bsn, data, eom);
        window
            .record_transmitted(generation(1), RtpPacket::parse(&bytes).unwrap())
            .unwrap();
    }

    fn ack(
        window: &mut ReliableSendWindow,
        sync: u16,
        echo: u16,
        rseq: u32,
        spans: &[AckSpan],
    ) -> Result<StatusEffect, SendError> {
        let bytes = status_packet(sync, echo, rseq, spans);
        window.observe_status(generation(1), RtpPacket::parse(&bytes).unwrap())
    }

    #[test]
    fn cumulative_ack_wraparound_and_stale_status() {
        let mut window =
            ReliableSendWindow::new(generation(1), SEND, STATUS, u32::MAX - 1, 1024).unwrap();
        sent(&mut window, u32::MAX - 1, b"AB", true);
        assert_eq!(window.next_bsn(), 1);
        sent(&mut window, 1, b"CD", true);
        let first = ack(&mut window, 0, 0, 1, &[]).unwrap();
        assert_eq!(first.acknowledged_packets, 1);
        assert!(first.retransmit_nlps.is_empty());
        assert_eq!(window.retained_packets(), 1);
        assert_eq!(
            ack(&mut window, 0, 0, 1, &[]),
            Err(SendError::DuplicateStatus)
        );
        assert_eq!(
            ack(&mut window, u16::MAX, 0, 1, &[]),
            Err(SendError::StaleStatus)
        );
        let second = ack(&mut window, 1, 0, 4, &[]).unwrap();
        assert_eq!(second.acknowledged_packets, 1);
        assert_eq!(window.retained_packets(), 0);
    }

    #[test]
    fn explicit_gap_schedules_only_missing_packet() {
        let mut window = ReliableSendWindow::new(generation(1), SEND, STATUS, 10, 1024).unwrap();
        sent(&mut window, 10, b"AA", true); // [10,13)
        sent(&mut window, 13, b"BB", true); // [13,16)
        sent(&mut window, 16, b"CC", true); // [16,19)
        let effect = ack(&mut window, 0, 0, 13, &[AckSpan { begin: 16, end: 19 }]).unwrap();
        assert_eq!(effect.acknowledged_packets, 2);
        assert_eq!(effect.retransmit_nlps, vec![user_packet(13, b"BB", true)]);
        assert_eq!(effect.next_unacknowledged_bsn, 13);
        assert_eq!(window.retained_packets(), 1);
        // The peer may repeat an ABSP after that packet was released.
        let repeated = ack(&mut window, 1, 0, 13, &[AckSpan { begin: 16, end: 19 }]).unwrap();
        assert_eq!(repeated.acknowledged_packets, 0);
        assert_eq!(repeated.retransmit_nlps, vec![user_packet(13, b"BB", true)]);
        assert!(ack(&mut window, 2, 0, 13, &[])
            .unwrap()
            .retransmit_nlps
            .is_empty());
        assert_eq!(
            ack(&mut window, 3, 0, 19, &[])
                .unwrap()
                .acknowledged_packets,
            1
        );
        assert_eq!(window.retained_packets(), 0);
        let idle = ack(&mut window, 4, 0, 19, &[]).unwrap();
        assert_eq!(idle.acknowledged_packets, 0);
        assert!(idle.retransmit_nlps.is_empty());
    }

    #[test]
    fn two_selective_spans_schedule_only_two_confirmed_gaps() {
        let mut window = ReliableSendWindow::new(generation(1), SEND, STATUS, 10, 1024).unwrap();
        for (bsn, payload) in [(10, b"AA"), (13, b"BB"), (16, b"CC"), (19, b"DD")] {
            sent(&mut window, bsn, payload, true);
        }
        let effect = ack(
            &mut window,
            0,
            0,
            10,
            &[
                AckSpan { begin: 13, end: 16 },
                AckSpan { begin: 19, end: 22 },
            ],
        )
        .unwrap();
        assert_eq!(effect.acknowledged_packets, 2);
        assert_eq!(
            effect.retransmit_nlps,
            vec![user_packet(10, b"AA", true), user_packet(16, b"CC", true)]
        );
        assert_eq!(window.retained_packets(), 2);
    }

    #[test]
    fn echo_rseq_span_generation_and_cap_are_checked() {
        let mut window = ReliableSendWindow::new(generation(1), SEND, STATUS, 0, 70).unwrap();
        sent(&mut window, 0, b"A", true);
        let too_large = user_packet(2, &[0; 50], true);
        assert_eq!(
            window.record_transmitted(generation(1), RtpPacket::parse(&too_large).unwrap()),
            Err(SendError::BufferFull)
        );
        assert_eq!(window.next_bsn(), 2);
        window.record_local_sync(generation(1), 5).unwrap();
        assert_eq!(ack(&mut window, 0, 4, 0, &[]), Err(SendError::WrongEcho));
        assert_eq!(
            ack(&mut window, 0, 5, 3, &[]),
            Err(SendError::AcknowledgesUnsent)
        );
        assert_eq!(
            ack(&mut window, 0, 5, 0, &[AckSpan { begin: 1, end: 3 }]),
            Err(SendError::InvalidSpan)
        );
        let bytes = status_packet(0, 5, 0, &[]);
        assert_eq!(
            window.observe_status(generation(2), RtpPacket::parse(&bytes).unwrap()),
            Err(SendError::WrongGeneration)
        );
        ack(&mut window, 0, 5, 2, &[]).unwrap();
        assert_eq!(ack(&mut window, 1, 5, 1, &[]), Err(SendError::StaleRseq));
    }

    #[test]
    fn malformed_status_and_sync_wrap_are_checked() {
        let mut window = ReliableSendWindow::new(generation(1), SEND, STATUS, 0, 1024).unwrap();
        window.record_local_sync(generation(1), u16::MAX).unwrap();
        window.record_local_sync(generation(1), 0).unwrap();
        sent(&mut window, 0, b"A", true);
        ack(&mut window, u16::MAX, u16::MAX, 0, &[]).unwrap();
        ack(&mut window, 0, 0, 2, &[]).unwrap();
        assert_eq!(window.retained_packets(), 0);
        let mut bytes = status_packet(1, 0, 2, &[]);
        bytes[6 + 20 + 2] = 0x80; // Gap bit without any ABSP.
        assert_eq!(
            parse_peer_status(RtpPacket::parse(&bytes).unwrap()),
            Err(SendError::InvalidStatus)
        );
        bytes[6 + 20 + 2] = 0;
        bytes[6 + 20 + 12] = 1; // Reserved STATUS byte.
        assert_eq!(
            parse_peer_status(RtpPacket::parse(&bytes).unwrap()),
            Err(SendError::InvalidStatus)
        );
    }

    #[test]
    fn near_u64_limit_span_does_not_wrap_or_change_state() {
        let mut window = ReliableSendWindow::new(generation(1), SEND, STATUS, 0, 1024).unwrap();
        window.ack_abs = u64::MAX - 10;
        window.next_abs = u64::MAX - 2;
        let rseq = window.ack_abs as u32;
        let before = window.clone();
        assert_eq!(
            ack(
                &mut window,
                0,
                0,
                rseq,
                &[AckSpan {
                    begin: rseq.wrapping_add(20),
                    end: rseq.wrapping_add(21),
                }],
            ),
            Err(SendError::SequenceAmbiguous)
        );
        assert_eq!(window, before);
    }
}
