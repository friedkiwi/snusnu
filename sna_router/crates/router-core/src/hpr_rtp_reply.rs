//! Packet template for the first RTP STATUS + CIE reply.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 2-7, 2-11–2-18 defines these fields.
//! The observed V5R4 reply has a 20-byte no-gap STATUS, a 12-byte CIE,
//! a 52-byte THDR, and no data. Later STATUS packets can contain ABSPs.
//! RSEQ and ABSPs come from the bounded reliable receive window; the caller
//! supplies the status exchange numbers and outbound BSN.
//! This encoder does not transmit, perform RTP reliability, or activate a
//! connection.

use crate::hpr_rtp_receive::ReceiveStatus;

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const BASE_THDR_LEN: usize = 52;
const MAX_ABSP: usize = 125; // One-byte STATUS length/4: (20 + 8*125)/4 = 255.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyEncodeError {
    InvalidOriginTcid,
    InvalidAssignedTcid,
    InvalidPriority,
    InvalidAnrLabel,
    TooManySpans,
    InvalidSpan,
}

/// The entire ANR routing field for a directly adjacent peer, excluding its
/// X'FF' delimiter. The caller obtains this from the established path; an
/// inbound ANR field is not automatically a valid reverse path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyPath<'a> {
    pub anr_label: &'a [u8],
    /// NHDR transmission priority: 0=low, 1=medium, 2=high, 3=network.
    pub priority: u8,
}

/// Legacy no-gap STATUS values supplied after caller receive validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallerStatus {
    pub sync: u16,
    pub echo: u16,
    pub rseq: u32,
    pub outbound_bsn: u32,
}

/// Status exchange values supplied by the caller's RTP control state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusExchange {
    pub sync: u16,
    pub echo: u16,
    pub outbound_bsn: u32,
}

/// Encode the observed no-gap STATUS + CIE reply shape for an already
/// verified inbound qualified setup. `origin_tcid` is the setup's sender-
/// assigned TCID; `assigned_tcid` is a newly allocated local ID. The caller
/// must not transmit the result before it has a validated return ANR path,
/// ordered receive state, and status exchange state.
pub fn encode_setup_reply(
    origin_tcid: u64,
    assigned_tcid: u64,
    path: ReplyPath<'_>,
    status: CallerStatus,
) -> Result<Vec<u8>, ReplyEncodeError> {
    encode_setup_reply_from_snapshot(
        origin_tcid,
        assigned_tcid,
        path,
        StatusExchange {
            sync: status.sync,
            echo: status.echo,
            outbound_bsn: status.outbound_bsn,
        },
        &ReceiveStatus {
            rseq: status.rseq,
            spans: Vec::new(),
        },
    )
}

/// Encode STATUS + CIE from a validated receive snapshot. The snapshot is
/// caller-provided so this function does not itself establish the connection
/// or decide when a STATUS is due. ABSPs must be ordered and lie ahead of
/// RSEQ in an unambiguous 32-bit half-window.
pub fn encode_setup_reply_from_snapshot(
    origin_tcid: u64,
    assigned_tcid: u64,
    path: ReplyPath<'_>,
    exchange: StatusExchange,
    snapshot: &ReceiveStatus,
) -> Result<Vec<u8>, ReplyEncodeError> {
    if origin_tcid & (ASSIGNOR | RESERVED) != ASSIGNOR {
        return Err(ReplyEncodeError::InvalidOriginTcid);
    }
    if assigned_tcid & (ASSIGNOR | RESERVED) != ASSIGNOR {
        return Err(ReplyEncodeError::InvalidAssignedTcid);
    }
    if path.priority > 3 {
        return Err(ReplyEncodeError::InvalidPriority);
    }
    // A directly adjacent ANR NCE label is one to eight bytes. Its first
    // byte has the high bit set; X'FF' is reserved as the delimiter.
    if path.anr_label.is_empty()
        || path.anr_label.len() > 8
        || path.anr_label[0] & 0x80 == 0
        || path.anr_label.contains(&0xff)
    {
        return Err(ReplyEncodeError::InvalidAnrLabel);
    }
    if snapshot.spans.len() > MAX_ABSP {
        return Err(ReplyEncodeError::TooManySpans);
    }
    let mut last_end = 0u32;
    for span in &snapshot.spans {
        let begin = span.begin.wrapping_sub(snapshot.rseq) as i32;
        let end = span.end.wrapping_sub(snapshot.rseq) as i32;
        if begin <= 0 || end < begin || (begin as u32) < last_end {
            return Err(ReplyEncodeError::InvalidSpan);
        }
        last_end = end as u32;
    }

    let thdr_len = BASE_THDR_LEN + 8 * snapshot.spans.len();
    let mut packet = Vec::with_capacity(4 + path.anr_label.len() + thdr_len);
    packet.push(0xc0 | path.priority << 1); // NHDR: ANR switching mode.
    packet.push(0x08); // Time sensitive because STATUS is present.
    packet.extend_from_slice(path.anr_label);
    packet.extend_from_slice(&[0xff, 0]); // ANR delimiter, reserved byte.

    let mut thdr = vec![0u8; thdr_len];
    thdr[..8].copy_from_slice(&(origin_tcid & !ASSIGNOR).to_be_bytes());
    thdr[9] = 0x04; // Optional segments, no qualifier.
    thdr[10..12].copy_from_slice(&((thdr_len / 4) as u16).to_be_bytes());
    thdr[16..20].copy_from_slice(&exchange.outbound_bsn.to_be_bytes());

    thdr[20] = (5 + 2 * snapshot.spans.len()) as u8;
    thdr[21] = 0x0e;
    if !snapshot.spans.is_empty() {
        thdr[22] = 0x80; // GAPDETR, because NABSP is nonzero.
    }
    thdr[23] = snapshot.spans.len() as u8;
    thdr[24..26].copy_from_slice(&exchange.sync.to_be_bytes());
    thdr[26..28].copy_from_slice(&exchange.echo.to_be_bytes());
    thdr[28..32].copy_from_slice(&snapshot.rseq.to_be_bytes());
    // Bytes 32–39 are reserved and zero.

    for (index, span) in snapshot.spans.iter().enumerate() {
        let start = 40 + index * 8;
        thdr[start..start + 4].copy_from_slice(&span.begin.to_be_bytes());
        thdr[start + 4..start + 8].copy_from_slice(&span.end.to_be_bytes());
    }

    let cie_start = 40 + snapshot.spans.len() * 8;
    thdr[cie_start] = 3; // CIE length in four-byte words.
    thdr[cie_start + 1] = 0x10;
    // Next two bytes are reserved and zero.
    thdr[cie_start + 4..cie_start + 12].copy_from_slice(&assigned_tcid.to_be_bytes());
    packet.extend_from_slice(&thdr);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_rtp::RtpPacket,
        hpr_rtp_receive::{AcknowledgedSpan, ReliableReceiveWindow},
        hpr_rtp_send::parse_peer_status,
        hpr_rtp_setup::{RtpInboundSetup, RtpLocalTarget, SetupPhase},
        ConnectionGeneration,
    };

    const ORIGIN: u64 = 0x8015_0001_0000_0040;
    const ASSIGNED: u64 = 0x8016_0002_0000_0040;

    fn path() -> ReplyPath<'static> {
        ReplyPath {
            anr_label: &[0xa4, 0],
            priority: 3,
        }
    }

    fn status() -> CallerStatus {
        CallerStatus {
            sync: 7,
            echo: 3,
            rseq: 113,
            outbound_bsn: 19,
        }
    }

    fn lt(key: u8, body: &[u8]) -> Vec<u8> {
        let mut cv = vec![(body.len() + 2) as u8, key];
        cv.extend_from_slice(body);
        cv.resize(cv.len().div_ceil(4) * 4, 0);
        cv
    }

    fn segment(key: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, key];
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().div_ceil(4) * 4, 0);
        bytes[0] = (bytes.len() / 4) as u8;
        bytes
    }

    fn synthetic_inbound_setup(target: &RtpLocalTarget) -> Vec<u8> {
        // The V5R4 structural layout, with synthetic identifiers and no
        // application data. This verifies encoder/observer compatibility.
        let qualifier = [
            30, 5, 0x80, 0, 8, 3, b'S', b'R', b'C', b'0', b'0', b'1', 6, 0, b'O', b'R', b'I', b'G',
            0, 0, 4, 0x26, 0x12, 0x34, 6, 0x39, 0, 0, 0, 8, 0, 0,
        ];
        let mut cs = vec![1, 1, 0x98, 0, 0, 0];
        cs.extend_from_slice(&lt(0x28, b"\0RSETUP"));
        cs.extend_from_slice(&lt(0x03, &target.network_id));
        cs.extend_from_slice(&lt(0x00, &target.node_id));
        cs.extend_from_slice(&lt(0x39, &target.nce_instance));
        let mut si = vec![0, 0];
        si.extend_from_slice(&lt(0x83, &[0; 20]));
        si.extend_from_slice(&lt(0x85, &[0; 24]));
        let mut segments = segment(0x0d, &cs);
        segments.extend_from_slice(&segment(0x14, &si));
        segments.extend_from_slice(&segment(0x22, &[0; 18]));
        let mut packet = vec![0xc2, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&ORIGIN.to_be_bytes());
        thdr[8] = 0x7c;
        thdr[9] = 0x0c;
        thdr[10..12]
            .copy_from_slice(&((20 + qualifier.len() + segments.len()) as u16 / 4).to_be_bytes());
        packet.extend_from_slice(&thdr);
        packet.extend_from_slice(&qualifier);
        packet.extend_from_slice(&segments);
        packet
    }

    fn synthetic_received(bsn: u32, payload: &[u8], eom: bool) -> Vec<u8> {
        let mut packet = vec![0xc6, 0, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&(ASSIGNED & !ASSIGNOR).to_be_bytes());
        thdr[8] = 0x20 | if eom { 0x10 } else { 0 };
        thdr[10..12].copy_from_slice(&5u16.to_be_bytes());
        thdr[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        thdr[16..20].copy_from_slice(&bsn.to_be_bytes());
        packet.extend_from_slice(&thdr);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn reply_fields_roundtrip_through_receive_parser() {
        let encoded = encode_setup_reply(ORIGIN, ASSIGNED, path(), status()).unwrap();
        assert_eq!(&encoded[..6], &[0xc6, 0x08, 0xa4, 0, 0xff, 0]);
        assert_eq!(encoded.len(), 58);
        let packet = RtpPacket::parse(&encoded).unwrap();
        assert_eq!(packet.tcid, ORIGIN & !ASSIGNOR);
        assert_eq!(packet.nhdr.len(), 6);
        assert_eq!(packet.thdr.len(), BASE_THDR_LEN);
        assert!(packet.data.is_empty());
        assert_eq!(packet.byte_sequence_number, 19);
        assert_eq!(packet.thdr[8..12], [0, 4, 0, 13]);
        assert_eq!(packet.thdr[20..24], [5, 0x0e, 0, 0]);
        assert_eq!(
            u16::from_be_bytes(packet.thdr[24..26].try_into().unwrap()),
            7
        );
        assert_eq!(
            u16::from_be_bytes(packet.thdr[26..28].try_into().unwrap()),
            3
        );
        assert_eq!(
            u32::from_be_bytes(packet.thdr[28..32].try_into().unwrap()),
            113
        );
        assert!(packet.thdr[32..40].iter().all(|byte| *byte == 0));
        assert_eq!(packet.connection_identifier_exchange(), Ok(Some(ASSIGNED)));
        assert_eq!(packet.optional_segments().unwrap().len(), 2);
    }

    #[test]
    fn observer_accepts_template_only_after_verified_setup() {
        let generation = ConnectionGeneration::new(1).unwrap();
        let target = RtpLocalTarget {
            network_id: b"NET001".to_vec(),
            node_id: *b"NODE",
            nce_instance: [0, 0, 0, 4],
        };
        let mut observer = RtpInboundSetup::new(generation, target.clone()).unwrap();
        let encoded = encode_setup_reply(ORIGIN, ASSIGNED, path(), status()).unwrap();
        assert!(observer
            .observe_outbound_reply_sent(generation, RtpPacket::parse(&encoded).unwrap())
            .is_err());
        assert_eq!(observer.phase(), SetupPhase::Idle);
        let setup = synthetic_inbound_setup(&target);
        observer
            .observe_inbound_setup(generation, RtpPacket::parse(&setup).unwrap())
            .unwrap();
        assert_eq!(observer.phase(), SetupPhase::AwaitReplySent);
        observer
            .observe_outbound_reply_sent(generation, RtpPacket::parse(&encoded).unwrap())
            .unwrap();
        assert_eq!(observer.phase(), SetupPhase::AwaitPeerUse);
    }

    #[test]
    fn receive_window_snapshot_roundtrips_through_status_parser() {
        let generation = ConnectionGeneration::new(1).unwrap();
        let mut receive =
            ReliableReceiveWindow::new(generation, ASSIGNED & !ASSIGNOR, 10, 1024).unwrap();
        for (bsn, data) in [(21, &b"XY"[..]), (31, &b"Z"[..])] {
            let raw = synthetic_received(bsn, data, true);
            receive
                .observe(generation, RtpPacket::parse(&raw).unwrap())
                .unwrap();
        }
        let snapshot = receive.status();
        assert_eq!(snapshot.spans.len(), 2);
        let encoded = encode_setup_reply_from_snapshot(
            ORIGIN,
            ASSIGNED,
            path(),
            StatusExchange {
                sync: 7,
                echo: 3,
                outbound_bsn: 19,
            },
            &snapshot,
        )
        .unwrap();
        let packet = RtpPacket::parse(&encoded).unwrap();
        assert_eq!(packet.thdr.len(), 68);
        assert_eq!(packet.thdr[20..24], [9, 0x0e, 0x80, 2]);
        assert_eq!(packet.connection_identifier_exchange(), Ok(Some(ASSIGNED)));
        let parsed = parse_peer_status(packet).unwrap();
        assert_eq!((parsed.sync, parsed.echo, parsed.rseq), (7, 3, 10));
        assert_eq!(parsed.spans[0].begin, 21);
        assert_eq!(parsed.spans[0].end, 24);
        assert_eq!(parsed.spans[1].begin, 31);
        assert_eq!(parsed.spans[1].end, 33);
    }

    #[test]
    fn maximum_architected_absp_count_and_bad_spans() {
        let exchange = StatusExchange {
            sync: 0,
            echo: 0,
            outbound_bsn: 0,
        };
        let mut snapshot = ReceiveStatus {
            rseq: u32::MAX - 1,
            spans: (0..MAX_ABSP)
                .map(|index| AcknowledgedSpan {
                    begin: snapshot_bsn(u32::MAX - 1, 1 + index as u32 * 2),
                    end: snapshot_bsn(u32::MAX - 1, 2 + index as u32 * 2),
                })
                .collect(),
        };
        let encoded =
            encode_setup_reply_from_snapshot(ORIGIN, ASSIGNED, path(), exchange, &snapshot)
                .unwrap();
        let packet = RtpPacket::parse(&encoded).unwrap();
        assert_eq!(packet.thdr.len(), 1052);
        assert_eq!(packet.thdr[20], 255);
        assert_eq!(parse_peer_status(packet).unwrap().spans.len(), MAX_ABSP);
        snapshot.spans.push(AcknowledgedSpan {
            begin: 251,
            end: 252,
        });
        assert_eq!(
            encode_setup_reply_from_snapshot(ORIGIN, ASSIGNED, path(), exchange, &snapshot),
            Err(ReplyEncodeError::TooManySpans)
        );
        snapshot.spans = vec![AcknowledgedSpan { begin: 2, end: 1 }];
        snapshot.rseq = 0;
        assert_eq!(
            encode_setup_reply_from_snapshot(ORIGIN, ASSIGNED, path(), exchange, &snapshot),
            Err(ReplyEncodeError::InvalidSpan)
        );
    }

    fn snapshot_bsn(initial: u32, distance: u32) -> u32 {
        initial.wrapping_add(distance)
    }

    #[test]
    fn invalid_ids_and_path_are_rejected() {
        let good = status();
        assert_eq!(
            encode_setup_reply(ORIGIN & !ASSIGNOR, ASSIGNED, path(), good),
            Err(ReplyEncodeError::InvalidOriginTcid)
        );
        assert_eq!(
            encode_setup_reply(ORIGIN, ASSIGNED | RESERVED, path(), good),
            Err(ReplyEncodeError::InvalidAssignedTcid)
        );
        assert_eq!(
            encode_setup_reply(
                ORIGIN,
                ASSIGNED,
                ReplyPath {
                    anr_label: &[0xa4],
                    priority: 4
                },
                good
            ),
            Err(ReplyEncodeError::InvalidPriority)
        );
        for label in [&[][..], &[0x24][..], &[0xff][..], &[0xa4; 9][..]] {
            assert_eq!(
                encode_setup_reply(
                    ORIGIN,
                    ASSIGNED,
                    ReplyPath {
                        anr_label: label,
                        priority: 3
                    },
                    good
                ),
                Err(ReplyEncodeError::InvalidAnrLabel)
            );
        }
    }
}
