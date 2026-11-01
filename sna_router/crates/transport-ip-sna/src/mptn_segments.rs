//! Bounded TCP62 `X'20'` segmented record reassembly.
//!
//! IBM's TCP62 draft section 4.1 specifies `X'20'` for every non-final
//! segment and `X'00'` for the final segment. Only the first segment carries
//! the reduced TH and RH; later segments append RU bytes. This module joins
//! those bytes into one ordinary `X'00'` record. It does not segment or
//! reassemble native FID2 PIUs or supply SNA session pacing.

use std::io;

use crate::anynet::{TcpKind, TcpRecord, MAX_RECORD};

const ENVELOPE: usize = 5;
const REDUCED_TH_AND_RH: usize = 5;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Default)]
pub struct Reassembler {
    partial: Option<Vec<u8>>,
}

impl Reassembler {
    pub fn is_partial(&self) -> bool {
        self.partial.is_some()
    }

    pub fn clear(&mut self) {
        self.partial = None;
    }

    /// Return a complete TCP62 record, or `None` while awaiting the final
    /// segment. Expedited records may bypass a partial normal RU; an abort
    /// discards the partial RU. The caller must preserve TCP record order.
    pub fn push(&mut self, record: &TcpRecord) -> io::Result<Option<TcpRecord>> {
        let checked = TcpRecord::decode(record.bytes.clone())?;
        match checked.kind {
            TcpKind::Segmented => {
                let body = &checked.bytes[ENVELOPE..];
                if body.is_empty() || (self.partial.is_none() && body.len() < REDUCED_TH_AND_RH) {
                    return Err(invalid("TCP62 segment lacks reduced SNA header or RU data"));
                }
                let partial = self.partial.get_or_insert_with(Vec::new);
                if partial.len() + body.len() > MAX_RECORD - ENVELOPE {
                    return Err(invalid("TCP62 reassembled record exceeds bound"));
                }
                partial.extend_from_slice(body);
                Ok(None)
            }
            TcpKind::Normal => {
                let Some(mut partial) = self.partial.take() else {
                    return Ok(Some(checked));
                };
                let body = &checked.bytes[ENVELOPE..];
                if partial.len() + body.len() > MAX_RECORD - ENVELOPE {
                    return Err(invalid("TCP62 reassembled record exceeds bound"));
                }
                partial.extend_from_slice(body);
                let len = partial.len() + ENVELOPE;
                let mut bytes = Vec::with_capacity(len);
                bytes.extend_from_slice(&(len as u32).to_be_bytes());
                bytes.push(0x00);
                bytes.extend_from_slice(&partial);
                Ok(Some(TcpRecord::decode(bytes)?))
            }
            TcpKind::Abort => {
                self.clear();
                Ok(Some(checked))
            }
            TcpKind::Expedited | TcpKind::ExpeditedAck => Ok(Some(checked)),
            TcpKind::Connect => Err(invalid("TCP62 Connect cannot interrupt segmented data")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, body: &[u8]) -> TcpRecord {
        let len = ENVELOPE + body.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(body);
        TcpRecord::decode(bytes).unwrap()
    }

    #[test]
    fn joins_first_header_and_later_ru_without_repeating_header() {
        let mut assembler = Reassembler::default();
        assert!(assembler
            .push(&record(0x20, &[0x12, 0x34, 0x03, 0, 0, 0xaa]))
            .unwrap()
            .is_none());
        assert!(assembler.push(&record(0x20, &[0xbb])).unwrap().is_none());
        let whole = assembler.push(&record(0x00, &[0xcc])).unwrap().unwrap();
        assert_eq!(
            whole.bytes,
            record(0x00, &[0x12, 0x34, 0x03, 0, 0, 0xaa, 0xbb, 0xcc]).bytes
        );
        assert!(!assembler.is_partial());
    }

    #[test]
    fn expedited_bypasses_partial_normal_and_abort_discards_it() {
        let mut assembler = Reassembler::default();
        assembler
            .push(&record(0x20, &[0x12, 0x34, 0x03, 0, 0]))
            .unwrap();
        let expedite = record(0x01, &[0x22, 0x33, 0x83, 0, 0, 0xaa]);
        assert_eq!(assembler.push(&expedite).unwrap(), Some(expedite));
        assert!(assembler.is_partial());
        let abort = record(0x10, &[]);
        assert_eq!(assembler.push(&abort).unwrap(), Some(abort));
        assert!(!assembler.is_partial());
        assert_eq!(
            assembler
                .push(&record(0x00, &[0xaa]))
                .unwrap()
                .unwrap()
                .bytes,
            record(0x00, &[0xaa]).bytes
        );
    }

    #[test]
    fn rejects_truncated_first_segment_and_bounded_overflow() {
        let mut assembler = Reassembler::default();
        assert!(assembler.push(&record(0x20, &[0, 1, 2, 3])).is_err());
        let first = vec![0; MAX_RECORD - ENVELOPE];
        assert!(assembler.push(&record(0x20, &first)).unwrap().is_none());
        assert!(assembler.push(&record(0x00, &[0xaa])).is_err());
    }
}
