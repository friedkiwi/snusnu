//! Complete RTP message assembly after reliable receive resequencing.
//!
//! `ReliableReceiveWindow` emits fragments in byte-sequence order, including
//! fragments released after an earlier gap closes. The framing flags are
//! retained on each fragment so message assembly must run after that window,
//! not on the original arrival order. This module never validates a peer or
//! authorizes an RTP connection.

use crate::hpr_rtp_receive::ReceivedFragment;

pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageError {
    InvalidLimit,
    MissingStart,
    UnexpectedStart,
    TooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedMessageAssembler {
    max_message_bytes: usize,
    partial: Option<Vec<u8>>,
}

impl OrderedMessageAssembler {
    pub fn new(max_message_bytes: usize) -> Result<Self, MessageError> {
        if max_message_bytes == 0 || max_message_bytes > MAX_MESSAGE_BYTES {
            return Err(MessageError::InvalidLimit);
        }
        Ok(Self {
            max_message_bytes,
            partial: None,
        })
    }

    /// Consume one contiguous batch from a validated receive window. Returns
    /// complete messages in wire order. Malformed framing leaves this state
    /// unchanged so the caller can close only the affected RTP connection.
    pub fn observe(
        &mut self,
        fragments: &[ReceivedFragment],
    ) -> Result<Vec<Vec<u8>>, MessageError> {
        let mut next = self.partial.clone();
        let mut messages = Vec::new();
        for fragment in fragments {
            if fragment.start_of_message {
                if next.is_some() {
                    return Err(MessageError::UnexpectedStart);
                }
                next = Some(Vec::new());
            }
            if next.is_none() {
                if !fragment.data.is_empty() || fragment.end_of_message {
                    return Err(MessageError::MissingStart);
                }
                continue;
            }
            let partial = next.as_mut().unwrap();
            if fragment.data.len() > self.max_message_bytes - partial.len() {
                return Err(MessageError::TooLarge);
            }
            partial.extend_from_slice(&fragment.data);
            if fragment.end_of_message {
                messages.push(next.take().unwrap());
            }
        }
        self.partial = next;
        Ok(messages)
    }

    pub fn reset(&mut self) {
        self.partial = None;
    }

    pub fn partial_bytes(&self) -> usize {
        self.partial.as_ref().map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(data: &[u8], start: bool, end: bool) -> ReceivedFragment {
        ReceivedFragment {
            data: data.to_vec(),
            start_of_message: start,
            end_of_message: end,
        }
    }

    #[test]
    fn assembles_reordered_window_release_in_order() {
        let mut assembler = OrderedMessageAssembler::new(16).unwrap();
        assert_eq!(
            assembler.observe(&[fragment(b"AB", true, false)]),
            Ok(vec![])
        );
        assert_eq!(assembler.partial_bytes(), 2);
        assert_eq!(
            assembler.observe(&[
                fragment(b"CD", false, true),
                fragment(b"", false, false),
                fragment(b"EF", true, true),
            ]),
            Ok(vec![b"ABCD".to_vec(), b"EF".to_vec()])
        );
        assert_eq!(assembler.partial_bytes(), 0);
    }

    #[test]
    fn rejects_bad_framing_without_committing_batch() {
        let mut assembler = OrderedMessageAssembler::new(3).unwrap();
        let original = assembler.clone();
        assert_eq!(
            assembler.observe(&[fragment(b"A", true, false), fragment(b"B", true, true)]),
            Err(MessageError::UnexpectedStart)
        );
        assert_eq!(assembler, original);
        assert_eq!(
            assembler.observe(&[fragment(b"A", false, true)]),
            Err(MessageError::MissingStart)
        );
        assert_eq!(assembler, original);
        assert_eq!(
            assembler.observe(&[fragment(b"ABCD", true, true)]),
            Err(MessageError::TooLarge)
        );
        assert_eq!(assembler, original);
    }

    #[test]
    fn empty_message_and_reset_are_defined() {
        let mut assembler = OrderedMessageAssembler::new(1).unwrap();
        assert_eq!(
            assembler.observe(&[fragment(b"", true, true)]),
            Ok(vec![vec![]])
        );
        assembler.observe(&[fragment(b"A", true, false)]).unwrap();
        assembler.reset();
        assert_eq!(assembler.partial_bytes(), 0);
        assert_eq!(
            OrderedMessageAssembler::new(0),
            Err(MessageError::InvalidLimit)
        );
    }
}
