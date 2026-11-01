//! Bounded LU 6.2 BIS exchange for the observed V4R4 management session.
//!
//! IBM SNA LU 6.2 Reference: Peer Protocols (SC31-6808), chapter 3, describes
//! BIS as a session shutdown handshake. The receiver returns BIS only after
//! pending bracket and allocation work is drained. BIS does not complete CNOS;
//! the successful CNOS bracket ends on the reply chain's CEB (Figure 5.4-4).
//! The exact request and reply RHs below are verified against the sanitized
//! V4R4 LLC capture.

use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BisError {
    InvalidPiu,
    UnexpectedState,
    BracketBusy,
}

impl fmt::Display for BisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid LU 6.2 BIS exchange: {self:?}")
    }
}

impl Error for BisError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BisPhase {
    AwaitRequest,
    WaitingForBracketFree,
    ReplyPendingTransmit,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BisAddress {
    pub daf: u8,
    pub oaf: u8,
    pub request_sequence: u16,
}

/// Tracks one received BIS request. The owner checks bracket and allocation
/// state before preparing the reply, and confirms exact egress acceptance.
pub struct BisResponder {
    phase: BisPhase,
    next_send_sequence: u16,
    address: Option<BisAddress>,
    pending_reply: Option<[u8; 10]>,
}

impl BisResponder {
    pub fn new(next_send_sequence: u16) -> Result<Self, BisError> {
        if next_send_sequence == 0 {
            return Err(BisError::InvalidPiu);
        }
        Ok(Self {
            phase: BisPhase::AwaitRequest,
            next_send_sequence,
            address: None,
            pending_reply: None,
        })
    }

    pub fn phase(&self) -> BisPhase {
        self.phase
    }

    pub fn address(&self) -> Option<BisAddress> {
        self.address
    }

    /// Accept only an unsegmented FID2 DFC BIS request, with no padding.
    pub fn observe_request(&mut self, piu: &[u8]) -> Result<BisAddress, BisError> {
        if self.phase != BisPhase::AwaitRequest {
            return Err(BisError::UnexpectedState);
        }
        if piu.len() != 10
            || piu[..2] != [0x2c, 0]
            || piu[6..] != [0x4b, 0x91, 0, 0x70]
            || piu[2] == 0
            || piu[3] == 0
            || piu[2] == piu[3]
        {
            return Err(BisError::InvalidPiu);
        }
        let request_sequence = u16::from_be_bytes([piu[4], piu[5]]);
        if request_sequence == 0 {
            return Err(BisError::InvalidPiu);
        }
        let address = BisAddress {
            daf: piu[2],
            oaf: piu[3],
            request_sequence,
        };
        self.address = Some(address);
        self.phase = BisPhase::WaitingForBracketFree;
        Ok(address)
    }

    /// `bracket_free` means no bracket is active or in transit and no waiting
    /// allocation for this session remains, as required by the BIS protocol.
    pub fn prepare_reply(&mut self, bracket_free: bool) -> Result<&[u8], BisError> {
        if self.phase != BisPhase::WaitingForBracketFree {
            return Err(BisError::UnexpectedState);
        }
        if !bracket_free {
            return Err(BisError::BracketBusy);
        }
        let address = self.address.ok_or(BisError::UnexpectedState)?;
        let [high, low] = self.next_send_sequence.to_be_bytes();
        self.pending_reply = Some([
            0x2c,
            0,
            address.oaf,
            address.daf,
            high,
            low,
            0x4b,
            0xb1,
            0,
            0x70,
        ]);
        self.phase = BisPhase::ReplyPendingTransmit;
        Ok(self.pending_reply.as_ref().expect("reply just stored"))
    }

    pub fn mark_reply_transmitted(&mut self, piu: &[u8]) -> Result<(), BisError> {
        if self.phase != BisPhase::ReplyPendingTransmit
            || self.pending_reply.as_ref().map(<[u8; 10]>::as_slice) != Some(piu)
        {
            return Err(BisError::UnexpectedState);
        }
        self.pending_reply = None;
        self.phase = BisPhase::Complete;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized V4R4 management session; no application payload.
    const REQUEST: [u8; 10] = [0x2c, 0, 1, 2, 0, 2, 0x4b, 0x91, 0, 0x70];
    const REPLY: [u8; 10] = [0x2c, 0, 2, 1, 0, 2, 0x4b, 0xb1, 0, 0x70];

    #[test]
    fn waits_for_bracket_and_egress_before_completing() {
        let mut responder = BisResponder::new(2).unwrap();
        assert_eq!(responder.phase(), BisPhase::AwaitRequest);
        assert_eq!(
            responder.prepare_reply(true),
            Err(BisError::UnexpectedState)
        );
        assert_eq!(
            responder.observe_request(&REQUEST).unwrap(),
            BisAddress {
                daf: 1,
                oaf: 2,
                request_sequence: 2,
            }
        );
        assert_eq!(responder.prepare_reply(false), Err(BisError::BracketBusy));
        assert_eq!(responder.phase(), BisPhase::WaitingForBracketFree);
        assert_eq!(
            responder.observe_request(&REQUEST),
            Err(BisError::UnexpectedState)
        );
        let reply = responder.prepare_reply(true).unwrap().to_vec();
        assert_eq!(reply, REPLY);
        let mut wrong_reply = reply.clone();
        wrong_reply[7] &= !0x20;
        assert_eq!(
            responder.mark_reply_transmitted(&wrong_reply),
            Err(BisError::UnexpectedState)
        );
        assert_eq!(responder.phase(), BisPhase::ReplyPendingTransmit);
        responder.mark_reply_transmitted(&reply).unwrap();
        assert_eq!(responder.phase(), BisPhase::Complete);
    }

    #[test]
    fn rejects_malformed_bis_and_zero_sequence() {
        assert!(BisResponder::new(0).is_err());
        for offset in [0, 2, 6, 7, 8, 9] {
            let mut invalid = REQUEST;
            invalid[offset] ^= 1;
            let mut responder = BisResponder::new(2).unwrap();
            assert_eq!(
                responder.observe_request(&invalid),
                Err(BisError::InvalidPiu)
            );
            assert_eq!(responder.phase(), BisPhase::AwaitRequest);
        }
        let mut zero_sequence = REQUEST;
        zero_sequence[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            BisResponder::new(2)
                .unwrap()
                .observe_request(&zero_sequence),
            Err(BisError::InvalidPiu)
        );
    }
}
