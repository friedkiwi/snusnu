//! Conservative parser for the observed native APPN management conversation.
//!
//! The V4R4 SNASVCMG exchange uses an FMH-5 Attach to control operator TP
//! X'06F1', a CNOS X'1210' set-limits GDS, an accepted-pending GDS reply,
//! and bilateral BIS (bracket initiation stopped) requests. Seeing both BIS
//! requests does not prove that CNOS completed or that a user session may open.
//!
//! FMH-5 fields: IBM SNA Programmer's LU 6.2 Guide, chapter 7, page 151.
//! BIS X'70': IBM SNA Formats GA27-3136, chapter 5.1.

use crate::cnos::{CnosError, CnosGds, CnosResponder, Service};
use std::{error::Error, fmt};

const CONTROL_OPERATOR_TP: [u8; 2] = [0x06, 0xf1];
const FMH5_HEADER: [u8; 10] = [0x0c, 0x05, 0x02, 0xff, 0x00, 0x03, 0xd0, 0x00, 0x00, 0x02];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    Truncated,
    UnsupportedPiu,
    UnsupportedAttach,
    InvalidCnos,
    UnexpectedState,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid native APPN management exchange: {self:?}")
    }
}

impl Error for ControlError {}

impl From<CnosError> for ControlError {
    fn from(_: CnosError) -> Self {
        Self::InvalidCnos
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAddress {
    pub daf: u8,
    pub oaf: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CnosAttach {
    pub address: SessionAddress,
    pub sequence: u16,
    pub request: CnosGds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bis {
    pub address: SessionAddress,
    pub sequence: u16,
}

struct Piu<'a> {
    address: SessionAddress,
    sequence: u16,
    category: u8,
    response: bool,
    format_indicator: bool,
    ru: &'a [u8],
}

fn piu(bytes: &[u8]) -> Result<Piu<'_>, ControlError> {
    if bytes.len() < 9 {
        return Err(ControlError::Truncated);
    }
    // FID2, one complete normal-flow PIU with an RH. This module does not
    // reassemble segmented RUs or interpret expedited/session-control flows.
    if bytes[0] >> 4 != 2 || (bytes[0] >> 2) & 3 != 3 || bytes[0] & 0x08 == 0 || bytes[0] & 1 != 0 {
        return Err(ControlError::UnsupportedPiu);
    }
    Ok(Piu {
        address: SessionAddress {
            daf: bytes[2],
            oaf: bytes[3],
        },
        sequence: u16::from_be_bytes([bytes[4], bytes[5]]),
        category: (bytes[6] >> 5) & 3,
        response: bytes[6] & 0x80 != 0,
        format_indicator: bytes[6] & 0x08 != 0,
        ru: &bytes[9..],
    })
}

impl CnosAttach {
    /// Parse only the no-security, basic half-duplex Attach used for the
    /// observed SNASVCMG CNOS set-limits operation. Other FMH-5 variants need
    /// a full APPC conversation handler and are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        let frame = piu(bytes)?;
        if frame.category != 0 || frame.response || !frame.format_indicator {
            return Err(ControlError::UnsupportedPiu);
        }
        let ru = frame.ru;
        if ru.len() < 12 {
            return Err(ControlError::Truncated);
        }
        if ru[..10] != FMH5_HEADER || ru[10..12] != CONTROL_OPERATOR_TP {
            return Err(ControlError::UnsupportedAttach);
        }
        let request = CnosGds::decode(&ru[12..])?;
        if request.service != Service::Request {
            return Err(ControlError::InvalidCnos);
        }
        Ok(Self {
            address: frame.address,
            sequence: frame.sequence,
            request,
        })
    }
}

impl Bis {
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        let frame = piu(bytes)?;
        if frame.category != 2 || frame.response || frame.ru != [0x70] {
            return Err(ControlError::UnsupportedPiu);
        }
        Ok(Self {
            address: frame.address,
            sequence: frame.sequence,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    AwaitAttach,
    AwaitPendingReply,
    Pending,
}

/// Tracks evidence from one management exchange. It never has a Ready state:
/// CNOS completion belongs to a separate APPN conversation/bracket engine.
pub struct ControlMonitor {
    phase: Phase,
    initiating: Option<SessionAddress>,
    request: Option<CnosGds>,
    bis_from_initiator: bool,
    bis_from_responder: bool,
}

/// The successful CNOS control-operator conversation in IBM SC31-6808,
/// Figure 5.4-4, consists of exactly two request chains. The reply's CEB
/// closes the bracket. DEALLOCATE(TYPE=LOCAL) at the source is a local verb,
/// not another wire PIU. BIS belongs to later session shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponderPhase {
    AwaitAttach,
    ReplyPendingTransmit,
    Complete,
}

/// Responder for the bounded, unsegmented V4R4 SNASVCMG CNOS exchange.
/// The caller owns LLC pacing, retransmission, and the session lifetime.
pub struct ControlResponder {
    phase: ResponderPhase,
    cnos: CnosResponder,
    pending_reply: Option<Vec<u8>>,
    negotiated: Option<CnosGds>,
    source_sequence: Option<u16>,
    address: Option<SessionAddress>,
}

impl ControlResponder {
    pub fn new(expected_mode: String, maximum_sessions: u16) -> Result<Self, ControlError> {
        Ok(Self {
            phase: ResponderPhase::AwaitAttach,
            cnos: CnosResponder::new(expected_mode, maximum_sessions)?,
            pending_reply: None,
            negotiated: None,
            source_sequence: None,
            address: None,
        })
    }

    pub fn phase(&self) -> ResponderPhase {
        self.phase
    }

    pub fn source_sequence(&self) -> Option<u16> {
        self.source_sequence
    }

    pub fn address(&self) -> Option<SessionAddress> {
        self.address
    }

    /// Session limits become available only after the reply chain has been
    /// accepted by egress. The source/target winner fields keep wire polarity.
    pub fn negotiated(&self) -> Option<&CnosGds> {
        (self.phase == ResponderPhase::Complete)
            .then_some(self.negotiated.as_ref())
            .flatten()
    }

    /// Accept only the captured one-chain basic Attach form. The reply uses
    /// CEB (RH byte 2 bit 7) and a target-origin send sequence of one.
    pub fn accept_attach(&mut self, bytes: &[u8]) -> Result<&[u8], ControlError> {
        if self.phase != ResponderPhase::AwaitAttach {
            return Err(ControlError::UnexpectedState);
        }
        let attach = CnosAttach::decode(bytes)?;
        if bytes[..2] != [0x2c, 0x00]
            || bytes[6..9] != [0x0b, 0x91, 0x20]
            || attach.address.daf == 0
            || attach.address.oaf == 0
            || attach.address.daf == attach.address.oaf
        {
            return Err(ControlError::UnsupportedPiu);
        }
        let reply_gds = self.cnos.accept_request(&bytes[21..])?;
        let mut reply = Vec::with_capacity(9 + reply_gds.len());
        reply.extend_from_slice(&[0x2c, 0x00, attach.address.oaf, attach.address.daf]);
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&[0x03, 0x91, 0x01]);
        reply.extend_from_slice(&reply_gds);
        self.source_sequence = Some(attach.sequence);
        self.address = Some(attach.address);
        self.negotiated = Some(attach.request);
        self.pending_reply = Some(reply);
        self.phase = ResponderPhase::ReplyPendingTransmit;
        Ok(self.pending_reply.as_deref().expect("reply just stored"))
    }

    /// Call after the exact reply has been accepted by the session egress.
    /// The target has then sent its Deallocate-normal/CEB chain and can apply
    /// the negotiated limits. No extra on-wire CNOS completion is expected.
    pub fn mark_reply_transmitted(&mut self, bytes: &[u8]) -> Result<(), ControlError> {
        if self.phase != ResponderPhase::ReplyPendingTransmit
            || self.pending_reply.as_deref() != Some(bytes)
        {
            return Err(ControlError::UnexpectedState);
        }
        self.cnos.mark_completed()?;
        self.pending_reply = None;
        self.phase = ResponderPhase::Complete;
        Ok(())
    }
}

impl Default for ControlMonitor {
    fn default() -> Self {
        Self {
            phase: Phase::AwaitAttach,
            initiating: None,
            request: None,
            bis_from_initiator: false,
            bis_from_responder: false,
        }
    }
}

impl ControlMonitor {
    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn bis_seen(&self) -> (bool, bool) {
        (self.bis_from_initiator, self.bis_from_responder)
    }

    pub fn observe_attach(&mut self, bytes: &[u8]) -> Result<CnosAttach, ControlError> {
        if self.phase != Phase::AwaitAttach {
            return Err(ControlError::UnexpectedState);
        }
        let attach = CnosAttach::decode(bytes)?;
        self.initiating = Some(attach.address);
        self.request = Some(attach.request.clone());
        self.phase = Phase::AwaitPendingReply;
        Ok(attach)
    }

    pub fn observe_reply(&mut self, bytes: &[u8]) -> Result<CnosGds, ControlError> {
        if self.phase != Phase::AwaitPendingReply {
            return Err(ControlError::UnexpectedState);
        }
        let frame = piu(bytes)?;
        let initiating = self.initiating.ok_or(ControlError::UnexpectedState)?;
        if frame.category != 0
            || frame.response
            || frame.address.daf != initiating.oaf
            || frame.address.oaf != initiating.daf
        {
            return Err(ControlError::UnsupportedPiu);
        }
        let reply = CnosGds::decode(frame.ru)?;
        let request = self.request.as_ref().ok_or(ControlError::UnexpectedState)?;
        if reply.service != Service::AcceptedPending
            || reply.modifier != 0
            || reply.mode != request.mode
            || reply.session_limit != request.session_limit
            || reply.source_winners != request.source_winners
            || reply.target_winners != request.target_winners
        {
            return Err(ControlError::InvalidCnos);
        }
        self.phase = Phase::Pending;
        Ok(reply)
    }

    pub fn observe_bis(&mut self, bytes: &[u8]) -> Result<Bis, ControlError> {
        if self.phase != Phase::Pending {
            return Err(ControlError::UnexpectedState);
        }
        let bis = Bis::decode(bytes)?;
        let initiating = self.initiating.ok_or(ControlError::UnexpectedState)?;
        if bis.address == initiating {
            if self.bis_from_initiator {
                return Err(ControlError::UnexpectedState);
            }
            self.bis_from_initiator = true;
        } else if bis.address
            == (SessionAddress {
                daf: initiating.oaf,
                oaf: initiating.daf,
            })
        {
            if self.bis_from_responder {
                return Err(ControlError::UnexpectedState);
            }
            self.bis_from_responder = true;
        } else {
            return Err(ControlError::UnsupportedPiu);
        }
        Ok(bis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized V4R4 management trace: no credentials or application data.
    const ATTACH: [u8; 46] = [
        0x2c, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20, 0x0c, 0x05, 0x02, 0xff, 0, 3, 0xd0, 0, 0, 2, 0x06,
        0xf1, 0, 25, 0x12, 0x10, 2, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40,
    ];
    const PENDING: [u8; 34] = [
        0x2c, 0, 2, 1, 0, 1, 0x03, 0x91, 0x01, 0, 25, 0x12, 0x10, 0x0a, 0, 0, 0, 0, 0, 8, 0, 4, 0,
        4, 0, 8, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    ];
    const INITIATOR_BIS: [u8; 10] = [0x2c, 0, 1, 2, 0, 2, 0x4b, 0x91, 0, 0x70];
    const RESPONDER_BIS: [u8; 10] = [0x2c, 0, 2, 1, 0, 2, 0x4b, 0xb1, 0, 0x70];

    #[test]
    fn responds_to_captured_cnos_and_completes_only_after_transmit() {
        let mut responder = ControlResponder::new(String::new(), 8).unwrap();
        assert_eq!(responder.phase(), ResponderPhase::AwaitAttach);
        assert!(responder.negotiated().is_none());
        assert_eq!(
            responder.mark_reply_transmitted(&PENDING),
            Err(ControlError::UnexpectedState)
        );
        let reply = responder.accept_attach(&ATTACH).unwrap().to_vec();
        assert_eq!(reply, PENDING);
        assert_eq!(responder.source_sequence(), Some(1));
        assert_eq!(responder.address(), Some(SessionAddress { daf: 1, oaf: 2 }));
        assert_eq!(responder.phase(), ResponderPhase::ReplyPendingTransmit);
        assert!(responder.negotiated().is_none());
        assert_eq!(
            responder.accept_attach(&ATTACH),
            Err(ControlError::UnexpectedState)
        );
        let mut without_ceb = reply.clone();
        without_ceb[8] &= !1;
        assert_eq!(
            responder.mark_reply_transmitted(&without_ceb),
            Err(ControlError::UnexpectedState)
        );
        assert_eq!(responder.phase(), ResponderPhase::ReplyPendingTransmit);
        responder.mark_reply_transmitted(&reply).unwrap();
        assert_eq!(responder.phase(), ResponderPhase::Complete);
        assert_eq!(responder.negotiated().unwrap().session_limit, 8);
        assert_eq!(responder.negotiated().unwrap().source_winners, 4);
        assert_eq!(responder.negotiated().unwrap().target_winners, 4);
        assert_eq!(
            responder.mark_reply_transmitted(&reply),
            Err(ControlError::UnexpectedState)
        );
    }

    #[test]
    fn rejects_invalid_attach_without_advancing_responder() {
        for offset in [6, 20, 24, 25, 31, 45] {
            let mut invalid = ATTACH;
            invalid[offset] ^= 1;
            let mut responder = ControlResponder::new(String::new(), 8).unwrap();
            assert!(
                responder.accept_attach(&invalid).is_err(),
                "offset {offset}"
            );
            assert_eq!(responder.phase(), ResponderPhase::AwaitAttach);
        }
        let mut responder = ControlResponder::new(String::new(), 4).unwrap();
        assert_eq!(
            responder.accept_attach(&ATTACH),
            Err(ControlError::InvalidCnos)
        );
    }

    #[test]
    fn tracks_observed_exchange_without_declaring_completion() {
        let mut monitor = ControlMonitor::default();
        let attach = monitor.observe_attach(&ATTACH).unwrap();
        assert_eq!(attach.address, SessionAddress { daf: 1, oaf: 2 });
        assert_eq!(attach.request.session_limit, 8);
        assert_eq!(monitor.phase(), Phase::AwaitPendingReply);
        monitor.observe_reply(&PENDING).unwrap();
        assert_eq!(monitor.phase(), Phase::Pending);
        monitor.observe_bis(&INITIATOR_BIS).unwrap();
        monitor.observe_bis(&RESPONDER_BIS).unwrap();
        assert_eq!(monitor.bis_seen(), (true, true));
        assert_eq!(monitor.phase(), Phase::Pending);
    }

    #[test]
    fn rejects_wrong_pair_duplicate_bis_and_unsupported_attach() {
        let mut monitor = ControlMonitor::default();
        let mut wrong_attach = ATTACH;
        wrong_attach[20] = 0xf2;
        assert_eq!(
            monitor.observe_attach(&wrong_attach),
            Err(ControlError::UnsupportedAttach)
        );
        monitor.observe_attach(&ATTACH).unwrap();
        let mut wrong_reply = PENDING;
        wrong_reply[2] = 3;
        assert_eq!(
            monitor.observe_reply(&wrong_reply),
            Err(ControlError::UnsupportedPiu)
        );
        monitor.observe_reply(&PENDING).unwrap();
        monitor.observe_bis(&INITIATOR_BIS).unwrap();
        assert_eq!(
            monitor.observe_bis(&INITIATOR_BIS),
            Err(ControlError::UnexpectedState)
        );
        let mut wrong_bis = RESPONDER_BIS;
        wrong_bis[9] = 0x71;
        assert_eq!(Bis::decode(&wrong_bis), Err(ControlError::UnsupportedPiu));
    }
}
