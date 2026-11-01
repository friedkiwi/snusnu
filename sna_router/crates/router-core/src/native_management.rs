//! The first native SNASVCMG session boundary after LLC2 contact.
//!
//! A positive BIND response is prepared from a validated local LU policy and
//! only commits the session when the exact PIU has been enqueued and its LLC
//! information frame acknowledged. This pure state never sends a PIU or
//! declares the router ready for user traffic. Later phases own CNOS, BIS,
//! UNBIND, and the user-session gateway separately.

use crate::{
    appn_control::{CnosAttach, ControlError, ControlResponder},
    fid2_session_control::{ManagementBind, ManagementPacing, SessionControlError},
    fixed_pacing::{is_canonical_ipr, FixedPacing, PacingError, IPR_RH, PACING_INDICATOR},
};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementError {
    Bind(SessionControlError),
    Pacing(PacingError),
    Control(ControlError),
    UnexpectedState,
    WrongEgress,
}

impl fmt::Display for ManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native management session: {self:?}")
    }
}

impl Error for ManagementError {}

impl From<SessionControlError> for ManagementError {
    fn from(value: SessionControlError) -> Self {
        Self::Bind(value)
    }
}

impl From<PacingError> for ManagementError {
    fn from(value: PacingError) -> Self {
        Self::Pacing(value)
    }
}

impl From<ControlError> for ManagementError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    AwaitBind,
    BindObserved,
    BindResponsePrepared,
    AwaitBindAck,
    AwaitAttach,
    AttachRepliesPrepared,
    AwaitCnosAck,
    CnosComplete,
}

pub struct ManagementSession {
    remote_plu: String,
    local_slu: String,
    phase: Phase,
    bind: Option<ManagementBind>,
    request: Option<Vec<u8>>,
    pending_response: Option<Vec<u8>>,
    early_attach: Option<Vec<u8>>,
    pacing: Option<FixedPacing>,
    cnos: Option<ControlResponder>,
    pending_ipr: Option<[u8; 9]>,
    pending_cnos: Option<Vec<u8>>,
    attach_acks: usize,
}

impl ManagementSession {
    pub fn new(remote_plu: String, local_slu: String) -> Self {
        Self {
            remote_plu,
            local_slu,
            phase: Phase::AwaitBind,
            bind: None,
            request: None,
            pending_response: None,
            early_attach: None,
            pacing: None,
            cnos: None,
            pending_ipr: None,
            pending_cnos: None,
            attach_acks: 0,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn bind(&self) -> Option<&ManagementBind> {
        self.bind.as_ref()
    }

    pub fn pacing(&self) -> Option<&FixedPacing> {
        self.pacing.as_ref()
    }

    /// Validate and retain one complete live V4R4 management BIND. No
    /// response is generated before the caller explicitly prepares it.
    pub fn observe_bind(&mut self, piu: &[u8]) -> Result<&ManagementBind, ManagementError> {
        if self.phase != Phase::AwaitBind {
            return Err(ManagementError::UnexpectedState);
        }
        let bind = ManagementBind::from_request(piu, &self.remote_plu, &self.local_slu)?;
        self.request = Some(piu.to_vec());
        self.bind = Some(bind);
        self.phase = Phase::BindObserved;
        Ok(self.bind.as_ref().expect("stored BIND"))
    }

    /// Prepare the source-backed fixed one-stage response. The caller must
    /// not use this method until its LLC egress and CNOS/CONFIRM handling are
    /// configured. Calling it does not imply transmission or activation.
    pub fn prepare_bind_response(&mut self) -> Result<&[u8], ManagementError> {
        if self.phase != Phase::BindObserved {
            return Err(ManagementError::UnexpectedState);
        }
        let bind = self.bind.as_ref().ok_or(ManagementError::UnexpectedState)?;
        let request = self
            .request
            .as_ref()
            .ok_or(ManagementError::UnexpectedState)?;
        let response = bind.build_v4r4_positive_response(
            request,
            ManagementPacing::FixedOneStage {
                local_receive_window: 1,
            },
        )?;
        self.pending_response = Some(response);
        self.phase = Phase::BindResponsePrepared;
        Ok(self.pending_response.as_deref().expect("prepared response"))
    }

    /// Record that the exact response was accepted into the local LLC send
    /// window or bounded egress queue. This does not activate the session.
    pub fn mark_bind_enqueued(&mut self, bytes: &[u8]) -> Result<(), ManagementError> {
        if self.phase != Phase::BindResponsePrepared
            || self.pending_response.as_deref() != Some(bytes)
        {
            return Err(ManagementError::WrongEgress);
        }
        self.phase = Phase::AwaitBindAck;
        Ok(())
    }

    /// Correlate the LLC acknowledgement for the single queued BIND reply.
    /// Only then can the FID2 session enter fixed pacing and await Attach.
    pub fn acknowledge_bind(
        &mut self,
        completed_information: usize,
    ) -> Result<(), ManagementError> {
        if self.phase != Phase::AwaitBindAck || completed_information != 1 {
            return Err(ManagementError::UnexpectedState);
        }
        self.pacing = Some(FixedPacing::new(7, 1)?);
        self.pending_response = None;
        self.phase = Phase::AwaitAttach;
        Ok(())
    }

    /// A peer may piggyback its LLC ACK on the Attach I-frame. The endpoint
    /// normally reports that ACK first, but retain one complete Attach if the
    /// event reaches this state before the completion callback. Do not run
    /// the CNOS conversation until the BIND response is acknowledged.
    pub fn buffer_early_attach(&mut self, piu: &[u8]) -> Result<(), ManagementError> {
        if self.phase != Phase::AwaitBindAck || self.early_attach.is_some() {
            return Err(ManagementError::UnexpectedState);
        }
        let attach = CnosAttach::decode(piu)?;
        let bind = self.bind.as_ref().ok_or(ManagementError::UnexpectedState)?;
        let (daf, oaf) = bind.request_addresses();
        let request = self
            .request
            .as_ref()
            .ok_or(ManagementError::UnexpectedState)?;
        if attach.address.daf != daf
            || attach.address.oaf != oaf
            || piu[0] & 0x02 != request[0] & 0x02
        {
            return Err(ManagementError::UnexpectedState);
        }
        self.early_attach = Some(piu.to_vec());
        Ok(())
    }

    pub fn take_early_attach(&mut self) -> Option<Vec<u8>> {
        (self.phase == Phase::AwaitAttach)
            .then(|| self.early_attach.take())
            .flatten()
    }

    /// Validate one complete CNOS Attach, including the management session
    /// address pair and ODAI. Reserve a receive-window grant before preparing
    /// the IPR, and charge the reply against the outbound send window.
    /// Nothing is considered transmitted until the caller confirms egress.
    pub fn observe_attach(&mut self, piu: &[u8]) -> Result<(&[u8], &[u8]), ManagementError> {
        if self.phase != Phase::AwaitAttach || piu.len() > 1496 {
            return Err(ManagementError::UnexpectedState);
        }
        let attach = CnosAttach::decode(piu)?;
        let bind = self.bind.as_ref().ok_or(ManagementError::UnexpectedState)?;
        let (daf, oaf) = bind.request_addresses();
        let bind_request = self
            .request
            .as_ref()
            .ok_or(ManagementError::UnexpectedState)?;
        if attach.address.daf != daf
            || attach.address.oaf != oaf
            || piu[0] & 0x02 != bind_request[0] & 0x02
        {
            return Err(ManagementError::UnexpectedState);
        }
        // Build in temporary state so a malformed Attach cannot consume a
        // receive window or advance the CNOS conversation.
        let mut pacing = self
            .pacing
            .as_ref()
            .ok_or(ManagementError::UnexpectedState)?
            .clone();
        pacing.receive_request(piu[7] & PACING_INDICATOR != 0)?;
        pacing.grant_receive_window()?;
        let mut cnos = ControlResponder::new(String::new(), 8)?;
        let reply = cnos.accept_attach(piu)?.to_vec();
        if !pacing.send_request()? || reply[7] & PACING_INDICATOR == 0 {
            return Err(ManagementError::UnexpectedState);
        }
        let ipr = [
            bind_request[0],
            0,
            oaf,
            daf,
            0,
            0,
            IPR_RH[0],
            IPR_RH[1],
            IPR_RH[2],
        ];
        self.pacing = Some(pacing);
        self.cnos = Some(cnos);
        self.pending_ipr = Some(ipr);
        self.pending_cnos = Some(reply);
        self.phase = Phase::AttachRepliesPrepared;
        Ok((
            self.pending_ipr.as_ref().unwrap(),
            self.pending_cnos.as_deref().unwrap(),
        ))
    }

    pub fn mark_attach_replies_enqueued(
        &mut self,
        ipr: &[u8],
        cnos: &[u8],
    ) -> Result<(), ManagementError> {
        if self.phase != Phase::AttachRepliesPrepared
            || self.pending_ipr.as_ref().map(<[u8; 9]>::as_slice) != Some(ipr)
            || self.pending_cnos.as_deref() != Some(cnos)
        {
            return Err(ManagementError::WrongEgress);
        }
        self.cnos
            .as_mut()
            .ok_or(ManagementError::UnexpectedState)?
            .mark_reply_transmitted(cnos)?;
        self.phase = Phase::AwaitCnosAck;
        Ok(())
    }

    /// Both IPR and CNOS reply are queued in this order. Two LLC completions
    /// close the bounded CNOS bracket; no user route is ready.
    pub fn acknowledge_attach_replies(
        &mut self,
        completed_information: usize,
    ) -> Result<(), ManagementError> {
        if self.phase != Phase::AwaitCnosAck
            || completed_information == 0
            || self.attach_acks + completed_information > 2
        {
            return Err(ManagementError::UnexpectedState);
        }
        self.attach_acks += completed_information;
        if self.attach_acks < 2 {
            return Ok(());
        }
        self.pending_ipr = None;
        self.pending_cnos = None;
        self.phase = Phase::CnosComplete;
        Ok(())
    }

    /// A peer's isolated pacing response grants the next outbound CNOS
    /// window. It is independent of the LLC acknowledgement for our reply.
    pub fn observe_ipr(&mut self, piu: &[u8]) -> Result<(), ManagementError> {
        if !matches!(self.phase, Phase::AwaitCnosAck | Phase::CnosComplete) || piu.len() != 9 {
            return Err(ManagementError::UnexpectedState);
        }
        let bind = self.bind.as_ref().ok_or(ManagementError::UnexpectedState)?;
        let request = self
            .request
            .as_ref()
            .ok_or(ManagementError::UnexpectedState)?;
        let (daf, oaf) = bind.request_addresses();
        if piu[0] != request[0]
            || piu[1] != 0
            || piu[2] != daf
            || piu[3] != oaf
            || !is_canonical_ipr(&piu[6..9], &piu[9..])
        {
            return Err(ManagementError::UnexpectedState);
        }
        self.pacing
            .as_mut()
            .ok_or(ManagementError::UnexpectedState)?
            .receive_pacing_response()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_shape_bind() -> Vec<u8> {
        // Sanitized live V4R4 probe BIND: FQPCID and COS tokens replaced.
        let hex = concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
            "2c0a00000000000000000000"
        );
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn bind_requires_exact_egress_and_ack_before_session_pacing() {
        let mut session = ManagementSession::new("SOLNET.SNAA".into(), "SOLNET.SNAB".into());
        let request = live_shape_bind();
        assert_eq!(request.len(), 141);
        assert!(session.observe_bind(&request).is_ok());
        assert_eq!(session.phase(), Phase::BindObserved);
        assert!(session.pacing().is_none());
        assert_eq!(
            session.acknowledge_bind(1),
            Err(ManagementError::UnexpectedState)
        );
        let response = session.prepare_bind_response().unwrap().to_vec();
        assert_eq!(&response[..9], &[0x2d, 0, 2, 1, 0, 0, 0xeb, 0x80, 0]);
        assert_eq!(&response[17..23], &[7, 1, 0x86, 0x86, 0x81, 7]);
        let mut wrong = response.clone();
        wrong[2] = 3;
        assert_eq!(
            session.mark_bind_enqueued(&wrong),
            Err(ManagementError::WrongEgress)
        );
        session.mark_bind_enqueued(&response).unwrap();
        assert!(session.pacing().is_none());
        assert_eq!(
            session.acknowledge_bind(0),
            Err(ManagementError::UnexpectedState)
        );
        session.acknowledge_bind(1).unwrap();
        assert_eq!(session.phase(), Phase::AwaitAttach);
        assert_eq!(session.pacing().unwrap().send_remaining(), 7);
        assert_eq!(session.pacing().unwrap().receive_remaining(), 1);
    }

    #[test]
    fn wrong_lu_policy_does_not_advance_state() {
        let mut session = ManagementSession::new("SOLNET.OTHER".into(), "SOLNET.SNAB".into());
        assert!(matches!(
            session.observe_bind(&live_shape_bind()),
            Err(ManagementError::Bind(_))
        ));
        assert_eq!(session.phase(), Phase::AwaitBind);
        assert_eq!(
            session.prepare_bind_response(),
            Err(ManagementError::UnexpectedState)
        );
    }

    #[test]
    fn buffers_one_correlated_attach_until_bind_ack() {
        // Sanitized CNOS Attach from the same V4R4 management session.
        let attach = [
            0x2c, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20, 0x0c, 0x05, 0x02, 0xff, 0, 3, 0xd0, 0, 0, 2,
            0x06, 0xf1, 0, 25, 0x12, 0x10, 2, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40,
            0x40, 0x40, 0x40, 0x40, 0x40,
        ];
        let mut session = ManagementSession::new("SOLNET.SNAA".into(), "SOLNET.SNAB".into());
        session.observe_bind(&live_shape_bind()).unwrap();
        let response = session.prepare_bind_response().unwrap().to_vec();
        session.mark_bind_enqueued(&response).unwrap();
        session.buffer_early_attach(&attach).unwrap();
        assert_eq!(
            session.buffer_early_attach(&attach),
            Err(ManagementError::UnexpectedState)
        );
        assert!(session.take_early_attach().is_none());
        session.acknowledge_bind(1).unwrap();
        assert_eq!(session.take_early_attach(), Some(attach.to_vec()));
        assert!(session.take_early_attach().is_none());
    }

    #[test]
    fn cnos_attach_prepares_correlated_ipr_and_bounded_reply() {
        let attach = [
            0x2c, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20, 0x0c, 0x05, 0x02, 0xff, 0, 3, 0xd0, 0, 0, 2,
            0x06, 0xf1, 0, 25, 0x12, 0x10, 2, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40,
            0x40, 0x40, 0x40, 0x40, 0x40,
        ];
        let mut session = ManagementSession::new("SOLNET.SNAA".into(), "SOLNET.SNAB".into());
        session.observe_bind(&live_shape_bind()).unwrap();
        let bind_reply = session.prepare_bind_response().unwrap().to_vec();
        session.mark_bind_enqueued(&bind_reply).unwrap();
        session.acknowledge_bind(1).unwrap();
        let (ipr, reply) = session.observe_attach(&attach).unwrap();
        assert_eq!(ipr, &[0x2d, 0, 2, 1, 0, 0, 0x83, 1, 0]);
        assert_eq!(&reply[..9], &[0x2c, 0, 2, 1, 0, 1, 3, 0x91, 1]);
        let (ipr, reply) = (ipr.to_vec(), reply.to_vec());
        assert_eq!(session.phase(), Phase::AttachRepliesPrepared);
        assert_eq!(session.mark_attach_replies_enqueued(&ipr, &reply), Ok(()));
        let peer_ipr = [0x2d, 0, 1, 2, 0, 0, 0x83, 1, 0];
        assert_eq!(session.observe_ipr(&peer_ipr), Ok(()));
        assert_eq!(
            session.observe_ipr(&peer_ipr),
            Err(ManagementError::Pacing(
                PacingError::DuplicatePacingResponse
            ))
        );
        assert_eq!(session.acknowledge_attach_replies(1), Ok(()));
        assert_eq!(session.phase(), Phase::AwaitCnosAck);
        assert_eq!(session.acknowledge_attach_replies(1), Ok(()));
        assert_eq!(session.phase(), Phase::CnosComplete);
        assert_eq!(session.pacing().unwrap().send_remaining(), 6);
    }
}
