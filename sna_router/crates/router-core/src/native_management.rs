//! The first native SNASVCMG session boundary after LLC2 contact.
//!
//! A positive BIND response is prepared from a validated local LU policy and
//! only commits the session when the exact PIU has been enqueued and its LLC
//! information frame acknowledged. This pure state never sends a PIU or
//! declares the router ready for user traffic. Later phases own CNOS, BIS,
//! UNBIND, and the user-session gateway separately.

use crate::{
    fid2_session_control::{ManagementBind, ManagementPacing, SessionControlError},
    fixed_pacing::{FixedPacing, PacingError},
};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementError {
    Bind(SessionControlError),
    Pacing(PacingError),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    AwaitBind,
    BindObserved,
    BindResponsePrepared,
    AwaitBindAck,
    AwaitAttach,
}

pub struct ManagementSession {
    remote_plu: String,
    local_slu: String,
    phase: Phase,
    bind: Option<ManagementBind>,
    request: Option<Vec<u8>>,
    pending_response: Option<Vec<u8>>,
    pacing: Option<FixedPacing>,
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
            pacing: None,
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
}
