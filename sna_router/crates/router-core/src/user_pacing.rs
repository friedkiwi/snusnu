//! Per-user-session fixed pacing after a locally accepted LU 6.2 BIND.
//!
//! This is separate from SNASVCMG pacing. A candidate RSP(BIND) and each
//! later pacing grant become effective only after exact egress confirmation.
//! IBM SC31-6808-0 §6.2 defines PI on the first normal request of a window;
//! GA27-3136 defines an isolated pacing response as RH `83 01 00`, no RU.
//! This pure state does not authorize transmitting the candidate response or
//! activating an APPC/AnyNet gateway before a live peer accepts negotiation.

use crate::{
    fid2_session_control::ManagementBind,
    fixed_pacing::{is_canonical_ipr, FixedPacing, PacingError, IPR_RH, PACING_INDICATOR},
    user_bind::{UserBindError, UserBindOffer},
};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPacingError {
    Bind(UserBindError),
    Pacing(PacingError),
    WrongSession,
    WrongPhase,
    WrongEgress,
    UnsupportedPiu,
}

impl fmt::Display for UserPacingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native user session pacing: {self:?}")
    }
}

impl Error for UserPacingError {}

impl From<UserBindError> for UserPacingError {
    fn from(value: UserBindError) -> Self {
        Self::Bind(value)
    }
}

impl From<PacingError> for UserPacingError {
    fn from(value: PacingError) -> Self {
        Self::Pacing(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPacingPhase {
    ResponsePrepared,
    AwaitBindAck,
    Active,
    Closed,
}

struct PendingEgress {
    piu: Vec<u8>,
    pacing_after: FixedPacing,
}

/// One FID2 user session. All normal PIUs must use its address pair and ODAI;
/// the management session's address pair and FQPCID are explicitly excluded.
pub struct UserPacingSession {
    daf: u8,
    oaf: u8,
    expedited_th0: u8,
    response: Vec<u8>,
    local_receive_window: u8,
    phase: UserPacingPhase,
    pacing: Option<FixedPacing>,
    pending: Option<PendingEgress>,
}

impl UserPacingSession {
    pub fn new(
        offer: &UserBindOffer,
        management: &ManagementBind,
        local_receive_window: u8,
    ) -> Result<Self, UserPacingError> {
        if (offer.daf, offer.oaf) == management.request_addresses()
            || &offer.fqpcid == management.fqpcid()
            || offer.request()[0] & 0x08 == 0
        {
            return Err(UserPacingError::WrongSession);
        }
        let response = offer.build_fixed_response(local_receive_window)?;
        if response[9 + 8] != 3
            || response[9 + 9] != local_receive_window
            || response[9 + 12] != 0x80 | local_receive_window
            || response[9 + 13] != 3
            || response[9 + 23] != 0
            || response[9 + 24] != 0x23
        {
            return Err(UserPacingError::Bind(UserBindError::UnsupportedProfile));
        }
        Ok(Self {
            daf: offer.daf,
            oaf: offer.oaf,
            expedited_th0: offer.request()[0],
            response,
            local_receive_window,
            phase: UserPacingPhase::ResponsePrepared,
            pacing: None,
            pending: None,
        })
    }

    pub fn phase(&self) -> UserPacingPhase {
        self.phase
    }

    pub fn prepared_bind_response(&self) -> &[u8] {
        &self.response
    }

    pub fn mark_bind_enqueued(&mut self, piu: &[u8]) -> Result<(), UserPacingError> {
        if self.phase != UserPacingPhase::ResponsePrepared || piu != self.response {
            return Err(UserPacingError::WrongEgress);
        }
        self.phase = UserPacingPhase::AwaitBindAck;
        Ok(())
    }

    pub fn acknowledge_bind(&mut self, completed: usize) -> Result<(), UserPacingError> {
        if self.phase != UserPacingPhase::AwaitBindAck || completed != 1 {
            return Err(UserPacingError::WrongPhase);
        }
        self.pacing = Some(FixedPacing::new(3, self.local_receive_window)?);
        self.phase = UserPacingPhase::Active;
        Ok(())
    }

    /// Account for one complete inbound normal-flow user request. It may be
    /// routed only after the caller separately validates its APPC payload.
    pub fn observe_normal_request(&mut self, piu: &[u8]) -> Result<(), UserPacingError> {
        self.require_active_idle()?;
        self.check_normal_piu(piu, self.daf, self.oaf)?;
        if piu[6] & 0x80 != 0 {
            return Err(UserPacingError::UnsupportedPiu);
        }
        self.pacing_mut()?
            .receive_request(piu[7] & PACING_INDICATOR != 0)?;
        Ok(())
    }

    /// Prepare one IPR only when the next inbound user window has storage.
    /// Credit is not granted until `mark_egress_enqueued` succeeds.
    pub fn prepare_ipr(&mut self, available_slots: usize) -> Result<&[u8], UserPacingError> {
        self.require_active_idle()?;
        if available_slots < self.local_receive_window as usize {
            return Err(UserPacingError::Pacing(PacingError::ReceiveWindowExceeded));
        }
        let mut next = self.pacing_ref()?.clone();
        next.grant_receive_window()?;
        let piu = vec![
            self.expedited_th0,
            0,
            self.oaf,
            self.daf,
            0,
            0,
            IPR_RH[0],
            IPR_RH[1],
            IPR_RH[2],
        ];
        self.pending = Some(PendingEgress {
            piu,
            pacing_after: next,
        });
        Ok(&self.pending.as_ref().unwrap().piu)
    }

    /// Prepare one outbound complete normal-flow PIU and apply PI according
    /// to this user session's send window. Caller owns APPC validation.
    pub fn prepare_normal_send(&mut self, piu: &[u8]) -> Result<&[u8], UserPacingError> {
        self.require_active_idle()?;
        self.check_normal_piu(piu, self.oaf, self.daf)?;
        if piu[6] & 0x80 != 0 || piu[7] & PACING_INDICATOR != 0 {
            return Err(UserPacingError::UnsupportedPiu);
        }
        let mut next = self.pacing_ref()?.clone();
        let pi = next.send_request()?;
        let mut outbound = piu.to_vec();
        if pi {
            outbound[7] |= PACING_INDICATOR;
        }
        self.pending = Some(PendingEgress {
            piu: outbound,
            pacing_after: next,
        });
        Ok(&self.pending.as_ref().unwrap().piu)
    }

    /// Commit a prepared IPR or normal request after the exact PIU enters a
    /// bounded egress queue. A failed queue attempt leaves pacing unchanged.
    pub fn mark_egress_enqueued(&mut self, piu: &[u8]) -> Result<(), UserPacingError> {
        if self.phase != UserPacingPhase::Active
            || self.pending.as_ref().map(|pending| pending.piu.as_slice()) != Some(piu)
        {
            return Err(UserPacingError::WrongEgress);
        }
        let pending = self.pending.take().unwrap();
        self.pacing = Some(pending.pacing_after);
        Ok(())
    }

    /// A correlated IPR from the PLU grants the next outbound user window.
    pub fn observe_ipr(&mut self, piu: &[u8]) -> Result<(), UserPacingError> {
        self.require_active_idle()?;
        if piu.len() != 9
            || piu[0] != self.expedited_th0
            || piu[1] != 0
            || piu[2] != self.daf
            || piu[3] != self.oaf
            || piu[4..6] != [0, 0]
            || !is_canonical_ipr(&piu[6..9], &piu[9..])
        {
            return Err(UserPacingError::WrongSession);
        }
        self.pacing_mut()?.receive_pacing_response()?;
        Ok(())
    }

    pub fn close(&mut self) {
        self.phase = UserPacingPhase::Closed;
        self.pending = None;
        self.pacing = None;
    }

    fn require_active_idle(&self) -> Result<(), UserPacingError> {
        if self.phase != UserPacingPhase::Active || self.pending.is_some() {
            return Err(UserPacingError::WrongPhase);
        }
        Ok(())
    }

    fn pacing_ref(&self) -> Result<&FixedPacing, UserPacingError> {
        self.pacing.as_ref().ok_or(UserPacingError::WrongPhase)
    }

    fn pacing_mut(&mut self) -> Result<&mut FixedPacing, UserPacingError> {
        self.pacing.as_mut().ok_or(UserPacingError::WrongPhase)
    }

    fn check_normal_piu(&self, piu: &[u8], daf: u8, oaf: u8) -> Result<(), UserPacingError> {
        if piu.len() < 10
            || piu.len() > 1496
            || piu[0] != self.expedited_th0 & !0x01
            || piu[1] != 0
            || piu[2] != daf
            || piu[3] != oaf
            || piu[6] & 0x60 != 0
            || piu[6] & 0x07 != 0x03
        {
            return Err(UserPacingError::WrongSession);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn sessions() -> (ManagementBind, UserBindOffer) {
        // Sanitized V4R4 live management and user BINDs. Their address pairs
        // and FQPCIDs differ, so pacing cannot leak between the two sessions.
        let management = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let mgmt = ManagementBind::from_request(&management, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let user = hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260142222222222222222222222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        let offer = UserBindOffer::from_request(&user, &mgmt, "").unwrap();
        (mgmt, offer)
    }

    fn active() -> UserPacingSession {
        let (management, offer) = sessions();
        let mut session = UserPacingSession::new(&offer, &management, 1).unwrap();
        let response = session.prepared_bind_response().to_vec();
        assert_eq!(response.len(), 89);
        assert_eq!(&response[17..23], &[3, 1, 0xc7, 0xc7, 0x81, 3]);
        assert_eq!(session.phase(), UserPacingPhase::ResponsePrepared);
        assert_eq!(
            session.acknowledge_bind(1),
            Err(UserPacingError::WrongPhase)
        );
        assert_eq!(
            session.mark_bind_enqueued(&response[..9]),
            Err(UserPacingError::WrongEgress)
        );
        session.mark_bind_enqueued(&response).unwrap();
        assert_eq!(session.phase(), UserPacingPhase::AwaitBindAck);
        assert_eq!(
            session.observe_normal_request(&hex("2c00020200010b81000c")),
            Err(UserPacingError::WrongPhase)
        );
        assert_eq!(
            session.acknowledge_bind(2),
            Err(UserPacingError::WrongPhase)
        );
        session.acknowledge_bind(1).unwrap();
        assert_eq!(session.phase(), UserPacingPhase::Active);
        session
    }

    #[test]
    fn user_receive_window_grants_only_after_exact_ipr_egress() {
        let mut session = active();
        let incoming = hex("2c00020200010b81000c");
        let mut management = incoming.clone();
        management[2] = 1;
        assert_eq!(
            session.observe_normal_request(&management),
            Err(UserPacingError::WrongSession)
        );
        session.observe_normal_request(&incoming).unwrap();
        assert_eq!(
            session.prepare_ipr(0),
            Err(UserPacingError::Pacing(PacingError::ReceiveWindowExceeded))
        );
        let ipr = session.prepare_ipr(1).unwrap().to_vec();
        assert_eq!(&ipr, &hex("2d0002020000830100"));
        assert_eq!(
            session.mark_egress_enqueued(&ipr[..8]),
            Err(UserPacingError::WrongEgress)
        );
        assert_eq!(
            session.observe_normal_request(&incoming),
            Err(UserPacingError::WrongPhase)
        );
        session.mark_egress_enqueued(&ipr).unwrap();
        session.observe_normal_request(&incoming).unwrap();
        assert_eq!(
            session.observe_normal_request(&incoming),
            Err(UserPacingError::Pacing(PacingError::ReceiveWindowExceeded))
        );
    }

    #[test]
    fn outbound_pi_and_inbound_ipr_are_isolated_from_management_session() {
        let mut session = active();
        let mut outbound = hex("2c00020200010b80000c");
        let first = session.prepare_normal_send(&outbound).unwrap().to_vec();
        assert_eq!(first[7], 0x81);
        session.mark_egress_enqueued(&first).unwrap();
        assert_eq!(
            session.observe_ipr(&hex("2d0001020000830100")),
            Err(UserPacingError::WrongSession)
        );
        assert_eq!(
            session.observe_ipr(&hex("2d000202000083010000")),
            Err(UserPacingError::WrongSession)
        );
        session.observe_ipr(&hex("2d0002020000830100")).unwrap();
        assert_eq!(
            session.observe_ipr(&hex("2d0002020000830100")),
            Err(UserPacingError::Pacing(
                PacingError::DuplicatePacingResponse
            ))
        );
        for sequence in [2, 3] {
            outbound[5] = sequence;
            let next = session.prepare_normal_send(&outbound).unwrap().to_vec();
            assert_eq!(next[7], 0x80);
            session.mark_egress_enqueued(&next).unwrap();
        }
        outbound[5] = 4;
        let next_window = session.prepare_normal_send(&outbound).unwrap().to_vec();
        assert_eq!(next_window[7], 0x81);
        session.mark_egress_enqueued(&next_window).unwrap();
        session.close();
        assert_eq!(session.phase(), UserPacingPhase::Closed);
        assert_eq!(
            session.observe_ipr(&hex("2d0002020000830100")),
            Err(UserPacingError::WrongPhase)
        );
    }

    #[test]
    fn rejects_user_session_aliases_and_unsupported_window() {
        let (management, offer) = sessions();
        assert!(matches!(
            UserPacingSession::new(&offer, &management, 0),
            Err(UserPacingError::Bind(UserBindError::UnsupportedProfile))
        ));
        let mut alias = offer.clone();
        (alias.daf, alias.oaf) = management.request_addresses();
        assert!(matches!(
            UserPacingSession::new(&alias, &management, 1),
            Err(UserPacingError::WrongSession)
        ));
        alias = offer;
        alias.fqpcid = *management.fqpcid();
        assert!(matches!(
            UserPacingSession::new(&alias, &management, 1),
            Err(UserPacingError::WrongSession)
        ));
    }
}
