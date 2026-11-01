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
    user_fmh5::{parse_first_user_attach, UserFmh5Error},
};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPacingError {
    Bind(UserBindError),
    Fmh5(UserFmh5Error),
    Pacing(PacingError),
    WrongSession,
    WrongRoute,
    WrongPhase,
    WrongEgress,
    UnsupportedPiu,
    InvalidFmh5,
    DuplicateAttach,
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

impl From<UserFmh5Error> for UserPacingError {
    fn from(value: UserFmh5Error) -> Self {
        Self::Fmh5(value)
    }
}

/// The route selected for one observed first APPC Attach. The TP name is raw
/// SNA bytes because service TP names need not be ordinary EBCDIC text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstAttachRoute {
    pub remote_lu: String,
    pub local_lu: String,
    pub mode: String,
    pub transaction_program: Vec<u8>,
    pub luw_instance: [u8; 6],
    pub luw_sequence: u16,
    pub pip_bytes: usize,
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
    fqpcid: Vec<u8>,
    expedited_th0: u8,
    response: Vec<u8>,
    local_receive_window: u8,
    phase: UserPacingPhase,
    pacing: Option<FixedPacing>,
    pending: Option<PendingEgress>,
    first_attach_seen: bool,
}

impl UserPacingSession {
    pub fn new(
        offer: &UserBindOffer,
        management: &ManagementBind,
        local_receive_window: u8,
    ) -> Result<Self, UserPacingError> {
        Self::new_internal(offer, management, local_receive_window, false)
    }

    /// Caller has completed management UNBIND, releasing its address pair.
    pub fn new_after_management(
        offer: &UserBindOffer,
        management: &ManagementBind,
        local_receive_window: u8,
    ) -> Result<Self, UserPacingError> {
        Self::new_internal(offer, management, local_receive_window, true)
    }

    fn new_internal(
        offer: &UserBindOffer,
        management: &ManagementBind,
        local_receive_window: u8,
        management_closed: bool,
    ) -> Result<Self, UserPacingError> {
        if (!management_closed && (offer.daf, offer.oaf) == management.request_addresses())
            || offer.fqpcid == management.fqpcid()
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
            fqpcid: offer.fqpcid.clone(),
            expedited_th0: offer.request()[0],
            response,
            local_receive_window,
            phase: UserPacingPhase::ResponsePrepared,
            pacing: None,
            pending: None,
            first_attach_seen: false,
        })
    }

    pub fn phase(&self) -> UserPacingPhase {
        self.phase
    }

    /// Bind a later APPC frame gate to this exact user session rather than
    /// merely matching the FID2 address pair, which peers may reuse.
    pub fn matches_offer(&self, offer: &UserBindOffer) -> bool {
        self.daf == offer.daf
            && self.oaf == offer.oaf
            && self.fqpcid == offer.fqpcid
            && self.expedited_th0 == offer.request()[0]
    }

    /// Correlate the first captured user FMH-5 to this BIND and an explicit
    /// TP route before charging the user receive window. The p86/p51 profile
    /// has basic half-duplex, CONFIRM, no access security, a LUW origin equal
    /// to the remote PLU, and one PIP GDS variable. Application data remains
    /// opaque. This does not prepare or authorize an APPC response.
    pub fn observe_first_attach(
        &mut self,
        offer: &UserBindOffer,
        expected_tp: &[u8],
        piu: &[u8],
    ) -> Result<FirstAttachRoute, UserPacingError> {
        self.require_active_idle()?;
        if self.first_attach_seen {
            return Err(UserPacingError::DuplicateAttach);
        }
        if !self.matches_offer(offer) {
            return Err(UserPacingError::WrongSession);
        }
        parse_first_user_attach(piu, offer)?;
        let ru = &piu[9..];
        let plu = encode_lu_name(&offer.plu)?;
        let fmh_len = 25 + plu.len();
        if ru.len() < fmh_len + 8
            || ru[0] as usize != fmh_len
            || ru[4..10] != [8, 3, 0xd0, 0, 0x40, 4]
            || ru[14..16] != [0, (plu.len() + 9) as u8]
            || ru[16] as usize != plu.len()
        {
            return Err(UserPacingError::InvalidFmh5);
        }
        if expected_tp.len() != 4 || ru[10..14] != *expected_tp {
            return Err(UserPacingError::WrongRoute);
        }
        if ru.get(17..17 + plu.len()) != Some(plu.as_slice()) {
            return Err(UserPacingError::WrongRoute);
        }
        // The FMH-5 ends after its length-qualified LUW name. Its PIP flag requires one complete
        // GDS X'12F5' containing one X'12E2' subfield. Do not interpret the
        // application-specific subfield body or expose it as route metadata.
        let pip = &ru[fmh_len..];
        let gds_len = u16::from_be_bytes([pip[0], pip[1]]) as usize;
        let sub_len = u16::from_be_bytes([pip[4], pip[5]]) as usize;
        if gds_len != pip.len()
            || gds_len < 8
            || pip[2..4] != [0x12, 0xf5]
            || sub_len != pip.len() - 4
            || sub_len < 4
            || pip[6..8] != [0x12, 0xe2]
        {
            return Err(UserPacingError::InvalidFmh5);
        }
        // `observe_normal_request` checks ODAI, addresses, complete BIU, and
        // the required PI before it consumes this session's receive credit.
        self.observe_normal_request(piu)?;
        self.first_attach_seen = true;
        Ok(FirstAttachRoute {
            remote_lu: offer.plu.clone(),
            local_lu: offer.slu.clone(),
            mode: offer.mode.clone(),
            transaction_program: expected_tp.to_vec(),
            luw_instance: ru[17 + plu.len()..23 + plu.len()].try_into().unwrap(),
            luw_sequence: u16::from_be_bytes([ru[23 + plu.len()], ru[24 + plu.len()]]),
            pip_bytes: pip.len(),
        })
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
            // An isolated IPR may use either flow. The live V4R4 user IPR
            // uses normal TH0 0x2c after an expedited 0x2d user BIND, while
            // the management IPR used expedited flow. Keep every other TH0
            // bit, including ODAI, tied to this session.
            || piu[0] & !0x01 != self.expedited_th0 & !0x01
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

fn encode_lu_name(name: &str) -> Result<Vec<u8>, UserPacingError> {
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => return Err(UserPacingError::WrongRoute),
            })
        })
        .collect()
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
            "0be2d6d3d5c5e34be2d5c1c2601411111111111111110b1111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let mgmt = ManagementBind::from_request(&management, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let user = hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601422222222222222220b2222222222222222222222",
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

    fn first_attach() -> Vec<u8> {
        // Independent sanitized V4R4 p86/p51 first user Attach. The PIP GDS
        // body is application-private and replaced with zeros; all lengths,
        // IDs, route fields, and the PI-bearing FID2 header are preserved.
        let mut piu = hex(concat!(
            "2c00020200010b9120",
            "240502ff0803d000400430f0f0f500140b",
            "e2d6d3d5c5e34be2d5c1c1",
            "0102030405060001",
            "00c512f500c112e2"
        ));
        piu.extend_from_slice(&[0; 189]);
        assert_eq!(piu.len(), 242);
        piu
    }

    #[test]
    fn first_attach_selects_explicit_tp_and_charges_only_user_pacing() {
        let mut session = active();
        let (_, offer) = sessions();
        let piu = first_attach();
        let route = session
            .observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &piu)
            .unwrap();
        assert_eq!(route.remote_lu, "SOLNET.SNAA");
        assert_eq!(route.local_lu, "SOLNET.SNAB");
        assert_eq!(route.mode, "");
        assert_eq!(route.transaction_program, [0x30, 0xf0, 0xf0, 0xf5]);
        assert_eq!(route.luw_instance, [1, 2, 3, 4, 5, 6]);
        assert_eq!(route.luw_sequence, 1);
        assert_eq!(route.pip_bytes, 197);
        assert_eq!(
            session.observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &piu),
            Err(UserPacingError::DuplicateAttach)
        );
        assert_eq!(session.prepare_ipr(1).unwrap(), &hex("2d0002020000830100"));
    }

    #[test]
    fn malformed_first_attach_does_not_consume_user_window() {
        let mut session = active();
        let (_, offer) = sessions();
        let piu = first_attach();
        assert_eq!(
            session.observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf6], &piu),
            Err(UserPacingError::WrongRoute)
        );
        let mut wrong_luw = piu.clone();
        wrong_luw[9 + 17] ^= 1;
        assert_eq!(
            session.observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &wrong_luw),
            Err(UserPacingError::WrongRoute)
        );
        let mut bad_pip = piu.clone();
        bad_pip[9 + 36 + 1] = 0xc4;
        assert_eq!(
            session.observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &bad_pip),
            Err(UserPacingError::InvalidFmh5)
        );
        let mut wrong_pi = piu.clone();
        wrong_pi[7] &= !PACING_INDICATOR;
        assert!(matches!(
            session.observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &wrong_pi),
            Err(UserPacingError::Fmh5(UserFmh5Error::UnsupportedPiu))
        ));
        let mut alias = offer.clone();
        alias.fqpcid[2] ^= 1;
        assert_eq!(
            session.observe_first_attach(&alias, &[0x30, 0xf0, 0xf0, 0xf5], &piu),
            Err(UserPacingError::WrongSession)
        );
        // All rejected variants leave the receive window available.
        session
            .observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &piu)
            .unwrap();
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
        assert_eq!(
            session.observe_ipr(&hex("2e0002020000830100")),
            Err(UserPacingError::WrongSession)
        );
        // Live V4R4 sustained flow: A's IPR is normal-flow 0x2c even though
        // its user BIND used expedited-flow 0x2d.
        session.observe_ipr(&hex("2c0002020000830100")).unwrap();
        assert_eq!(
            session.observe_ipr(&hex("2c0002020000830100")),
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
        // The same isolated IPR also remains legal on the expedited flow.
        session.observe_ipr(&hex("2d0002020000830100")).unwrap();
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
        assert!(UserPacingSession::new_after_management(&alias, &management, 1).is_ok());
        alias = offer;
        alias.fqpcid = management.fqpcid().to_vec();
        assert!(matches!(
            UserPacingSession::new(&alias, &management, 1),
            Err(UserPacingError::WrongSession)
        ));
    }
}
