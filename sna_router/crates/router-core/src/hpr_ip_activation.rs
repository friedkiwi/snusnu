//! Read-only activation state for an HPR/IP link between two genuine nodes.
//!
//! RFC 2353 §2.5.1/§2.5.3 specifies the XID3 TG and enhanced-negotiation
//! requirements. A sanitized V5R4 relay capture observed null XIDs, each
//! side's prenegotiation and negotiation XID3, repeated negotiation XID3,
//! XID_DONE request/response, and bidirectional TEST liveness. This monitor
//! validates that order. It never emits local XID3, promises RTP capability,
//! or authorizes an APPN session gateway to route user traffic.

use crate::{
    hpr_lan::HprMedium,
    hpr_setmode::{SetModeError, XidDone},
    hpr_xid_leg::{HprXidLeg, LegAgreement, LegError, Side},
    xid3::{ExchangeState, Xid3, XidError},
};

const MAX_XID_OBSERVATIONS_PER_SIDE: u8 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Down,
    Negotiating,
    Agreed,
    WaitingForXidDone,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    InvalidXid(XidError),
    InvalidLeg(LegError),
    InvalidXidDone(SetModeError),
    XidRetryLimit,
    UnexpectedXid,
    SetModeBeforeAgreement,
    WrongSetModeDirection,
    UnexpectedSetMode,
    TestBeforeActivation,
    UnsolicitedTestResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    None,
    Agreement,
    Activated,
    TestCompleted,
    Deactivated,
}

#[derive(Clone, Debug)]
pub struct HprIpActivation {
    leg: HprXidLeg,
    phase: Phase,
    xid_observations: [u8; 2],
    xid_done_requester: Option<Side>,
    test_outstanding: [bool; 2],
}

impl HprIpActivation {
    pub fn new(initiator: Side) -> Self {
        Self {
            leg: HprXidLeg::new(HprMedium::EnterpriseExtender, initiator),
            phase: Phase::Down,
            xid_observations: [0; 2],
            xid_done_requester: None,
            test_outstanding: [false; 2],
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn agreement(&self) -> Option<LegAgreement> {
        self.leg.xid_agreement().ok()
    }

    pub fn observe_xid(
        &mut self,
        side: Side,
        information: &[u8],
    ) -> Result<Observation, ActivationError> {
        // The null XID is a genuine activation bootstrap, but carries no CP
        // or HPR claim. It can restart an active link without copying state.
        if information.is_empty() {
            if self.phase == Phase::Active {
                *self = Self::new(side);
                return Ok(Observation::Deactivated);
            }
            return Ok(Observation::None);
        }
        let xid = Xid3::decode(information).map_err(ActivationError::InvalidXid)?;
        if self.phase == Phase::Active && xid.exchange_state() == ExchangeState::Prenegotiation {
            *self = Self::new(side);
        } else if self.phase == Phase::Active {
            return Err(ActivationError::UnexpectedXid);
        }
        let index = side_index(side);
        self.xid_observations[index] = self.xid_observations[index]
            .checked_add(1)
            .filter(|count| *count <= MAX_XID_OBSERVATIONS_PER_SIDE)
            .ok_or(ActivationError::XidRetryLimit)?;
        match xid.exchange_state() {
            ExchangeState::Prenegotiation => {
                self.leg
                    .observe_prenegotiation(side, information)
                    .map_err(ActivationError::InvalidLeg)?;
                self.phase = Phase::Negotiating;
                self.xid_done_requester = None;
                Ok(Observation::None)
            }
            ExchangeState::NegotiationProceeding => {
                self.leg
                    .observe_negotiation(side, information)
                    .map_err(ActivationError::InvalidLeg)?;
                // A fresh NP XID after XID_DONE request invalidates that
                // request. The peer must request XID_DONE again before a
                // response can activate the link.
                if self.phase == Phase::WaitingForXidDone {
                    self.xid_done_requester = None;
                }
                if self.leg.xid_agreement().is_ok() {
                    if self.phase == Phase::Agreed {
                        return Ok(Observation::None);
                    }
                    self.phase = Phase::Agreed;
                    return Ok(Observation::Agreement);
                }
                self.phase = Phase::Negotiating;
                Ok(Observation::None)
            }
            _ => Err(ActivationError::InvalidLeg(LegError::WrongExchangeState)),
        }
    }

    /// `nlp` excludes the three-byte LLC-like HPR/IP datagram header.
    pub fn observe_xid_done(
        &mut self,
        side: Side,
        nlp: &[u8],
    ) -> Result<Observation, ActivationError> {
        let kind = XidDone::parse(nlp).map_err(ActivationError::InvalidXidDone)?;
        if matches!(self.phase, Phase::Down | Phase::Negotiating) {
            return Err(ActivationError::SetModeBeforeAgreement);
        }
        let agreement = self
            .leg
            .xid_agreement()
            .map_err(ActivationError::InvalidLeg)?;
        let primary = if agreement.local.role == crate::xid3::Role::Primary {
            Side::Local
        } else {
            Side::Remote
        };
        match (kind, self.phase) {
            (XidDone::Request, Phase::Agreed | Phase::WaitingForXidDone) if side == primary => {
                self.xid_done_requester = Some(side);
                self.phase = Phase::WaitingForXidDone;
                Ok(Observation::None)
            }
            (XidDone::Response, Phase::WaitingForXidDone)
                if self.xid_done_requester == Some(opposite(side)) =>
            {
                self.phase = Phase::Active;
                Ok(Observation::Activated)
            }
            (XidDone::Request, _) if side != primary => Err(ActivationError::WrongSetModeDirection),
            _ => Err(ActivationError::UnexpectedSetMode),
        }
    }

    /// A TEST response must answer an outstanding request sent by the other
    /// side. Request retransmission and simultaneous opposite requests are
    /// permitted; this monitor never sends a response itself.
    pub fn observe_test(
        &mut self,
        side: Side,
        response: bool,
    ) -> Result<Observation, ActivationError> {
        if self.phase != Phase::Active {
            return Err(ActivationError::TestBeforeActivation);
        }
        if !response {
            self.test_outstanding[side_index(side)] = true;
            return Ok(Observation::None);
        }
        let requester = side_index(opposite(side));
        if !self.test_outstanding[requester] {
            return Err(ActivationError::UnsolicitedTestResponse);
        }
        self.test_outstanding[requester] = false;
        Ok(Observation::TestCompleted)
    }

    pub fn observe_disconnect(&mut self, initiator: Side) -> Observation {
        *self = Self::new(initiator);
        Observation::Deactivated
    }
}

fn side_index(side: Side) -> usize {
    match side {
        Side::Local => 0,
        Side::Remote => 1,
    }
}

fn opposite(side: Side) -> Side {
    match side {
        Side::Local => Side::Remote,
        Side::Remote => Side::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xid3::{ControlVector, Role};

    fn xid(side: Side, state: ExchangeState, role: Role, complete: bool) -> Vec<u8> {
        // CV61 prefix, SAP, and CV46 TG identifier match sanitized V5R4 EE
        // control evidence. CP and node identifiers are synthetic.
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(match side {
            Side::Local => &[0xff, 0xf0, 0, 1],
            Side::Remote => &[0xff, 0xf0, 0, 2],
        });
        fixed[9] = match state {
            ExchangeState::Prenegotiation => 0x08,
            ExchangeState::NegotiationProceeding => 0x04,
            _ => panic!("test needs activation exchange"),
        };
        fixed[12] = 0x80 | if complete { 0x40 } else { 0 };
        fixed[16] = 1;
        fixed[19] = match role {
            Role::Primary => 0x10,
            Role::Secondary => 0,
            Role::Negotiable => 0x30,
        };
        fixed[21..23].copy_from_slice(&1461u16.to_be_bytes());
        fixed[27] = 7;
        let mut cp = vec![
            0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1,
        ];
        cp.push(if side == Side::Local { 0xc1 } else { 0xc2 });
        let mut vectors = vec![
            ControlVector {
                key: 0x0e,
                data: cp,
            },
            ControlVector {
                key: 0x46,
                data: vec![5, 0x80, 1, 0, 0],
            },
        ];
        if state == ExchangeState::NegotiationProceeding {
            vectors.push(ControlVector {
                key: 0x61,
                data: vec![0xf8, 0, 2, 0x80, 2, 3, 0x80, 4],
            });
        }
        Xid3::from_parts(fixed, vectors).unwrap().encode().unwrap()
    }

    fn negotiate(observer: &mut HprIpActivation, initiator: Side, primary: Side) {
        assert_eq!(observer.observe_xid(initiator, &[]), Ok(Observation::None));
        for side in [initiator, opposite(initiator)] {
            assert_eq!(
                observer.observe_xid(
                    side,
                    &xid(side, ExchangeState::Prenegotiation, Role::Negotiable, false)
                ),
                Ok(Observation::None)
            );
        }
        for side in [initiator, opposite(initiator)] {
            assert_eq!(
                observer.observe_xid(
                    side,
                    &xid(
                        side,
                        ExchangeState::NegotiationProceeding,
                        Role::Negotiable,
                        false
                    )
                ),
                Ok(Observation::None)
            );
        }
        for side in [opposite(primary), primary] {
            let role = if side == primary {
                Role::Primary
            } else {
                Role::Secondary
            };
            let result = observer.observe_xid(
                side,
                &xid(
                    side,
                    ExchangeState::NegotiationProceeding,
                    role,
                    role == Role::Secondary,
                ),
            );
            if side == primary {
                assert_eq!(result, Ok(Observation::Agreement));
            } else {
                assert_eq!(result, Ok(Observation::None));
            }
        }
        assert_eq!(observer.phase(), Phase::Agreed);
    }

    #[test]
    fn captured_direction_retries_xid_done_then_liveness_in_both_directions() {
        let mut observer = HprIpActivation::new(Side::Local);
        assert_eq!(
            observer.observe_xid_done(Side::Remote, &XidDone::Request.encode()),
            Err(ActivationError::SetModeBeforeAgreement)
        );
        negotiate(&mut observer, Side::Local, Side::Remote);
        let repeated = xid(
            Side::Local,
            ExchangeState::NegotiationProceeding,
            Role::Secondary,
            true,
        );
        assert_eq!(
            observer.observe_xid(Side::Local, &repeated),
            Ok(Observation::None)
        );
        for _ in 0..2 {
            assert_eq!(
                observer.observe_xid_done(Side::Remote, &XidDone::Request.encode()),
                Ok(Observation::None)
            );
        }
        assert_eq!(observer.phase(), Phase::WaitingForXidDone);
        assert_eq!(
            observer.observe_xid_done(Side::Local, &XidDone::Response.encode()),
            Ok(Observation::Activated)
        );
        for side in [Side::Remote, Side::Local] {
            assert_eq!(observer.observe_test(side, false), Ok(Observation::None));
            assert_eq!(
                observer.observe_test(opposite(side), true),
                Ok(Observation::TestCompleted)
            );
        }
        assert_eq!(observer.phase(), Phase::Active);
        assert_eq!(
            observer.observe_disconnect(Side::Remote),
            Observation::Deactivated
        );
        assert_eq!(observer.phase(), Phase::Down);
    }

    #[test]
    fn reverse_initiation_and_wrong_direction_fail_closed() {
        let mut observer = HprIpActivation::new(Side::Remote);
        negotiate(&mut observer, Side::Remote, Side::Local);
        assert_eq!(
            observer.observe_xid_done(Side::Remote, &XidDone::Request.encode()),
            Err(ActivationError::WrongSetModeDirection)
        );
        assert_eq!(
            observer.observe_xid_done(Side::Local, &XidDone::Request.encode()),
            Ok(Observation::None)
        );
        assert_eq!(
            observer.observe_xid_done(Side::Local, &XidDone::Response.encode()),
            Err(ActivationError::UnexpectedSetMode)
        );
        assert_eq!(
            observer.observe_xid_done(Side::Remote, &XidDone::Response.encode()),
            Ok(Observation::Activated)
        );
        assert_eq!(
            observer.observe_test(Side::Remote, true),
            Err(ActivationError::UnsolicitedTestResponse)
        );
        assert_eq!(
            observer.observe_xid(
                Side::Local,
                &xid(
                    Side::Local,
                    ExchangeState::NegotiationProceeding,
                    Role::Primary,
                    false
                )
            ),
            Err(ActivationError::UnexpectedXid)
        );
        assert_eq!(
            observer.observe_xid(Side::Remote, &[]),
            Ok(Observation::Deactivated)
        );
    }

    #[test]
    fn repeated_xid_is_bounded() {
        let mut observer = HprIpActivation::new(Side::Local);
        let pre = xid(
            Side::Local,
            ExchangeState::Prenegotiation,
            Role::Negotiable,
            false,
        );
        for _ in 0..MAX_XID_OBSERVATIONS_PER_SIDE {
            assert_eq!(
                observer.observe_xid(Side::Local, &pre),
                Ok(Observation::None)
            );
        }
        assert_eq!(
            observer.observe_xid(Side::Local, &pre),
            Err(ActivationError::XidRetryLimit)
        );
    }

    #[test]
    fn renegotiation_discards_pending_xid_done_request() {
        let mut observer = HprIpActivation::new(Side::Local);
        negotiate(&mut observer, Side::Local, Side::Remote);
        assert_eq!(
            observer.observe_xid_done(Side::Remote, &XidDone::Request.encode()),
            Ok(Observation::None)
        );
        assert_eq!(
            observer.observe_xid(
                Side::Local,
                &xid(
                    Side::Local,
                    ExchangeState::NegotiationProceeding,
                    Role::Secondary,
                    true
                )
            ),
            Ok(Observation::Agreement)
        );
        assert_eq!(observer.phase(), Phase::Agreed);
        assert_eq!(
            observer.observe_xid_done(Side::Local, &XidDone::Response.encode()),
            Err(ActivationError::UnexpectedSetMode)
        );
    }
}
