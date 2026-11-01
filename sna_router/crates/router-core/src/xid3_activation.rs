//! Bounded XID3 activation for a locally configured fixed-role ABM link station.
//!
//! IBM SC30-3422-0, chapter 2, permits a fixed primary or secondary to pair
//! with a negotiable or complementary fixed-role station. Each must exchange
//! negotiation-proceeding XID3 with complementary nonnegotiable roles before
//! link activation completes. This engine stops there. The caller remains
//! responsible for LLC command/response framing, retries, and SABME, and must
//! provide a truthful local capability profile rather than copying a peer XID.

use crate::xid3::{ExchangeState, Role, Xid3, XidError};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    InvalidLocalProfile,
    InvalidPeer(XidError),
    IncompatibleAbm,
    IncompatibleRole,
    UnexpectedState,
    UnconfirmedSend,
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "APPN XID activation: {self:?}")
    }
}

impl Error for ActivationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Exchanging,
    ReadyForSabme,
}

pub struct FixedRoleActivation {
    local: Xid3,
    local_role: Role,
    awaiting_send: Option<Xid3>,
    sent_proceeding: bool,
    received_complementary_proceeding: bool,
    peer_name: Option<String>,
    peer_node_id: Option<[u8; 4]>,
}

impl FixedRoleActivation {
    pub fn new(local: Xid3) -> Result<Self, ActivationError> {
        let local_role = local
            .role()
            .map_err(|_| ActivationError::InvalidLocalProfile)?;
        if local_role == Role::Negotiable
            || !local.abm_capable()
            || local.exchange_state() != ExchangeState::Prenegotiation
            || local.cp_name().is_err()
            || local.encode().is_err()
        {
            return Err(ActivationError::InvalidLocalProfile);
        }
        Ok(Self {
            local,
            local_role,
            awaiting_send: None,
            sent_proceeding: false,
            received_complementary_proceeding: false,
            peer_name: None,
            peer_node_id: None,
        })
    }

    pub fn phase(&self) -> Phase {
        if self.sent_proceeding && self.received_complementary_proceeding {
            Phase::ReadyForSabme
        } else {
            Phase::Exchanging
        }
    }

    pub fn peer_name(&self) -> Option<&str> {
        self.peer_name.as_deref()
    }

    pub fn peer_node_id(&self) -> Option<[u8; 4]> {
        self.peer_node_id
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    /// Respond to a null XID command with a locally owned XID3. Once a peer
    /// XID3 has been seen, retain negotiation-proceeding state. Only the
    /// caller can decide which LLC command/response bit to use.
    pub fn on_null_xid(&mut self) -> Result<Xid3, ActivationError> {
        if self.phase() == Phase::ReadyForSabme {
            return Err(ActivationError::UnexpectedState);
        }
        let mut outgoing = self.local.clone();
        if self.peer_node_id.is_some() {
            outgoing.set_exchange_state(ExchangeState::NegotiationProceeding);
        }
        self.awaiting_send = Some(outgoing.clone());
        Ok(outgoing)
    }

    /// Process the complete I-field from a peer XID3 and prepare the local
    /// response. The local ESI advances to proceeding only after a peer XID3
    /// is seen; the local role remains fixed throughout.
    pub fn on_peer_xid(&mut self, bytes: &[u8]) -> Result<Xid3, ActivationError> {
        let peer = Xid3::decode(bytes).map_err(ActivationError::InvalidPeer)?;
        if !peer.abm_capable() {
            return Err(ActivationError::IncompatibleAbm);
        }
        let expected_peer_role = match self.local_role {
            Role::Primary => Role::Secondary,
            Role::Secondary => Role::Primary,
            Role::Negotiable => unreachable!("constructor rejects negotiable role"),
        };
        if !matches!(peer.role(), Ok(role) if role == expected_peer_role || role == Role::Negotiable)
        {
            return Err(ActivationError::IncompatibleRole);
        }
        if !matches!(
            peer.exchange_state(),
            ExchangeState::Prenegotiation | ExchangeState::NegotiationProceeding
        ) {
            return Err(ActivationError::UnexpectedState);
        }
        if self.phase() == Phase::ReadyForSabme
            && (peer.exchange_state() != ExchangeState::NegotiationProceeding
                || peer.role() != Ok(expected_peer_role))
        {
            return Err(ActivationError::UnexpectedState);
        }
        if let Ok(name) = peer.cp_name() {
            if name == self.local.cp_name().expect("validated local CP name") {
                return Err(ActivationError::IncompatibleRole);
            }
            if self
                .peer_name
                .as_deref()
                .is_some_and(|previous| previous != name)
            {
                return Err(ActivationError::UnexpectedState);
            }
            self.peer_name = Some(name);
        }
        self.peer_node_id = Some(peer.node_id());
        if peer.exchange_state() == ExchangeState::NegotiationProceeding
            && peer.role() == Ok(expected_peer_role)
        {
            self.received_complementary_proceeding = true;
        }
        let mut outgoing = self.local.clone();
        outgoing.set_exchange_state(ExchangeState::NegotiationProceeding);
        self.awaiting_send = Some(outgoing.clone());
        Ok(outgoing)
    }

    /// Record that the exact prepared I-field was handed to LLC for sending.
    /// The link is ready for SABME only after this and a complementary peer
    /// proceeding XID3 were both observed.
    pub fn confirm_sent(&mut self, sent: &Xid3) -> Result<Phase, ActivationError> {
        if self.awaiting_send.as_ref() != Some(sent) {
            return Err(ActivationError::UnconfirmedSend);
        }
        self.awaiting_send = None;
        if sent.exchange_state() == ExchangeState::NegotiationProceeding {
            self.sent_proceeding = true;
        }
        Ok(self.phase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xid3::ControlVector;

    fn xid(name: &str, role: Role, state: ExchangeState) -> Xid3 {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(if name.ends_with("ROUTER") {
            &[0xff, 0xf1, 0x12, 0x34]
        } else {
            &[0x05, 0x63, 0x39, 0x50]
        });
        fixed[9] = 0x08;
        fixed[19] = 0x40;
        fixed[21..23].copy_from_slice(&1496u16.to_be_bytes());
        fixed[27] = 7;
        let mut xid = Xid3::from_parts(
            fixed,
            vec![ControlVector {
                key: 0x0e,
                data: vec![
                    0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2,
                ],
            }],
        )
        .unwrap();
        xid.set_cp_name(name).unwrap();
        xid.set_role(role);
        xid.set_exchange_state(state);
        xid
    }

    #[test]
    fn waits_for_both_proceeding_xids_and_primary_peer_role() {
        let local = xid(
            "SOLNET.ROUTER",
            Role::Secondary,
            ExchangeState::Prenegotiation,
        );
        let mut activation = FixedRoleActivation::new(local).unwrap();
        let pre = activation.on_null_xid().unwrap();
        assert_eq!(pre.exchange_state(), ExchangeState::Prenegotiation);
        assert_eq!(activation.confirm_sent(&pre), Ok(Phase::Exchanging));

        let peer_pre = xid(
            "SOLNET.SNAB",
            Role::Negotiable,
            ExchangeState::Prenegotiation,
        );
        let proceeding = activation.on_peer_xid(&peer_pre.encode().unwrap()).unwrap();
        assert_eq!(proceeding.role(), Ok(Role::Secondary));
        assert_eq!(
            proceeding.exchange_state(),
            ExchangeState::NegotiationProceeding
        );
        assert_eq!(activation.confirm_sent(&proceeding), Ok(Phase::Exchanging));
        assert_eq!(
            activation.on_null_xid().unwrap().exchange_state(),
            ExchangeState::NegotiationProceeding
        );

        let peer_proceeding = xid(
            "SOLNET.SNAB",
            Role::Primary,
            ExchangeState::NegotiationProceeding,
        );
        let response = activation
            .on_peer_xid(&peer_proceeding.encode().unwrap())
            .unwrap();
        assert_eq!(activation.phase(), Phase::ReadyForSabme);
        assert_eq!(activation.confirm_sent(&response), Ok(Phase::ReadyForSabme));
        assert_eq!(activation.peer_name(), Some("SOLNET.SNAB"));
    }

    #[test]
    fn rejects_incompatible_peer_and_unconfirmed_sends() {
        let local = xid(
            "SOLNET.ROUTER",
            Role::Secondary,
            ExchangeState::Prenegotiation,
        );
        let mut activation = FixedRoleActivation::new(local.clone()).unwrap();
        assert_eq!(
            activation.confirm_sent(&local),
            Err(ActivationError::UnconfirmedSend)
        );
        let peer_secondary = xid(
            "SOLNET.SNAB",
            Role::Secondary,
            ExchangeState::Prenegotiation,
        );
        assert_eq!(
            activation.on_peer_xid(&peer_secondary.encode().unwrap()),
            Err(ActivationError::IncompatibleRole)
        );
        let mut peer_no_abm = xid("SOLNET.SNAB", Role::Primary, ExchangeState::Prenegotiation);
        peer_no_abm.set_role(Role::Primary);
        let mut wire = peer_no_abm.encode().unwrap();
        wire[19] &= !0x40;
        assert_eq!(
            activation.on_peer_xid(&wire),
            Err(ActivationError::IncompatibleAbm)
        );
    }

    #[test]
    fn fixed_primary_waits_for_peer_secondary_before_sabme() {
        let local = xid(
            "SOLNET.ROUTER",
            Role::Primary,
            ExchangeState::Prenegotiation,
        );
        let mut activation = FixedRoleActivation::new(local).unwrap();
        assert_eq!(activation.local_role(), Role::Primary);
        let peer_pre = xid(
            "SOLNET.SNAA",
            Role::Negotiable,
            ExchangeState::Prenegotiation,
        );
        let outgoing = activation.on_peer_xid(&peer_pre.encode().unwrap()).unwrap();
        assert_eq!(outgoing.role(), Ok(Role::Primary));
        assert_eq!(activation.confirm_sent(&outgoing), Ok(Phase::Exchanging));
        let peer_final = xid(
            "SOLNET.SNAA",
            Role::Secondary,
            ExchangeState::NegotiationProceeding,
        );
        let outgoing = activation
            .on_peer_xid(&peer_final.encode().unwrap())
            .unwrap();
        assert_eq!(activation.confirm_sent(&outgoing), Ok(Phase::ReadyForSabme));
    }
}
