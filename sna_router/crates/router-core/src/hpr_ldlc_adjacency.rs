//! Bounded, read-only LDLC adjacency state for one HPR/IP IP-address pair.
//!
//! RFC 2353 sections 2.3 and 2.5 identify a link by its IP and SAP pairs.
//! The caller owns the IP pair and supplies observations for both directions.
//! This state validates the negotiated SAPs before accepting an NLP as link
//! traffic, expires idle state, and debounces an active link's restart XID.
//! It never emits an XID, advertises a CV61 capability, or authorizes RTP.

use crate::{
    hpr_ip_activation::{ActivationError, HprIpActivation, Observation, Phase},
    hpr_xid_leg::Side,
    xid3::{ExchangeState, Xid3, XidError},
};

const IDLE_TIMEOUT_MS: u64 = 60_000;
const RESTART_WINDOW_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjacencyError {
    ClockMovedBackwards,
    InvalidXid(XidError),
    Activation(ActivationError),
    IdentityChanged,
    NotActive,
    SapMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RestartProbe {
    side: Side,
    cp: String,
    node_id: [u8; 4],
    first_seen_ms: u64,
}

/// One LDLC link. A caller must keep different IP pairs in different values.
#[derive(Clone, Debug)]
pub struct HprLdlcAdjacency {
    activation: HprIpActivation,
    initiator: Side,
    last_seen_ms: Option<u64>,
    restart_probe: Option<RestartProbe>,
    generation: u64,
}

impl HprLdlcAdjacency {
    pub fn new(initiator: Side) -> Self {
        Self {
            activation: HprIpActivation::new(initiator),
            initiator,
            last_seen_ms: None,
            restart_probe: None,
            generation: 1,
        }
    }

    pub fn phase(&self) -> Phase {
        self.activation.phase()
    }

    /// Increases on disconnect, idle expiry, and confirmed reactivation.
    /// A caller can use this value to keep old RTP state out of a new link.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Reset after 60 seconds without validated link traffic. This exceeds
    /// the normal EE TEST retry interval; an eventual endpoint must still
    /// coordinate this observer with its own negotiated liveness policy.
    pub fn expire(&mut self, now_ms: u64) -> Result<bool, AdjacencyError> {
        if let Some(previous) = self.last_seen_ms {
            if now_ms < previous {
                return Err(AdjacencyError::ClockMovedBackwards);
            }
            if now_ms - previous >= IDLE_TIMEOUT_MS {
                self.reset();
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Observe an XID information field after the caller has matched the IP
    /// pair and control UDP port. An active link only restarts after two
    /// matching prenegotiation XIDs within five seconds, avoiding a stray
    /// delayed UDP XID tearing down a healthy link.
    pub fn observe_xid(
        &mut self,
        side: Side,
        information: &[u8],
        now_ms: u64,
    ) -> Result<Observation, AdjacencyError> {
        self.expire(now_ms)?;
        if self.phase() == Phase::Active && information.is_empty() {
            self.reset();
            return Ok(Observation::Deactivated);
        }
        if self.phase() == Phase::Active && !information.is_empty() {
            let xid = Xid3::decode(information).map_err(AdjacencyError::InvalidXid)?;
            if xid.exchange_state() == ExchangeState::Prenegotiation {
                let cp = xid.cp_name().map_err(AdjacencyError::InvalidXid)?;
                let node_id = xid.node_id();
                let agreement = self
                    .activation
                    .agreement()
                    .ok_or(AdjacencyError::NotActive)?;
                let expected = match side {
                    Side::Local => &agreement.local,
                    Side::Remote => &agreement.remote,
                };
                if cp != expected.cp_name || node_id != expected.node_id {
                    return Err(AdjacencyError::IdentityChanged);
                }
                let matching = self.restart_probe.as_ref().is_some_and(|probe| {
                    probe.side == side
                        && probe.cp == cp
                        && probe.node_id == node_id
                        && now_ms - probe.first_seen_ms <= RESTART_WINDOW_MS
                });
                if !matching {
                    self.restart_probe = Some(RestartProbe {
                        side,
                        cp,
                        node_id,
                        first_seen_ms: now_ms,
                    });
                    self.last_seen_ms = Some(now_ms);
                    return Ok(Observation::None);
                }
                self.reset();
                let result = self
                    .activation
                    .observe_xid(side, information)
                    .map_err(AdjacencyError::Activation)?;
                self.last_seen_ms = Some(now_ms);
                debug_assert_eq!(result, Observation::None);
                return Ok(Observation::Deactivated);
            }
        }
        let result = self
            .activation
            .observe_xid(side, information)
            .map_err(AdjacencyError::Activation)?;
        self.last_seen_ms = Some(now_ms);
        Ok(result)
    }

    /// Observe XID_DONE after the caller has validated control framing.
    pub fn observe_xid_done(
        &mut self,
        side: Side,
        nlp: &[u8],
        now_ms: u64,
    ) -> Result<Observation, AdjacencyError> {
        self.expire(now_ms)?;
        let result = self
            .activation
            .observe_xid_done(side, nlp)
            .map_err(AdjacencyError::Activation)?;
        self.last_seen_ms = Some(now_ms);
        Ok(result)
    }

    pub fn observe_test(
        &mut self,
        side: Side,
        response: bool,
        now_ms: u64,
    ) -> Result<Observation, AdjacencyError> {
        self.expire(now_ms)?;
        let result = self
            .activation
            .observe_test(side, response)
            .map_err(AdjacencyError::Activation)?;
        self.last_seen_ms = Some(now_ms);
        Ok(result)
    }

    /// UI NLP is accepted only under the SAPs exchanged in CV61. This is
    /// framing evidence, not proof that any RTP connection is established.
    pub fn observe_nlp(
        &mut self,
        side: Side,
        dsap: u8,
        ssap: u8,
        now_ms: u64,
    ) -> Result<(), AdjacencyError> {
        self.expire(now_ms)?;
        if self.phase() != Phase::Active {
            return Err(AdjacencyError::NotActive);
        }
        let agreement = self
            .activation
            .agreement()
            .ok_or(AdjacencyError::NotActive)?;
        let (destination, source) = match side {
            Side::Local => (
                agreement.remote.advertised_sap,
                agreement.local.advertised_sap,
            ),
            Side::Remote => (
                agreement.local.advertised_sap,
                agreement.remote.advertised_sap,
            ),
        };
        if dsap != destination || ssap != source {
            return Err(AdjacencyError::SapMismatch);
        }
        self.last_seen_ms = Some(now_ms);
        Ok(())
    }

    pub fn observe_disconnect(&mut self) -> Observation {
        self.reset();
        Observation::Deactivated
    }

    fn reset(&mut self) {
        self.activation = HprIpActivation::new(self.initiator);
        self.last_seen_ms = None;
        self.restart_probe = None;
        self.generation = self.generation.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_setmode::XidDone,
        hpr_xid_leg::local_ee_tg_descriptor,
        xid3::{ControlVector, Role},
    };

    fn xid(side: Side, state: ExchangeState, role: Role, complete: bool) -> Vec<u8> {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(match side {
            Side::Local => &[0xff, 0xf0, 0, 1],
            Side::Remote => &[0xff, 0xf0, 0, 2],
        });
        fixed[9] = match state {
            ExchangeState::Prenegotiation => 0x08,
            ExchangeState::NegotiationProceeding => 0x04,
            _ => unreachable!(),
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
            local_ee_tg_descriptor(1),
        ];
        if state == ExchangeState::NegotiationProceeding {
            vectors.push(ControlVector {
                key: 0x61,
                data: vec![0xf8, 0, 2, 0x80, 2, 3, 0x80, 4],
            });
        }
        Xid3::from_parts(fixed, vectors).unwrap().encode().unwrap()
    }

    fn activate(link: &mut HprLdlcAdjacency) {
        for (index, side) in [Side::Remote, Side::Local].into_iter().enumerate() {
            link.observe_xid(
                side,
                &xid(side, ExchangeState::Prenegotiation, Role::Negotiable, false),
                1 + 2 * index as u64,
            )
            .unwrap();
            link.observe_xid(
                side,
                &xid(
                    side,
                    ExchangeState::NegotiationProceeding,
                    Role::Negotiable,
                    false,
                ),
                2 + 2 * index as u64,
            )
            .unwrap();
        }
        link.observe_xid(
            Side::Local,
            &xid(
                Side::Local,
                ExchangeState::NegotiationProceeding,
                Role::Secondary,
                true,
            ),
            5,
        )
        .unwrap();
        assert_eq!(
            link.observe_xid(
                Side::Remote,
                &xid(
                    Side::Remote,
                    ExchangeState::NegotiationProceeding,
                    Role::Primary,
                    false
                ),
                6
            ),
            Ok(Observation::Agreement)
        );
        link.observe_xid_done(Side::Remote, &XidDone::Request.encode(), 7)
            .unwrap();
        assert_eq!(
            link.observe_xid_done(Side::Local, &XidDone::Response.encode(), 8),
            Ok(Observation::Activated)
        );
    }

    #[test]
    fn idle_and_clock_bounds_do_not_promote_remote_only_xid() {
        let mut link = HprLdlcAdjacency::new(Side::Remote);
        assert_eq!(
            link.observe_xid(Side::Remote, &[], 100),
            Ok(Observation::None)
        );
        assert_eq!(link.phase(), Phase::Down);
        assert_eq!(
            link.observe_nlp(Side::Remote, 4, 4, 101),
            Err(AdjacencyError::NotActive)
        );
        assert_eq!(link.expire(99), Err(AdjacencyError::ClockMovedBackwards));
        assert_eq!(link.expire(60_100), Ok(true));
        assert_eq!(link.generation(), 2);
        assert_eq!(link.observe_disconnect(), Observation::Deactivated);
        assert_eq!(link.generation(), 3);
    }

    #[test]
    fn negotiated_sap_and_restart_debounce() {
        let mut link = HprLdlcAdjacency::new(Side::Remote);
        activate(&mut link);
        assert_eq!(link.observe_nlp(Side::Remote, 4, 4, 9), Ok(()));
        assert_eq!(
            link.observe_nlp(Side::Remote, 5, 4, 10),
            Err(AdjacencyError::SapMismatch)
        );
        let restart = xid(
            Side::Remote,
            ExchangeState::Prenegotiation,
            Role::Negotiable,
            false,
        );
        assert_eq!(
            link.observe_xid(Side::Remote, &restart, 11),
            Ok(Observation::None)
        );
        assert_eq!(link.phase(), Phase::Active);
        assert_eq!(link.generation(), 1);
        assert_eq!(
            link.observe_xid(Side::Remote, &restart, 12),
            Ok(Observation::Deactivated)
        );
        assert_eq!(link.phase(), Phase::Negotiating);
        assert_eq!(link.generation(), 2);
        assert_eq!(
            link.observe_nlp(Side::Remote, 4, 4, 13),
            Err(AdjacencyError::NotActive)
        );
    }

    #[test]
    fn one_restart_xid_outside_window_does_not_deactivate() {
        let mut link = HprLdlcAdjacency::new(Side::Remote);
        activate(&mut link);
        let restart = xid(
            Side::Remote,
            ExchangeState::Prenegotiation,
            Role::Negotiable,
            false,
        );
        link.observe_xid(Side::Remote, &restart, 10).unwrap();
        link.observe_xid(Side::Remote, &restart, 5_011).unwrap();
        assert_eq!(link.phase(), Phase::Active);
        assert_eq!(link.generation(), 1);
        assert_eq!(
            link.observe_xid(Side::Remote, &[], 5_012),
            Ok(Observation::Deactivated)
        );
        assert_eq!(link.generation(), 2);
    }
}
