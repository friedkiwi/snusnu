//! Platform-independent circuit domain foundation.

pub mod appn_control;
pub mod bis_control;
pub mod cnos;
pub mod fid2_bind;
pub mod fid2_session_control;
pub mod fixed_pacing;
pub mod hpr_cv61;
pub mod hpr_fid5;
pub mod hpr_ip_activation;
pub mod hpr_lan;
pub mod hpr_ldlc_adjacency;
pub mod hpr_route_setup;
pub mod hpr_rtp;
pub mod hpr_rtp_receive;
pub mod hpr_rtp_reply;
pub mod hpr_rtp_send;
pub mod hpr_rtp_setup;
pub mod hpr_session_address;
pub mod hpr_setmode;
pub mod hpr_xid_evidence;
pub mod hpr_xid_leg;
pub mod llc;
pub mod llc2;
pub mod llc_type1;
pub mod native_management;
pub mod native_management_initiator;
pub mod packet_log;
pub mod session;
pub mod session_fabric;
pub mod user_bind;
pub mod user_fmh5;
pub mod user_pacing;
pub mod user_session_control;
pub mod user_startup_record;
pub mod xid3;
pub mod xid3_activation;
pub mod xid3_local;

use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CircuitId(NonZeroU64);

impl CircuitId {
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConnectionGeneration(NonZeroU64);

impl ConnectionGeneration {
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitState {
    Opening,
    Open,
    Closed,
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition;

impl CircuitState {
    pub fn transition(self, next: Self) -> Result<Self, InvalidTransition> {
        match (self, next) {
            (Self::Opening, Self::Open | Self::Closed | Self::Reset)
            | (Self::Open, Self::Closed | Self::Reset) => Ok(next),
            _ => Err(InvalidTransition),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_reject_zero() {
        assert!(CircuitId::new(0).is_none());
        assert_eq!(CircuitId::new(42).map(CircuitId::get), Some(42));
        assert!(ConnectionGeneration::new(0).is_none());
        assert_eq!(
            ConnectionGeneration::new(7).map(ConnectionGeneration::get),
            Some(7)
        );
    }

    #[test]
    fn lifecycle_rejects_reopening_terminal_states() {
        assert_eq!(
            CircuitState::Opening.transition(CircuitState::Open),
            Ok(CircuitState::Open)
        );
        assert_eq!(
            CircuitState::Open.transition(CircuitState::Closed),
            Ok(CircuitState::Closed)
        );
        assert_eq!(
            CircuitState::Closed.transition(CircuitState::Open),
            Err(InvalidTransition)
        );
        assert_eq!(
            CircuitState::Reset.transition(CircuitState::Open),
            Err(InvalidTransition)
        );
        assert_eq!(
            CircuitState::Open.transition(CircuitState::Opening),
            Err(InvalidTransition)
        );
    }
}
