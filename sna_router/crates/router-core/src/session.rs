//! Carrier-neutral SNA session boundary.
//!
//! A link adapter must remove LLC, MPTN, or HPR framing before emitting these
//! events. It must not feed an unparsed transport record into `Information`.
//! Carrier-specific negotiation, FID2 addresses, and pacing translation stay
//! with the adapter. The two-byte SNA sequence field (SNF) stays with the
//! session unit so forwarding preserves request/response correlation.
//! This contract fixes the ordering and bounded data
//! presented to the router's session selector.

use std::{fmt, str::FromStr};

pub const MAX_SESSION_UNIT: usize = 64 * 1024;
pub const MAX_WINDOW_GRANT: u32 = 1 << 20;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct QualifiedName {
    pub netid: String,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidIdentity,
    InvalidUnit,
    InvalidCredit,
    InvalidTransition,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SessionError {}

impl QualifiedName {
    pub fn new(netid: impl Into<String>, name: impl Into<String>) -> Result<Self, SessionError> {
        let result = Self {
            netid: netid.into(),
            name: name.into(),
        };
        if !valid_name(&result.netid) || !valid_name(&result.name) {
            return Err(SessionError::InvalidIdentity);
        }
        Ok(result)
    }
}

impl FromStr for QualifiedName {
    type Err = SessionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (netid, name) = value.split_once('.').ok_or(SessionError::InvalidIdentity)?;
        Self::new(netid, name)
    }
}

impl fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.netid, self.name)
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'@' | b'#' | b'$')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub source_lu: QualifiedName,
    pub target_lu: QualifiedName,
    pub source_cp: Option<QualifiedName>,
    pub target_cp: Option<QualifiedName>,
}

impl SessionIdentity {
    pub fn new(source_lu: QualifiedName, target_lu: QualifiedName) -> Self {
        Self {
            source_lu,
            target_lu,
            source_cp: None,
            target_cp: None,
        }
    }

    pub fn with_control_points(
        mut self,
        source_cp: Option<QualifiedName>,
        target_cp: Option<QualifiedName>,
    ) -> Result<Self, SessionError> {
        if source_cp
            .as_ref()
            .is_some_and(|cp| cp.netid != self.source_lu.netid)
            || target_cp
                .as_ref()
                .is_some_and(|cp| cp.netid != self.target_lu.netid)
        {
            return Err(SessionError::InvalidIdentity);
        }
        self.source_cp = source_cp;
        self.target_cp = target_cp;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flow {
    Normal,
    Expedited,
}

/// One complete reduced SNA session unit: two-byte SNF, three-byte RH, then RU.
/// FID2 addressing or HPR framing belongs to the carrier adapter. An empty
/// RU is valid for some control units; BIND and UNBIND require a nonempty RU.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionUnit(Vec<u8>);

impl SessionUnit {
    pub fn from_reduced(bytes: &[u8]) -> Result<Self, SessionError> {
        if !(5..=MAX_SESSION_UNIT).contains(&bytes.len()) {
            return Err(SessionError::InvalidUnit);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn snf(&self) -> &[u8] {
        &self.0[..2]
    }

    pub fn rh(&self) -> &[u8] {
        &self.0[2..5]
    }

    pub fn ru(&self) -> &[u8] {
        &self.0[5..]
    }

    pub fn as_reduced(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    /// BIND RH/RU after the ingress adapter has removed carrier framing.
    BindRequest(SessionUnit),
    /// Positive or negative BIND response as reduced RH/RU.
    BindResult {
        accepted: bool,
        unit: SessionUnit,
    },
    /// One complete reduced SNA unit, never a raw TCP62 or HPR record.
    Information {
        flow: Flow,
        unit: SessionUnit,
    },
    /// Capacity admitted by the destination side, not a carrier window byte.
    Credit {
        normal: u32,
        expedited: u32,
    },
    Unbind(SessionUnit),
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    AwaitBind,
    AwaitBindResult,
    Open,
    AwaitUnbindResult,
    Closed,
}

#[derive(Clone, Debug)]
pub struct SessionContract {
    pub identity: SessionIdentity,
    phase: SessionPhase,
    pending_unbind_snf: Option<[u8; 2]>,
}

impl SessionContract {
    pub fn new(identity: SessionIdentity) -> Self {
        Self {
            identity,
            phase: SessionPhase::AwaitBind,
            pending_unbind_snf: None,
        }
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// Validate an event before forwarding it. A failed transition leaves the
    /// session unchanged, so a malformed carrier record cannot advance it.
    pub fn accept(&mut self, event: &SessionEvent) -> Result<(), SessionError> {
        let mut pending_unbind_snf = self.pending_unbind_snf;
        let next = match (self.phase, event) {
            (SessionPhase::AwaitBind, SessionEvent::BindRequest(unit)) => {
                if unit.ru().is_empty() {
                    return Err(SessionError::InvalidUnit);
                }
                SessionPhase::AwaitBindResult
            }
            (SessionPhase::AwaitBindResult, SessionEvent::BindResult { accepted, .. }) => {
                if *accepted {
                    SessionPhase::Open
                } else {
                    SessionPhase::Closed
                }
            }
            (SessionPhase::Open, SessionEvent::Information { .. }) => SessionPhase::Open,
            (SessionPhase::Open, SessionEvent::Credit { normal, expedited }) => {
                if *normal > MAX_WINDOW_GRANT || *expedited > MAX_WINDOW_GRANT {
                    return Err(SessionError::InvalidCredit);
                }
                SessionPhase::Open
            }
            (SessionPhase::Open, SessionEvent::Unbind(unit)) => {
                if unit.ru().is_empty() || unit.rh()[0] & 0x80 != 0 {
                    return Err(SessionError::InvalidUnit);
                }
                pending_unbind_snf = Some(unit.snf().try_into().unwrap());
                SessionPhase::AwaitUnbindResult
            }
            (SessionPhase::AwaitUnbindResult, SessionEvent::Unbind(unit)) => {
                if unit.rh()[0] & 0x80 == 0
                    || Some(unit.snf()) != pending_unbind_snf.as_ref().map(|snf| snf.as_slice())
                {
                    return Err(SessionError::InvalidUnit);
                }
                pending_unbind_snf = None;
                SessionPhase::Closed
            }
            (
                SessionPhase::AwaitBind
                | SessionPhase::AwaitBindResult
                | SessionPhase::Open
                | SessionPhase::AwaitUnbindResult,
                SessionEvent::Reset,
            ) => {
                pending_unbind_snf = None;
                SessionPhase::Closed
            }
            _ => return Err(SessionError::InvalidTransition),
        };
        self.phase = next;
        self.pending_unbind_snf = pending_unbind_snf;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SessionIdentity {
        SessionIdentity::new("NETA.LUA".parse().unwrap(), "NETB.LUB".parse().unwrap())
            .with_control_points(
                Some("NETA.CPA".parse().unwrap()),
                Some("NETB.CPB".parse().unwrap()),
            )
            .unwrap()
    }

    fn unit(bytes: &[u8]) -> SessionUnit {
        SessionUnit::from_reduced(&[&[0, 0][..], bytes].concat()).unwrap()
    }

    #[test]
    fn names_and_hosts_are_bounded_and_network_qualified() {
        assert_eq!(
            "NETA.LUA".parse::<QualifiedName>().unwrap().to_string(),
            "NETA.LUA"
        );
        assert!("NETA.1LU".parse::<QualifiedName>().is_ok());
        for invalid in [
            "NETA",
            "NETA.",
            "NETA.LUA.EXTRA",
            "neta.LUA",
            "NINECHARS.LUA",
        ] {
            assert!(invalid.parse::<QualifiedName>().is_err(), "{invalid}");
        }
        assert!(
            SessionIdentity::new("NETA.LUA".parse().unwrap(), "NETB.LUB".parse().unwrap())
                .with_control_points(Some("NETB.CPA".parse().unwrap()), None)
                .is_err()
        );
    }

    #[test]
    fn reduced_unit_has_one_consistent_boundary() {
        let bind = unit(&[0x31, 0, 0, 0x31]);
        assert_eq!(bind.snf(), &[0, 0]);
        assert_eq!(bind.rh(), &[0x31, 0, 0]);
        assert_eq!(bind.ru(), &[0x31]);
        assert_eq!(bind.as_reduced(), &[0, 0, 0x31, 0, 0, 0x31]);
        let request = SessionUnit::from_reduced(&[0, 2, 0x03, 0x91, 0x20, 0xc1]).unwrap();
        assert_eq!(request.snf(), &[0, 2]);
        assert_eq!(request.rh(), &[0x03, 0x91, 0x20]);
        assert_eq!(request.ru(), &[0xc1]);
        assert_eq!(
            SessionUnit::from_reduced(&[0, 0, 1, 2]),
            Err(SessionError::InvalidUnit)
        );
        assert_eq!(
            SessionUnit::from_reduced(&vec![0; MAX_SESSION_UNIT + 1]),
            Err(SessionError::InvalidUnit)
        );
    }

    #[test]
    fn bind_data_credit_and_close_have_explicit_order_and_bounds() {
        let mut session = SessionContract::new(identity());
        assert_eq!(
            session.accept(&SessionEvent::Information {
                flow: Flow::Normal,
                unit: unit(&[0, 0, 0])
            }),
            Err(SessionError::InvalidTransition)
        );
        assert_eq!(
            session.accept(&SessionEvent::BindRequest(unit(&[0x31, 0, 0]))),
            Err(SessionError::InvalidUnit)
        );
        assert_eq!(session.phase(), SessionPhase::AwaitBind);
        session
            .accept(&SessionEvent::BindRequest(unit(&[0x31, 0, 0, 1])))
            .unwrap();
        assert_eq!(
            session.accept(&SessionEvent::BindRequest(unit(&[0x31, 0, 0, 1]))),
            Err(SessionError::InvalidTransition)
        );
        session
            .accept(&SessionEvent::BindResult {
                accepted: true,
                unit: unit(&[0, 0, 0]),
            })
            .unwrap();
        assert_eq!(session.phase(), SessionPhase::Open);
        session
            .accept(&SessionEvent::Information {
                flow: Flow::Expedited,
                unit: unit(&[0, 0, 0, 1]),
            })
            .unwrap();
        assert_eq!(
            session.accept(&SessionEvent::Credit {
                normal: MAX_WINDOW_GRANT + 1,
                expedited: 0
            }),
            Err(SessionError::InvalidCredit)
        );
        session
            .accept(&SessionEvent::Credit {
                normal: 7,
                expedited: 1,
            })
            .unwrap();
        session
            .accept(&SessionEvent::Unbind(unit(&[0, 0, 0, 1])))
            .unwrap();
        assert_eq!(session.phase(), SessionPhase::AwaitUnbindResult);
        assert_eq!(
            session.accept(&SessionEvent::Unbind(unit(&[0x80, 0, 0, 1]))),
            Ok(())
        );
        assert_eq!(session.phase(), SessionPhase::Closed);
        assert_eq!(
            session.accept(&SessionEvent::Reset),
            Err(SessionError::InvalidTransition)
        );
    }

    #[test]
    fn rejected_bind_and_reset_are_terminal() {
        let mut rejected = SessionContract::new(identity());
        rejected
            .accept(&SessionEvent::BindRequest(unit(&[0x31, 0, 0, 1])))
            .unwrap();
        rejected
            .accept(&SessionEvent::BindResult {
                accepted: false,
                unit: unit(&[0, 0, 0, 8]),
            })
            .unwrap();
        assert_eq!(rejected.phase(), SessionPhase::Closed);
        let mut reset = SessionContract::new(identity());
        reset.accept(&SessionEvent::Reset).unwrap();
        assert_eq!(reset.phase(), SessionPhase::Closed);
    }

    #[test]
    fn unbind_waits_for_correlated_response() {
        let mut session = SessionContract::new(identity());
        session
            .accept(&SessionEvent::BindRequest(unit(&[0x31, 0, 0, 1])))
            .unwrap();
        session
            .accept(&SessionEvent::BindResult {
                accepted: true,
                unit: unit(&[0, 0, 0]),
            })
            .unwrap();
        let request = SessionUnit::from_reduced(&[0x12, 0x34, 0x6b, 0x80, 0, 0x32]).unwrap();
        session.accept(&SessionEvent::Unbind(request)).unwrap();
        assert_eq!(session.phase(), SessionPhase::AwaitUnbindResult);
        let wrong = SessionUnit::from_reduced(&[0x12, 0x35, 0xeb, 0x80, 0, 0x32]).unwrap();
        assert_eq!(
            session.accept(&SessionEvent::Unbind(wrong)),
            Err(SessionError::InvalidUnit)
        );
        assert_eq!(session.phase(), SessionPhase::AwaitUnbindResult);
        let response = SessionUnit::from_reduced(&[0x12, 0x34, 0xeb, 0x80, 0, 0x32]).unwrap();
        session.accept(&SessionEvent::Unbind(response)).unwrap();
        assert_eq!(session.phase(), SessionPhase::Closed);
    }
}
