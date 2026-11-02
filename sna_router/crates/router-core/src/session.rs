//! Carrier-neutral SNA session boundary.
//!
//! A link adapter must remove LLC, MPTN, or HPR framing before emitting these
//! events. It must not feed an unparsed transport record into `Information`.
//! Carrier-specific negotiation, FID2 addresses, and pacing translation stay
//! with the adapter; this contract only fixes the ordering and bounded data
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
        && matches!(value.as_bytes()[0], b'A'..=b'Z' | b'@' | b'#' | b'$')
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    /// SNA BIND RU after the ingress adapter has removed carrier framing.
    BindRequest(Vec<u8>),
    /// Positive or negative BIND response, with its SNA response RU.
    BindResult {
        accepted: bool,
        ru: Vec<u8>,
    },
    /// One complete normalized SNA PIU, never a raw TCP62 or HPR record.
    Information {
        flow: Flow,
        piu: Vec<u8>,
    },
    /// Capacity admitted by the destination side, not a carrier window byte.
    Credit {
        normal: u32,
        expedited: u32,
    },
    Unbind(Vec<u8>),
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    AwaitBind,
    AwaitBindResult,
    Open,
    Closed,
}

#[derive(Clone, Debug)]
pub struct SessionContract {
    pub identity: SessionIdentity,
    phase: SessionPhase,
}

impl SessionContract {
    pub fn new(identity: SessionIdentity) -> Self {
        Self {
            identity,
            phase: SessionPhase::AwaitBind,
        }
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// Validate an event before forwarding it. A failed transition leaves the
    /// session unchanged, so a malformed carrier record cannot advance it.
    pub fn accept(&mut self, event: &SessionEvent) -> Result<(), SessionError> {
        let next = match (self.phase, event) {
            (SessionPhase::AwaitBind, SessionEvent::BindRequest(ru)) => {
                check_unit(ru)?;
                SessionPhase::AwaitBindResult
            }
            (SessionPhase::AwaitBindResult, SessionEvent::BindResult { accepted, ru }) => {
                check_optional_unit(ru)?;
                if *accepted {
                    SessionPhase::Open
                } else {
                    SessionPhase::Closed
                }
            }
            (SessionPhase::Open, SessionEvent::Information { piu, .. }) => {
                check_unit(piu)?;
                SessionPhase::Open
            }
            (SessionPhase::Open, SessionEvent::Credit { normal, expedited }) => {
                if *normal > MAX_WINDOW_GRANT || *expedited > MAX_WINDOW_GRANT {
                    return Err(SessionError::InvalidCredit);
                }
                SessionPhase::Open
            }
            (SessionPhase::Open, SessionEvent::Unbind(ru)) => {
                check_unit(ru)?;
                SessionPhase::Closed
            }
            (
                SessionPhase::AwaitBind | SessionPhase::AwaitBindResult | SessionPhase::Open,
                SessionEvent::Reset,
            ) => SessionPhase::Closed,
            _ => return Err(SessionError::InvalidTransition),
        };
        self.phase = next;
        Ok(())
    }
}

fn check_unit(unit: &[u8]) -> Result<(), SessionError> {
    if unit.is_empty() || unit.len() > MAX_SESSION_UNIT {
        return Err(SessionError::InvalidUnit);
    }
    Ok(())
}

fn check_optional_unit(unit: &[u8]) -> Result<(), SessionError> {
    if unit.len() > MAX_SESSION_UNIT {
        return Err(SessionError::InvalidUnit);
    }
    Ok(())
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

    #[test]
    fn names_and_hosts_are_bounded_and_network_qualified() {
        assert_eq!(
            "NETA.LUA".parse::<QualifiedName>().unwrap().to_string(),
            "NETA.LUA"
        );
        for invalid in [
            "NETA",
            "NETA.",
            "NETA.LUA.EXTRA",
            "neta.LUA",
            "NETA.1LU",
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
    fn bind_data_credit_and_close_have_explicit_order_and_bounds() {
        let mut session = SessionContract::new(identity());
        assert_eq!(session.phase(), SessionPhase::AwaitBind);
        assert_eq!(
            session.accept(&SessionEvent::Information {
                flow: Flow::Normal,
                piu: vec![1]
            }),
            Err(SessionError::InvalidTransition)
        );
        session
            .accept(&SessionEvent::BindRequest(vec![0x31]))
            .unwrap();
        assert_eq!(
            session.accept(&SessionEvent::BindRequest(vec![0x31])),
            Err(SessionError::InvalidTransition)
        );
        session
            .accept(&SessionEvent::BindResult {
                accepted: true,
                ru: vec![],
            })
            .unwrap();
        assert_eq!(
            session.accept(&SessionEvent::Information {
                flow: Flow::Expedited,
                piu: vec![]
            }),
            Err(SessionError::InvalidUnit)
        );
        assert_eq!(session.phase(), SessionPhase::Open);
        session
            .accept(&SessionEvent::Information {
                flow: Flow::Expedited,
                piu: vec![1, 2],
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
        session.accept(&SessionEvent::Unbind(vec![0x01])).unwrap();
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
            .accept(&SessionEvent::BindRequest(vec![0x31]))
            .unwrap();
        rejected
            .accept(&SessionEvent::BindResult {
                accepted: false,
                ru: vec![0x08],
            })
            .unwrap();
        assert_eq!(rejected.phase(), SessionPhase::Closed);
        let mut reset = SessionContract::new(identity());
        reset.accept(&SessionEvent::Reset).unwrap();
        assert_eq!(reset.phase(), SessionPhase::Closed);
    }
}
