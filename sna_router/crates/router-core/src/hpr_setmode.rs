//! Link activation control for one HPR LAN ↔ EE adjacency. IBM *SNA Formats*
//! GA27-3136-19, chapter 2 pp. 2-7 and 2-10, defines the LDLC function NLP;
//! RFC 2353 §2.5 treats LLC2 SABME and LDLC XID_DONE_RQ as alternative
//! SETMODE commands. This state machine does not negotiate XID3 or TGs.

/// Default LDLC function routing address X'0001', with the observed V5R4
/// function routing envelope. Only the exact default address is accepted.
const XID_DONE_PREFIX: [u8; 6] = [0xa0, 0x10, 0x00, 0x01, 0xff, 0x00];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XidDone {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetModeError {
    InvalidXidDone,
    NotReady,
    UnexpectedEvent,
}

impl XidDone {
    pub fn parse(nlp: &[u8]) -> Result<Self, SetModeError> {
        if nlp.len() != 7 || nlp[..6] != XID_DONE_PREFIX {
            return Err(SetModeError::InvalidXidDone);
        }
        match nlp[6] {
            0x03 => Ok(Self::Request),
            0x04 => Ok(Self::Response),
            _ => Err(SetModeError::InvalidXidDone),
        }
    }

    pub fn encode(self) -> [u8; 7] {
        let mut nlp = [0; 7];
        nlp[..6].copy_from_slice(&XID_DONE_PREFIX);
        nlp[6] = match self {
            Self::Request => 0x03,
            Self::Response => 0x04,
        };
        nlp
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Negotiating,
    Ready,
    WaitingForEeResponse,
    WaitingForLanUa,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    SendEeRequest,
    SendEeResponse,
    SendLanSabme,
    SendLanUa { final_bit: bool },
    Activated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetModeBridge {
    phase: Phase,
    lan_poll: bool,
}

impl Default for SetModeBridge {
    fn default() -> Self {
        Self {
            phase: Phase::Negotiating,
            lan_poll: false,
        }
    }
}

impl SetModeBridge {
    pub fn phase(self) -> Phase {
        self.phase
    }

    /// Call only after both XID3 legs have completed role, TG and SAP
    /// negotiation. Repeated prenegotiation XIDs must not arm this state.
    pub fn arm(&mut self) -> Result<(), SetModeError> {
        if self.phase != Phase::Negotiating {
            return Err(SetModeError::UnexpectedEvent);
        }
        self.phase = Phase::Ready;
        Ok(())
    }

    pub fn on_lan_sabme(&mut self, poll: bool) -> Result<Vec<Action>, SetModeError> {
        match self.phase {
            Phase::Ready | Phase::WaitingForEeResponse => {
                self.lan_poll = poll;
                self.phase = Phase::WaitingForEeResponse;
                Ok(vec![Action::SendEeRequest])
            }
            Phase::Negotiating => Err(SetModeError::NotReady),
            _ => Err(SetModeError::UnexpectedEvent),
        }
    }

    pub fn on_ee_request(&mut self) -> Result<Vec<Action>, SetModeError> {
        match self.phase {
            Phase::Ready | Phase::WaitingForLanUa => {
                self.phase = Phase::WaitingForLanUa;
                Ok(vec![Action::SendLanSabme])
            }
            Phase::Negotiating => Err(SetModeError::NotReady),
            _ => Err(SetModeError::UnexpectedEvent),
        }
    }

    pub fn on_ee_response(&mut self) -> Result<Vec<Action>, SetModeError> {
        if self.phase != Phase::WaitingForEeResponse {
            return Err(SetModeError::UnexpectedEvent);
        }
        self.phase = Phase::Active;
        Ok(vec![
            Action::SendLanUa {
                final_bit: self.lan_poll,
            },
            Action::Activated,
        ])
    }

    pub fn on_lan_ua(&mut self) -> Result<Vec<Action>, SetModeError> {
        if self.phase != Phase::WaitingForLanUa {
            return Err(SetModeError::UnexpectedEvent);
        }
        self.phase = Phase::Active;
        Ok(vec![Action::SendEeResponse, Action::Activated])
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_observed_v5r4_ee_setmode_and_rejects_other_function_routes() {
        assert_eq!(
            XidDone::parse(&[0xa0, 0x10, 0, 1, 0xff, 0, 3]),
            Ok(XidDone::Request)
        );
        assert_eq!(
            XidDone::parse(&[0xa0, 0x10, 0, 1, 0xff, 0, 4]),
            Ok(XidDone::Response)
        );
        assert_eq!(XidDone::Request.encode(), [0xa0, 0x10, 0, 1, 0xff, 0, 3]);
        assert_eq!(
            XidDone::parse(&[0xa0, 0x10, 0, 1, 0xff, 0]),
            Err(SetModeError::InvalidXidDone)
        );
        assert_eq!(
            XidDone::parse(&[0xa0, 0x10, 0, 2, 0xff, 0, 3]),
            Err(SetModeError::InvalidXidDone)
        );
    }

    #[test]
    fn lan_primary_waits_for_ee_agreement_before_ua() {
        let mut bridge = SetModeBridge::default();
        assert_eq!(bridge.on_lan_sabme(true), Err(SetModeError::NotReady));
        bridge.arm().unwrap();
        assert_eq!(bridge.on_lan_sabme(true), Ok(vec![Action::SendEeRequest]));
        assert_eq!(bridge.phase(), Phase::WaitingForEeResponse);
        assert_eq!(
            bridge.on_ee_response(),
            Ok(vec![
                Action::SendLanUa { final_bit: true },
                Action::Activated
            ])
        );
        assert_eq!(bridge.phase(), Phase::Active);
        bridge.reset();
        assert_eq!(bridge.phase(), Phase::Negotiating);
    }

    #[test]
    fn ee_primary_waits_for_lan_ua_before_response() {
        let mut bridge = SetModeBridge::default();
        bridge.arm().unwrap();
        assert_eq!(bridge.on_ee_request(), Ok(vec![Action::SendLanSabme]));
        assert_eq!(bridge.on_ee_request(), Ok(vec![Action::SendLanSabme]));
        assert_eq!(
            bridge.on_lan_ua(),
            Ok(vec![Action::SendEeResponse, Action::Activated])
        );
        assert_eq!(
            bridge.on_lan_sabme(true),
            Err(SetModeError::UnexpectedEvent)
        );
    }
}
