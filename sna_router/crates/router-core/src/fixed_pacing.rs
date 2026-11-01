//! Bounded, one-stage, fixed session-level pacing for a single SNA session.
//!
//! IBM GA27-3136-19, RH chapter, defines the IPR as RH `83 01 00` with no RU.
//! IBM SC31-6808-0 §6.2 says the *first* normal-flow request in each window
//! carries PI; a pacing response may grant the next window before the current
//! window has been exhausted. The caller validates FID2 addresses, flow, and
//! session activation, and applies PI to the RH on normal requests.

/// Canonical isolated pacing response RH. An IPR has no RU.
pub const IPR_RH: [u8; 3] = [0x83, 0x01, 0x00];
/// Pacing indicator in the second RH byte, in both requests and responses.
pub const PACING_INDICATOR: u8 = 0x01;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacingError {
    InvalidWindow,
    SendWindowExhausted,
    ReceiveWindowExceeded,
    MissingPacingRequest,
    UnexpectedPacingRequest,
    NoPacingRequestPending,
    DuplicatePacingResponse,
}

/// Pacing state in both directions of one active, fixed-window SNA session.
///
/// `send_window` is the BIND secondary-send window (7 in the V4R4 profile);
/// `receive_window` is the negotiated secondary-receive window (1 in the
/// conservative local profile). This state does not construct FID2 THs or
/// decide when receive buffers are available for a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedPacing {
    send_window: u8,
    receive_window: u8,
    send_remaining: u8,
    receive_remaining: u8,
    send_first: bool,
    receive_first: bool,
    awaiting_response: bool,
    next_send_granted: bool,
    grant_pending: bool,
    next_receive_granted: bool,
}

impl FixedPacing {
    pub fn new(send_window: u8, receive_window: u8) -> Result<Self, PacingError> {
        if !(1..=63).contains(&send_window) || !(1..=63).contains(&receive_window) {
            return Err(PacingError::InvalidWindow);
        }
        Ok(Self {
            send_window,
            receive_window,
            send_remaining: send_window,
            receive_remaining: receive_window,
            send_first: true,
            receive_first: true,
            awaiting_response: false,
            next_send_granted: false,
            grant_pending: false,
            next_receive_granted: false,
        })
    }

    /// Reserve one outbound normal-flow request. Returns whether its RH must
    /// carry PI. A caller must not transmit after an error.
    pub fn send_request(&mut self) -> Result<bool, PacingError> {
        if self.send_remaining == 0 {
            if !self.next_send_granted {
                return Err(PacingError::SendWindowExhausted);
            }
            self.next_send_granted = false;
            self.send_remaining = self.send_window;
            self.send_first = true;
        }
        let pi = self.send_first;
        self.send_first = false;
        self.send_remaining -= 1;
        if pi {
            self.awaiting_response = true;
        }
        Ok(pi)
    }

    /// Account for a correlated IPR, or PI on a normal-flow response. The
    /// caller must check the FID2 session and RH before calling this method.
    pub fn receive_pacing_response(&mut self) -> Result<(), PacingError> {
        if !self.awaiting_response || self.next_send_granted {
            return Err(PacingError::DuplicatePacingResponse);
        }
        self.awaiting_response = false;
        self.next_send_granted = true;
        Ok(())
    }

    /// Account for an inbound normal-flow request. `pi` is RH byte 1 bit 7
    /// (numeric mask 0x01). The first request of every window must carry PI.
    pub fn receive_request(&mut self, pi: bool) -> Result<(), PacingError> {
        let entering_next = self.receive_remaining == 0;
        if entering_next && !self.next_receive_granted {
            return Err(PacingError::ReceiveWindowExceeded);
        }
        let first = entering_next || self.receive_first;
        if first && !pi {
            return Err(PacingError::MissingPacingRequest);
        }
        if !first && pi {
            return Err(PacingError::UnexpectedPacingRequest);
        }
        if entering_next {
            self.next_receive_granted = false;
            self.receive_remaining = self.receive_window;
        }
        self.receive_first = false;
        self.receive_remaining -= 1;
        if pi {
            self.grant_pending = true;
        }
        Ok(())
    }

    /// Reserve capacity for the next inbound window and authorize one IPR.
    /// The caller emits `IPR_RH` only after this succeeds. It may defer this
    /// call until the application has room; no automatic grant is assumed.
    pub fn grant_receive_window(&mut self) -> Result<(), PacingError> {
        if !self.grant_pending || self.next_receive_granted {
            return Err(PacingError::NoPacingRequestPending);
        }
        self.grant_pending = false;
        self.next_receive_granted = true;
        Ok(())
    }

    pub fn send_remaining(&self) -> u8 {
        self.send_remaining
    }

    pub fn receive_remaining(&self) -> u8 {
        self.receive_remaining
    }

    pub fn grant_pending(&self) -> bool {
        self.grant_pending
    }
}

/// Match the canonical IPR RH and its empty RU. The caller must additionally
/// correlate FID2 session addresses and accept only a normal or expedited flow.
pub fn is_canonical_ipr(rh: &[u8], ru: &[u8]) -> bool {
    rh == IPR_RH && ru.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_can_receive_next_grant_before_current_window_ends() {
        let mut pacing = FixedPacing::new(7, 1).unwrap();
        assert_eq!(pacing.send_request(), Ok(true));
        assert_eq!(pacing.receive_pacing_response(), Ok(()));
        assert_eq!(
            pacing.receive_pacing_response(),
            Err(PacingError::DuplicatePacingResponse)
        );
        for _ in 0..6 {
            assert_eq!(pacing.send_request(), Ok(false));
        }
        assert_eq!(pacing.send_request(), Ok(true));
        for _ in 0..6 {
            assert_eq!(pacing.send_request(), Ok(false));
        }
        assert_eq!(pacing.send_request(), Err(PacingError::SendWindowExhausted));
    }

    #[test]
    fn receiver_requires_pi_and_explicit_capacity_grant() {
        let mut pacing = FixedPacing::new(7, 1).unwrap();
        assert_eq!(
            pacing.receive_request(false),
            Err(PacingError::MissingPacingRequest)
        );
        assert_eq!(pacing.receive_request(true), Ok(()));
        assert!(pacing.grant_pending());
        assert_eq!(
            pacing.receive_request(true),
            Err(PacingError::ReceiveWindowExceeded)
        );
        assert_eq!(pacing.grant_receive_window(), Ok(()));
        assert_eq!(
            pacing.grant_receive_window(),
            Err(PacingError::NoPacingRequestPending)
        );
        assert_eq!(pacing.receive_request(true), Ok(()));
    }

    #[test]
    fn only_first_request_of_multiframe_window_carries_pi() {
        let mut pacing = FixedPacing::new(1, 3).unwrap();
        assert_eq!(pacing.receive_request(true), Ok(()));
        assert_eq!(
            pacing.receive_request(true),
            Err(PacingError::UnexpectedPacingRequest)
        );
        assert_eq!(pacing.receive_request(false), Ok(()));
        assert_eq!(pacing.receive_request(false), Ok(()));
        assert_eq!(
            pacing.receive_request(false),
            Err(PacingError::ReceiveWindowExceeded)
        );
    }

    #[test]
    fn ipr_must_have_no_ru() {
        assert!(is_canonical_ipr(&IPR_RH, &[]));
        assert!(!is_canonical_ipr(&IPR_RH, &[0]));
        assert!(!is_canonical_ipr(&[0x83, 0x01], &[]));
        assert!(FixedPacing::new(0, 1).is_err());
        assert!(FixedPacing::new(1, 64).is_err());
    }
}
