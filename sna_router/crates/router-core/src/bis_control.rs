//! One bounded LU 6.2 BIS exchange on the observed V4R4 management session.
//!
//! IBM SC31-6808, chapter 3, describes bilateral BIS during session shutdown.
//! Each LU sends its own DFC BIS request after its brackets and pending session
//! allocations drain. The two requests are independent; either may arrive
//! first. BIS does not complete CNOS (SC31-6808, Figure 5.4-4).

use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BisError {
    InvalidPiu,
    UnexpectedState,
    BracketBusy,
}

impl fmt::Display for BisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid LU 6.2 BIS exchange: {self:?}")
    }
}

impl Error for BisError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BisAddress {
    pub daf: u8,
    pub oaf: u8,
    pub sequence: u16,
}

/// A local BIS and a remote BIS are independent requests. `complete()` means
/// both have been seen/sent; session deactivation is owned by the caller.
pub struct BisPeer {
    th0: u8,
    local_daf: u8,
    local_oaf: u8,
    local_sequence: u16,
    remote: Option<BisAddress>,
    pending_local: Option<[u8; 10]>,
    local_sent: bool,
}

impl BisPeer {
    /// `local_daf` is the remote session address; `local_oaf` is ours.
    /// TH byte 0 preserves the link's ODAI bit (X'2C' or X'2E').
    pub fn new(
        th0: u8,
        local_daf: u8,
        local_oaf: u8,
        local_sequence: u16,
    ) -> Result<Self, BisError> {
        if !matches!(th0, 0x2c | 0x2e)
            || local_daf == 0
            || local_oaf == 0
            || local_daf == local_oaf
            || local_sequence == 0
        {
            return Err(BisError::InvalidPiu);
        }
        Ok(Self {
            th0,
            local_daf,
            local_oaf,
            local_sequence,
            remote: None,
            pending_local: None,
            local_sent: false,
        })
    }

    pub fn remote(&self) -> Option<BisAddress> {
        self.remote
    }

    pub fn local_sent(&self) -> bool {
        self.local_sent
    }

    pub fn complete(&self) -> bool {
        self.local_sent && self.remote.is_some()
    }

    /// Accept the V4R4 source-side DFC BIS request; it is not an SNA response.
    pub fn observe_remote_bis(&mut self, piu: &[u8]) -> Result<BisAddress, BisError> {
        if self.remote.is_some() {
            return Err(BisError::UnexpectedState);
        }
        if piu.len() != 10
            || piu[0] != self.th0
            || piu[1] != 0
            || piu[2] != self.local_oaf
            || piu[3] != self.local_daf
            || piu[6..] != [0x4b, 0x91, 0, 0x70]
        {
            return Err(BisError::InvalidPiu);
        }
        let sequence = u16::from_be_bytes([piu[4], piu[5]]);
        if sequence == 0 {
            return Err(BisError::InvalidPiu);
        }
        let remote = BisAddress {
            daf: piu[2],
            oaf: piu[3],
            sequence,
        };
        self.remote = Some(remote);
        Ok(remote)
    }

    /// Build our independent BIS request only once local bracket and waiting
    /// allocation work has drained. It may precede the remote BIS.
    pub fn prepare_local_bis(&mut self, bracket_free: bool) -> Result<&[u8], BisError> {
        self.prepare_local_bis_with_pi(bracket_free, true)
    }

    /// The fixed-pacing caller supplies PI for this normal-flow DFC request.
    /// Adaptive V4R4 captures used PI=1; a second request in a seven-frame
    /// fixed local window uses PI=0.
    pub fn prepare_local_bis_with_pi(
        &mut self,
        bracket_free: bool,
        pi: bool,
    ) -> Result<&[u8], BisError> {
        if self.local_sent || self.pending_local.is_some() {
            return Err(BisError::UnexpectedState);
        }
        if !bracket_free {
            return Err(BisError::BracketBusy);
        }
        let [high, low] = self.local_sequence.to_be_bytes();
        self.pending_local = Some([
            self.th0,
            0,
            self.local_daf,
            self.local_oaf,
            high,
            low,
            0x4b,
            if pi { 0xb1 } else { 0xb0 },
            0,
            0x70,
        ]);
        Ok(self.pending_local.as_ref().expect("local BIS just stored"))
    }

    /// A successful egress handoff of these exact bytes is required before
    /// considering our local BIS sent.
    pub fn mark_local_bis_transmitted(&mut self, piu: &[u8]) -> Result<(), BisError> {
        if self.pending_local.as_ref().map(<[u8; 10]>::as_slice) != Some(piu) {
            return Err(BisError::UnexpectedState);
        }
        self.pending_local = None;
        self.local_sent = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized V4R4 management session, /tmp/snusnu-sol4-b.pcap p68/p74.
    const REMOTE: [u8; 10] = [0x2e, 0, 1, 2, 0, 2, 0x4b, 0x91, 0, 0x70];
    const LOCAL: [u8; 10] = [0x2e, 0, 2, 1, 0, 2, 0x4b, 0xb1, 0, 0x70];

    fn peer() -> BisPeer {
        BisPeer::new(0x2e, 2, 1, 2).unwrap()
    }

    #[test]
    fn remote_first_matches_capture_and_requires_local_drain() {
        let mut peer = peer();
        assert_eq!(peer.observe_remote_bis(&REMOTE).unwrap().sequence, 2);
        assert!(!peer.complete());
        assert_eq!(peer.prepare_local_bis(false), Err(BisError::BracketBusy));
        let local = peer.prepare_local_bis(true).unwrap().to_vec();
        assert_eq!(local, LOCAL);
        let mut wrong = local.clone();
        wrong[7] ^= 0x20;
        assert_eq!(
            peer.mark_local_bis_transmitted(&wrong),
            Err(BisError::UnexpectedState)
        );
        assert!(!peer.complete());
        peer.mark_local_bis_transmitted(&local).unwrap();
        assert!(peer.complete());
        assert_eq!(
            peer.observe_remote_bis(&REMOTE),
            Err(BisError::UnexpectedState)
        );
    }

    #[test]
    fn local_first_is_legal_and_odai_is_preserved() {
        let mut peer = peer();
        let local = peer.prepare_local_bis(true).unwrap().to_vec();
        peer.mark_local_bis_transmitted(&local).unwrap();
        assert!(!peer.complete());
        peer.observe_remote_bis(&REMOTE).unwrap();
        assert!(peer.complete());

        let mut no_odai = BisPeer::new(0x2c, 2, 1, 2).unwrap();
        let mut remote = REMOTE;
        remote[0] = 0x2c;
        no_odai.observe_remote_bis(&remote).unwrap();
        assert_eq!(no_odai.prepare_local_bis(true).unwrap()[0], 0x2c);
    }

    #[test]
    fn rejects_wrong_session_and_malformed_bis() {
        assert!(BisPeer::new(0x2c, 2, 1, 0).is_err());
        for offset in [0, 2, 3, 6, 7, 8, 9] {
            let mut invalid = REMOTE;
            invalid[offset] ^= 1;
            assert_eq!(
                peer().observe_remote_bis(&invalid),
                Err(BisError::InvalidPiu)
            );
        }
        let mut zero_sequence = REMOTE;
        zero_sequence[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            peer().observe_remote_bis(&zero_sequence),
            Err(BisError::InvalidPiu)
        );
    }
}
