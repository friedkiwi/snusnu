//! Cross-path duplicate suppression for TCP62 expedited messages.
//!
//! IBM's TCP62 draft section 3.2.2.1.1 assigns consecutive u16 sequence
//! numbers starting at zero. TCP expedited records carry the number
//! implicitly; a UDP X'83' fallback copy carries it explicitly:
//! https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00
//!
//! Callers must validate the X'83' wire format and connection correlator
//! before using this state. This module does not enable UDP fallback or the
//! X'83' required compensation by itself.

use std::{collections::BTreeSet, io};

/// Maximum number of not-yet-seen TCP expedited records that a UDP copy may
/// lead. This is a local memory bound, not a TCP62 wire limit.
pub const MAX_AHEAD: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    New,
    Duplicate,
}

/// One direction of one MPTN connection. Keep separate windows for the two
/// directions; each sender owns its own expedited sequence.
#[derive(Debug, Default)]
pub struct SequenceWindow {
    tcp_count: u64,
    delivered_udp: BTreeSet<u16>,
}

impl SequenceWindow {
    pub fn next_tcp_sequence(&self) -> u16 {
        self.tcp_count as u16
    }

    /// Call once for each TCP X'01' record in stream order. A UDP copy may
    /// have already delivered its data while this TCP record was delayed.
    pub fn receive_tcp(&mut self) -> Delivery {
        let sequence = self.next_tcp_sequence();
        self.tcp_count += 1;
        if self.delivered_udp.remove(&sequence) {
            Delivery::Duplicate
        } else {
            Delivery::New
        }
    }

    /// Call for a correlated UDP X'83' request. A repeated UDP copy, or a
    /// copy whose TCP record was delivered already, must not reach the native
    /// endpoint again. The receive window is deliberately bounded.
    pub fn receive_udp(&mut self, sequence: u16) -> io::Result<Delivery> {
        let ahead = sequence.wrapping_sub(self.next_tcp_sequence());
        if ahead < MAX_AHEAD {
            return Ok(if self.delivered_udp.insert(sequence) {
                Delivery::New
            } else {
                Delivery::Duplicate
            });
        }
        let behind = self.next_tcp_sequence().wrapping_sub(sequence);
        if behind <= MAX_AHEAD && self.tcp_count >= u64::from(behind) {
            return Ok(Delivery::Duplicate);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP62 OOB sequence outside bounded receive window",
        ))
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_first_then_tcp_discards_the_delayed_copy() {
        let mut window = SequenceWindow::default();
        assert_eq!(window.receive_udp(0).unwrap(), Delivery::New);
        assert_eq!(window.receive_udp(0).unwrap(), Delivery::Duplicate);
        assert_eq!(window.receive_tcp(), Delivery::Duplicate);
        assert_eq!(window.receive_tcp(), Delivery::New);
        assert_eq!(window.receive_udp(1).unwrap(), Delivery::Duplicate);
    }

    #[test]
    fn tcp_first_then_udp_discards_fallback_copy() {
        let mut window = SequenceWindow::default();
        assert_eq!(window.receive_tcp(), Delivery::New);
        assert_eq!(window.receive_udp(0).unwrap(), Delivery::Duplicate);
        assert_eq!(
            window.receive_udp(u16::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn udp_ahead_is_bounded_and_tcp_order_drains_it() {
        let mut window = SequenceWindow::default();
        assert_eq!(window.receive_udp(2).unwrap(), Delivery::New);
        assert_eq!(
            window.receive_udp(MAX_AHEAD).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(window.receive_tcp(), Delivery::New);
        assert_eq!(window.receive_tcp(), Delivery::New);
        assert_eq!(window.receive_tcp(), Delivery::Duplicate);
        assert_eq!(window.receive_udp(2).unwrap(), Delivery::Duplicate);
    }

    #[test]
    fn sequence_wraps_after_65535() {
        let mut window = SequenceWindow::default();
        for _ in 0..u16::MAX {
            window.receive_tcp();
        }
        assert_eq!(window.next_tcp_sequence(), u16::MAX);
        assert_eq!(window.receive_udp(0).unwrap(), Delivery::New);
        assert_eq!(window.receive_tcp(), Delivery::New);
        assert_eq!(window.receive_tcp(), Delivery::Duplicate);
        assert_eq!(window.receive_udp(u16::MAX).unwrap(), Delivery::Duplicate);
        window.clear();
        assert_eq!(window.next_tcp_sequence(), 0);
    }
}
