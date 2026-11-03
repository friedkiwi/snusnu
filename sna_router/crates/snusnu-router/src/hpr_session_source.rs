//! Carrier-neutral source of one session headed toward an EE peer.
//!
//! The source retains a received event until `complete_received` confirms
//! admission to the shared session fabric. This is necessary for both
//! WebSocket byte credit and native LLC receive-window backpressure.

use std::io;

use router_core::session::SessionEvent;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SourceUpdate {
    Event(SessionEvent),
    Closed,
}

pub(crate) trait SessionSource {
    /// Repeated polls return the same event until `complete_received`.
    fn poll(&mut self) -> io::Result<Option<SourceUpdate>>;

    /// Confirm one event after the fabric accepted it. `charge` is false for
    /// neutral Credit events, which consume no WebSocket payload byte credit.
    fn complete_received(&mut self, charge: bool) -> io::Result<()>;

    /// Queue one fabric event for this carrier. False means backpressure and
    /// leaves the caller's delivery lease intact for a later retry.
    fn send(&mut self, event: &SessionEvent) -> io::Result<bool>;

    fn close(&mut self) -> io::Result<()>;
}
