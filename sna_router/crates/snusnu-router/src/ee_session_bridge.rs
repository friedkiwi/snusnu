//! One bounded session-event bridge between two independently framed EE links.
//!
//! The ingress half behaves like a local HPR egress. The source half feeds
//! `ReverseRuntime` on the destination EE attachment. Neither half carries
//! datagrams or RTP state; each retains a received event until its caller
//! confirms admission to the destination session fabric.

use std::{cell::RefCell, collections::VecDeque, io, rc::Rc};

use router_core::session::SessionEvent;

use crate::hpr_session_source::{SessionSource, SourceUpdate};

const MAX_EVENTS_PER_DIRECTION: usize = 64;
const MAX_BYTES_PER_DIRECTION: usize = 128 * 1024;

#[derive(Default)]
struct Queue {
    events: VecDeque<SessionEvent>,
    bytes: usize,
}

impl Queue {
    fn push(&mut self, event: &SessionEvent) -> bool {
        let len = event_bytes(event);
        if self.events.len() >= MAX_EVENTS_PER_DIRECTION
            || self.bytes.saturating_add(len) > MAX_BYTES_PER_DIRECTION
        {
            return false;
        }
        self.events.push_back(event.clone());
        self.bytes += len;
        true
    }

    fn front(&self) -> Option<SessionEvent> {
        self.events.front().cloned()
    }

    fn pop(&mut self) -> io::Result<()> {
        let event = self
            .events
            .pop_front()
            .ok_or_else(|| invalid("EE bridge has no leased event"))?;
        self.bytes -= event_bytes(&event);
        Ok(())
    }
}

#[derive(Default)]
struct State {
    toward_ee: Queue,
    toward_ingress: Queue,
    ingress_closed: bool,
    source_closed: bool,
    ingress_reset_delivered: bool,
}

pub(crate) struct EeBridgeIngress(Rc<RefCell<State>>);
pub(crate) struct EeBridgeSource(Rc<RefCell<State>>);

/// Build one session pair after the ingress EE adapter has selected a verified
/// destination LU on another EE attachment.
pub(crate) fn pair() -> (EeBridgeIngress, EeBridgeSource) {
    let shared = Rc::new(RefCell::new(State::default()));
    (EeBridgeIngress(shared.clone()), EeBridgeSource(shared))
}

impl EeBridgeIngress {
    /// Queue an event decoded from the ingress EE link for the destination
    /// reverse runtime. False means bounded backpressure; retry the same event.
    pub(crate) fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        let mut state = self.0.borrow_mut();
        if state.ingress_closed || state.source_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "EE bridge closed",
            ));
        }
        Ok(state.toward_ee.push(event))
    }

    pub(crate) fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
        let state = self.0.borrow();
        if let Some(event) = state.toward_ingress.front() {
            return Ok(Some(event));
        }
        if state.source_closed && !state.ingress_reset_delivered {
            return Ok(Some(SessionEvent::Reset));
        }
        Ok(None)
    }

    pub(crate) fn confirm_polled(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        if !state.toward_ingress.events.is_empty() {
            state.toward_ingress.pop()
        } else if state.source_closed && !state.ingress_reset_delivered {
            state.ingress_reset_delivered = true;
            Ok(())
        } else {
            Err(invalid("EE bridge ingress has no leased event"))
        }
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.0.borrow_mut().ingress_closed = true;
        Ok(())
    }
}

impl Drop for EeBridgeIngress {
    fn drop(&mut self) {
        self.0.borrow_mut().ingress_closed = true;
    }
}

impl SessionSource for EeBridgeSource {
    fn poll(&mut self) -> io::Result<Option<SourceUpdate>> {
        let state = self.0.borrow();
        if let Some(event) = state.toward_ee.front() {
            return Ok(Some(SourceUpdate::Event(event)));
        }
        if state.ingress_closed {
            return Ok(Some(SourceUpdate::Closed));
        }
        Ok(None)
    }

    fn complete_received(&mut self, _charge: bool) -> io::Result<()> {
        self.0.borrow_mut().toward_ee.pop()
    }

    fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        let mut state = self.0.borrow_mut();
        if state.ingress_closed || state.source_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "EE bridge closed",
            ));
        }
        Ok(state.toward_ingress.push(event))
    }

    fn close(&mut self) -> io::Result<()> {
        self.0.borrow_mut().source_closed = true;
        Ok(())
    }
}

impl Drop for EeBridgeSource {
    fn drop(&mut self) {
        self.0.borrow_mut().source_closed = true;
    }
}

fn event_bytes(event: &SessionEvent) -> usize {
    match event {
        SessionEvent::BindRequest(unit)
        | SessionEvent::BindResult { unit, .. }
        | SessionEvent::Information { unit, .. }
        | SessionEvent::Unbind(unit) => unit.as_reduced().len(),
        SessionEvent::Credit { .. } => 8,
        SessionEvent::Reset => 1,
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::session::{Flow, SessionUnit};

    fn unit(opcode: u8) -> SessionUnit {
        SessionUnit::from_reduced(&[0, 1, 0x6b, 0x80, 0, opcode]).unwrap()
    }

    #[test]
    fn ee_bridge_preserves_both_directions_and_delivery_leases() {
        let (mut ingress, mut source) = pair();
        let bind = SessionEvent::BindRequest(unit(0x31));
        assert!(ingress.send(&bind).unwrap());
        assert_eq!(
            source.poll().unwrap(),
            Some(SourceUpdate::Event(bind.clone()))
        );
        assert_eq!(source.poll().unwrap(), Some(SourceUpdate::Event(bind)));
        source.complete_received(true).unwrap();
        assert_eq!(source.poll().unwrap(), None);

        let accepted = SessionEvent::BindResult {
            accepted: true,
            unit: unit(0x31),
        };
        assert!(source.send(&accepted).unwrap());
        assert_eq!(ingress.poll().unwrap(), Some(accepted.clone()));
        assert_eq!(ingress.poll().unwrap(), Some(accepted));
        ingress.confirm_polled().unwrap();
        assert_eq!(ingress.poll().unwrap(), None);

        let data = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(0x01),
        };
        assert!(ingress.send(&data).unwrap());
        assert_eq!(source.poll().unwrap(), Some(SourceUpdate::Event(data)));
        source.complete_received(true).unwrap();
        assert_eq!(source.poll().unwrap(), None);
    }

    #[test]
    fn ee_bridge_bounds_traffic_and_withdrawal_resets_only_its_pair() {
        let (mut a_ingress, mut a_source) = pair();
        let (mut b_ingress, mut b_source) = pair();
        let credit = SessionEvent::Credit {
            normal: 1,
            expedited: 0,
        };
        for _ in 0..MAX_EVENTS_PER_DIRECTION {
            assert!(a_ingress.send(&credit).unwrap());
        }
        assert!(!a_ingress.send(&credit).unwrap());
        assert!(b_ingress.send(&credit).unwrap());
        a_source.close().unwrap();
        for _ in 0..MAX_EVENTS_PER_DIRECTION {
            assert_eq!(
                a_source.poll().unwrap(),
                Some(SourceUpdate::Event(credit.clone()))
            );
            a_source.complete_received(false).unwrap();
        }
        assert_eq!(a_ingress.poll().unwrap(), Some(SessionEvent::Reset));
        a_ingress.confirm_polled().unwrap();
        assert_eq!(a_ingress.poll().unwrap(), None);
        assert_eq!(b_source.poll().unwrap(), Some(SourceUpdate::Event(credit)));
    }
}
