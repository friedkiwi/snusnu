//! LLC adapter and local route configuration.

use crate::{
    endpoint::{Endpoint, Event},
    remote::{Config as RemoteConfig, WsRoutePort},
    routing::{PortId, RoutePort, RoutedUnit, Router, RouterEvent},
};
use router_core::llc2::State;
use std::{
    io,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const CONNECT_BARRIER: Duration = Duration::from_millis(200);

#[derive(Clone, Copy)]
pub(crate) struct LlcPeer<'a> {
    pub(crate) interface: &'a str,
    pub(crate) guest_mac: [u8; 6],
    pub(crate) proxy_mac: [u8; 6],
}

pub(crate) struct LlcPort {
    endpoint: Endpoint,
}

impl LlcPort {
    pub(crate) fn open(peer: LlcPeer<'_>) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?,
        })
    }
}

fn map_event(event: Event) -> RouterEvent {
    match event {
        Event::Type1(pdu) => RouterEvent::Unit(RoutedUnit::DlcType1(pdu)),
        Event::Information(data) => RouterEvent::Unit(RoutedUnit::SnaInformation(data)),
        Event::Connected => RouterEvent::Ready,
        Event::Disconnected => RouterEvent::Closed,
        Event::TimedOut => RouterEvent::TimedOut,
    }
}

impl RoutePort for LlcPort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        self.endpoint
            .poll(can_accept_information)
            .map(|events| events.map(|events| events.into_iter().map(map_event).collect()))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.endpoint
            .tick()
            .map(|events| events.into_iter().map(map_event).collect())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        match unit {
            RoutedUnit::DlcType1(pdu) => {
                self.endpoint.send_type1(&pdu)?;
                Ok(true)
            }
            RoutedUnit::SnaInformation(data) => self.endpoint.queue_information(data),
        }
    }

    fn has_capacity(&self) -> bool {
        self.endpoint.has_capacity()
    }

    fn available_receive_slots(&self) -> usize {
        self.endpoint.available_receive_slots()
    }

    fn take_completed_information_count(&mut self) -> usize {
        self.endpoint.take_completed_information_count()
    }

    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.endpoint.set_local_busy(busy)
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        if self.endpoint.state() == State::Disconnected {
            self.endpoint.begin_connect_after(CONNECT_BARRIER);
        }
        Ok(())
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.endpoint.disconnect()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.endpoint.flush()
    }
}

pub(crate) fn run(a: LlcPeer<'_>, b: LlcPeer<'_>) -> io::Result<()> {
    eprintln!(
        "local link: {} <-> {}; SNA SAP 04",
        a.interface, b.interface
    );
    let mut router = Router::new();
    let a_id = PortId::new("local-a");
    let b_id = PortId::new("local-b");
    router.register_port(a_id.clone(), Box::new(LlcPort::open(a)?))?;
    router.register_port(b_id.clone(), Box::new(LlcPort::open(b)?))?;
    router.add_route(&a_id, &b_id)?;
    router.add_route(&b_id, &a_id)?;
    router.run()
}

pub(crate) fn run_remote(local: LlcPeer<'_>, config: RemoteConfig) -> io::Result<()> {
    const FIRST_RETRY: Duration = Duration::from_millis(500);
    const MAX_RETRY: Duration = Duration::from_secs(30);
    let mut delay = FIRST_RETRY;
    while !crate::STOP.load(Ordering::Relaxed) {
        let remote = match WsRoutePort::connect(config.clone()) {
            Ok(port) => port,
            Err(error) if retryable_remote_error(&error) => {
                eprintln!("concentrator connection failed: {error}; retrying in {delay:?}");
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(MAX_RETRY);
                continue;
            }
            Err(error) => return Err(error),
        };
        let connected_at = Instant::now();
        let local_id = PortId::new("local-llc");
        let remote_id = PortId::new("concentrator");
        let mut router = Router::new();
        router.register_port(local_id.clone(), Box::new(LlcPort::open(local)?))?;
        router.register_port(remote_id.clone(), Box::new(remote))?;
        router.add_route(&local_id, &remote_id)?;
        router.add_route(&remote_id, &local_id)?;
        match router.run() {
            Ok(()) => return Ok(()),
            Err(error) => {
                // The old server epoch and circuit cannot be reused. Notify
                // the OS/400 LLC peer before constructing a fresh router.
                router.disconnect_port(&local_id)?;
                if !retryable_remote_error(&error) {
                    return Err(error);
                }
                if connected_at.elapsed() >= MAX_RETRY {
                    delay = FIRST_RETRY;
                }
                eprintln!("concentrator link lost: {error}; reconnecting in {delay:?}");
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(MAX_RETRY);
            }
        }
    }
    Ok(())
}

fn retryable_remote_error(error: &io::Error) -> bool {
    use transport_ws::Error as WsError;
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<WsError>())
        .is_some_and(WsError::is_retryable)
}

fn wait_or_stop(delay: Duration) {
    let mut remaining = delay;
    while !remaining.is_zero() && !crate::STOP.load(Ordering::Relaxed) {
        let step = remaining.min(Duration::from_millis(100));
        thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn rejects_permanent_router_protocol_errors() {
        let invalid = io::Error::other(transport_ws::Error::InvalidBearer);
        assert!(!retryable_remote_error(&invalid));
        let closed = io::Error::other(transport_ws::Error::Protocol("server closed connection"));
        assert!(retryable_remote_error(&closed));
        assert!(!retryable_remote_error(&io::Error::other(
            "local TAP failed"
        )));
    }
}
