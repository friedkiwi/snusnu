//! LLC adapter and local route configuration.

use crate::{
    endpoint::{Endpoint, Event},
    routing::{PortId, RoutePort, RoutedUnit, Router, RouterEvent},
};
use router_core::llc2::State;
use std::{io, time::Duration};

const CONNECT_BARRIER: Duration = Duration::from_millis(200);

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
