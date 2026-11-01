//! Transport-neutral SNA routing between registered ports.

use crate::STOP;
use std::{collections::HashMap, io, sync::atomic::Ordering, thread, time::Duration};

const IDLE_POLL: Duration = Duration::from_micros(200);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PortId(pub(crate) String);

impl PortId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// The SNA content passed between encapsulations. A DLC control frame keeps
/// its original LLC PDU bytes so an LLC egress can reconstruct Ethernet.
pub(crate) enum RoutedUnit {
    DlcType1(Vec<u8>),
    SnaInformation(Vec<u8>),
}

pub(crate) enum RouterEvent {
    Unit(RoutedUnit),
    Ready,
    Closed,
    TimedOut,
}

/// One attachment to the router. Adapters translate their own protocol into
/// router events and accept routed units. `poll` must be nonblocking and
/// apply `can_accept_information` before acknowledging incoming information.
pub(crate) trait RoutePort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>>;
    fn tick(&mut self) -> io::Result<Vec<RouterEvent>>;
    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool>;
    fn has_capacity(&self) -> bool;
    /// The egress port's current information backlog budget. A port that
    /// does not track slots may expose a single yes/no slot.
    fn available_receive_slots(&self) -> usize {
        usize::from(self.has_capacity())
    }
    /// Lets ingress transports advertise new credit when egress drains.
    fn on_downstream_capacity(&mut self, _available_slots: usize) -> io::Result<()> {
        Ok(())
    }
    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()>;
    fn on_peer_ready(&mut self) -> io::Result<()>;
    fn disconnect(&mut self) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

pub(crate) struct Router {
    ports: HashMap<PortId, Box<dyn RoutePort>>,
    order: Vec<PortId>,
    routes: HashMap<PortId, PortId>,
}

impl Router {
    pub(crate) fn new() -> Self {
        Self {
            ports: HashMap::new(),
            order: Vec::new(),
            routes: HashMap::new(),
        }
    }

    pub(crate) fn register_port(&mut self, id: PortId, port: Box<dyn RoutePort>) -> io::Result<()> {
        if self.ports.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "duplicate router port",
            ));
        }
        self.order.push(id.clone());
        self.ports.insert(id, port);
        Ok(())
    }

    pub(crate) fn add_route(&mut self, source: &PortId, target: &PortId) -> io::Result<()> {
        if source == target || !self.ports.contains_key(source) || !self.ports.contains_key(target)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid router route",
            ));
        }
        self.routes.insert(source.clone(), target.clone());
        Ok(())
    }

    pub(crate) fn run(&mut self) -> io::Result<()> {
        while !STOP.load(Ordering::Relaxed) {
            let mut received = false;
            for source in self.order.clone() {
                let target = self.target(&source)?.clone();
                loop {
                    let capacity = self.port(&target)?.has_capacity();
                    let slots = self.port(&target)?.available_receive_slots();
                    let ingress = self.port_mut(&source)?;
                    ingress.on_downstream_capacity(slots)?;
                    ingress.set_ingress_busy(!capacity)?;
                    let Some(events) = ingress.poll(capacity)? else {
                        break;
                    };
                    received = true;
                    self.dispatch(&source, events)?;
                }
            }
            for source in self.order.clone() {
                let events = self.port_mut(&source)?.tick()?;
                self.dispatch(&source, events)?;
            }
            if !received {
                thread::sleep(IDLE_POLL);
            }
        }
        Ok(())
    }

    fn target(&self, source: &PortId) -> io::Result<&PortId> {
        self.routes.get(source).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no route for {}", source.0),
            )
        })
    }

    fn port(&self, id: &PortId) -> io::Result<&dyn RoutePort> {
        self.ports.get(id).map(|port| port.as_ref()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("router port {} is absent", id.0),
            )
        })
    }

    fn port_mut(&mut self, id: &PortId) -> io::Result<&mut (dyn RoutePort + '_)> {
        match self.ports.get_mut(id) {
            Some(port) => Ok(port.as_mut()),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("router port {} is absent", id.0),
            )),
        }
    }

    fn dispatch(&mut self, source: &PortId, events: Vec<RouterEvent>) -> io::Result<()> {
        let target = self.target(source)?.clone();
        for event in events {
            match event {
                RouterEvent::Unit(unit) => {
                    if !self.port_mut(&target)?.send(unit)? {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "route capacity changed during dispatch",
                        ));
                    }
                }
                RouterEvent::Ready => self.port_mut(&target)?.on_peer_ready()?,
                RouterEvent::Closed => {
                    self.port_mut(source)?.disconnect()?;
                    self.port_mut(&target)?.disconnect()?;
                }
                RouterEvent::TimedOut => eprintln!("router port {} timed out", source.0),
            }
        }
        self.port_mut(source)?.flush()?;
        self.port_mut(&target)?.flush()?;
        Ok(())
    }
}
