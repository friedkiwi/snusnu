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
    /// Number of previously accepted information units fully delivered by
    /// this port since the last call. LLC ports count peer acknowledgements.
    fn take_completed_information_count(&mut self) -> usize {
        0
    }
    fn on_downstream_completed(&mut self, _count: usize) -> io::Result<()> {
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
                self.release_completed(&source, &target)?;
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

    /// End a local association before a failed transport is discarded. This
    /// gives an LLC peer a DISC instead of leaving it linked to a dead route.
    pub(crate) fn disconnect_port(&mut self, id: &PortId) -> io::Result<()> {
        self.port_mut(id)?.disconnect()
    }

    fn target(&self, source: &PortId) -> io::Result<&PortId> {
        self.routes.get(source).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no route for {}", source.0),
            )
        })
    }

    fn release_completed(&mut self, source: &PortId, target: &PortId) -> io::Result<()> {
        let completed = self.port_mut(target)?.take_completed_information_count();
        if completed != 0 {
            self.port_mut(source)?.on_downstream_completed(completed)?;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct State {
        completions: usize,
        credited: usize,
        free_slots: usize,
    }

    struct FakePort(Rc<RefCell<State>>);

    impl RoutePort for FakePort {
        fn poll(&mut self, _: bool) -> io::Result<Option<Vec<RouterEvent>>> {
            Ok(None)
        }
        fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
            Ok(Vec::new())
        }
        fn send(&mut self, _: RoutedUnit) -> io::Result<bool> {
            Ok(true)
        }
        fn has_capacity(&self) -> bool {
            self.0.borrow().free_slots > 0
        }
        fn available_receive_slots(&self) -> usize {
            self.0.borrow().free_slots
        }
        fn take_completed_information_count(&mut self) -> usize {
            std::mem::take(&mut self.0.borrow_mut().completions)
        }
        fn on_downstream_completed(&mut self, count: usize) -> io::Result<()> {
            self.0.borrow_mut().credited += count;
            Ok(())
        }
        fn set_ingress_busy(&mut self, _: bool) -> io::Result<()> {
            Ok(())
        }
        fn on_peer_ready(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn disconnect(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn completion_releases_credit_even_when_queue_occupancy_is_unchanged() {
        let ingress_state = Rc::new(RefCell::new(State::default()));
        // An ACK freed one sent frame while a queued frame immediately took
        // the same slot. The number of free slots did not change.
        let egress_state = Rc::new(RefCell::new(State {
            completions: 1,
            free_slots: 0,
            ..State::default()
        }));
        let ingress = PortId::new("ingress");
        let egress = PortId::new("egress");
        let mut router = Router::new();
        router
            .register_port(ingress.clone(), Box::new(FakePort(ingress_state.clone())))
            .unwrap();
        router
            .register_port(egress.clone(), Box::new(FakePort(egress_state.clone())))
            .unwrap();
        router.add_route(&ingress, &egress).unwrap();

        router.release_completed(&ingress, &egress).unwrap();
        assert_eq!(ingress_state.borrow().credited, 1);
        assert_eq!(egress_state.borrow().free_slots, 0);
        router.release_completed(&ingress, &egress).unwrap();
        assert_eq!(ingress_state.borrow().credited, 1);
    }
}
