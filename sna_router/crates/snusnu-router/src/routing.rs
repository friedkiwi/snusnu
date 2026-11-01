//! Transport-neutral SNA routing between registered ports.

use crate::STOP;
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const IDLE_POLL: Duration = Duration::from_micros(200);
const FIRST_RETRY: Duration = Duration::from_millis(500);
const MAX_RETRY: Duration = Duration::from_secs(30);
const QUARANTINED_POLL: Duration = Duration::from_millis(10);
const MAX_POLL_BATCHES: usize = 64;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PortId(pub(crate) String);

impl PortId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// Address used to select a peer association. A route port still represents
/// one LLC association or one remote circuit so its credit remains isolated.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RouteAddress {
    Mac([u8; 6]),
    ControlPoint {
        netid: String,
        name: String,
    },
    LogicalUnit {
        netid: String,
        cp: Option<String>,
        name: String,
    },
}

impl fmt::Display for RouteAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mac(mac) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            Self::ControlPoint { netid, name } => write!(f, "{netid}.{name}"),
            Self::LogicalUnit { netid, cp, name } => match cp {
                Some(cp) => write!(f, "{netid}.{cp}.{name}"),
                None => write!(f, "{netid}.{name}"),
            },
        }
    }
}

/// The SNA content passed between encapsulations. A DLC control frame keeps
/// its original LLC PDU bytes so an LLC egress can reconstruct Ethernet.
pub(crate) enum RoutedUnit {
    DlcType1(Vec<u8>),
    SnaInformation(Vec<u8>),
    AnyNetTcpRecord(Vec<u8>),
    AnyNetUdpDatagram(Vec<u8>),
    EeDatagram { priority: u8, payload: Vec<u8> },
}

pub(crate) enum RouterEvent {
    Unit(RoutedUnit),
    /// The concentrator-assigned virtual MAC for this destination CP.
    ManagedMac([u8; 6]),
    Ready,
    Closed,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureScope {
    /// Reset and retry only the connected route component.
    Route,
    /// A shared transport is gone; the runtime must reconstruct its ports.
    /// The current runtime rebuilds all ports, including unrelated local pairs.
    SharedTransport,
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
    fn on_managed_mac(&mut self, _mac: [u8; 6]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "route port does not accept a managed MAC",
        ))
    }
    fn failure_scope(&self, _error: &io::Error) -> FailureScope {
        FailureScope::Route
    }
    fn disconnect(&mut self) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

pub(crate) struct Router {
    ports: HashMap<PortId, Box<dyn RoutePort>>,
    order: Vec<PortId>,
    routes: HashMap<PortId, PortId>,
    address_routes: HashMap<(PortId, RouteAddress), PortId>,
    destinations: HashMap<PortId, RouteAddress>,
    failures: HashMap<PortId, RouteFailure>,
}

#[derive(Clone, Copy)]
struct RouteFailure {
    failures: u32,
    retry_at: Instant,
}

impl Router {
    pub(crate) fn new() -> Self {
        Self {
            ports: HashMap::new(),
            order: Vec::new(),
            routes: HashMap::new(),
            address_routes: HashMap::new(),
            destinations: HashMap::new(),
            failures: HashMap::new(),
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
        tracing::info!(port = %id.0, "router port registered");
        self.ports.insert(id, port);
        Ok(())
    }

    pub(crate) fn add_route(&mut self, source: &PortId, target: &PortId) -> io::Result<()> {
        self.check_route_ports(source, target)?;
        if self.address_routes.keys().any(|(port, _)| port == source) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already uses addressed routes", source.0),
            ));
        }
        Self::insert_route(&mut self.routes, source.clone(), target.clone())?;
        tracing::info!(source_port = %source.0, target_port = %target.0, "route installed");
        Ok(())
    }

    /// Install a route for one destination seen by this source association.
    /// An address cannot silently switch to another port if configuration is
    /// applied twice; the caller must explicitly rebuild the route table.
    pub(crate) fn add_address_route(
        &mut self,
        source: &PortId,
        address: RouteAddress,
        target: &PortId,
    ) -> io::Result<()> {
        self.check_route_ports(source, target)?;
        if self.routes.contains_key(source) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already uses a default route", source.0),
            ));
        }
        Self::insert_route(
            &mut self.address_routes,
            (source.clone(), address.clone()),
            target.clone(),
        )?;
        tracing::info!(source_port = %source.0, destination = %address, target_port = %target.0, "address route installed");
        Ok(())
    }

    /// Select the addressed route for a source association. A missing exact
    /// route is an error even when a legacy default route is also configured.
    /// A source cannot switch destinations in place: an earlier target may
    /// still own queued information and LLC acknowledgements for that source.
    pub(crate) fn bind_destination(
        &mut self,
        source: &PortId,
        address: RouteAddress,
    ) -> io::Result<()> {
        if !self
            .address_routes
            .contains_key(&(source.clone(), address.clone()))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no route from {} to {address}", source.0),
            ));
        }
        if let Some(current) = self.destinations.get(source) {
            if current != &address {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("destination for {} is already bound to {current}", source.0),
                ));
            }
            return Ok(());
        }
        tracing::info!(source_port = %source.0, destination = %address, "route destination bound");
        self.destinations.insert(source.clone(), address);
        Ok(())
    }

    fn check_route_ports(&self, source: &PortId, target: &PortId) -> io::Result<()> {
        if source == target || !self.ports.contains_key(source) || !self.ports.contains_key(target)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid router route",
            ));
        }
        Ok(())
    }

    fn insert_route<K: Eq + std::hash::Hash>(
        routes: &mut HashMap<K, PortId>,
        key: K,
        target: PortId,
    ) -> io::Result<()> {
        if routes.get(&key).is_some_and(|existing| existing != &target) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "route selector already targets another port",
            ));
        }
        routes.insert(key, target);
        Ok(())
    }

    pub(crate) fn run(&mut self) -> io::Result<()> {
        self.validate_routes()?;
        while !STOP.load(Ordering::Relaxed) {
            if !self.poll_once()? {
                thread::sleep(self.idle_delay());
            }
        }
        Ok(())
    }

    fn poll_once(&mut self) -> io::Result<bool> {
        let mut received = false;
        let mut polled = HashSet::new();
        for source in self.order.clone() {
            if self.is_quarantined(&source) {
                continue;
            }
            match self.poll_source(&source) {
                Ok(got_data) => {
                    received |= got_data;
                    polled.insert(source);
                }
                Err(error) => self.handle_route_error(&source, error)?,
            }
        }
        for source in self.order.clone() {
            if self.is_quarantined(&source) {
                continue;
            }
            match self.tick_source(&source) {
                Ok(()) => {
                    if polled.contains(&source) {
                        self.failures.remove(&source);
                    }
                }
                Err(error) => self.handle_route_error(&source, error)?,
            }
        }
        Ok(received)
    }

    fn poll_source(&mut self, source: &PortId) -> io::Result<bool> {
        let target = self.target(source)?.clone();
        self.release_completed(source, &target)?;
        let mut received = false;
        for _ in 0..MAX_POLL_BATCHES {
            let capacity = self.port(&target)?.has_capacity();
            let slots = self.port(&target)?.available_receive_slots();
            let ingress = self.port_mut(source)?;
            ingress.on_downstream_capacity(slots)?;
            ingress.set_ingress_busy(!capacity)?;
            let Some(events) = ingress.poll(capacity)? else {
                break;
            };
            received = true;
            self.dispatch(source, events)?;
        }
        Ok(received)
    }

    fn tick_source(&mut self, source: &PortId) -> io::Result<()> {
        let events = self.port_mut(source)?.tick()?;
        self.dispatch(source, events)
    }

    fn is_quarantined(&self, source: &PortId) -> bool {
        self.failures
            .get(source)
            .is_some_and(|state| state.retry_at > Instant::now())
    }

    fn idle_delay(&self) -> Duration {
        if self.order.iter().all(|source| self.is_quarantined(source)) {
            let now = Instant::now();
            self.failures
                .values()
                .filter_map(|state| state.retry_at.checked_duration_since(now))
                .min()
                .unwrap_or(IDLE_POLL)
                .min(QUARANTINED_POLL)
        } else {
            IDLE_POLL
        }
    }

    fn route_component(&self, source: &PortId) -> io::Result<Vec<PortId>> {
        let mut component = Vec::new();
        let mut seen = HashSet::new();
        let mut current = source.clone();
        while seen.insert(current.clone()) {
            component.push(current.clone());
            current = self.target(&current)?.clone();
        }
        Ok(component)
    }

    fn handle_route_error(&mut self, source: &PortId, error: io::Error) -> io::Result<()> {
        let component = self.route_component(source)?;
        if component.iter().any(|id| {
            self.port(id)
                .is_ok_and(|port| port.failure_scope(&error) == FailureScope::SharedTransport)
        }) {
            return Err(error);
        }
        let failures = component
            .iter()
            .filter_map(|id| self.failures.get(id).map(|state| state.failures))
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let delay = FIRST_RETRY
            .saturating_mul(1u32 << failures.saturating_sub(1).min(6))
            .min(MAX_RETRY);
        let retry_at = Instant::now() + delay;
        tracing::warn!(source_port = %source.0, component = ?component.iter().map(|id| id.0.as_str()).collect::<Vec<_>>(), error = %error, retry_ms = delay.as_millis(), "route component quarantined");
        for id in component {
            self.failures
                .insert(id.clone(), RouteFailure { failures, retry_at });
            if let Err(disconnect_error) = self.port_mut(&id)?.disconnect() {
                if self.port(&id)?.failure_scope(&disconnect_error) == FailureScope::SharedTransport
                {
                    return Err(disconnect_error);
                }
                tracing::warn!(port = %id.0, error = %disconnect_error, "route port disconnect failed during quarantine");
            }
        }
        Ok(())
    }

    /// End a local association before a failed transport is discarded. This
    /// gives an LLC peer a DISC instead of leaving it linked to a dead route.
    pub(crate) fn disconnect_port(&mut self, id: &PortId) -> io::Result<()> {
        tracing::info!(port = %id.0, "router port disconnecting");
        self.port_mut(id)?.disconnect()
    }

    fn target(&self, source: &PortId) -> io::Result<&PortId> {
        let target = if let Some(address) = self.destinations.get(source) {
            self.address_routes.get(&(source.clone(), address.clone()))
        } else {
            self.routes.get(source)
        };
        target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no route for {}", source.0),
            )
        })
    }

    /// Completion counts and credit belong to one source/target association.
    /// Reject fan-in until the egress adapter exposes separate circuit ports.
    fn validate_routes(&self) -> io::Result<()> {
        let mut upstreams = HashMap::<&PortId, &PortId>::new();
        for source in &self.order {
            let target = self.target(source)?;
            if let Some(previous) = upstreams.insert(target, source) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "ports {} and {} share egress {}; use one port per circuit",
                        previous.0, source.0, target.0
                    ),
                ));
            }
        }
        Ok(())
    }

    /// A managed MAC changes the LLC endpoint's destination address and its
    /// source association selector. Validate the route table before touching
    /// the endpoint so a rejected update cannot leave the two out of sync.
    fn prepare_managed_mac_rebind(
        &self,
        peer: &PortId,
        mac: [u8; 6],
    ) -> io::Result<Option<(RouteAddress, PortId)>> {
        // Keep the namespace check at the routing boundary as well as in the
        // WebSocket decoder and LLC endpoint. Other RoutePort adapters can
        // accept managed-MAC events without passing through either check.
        if mac[..3] != [0x02, 0x53, 0x4e] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed MAC is outside the SNUSNU namespace",
            ));
        }
        let Some(old @ RouteAddress::Mac(_)) = self.destinations.get(peer) else {
            return Ok(None);
        };
        let new = RouteAddress::Mac(mac);
        if old == &new {
            return Ok(None);
        }
        if self
            .destinations
            .iter()
            .any(|(other, address)| other != peer && address == &new)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("managed MAC {new} is already bound to another port"),
            ));
        }
        let route_target = self
            .address_routes
            .get(&(peer.clone(), old.clone()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "bound MAC route is absent"))?
            .clone();
        if self
            .address_routes
            .get(&(peer.clone(), new.clone()))
            .is_some_and(|target| target != &route_target)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("managed MAC {new} already selects another route"),
            ));
        }
        Ok(Some((old.clone(), route_target)))
    }

    fn finish_managed_mac_rebind(
        &mut self,
        peer: &PortId,
        mac: [u8; 6],
        old: RouteAddress,
        route_target: PortId,
    ) {
        let new = RouteAddress::Mac(mac);
        self.address_routes.remove(&(peer.clone(), old.clone()));
        self.address_routes
            .insert((peer.clone(), new.clone()), route_target);
        self.destinations.insert(peer.clone(), new.clone());
        tracing::info!(port = %peer.0, old_mac = %old, managed_mac = %new, "managed MAC route rebound");
    }

    fn release_completed(&mut self, source: &PortId, target: &PortId) -> io::Result<()> {
        let completed = self.port_mut(target)?.take_completed_information_count();
        if completed != 0 {
            tracing::trace!(source_port = %source.0, target_port = %target.0, completed, "downstream delivery completed");
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
                    let (kind, bytes) = match &unit {
                        RoutedUnit::DlcType1(data) => ("dlc_type1", data.len()),
                        RoutedUnit::SnaInformation(data) => ("sna_information", data.len()),
                        RoutedUnit::AnyNetTcpRecord(data) => ("anynet_tcp_record", data.len()),
                        RoutedUnit::AnyNetUdpDatagram(data) => ("anynet_udp_datagram", data.len()),
                        RoutedUnit::EeDatagram { payload, .. } => ("ee_datagram", payload.len()),
                    };
                    tracing::trace!(source_port = %source.0, target_port = %target.0, kind, bytes, "unit routed");
                    if !self.port_mut(&target)?.send(unit)? {
                        tracing::warn!(source_port = %source.0, target_port = %target.0, kind, bytes, "route target rejected unit");
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "route capacity changed during dispatch",
                        ));
                    }
                }
                RouterEvent::ManagedMac(mac) => {
                    let rebind = self.prepare_managed_mac_rebind(&target, mac)?;
                    tracing::info!(source_port = %source.0, target_port = %target.0, mac = %RouteAddress::Mac(mac), "managed MAC routed");
                    self.port_mut(&target)?.on_managed_mac(mac)?;
                    if let Some((old, route_target)) = rebind {
                        self.finish_managed_mac_rebind(&target, mac, old, route_target);
                    }
                }
                RouterEvent::Ready => {
                    tracing::info!(source_port = %source.0, target_port = %target.0, "route source ready");
                    self.port_mut(&target)?.on_peer_ready()?
                }
                RouterEvent::Closed => {
                    tracing::info!(source_port = %source.0, target_port = %target.0, "route closed");
                    self.port_mut(source)?.disconnect()?;
                    self.port_mut(&target)?.disconnect()?;
                }
                RouterEvent::TimedOut => {
                    tracing::warn!(source_port = %source.0, target_port = %target.0, "router port timed out")
                }
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
        managed_macs: Vec<[u8; 6]>,
        reject_managed_mac: bool,
        poll_count: usize,
        poll_failures_remaining: usize,
        tick_count: usize,
        tick_failures_remaining: usize,
        disconnect_count: usize,
        next_event: Option<RouterEvent>,
        send_failures_remaining: usize,
        shared_failure: bool,
    }

    struct FakePort(Rc<RefCell<State>>);

    impl RoutePort for FakePort {
        fn poll(&mut self, _: bool) -> io::Result<Option<Vec<RouterEvent>>> {
            let mut state = self.0.borrow_mut();
            state.poll_count += 1;
            if state.poll_failures_remaining > 0 {
                state.poll_failures_remaining -= 1;
                return Err(io::Error::other("simulated poll failure"));
            }
            Ok(state.next_event.take().map(|event| vec![event]))
        }
        fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
            let mut state = self.0.borrow_mut();
            state.tick_count += 1;
            if state.tick_failures_remaining > 0 {
                state.tick_failures_remaining -= 1;
                return Err(io::Error::other("simulated tick failure"));
            }
            Ok(Vec::new())
        }
        fn send(&mut self, _: RoutedUnit) -> io::Result<bool> {
            let mut state = self.0.borrow_mut();
            if state.send_failures_remaining > 0 {
                state.send_failures_remaining -= 1;
                return Err(io::Error::other("simulated send failure"));
            }
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
        fn on_managed_mac(&mut self, mac: [u8; 6]) -> io::Result<()> {
            if self.0.borrow().reject_managed_mac {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "MAC rejected"));
            }
            self.0.borrow_mut().managed_macs.push(mac);
            Ok(())
        }
        fn disconnect(&mut self) -> io::Result<()> {
            self.0.borrow_mut().disconnect_count += 1;
            Ok(())
        }
        fn failure_scope(&self, _error: &io::Error) -> FailureScope {
            if self.0.borrow().shared_failure {
                FailureScope::SharedTransport
            } else {
                FailureScope::Route
            }
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

    #[test]
    fn destination_rebind_cannot_move_in_flight_credit_to_another_target() {
        let ingress_state = Rc::new(RefCell::new(State::default()));
        let first_state = Rc::new(RefCell::new(State {
            completions: 1,
            ..State::default()
        }));
        let second_state = Rc::new(RefCell::new(State {
            completions: 1,
            ..State::default()
        }));
        let mut router = Router::new();
        let ingress = PortId::new("ingress");
        let first = PortId::new("first");
        let second = PortId::new("second");
        for (id, state) in [
            (&ingress, &ingress_state),
            (&first, &first_state),
            (&second, &second_state),
        ] {
            router
                .register_port(id.clone(), Box::new(FakePort(state.clone())))
                .unwrap();
        }
        let first_mac = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 1]);
        let second_mac = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 2]);
        router
            .add_address_route(&ingress, first_mac.clone(), &first)
            .unwrap();
        router
            .add_address_route(&ingress, second_mac.clone(), &second)
            .unwrap();
        router
            .bind_destination(&ingress, first_mac.clone())
            .unwrap();
        // Repeating the original binding is safe; moving to the second
        // target would misattribute the first target's pending completion.
        router.bind_destination(&ingress, first_mac).unwrap();
        assert_eq!(
            router
                .bind_destination(&ingress, second_mac)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        let target = router.target(&ingress).unwrap().clone();
        assert_eq!(target, first);
        router.release_completed(&ingress, &target).unwrap();
        assert_eq!(ingress_state.borrow().credited, 1);
        assert_eq!(first_state.borrow().completions, 0);
        assert_eq!(second_state.borrow().completions, 1);
    }

    fn fake_port(router: &mut Router, name: &str) -> PortId {
        let id = PortId::new(name);
        router
            .register_port(
                id.clone(),
                Box::new(FakePort(Rc::new(RefCell::new(State::default())))),
            )
            .unwrap();
        id
    }

    #[test]
    fn address_routes_select_distinct_targets_for_distinct_peer_ports() {
        let mut router = Router::new();
        let a = fake_port(&mut router, "llc-a");
        let b = fake_port(&mut router, "llc-b");
        let c = fake_port(&mut router, "remote-circuit-a");
        let d = fake_port(&mut router, "remote-circuit-b");
        let cp_a = RouteAddress::ControlPoint {
            netid: "NET".into(),
            name: "CPA".into(),
        };
        let cp_b = RouteAddress::ControlPoint {
            netid: "NET".into(),
            name: "CPB".into(),
        };
        router.add_address_route(&a, cp_a.clone(), &c).unwrap();
        router.add_address_route(&b, cp_b.clone(), &d).unwrap();
        router.bind_destination(&a, cp_a).unwrap();
        router.bind_destination(&b, cp_b).unwrap();
        router.add_route(&c, &a).unwrap();
        router.add_route(&d, &b).unwrap();
        assert_eq!(router.target(&a).unwrap(), &c);
        assert_eq!(router.target(&b).unwrap(), &d);
        router.validate_routes().unwrap();
    }

    #[test]
    fn addressed_source_cannot_fall_back_to_a_default_route() {
        let mut router = Router::new();
        let a = fake_port(&mut router, "llc-a");
        let b = fake_port(&mut router, "llc-b");
        let c = fake_port(&mut router, "llc-c");
        let mac = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 1]);
        router.add_address_route(&a, mac.clone(), &b).unwrap();
        assert_eq!(
            router.add_route(&a, &c).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            router.target(&a).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            router
                .add_address_route(&a, mac.clone(), &c)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            router
                .bind_destination(&a, RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 2]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        router.bind_destination(&a, mac).unwrap();
        assert_eq!(router.target(&a).unwrap(), &b);

        let default_source = fake_port(&mut router, "default-source");
        router.add_route(&default_source, &c).unwrap();
        assert_eq!(
            router
                .add_address_route(
                    &default_source,
                    RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 2]),
                    &b,
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(router.target(&default_source).unwrap(), &c);
    }

    #[test]
    fn logical_unit_selector_uses_full_cp_and_lu_identity() {
        let mut router = Router::new();
        let source = fake_port(&mut router, "source");
        let first = fake_port(&mut router, "first");
        let second = fake_port(&mut router, "second");
        let lu = |name: &str| RouteAddress::LogicalUnit {
            netid: "NET".into(),
            cp: Some("CPA".into()),
            name: name.into(),
        };
        router
            .add_address_route(&source, lu("LU1"), &first)
            .unwrap();
        router
            .add_address_route(&source, lu("LU2"), &second)
            .unwrap();
        router.bind_destination(&source, lu("LU2")).unwrap();
        assert_eq!(router.target(&source).unwrap(), &second);
    }

    #[test]
    fn unknown_lu_hosting_cp_does_not_alias_a_known_cp() {
        let mut router = Router::new();
        let source = fake_port(&mut router, "source");
        let known = fake_port(&mut router, "known");
        let unknown = fake_port(&mut router, "unknown");
        let known_lu = RouteAddress::LogicalUnit {
            netid: "NET".into(),
            cp: Some("CPA".into()),
            name: "LU1".into(),
        };
        let unknown_lu = RouteAddress::LogicalUnit {
            netid: "NET".into(),
            cp: None,
            name: "LU1".into(),
        };
        router
            .add_address_route(&source, known_lu.clone(), &known)
            .unwrap();
        router
            .add_address_route(&source, unknown_lu.clone(), &unknown)
            .unwrap();
        router
            .bind_destination(&source, unknown_lu.clone())
            .unwrap();
        assert_eq!(router.target(&source).unwrap(), &unknown);
        assert_eq!(
            router
                .bind_destination(&source, known_lu.clone())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(router.target(&source).unwrap(), &unknown);
        assert_eq!(
            router
                .address_routes
                .get(&(source.clone(), known_lu.clone())),
            Some(&known)
        );
        assert_eq!(known_lu.to_string(), "NET.CPA.LU1");
        assert_eq!(unknown_lu.to_string(), "NET.LU1");
    }

    #[test]
    fn fan_in_is_rejected_until_egress_exposes_separate_circuit_ports() {
        let mut router = Router::new();
        let a = fake_port(&mut router, "llc-a");
        let b = fake_port(&mut router, "llc-b");
        let c = fake_port(&mut router, "shared-egress");
        router.add_route(&a, &c).unwrap();
        router.add_route(&b, &c).unwrap();
        router.add_route(&c, &a).unwrap();
        assert_eq!(
            router.validate_routes().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn managed_mac_reaches_only_the_addressed_peer() {
        let mut router = Router::new();
        let source = fake_port(&mut router, "remote");
        let a = Rc::new(RefCell::new(State::default()));
        let b = Rc::new(RefCell::new(State::default()));
        let a_id = PortId::new("llc-a");
        let b_id = PortId::new("llc-b");
        router
            .register_port(a_id.clone(), Box::new(FakePort(a.clone())))
            .unwrap();
        router
            .register_port(b_id.clone(), Box::new(FakePort(b.clone())))
            .unwrap();
        let cp = RouteAddress::ControlPoint {
            netid: "NET".into(),
            name: "CPA".into(),
        };
        router
            .add_address_route(&source, cp.clone(), &a_id)
            .unwrap();
        router
            .add_address_route(
                &source,
                RouteAddress::ControlPoint {
                    netid: "NET".into(),
                    name: "CPB".into(),
                },
                &b_id,
            )
            .unwrap();
        router.bind_destination(&source, cp).unwrap();
        let initial = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 1]);
        router
            .add_address_route(&a_id, initial.clone(), &source)
            .unwrap();
        router.bind_destination(&a_id, initial.clone()).unwrap();
        let mac = [0x02, 0x53, 0x4e, 0, 0, 7];
        router
            .dispatch(&source, vec![RouterEvent::ManagedMac(mac)])
            .unwrap();
        assert_eq!(a.borrow().managed_macs, vec![mac]);
        assert!(b.borrow().managed_macs.is_empty());
        assert_eq!(
            router.destinations.get(&a_id),
            Some(&RouteAddress::Mac(mac))
        );
        assert_eq!(router.target(&a_id).unwrap(), &source);
        assert!(!router.address_routes.contains_key(&(a_id.clone(), initial)));
    }

    #[test]
    fn managed_mac_collision_is_rejected_before_endpoint_change() {
        let mut router = Router::new();
        let remote = fake_port(&mut router, "remote");
        let target_state = Rc::new(RefCell::new(State::default()));
        let target = PortId::new("target");
        router
            .register_port(target.clone(), Box::new(FakePort(target_state.clone())))
            .unwrap();
        let other = fake_port(&mut router, "other-llc");
        let cp = RouteAddress::ControlPoint {
            netid: "NET".into(),
            name: "CPA".into(),
        };
        router
            .add_address_route(&remote, cp.clone(), &target)
            .unwrap();
        router.bind_destination(&remote, cp).unwrap();
        let initial = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 1]);
        let occupied = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 7]);
        router
            .add_address_route(&target, initial.clone(), &remote)
            .unwrap();
        router.bind_destination(&target, initial.clone()).unwrap();
        router
            .add_address_route(&other, occupied.clone(), &remote)
            .unwrap();
        router.bind_destination(&other, occupied).unwrap();
        let error = router
            .dispatch(
                &remote,
                vec![RouterEvent::ManagedMac([0x02, 0x53, 0x4e, 0, 0, 7])],
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(target_state.borrow().managed_macs.is_empty());
        assert_eq!(router.destinations.get(&target), Some(&initial));
    }

    #[test]
    fn managed_mac_namespace_is_checked_before_port_or_route_changes() {
        let mut router = Router::new();
        let remote = fake_port(&mut router, "remote");
        let target_state = Rc::new(RefCell::new(State::default()));
        let target = PortId::new("target");
        router
            .register_port(target.clone(), Box::new(FakePort(target_state.clone())))
            .unwrap();
        router.add_route(&remote, &target).unwrap();
        let initial = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 1]);
        router
            .add_address_route(&target, initial.clone(), &remote)
            .unwrap();
        router.bind_destination(&target, initial.clone()).unwrap();

        let invalid = [0x02, 0x53, 0x4f, 0, 0, 7];
        let error = router
            .dispatch(&remote, vec![RouterEvent::ManagedMac(invalid)])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(target_state.borrow().managed_macs.is_empty());
        assert_eq!(router.destinations.get(&target), Some(&initial));
        assert_eq!(router.target(&target).unwrap(), &remote);
    }

    #[test]
    fn endpoint_rejection_keeps_old_mac_route_bound() {
        let mut router = Router::new();
        let remote = fake_port(&mut router, "remote");
        let target_state = Rc::new(RefCell::new(State {
            reject_managed_mac: true,
            ..State::default()
        }));
        let target = PortId::new("target");
        router
            .register_port(target.clone(), Box::new(FakePort(target_state)))
            .unwrap();
        router.add_route(&remote, &target).unwrap();
        let initial = RouteAddress::Mac([0x02, 0x53, 0x4e, 0, 0, 1]);
        router
            .add_address_route(&target, initial.clone(), &remote)
            .unwrap();
        router.bind_destination(&target, initial.clone()).unwrap();
        let error = router
            .dispatch(
                &remote,
                vec![RouterEvent::ManagedMac([0x02, 0x53, 0x4e, 0, 0, 7])],
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(router.destinations.get(&target), Some(&initial));
        assert_eq!(router.target(&target).unwrap(), &remote);
    }

    fn paired_fake_routes(
        a: Rc<RefCell<State>>,
        b: Rc<RefCell<State>>,
        c: Rc<RefCell<State>>,
        d: Rc<RefCell<State>>,
    ) -> Router {
        let mut router = Router::new();
        for (name, state) in [("a", a), ("b", b), ("c", c), ("d", d)] {
            router
                .register_port(PortId::new(name), Box::new(FakePort(state)))
                .unwrap();
        }
        for (source, target) in [("a", "b"), ("b", "a"), ("c", "d"), ("d", "c")] {
            router
                .add_route(&PortId::new(source), &PortId::new(target))
                .unwrap();
        }
        router.validate_routes().unwrap();
        router
    }

    #[test]
    fn failed_pair_is_quarantined_while_other_pair_stays_active() {
        let a = Rc::new(RefCell::new(State {
            poll_failures_remaining: 1,
            ..State::default()
        }));
        let b = Rc::new(RefCell::new(State::default()));
        let c = Rc::new(RefCell::new(State::default()));
        let d = Rc::new(RefCell::new(State::default()));
        let mut router = paired_fake_routes(a.clone(), b.clone(), c.clone(), d.clone());
        router.poll_once().unwrap();
        assert_eq!(a.borrow().disconnect_count, 1);
        assert_eq!(b.borrow().disconnect_count, 1);
        assert_eq!(b.borrow().poll_count, 0);
        assert_eq!(c.borrow().poll_count, 1);
        assert_eq!(d.borrow().tick_count, 1);
        assert!(router.is_quarantined(&PortId::new("a")));
        assert!(router.is_quarantined(&PortId::new("b")));
        for name in ["a", "b"] {
            router
                .failures
                .get_mut(&PortId::new(name))
                .unwrap()
                .retry_at = Instant::now();
        }
        router.poll_once().unwrap();
        assert_eq!(a.borrow().poll_count, 2);
        assert_eq!(b.borrow().poll_count, 1);
        assert!(!router.failures.contains_key(&PortId::new("a")));
        assert!(!router.failures.contains_key(&PortId::new("b")));
    }

    #[test]
    fn target_send_failure_is_isolated_to_its_pair() {
        let a = Rc::new(RefCell::new(State {
            next_event: Some(RouterEvent::Unit(RoutedUnit::SnaInformation(vec![1]))),
            ..State::default()
        }));
        let b = Rc::new(RefCell::new(State {
            send_failures_remaining: 1,
            ..State::default()
        }));
        let c = Rc::new(RefCell::new(State::default()));
        let d = Rc::new(RefCell::new(State::default()));
        let mut router = paired_fake_routes(a, b.clone(), c.clone(), d);
        router.poll_once().unwrap();
        assert_eq!(b.borrow().disconnect_count, 1);
        assert_eq!(c.borrow().poll_count, 1);
    }

    #[test]
    fn tick_failure_is_isolated_to_its_pair() {
        let a = Rc::new(RefCell::new(State {
            tick_failures_remaining: 1,
            ..State::default()
        }));
        let b = Rc::new(RefCell::new(State::default()));
        let c = Rc::new(RefCell::new(State::default()));
        let d = Rc::new(RefCell::new(State::default()));
        let mut router = paired_fake_routes(a.clone(), b.clone(), c.clone(), d.clone());
        router.poll_once().unwrap();
        assert_eq!(a.borrow().disconnect_count, 1);
        assert_eq!(b.borrow().tick_count, 0);
        assert_eq!(c.borrow().tick_count, 1);
        assert_eq!(d.borrow().tick_count, 1);
    }

    #[test]
    fn shared_transport_failure_still_restarts_router() {
        let a = Rc::new(RefCell::new(State {
            poll_failures_remaining: 1,
            ..State::default()
        }));
        let b = Rc::new(RefCell::new(State {
            shared_failure: true,
            ..State::default()
        }));
        let c = Rc::new(RefCell::new(State::default()));
        let d = Rc::new(RefCell::new(State::default()));
        let mut router = paired_fake_routes(a.clone(), b.clone(), c, d);
        let error = router.poll_once().unwrap_err();
        assert_eq!(error.to_string(), "simulated poll failure");
        assert!(router.failures.is_empty());
        assert_eq!(a.borrow().disconnect_count, 0);
        assert_eq!(b.borrow().disconnect_count, 0);
    }
}
