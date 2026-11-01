//! WebSocket circuit adapter. The routing core sees the same SNA units as it
//! does on a local LLC port; only this module knows the concentrator protocol.

use crate::routing::{FailureScope, RoutePort, RoutedUnit, RouterEvent};
use router_core::packet_log::{decode_llc_pdu, decode_sna_information, hex_dump};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    io,
    rc::Rc,
    time::Duration,
};
use tracing::{debug, info, warn};
use transport_ws::{wire, WsClient};

const INITIAL_ALLOWANCE: u64 = 1500;
const MAX_PENDING_EVENTS: usize = INITIAL_ALLOWANCE as usize;
const MAX_PENDING_TYPE1: usize = 16;
const MAX_CLOSED_IDS: usize = 64;

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) url: String,
    pub(crate) bearer: String,
    pub(crate) local_cp: wire::SnaName,
    pub(crate) target_cp: wire::SnaName,
    pub(crate) target_lu: Option<wire::SnaName>,
}

struct Circuit {
    id: Vec<u8>,
    ready: bool,
    send_allowance: u64,
    sent_bytes: u64,
    receive_allowance: u64,
    received_bytes: u64,
}

struct SharedWs {
    client: WsClient,
    inbox: Vec<VecDeque<wire::ws_envelope::Body>>,
    route_owners: HashMap<u64, usize>,
    request_owners: HashMap<u64, usize>,
    circuit_owners: HashMap<Vec<u8>, usize>,
    closed_circuits: VecDeque<Vec<u8>>,
    closed_requests: VecDeque<u64>,
    next_request_id: u64,
    last_managed_revision: u64,
}

impl SharedWs {
    fn dequeue(&mut self, index: usize) -> io::Result<Option<wire::ws_envelope::Body>> {
        use wire::ws_envelope::Body;
        while let Some(body) = self.inbox[index].pop_front() {
            let circuit_id = match &body {
                Body::OpenReady(value) => Some(value.circuit_id.as_slice()),
                Body::CircuitEvent(value) => Some(value.circuit_id.as_slice()),
                Body::CircuitCredit(value) => Some(value.circuit_id.as_slice()),
                Body::CircuitClose(value) => Some(value.circuit_id.as_slice()),
                Body::CircuitReset(value) => Some(value.circuit_id.as_slice()),
                _ => None,
            };
            if circuit_id.is_some_and(|id| {
                !self.circuit_owners.contains_key(id)
                    && self.closed_circuits.iter().any(|closed| closed == id)
            }) {
                continue;
            }
            if let Body::OpenResult(result) = &body {
                if !self.request_owners.contains_key(&result.request_id)
                    && self.closed_requests.contains(&result.request_id)
                {
                    if result.accepted && result.circuit_id.len() == 16 {
                        self.client
                            .send(envelope(Body::CircuitClose(wire::CircuitClose {
                                circuit_id: result.circuit_id.clone(),
                            })))
                            .map_err(io_error)?;
                    }
                    continue;
                }
            }
            return Ok(Some(body));
        }
        Ok(None)
    }

    fn receive_once(&mut self) -> io::Result<bool> {
        let Some(message) = self
            .client
            .recv_timeout(Duration::from_micros(100))
            .map_err(io_error)?
        else {
            return Ok(false);
        };
        let body = message.body.ok_or_else(|| protocol("empty envelope"))?;
        use wire::ws_envelope::Body;
        match &body {
            Body::OriginRoutes(_) | Body::OriginWithdraw(_) => {
                for inbox in &mut self.inbox {
                    inbox.push_back(body.clone());
                }
            }
            Body::ManagedCpBindings(bindings) => {
                accept_managed_revision(&mut self.last_managed_revision, bindings.revision)?;
                for inbox in &mut self.inbox {
                    inbox.push_back(body.clone());
                }
            }
            Body::IncomingOpen(open) => {
                let route_id = open.target.as_ref().map(|route| route.route_id);
                if let Some(owner) = route_id.and_then(|id| self.route_owners.get(&id)).copied() {
                    self.inbox[owner].push_back(body);
                } else {
                    self.client
                        .send(envelope(Body::OpenDecision(wire::OpenDecision {
                            circuit_id: open.circuit_id.clone(),
                            accept: false,
                            receive_allowance_bytes: 0,
                            reason: wire::OpenFailure::RouteGone as i32,
                        })))
                        .map_err(io_error)?;
                }
            }
            Body::OpenResult(result) => {
                if let Some(owner) = self.request_owners.get(&result.request_id).copied() {
                    self.inbox[owner].push_back(body);
                } else if self.closed_requests.contains(&result.request_id) {
                    if result.accepted && result.circuit_id.len() == 16 {
                        self.client
                            .send(envelope(Body::CircuitClose(wire::CircuitClose {
                                circuit_id: result.circuit_id.clone(),
                            })))
                            .map_err(io_error)?;
                    }
                } else {
                    return Err(protocol("unknown open request ID"));
                }
            }
            Body::OpenReady(ready) => {
                let id = ready.circuit_id.clone();
                self.queue_circuit(&id, body)?;
            }
            Body::CircuitEvent(event) => {
                let id = event.circuit_id.clone();
                self.queue_circuit(&id, body)?;
            }
            Body::CircuitCredit(credit) => {
                let id = credit.circuit_id.clone();
                self.queue_circuit(&id, body)?;
            }
            Body::CircuitClose(close) => {
                let id = close.circuit_id.clone();
                self.queue_circuit(&id, body)?;
            }
            Body::CircuitReset(reset) => {
                let id = reset.circuit_id.clone();
                self.queue_circuit(&id, body)?;
            }
            Body::IdentityUpdate(_) => self.inbox[0].push_back(body),
            _ => return Err(protocol("unexpected server message")),
        }
        Ok(true)
    }

    fn queue_circuit(&mut self, id: &[u8], body: wire::ws_envelope::Body) -> io::Result<()> {
        if let Some(owner) = self.circuit_owners.get(id).copied() {
            self.inbox[owner].push_back(body);
        } else if !self.closed_circuits.iter().any(|closed| closed == id) {
            return Err(protocol("unknown circuit ID"));
        }
        Ok(())
    }

    fn retire_circuit(&mut self, id: &[u8]) {
        self.circuit_owners.remove(id);
        self.closed_circuits.push_back(id.to_vec());
        if self.closed_circuits.len() > MAX_CLOSED_IDS {
            self.closed_circuits.pop_front();
        }
    }

    fn retire_request(&mut self, id: u64) {
        self.request_owners.remove(&id);
        self.closed_requests.push_back(id);
        if self.closed_requests.len() > MAX_CLOSED_IDS {
            self.closed_requests.pop_front();
        }
    }
}

pub(crate) struct WsRoutePort {
    shared: Rc<RefCell<SharedWs>>,
    index: usize,
    welcome: wire::RouterWelcome,
    local_cp: wire::SnaName,
    local_route_ids: HashSet<u64>,
    target_cp: wire::SnaName,
    target_lu: Option<wire::SnaName>,
    target: Option<wire::RouteReference>,
    source_route: Option<wire::RouteReference>,
    require_managed_binding: bool,
    managed_binding_seen: bool,
    managed_mac: Option<[u8; 6]>,
    circuit: Option<Circuit>,
    opening: bool,
    local_ready: bool,
    request_id: u64,
    pending_type1: VecDeque<Vec<u8>>,
    pending_information: VecDeque<Vec<u8>>,
    // Each unit forwarded into the LLC endpoint remains retained here until
    // that endpoint's ACK releases its queue/pending I-frame slot.
    downstream_sizes: VecDeque<usize>,
    // A-side CircuitCredit is issued by the remote LLC adapter only after
    // information delivery. Account by exact PIU lengths, not socket writes.
    outbound_completions: OutboundCompletions,
}

#[derive(Default)]
struct OutboundCompletions {
    sizes: VecDeque<usize>,
    pending_bytes: u64,
    partial_credit: u64,
    completed: usize,
}

impl OutboundCompletions {
    fn sent(&mut self, bytes: usize) -> io::Result<()> {
        self.pending_bytes = self
            .pending_bytes
            .checked_add(bytes as u64)
            .ok_or_else(|| protocol("outbound completion byte count overflow"))?;
        self.sizes.push_back(bytes);
        Ok(())
    }

    fn credit(&mut self, bytes: u64) -> io::Result<()> {
        if bytes > self.pending_bytes.saturating_sub(self.partial_credit) {
            return Err(protocol("CircuitCredit exceeds unacknowledged information"));
        }
        let mut available = self.partial_credit + bytes;
        while self
            .sizes
            .front()
            .is_some_and(|size| *size as u64 <= available)
        {
            let size = self.sizes.pop_front().unwrap() as u64;
            available -= size;
            self.pending_bytes -= size;
            self.completed += 1;
        }
        self.partial_credit = available;
        Ok(())
    }

    fn take_completed(&mut self) -> usize {
        std::mem::take(&mut self.completed)
    }
}

impl WsRoutePort {
    pub(crate) fn connect(config: Config) -> io::Result<Self> {
        Ok(Self::connect_many_with_mode(vec![config], vec![], false, None)?.remove(0))
    }

    pub(crate) fn connect_many(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
    ) -> io::Result<Vec<Self>> {
        Self::connect_many_with_mode(configs, logical_units, true, None)
    }

    /// One virtual native gateway circuit. The source LU must be a locally
    /// published export; the server validates its live reference at OPEN.
    pub(crate) fn connect_gateway_v2(
        config: Config,
        logical_units: Vec<wire::LuReachability>,
        source_lu: wire::SnaName,
    ) -> io::Result<Self> {
        Ok(Self::connect_many_with_mode(
            vec![config],
            logical_units,
            false,
            Some(vec![Some(source_lu)]),
        )?
        .remove(0))
    }

    /// LLC-facing v2 ports may receive source-LU authenticated opens while
    /// still requiring the managed CP address binding on their local link.
    pub(crate) fn connect_many_v2(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
        source_lus: Vec<Option<wire::SnaName>>,
    ) -> io::Result<Vec<Self>> {
        Self::connect_many_with_mode(configs, logical_units, true, Some(source_lus))
    }

    fn connect_many_with_mode(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
        require_managed_binding: bool,
        source_lus: Option<Vec<Option<wire::SnaName>>>,
    ) -> io::Result<Vec<Self>> {
        let primary = configs
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no remote routes"))?;
        if source_lus
            .as_ref()
            .is_some_and(|lus| lus.len() != configs.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source LU count differs from remote routes",
            ));
        }
        for config in &configs {
            validate_name(&config.local_cp)?;
            validate_name(&config.target_cp)?;
            if let Some(target_lu) = &config.target_lu {
                validate_name(target_lu)?;
                if target_lu.netid != config.target_cp.netid {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "target LU NETID differs from target CP NETID",
                    ));
                }
            }
            if config.url != primary.url || config.bearer != primary.bearer {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "remote routes must share one upstream URL and bearer",
                ));
            }
        }
        let (mut client, welcome) = if source_lus.is_some() {
            WsClient::connect_v2(&primary.url, &primary.bearer)
        } else {
            WsClient::connect(&primary.url, &primary.bearer)
        }
        .map_err(io_error)?;
        if configs
            .iter()
            .any(|config| config.local_cp.netid != welcome.allowed_netid)
            || logical_units.iter().any(|lu| {
                lu.lu
                    .as_ref()
                    .is_some_and(|name| name.netid != welcome.allowed_netid)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured route NETID does not match concentrator assignment",
            ));
        }
        if configs.len() > welcome.max_circuits as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured remote routes exceed concentrator circuit limit",
            ));
        }
        let upstream_address = client
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".to_owned());
        info!(
            server = %server_authority(&primary.url),
            upstream_address = %upstream_address,
            router_id = %format_uuid(&welcome.router_id),
            connection_epoch = %format_uuid(&welcome.connection_epoch),
            display_name = %welcome.display_name,
            allowed_netid = %welcome.allowed_netid,
            local_route_count = configs.len(),
            "connected to concentrator"
        );
        let snapshot = local_route_snapshot(
            &welcome.connection_epoch,
            1,
            &primary.local_cp,
            &configs[1..]
                .iter()
                .map(|config| config.local_cp.clone())
                .collect::<Vec<_>>(),
            &logical_units,
        )?;
        let source_routes = source_lus.as_ref().map(|lus| {
            lus.iter().zip(&configs).map(|(lu, config)| {
                let Some(lu) = lu else { return Ok(None) };
                validate_name(lu)?;
                let route = snapshot.routes.iter().find(|route| {
                    matches!(route.resource.as_ref(), Some(wire::route_export::Resource::LogicalUnit(export))
                        if export.lu.as_ref() == Some(lu) && export.hosting_cp.as_ref() == Some(&config.local_cp))
                }).ok_or_else(|| protocol("v2 source LU must be exported under local CP"))?;
                Ok(Some(wire::RouteReference {
                    router_id: welcome.router_id.clone(),
                    epoch: welcome.connection_epoch.clone(),
                    route_id: route.id,
                    route_generation: route.generation,
                }))
            }).collect::<io::Result<Vec<_>>>()
        }).transpose()?;
        let mut route_owners = HashMap::new();
        let mut local_route_ids = vec![HashSet::new(); configs.len()];
        for route in &snapshot.routes {
            let owner = match route.resource.as_ref() {
                Some(wire::route_export::Resource::ControlPoint(cp)) => configs
                    .iter()
                    .position(|config| config.local_cp == *cp)
                    .ok_or_else(|| protocol("exported CP has no remote port"))?,
                Some(wire::route_export::Resource::LogicalUnit(lu)) => {
                    let host = lu.hosting_cp.as_ref();
                    match host {
                        Some(host) => configs
                            .iter()
                            .position(|config| config.local_cp == *host)
                            .ok_or_else(|| protocol("LU hosting CP has no remote port"))?,
                        None if configs.len() == 1 => 0,
                        None => return Err(protocol("LU hosting CP required with multiple ports")),
                    }
                }
                None => return Err(protocol("route export missing resource")),
            };
            route_owners.insert(route.id, owner);
            local_route_ids[owner].insert(route.id);
        }
        let export_count = snapshot.routes.len();
        client
            .send(envelope(wire::ws_envelope::Body::PublishRoutes(snapshot)))
            .map_err(io_error)?;
        info!(
            router_id = %format_uuid(&welcome.router_id),
            export_count,
            revision = 1,
            "published local reachability"
        );
        let shared = Rc::new(RefCell::new(SharedWs {
            client,
            inbox: vec![VecDeque::new(); configs.len()],
            route_owners,
            request_owners: HashMap::new(),
            circuit_owners: HashMap::new(),
            closed_circuits: VecDeque::new(),
            closed_requests: VecDeque::new(),
            next_request_id: 0,
            last_managed_revision: 0,
        }));
        Ok(configs
            .into_iter()
            .zip(local_route_ids)
            .enumerate()
            .map(|(index, (config, local_route_ids))| Self {
                shared: shared.clone(),
                index,
                welcome: welcome.clone(),
                local_cp: config.local_cp,
                local_route_ids,
                target_cp: config.target_cp,
                target_lu: config.target_lu,
                target: None,
                source_route: source_routes
                    .as_ref()
                    .and_then(|routes| routes[index].clone()),
                require_managed_binding,
                managed_binding_seen: false,
                managed_mac: None,
                circuit: None,
                opening: false,
                local_ready: false,
                request_id: 0,
                pending_type1: VecDeque::new(),
                pending_information: VecDeque::new(),
                downstream_sizes: VecDeque::new(),
                outbound_completions: OutboundCompletions::default(),
            })
            .collect())
    }

    fn send_body(&mut self, body: wire::ws_envelope::Body) -> io::Result<()> {
        self.shared
            .borrow_mut()
            .client
            .send(envelope(body))
            .map_err(io_error)
    }

    fn maybe_open(&mut self) -> io::Result<()> {
        if self.shared.borrow().client.subprotocol() == transport_ws::SUBPROTOCOL_V2
            && self.source_route.is_none()
        {
            return Ok(());
        }
        if self.circuit.is_some()
            || self.opening
            || self.pending_type1.is_empty()
            || (self.require_managed_binding && self.managed_mac.is_none())
        {
            return Ok(());
        }
        let Some(target) = self.target.clone() else {
            return Ok(());
        };
        let mut shared = self.shared.borrow_mut();
        shared.next_request_id = shared
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("request ID exhausted"))?;
        self.request_id = shared.next_request_id;
        shared.request_owners.insert(self.request_id, self.index);
        drop(shared);
        self.opening = true;
        info!(
            request_id = self.request_id,
            target_router_id = %format_uuid(&target.router_id),
            target_epoch = %format_uuid(&target.epoch),
            target_route_id = target.route_id,
            target_generation = target.route_generation,
            target_cp = %format_cp(&self.target_cp),
            "requesting circuit open"
        );
        self.send_body(wire::ws_envelope::Body::OpenRequest(wire::OpenRequest {
            request_id: self.request_id,
            target: Some(target),
            receive_allowance_bytes: INITIAL_ALLOWANCE,
            source_route: self.source_route.clone(),
        }))
    }

    fn send_event(&mut self, event: wire::circuit_event::Event) -> io::Result<()> {
        let Some(circuit) = &self.circuit else {
            return Ok(());
        };
        if !circuit.ready {
            return Ok(());
        }
        self.send_body(wire::ws_envelope::Body::CircuitEvent(wire::CircuitEvent {
            circuit_id: circuit.id.clone(),
            event: Some(event),
        }))
    }

    fn flush_type1(&mut self) -> io::Result<()> {
        while self.circuit.as_ref().is_some_and(|c| c.ready) {
            let Some(pdu) = self.pending_type1.pop_front() else {
                break;
            };
            debug!(
                circuit_id = %self.circuit.as_ref().map(|c| format_uuid(&c.id)).unwrap_or_default(),
                bytes = pdu.len(),
                decoded = %decode_llc_pdu(&pdu),
                hex = %hex_dump(&pdu),
                "send Type1 over WebSocket"
            );
            self.send_event(wire::circuit_event::Event::Type1(encode_type1(&pdu)?))?;
        }
        if self.local_ready && self.circuit.as_ref().is_some_and(|c| c.ready) {
            info!(
                circuit_id = %self.circuit.as_ref().map(|c| format_uuid(&c.id)).unwrap_or_default(),
                "send local link ready"
            );
            self.send_event(wire::circuit_event::Event::LinkReady(wire::LinkReady {}))?;
            self.local_ready = false;
        }
        Ok(())
    }

    fn handle(&mut self, body: wire::ws_envelope::Body) -> io::Result<Vec<RouterEvent>> {
        use wire::ws_envelope::Body;
        match body {
            Body::OriginRoutes(origin) => {
                if origin.router_id.len() != 16 {
                    return Err(protocol("invalid origin ID"));
                }
                let snapshot = origin
                    .snapshot
                    .ok_or_else(|| protocol("missing route snapshot"))?;
                if snapshot.epoch.len() != 16 {
                    return Err(protocol("invalid route epoch"));
                }
                if self.target_lu.is_none()
                    && self.managed_binding_seen
                    && (self.require_managed_binding || self.managed_mac.is_some())
                {
                    return Ok(Vec::new());
                }
                if let Some(route) = snapshot
                    .routes
                    .into_iter()
                    .find(|route| self.matches_target_route(route))
                {
                    let next_target = wire::RouteReference {
                        router_id: origin.router_id,
                        epoch: snapshot.epoch,
                        route_id: route.id,
                        route_generation: route.generation,
                    };
                    let retargeted = self.target.as_ref().is_some_and(|old| old != &next_target);
                    debug!(
                        origin_router_id = %format_uuid(&next_target.router_id),
                        origin_epoch = %format_uuid(&next_target.epoch),
                        target_cp = %format_cp(&self.target_cp),
                        route_id = next_target.route_id,
                        generation = next_target.route_generation,
                        retargeted,
                        "received target route"
                    );
                    self.target = Some(next_target);
                    if retargeted && self.circuit.is_some() {
                        warn!(target_cp = %format_cp(&self.target_cp), "target route changed; closing circuit");
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                    if retargeted && self.opening {
                        self.clear_circuit();
                    }
                    self.maybe_open()?;
                } else if self
                    .target
                    .as_ref()
                    .is_some_and(|r| r.router_id == origin.router_id)
                {
                    warn!(
                        origin_router_id = %format_uuid(&origin.router_id),
                        target_cp = %format_cp(&self.target_cp),
                        "target resource withdrawn from route snapshot"
                    );
                    self.target = None;
                    if self.circuit.is_some() {
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                    if self.opening {
                        self.clear_circuit();
                    }
                }
            }
            Body::OriginWithdraw(withdraw) => {
                if self.target_lu.is_none()
                    && self.managed_binding_seen
                    && (self.require_managed_binding || self.managed_mac.is_some())
                {
                    return Ok(Vec::new());
                }
                if self
                    .target
                    .as_ref()
                    .is_some_and(|r| r.router_id == withdraw.router_id && r.epoch == withdraw.epoch)
                {
                    warn!(
                        origin_router_id = %format_uuid(&withdraw.router_id),
                        origin_epoch = %format_uuid(&withdraw.epoch),
                        target_cp = %format_cp(&self.target_cp),
                        "target router withdrew routes"
                    );
                    self.target = None;
                    if self.circuit.is_some() {
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                    if self.opening {
                        self.clear_circuit();
                    }
                }
            }
            Body::ManagedCpBindings(bindings) => {
                if bindings.schema_version != 1
                    || bindings.recipient_epoch != self.welcome.connection_epoch
                {
                    return Err(protocol("invalid managed CP binding snapshot"));
                }
                validate_managed_bindings(&bindings.bindings)?;
                self.managed_binding_seen = true;
                debug!(
                    revision = bindings.revision,
                    binding_count = bindings.bindings.len(),
                    "received managed CP bindings"
                );
                if let Some(binding) = bindings
                    .bindings
                    .into_iter()
                    .find(|b| b.control_point.as_ref() == Some(&self.target_cp))
                {
                    let mac: [u8; 6] = binding
                        .virtual_mac
                        .as_slice()
                        .try_into()
                        .map_err(|_| protocol("invalid managed virtual MAC"))?;
                    info!(
                        target_cp = %format_cp(&self.target_cp),
                        virtual_mac = %format_mac(&binding.virtual_mac),
                        candidate_count = binding.candidates.len(),
                        "selected managed CP binding"
                    );
                    let next_target = binding.candidates.into_iter().next();
                    let target_changed = self.target_lu.is_none() && self.target != next_target;
                    let changed = target_changed || self.managed_mac != Some(mac);
                    if self.target_lu.is_none() {
                        self.target = next_target;
                    }
                    self.managed_mac = Some(mac);
                    if changed && self.opening {
                        self.clear_circuit();
                    }
                    if changed && self.circuit.is_some() {
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed, RouterEvent::ManagedMac(mac)]);
                    }
                    return Ok(vec![RouterEvent::ManagedMac(mac)]);
                }
                if self.require_managed_binding || self.managed_mac.is_some() {
                    if self.target_lu.is_none() {
                        self.target = None;
                    }
                    self.managed_mac = None;
                    if self.opening {
                        self.clear_circuit();
                    }
                    if self.circuit.is_some() {
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                }
            }
            Body::IncomingOpen(incoming) => self.incoming_open(incoming)?,
            Body::OpenReady(ready) => {
                let circuit = self
                    .circuit
                    .as_mut()
                    .ok_or_else(|| protocol("unexpected OpenReady"))?;
                if circuit.id != ready.circuit_id {
                    return Err(protocol("wrong circuit ID"));
                }
                circuit.ready = true;
                info!(circuit_id = %format_uuid(&ready.circuit_id), "incoming circuit ready");
                self.flush_type1()?;
            }
            Body::OpenResult(result) => {
                let rejected = !result.accepted;
                self.open_result(result)?;
                if rejected {
                    return Ok(vec![RouterEvent::Closed]);
                }
            }
            Body::CircuitEvent(event) => return self.incoming_event(event),
            Body::CircuitCredit(credit) => {
                let circuit = self.checked_circuit_mut(&credit.circuit_id)?;
                if credit.allowance_bytes <= circuit.send_allowance {
                    return Err(protocol("credit did not increase"));
                }
                let granted = credit.allowance_bytes - circuit.send_allowance;
                self.outbound_completions.credit(granted)?;
                let circuit = self.checked_circuit_mut(&credit.circuit_id)?;
                circuit.send_allowance = credit.allowance_bytes;
                debug!(
                    circuit_id = %format_uuid(&credit.circuit_id),
                    allowance_bytes = credit.allowance_bytes,
                    sent_bytes = circuit.sent_bytes,
                    "received circuit credit"
                );
            }
            Body::CircuitClose(close) => {
                info!(circuit_id = %format_uuid(&close.circuit_id), "remote closed circuit");
                self.checked_circuit_mut(&close.circuit_id)?;
                self.clear_circuit();
                return Ok(vec![RouterEvent::Closed]);
            }
            Body::CircuitReset(reset) => {
                warn!(
                    circuit_id = %format_uuid(&reset.circuit_id),
                    reason = reset.reason,
                    "remote reset circuit"
                );
                self.checked_circuit_mut(&reset.circuit_id)?;
                self.clear_circuit();
                return Ok(vec![RouterEvent::Closed]);
            }
            Body::IdentityUpdate(update) => {
                info!(
                    router_id = %format_uuid(&self.welcome.router_id),
                    display_name = %update.display_name,
                    "server updated router identity"
                );
            }
            _ => return Err(protocol("unexpected server message")),
        }
        Ok(Vec::new())
    }

    fn matches_target_route(&self, route: &wire::RouteExport) -> bool {
        match (&self.target_lu, &route.resource) {
            (None, Some(wire::route_export::Resource::ControlPoint(cp))) => *cp == self.target_cp,
            (Some(target_lu), Some(wire::route_export::Resource::LogicalUnit(lu))) => {
                lu.lu.as_ref() == Some(target_lu) && lu.hosting_cp.as_ref() == Some(&self.target_cp)
            }
            _ => false,
        }
    }

    fn incoming_open(&mut self, incoming: wire::IncomingOpen) -> io::Result<()> {
        if incoming.circuit_id.len() != 16 || incoming.source_router_id.len() != 16 {
            return Err(protocol("invalid incoming circuit ID"));
        }
        let target_ok = incoming.target.as_ref().is_some_and(|r| {
            r.router_id == self.welcome.router_id
                && r.epoch == self.welcome.connection_epoch
                && self.local_route_ids.contains(&r.route_id)
                && r.route_generation == 1
        });
        let v2 = self.shared.borrow().client.subprotocol() == transport_ws::SUBPROTOCOL_V2;
        let source_ok = if v2 {
            self.target_lu.is_some()
                && incoming.source_route.as_ref() == self.target.as_ref()
                && incoming
                    .source_route
                    .as_ref()
                    .is_some_and(|r| r.router_id == incoming.source_router_id)
        } else {
            incoming.source_route.is_none()
        };
        let accept = target_ok
            && source_ok
            && self.circuit.is_none()
            && !self.opening
            && (!self.require_managed_binding || self.managed_mac.is_some());
        let reason = if accept {
            wire::OpenFailure::Unspecified
        } else if !source_ok {
            wire::OpenFailure::Forbidden
        } else if target_ok {
            wire::OpenFailure::Busy
        } else {
            wire::OpenFailure::RouteGone
        };
        if accept {
            info!(
                circuit_id = %format_uuid(&incoming.circuit_id),
                source_router_id = %format_uuid(&incoming.source_router_id),
                local_router_id = %format_uuid(&self.welcome.router_id),
                local_cp = %format_cp(&self.local_cp),
                receive_allowance_bytes = INITIAL_ALLOWANCE,
                "accepted incoming circuit"
            );
        } else {
            warn!(
                circuit_id = %format_uuid(&incoming.circuit_id),
                source_router_id = %format_uuid(&incoming.source_router_id),
                reason = ?reason,
                "rejected incoming circuit"
            );
        }
        self.send_body(wire::ws_envelope::Body::OpenDecision(wire::OpenDecision {
            circuit_id: incoming.circuit_id.clone(),
            accept,
            receive_allowance_bytes: if accept { INITIAL_ALLOWANCE } else { 0 },
            reason: reason as i32,
        }))?;
        if accept {
            self.shared
                .borrow_mut()
                .circuit_owners
                .insert(incoming.circuit_id.clone(), self.index);
            self.circuit = Some(Circuit {
                id: incoming.circuit_id,
                ready: false,
                send_allowance: incoming.source_receive_allowance_bytes,
                sent_bytes: 0,
                receive_allowance: INITIAL_ALLOWANCE,
                received_bytes: 0,
            });
        }
        Ok(())
    }

    fn open_result(&mut self, result: wire::OpenResult) -> io::Result<()> {
        if !self.opening || result.request_id != self.request_id {
            return Err(protocol("unexpected OpenResult"));
        }
        self.opening = false;
        self.shared
            .borrow_mut()
            .request_owners
            .remove(&result.request_id);
        if !result.accepted {
            warn!(
                request_id = result.request_id,
                reason = result.reason,
                target_cp = %format_cp(&self.target_cp),
                "circuit open rejected"
            );
            self.pending_type1.clear();
            return Ok(());
        }
        if result.circuit_id.len() != 16 {
            return Err(protocol("invalid circuit ID"));
        }
        info!(
            request_id = result.request_id,
            circuit_id = %format_uuid(&result.circuit_id),
            target_cp = %format_cp(&self.target_cp),
            peer_allowance_bytes = result.peer_receive_allowance_bytes,
            "outgoing circuit open accepted"
        );
        self.circuit = Some(Circuit {
            id: result.circuit_id.clone(),
            ready: true,
            send_allowance: result.peer_receive_allowance_bytes,
            sent_bytes: 0,
            receive_allowance: INITIAL_ALLOWANCE,
            received_bytes: 0,
        });
        self.shared
            .borrow_mut()
            .circuit_owners
            .insert(result.circuit_id, self.index);
        self.flush_type1()
    }

    fn incoming_event(&mut self, event: wire::CircuitEvent) -> io::Result<Vec<RouterEvent>> {
        let circuit = self.checked_circuit_mut(&event.circuit_id)?;
        if !circuit.ready {
            return Err(protocol("event before OpenReady"));
        }
        match event.event.ok_or_else(|| protocol("empty circuit event"))? {
            wire::circuit_event::Event::Type1(type1) => {
                let pdu = decode_type1(type1)?;
                debug!(
                    circuit_id = %format_uuid(&event.circuit_id),
                    bytes = pdu.len(),
                    decoded = %decode_llc_pdu(&pdu),
                    hex = %hex_dump(&pdu),
                    "received Type1 over WebSocket"
                );
                Ok(vec![RouterEvent::Unit(RoutedUnit::DlcType1(pdu))])
            }
            wire::circuit_event::Event::LinkReady(_) => {
                info!(circuit_id = %format_uuid(&event.circuit_id), "remote link ready");
                Ok(vec![RouterEvent::Ready])
            }
            wire::circuit_event::Event::SnaInformation(data) => {
                if data.is_empty() || data.len() > 1496 {
                    return Err(protocol("invalid SNA information size"));
                }
                circuit.received_bytes = circuit
                    .received_bytes
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| protocol("receive byte counter overflow"))?;
                if circuit.received_bytes > circuit.receive_allowance {
                    return Err(protocol("peer exceeded receive allowance"));
                }
                if self.pending_information.len() + self.downstream_sizes.len()
                    >= MAX_PENDING_EVENTS
                {
                    return Err(protocol("receive event backlog full"));
                }
                debug!(
                    circuit_id = %format_uuid(&event.circuit_id),
                    bytes = data.len(),
                    decoded = %decode_sna_information(&data),
                    hex = %hex_dump(&data),
                    "received SNA information over WebSocket"
                );
                self.pending_information.push_back(data);
                Ok(Vec::new())
            }
        }
    }

    fn checked_circuit_mut(&mut self, id: &[u8]) -> io::Result<&mut Circuit> {
        self.circuit
            .as_mut()
            .filter(|c| c.id == id)
            .ok_or_else(|| protocol("unknown circuit ID"))
    }

    fn clear_circuit(&mut self) {
        let mut shared = self.shared.borrow_mut();
        if let Some(circuit) = &self.circuit {
            shared.retire_circuit(&circuit.id);
        }
        if self.opening {
            shared.retire_request(self.request_id);
        }
        drop(shared);
        self.circuit = None;
        self.opening = false;
        self.pending_type1.clear();
        self.pending_information.clear();
        self.downstream_sizes.clear();
        self.outbound_completions = OutboundCompletions::default();
        self.local_ready = false;
    }
}

impl RoutePort for WsRoutePort {
    fn failure_scope(&self, error: &io::Error) -> FailureScope {
        if error
            .get_ref()
            .and_then(|source| source.downcast_ref::<transport_ws::Error>())
            .is_some()
        {
            FailureScope::SharedTransport
        } else {
            FailureScope::Route
        }
    }

    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if can_accept_information {
            if let Some(data) = self.pending_information.pop_front() {
                self.downstream_sizes.push_back(data.len());
                return Ok(Some(vec![RouterEvent::Unit(RoutedUnit::SnaInformation(
                    data,
                ))]));
            }
        }
        let body = {
            let mut shared = self.shared.borrow_mut();
            if shared.inbox[self.index].is_empty() {
                shared.receive_once()?;
            }
            shared.dequeue(self.index)?
        };
        let Some(body) = body else {
            return Ok(None);
        };
        let events = self.handle(body)?;
        Ok(Some(events))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.maybe_open()?;
        Ok(Vec::new())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        match unit {
            RoutedUnit::DlcType1(pdu) => {
                encode_type1(&pdu)?;
                // A guest can retry XID while its target route is still
                // undiscovered. Keep the newest bounded exchange and never
                // terminate the router merely because those retries repeat.
                if self.circuit.is_none() && self.pending_type1.back() == Some(&pdu) {
                    return Ok(true);
                }
                if self.pending_type1.len() >= MAX_PENDING_TYPE1 {
                    warn!(
                        target_cp = %format_cp(&self.target_cp),
                        queued = self.pending_type1.len(),
                        "dropping oldest pre-open Type1 retry"
                    );
                    self.pending_type1.pop_front();
                }
                self.pending_type1.push_back(pdu);
                self.maybe_open()?;
                self.flush_type1()?;
                Ok(true)
            }
            RoutedUnit::SnaInformation(data) => {
                if data.is_empty() || data.len() > 1496 {
                    return Err(protocol("invalid SNA information size"));
                }
                let bytes = data.len();
                let Some(circuit) = self.circuit.as_mut().filter(|c| c.ready) else {
                    return Ok(false);
                };
                if circuit.sent_bytes.saturating_add(data.len() as u64) > circuit.send_allowance {
                    return Ok(false);
                }
                circuit.sent_bytes += data.len() as u64;
                debug!(
                    circuit_id = %format_uuid(&circuit.id),
                    bytes = data.len(),
                    sent_bytes = circuit.sent_bytes,
                    allowance_bytes = circuit.send_allowance,
                    decoded = %decode_sna_information(&data),
                    hex = %hex_dump(&data),
                    "send SNA information over WebSocket"
                );
                self.send_event(wire::circuit_event::Event::SnaInformation(data))?;
                self.outbound_completions.sent(bytes)?;
                Ok(true)
            }
            RoutedUnit::AnyNetTcpRecord(_)
            | RoutedUnit::AnyNetUdpDatagram(_)
            | RoutedUnit::EeDatagram { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WebSocket circuit profile does not carry AnyNet or EE payloads",
            )),
        }
    }

    fn has_capacity(&self) -> bool {
        self.circuit
            .as_ref()
            .is_some_and(|c| c.ready && c.send_allowance.saturating_sub(c.sent_bytes) >= 1500)
    }

    fn take_completed_information_count(&mut self) -> usize {
        self.outbound_completions.take_completed()
    }

    fn set_ingress_busy(&mut self, _busy: bool) -> io::Result<()> {
        Ok(())
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        self.local_ready = true;
        self.flush_type1()
    }

    fn disconnect(&mut self) -> io::Result<()> {
        if let Some(circuit) = self.circuit.take() {
            self.shared.borrow_mut().retire_circuit(&circuit.id);
            info!(circuit_id = %format_uuid(&circuit.id), "closing circuit");
            self.send_body(wire::ws_envelope::Body::CircuitClose(wire::CircuitClose {
                circuit_id: circuit.id,
            }))?;
        }
        self.clear_circuit();
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_type1()
    }

    fn on_downstream_completed(&mut self, count: usize) -> io::Result<()> {
        // The LLC adapter reports ACKs, including when it immediately sends
        // the next queued I-frame and its occupied slot count stays constant.
        let mut freed = 0u64;
        for _ in 0..count {
            let size = self
                .downstream_sizes
                .pop_front()
                .ok_or_else(|| protocol("LLC completion without routed information"))?;
            freed += size as u64;
        }
        if freed != 0 {
            if let Some(circuit) = self.circuit.as_mut() {
                circuit.receive_allowance = circuit
                    .receive_allowance
                    .checked_add(freed)
                    .ok_or_else(|| protocol("credit counter overflow"))?;
                let id = circuit.id.clone();
                let allowance = circuit.receive_allowance;
                debug!(
                    circuit_id = %format_uuid(&id),
                    completed_information = count,
                    freed_bytes = freed,
                    allowance_bytes = allowance,
                    "granting circuit receive credit"
                );
                self.send_body(wire::ws_envelope::Body::CircuitCredit(
                    wire::CircuitCredit {
                        circuit_id: id,
                        allowance_bytes: allowance,
                    },
                ))?;
            }
        }
        Ok(())
    }
}

fn envelope(body: wire::ws_envelope::Body) -> wire::WsEnvelope {
    wire::WsEnvelope { body: Some(body) }
}

fn validate_name(name: &wire::SnaName) -> io::Result<()> {
    let valid = |value: &str| {
        (1..=8).contains(&value.len())
            && matches!(value.as_bytes()[0], b'A'..=b'Z' | b'@' | b'#' | b'$')
            && value.bytes().all(|b| {
                b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'@' | b'#' | b'$')
            })
    };
    if valid(&name.netid) && valid(&name.name) {
        Ok(())
    } else {
        Err(protocol("invalid NETID.CPNAME"))
    }
}

/// Build a complete local reachability snapshot. The primary CP keeps route
/// ID 1 for the existing single-peer adapter. Additional CP and LU IDs are
/// derived from their resource names, so inserting another export does not
/// silently retarget an existing route ID. The caller must increase the
/// generation if an export's actual destination changes within an epoch.
pub(crate) fn local_route_snapshot(
    epoch: &[u8],
    revision: u64,
    primary_cp: &wire::SnaName,
    additional_cps: &[wire::SnaName],
    logical_units: &[wire::LuReachability],
) -> io::Result<wire::RouteSnapshot> {
    if epoch.len() != 16 || revision == 0 {
        return Err(protocol("invalid route snapshot epoch or revision"));
    }
    validate_name(primary_cp)?;
    let mut identities = HashSet::new();
    identities.insert((primary_cp.netid.clone(), primary_cp.name.clone(), false));
    let mut ids = HashSet::new();
    ids.insert(1);
    let mut routes = vec![wire::RouteExport {
        id: 1,
        generation: 1,
        resource: Some(wire::route_export::Resource::ControlPoint(
            primary_cp.clone(),
        )),
    }];
    for cp in additional_cps {
        validate_name(cp)?;
        if cp.netid != primary_cp.netid {
            return Err(protocol("local CP export outside assigned NETID"));
        }
        if !identities.insert((cp.netid.clone(), cp.name.clone(), false)) {
            return Err(protocol("duplicate local CP export"));
        }
        let id = stable_route_id(b'C', cp);
        if id == 0 || !ids.insert(id) {
            return Err(protocol("local route ID collision"));
        }
        routes.push(wire::RouteExport {
            id,
            generation: 1,
            resource: Some(wire::route_export::Resource::ControlPoint(cp.clone())),
        });
    }
    for lu in logical_units {
        let name = lu
            .lu
            .as_ref()
            .ok_or_else(|| protocol("LU export missing name"))?;
        validate_name(name)?;
        if name.netid != primary_cp.netid {
            return Err(protocol("local LU export outside assigned NETID"));
        }
        if let Some(host) = &lu.hosting_cp {
            validate_name(host)?;
            if host.netid != primary_cp.netid
                || !identities.contains(&(host.netid.clone(), host.name.clone(), false))
            {
                return Err(protocol("LU hosting CP is not an exported local CP"));
            }
        }
        if !identities.insert((name.netid.clone(), name.name.clone(), true)) {
            return Err(protocol("duplicate local LU export"));
        }
        let id = stable_route_id(b'L', name);
        if id == 0 || !ids.insert(id) {
            return Err(protocol("local route ID collision"));
        }
        routes.push(wire::RouteExport {
            id,
            generation: 1,
            resource: Some(wire::route_export::Resource::LogicalUnit(lu.clone())),
        });
    }
    routes[1..].sort_by_key(|route| route.id);
    Ok(wire::RouteSnapshot {
        epoch: epoch.to_vec(),
        revision,
        routes,
    })
}

// FNV-1a with a resource-kind prefix and component separators. A collision
// is rejected above rather than allowing a circuit to reach another route.
fn stable_route_id(kind: u8, name: &wire::SnaName) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in [kind]
        .into_iter()
        .chain(name.netid.bytes())
        .chain([0])
        .chain(name.name.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn accept_managed_revision(last: &mut u64, next: u64) -> io::Result<()> {
    if next == 0 || next <= *last {
        return Err(protocol("managed CP binding revision is not increasing"));
    }
    *last = next;
    Ok(())
}

fn validate_managed_bindings(bindings: &[wire::ManagedCpBinding]) -> io::Result<()> {
    let mut addresses = HashSet::new();
    let mut address_ids = HashSet::new();
    let mut control_points = HashSet::new();
    for binding in bindings {
        let cp = binding
            .control_point
            .as_ref()
            .ok_or_else(|| protocol("managed binding missing CP"))?;
        validate_name(cp)?;
        if binding.virtual_mac.len() != 6
            || binding.virtual_mac[..3] != [0x02, 0x53, 0x4e]
            || !addresses.insert(binding.virtual_mac.as_slice())
            || binding.address_id.len() != 16
            || !address_ids.insert(binding.address_id.as_slice())
            || !control_points.insert((cp.netid.as_str(), cp.name.as_str()))
        {
            return Err(protocol("invalid or duplicate managed CP binding"));
        }
    }
    Ok(())
}

fn encode_type1(pdu: &[u8]) -> io::Result<wire::DlcType1> {
    if pdu.len() < 3 || pdu[0] != 4 || pdu[1] & !1 != 4 {
        return Err(protocol("invalid Type1 PDU"));
    }
    let kind = match pdu[2] & !0x10 {
        0xaf => wire::Type1Kind::Xid,
        0xe3 => wire::Type1Kind::Test,
        _ => return Err(protocol("unsupported Type1 control")),
    };
    Ok(wire::DlcType1 {
        kind: kind as i32,
        response: pdu[1] & 1 != 0,
        poll_final: pdu[2] & 0x10 != 0,
        dsap: pdu[0] as u32,
        ssap: (pdu[1] & !1) as u32,
        information: pdu[3..].to_vec(),
    })
}

fn decode_type1(value: wire::DlcType1) -> io::Result<Vec<u8>> {
    if value.dsap != 4 || value.ssap != 4 || value.information.len() > 1497 {
        return Err(protocol("invalid remote Type1 SAP or size"));
    }
    let control = match wire::Type1Kind::try_from(value.kind).ok() {
        Some(wire::Type1Kind::Xid) => 0xaf,
        Some(wire::Type1Kind::Test) => 0xe3,
        _ => return Err(protocol("invalid remote Type1 kind")),
    };
    let mut pdu = vec![
        4,
        4 | u8::from(value.response),
        control | if value.poll_final { 0x10 } else { 0 },
    ];
    pdu.extend(value.information);
    Ok(pdu)
}

fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "invalid".into();
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn format_cp(name: &wire::SnaName) -> String {
    format!("{}.{}", name.netid, name.name)
}

fn format_mac(mac: &[u8]) -> String {
    if mac.len() != 6 {
        return "invalid".to_owned();
    }
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn server_authority(url: &str) -> &str {
    url.split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("unknown")
}

fn protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn io_error(error: transport_ws::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::{net::TcpListener, sync::mpsc, thread, time::Instant};
    use tungstenite::{
        http::{header::SEC_WEBSOCKET_PROTOCOL, HeaderValue},
        Message as WsMessage,
    };

    #[test]
    fn circuit_credit_retires_only_whole_outbound_information_frames() {
        let mut completions = OutboundCompletions::default();
        completions.sent(141).unwrap();
        completions.sent(46).unwrap();
        completions.credit(100).unwrap();
        assert_eq!(completions.take_completed(), 0);
        completions.credit(41).unwrap();
        assert_eq!(completions.take_completed(), 1);
        completions.credit(46).unwrap();
        assert_eq!(completions.take_completed(), 1);
        assert_eq!(
            completions.credit(1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn name(netid: &str, name: &str) -> wire::SnaName {
        wire::SnaName {
            netid: netid.into(),
            name: name.into(),
        }
    }

    #[test]
    fn shared_socket_demultiplexes_two_incoming_circuits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(transport_ws::SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let send = |socket: &mut tungstenite::WebSocket<std::net::TcpStream>, body| {
                socket
                    .send(WsMessage::Binary(envelope(body).encode_to_vec().into()))
                    .unwrap();
            };
            send(
                &mut socket,
                wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 65536,
                    max_circuits: 4,
                    display_name: "test router".into(),
                    allowed_netid: "SOLNET".into(),
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("expected route snapshot");
            };
            let snapshot = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::PublishRoutes(snapshot)) = snapshot.body else {
                panic!("expected published routes");
            };
            assert_eq!(snapshot.routes.len(), 3);
            let mut cp_ids = HashMap::new();
            for route in &snapshot.routes {
                if let Some(wire::route_export::Resource::ControlPoint(cp)) = &route.resource {
                    cp_ids.insert(cp.name.clone(), route.id);
                }
            }
            assert_eq!(cp_ids.len(), 2);
            send(
                &mut socket,
                wire::ws_envelope::Body::ManagedCpBindings(wire::ManagedCpBindingSnapshot {
                    schema_version: 1,
                    recipient_epoch: vec![8; 16],
                    revision: 1,
                    bindings: ["PEERA", "PEERB"]
                        .into_iter()
                        .enumerate()
                        .map(|(index, cp)| wire::ManagedCpBinding {
                            address_id: vec![(index + 1) as u8; 16],
                            control_point: Some(name("SOLNET", cp)),
                            virtual_mac: vec![0x02, 0x53, 0x4e, 0, 0, (index + 1) as u8],
                            candidates: vec![],
                        })
                        .collect(),
                }),
            );
            for (index, cp) in ["SNAA", "SNAB"].into_iter().enumerate() {
                send(
                    &mut socket,
                    wire::ws_envelope::Body::IncomingOpen(wire::IncomingOpen {
                        circuit_id: vec![(index + 1) as u8; 16],
                        source_router_id: vec![9; 16],
                        target: Some(wire::RouteReference {
                            router_id: vec![7; 16],
                            epoch: vec![8; 16],
                            route_id: cp_ids[cp],
                            route_generation: 1,
                        }),
                        source_receive_allowance_bytes: 1500,
                        source_route: None,
                    }),
                );
            }
            let mut accepted = HashSet::new();
            for _ in 0..2 {
                let WsMessage::Binary(payload) = socket.read().unwrap() else {
                    panic!("expected open decision");
                };
                let decision = wire::WsEnvelope::decode(payload).unwrap();
                let Some(wire::ws_envelope::Body::OpenDecision(decision)) = decision.body else {
                    panic!("expected open decision");
                };
                assert!(decision.accept);
                accepted.insert(decision.circuit_id);
            }
            assert_eq!(accepted.len(), 2);
            for (index, marker) in [0x11, 0x22].into_iter().enumerate() {
                let id = vec![(index + 1) as u8; 16];
                send(
                    &mut socket,
                    wire::ws_envelope::Body::OpenReady(wire::OpenReady {
                        circuit_id: id.clone(),
                    }),
                );
                send(
                    &mut socket,
                    wire::ws_envelope::Body::CircuitEvent(wire::CircuitEvent {
                        circuit_id: id,
                        event: Some(wire::circuit_event::Event::Type1(
                            encode_type1(&[4, 4, 0xaf, marker]).unwrap(),
                        )),
                    }),
                );
            }
            done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitClose(wire::CircuitClose {
                    circuit_id: vec![1; 16],
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitCredit(wire::CircuitCredit {
                    circuit_id: vec![1; 16],
                    allowance_bytes: 1600,
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: vec![2; 16],
                    event: Some(wire::circuit_event::Event::Type1(
                        encode_type1(&[4, 4, 0xaf, 0x33]).unwrap(),
                    )),
                }),
            );
            done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let configs = ["SNAA", "SNAB"]
            .into_iter()
            .map(|cp| Config {
                url: url.clone(),
                bearer: "test-token".into(),
                local_cp: name("SOLNET", cp),
                target_cp: name("SOLNET", if cp == "SNAA" { "PEERA" } else { "PEERB" }),
                target_lu: None,
            })
            .collect();
        let mut ports = WsRoutePort::connect_many(
            configs,
            vec![wire::LuReachability {
                lu: Some(name("SOLNET", "USER1")),
                hosting_cp: Some(name("SOLNET", "SNAB")),
                supported_types: Vec::new(),
            }],
        )
        .unwrap();
        assert!(matches!(
            ports[0].failure_scope(&io_error(transport_ws::Error::Protocol(
                "server closed connection"
            ))),
            FailureScope::SharedTransport
        ));
        assert!(matches!(
            ports[0].failure_scope(&protocol("invalid circuit")),
            FailureScope::Route
        ));
        let mut received = [None, None];
        let mut managed_macs = [None, None];
        let deadline = Instant::now() + Duration::from_secs(2);
        while (received.iter().any(Option::is_none) || managed_macs.iter().any(Option::is_none))
            && Instant::now() < deadline
        {
            for (index, port) in ports.iter_mut().enumerate() {
                if let Some(events) = port.poll(true).unwrap() {
                    for event in events {
                        match event {
                            RouterEvent::Unit(RoutedUnit::DlcType1(pdu)) => {
                                received[index] = Some(pdu[3]);
                            }
                            RouterEvent::ManagedMac(mac) => managed_macs[index] = Some(mac),
                            _ => {}
                        }
                    }
                }
            }
        }
        assert_eq!(received, [Some(0x11), Some(0x22)]);
        assert_eq!(
            managed_macs,
            [
                Some([0x02, 0x53, 0x4e, 0, 0, 1]),
                Some([0x02, 0x53, 0x4e, 0, 0, 2]),
            ]
        );
        done_tx.send(()).unwrap();
        // Pump both frames for circuit 1 through the other logical port,
        // then retire circuit 1. Its queued late credit must be discarded.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut second_marker = None;
        while second_marker.is_none() && Instant::now() < deadline {
            if let Some(events) = ports[1].poll(true).unwrap() {
                for event in events {
                    if let RouterEvent::Unit(RoutedUnit::DlcType1(pdu)) = event {
                        second_marker = Some(pdu[3]);
                    }
                }
            }
        }
        assert_eq!(second_marker, Some(0x33));
        assert!(matches!(
            ports[0].poll(true).unwrap(),
            Some(events) if matches!(events.as_slice(), [RouterEvent::Closed])
        ));
        assert!(ports[0].poll(true).unwrap().is_none());
        done_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn legacy_remote_uses_origin_route_after_empty_managed_snapshot() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(transport_ws::SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let send = |socket: &mut tungstenite::WebSocket<std::net::TcpStream>, body| {
                socket
                    .send(WsMessage::Binary(envelope(body).encode_to_vec().into()))
                    .unwrap();
            };
            send(
                &mut socket,
                wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 65536,
                    max_circuits: 4,
                    display_name: "legacy test".into(),
                    allowed_netid: "SOLNET".into(),
                }),
            );
            let _snapshot = socket.read().unwrap();
            send(
                &mut socket,
                wire::ws_envelope::Body::ManagedCpBindings(wire::ManagedCpBindingSnapshot {
                    schema_version: 1,
                    recipient_epoch: vec![8; 16],
                    revision: 1,
                    bindings: vec![],
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 1,
                        routes: vec![wire::RouteExport {
                            id: 99,
                            generation: 1,
                            resource: Some(wire::route_export::Resource::ControlPoint(name(
                                "SOLNET", "PEERB",
                            ))),
                        }],
                    }),
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("expected open request");
            };
            let request = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::OpenRequest(request)) = request.body else {
                panic!("expected open request");
            };
            assert_eq!(request.target.unwrap().route_id, 99);
        });
        let mut port = WsRoutePort::connect(Config {
            url,
            bearer: "test-token".into(),
            local_cp: name("SOLNET", "SNAA"),
            target_cp: name("SOLNET", "PEERB"),
            target_lu: None,
        })
        .unwrap();
        port.send(RoutedUnit::DlcType1(vec![4, 4, 0xaf])).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !port.opening && Instant::now() < deadline {
            port.poll(true).unwrap();
        }
        assert!(port.opening);
        server.join().unwrap();
    }

    #[test]
    fn cross_netid_target_lu_selects_lu_route_instead_of_host_cp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(transport_ws::SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let send = |socket: &mut tungstenite::WebSocket<std::net::TcpStream>, body| {
                socket
                    .send(WsMessage::Binary(envelope(body).encode_to_vec().into()))
                    .unwrap();
            };
            send(
                &mut socket,
                wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 65536,
                    max_circuits: 4,
                    display_name: "source router".into(),
                    allowed_netid: "SRCNET".into(),
                }),
            );
            let _snapshot = socket.read().unwrap();
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 1,
                        routes: vec![
                            wire::RouteExport {
                                id: 22,
                                generation: 1,
                                resource: Some(wire::route_export::Resource::ControlPoint(name(
                                    "DSTNET", "SNAB",
                                ))),
                            },
                            wire::RouteExport {
                                id: 99,
                                generation: 1,
                                resource: Some(wire::route_export::Resource::LogicalUnit(
                                    wire::LuReachability {
                                        lu: Some(name("DSTNET", "PAYROLL")),
                                        hosting_cp: Some(name("DSTNET", "SNAB")),
                                        supported_types: vec![wire::LuType::LuType62 as i32],
                                    },
                                )),
                            },
                        ],
                    }),
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("expected open request");
            };
            let envelope = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::OpenRequest(request)) = envelope.body else {
                panic!("expected open request");
            };
            assert_eq!(request.target.unwrap().route_id, 99);
        });
        let mut port = WsRoutePort::connect(Config {
            url,
            bearer: "test-token".into(),
            local_cp: name("SRCNET", "SNAA"),
            target_cp: name("DSTNET", "SNAB"),
            target_lu: Some(name("DSTNET", "PAYROLL")),
        })
        .unwrap();
        port.send(RoutedUnit::DlcType1(vec![4, 4, 0xaf])).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !port.opening && Instant::now() < deadline {
            port.poll(true).unwrap();
        }
        assert!(port.opening);
        server.join().unwrap();
    }

    #[test]
    fn v2_gateway_opens_with_local_lu_reference_without_managed_mac() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |request: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    assert_eq!(
                        request.headers()[SEC_WEBSOCKET_PROTOCOL],
                        transport_ws::SUBPROTOCOL_V2
                    );
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(transport_ws::SUBPROTOCOL_V2),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let send = |socket: &mut tungstenite::WebSocket<std::net::TcpStream>, body| {
                socket
                    .send(WsMessage::Binary(envelope(body).encode_to_vec().into()))
                    .unwrap();
            };
            send(
                &mut socket,
                wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 65536,
                    max_circuits: 4,
                    display_name: "v2 gateway".into(),
                    allowed_netid: "QABOB".into(),
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("expected snapshot")
            };
            let published = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::PublishRoutes(snapshot)) = published.body else {
                panic!("expected route snapshot")
            };
            let source_lu = snapshot.routes.iter().find(|route| matches!(route.resource.as_ref(),
                Some(wire::route_export::Resource::LogicalUnit(export)) if export.lu.as_ref() == Some(&name("QABOB", "LUB")))).unwrap();
            let source_id = source_lu.id;
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 1,
                        routes: vec![wire::RouteExport {
                            id: 99,
                            generation: 1,
                            resource: Some(wire::route_export::Resource::LogicalUnit(
                                wire::LuReachability {
                                    lu: Some(name("QAALICE", "LUA")),
                                    hosting_cp: Some(name("QAALICE", "SNAA")),
                                    supported_types: vec![wire::LuType::LuType62 as i32],
                                },
                            )),
                        }],
                    }),
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("expected open")
            };
            let opened = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::OpenRequest(open)) = opened.body else {
                panic!("expected open request")
            };
            assert_eq!(open.target.unwrap().route_id, 99);
            let source = open.source_route.unwrap();
            assert_eq!(source.router_id, vec![7; 16]);
            assert_eq!(source.epoch, vec![8; 16]);
            assert_eq!(source.route_id, source_id);
        });
        let source_lu = name("QABOB", "LUB");
        let mut port = WsRoutePort::connect_gateway_v2(
            Config {
                url,
                bearer: "test-token".into(),
                local_cp: name("QABOB", "SNAB"),
                target_cp: name("QAALICE", "SNAA"),
                target_lu: Some(name("QAALICE", "LUA")),
            },
            vec![wire::LuReachability {
                lu: Some(source_lu.clone()),
                hosting_cp: Some(name("QABOB", "SNAB")),
                supported_types: vec![wire::LuType::LuType62 as i32],
            }],
            source_lu,
        )
        .unwrap();
        port.send(RoutedUnit::DlcType1(vec![4, 4, 0xaf])).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !port.opening && Instant::now() < deadline {
            port.poll(true).unwrap();
        }
        assert!(port.opening);
        server.join().unwrap();
    }

    #[test]
    fn local_snapshot_exports_cp_and_lu_with_stable_distinct_ids() {
        let primary = name("SOLNET", "SNAA");
        let cp_b = name("SOLNET", "SNAB");
        let cp_c = name("SOLNET", "SNAC");
        let lu = wire::LuReachability {
            lu: Some(name("SOLNET", "USER1")),
            hosting_cp: Some(cp_b.clone()),
            supported_types: Vec::new(),
        };
        let first = local_route_snapshot(
            &[7; 16],
            1,
            &primary,
            &[cp_b.clone(), cp_c.clone()],
            std::slice::from_ref(&lu),
        )
        .unwrap();
        let reordered = local_route_snapshot(
            &[7; 16],
            2,
            &primary,
            &[cp_c, cp_b],
            std::slice::from_ref(&lu),
        )
        .unwrap();
        assert_eq!(first.routes, reordered.routes);
        assert_eq!(first.routes[0].id, 1);
        assert_eq!(first.routes.len(), 4);
        assert_eq!(
            first
                .routes
                .iter()
                .map(|r| r.id)
                .collect::<HashSet<_>>()
                .len(),
            4
        );
        assert!(first.routes.iter().any(|r| matches!(
            &r.resource,
            Some(wire::route_export::Resource::LogicalUnit(value)) if value == &lu
        )));
    }

    #[test]
    fn local_snapshot_rejects_duplicate_or_invalid_exports() {
        let primary = name("SOLNET", "SNAA");
        let lu = wire::LuReachability {
            lu: Some(name("SOLNET", "USER1")),
            hosting_cp: None,
            supported_types: Vec::new(),
        };
        assert!(local_route_snapshot(&[0; 15], 1, &primary, &[], &[]).is_err());
        assert!(local_route_snapshot(&[0; 16], 0, &primary, &[], &[]).is_err());
        assert!(
            local_route_snapshot(&[0; 16], 1, &primary, std::slice::from_ref(&primary), &[])
                .is_err()
        );
        assert!(local_route_snapshot(&[0; 16], 1, &primary, &[], &[lu.clone(), lu]).is_err());
        assert!(local_route_snapshot(
            &[0; 16],
            1,
            &primary,
            &[],
            &[wire::LuReachability {
                lu: None,
                hosting_cp: None,
                supported_types: Vec::new(),
            }]
        )
        .is_err());
        assert!(
            local_route_snapshot(&[0; 16], 1, &primary, &[name("OTHER", "SNAB")], &[]).is_err()
        );
        assert!(local_route_snapshot(
            &[0; 16],
            1,
            &primary,
            &[],
            &[wire::LuReachability {
                lu: Some(name("OTHER", "USER1")),
                hosting_cp: Some(primary.clone()),
                supported_types: Vec::new(),
            }]
        )
        .is_err());
        assert!(local_route_snapshot(
            &[0; 16],
            1,
            &primary,
            &[],
            &[wire::LuReachability {
                lu: Some(name("SOLNET", "USER1")),
                hosting_cp: Some(name("SOLNET", "OTHERCP")),
                supported_types: Vec::new(),
            }]
        )
        .is_err());
        assert!(local_route_snapshot(
            &[0; 16],
            1,
            &primary,
            &[],
            &[wire::LuReachability {
                lu: Some(name("SOLNET", "1BAD")),
                hosting_cp: Some(primary.clone()),
                supported_types: Vec::new(),
            }]
        )
        .is_err());
    }

    #[test]
    fn type1_roundtrip_preserves_xid3_bytes_and_flags() {
        for pdu in [vec![4, 4, 0xbf, 0x81, 0x10, 0x20], vec![4, 5, 0xf3, 0x37]] {
            assert_eq!(decode_type1(encode_type1(&pdu).unwrap()).unwrap(), pdu);
        }
    }

    #[test]
    fn validates_cp_components() {
        assert!(validate_name(&wire::SnaName {
            netid: "SOLNET".into(),
            name: "SNAA".into()
        })
        .is_ok());
        assert!(validate_name(&wire::SnaName {
            netid: "TOO-LONG-9".into(),
            name: "SNAA".into()
        })
        .is_err());
    }

    #[test]
    fn validates_managed_virtual_mac_namespace_and_uniqueness() {
        let binding = |mac: &[u8]| wire::ManagedCpBinding {
            address_id: vec![1; 16],
            control_point: Some(name("SOLNET", "PEERA")),
            virtual_mac: mac.to_vec(),
            candidates: vec![],
        };
        let valid = binding(&[0x02, 0x53, 0x4e, 0, 0, 1]);
        assert!(validate_managed_bindings(&[valid.clone()]).is_ok());
        assert!(validate_managed_bindings(&[valid.clone(), valid.clone()]).is_err());
        assert!(validate_managed_bindings(&[binding(&[0x02, 0x53, 0x4f, 0, 0, 1])]).is_err());
        let mut duplicate_cp = binding(&[0x02, 0x53, 0x4e, 0, 0, 2]);
        duplicate_cp.address_id = vec![2; 16];
        assert!(validate_managed_bindings(&[valid.clone(), duplicate_cp]).is_err());
        let mut duplicate_id = binding(&[0x02, 0x53, 0x4e, 0, 0, 2]);
        duplicate_id.control_point = Some(name("SOLNET", "PEERB"));
        assert!(validate_managed_bindings(&[valid.clone(), duplicate_id]).is_err());
        let mut missing_cp = valid.clone();
        missing_cp.control_point = None;
        assert!(validate_managed_bindings(&[missing_cp]).is_err());
        let mut short_id = valid;
        short_id.address_id.pop();
        assert!(validate_managed_bindings(&[short_id]).is_err());
    }

    #[test]
    fn duplicate_managed_cp_snapshot_is_rejected_before_a_route_can_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(transport_ws::SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            socket
                .send(WsMessage::Binary(
                    envelope(wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                        router_id: vec![7; 16],
                        connection_epoch: vec![8; 16],
                        max_message_bytes: 65536,
                        max_circuits: 1,
                        display_name: "test router".into(),
                        allowed_netid: "SOLNET".into(),
                    }))
                    .encode_to_vec()
                    .into(),
                ))
                .unwrap();
            let WsMessage::Binary(_) = socket.read().unwrap() else {
                panic!("expected published local routes");
            };
            let binding = |id, mac| wire::ManagedCpBinding {
                address_id: vec![id; 16],
                control_point: Some(name("SOLNET", "PEERA")),
                virtual_mac: vec![0x02, 0x53, 0x4e, 0, 0, mac],
                candidates: vec![],
            };
            socket
                .send(WsMessage::Binary(
                    envelope(wire::ws_envelope::Body::ManagedCpBindings(
                        wire::ManagedCpBindingSnapshot {
                            schema_version: 1,
                            recipient_epoch: vec![8; 16],
                            revision: 1,
                            bindings: vec![binding(1, 1), binding(2, 2)],
                        },
                    ))
                    .encode_to_vec()
                    .into(),
                ))
                .unwrap();
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let mut port = WsRoutePort::connect_many(
            vec![Config {
                url,
                bearer: "test-token".into(),
                local_cp: name("SOLNET", "SNAA"),
                target_cp: name("SOLNET", "PEERA"),
                target_lu: None,
            }],
            vec![],
        )
        .unwrap()
        .remove(0);
        let deadline = Instant::now() + Duration::from_secs(2);
        let error = loop {
            if let Err(error) = port.poll(true) {
                break error;
            }
            assert!(
                Instant::now() < deadline,
                "invalid managed snapshot was accepted"
            );
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(port.managed_mac.is_none());
        assert!(port.target.is_none());
        done_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn managed_binding_revisions_cannot_replay_or_regress() {
        let mut last = 0;
        assert!(accept_managed_revision(&mut last, 0).is_err());
        assert_eq!(last, 0);
        accept_managed_revision(&mut last, 1).unwrap();
        accept_managed_revision(&mut last, 2).unwrap();
        assert!(accept_managed_revision(&mut last, 2).is_err());
        assert!(accept_managed_revision(&mut last, 1).is_err());
        assert_eq!(last, 2);
        accept_managed_revision(&mut last, 3).unwrap();
    }

    #[test]
    fn logged_server_authority_excludes_url_query() {
        assert_eq!(
            server_authority("wss://concentrator.example:443/router/v1/ws?private=value"),
            "concentrator.example:443"
        );
        assert_eq!(
            server_authority("ws://[::1]:18743/router/v1/ws"),
            "[::1]:18743"
        );
        assert_eq!(
            server_authority("ws://127.0.0.1:18743?token=secret"),
            "127.0.0.1:18743"
        );
    }
}
