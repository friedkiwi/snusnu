//! WebSocket circuit adapter. The routing core sees the same SNA units as it
//! does on a local LLC port; only this module knows the concentrator protocol.

use crate::{
    local_status::{self, CircuitStatus, ConcentratorStatus},
    routing::{FailureScope, RouteAddress, RoutePort, RoutedUnit, RouterEvent},
};
use router_core::packet_log::{decode_llc_pdu, decode_sna_information, hex_dump};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    io,
    rc::Rc,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};
use transport_ws::{wire, WsClient};

const INITIAL_ALLOWANCE: u64 = 1500;
const MAX_PENDING_EVENTS: usize = INITIAL_ALLOWANCE as usize;
const MAX_PENDING_TYPE1: usize = 16;
const MAX_CLOSED_IDS: usize = 64;
const MAX_PENDING_AUTO_OPENS: usize = 64;
const FIRST_OPEN_RETRY: Duration = Duration::from_millis(500);
const MAX_OPEN_RETRY: Duration = Duration::from_secs(30);

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

/// A concentrator circuit accepted for a locally hosted LU. The runtime can
/// use this identity to start the matching outbound MPTN session.
#[derive(Clone, Debug)]
pub(crate) struct InboundOpen {
    pub(crate) circuit_id: Vec<u8>,
    pub(crate) source_router_id: Vec<u8>,
    pub(crate) source_route: wire::RouteReference,
}

struct GatewayInbound {
    hosted_route: wire::RouteReference,
    target_refs: Vec<Option<wire::RouteReference>>,
    /// Duplex gateways reserve one private port for concentrator-initiated
    /// circuits, even though both ports select the same remote LU.
    inbound_owner: Option<usize>,
}

impl GatewayInbound {
    fn owner(&self, open: &wire::IncomingOpen) -> Option<usize> {
        if open.target.as_ref() != Some(&self.hosted_route) {
            return None;
        }
        let source = open.source_route.as_ref()?;
        if source.router_id != open.source_router_id {
            return None;
        }
        if let Some(owner) = self.inbound_owner {
            self.target_refs
                .get(owner)?
                .as_ref()
                .filter(|known| *known == source)
                .map(|_| owner)
        } else {
            self.target_refs
                .iter()
                .position(|known| known.as_ref() == Some(source))
        }
    }
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
    gateway_inbound: Option<GatewayInbound>,
    auto_directory: Option<Rc<RefCell<AutoDirectory>>>,
    auto_incoming: VecDeque<wire::IncomingOpen>,
    auto_local_route_ids: HashSet<u64>,
    auto_free_indexes: Vec<usize>,
}

impl Drop for SharedWs {
    fn drop(&mut self) {
        if let Some(status) = crate::status() {
            let snapshot = status.snapshot();
            for origin in snapshot
                .upstream_routes
                .iter()
                .map(|route| &route.origin_router_id)
            {
                status.withdraw_origin(origin);
            }
            status.replace_managed_macs(Vec::new());
            remove_owned_circuit_status(status, &self.circuit_owners);
            if let Some(mut concentrator) = snapshot.concentrator {
                concentrator.state = "disconnected".into();
                concentrator.connection_epoch = None;
                concentrator.last_change_ms = local_status::now_ms();
                status.set_concentrator(Some(concentrator));
            }
        }
    }
}

fn remove_owned_circuit_status(
    status: &local_status::LocalStatus,
    circuit_owners: &HashMap<Vec<u8>, usize>,
) {
    for id in circuit_owners.keys() {
        status.remove_circuit(&format_uuid(id));
    }
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
                debug!(
                    request_id = result.request_id,
                    owner = index,
                    remaining = self.inbox[index].len(),
                    "dequeued concentrator circuit OpenResult"
                );
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
            Body::OriginRoutes(origin) => {
                if origin.router_id.len() != 16
                    || origin
                        .snapshot
                        .as_ref()
                        .is_none_or(|snapshot| snapshot.epoch.len() != 16)
                {
                    return Err(protocol("invalid origin route snapshot"));
                }
                if let Some(status) = crate::status() {
                    status.observe_origin_snapshot(origin);
                }
                if let Some(directory) = &self.auto_directory {
                    directory.borrow_mut().replace_origin(origin)?;
                }
                for inbox in &mut self.inbox {
                    inbox.push_back(body.clone());
                }
            }
            Body::OriginWithdraw(withdraw) => {
                if let Some(status) = crate::status() {
                    status.withdraw_origin_bytes(&withdraw.router_id);
                }
                if let Some(directory) = &self.auto_directory {
                    directory.borrow_mut().withdraw(withdraw)?;
                }
                for inbox in &mut self.inbox {
                    inbox.push_back(body.clone());
                }
            }
            Body::ManagedCpBindings(bindings) => {
                accept_managed_revision(&mut self.last_managed_revision, bindings.revision)?;
                validate_managed_bindings(&bindings.bindings)?;
                if let Some(status) = crate::status() {
                    status.observe_managed_snapshot(bindings);
                }
                if let Some(directory) = &self.auto_directory {
                    directory.borrow_mut().replace_managed(bindings)?;
                }
                for inbox in &mut self.inbox {
                    inbox.push_back(body.clone());
                }
            }
            Body::IncomingOpen(open) => {
                if self.auto_directory.is_some()
                    && open
                        .target
                        .as_ref()
                        .is_some_and(|target| self.auto_local_route_ids.contains(&target.route_id))
                {
                    if self.auto_incoming.len() < MAX_PENDING_AUTO_OPENS {
                        self.auto_incoming.push_back(open.clone());
                    } else {
                        warn!(circuit_id = %format_uuid(&open.circuit_id),
                            "automatic incoming circuit queue is full");
                        self.client
                            .send(envelope(Body::OpenDecision(wire::OpenDecision {
                                circuit_id: open.circuit_id.clone(),
                                accept: false,
                                receive_allowance_bytes: 0,
                                reason: wire::OpenFailure::Busy as i32,
                            })))
                            .map_err(io_error)?;
                    }
                    return Ok(true);
                }
                let owner = if let Some(gateway) = &self.gateway_inbound {
                    gateway.owner(open)
                } else {
                    open.target
                        .as_ref()
                        .and_then(|route| self.route_owners.get(&route.route_id))
                        .copied()
                };
                if let Some(owner) = owner {
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
                    debug!(
                        request_id = result.request_id,
                        owner,
                        accepted = result.accepted,
                        inbox_depth = self.inbox[owner].len(),
                        "received concentrator circuit OpenResult"
                    );
                    self.inbox[owner].push_back(body);
                } else if self.closed_requests.contains(&result.request_id) {
                    debug!(
                        request_id = result.request_id,
                        accepted = result.accepted,
                        "received late concentrator circuit OpenResult"
                    );
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
    retired_target_epochs: HashSet<Vec<u8>>,
    source_route: Option<wire::RouteReference>,
    profile: wire::CircuitProfile,
    require_managed_binding: bool,
    managed_binding_seen: bool,
    managed_mac: Option<[u8; 6]>,
    circuit: Option<Circuit>,
    opening: bool,
    local_ready: bool,
    request_id: u64,
    retry_at: Option<Instant>,
    retry_delay: Duration,
    pending_type1: VecDeque<Vec<u8>>,
    pending_information: VecDeque<Vec<u8>>,
    pending_session: VecDeque<(wire::SessionEvent, usize)>,
    // Each unit forwarded into the LLC endpoint remains retained here until
    // that endpoint's ACK releases its queue/pending I-frame slot.
    downstream_sizes: VecDeque<usize>,
    // A-side CircuitCredit is issued by the remote LLC adapter only after
    // information delivery. Account by exact PIU lengths, not socket writes.
    outbound_completions: OutboundCompletions,
    inbound_open: Option<InboundOpen>,
    auto_owned: bool,
}

/// One authenticated, carrier-neutral LU session on the automatic hub's
/// existing WebSocket. The link adapter owns RTP and local pacing; this port
/// owns only ordered session events and circuit byte credit.
#[allow(dead_code)] // The automatic HPR runtime will own this port after endpoint activation.
pub(crate) struct SessionWsPort {
    inner: WsRoutePort,
    opened_reported: bool,
}

#[allow(dead_code)]
pub(crate) enum SessionWsUpdate {
    Opened,
    Event(wire::SessionEvent),
    Closed,
}

#[allow(dead_code)]
impl SessionWsPort {
    pub(crate) fn is_open(&self) -> bool {
        self.inner.circuit.as_ref().is_some_and(|c| c.ready)
    }

    pub(crate) fn poll(&mut self) -> io::Result<Option<SessionWsUpdate>> {
        self.inner.maybe_open()?;
        let result = RoutePort::poll(&mut self.inner, true)?;
        if let Some((event, cost)) = self.inner.pending_session.pop_front() {
            if cost != 0 {
                self.inner.downstream_sizes.push_back(cost);
            }
            return Ok(Some(SessionWsUpdate::Event(event)));
        }
        if result.as_ref().is_some_and(|events| {
            events
                .iter()
                .any(|event| matches!(event, RouterEvent::Closed))
        }) {
            self.opened_reported = false;
            return Ok(Some(SessionWsUpdate::Closed));
        }
        if self.is_open() && !self.opened_reported {
            self.opened_reported = true;
            return Ok(Some(SessionWsUpdate::Opened));
        }
        Ok(None)
    }

    /// False means the circuit is not ready or its byte allowance is full.
    /// Pacing-credit events consume no circuit byte allowance.
    pub(crate) fn send(&mut self, event: wire::SessionEvent) -> io::Result<bool> {
        let cost = session_event_cost(&event)?;
        let Some(circuit) = self.inner.circuit.as_ref().filter(|c| c.ready) else {
            return Ok(false);
        };
        if circuit.sent_bytes.saturating_add(cost as u64) > circuit.send_allowance {
            return Ok(false);
        }
        self.inner
            .send_event(wire::circuit_event::Event::SessionEvent(event))?;
        if let Some(circuit) = self.inner.circuit.as_mut() {
            circuit.sent_bytes += cost as u64;
        }
        if cost != 0 {
            self.inner.outbound_completions.sent(cost)?;
        }
        self.inner.record_circuit_status();
        Ok(true)
    }

    /// Grant byte allowance after the destination adapter has accepted the
    /// corresponding nonempty session units. Zero-cost pacing events need no
    /// completion call.
    pub(crate) fn complete_received(&mut self, count: usize) -> io::Result<()> {
        self.inner.on_downstream_completed(count)
    }

    pub(crate) fn take_completed_send_count(&mut self) -> usize {
        self.inner.outbound_completions.take_completed()
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.inner.disconnect()
    }
}

impl Drop for WsRoutePort {
    fn drop(&mut self) {
        if !self.auto_owned {
            return;
        }
        let _ = self.disconnect();
        if let Ok(mut shared) = self.shared.try_borrow_mut() {
            shared.inbox[self.index].clear();
            shared.auto_free_indexes.push(self.index);
        }
    }
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
    fn sync_gateway_target(&self) {
        if let Some(gateway) = self.shared.borrow_mut().gateway_inbound.as_mut() {
            gateway.target_refs[self.index] = self.target.clone();
        }
    }

    /// Return the authenticated source of a newly accepted inbound v2
    /// circuit. The circuit remains owned by this port and subject to its
    /// normal credit and close handling.
    pub(crate) fn take_inbound_open(&mut self) -> Option<InboundOpen> {
        self.inbound_open.take()
    }

    pub(crate) fn connect(config: Config) -> io::Result<Self> {
        Ok(Self::connect_many_with_mode(vec![config], vec![], false, None, false)?.remove(0))
    }

    pub(crate) fn connect_many(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
    ) -> io::Result<Vec<Self>> {
        Self::connect_many_with_mode(configs, logical_units, true, None, false)
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
            false,
        )?
        .remove(0))
    }

    /// Publish one hosted LU while opening separate v2 circuits to several
    /// destination LUs. Every returned port owns its own circuit and credit,
    /// but all ports use one WebSocket and the same authenticated source LU.
    /// Incoming opens for the published LU select the port whose live target
    /// route matches the authenticated source route.
    pub(crate) fn connect_gateway_targets_v2(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
        source_lu: wire::SnaName,
    ) -> io::Result<Vec<Self>> {
        if configs.is_empty() || configs.iter().any(|config| config.target_lu.is_none()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway targets require target LUs",
            ));
        }
        let local_cp = &configs[0].local_cp;
        if logical_units.len() != 1
            || logical_units[0].lu.as_ref() != Some(&source_lu)
            || logical_units[0].hosting_cp.as_ref() != Some(local_cp)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway targets require one source LU export under the local CP",
            ));
        }
        if configs.iter().any(|config| &config.local_cp != local_cp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway targets must share one local CP",
            ));
        }
        let mut targets = HashSet::new();
        if configs
            .iter()
            .any(|config| !targets.insert(config.target_lu.clone().unwrap()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate gateway target LU",
            ));
        }
        let source_lus = vec![Some(source_lu); configs.len()];
        Self::connect_many_with_mode(configs, logical_units, false, Some(source_lus), true)
    }

    /// A single hosted LU with separate circuit and credit owners for each
    /// initiation direction. Both ports share the WebSocket and publication;
    /// only the second port can accept an authenticated IncomingOpen.
    pub(crate) fn connect_gateway_duplex_v2(
        config: Config,
        logical_units: Vec<wire::LuReachability>,
        source_lu: wire::SnaName,
    ) -> io::Result<(Self, Self)> {
        if config.target_lu.is_none()
            || logical_units.len() != 1
            || logical_units[0].lu.as_ref() != Some(&source_lu)
            || logical_units[0].hosting_cp.as_ref() != Some(&config.local_cp)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplex gateway requires one hosted LU and a target LU",
            ));
        }
        let ports = Self::connect_many_with_mode(
            vec![config.clone(), config],
            logical_units,
            false,
            Some(vec![Some(source_lu.clone()), Some(source_lu)]),
            true,
        )?;
        ports[0]
            .shared
            .borrow_mut()
            .gateway_inbound
            .as_mut()
            .expect("shared gateway created")
            .inbound_owner = Some(1);
        let mut ports = ports.into_iter();
        Ok((ports.next().unwrap(), ports.next().unwrap()))
    }

    /// LLC-facing v2 ports may receive source-LU authenticated opens while
    /// still requiring the managed CP address binding on their local link.
    pub(crate) fn connect_many_v2(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
        source_lus: Vec<Option<wire::SnaName>>,
    ) -> io::Result<Vec<Self>> {
        Self::connect_many_with_mode(configs, logical_units, true, Some(source_lus), false)
    }

    fn connect_many_with_mode(
        configs: Vec<Config>,
        logical_units: Vec<wire::LuReachability>,
        require_managed_binding: bool,
        source_lus: Option<Vec<Option<wire::SnaName>>>,
        shared_local_cp: bool,
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
            WsClient::connect_v2_with_identity(
                &primary.url,
                &primary.bearer,
                "sna_router",
                env!("CARGO_PKG_VERSION"),
            )
        } else {
            WsClient::connect_with_identity(
                &primary.url,
                &primary.bearer,
                "sna_router",
                env!("CARGO_PKG_VERSION"),
            )
        }
        .map_err(|error| {
            if let Some(status) = crate::status() {
                status.set_concentrator(Some(ConcentratorStatus {
                    state: "disconnected".into(),
                    authority: server_authority(&primary.url).into(),
                    router_id: None,
                    allowed_netid: None,
                    connection_epoch: None,
                    last_change_ms: local_status::now_ms(),
                    last_error: Some("connection failed; see router logs".into()),
                }));
            }
            io_error(error)
        })?;
        if let Some(update) = &welcome.software_update_available {
            tracing::warn!(current_version = env!("CARGO_PKG_VERSION"), latest_version = %update.latest_version, "sna_router software update available");
        }
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
        let additional_cps = configs[1..]
            .iter()
            .map(|config| config.local_cp.clone())
            .filter(|cp| !shared_local_cp || cp != &primary.local_cp)
            .collect::<Vec<_>>();
        let snapshot = local_route_snapshot(
            &welcome.connection_epoch,
            1,
            &primary.local_cp,
            &additional_cps,
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
        let gateway_inbound = if shared_local_cp {
            let hosted_route = source_routes
                .as_ref()
                .and_then(|routes| routes[0].clone())
                .ok_or_else(|| protocol("gateway source LU route is absent"))?;
            for ids in &mut local_route_ids {
                ids.clear();
                ids.insert(hosted_route.route_id);
            }
            Some(GatewayInbound {
                hosted_route,
                target_refs: vec![None; configs.len()],
                inbound_owner: None,
            })
        } else {
            None
        };
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
            gateway_inbound,
            auto_directory: None,
            auto_incoming: VecDeque::new(),
            auto_local_route_ids: HashSet::new(),
            auto_free_indexes: Vec::new(),
        }));
        if let Some(status) = crate::status() {
            status.set_concentrator(Some(ConcentratorStatus {
                state: "connected".into(),
                authority: server_authority(&primary.url).into(),
                router_id: Some(format_uuid(&welcome.router_id)),
                allowed_netid: Some(welcome.allowed_netid.clone()),
                connection_epoch: Some(format_uuid(&welcome.connection_epoch)),
                last_change_ms: local_status::now_ms(),
                last_error: None,
            }));
        }
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
                retired_target_epochs: HashSet::new(),
                source_route: source_routes
                    .as_ref()
                    .and_then(|routes| routes[index].clone()),
                profile: wire::CircuitProfile::NativeDlc,
                require_managed_binding,
                managed_binding_seen: false,
                managed_mac: None,
                circuit: None,
                opening: false,
                local_ready: false,
                request_id: 0,
                retry_at: None,
                retry_delay: FIRST_OPEN_RETRY,
                pending_type1: VecDeque::new(),
                pending_information: VecDeque::new(),
                pending_session: VecDeque::new(),
                downstream_sizes: VecDeque::new(),
                outbound_completions: OutboundCompletions::default(),
                inbound_open: None,
                auto_owned: false,
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
            || (self.profile == wire::CircuitProfile::NativeDlc && self.pending_type1.is_empty())
            || self.retry_at.is_some_and(|at| Instant::now() < at)
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
            profile: self.profile as i32,
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
                if self.auto_owned {
                    // A destination can withdraw an exclusive LU while its
                    // accepted circuit owns the local attachment. That
                    // withdrawal only blocks new opens; the concentrator
                    // controls the lifetime of this established circuit.
                    if self.circuit.is_some() {
                        return Ok(Vec::new());
                    }
                    // A SessionV1 source may have opened just as the selected
                    // router disconnected. Keep its owner identity while the
                    // WebSocket stays up, so a fresh epoch can be selected
                    // without discarding the local TCP62 session.
                    if self.target_lu.is_some() && self.inbound_open.is_none() {
                        let Some(current) = self.target.as_ref() else {
                            return Ok(Vec::new());
                        };
                        if current.router_id != origin.router_id {
                            return Ok(Vec::new());
                        }
                        if self.retired_target_epochs.contains(&snapshot.epoch) {
                            debug!(origin_router_id = %format_uuid(&origin.router_id),
                                origin_epoch = %format_uuid(&snapshot.epoch),
                                "ignoring retired target route epoch");
                            return Ok(Vec::new());
                        }
                        let next = snapshot
                            .routes
                            .iter()
                            .find(|route| self.matches_target_route(route))
                            .map(|route| wire::RouteReference {
                                router_id: origin.router_id.clone(),
                                epoch: snapshot.epoch.clone(),
                                route_id: route.id,
                                route_generation: route.generation,
                            });
                        if self.target.as_ref() != next.as_ref() {
                            if next
                                .as_ref()
                                .is_some_and(|route| route.epoch != current.epoch)
                            {
                                self.retired_target_epochs.insert(current.epoch.clone());
                            }
                            if self.circuit.is_some() {
                                self.disconnect()?;
                                return Ok(vec![RouterEvent::Closed]);
                            }
                            if self.opening {
                                self.clear_circuit();
                            }
                            if let Some(next) = next {
                                self.target = Some(next);
                                self.retry_at = None;
                                self.maybe_open()?;
                            } else {
                                self.retry_at = Some(Instant::now() + Duration::from_secs(30));
                            }
                        }
                        return Ok(Vec::new());
                    }
                    let target_gone = self.target.as_ref().is_some_and(|target| {
                        target.router_id == origin.router_id
                            && target.epoch == snapshot.epoch
                            && !snapshot.routes.iter().any(|route| {
                                route.id == target.route_id
                                    && route.generation == target.route_generation
                            })
                    });
                    if target_gone {
                        self.target = None;
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                    return Ok(Vec::new());
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
                    self.sync_gateway_target();
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
                    self.sync_gateway_target();
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
                if self.auto_owned && self.circuit.is_some() {
                    return Ok(Vec::new());
                }
                if !self.auto_owned
                    && self.target_lu.is_none()
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
                    let retryable_auto_lu = self.auto_owned
                        && self.target_lu.is_some()
                        && self.inbound_open.is_none()
                        && self.circuit.is_none();
                    if !retryable_auto_lu {
                        self.target = None;
                        self.sync_gateway_target();
                    }
                    if self.circuit.is_some() {
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                    if self.opening {
                        self.clear_circuit();
                    }
                    if retryable_auto_lu {
                        self.retired_target_epochs.insert(withdraw.epoch.clone());
                        self.retry_at = Some(Instant::now() + Duration::from_secs(30));
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
                if self.auto_owned {
                    if self.target_lu.is_some() {
                        return Ok(Vec::new());
                    }
                    let binding = bindings
                        .bindings
                        .iter()
                        .find(|binding| binding.control_point.as_ref() == Some(&self.target_cp));
                    let authorized = binding.is_some_and(|binding| {
                        self.target.as_ref().is_some_and(|target| {
                            binding
                                .candidates
                                .iter()
                                .any(|candidate| candidate == target)
                        })
                    });
                    if !authorized {
                        self.managed_mac = None;
                        self.disconnect()?;
                        return Ok(vec![RouterEvent::Closed]);
                    }
                    let mac: [u8; 6] = binding
                        .unwrap()
                        .virtual_mac
                        .as_slice()
                        .try_into()
                        .map_err(|_| protocol("invalid managed virtual MAC"))?;
                    if self.managed_mac.replace(mac) != Some(mac) {
                        return Ok(vec![RouterEvent::ManagedMac(mac)]);
                    }
                    return Ok(Vec::new());
                }
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
                    // A route selected by target LU does not depend on the
                    // CP's virtual LLC MAC. Its binding can arrive during an
                    // Open without invalidating that request.
                    let changed = target_changed
                        || (self.target_lu.is_none() && self.managed_mac != Some(mac));
                    if self.target_lu.is_none() {
                        self.target = next_target;
                        self.sync_gateway_target();
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
                        self.sync_gateway_target();
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
                self.record_circuit_status();
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
            incoming.source_route.as_ref() == self.target.as_ref()
                && incoming
                    .source_route
                    .as_ref()
                    .is_some_and(|r| r.router_id == incoming.source_router_id)
        } else {
            incoming.source_route.is_none()
        };
        let accept = target_ok
            && source_ok
            && incoming.profile == self.profile as i32
            && self.circuit.is_none()
            && !self.opening
            && (!self.require_managed_binding || self.managed_mac.is_some());
        let reason = if accept {
            wire::OpenFailure::Unspecified
        } else if incoming.profile != self.profile as i32 {
            wire::OpenFailure::Unsupported
        } else if v2
            && self.target_lu.is_some()
            && self.target.is_none()
            && incoming.source_route.as_ref().is_some_and(|r| {
                r.router_id == incoming.source_router_id
                    && r.epoch.len() == 16
                    && r.route_id != 0
                    && r.route_generation != 0
            })
        {
            // The Go hub has validated this source LU, but this router may
            // receive IncomingOpen before its reciprocal OriginRoutes.
            wire::OpenFailure::RouteGone
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
            if let Some(source_route) = incoming.source_route.clone() {
                self.inbound_open = Some(InboundOpen {
                    circuit_id: incoming.circuit_id.clone(),
                    source_router_id: incoming.source_router_id.clone(),
                    source_route,
                });
            }
            self.circuit = Some(Circuit {
                id: incoming.circuit_id,
                ready: false,
                send_allowance: incoming.source_receive_allowance_bytes,
                sent_bytes: 0,
                receive_allowance: INITIAL_ALLOWANCE,
                received_bytes: 0,
            });
            self.record_circuit_status();
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
            if self.shared.borrow().client.subprotocol() == transport_ws::SUBPROTOCOL_V2
                && retryable_open_failure(result.reason)
            {
                let delay = self.retry_delay;
                self.retry_at = Some(Instant::now() + delay);
                self.retry_delay = delay.saturating_mul(2).min(MAX_OPEN_RETRY);
                info!(
                    request_id = result.request_id,
                    retry_ms = delay.as_millis(),
                    "retrying transient v2 circuit open"
                );
            } else {
                self.pending_type1.clear();
                self.retry_at = None;
                self.retry_delay = FIRST_OPEN_RETRY;
            }
            return Ok(());
        }
        self.retry_at = None;
        self.retry_delay = FIRST_OPEN_RETRY;
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
        self.record_circuit_status();
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
                self.record_circuit_status();
                Ok(Vec::new())
            }
            wire::circuit_event::Event::SessionEvent(session) => {
                if self.profile != wire::CircuitProfile::SessionV1 {
                    return Err(protocol("session event on native circuit"));
                }
                let cost = session_event_cost(&session)?;
                if self.pending_session.len() >= MAX_PENDING_EVENTS {
                    return Err(protocol("session event backlog full"));
                }
                let circuit = self.checked_circuit_mut(&event.circuit_id)?;
                if circuit.received_bytes.saturating_add(cost as u64) > circuit.receive_allowance {
                    return Err(protocol("session event exceeds receive allowance"));
                }
                circuit.received_bytes += cost as u64;
                self.pending_session.push_back((session, cost));
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

    fn record_circuit_status(&self) {
        let (Some(status), Some(circuit)) = (crate::status(), self.circuit.as_ref()) else {
            return;
        };
        let (ingress, egress) = if let Some(inbound) = self
            .inbound_open
            .as_ref()
            .filter(|inbound| inbound.circuit_id == circuit.id)
        {
            (
                format!("router {}", format_uuid(&inbound.source_router_id)),
                format!("local {}", format_cp(&self.local_cp)),
            )
        } else {
            (
                format!("local {}", format_cp(&self.local_cp)),
                format!("concentrator {}", format_cp(&self.target_cp)),
            )
        };
        status.upsert_circuit(CircuitStatus {
            id: format_uuid(&circuit.id),
            ingress,
            egress,
            state: if circuit.ready { "ready" } else { "opening" }.into(),
            bytes_in: circuit.received_bytes,
            bytes_out: circuit.sent_bytes,
            last_change_ms: local_status::now_ms(),
        });
    }

    fn clear_circuit(&mut self) {
        let mut shared = self.shared.borrow_mut();
        if let Some(circuit) = &self.circuit {
            shared.retire_circuit(&circuit.id);
            if let Some(status) = crate::status() {
                status.remove_circuit(&format_uuid(&circuit.id));
            }
        }
        if self.opening {
            shared.retire_request(self.request_id);
        }
        drop(shared);
        self.circuit = None;
        self.opening = false;
        self.pending_type1.clear();
        self.pending_information.clear();
        self.pending_session.clear();
        self.downstream_sizes.clear();
        self.outbound_completions = OutboundCompletions::default();
        self.local_ready = false;
        self.inbound_open = None;
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
                self.record_circuit_status();
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
            if let Some(status) = crate::status() {
                status.remove_circuit(&format_uuid(&circuit.id));
            }
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

fn session_event_cost(event: &wire::SessionEvent) -> io::Result<usize> {
    use wire::session_event::Event;
    let reduced = match event
        .event
        .as_ref()
        .ok_or_else(|| protocol("empty session event"))?
    {
        Event::BindRequest(unit) | Event::Unbind(unit) => {
            if unit.len() <= 5 {
                return Err(protocol("session control has no RU"));
            }
            Some(unit.as_slice())
        }
        Event::BindResult(result) => Some(result.reduced_unit.as_slice()),
        Event::Information(info) => Some(info.reduced_unit.as_slice()),
        Event::PacingCredit(credit) => {
            if credit.normal > 1 << 20
                || credit.expedited > 1 << 20
                || credit.normal + credit.expedited == 0
            {
                return Err(protocol("invalid session pacing credit"));
            }
            None
        }
    };
    if let Some(unit) = reduced {
        if !(5..=16 * 1024).contains(&unit.len()) {
            return Err(protocol("invalid reduced session unit size"));
        }
        Ok(unit.len())
    } else {
        Ok(0)
    }
}

fn retryable_open_failure(reason: i32) -> bool {
    reason == wire::OpenFailure::RouteGone as i32 || reason == wire::OpenFailure::Busy as i32
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

// FNV-1a with a resource-kind prefix and component separators. Go persists
// IDs in a signed SQLite INTEGER, so reserve the high bit. A zero or collision
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
    hash & i64::MAX as u64
}

/// Publish only locally learned identities owned by the NETID assigned in
/// Welcome.  An automatic router may see other NETIDs on its local media;
/// those identities remain available locally but must never be claimed on
/// this authenticated upstream connection.
pub(crate) fn automatic_route_snapshot(
    epoch: &[u8],
    revision: u64,
    allowed_netid: &str,
    control_points: &[wire::SnaName],
    logical_units: &[wire::LuReachability],
) -> io::Result<wire::RouteSnapshot> {
    if epoch.len() != 16 || revision == 0 {
        return Err(protocol("invalid route snapshot epoch or revision"));
    }
    let mut routes = Vec::new();
    let mut identities = HashSet::new();
    let mut route_ids = HashSet::new();
    for cp in control_points {
        validate_name(cp)?;
        if cp.netid != allowed_netid {
            warn!(local_cp = %format_cp(cp), assigned_netid = allowed_netid,
                "local CP excluded from concentrator announcement: NETID mismatch");
            continue;
        }
        if !identities.insert((cp.netid.clone(), cp.name.clone(), false)) {
            return Err(protocol("duplicate local CP export"));
        }
        let id = stable_route_id(b'C', cp);
        if id == 0 || !route_ids.insert(id) {
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
        if name.netid != allowed_netid {
            warn!(local_lu = %format_cp(name), assigned_netid = allowed_netid,
                "local LU excluded from concentrator announcement: NETID mismatch");
            continue;
        }
        if let Some(host) = &lu.hosting_cp {
            validate_name(host)?;
            if !identities.contains(&(host.netid.clone(), host.name.clone(), false)) {
                warn!(local_lu = %format_cp(name), hosting_cp = %format_cp(host),
                    assigned_netid = allowed_netid,
                    "local LU excluded from concentrator announcement: hosting CP unavailable");
                continue;
            }
        }
        if !identities.insert((name.netid.clone(), name.name.clone(), true)) {
            return Err(protocol("duplicate local LU export"));
        }
        let id = stable_route_id(b'L', name);
        if id == 0 || !route_ids.insert(id) {
            return Err(protocol("local route ID collision"));
        }
        routes.push(wire::RouteExport {
            id,
            generation: 1,
            resource: Some(wire::route_export::Resource::LogicalUnit(lu.clone())),
        });
    }
    routes.sort_by_key(|route| route.id);
    Ok(wire::RouteSnapshot {
        epoch: epoch.to_vec(),
        revision,
        routes,
    })
}

/// Complete downstream directory received on one authenticated WebSocket.
/// The lookup deliberately returns an error for duplicate names, since a
/// guessed route could deliver an SNA session to the wrong endpoint.
#[derive(Default)]
pub(crate) struct AutoDirectory {
    origins: HashMap<Vec<u8>, (Vec<u8>, u64, Vec<wire::RouteExport>)>,
    managed: HashMap<[u8; 6], (wire::SnaName, Vec<wire::RouteReference>)>,
}

impl AutoDirectory {
    fn route_for_reference(&self, reference: &wire::RouteReference) -> Option<&wire::RouteExport> {
        let (epoch, _, routes) = self.origins.get(&reference.router_id)?;
        if epoch != &reference.epoch {
            return None;
        }
        routes.iter().find(|route| {
            route.id == reference.route_id && route.generation == reference.route_generation
        })
    }
    pub(crate) fn replace_origin(&mut self, origin: &wire::OriginRouteSnapshot) -> io::Result<()> {
        if origin.router_id.len() != 16 {
            return Err(protocol("invalid origin ID"));
        }
        let snapshot = origin
            .snapshot
            .as_ref()
            .ok_or_else(|| protocol("missing route snapshot"))?;
        if snapshot.epoch.len() != 16 || snapshot.revision == 0 {
            return Err(protocol("invalid origin route snapshot"));
        }
        let mut ids = HashSet::new();
        for route in &snapshot.routes {
            if route.id == 0 || route.generation == 0 || !ids.insert(route.id) {
                return Err(protocol("invalid or duplicate origin route ID"));
            }
            match route.resource.as_ref() {
                Some(wire::route_export::Resource::ControlPoint(cp)) => validate_name(cp)?,
                Some(wire::route_export::Resource::LogicalUnit(lu)) => {
                    validate_name(
                        lu.lu
                            .as_ref()
                            .ok_or_else(|| protocol("LU route missing name"))?,
                    )?;
                    if let Some(host) = &lu.hosting_cp {
                        validate_name(host)?;
                    }
                }
                None => return Err(protocol("origin route missing resource")),
            }
        }
        if self
            .origins
            .get(&origin.router_id)
            .is_some_and(|(epoch, revision, _)| {
                epoch == &snapshot.epoch && snapshot.revision <= *revision
            })
        {
            return Err(protocol("origin route revision is not increasing"));
        }
        self.origins.insert(
            origin.router_id.clone(),
            (
                snapshot.epoch.clone(),
                snapshot.revision,
                snapshot.routes.clone(),
            ),
        );
        Ok(())
    }

    pub(crate) fn withdraw(&mut self, withdraw: &wire::OriginWithdraw) -> io::Result<()> {
        if withdraw.router_id.len() != 16 || withdraw.epoch.len() != 16 {
            return Err(protocol("invalid origin withdrawal"));
        }
        if self
            .origins
            .get(&withdraw.router_id)
            .is_some_and(|(epoch, _, _)| epoch == &withdraw.epoch)
        {
            self.origins.remove(&withdraw.router_id);
        }
        Ok(())
    }

    pub(crate) fn replace_managed(
        &mut self,
        bindings: &wire::ManagedCpBindingSnapshot,
    ) -> io::Result<()> {
        validate_managed_bindings(&bindings.bindings)?;
        let mut next = HashMap::new();
        for binding in &bindings.bindings {
            let mac: [u8; 6] = binding
                .virtual_mac
                .as_slice()
                .try_into()
                .map_err(|_| protocol("invalid managed virtual MAC"))?;
            let cp = binding
                .control_point
                .clone()
                .ok_or_else(|| protocol("managed CP missing name"))?;
            next.insert(mac, (cp, binding.candidates.clone()));
        }
        self.managed = next;
        Ok(())
    }

    pub(crate) fn resolve_lu(
        &self,
        name: &wire::SnaName,
    ) -> io::Result<Option<wire::RouteReference>> {
        self.resolve(|resource| {
            matches!(resource,
            wire::route_export::Resource::LogicalUnit(lu) if lu.lu.as_ref() == Some(name))
        })
    }

    #[allow(dead_code)] // The EE runtime calls this once proxy identity wiring lands.
    pub(crate) fn resolve_cp(
        &self,
        name: &wire::SnaName,
    ) -> io::Result<Option<wire::RouteReference>> {
        self.resolve(|resource| {
            matches!(resource,
            wire::route_export::Resource::ControlPoint(cp) if cp == name)
        })
    }

    pub(crate) fn resolve_mac(&self, mac: &[u8; 6]) -> io::Result<Option<wire::RouteReference>> {
        let Some((name, candidates)) = self.managed.get(mac) else {
            return Ok(None);
        };
        let mut found = Vec::new();
        for candidate in candidates {
            if self
                .origins
                .get(&candidate.router_id)
                .is_some_and(|(epoch, _, routes)| {
                    epoch == &candidate.epoch
                        && routes.iter().any(|route| {
                            route.id == candidate.route_id
                                && route.generation == candidate.route_generation
                                && matches!(route.resource.as_ref(),
                            Some(wire::route_export::Resource::ControlPoint(cp)) if cp == name)
                        })
                })
            {
                found.push(candidate.clone());
            }
        }
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => Err(protocol("ambiguous managed MAC destination")),
        }
    }

    // The automatic LLC bridge calls this once its runtime branch is wired.
    #[allow(dead_code)]
    pub(crate) fn managed_mac_for_cp(&self, cp: &wire::SnaName) -> io::Result<Option<[u8; 6]>> {
        let mut found = None;
        for (mac, (name, candidates)) in &self.managed {
            if name != cp || !candidates.iter().any(|candidate| {
                matches!(
                    self.route_for_reference(candidate).and_then(|route| route.resource.as_ref()),
                    Some(wire::route_export::Resource::ControlPoint(route_cp)) if route_cp == cp
                )
            }) {
                continue;
            }
            if found.replace(*mac).is_some() {
                return Err(protocol("ambiguous managed MAC for CP"));
            }
        }
        Ok(found)
    }

    fn resolve(
        &self,
        matches: impl Fn(&wire::route_export::Resource) -> bool,
    ) -> io::Result<Option<wire::RouteReference>> {
        let mut found = None;
        for (router_id, (epoch, _, routes)) in &self.origins {
            for route in routes {
                if route.resource.as_ref().is_some_and(&matches) {
                    if found.is_some() {
                        return Err(protocol("ambiguous upstream SNA destination"));
                    }
                    found = Some(wire::RouteReference {
                        router_id: router_id.clone(),
                        epoch: epoch.clone(),
                        route_id: route.id,
                        route_generation: route.generation,
                    });
                }
            }
        }
        Ok(found)
    }
}

/// A single authenticated connection for automatic routing.  Its socket and
/// directory outlive individual circuit ports; each circuit gets an isolated
/// inbox and credit counter in `WsRoutePort`.
pub(crate) struct AutoWsHub {
    shared: Rc<RefCell<SharedWs>>,
    directory: Rc<RefCell<AutoDirectory>>,
    welcome: wire::RouterWelcome,
    local_routes: HashMap<u64, wire::RouteExport>,
    revision: u64,
}

impl AutoWsHub {
    pub(crate) fn connect(
        url: &str,
        bearer: &str,
        control_points: &[wire::SnaName],
        logical_units: &[wire::LuReachability],
    ) -> io::Result<Self> {
        let (client, welcome) = WsClient::connect_v2_with_identity(
            url,
            bearer,
            "sna_router",
            env!("CARGO_PKG_VERSION"),
        )
        .map_err(io_error)?;
        if let Some(update) = &welcome.software_update_available {
            tracing::warn!(current_version = env!("CARGO_PKG_VERSION"), latest_version = %update.latest_version, "sna_router software update available");
        }
        let directory = Rc::new(RefCell::new(AutoDirectory::default()));
        let shared = Rc::new(RefCell::new(SharedWs {
            client,
            inbox: Vec::new(),
            route_owners: HashMap::new(),
            request_owners: HashMap::new(),
            circuit_owners: HashMap::new(),
            closed_circuits: VecDeque::new(),
            closed_requests: VecDeque::new(),
            next_request_id: 0,
            last_managed_revision: 0,
            gateway_inbound: None,
            auto_directory: Some(directory.clone()),
            auto_incoming: VecDeque::new(),
            auto_local_route_ids: HashSet::new(),
            auto_free_indexes: Vec::new(),
        }));
        info!(server = %server_authority(url), router_id = %format_uuid(&welcome.router_id),
            assigned_netid = %welcome.allowed_netid, "automatic router connected to concentrator");
        if let Some(status) = crate::status() {
            status.set_concentrator(Some(ConcentratorStatus {
                state: "connected".into(),
                authority: server_authority(url).into(),
                router_id: Some(format_uuid(&welcome.router_id)),
                allowed_netid: Some(welcome.allowed_netid.clone()),
                connection_epoch: Some(format_uuid(&welcome.connection_epoch)),
                last_change_ms: local_status::now_ms(),
                last_error: None,
            }));
        }
        let mut hub = Self {
            shared,
            directory,
            welcome,
            local_routes: HashMap::new(),
            revision: 0,
        };
        hub.publish_local(control_points, logical_units)?;
        Ok(hub)
    }

    pub(crate) fn allowed_netid(&self) -> &str {
        &self.welcome.allowed_netid
    }

    /// Server-owned router UUID from the authenticated welcome. This is
    /// read-only; local configuration cannot select or change it.
    #[allow(dead_code)]
    pub(crate) fn router_id_bytes(&self) -> io::Result<[u8; 16]> {
        self.welcome
            .router_id
            .as_slice()
            .try_into()
            .map_err(|_| protocol("invalid server-owned router ID"))
    }

    pub(crate) fn local_route(
        &self,
        reference: &wire::RouteReference,
    ) -> Option<&wire::RouteExport> {
        if reference.router_id != self.welcome.router_id
            || reference.epoch != self.welcome.connection_epoch
        {
            return None;
        }
        self.local_routes
            .get(&reference.route_id)
            .filter(|route| route.generation == reference.route_generation)
    }

    pub(crate) fn remote_route(
        &self,
        reference: &wire::RouteReference,
    ) -> Option<wire::RouteExport> {
        self.directory
            .borrow()
            .route_for_reference(reference)
            .cloned()
    }

    pub(crate) fn reject_incoming(
        &mut self,
        open: &wire::IncomingOpen,
        reason: wire::OpenFailure,
    ) -> io::Result<()> {
        self.shared
            .borrow_mut()
            .client
            .send(envelope(wire::ws_envelope::Body::OpenDecision(
                wire::OpenDecision {
                    circuit_id: open.circuit_id.clone(),
                    accept: false,
                    receive_allowance_bytes: 0,
                    reason: reason as i32,
                },
            )))
            .map_err(io_error)
    }

    pub(crate) fn publish_local(
        &mut self,
        control_points: &[wire::SnaName],
        logical_units: &[wire::LuReachability],
    ) -> io::Result<()> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| protocol("route revision exhausted"))?;
        let snapshot = automatic_route_snapshot(
            &self.welcome.connection_epoch,
            revision,
            &self.welcome.allowed_netid,
            control_points,
            logical_units,
        )?;
        let ids = snapshot.routes.iter().map(|route| route.id).collect();
        self.shared
            .borrow_mut()
            .client
            .send(envelope(wire::ws_envelope::Body::PublishRoutes(
                snapshot.clone(),
            )))
            .map_err(io_error)?;
        self.shared.borrow_mut().auto_local_route_ids = ids;
        self.local_routes = snapshot
            .routes
            .into_iter()
            .map(|route| (route.id, route))
            .collect();
        self.revision = revision;
        info!(revision, export_count = self.local_routes.len(), assigned_netid = %self.welcome.allowed_netid,
            "published automatic local reachability");
        Ok(())
    }

    pub(crate) fn local_reference_lu(&self, lu: &wire::SnaName) -> Option<wire::RouteReference> {
        self.local_reference(|resource| {
            matches!(resource,
            wire::route_export::Resource::LogicalUnit(reachability)
                if reachability.lu.as_ref() == Some(lu))
        })
    }

    // Used by the automatic LLC bridge after a verified XID3 CP is published.
    #[allow(dead_code)]
    pub(crate) fn local_reference_cp(&self, cp: &wire::SnaName) -> Option<wire::RouteReference> {
        self.local_reference(|resource| {
            matches!(resource,
            wire::route_export::Resource::ControlPoint(name) if name == cp)
        })
    }

    fn local_reference(
        &self,
        matches: impl Fn(&wire::route_export::Resource) -> bool,
    ) -> Option<wire::RouteReference> {
        let route = self
            .local_routes
            .values()
            .find(|route| route.resource.as_ref().is_some_and(&matches))?;
        Some(wire::RouteReference {
            router_id: self.welcome.router_id.clone(),
            epoch: self.welcome.connection_epoch.clone(),
            route_id: route.id,
            route_generation: route.generation,
        })
    }

    pub(crate) fn poll_incoming(&mut self) -> io::Result<Option<wire::IncomingOpen>> {
        let mut shared = self.shared.borrow_mut();
        if shared.auto_incoming.is_empty() {
            shared.receive_once()?;
        }
        Ok(shared.auto_incoming.pop_front())
    }

    pub(crate) fn resolve_lu(
        &self,
        lu: &wire::SnaName,
    ) -> io::Result<Option<(wire::RouteReference, Option<wire::SnaName>)>> {
        let directory = self.directory.borrow();
        let Some(reference) = directory.resolve_lu(lu)? else {
            return Ok(None);
        };
        let host = match directory
            .route_for_reference(&reference)
            .and_then(|route| route.resource.as_ref())
        {
            Some(wire::route_export::Resource::LogicalUnit(reachability)) => {
                reachability.hosting_cp.clone()
            }
            _ => None,
        };
        Ok(Some((reference, host)))
    }

    /// Resolve a CP from the authenticated upstream directory. This permits
    /// EE proxy presentation of a concentrator-owned CP without publishing it
    /// as a locally owned route.
    #[allow(dead_code)] // The EE runtime calls this once proxy identity wiring lands.
    pub(crate) fn resolve_cp(
        &self,
        cp: &wire::SnaName,
    ) -> io::Result<Option<wire::RouteReference>> {
        self.directory.borrow().resolve_cp(cp)
    }

    // Used by the automatic LLC bridge for concentrator-assigned proxy MACs.
    #[allow(dead_code)]
    pub(crate) fn resolve_mac(
        &self,
        mac: &[u8; 6],
    ) -> io::Result<Option<(wire::RouteReference, wire::SnaName)>> {
        let directory = self.directory.borrow();
        let Some(reference) = directory.resolve_mac(mac)? else {
            return Ok(None);
        };
        let cp = match directory
            .route_for_reference(&reference)
            .and_then(|route| route.resource.as_ref())
        {
            Some(wire::route_export::Resource::ControlPoint(cp)) => cp.clone(),
            _ => return Err(protocol("managed MAC points to missing CP route")),
        };
        Ok(Some((reference, cp)))
    }

    // Used by the automatic LLC bridge when an upstream CP initiates a circuit.
    #[allow(dead_code)]
    pub(crate) fn managed_mac_for_cp(&self, cp: &wire::SnaName) -> io::Result<Option<[u8; 6]>> {
        self.directory.borrow().managed_mac_for_cp(cp)
    }

    /// A current, medium-neutral view for the local automatic directory.
    /// OPEN still rechecks the selected live RouteReference before use.
    pub(crate) fn advertised_addresses(&self) -> Vec<RouteAddress> {
        let directory = self.directory.borrow();
        let mut addresses = Vec::new();
        for (router_id, (_, _, routes)) in &directory.origins {
            if router_id == &self.welcome.router_id {
                continue;
            }
            for route in routes {
                match route.resource.as_ref() {
                    Some(wire::route_export::Resource::ControlPoint(cp)) => {
                        addresses.push(RouteAddress::ControlPoint {
                            netid: cp.netid.clone(),
                            name: cp.name.clone(),
                        })
                    }
                    Some(wire::route_export::Resource::LogicalUnit(lu)) => {
                        if let Some(name) = &lu.lu {
                            addresses.push(RouteAddress::LogicalUnit {
                                netid: name.netid.clone(),
                                cp: lu.hosting_cp.as_ref().map(|cp| cp.name.clone()),
                                name: name.name.clone(),
                            });
                        }
                    }
                    None => {}
                }
            }
        }
        for mac in directory.managed.keys() {
            if directory.resolve_mac(mac).ok().flatten().is_some() {
                addresses.push(RouteAddress::Mac(*mac));
            }
        }
        addresses
    }

    pub(crate) fn open_lu(
        &mut self,
        target_lu: &wire::SnaName,
        source_lu: &wire::SnaName,
    ) -> io::Result<Option<WsRoutePort>> {
        let Some((target, Some(target_cp))) = self.resolve_lu(target_lu)? else {
            return Ok(None);
        };
        let Some(source) = self.local_reference_lu(source_lu) else {
            return Ok(None);
        };
        let local_cp = self.local_hosting_cp(&source)?;
        self.open_ref(
            target,
            target_cp,
            Some(target_lu.clone()),
            Some(source),
            local_cp,
        )
        .map(Some)
    }

    /// Start one LU 6.2 session against a live target LU. A locally published
    /// source LU is required; Go revalidates its owner and route generation at
    /// OPEN. The first poll sends OPEN and retries transient RouteGone races.
    #[allow(dead_code)]
    pub(crate) fn open_session_lu(
        &mut self,
        target_lu: &wire::SnaName,
        source_lu: &wire::SnaName,
    ) -> io::Result<Option<SessionWsPort>> {
        let Some(source_ref) = self.local_reference_lu(source_lu) else {
            return Ok(None);
        };
        let source_is_lu62 = self
            .local_route(&source_ref)
            .and_then(|route| match route.resource.as_ref() {
                Some(wire::route_export::Resource::LogicalUnit(lu)) => Some(lu),
                _ => None,
            })
            .is_some_and(|lu| {
                lu.supported_types
                    .contains(&(wire::LuType::LuType62 as i32))
            });
        if !source_is_lu62 {
            return Err(protocol("session source LU is not published as LU 6.2"));
        }
        let Some(mut port) = self.open_lu(target_lu, source_lu)? else {
            return Ok(None);
        };
        port.profile = wire::CircuitProfile::SessionV1;
        Ok(Some(SessionWsPort {
            inner: port,
            opened_reported: false,
        }))
    }

    fn local_hosting_cp(&self, reference: &wire::RouteReference) -> io::Result<wire::SnaName> {
        match self
            .local_routes
            .get(&reference.route_id)
            .and_then(|route| route.resource.as_ref())
        {
            Some(wire::route_export::Resource::ControlPoint(cp)) => Ok(cp.clone()),
            Some(wire::route_export::Resource::LogicalUnit(lu)) => lu
                .hosting_cp
                .clone()
                .ok_or_else(|| protocol("local LU has no hosting CP")),
            None => Err(protocol("local source route unavailable")),
        }
    }

    pub(crate) fn open_ref(
        &mut self,
        target: wire::RouteReference,
        target_cp: wire::SnaName,
        target_lu: Option<wire::SnaName>,
        source_route: Option<wire::RouteReference>,
        local_cp: wire::SnaName,
    ) -> io::Result<WsRoutePort> {
        let target_valid = {
            let directory = self.directory.borrow();
            match directory
                .route_for_reference(&target)
                .and_then(|route| route.resource.as_ref())
            {
                Some(wire::route_export::Resource::ControlPoint(cp)) => {
                    target_lu.is_none() && cp == &target_cp
                }
                Some(wire::route_export::Resource::LogicalUnit(lu)) => {
                    target_lu.as_ref() == lu.lu.as_ref()
                        && lu.hosting_cp.as_ref() == Some(&target_cp)
                }
                None => false,
            }
        };
        if !target_valid {
            return Err(protocol("target route is not in the current directory"));
        }
        if let Some(source) = &source_route {
            if source.router_id != self.welcome.router_id
                || source.epoch != self.welcome.connection_epoch
                || self.local_route(source).is_none()
            {
                return Err(protocol("source route is not currently published"));
            }
            let source_matches_profile = match self
                .local_route(source)
                .and_then(|route| route.resource.as_ref())
            {
                Some(wire::route_export::Resource::LogicalUnit(_)) => target_lu.is_some(),
                Some(wire::route_export::Resource::ControlPoint(_)) => target_lu.is_none(),
                None => false,
            };
            if !source_matches_profile {
                return Err(protocol("source and target route profiles differ"));
            }
        } else {
            return Err(protocol(
                "automatic v2 circuit requires a published source route",
            ));
        }
        let mut port =
            self.new_port(local_cp, target_cp, target_lu, source_route, HashSet::new())?;
        port.target = Some(target);
        Ok(port)
    }

    pub(crate) fn accept_incoming(
        &mut self,
        open: wire::IncomingOpen,
    ) -> io::Result<Option<WsRoutePort>> {
        if open.profile != wire::CircuitProfile::NativeDlc as i32 {
            return Ok(None);
        }
        self.accept_incoming_profile(open, wire::CircuitProfile::NativeDlc)
    }

    #[allow(dead_code)]
    pub(crate) fn accept_session_incoming(
        &mut self,
        open: wire::IncomingOpen,
    ) -> io::Result<Option<SessionWsPort>> {
        if open.profile != wire::CircuitProfile::SessionV1 as i32 {
            return Ok(None);
        }
        self.accept_incoming_profile(open, wire::CircuitProfile::SessionV1)
            .map(|port| {
                port.map(|inner| SessionWsPort {
                    inner,
                    opened_reported: false,
                })
            })
    }

    fn accept_incoming_profile(
        &mut self,
        open: wire::IncomingOpen,
        profile: wire::CircuitProfile,
    ) -> io::Result<Option<WsRoutePort>> {
        let Some(local_ref) = open.target.as_ref() else {
            return Ok(None);
        };
        if local_ref.router_id != self.welcome.router_id
            || local_ref.epoch != self.welcome.connection_epoch
            || self.local_route(local_ref).is_none()
        {
            return Ok(None);
        }
        let local_cp = self.local_hosting_cp(local_ref)?;
        let Some(source_ref) = open.source_route.as_ref() else {
            return Ok(None);
        };
        let (target_lu, target_cp) = {
            let directory = self.directory.borrow();
            let Some(route) = directory.route_for_reference(source_ref) else {
                return Ok(None);
            };
            match route.resource.as_ref() {
                Some(wire::route_export::Resource::LogicalUnit(lu)) => {
                    (lu.lu.clone(), lu.hosting_cp.clone())
                }
                Some(wire::route_export::Resource::ControlPoint(cp)) => (None, Some(cp.clone())),
                _ => return Ok(None),
            }
        };
        let Some(target_cp) = target_cp else {
            return Ok(None);
        };
        let local_is_lu = matches!(
            self.local_route(local_ref)
                .and_then(|route| route.resource.as_ref()),
            Some(wire::route_export::Resource::LogicalUnit(_))
        );
        if local_is_lu != target_lu.is_some() {
            return Ok(None);
        }
        let mut port = match self.new_port(
            local_cp,
            target_cp,
            target_lu,
            Some(local_ref.clone()),
            HashSet::from([local_ref.route_id]),
        ) {
            Ok(port) => port,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.reject_incoming(&open, wire::OpenFailure::Busy)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        port.profile = profile;
        port.target = Some(source_ref.clone());
        port.incoming_open(open)?;
        // `incoming_open` may reject a stale or busy request after the route
        // checks above. Never hand that rejected port to a carrier adapter.
        if port.circuit.is_some() {
            Ok(Some(port))
        } else {
            Ok(None)
        }
    }

    fn new_port(
        &mut self,
        local_cp: wire::SnaName,
        target_cp: wire::SnaName,
        target_lu: Option<wire::SnaName>,
        source_route: Option<wire::RouteReference>,
        local_route_ids: HashSet<u64>,
    ) -> io::Result<WsRoutePort> {
        let mut shared = self.shared.borrow_mut();
        if shared
            .inbox
            .len()
            .saturating_sub(shared.auto_free_indexes.len())
            >= self.welcome.max_circuits as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "concentrator circuit limit reached",
            ));
        }
        let index = if let Some(index) = shared.auto_free_indexes.pop() {
            index
        } else {
            shared.inbox.push(VecDeque::new());
            shared.inbox.len() - 1
        };
        drop(shared);
        Ok(WsRoutePort {
            shared: self.shared.clone(),
            index,
            welcome: self.welcome.clone(),
            local_cp,
            local_route_ids,
            target_cp,
            target_lu,
            target: None,
            retired_target_epochs: HashSet::new(),
            source_route,
            profile: wire::CircuitProfile::NativeDlc,
            require_managed_binding: false,
            managed_binding_seen: false,
            managed_mac: None,
            circuit: None,
            opening: false,
            local_ready: false,
            request_id: 0,
            retry_at: None,
            retry_delay: FIRST_OPEN_RETRY,
            pending_type1: VecDeque::new(),
            pending_information: VecDeque::new(),
            pending_session: VecDeque::new(),
            downstream_sizes: VecDeque::new(),
            outbound_completions: OutboundCompletions::default(),
            inbound_open: None,
            auto_owned: true,
        })
    }
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

pub(crate) fn server_authority(url: &str) -> &str {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("unknown");
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
}

fn protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn io_error(error: transport_ws::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
// Tungstenite's handshake callback has a large rejection response; these
// mock servers only accept connections and never construct that error path.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use prost::Message;
    use std::{net::TcpListener, sync::mpsc, thread, time::Instant};
    use tungstenite::{
        http::{header::SEC_WEBSOCKET_PROTOCOL, HeaderValue},
        Message as WsMessage,
    };

    #[test]
    fn websocket_disconnect_preserves_local_circuit_status() {
        let status = local_status::LocalStatus::new();
        let ws_id = vec![1; 16];
        let circuit = |id: String| CircuitStatus {
            id,
            ingress: "local a".into(),
            egress: "local b".into(),
            state: "ready".into(),
            bytes_in: 0,
            bytes_out: 0,
            last_change_ms: 0,
        };
        status.upsert_circuit(circuit("auto-7".into()));
        status.upsert_circuit(circuit(format_uuid(&ws_id)));

        remove_owned_circuit_status(&status, &HashMap::from([(ws_id, 0)]));

        let circuits = status.snapshot().circuits;
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].id, "auto-7");
    }

    #[test]
    fn automatic_snapshot_announces_only_assigned_netid_and_its_hosted_lus() {
        let owned = name("OWNED", "CPA");
        let foreign = name("OTHER", "CPB");
        let lu = |name: wire::SnaName, host: wire::SnaName| wire::LuReachability {
            lu: Some(name),
            hosting_cp: Some(host),
            supported_types: Vec::new(),
        };
        let snapshot = automatic_route_snapshot(
            &[7; 16],
            1,
            "OWNED",
            &[owned.clone(), foreign.clone()],
            &[
                lu(name("OWNED", "LUA"), owned.clone()),
                lu(name("OTHER", "LUB"), foreign.clone()),
                lu(name("OWNED", "LUC"), foreign),
            ],
        )
        .unwrap();
        assert_eq!(snapshot.routes.len(), 2);
        assert!(snapshot.routes.iter().any(|route| matches!(
            route.resource.as_ref(),
            Some(wire::route_export::Resource::ControlPoint(cp)) if cp == &owned
        )));
        assert!(snapshot.routes.iter().any(|route| matches!(
            route.resource.as_ref(),
            Some(wire::route_export::Resource::LogicalUnit(lu))
                if lu.lu.as_ref() == Some(&name("OWNED", "LUA"))
        )));
        assert!(automatic_route_snapshot(&[7; 16], 2, "OWNED", &[], &[])
            .unwrap()
            .routes
            .is_empty());
    }

    #[test]
    fn automatic_directory_resolves_unique_lu_and_fences_withdrawal_epoch() {
        let mut directory = AutoDirectory::default();
        let route = wire::RouteExport {
            id: 41,
            generation: 2,
            resource: Some(wire::route_export::Resource::LogicalUnit(
                wire::LuReachability {
                    lu: Some(name("TARGET", "LUA")),
                    hosting_cp: Some(name("TARGET", "CPA")),
                    supported_types: Vec::new(),
                },
            )),
        };
        let origin = wire::OriginRouteSnapshot {
            router_id: vec![1; 16],
            snapshot: Some(wire::RouteSnapshot {
                epoch: vec![2; 16],
                revision: 1,
                routes: vec![route.clone()],
            }),
        };
        directory.replace_origin(&origin).unwrap();
        assert!(directory.replace_origin(&origin).is_err());
        let mut advanced = origin.clone();
        advanced.snapshot.as_mut().unwrap().revision = 2;
        directory.replace_origin(&advanced).unwrap();
        assert_eq!(
            directory
                .resolve_lu(&name("TARGET", "LUA"))
                .unwrap()
                .unwrap()
                .route_id,
            41
        );
        directory
            .withdraw(&wire::OriginWithdraw {
                router_id: vec![1; 16],
                epoch: vec![9; 16],
            })
            .unwrap();
        assert!(directory
            .resolve_lu(&name("TARGET", "LUA"))
            .unwrap()
            .is_some());
        let mut another = origin.clone();
        another.router_id = vec![3; 16];
        directory.replace_origin(&another).unwrap();
        assert!(directory.resolve_lu(&name("TARGET", "LUA")).is_err());
        directory
            .withdraw(&wire::OriginWithdraw {
                router_id: vec![3; 16],
                epoch: vec![2; 16],
            })
            .unwrap();
        directory
            .withdraw(&wire::OriginWithdraw {
                router_id: vec![1; 16],
                epoch: vec![2; 16],
            })
            .unwrap();
        assert!(directory
            .resolve_lu(&name("TARGET", "LUA"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn automatic_directory_resolves_server_owned_cp_without_local_claim() {
        let mut directory = AutoDirectory::default();
        let service_cp = name("SNUSNU", "SVC");
        assert!(directory.resolve_cp(&service_cp).unwrap().is_none());
        let origin = wire::OriginRouteSnapshot {
            router_id: vec![1; 16],
            snapshot: Some(wire::RouteSnapshot {
                epoch: vec![2; 16],
                revision: 1,
                routes: vec![wire::RouteExport {
                    id: 41,
                    generation: 2,
                    resource: Some(wire::route_export::Resource::ControlPoint(
                        service_cp.clone(),
                    )),
                }],
            }),
        };
        directory.replace_origin(&origin).unwrap();
        let reference = directory.resolve_cp(&service_cp).unwrap().unwrap();
        assert_eq!(reference.router_id, origin.router_id);
        assert_eq!(reference.route_id, 41);
        assert!(directory
            .resolve_cp(&name("SNUSNU", "OTHER"))
            .unwrap()
            .is_none());
        let mut duplicate = origin.clone();
        duplicate.router_id = vec![3; 16];
        directory.replace_origin(&duplicate).unwrap();
        assert!(directory.resolve_cp(&service_cp).is_err());
        directory
            .withdraw(&wire::OriginWithdraw {
                router_id: duplicate.router_id,
                epoch: vec![2; 16],
            })
            .unwrap();
        assert_eq!(directory.resolve_cp(&service_cp).unwrap(), Some(reference));
    }

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
    fn session_v1_port_roundtrips_events_and_credit_on_shared_hub() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let circuit_id = vec![0x44; 16];
        let server_id = circuit_id.clone();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
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
            let read = |socket: &mut tungstenite::WebSocket<std::net::TcpStream>| {
                let WsMessage::Binary(payload) = socket.read().unwrap() else {
                    panic!("binary envelope expected")
                };
                wire::WsEnvelope::decode(payload).unwrap().body.unwrap()
            };
            send(
                &mut socket,
                wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 65536,
                    max_circuits: 4,
                    display_name: "session broker".into(),
                    allowed_netid: "OWNED".into(),
                    software_update_available: None,
                }),
            );
            let wire::ws_envelope::Body::PublishRoutes(snapshot) = read(&mut socket) else {
                panic!("source snapshot expected")
            };
            assert!(snapshot.routes.iter().any(|route| matches!(
                route.resource.as_ref(),
                Some(wire::route_export::Resource::LogicalUnit(lu))
                    if lu.lu.as_ref() == Some(&name("OWNED", "LUA"))
                        && lu.supported_types.contains(&(wire::LuType::LuType62 as i32))
            )));
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 1,
                        routes: vec![wire::RouteExport {
                            id: 2,
                            generation: 1,
                            resource: Some(wire::route_export::Resource::LogicalUnit(
                                wire::LuReachability {
                                    lu: Some(name("SNUSNU", "PING")),
                                    hosting_cp: Some(name("SNUSNU", "SVC")),
                                    supported_types: vec![wire::LuType::LuType62 as i32],
                                },
                            )),
                        }],
                    }),
                }),
            );
            let wire::ws_envelope::Body::OpenRequest(open) = read(&mut socket) else {
                panic!("session open expected")
            };
            assert_eq!(open.profile, wire::CircuitProfile::SessionV1 as i32);
            assert_eq!(open.source_route.as_ref().unwrap().router_id, vec![7; 16]);
            assert_eq!(open.target.as_ref().unwrap().route_id, 2);
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginWithdraw(wire::OriginWithdraw {
                    router_id: vec![9; 16],
                    epoch: vec![10; 16],
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::OpenResult(wire::OpenResult {
                    request_id: open.request_id,
                    circuit_id: vec![],
                    accepted: false,
                    peer_receive_allowance_bytes: 0,
                    reason: wire::OpenFailure::RouteGone as i32,
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![11; 16],
                        revision: 1,
                        routes: vec![wire::RouteExport {
                            id: 2,
                            generation: 1,
                            resource: Some(wire::route_export::Resource::LogicalUnit(
                                wire::LuReachability {
                                    lu: Some(name("SNUSNU", "PING")),
                                    hosting_cp: Some(name("SNUSNU", "SVC")),
                                    supported_types: vec![wire::LuType::LuType62 as i32],
                                },
                            )),
                        }],
                    }),
                }),
            );
            let wire::ws_envelope::Body::OpenRequest(reopened) = read(&mut socket) else {
                panic!("replacement session open expected")
            };
            assert!(reopened.request_id > open.request_id);
            assert_eq!(reopened.target.as_ref().unwrap().epoch, vec![11; 16]);
            // A delayed snapshot from the retired epoch must not supersede
            // the replacement and start a second circuit for the same LU.
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 2,
                        routes: vec![wire::RouteExport {
                            id: 2,
                            generation: 1,
                            resource: Some(wire::route_export::Resource::LogicalUnit(
                                wire::LuReachability {
                                    lu: Some(name("SNUSNU", "PING")),
                                    hosting_cp: Some(name("SNUSNU", "SVC")),
                                    supported_types: vec![wire::LuType::LuType62 as i32],
                                },
                            )),
                        }],
                    }),
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::OpenResult(wire::OpenResult {
                    request_id: reopened.request_id,
                    circuit_id: server_id.clone(),
                    accepted: true,
                    peer_receive_allowance_bytes: 1500,
                    reason: wire::OpenFailure::Unspecified as i32,
                }),
            );
            // The target reserves this exclusive LU for the accepted
            // circuit, then removes it from new-route announcements.
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![11; 16],
                        revision: 2,
                        routes: vec![],
                    }),
                }),
            );
            let wire::ws_envelope::Body::CircuitEvent(bind) = read(&mut socket) else {
                panic!("BIND expected")
            };
            let bind_bytes = bind
                .event
                .as_ref()
                .and_then(|event| match event {
                    wire::circuit_event::Event::SessionEvent(e) => Some(e),
                    _ => None,
                })
                .and_then(|e| match e.event.as_ref() {
                    Some(wire::session_event::Event::BindRequest(unit)) => Some(unit.clone()),
                    _ => None,
                });
            assert_eq!(bind_bytes, Some(vec![0, 1, 0x6b, 0x80, 0, 0x31]));
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitCredit(wire::CircuitCredit {
                    circuit_id: server_id.clone(),
                    allowance_bytes: 1506,
                }),
            );
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: server_id.clone(),
                    event: Some(wire::circuit_event::Event::SessionEvent(
                        wire::SessionEvent {
                            event: Some(wire::session_event::Event::BindResult(
                                wire::SessionBindResult {
                                    accepted: true,
                                    reduced_unit: vec![0, 1, 0xeb, 0x80, 0, 0x31],
                                },
                            )),
                        },
                    )),
                }),
            );
            let wire::ws_envelope::Body::CircuitCredit(credit) = read(&mut socket) else {
                panic!("BIND receive credit expected")
            };
            assert_eq!(credit.allowance_bytes, 1506);
            let wire::ws_envelope::Body::CircuitEvent(info) = read(&mut socket) else {
                panic!("information expected")
            };
            assert!(matches!(
                info.event.as_ref().and_then(|event| match event {
                    wire::circuit_event::Event::SessionEvent(e) => e.event.as_ref(),
                    _ => None,
                }),
                Some(wire::session_event::Event::Information(value))
                    if value.reduced_unit == [0, 2, 3, 0x91, 0x20, 0x42]
            ));
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: server_id.clone(),
                    event: Some(wire::circuit_event::Event::SessionEvent(
                        wire::SessionEvent {
                            event: Some(wire::session_event::Event::PacingCredit(
                                wire::SessionPacingCredit {
                                    normal: 1,
                                    expedited: 0,
                                },
                            )),
                        },
                    )),
                }),
            );
            let wire::ws_envelope::Body::CircuitEvent(unbind) = read(&mut socket) else {
                panic!("UNBIND expected")
            };
            assert!(matches!(
                unbind.event.as_ref().and_then(|event| match event {
                    wire::circuit_event::Event::SessionEvent(e) => e.event.as_ref(),
                    _ => None,
                }),
                Some(wire::session_event::Event::Unbind(unit)) if unit == &[0, 0, 0x6b, 0x80, 0, 0x32]
            ));
            send(
                &mut socket,
                wire::ws_envelope::Body::CircuitReset(wire::CircuitReset {
                    circuit_id: server_id,
                    reason: wire::ResetReason::RemoteLink as i32,
                }),
            );
        });
        let source = name("OWNED", "LUA");
        let target = name("SNUSNU", "PING");
        let mut hub = AutoWsHub::connect(
            &url,
            "",
            &[name("OWNED", "CPA")],
            &[wire::LuReachability {
                lu: Some(source.clone()),
                hosting_cp: Some(name("OWNED", "CPA")),
                supported_types: vec![wire::LuType::LuType62 as i32],
            }],
        )
        .unwrap();
        for _ in 0..1000 {
            hub.poll_incoming().unwrap();
            if hub.resolve_lu(&target).unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let mut port = hub.open_session_lu(&target, &source).unwrap().unwrap();
        for _ in 0..1000 {
            if matches!(port.poll().unwrap(), Some(SessionWsUpdate::Opened)) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(port.is_open());
        let bind = wire::SessionEvent {
            event: Some(wire::session_event::Event::BindRequest(vec![
                0, 1, 0x6b, 0x80, 0, 0x31,
            ])),
        };
        assert!(port.send(bind).unwrap());
        for _ in 0..1000 {
            match port.poll().unwrap() {
                Some(SessionWsUpdate::Event(event)) => {
                    assert!(matches!(
                        event.event,
                        Some(wire::session_event::Event::BindResult(_))
                    ));
                    break;
                }
                _ => thread::sleep(Duration::from_millis(1)),
            }
        }
        assert_eq!(port.take_completed_send_count(), 1);
        port.complete_received(1).unwrap();
        assert!(port
            .send(wire::SessionEvent {
                event: Some(wire::session_event::Event::Information(
                    wire::SessionInformation {
                        expedited: false,
                        reduced_unit: vec![0, 2, 3, 0x91, 0x20, 0x42],
                    }
                )),
            })
            .unwrap());
        for _ in 0..1000 {
            if matches!(port.poll().unwrap(), Some(SessionWsUpdate::Event(event)) if matches!(event.event, Some(wire::session_event::Event::PacingCredit(_))))
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(port
            .send(wire::SessionEvent {
                event: Some(wire::session_event::Event::Unbind(vec![
                    0, 0, 0x6b, 0x80, 0, 0x32,
                ])),
            })
            .unwrap());
        for _ in 0..1000 {
            if matches!(port.poll().unwrap(), Some(SessionWsUpdate::Closed)) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!port.is_open());
        server.join().unwrap();
    }

    #[test]
    fn automatic_hub_publishes_only_owned_names_and_resolves_dynamic_lu() {
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
                        HeaderValue::from_static(transport_ws::SUBPROTOCOL_V2),
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
                        display_name: "auto router".into(),
                        allowed_netid: "OWNED".into(),
                        software_update_available: None,
                    }))
                    .encode_to_vec()
                    .into(),
                ))
                .unwrap();
            let mut local_cp_route = None;
            for expected_revision in 1..=2 {
                let WsMessage::Binary(payload) = socket.read().unwrap() else {
                    panic!("snapshot expected")
                };
                let envelope = wire::WsEnvelope::decode(payload).unwrap();
                let Some(wire::ws_envelope::Body::PublishRoutes(snapshot)) = envelope.body else {
                    panic!("publish expected")
                };
                assert_eq!(snapshot.revision, expected_revision);
                assert!(snapshot.routes.iter().all(|route| {
                    match route.resource.as_ref().unwrap() {
                        wire::route_export::Resource::ControlPoint(cp) => cp.netid == "OWNED",
                        wire::route_export::Resource::LogicalUnit(lu) => {
                            lu.lu.as_ref().unwrap().netid == "OWNED"
                        }
                    }
                }));
                assert_eq!(
                    snapshot.routes.len(),
                    if expected_revision == 1 { 0 } else { 2 }
                );
                if expected_revision == 2 {
                    local_cp_route =
                        snapshot
                            .routes
                            .iter()
                            .find_map(|route| match route.resource.as_ref() {
                                Some(wire::route_export::Resource::ControlPoint(cp))
                                    if cp == &name("OWNED", "CPA") =>
                                {
                                    Some(route.id)
                                }
                                _ => None,
                            });
                }
            }
            socket
                .send(WsMessage::Binary(
                    envelope(wire::ws_envelope::Body::OriginRoutes(
                        wire::OriginRouteSnapshot {
                            router_id: vec![9; 16],
                            snapshot: Some(wire::RouteSnapshot {
                                epoch: vec![10; 16],
                                revision: 1,
                                routes: vec![
                                    wire::RouteExport {
                                        id: 30,
                                        generation: 1,
                                        resource: Some(wire::route_export::Resource::ControlPoint(
                                            name("TARGET", "CPB"),
                                        )),
                                    },
                                    wire::RouteExport {
                                        id: 31,
                                        generation: 1,
                                        resource: Some(wire::route_export::Resource::LogicalUnit(
                                            wire::LuReachability {
                                                lu: Some(name("TARGET", "LUB")),
                                                hosting_cp: Some(name("TARGET", "CPB")),
                                                supported_types: Vec::new(),
                                            },
                                        )),
                                    },
                                ],
                            }),
                        },
                    ))
                    .encode_to_vec()
                    .into(),
                ))
                .unwrap();
            socket
                .send(WsMessage::Binary(
                    envelope(wire::ws_envelope::Body::ManagedCpBindings(
                        wire::ManagedCpBindingSnapshot {
                            schema_version: 1,
                            recipient_epoch: vec![8; 16],
                            revision: 1,
                            bindings: vec![wire::ManagedCpBinding {
                                address_id: vec![11; 16],
                                control_point: Some(name("TARGET", "CPB")),
                                virtual_mac: vec![0x02, 0x53, 0x4e, 0, 0, 1],
                                candidates: vec![wire::RouteReference {
                                    router_id: vec![9; 16],
                                    epoch: vec![10; 16],
                                    route_id: 30,
                                    route_generation: 1,
                                }],
                            }],
                        },
                    ))
                    .encode_to_vec()
                    .into(),
                ))
                .unwrap();
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("open expected")
            };
            let message = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::OpenRequest(open)) = message.body else {
                panic!("open request expected")
            };
            assert_eq!(open.target.as_ref().unwrap().route_id, 30);
            assert_eq!(
                open.source_route.as_ref().unwrap().route_id,
                local_cp_route.unwrap()
            );
        });
        let mut hub = AutoWsHub::connect(&url, "", &[], &[]).unwrap();
        let source = name("OWNED", "LUA");
        let host = name("OWNED", "CPA");
        hub.publish_local(
            &[host.clone(), name("FOREIGN", "CPX")],
            &[wire::LuReachability {
                lu: Some(source.clone()),
                hosting_cp: Some(host),
                supported_types: Vec::new(),
            }],
        )
        .unwrap();
        let target = name("TARGET", "LUB");
        for _ in 0..1000 {
            hub.poll_incoming().unwrap();
            if hub.resolve_lu(&target).unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            hub.resolve_lu(&target).unwrap().unwrap().1,
            Some(name("TARGET", "CPB"))
        );
        let lu_port = hub.open_lu(&target, &source).unwrap().unwrap();
        let mac = [0x02, 0x53, 0x4e, 0, 0, 1];
        for _ in 0..1000 {
            hub.poll_incoming().unwrap();
            if hub.resolve_mac(&mac).unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            hub.managed_mac_for_cp(&name("TARGET", "CPB")).unwrap(),
            Some(mac)
        );
        let advertised = hub.advertised_addresses();
        assert!(advertised.contains(&RouteAddress::Mac(mac)));
        assert!(advertised.contains(&RouteAddress::LogicalUnit {
            netid: "TARGET".into(),
            cp: Some("CPB".into()),
            name: "LUB".into(),
        }));
        let (target_ref, target_cp) = hub.resolve_mac(&mac).unwrap().unwrap();
        let local_cp = name("OWNED", "CPA");
        let source_ref = hub.local_reference_cp(&local_cp).unwrap();
        assert_eq!(
            hub.open_ref(
                target_ref.clone(),
                target_cp.clone(),
                None,
                Some(source_ref.clone()),
                local_cp.clone()
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(lu_port);
        let mut cp_port = hub
            .open_ref(target_ref, target_cp, None, Some(source_ref), local_cp)
            .unwrap();
        cp_port
            .send(RoutedUnit::DlcType1(vec![4, 4, 0xaf]))
            .unwrap();
        server.join().unwrap();
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
                    software_update_available: None,
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
                        profile: wire::CircuitProfile::NativeDlc as i32,
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
                    software_update_available: None,
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
                    software_update_available: None,
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
                    software_update_available: None,
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
            send(
                &mut socket,
                wire::ws_envelope::Body::OpenResult(wire::OpenResult {
                    request_id: open.request_id,
                    circuit_id: vec![],
                    accepted: false,
                    peer_receive_allowance_bytes: 0,
                    reason: wire::OpenFailure::RouteGone as i32,
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("expected retried open")
            };
            let retried = wire::WsEnvelope::decode(payload).unwrap();
            let Some(wire::ws_envelope::Body::OpenRequest(retried)) = retried.body else {
                panic!("expected retried open request")
            };
            assert!(retried.request_id > open.request_id);
            assert_eq!(retried.source_route, Some(source));
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
        let first_request_id = port.request_id;
        let deadline = Instant::now() + Duration::from_secs(2);
        while port.request_id == first_request_id && Instant::now() < deadline {
            port.poll(true).unwrap();
            port.tick().unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        assert!(port.request_id > first_request_id);
        server.join().unwrap();
    }

    #[test]
    fn v2_gateway_targets_share_one_export_and_open_independent_circuits() {
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
                    software_update_available: None,
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("snapshot")
            };
            let Some(wire::ws_envelope::Body::PublishRoutes(snapshot)) =
                wire::WsEnvelope::decode(payload).unwrap().body
            else {
                panic!("published routes")
            };
            assert_eq!(snapshot.routes.len(), 2);
            let source_id = snapshot.routes.iter().find(|route| matches!(route.resource.as_ref(),
                Some(wire::route_export::Resource::LogicalUnit(lu)) if lu.lu.as_ref() == Some(&name("QABOB", "LUB")))).unwrap().id;
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 1,
                        routes: ["LUA", "LUC"]
                            .into_iter()
                            .enumerate()
                            .map(|(index, lu)| wire::RouteExport {
                                id: 90 + index as u64,
                                generation: 1,
                                resource: Some(wire::route_export::Resource::LogicalUnit(
                                    wire::LuReachability {
                                        lu: Some(name("QAALICE", lu)),
                                        hosting_cp: Some(name("QAALICE", "SNAA")),
                                        supported_types: vec![wire::LuType::LuType62 as i32],
                                    },
                                )),
                            })
                            .collect(),
                    }),
                }),
            );
            let mut target_ids = HashSet::new();
            let mut request_ids = HashSet::new();
            for _ in 0..2 {
                let WsMessage::Binary(payload) = socket.read().unwrap() else {
                    panic!("open")
                };
                let Some(wire::ws_envelope::Body::OpenRequest(open)) =
                    wire::WsEnvelope::decode(payload).unwrap().body
                else {
                    panic!("open request")
                };
                assert_eq!(open.source_route.as_ref().unwrap().route_id, source_id);
                target_ids.insert(open.target.unwrap().route_id);
                request_ids.insert(open.request_id);
            }
            assert_eq!(target_ids, HashSet::from([90, 91]));
            assert_eq!(request_ids.len(), 2);
        });
        let configs = ["LUA", "LUC"]
            .into_iter()
            .map(|lu| Config {
                url: url.clone(),
                bearer: "test-token".into(),
                local_cp: name("QABOB", "SNAB"),
                target_cp: name("QAALICE", "SNAA"),
                target_lu: Some(name("QAALICE", lu)),
            })
            .collect();
        let source_lu = name("QABOB", "LUB");
        let mut ports = WsRoutePort::connect_gateway_targets_v2(
            configs,
            vec![wire::LuReachability {
                lu: Some(source_lu.clone()),
                hosting_cp: Some(name("QABOB", "SNAB")),
                supported_types: vec![wire::LuType::LuType62 as i32],
            }],
            source_lu,
        )
        .unwrap();
        for port in &mut ports {
            port.send(RoutedUnit::DlcType1(vec![4, 4, 0xaf])).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while ports.iter().any(|port| !port.opening) && Instant::now() < deadline {
            for port in &mut ports {
                port.poll(true).unwrap();
            }
        }
        assert!(ports.iter().all(|port| port.opening));
        server.join().unwrap();
    }

    #[test]
    fn v2_incoming_open_selects_configured_source_lu_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
        let (routes_tx, routes_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let (decisions_tx, decisions_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
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
                    software_update_available: None,
                }),
            );
            let WsMessage::Binary(payload) = socket.read().unwrap() else {
                panic!("snapshot")
            };
            let Some(wire::ws_envelope::Body::PublishRoutes(snapshot)) =
                wire::WsEnvelope::decode(payload).unwrap().body
            else {
                panic!("routes")
            };
            let hosted_id = snapshot.routes.iter().find(|route| matches!(route.resource.as_ref(),
                Some(wire::route_export::Resource::LogicalUnit(lu)) if lu.lu.as_ref() == Some(&name("QABOB", "LUB")))).unwrap().id;
            let target = wire::RouteReference {
                router_id: vec![7; 16],
                epoch: vec![8; 16],
                route_id: hosted_id,
                route_generation: 1,
            };
            send(
                &mut socket,
                wire::ws_envelope::Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: vec![9; 16],
                    snapshot: Some(wire::RouteSnapshot {
                        epoch: vec![10; 16],
                        revision: 1,
                        routes: ["LUA", "LUC"]
                            .into_iter()
                            .enumerate()
                            .map(|(index, lu)| wire::RouteExport {
                                id: 90 + index as u64,
                                generation: 1,
                                resource: Some(wire::route_export::Resource::LogicalUnit(
                                    wire::LuReachability {
                                        lu: Some(name("QAALICE", lu)),
                                        hosting_cp: Some(name("QAALICE", "SNAA")),
                                        supported_types: vec![wire::LuType::LuType62 as i32],
                                    },
                                )),
                            })
                            .collect(),
                    }),
                }),
            );
            routes_tx.send(()).unwrap();
            start_rx.recv().unwrap();
            for (id, source_router_id) in [(1u8, vec![9; 16]), (2u8, vec![6; 16])] {
                send(
                    &mut socket,
                    wire::ws_envelope::Body::IncomingOpen(wire::IncomingOpen {
                        circuit_id: vec![id; 16],
                        source_router_id,
                        target: Some(target.clone()),
                        source_receive_allowance_bytes: 1500,
                        source_route: Some(wire::RouteReference {
                            router_id: vec![9; 16],
                            epoch: vec![10; 16],
                            route_id: 91,
                            route_generation: 1,
                        }),
                        profile: wire::CircuitProfile::NativeDlc as i32,
                    }),
                );
            }
            let mut decisions = Vec::new();
            for _ in 0..2 {
                let WsMessage::Binary(payload) = socket.read().unwrap() else {
                    panic!("decision")
                };
                let Some(wire::ws_envelope::Body::OpenDecision(decision)) =
                    wire::WsEnvelope::decode(payload).unwrap().body
                else {
                    panic!("open decision")
                };
                decisions.push(decision);
            }
            decisions_tx.send(decisions).unwrap();
            done_rx.recv().unwrap();
        });
        let configs = ["LUA", "LUC"]
            .into_iter()
            .map(|lu| Config {
                url: url.clone(),
                bearer: "test-token".into(),
                local_cp: name("QABOB", "SNAB"),
                target_cp: name("QAALICE", "SNAA"),
                target_lu: Some(name("QAALICE", lu)),
            })
            .collect();
        let source_lu = name("QABOB", "LUB");
        let mut ports = WsRoutePort::connect_gateway_targets_v2(
            configs,
            vec![wire::LuReachability {
                lu: Some(source_lu.clone()),
                hosting_cp: Some(name("QABOB", "SNAB")),
                supported_types: vec![wire::LuType::LuType62 as i32],
            }],
            source_lu,
        )
        .unwrap();
        routes_rx.recv().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while ports.iter().any(|port| port.target.is_none()) && Instant::now() < deadline {
            for port in &mut ports {
                port.poll(true).unwrap();
            }
        }
        assert!(ports.iter().all(|port| port.target.is_some()));
        start_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while ports[1].inbound_open.is_none() && Instant::now() < deadline {
            for port in &mut ports {
                port.poll(true).unwrap();
            }
        }
        let inbound = ports[1].take_inbound_open().unwrap();
        assert_eq!(inbound.circuit_id, vec![1; 16]);
        assert_eq!(inbound.source_router_id, vec![9; 16]);
        assert_eq!(inbound.source_route.route_id, 91);
        assert!(ports[0].take_inbound_open().is_none());
        let deadline = Instant::now() + Duration::from_secs(2);
        let decisions = loop {
            if let Ok(decisions) = decisions_rx.try_recv() {
                break decisions;
            }
            assert!(Instant::now() < deadline, "missing open decisions");
            for port in &mut ports {
                port.poll(true).unwrap();
            }
        };
        assert!(decisions
            .iter()
            .any(|decision| decision.circuit_id == vec![1; 16] && decision.accept));
        assert!(decisions
            .iter()
            .any(|decision| decision.circuit_id == vec![2; 16] && !decision.accept));
        done_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn v2_gateway_targets_reject_duplicate_targets_before_connecting() {
        let config = Config {
            url: "ws://127.0.0.1:9/router/v1/ws".into(),
            bearer: String::new(),
            local_cp: name("QABOB", "SNAB"),
            target_cp: name("QAALICE", "SNAA"),
            target_lu: Some(name("QAALICE", "LUA")),
        };
        let error = WsRoutePort::connect_gateway_targets_v2(
            vec![config.clone(), config],
            vec![wire::LuReachability {
                lu: Some(name("QABOB", "LUB")),
                hosting_cp: Some(name("QABOB", "SNAB")),
                supported_types: vec![wire::LuType::LuType62 as i32],
            }],
            name("QABOB", "LUB"),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("duplicate gateway target LU"));
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
    fn qa_cross_netid_lu_ids_fit_concentrator_signed_storage() {
        for (netid, cp) in [("QAALICE", "SNAA"), ("QABOB", "SNAB")] {
            let local = name(netid, cp);
            let snapshot = local_route_snapshot(
                &[8; 16],
                1,
                &local,
                &[],
                &[wire::LuReachability {
                    lu: Some(local.clone()),
                    hosting_cp: Some(local.clone()),
                    supported_types: vec![wire::LuType::LuType62 as i32],
                }],
            )
            .unwrap();
            assert_eq!(snapshot.routes.len(), 2);
            assert!(snapshot.routes[1].id > 0);
            assert!(snapshot.routes[1].id <= i64::MAX as u64);
            assert_ne!(snapshot.routes[1].id, snapshot.routes[0].id);
        }
    }

    #[test]
    fn only_transient_v2_open_rejections_retry() {
        assert!(retryable_open_failure(wire::OpenFailure::RouteGone as i32));
        assert!(retryable_open_failure(wire::OpenFailure::Busy as i32));
        for permanent in [
            wire::OpenFailure::Forbidden,
            wire::OpenFailure::Unsupported,
            wire::OpenFailure::Protocol,
            wire::OpenFailure::Unspecified,
        ] {
            assert!(!retryable_open_failure(permanent as i32));
        }
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
        assert!(validate_managed_bindings(std::slice::from_ref(&valid)).is_ok());
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
                        software_update_available: None,
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
    fn duplex_gateway_incoming_open_uses_responder_port_only() {
        let hosted = wire::RouteReference {
            router_id: vec![7; 16],
            epoch: vec![8; 16],
            route_id: 10,
            route_generation: 1,
        };
        let source = wire::RouteReference {
            router_id: vec![9; 16],
            epoch: vec![11; 16],
            route_id: 20,
            route_generation: 1,
        };
        let gateway = GatewayInbound {
            hosted_route: hosted.clone(),
            target_refs: vec![Some(source.clone()), Some(source.clone())],
            inbound_owner: Some(1),
        };
        let mut open = wire::IncomingOpen {
            circuit_id: vec![1; 16],
            source_router_id: source.router_id.clone(),
            target: Some(hosted),
            source_receive_allowance_bytes: 1500,
            source_route: Some(source),
            profile: wire::CircuitProfile::NativeDlc as i32,
        };
        assert_eq!(gateway.owner(&open), Some(1));
        open.source_router_id = vec![3; 16];
        assert_eq!(gateway.owner(&open), None);
        open.source_router_id = vec![9; 16];
        open.target.as_mut().unwrap().route_generation = 2;
        assert_eq!(gateway.owner(&open), None);
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
