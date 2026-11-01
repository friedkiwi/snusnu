//! WebSocket circuit adapter. The routing core sees the same SNA units as it
//! does on a local LLC port; only this module knows the concentrator protocol.

use crate::routing::{RoutePort, RoutedUnit, RouterEvent};
use router_core::packet_log::{decode_llc_pdu, decode_sna_information, hex_dump};
use std::{
    collections::{HashSet, VecDeque},
    io,
    time::Duration,
};
use tracing::{debug, info, warn};
use transport_ws::{wire, WsClient};

const INITIAL_ALLOWANCE: u64 = 1500;
const MAX_PENDING_EVENTS: usize = INITIAL_ALLOWANCE as usize;
const MAX_PENDING_TYPE1: usize = 16;

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) url: String,
    pub(crate) bearer: String,
    pub(crate) local_cp: wire::SnaName,
    pub(crate) target_cp: wire::SnaName,
}

struct Circuit {
    id: Vec<u8>,
    ready: bool,
    send_allowance: u64,
    sent_bytes: u64,
    receive_allowance: u64,
    received_bytes: u64,
}

pub(crate) struct WsRoutePort {
    client: WsClient,
    welcome: wire::RouterWelcome,
    local_cp: wire::SnaName,
    target_cp: wire::SnaName,
    target: Option<wire::RouteReference>,
    circuit: Option<Circuit>,
    opening: bool,
    local_ready: bool,
    request_id: u64,
    pending_type1: VecDeque<Vec<u8>>,
    pending_information: VecDeque<Vec<u8>>,
    // Each unit forwarded into the LLC endpoint remains retained here until
    // that endpoint's ACK releases its queue/pending I-frame slot.
    downstream_sizes: VecDeque<usize>,
}

impl WsRoutePort {
    pub(crate) fn connect(config: Config) -> io::Result<Self> {
        validate_name(&config.local_cp)?;
        validate_name(&config.target_cp)?;
        let (mut client, welcome) =
            WsClient::connect(&config.url, &config.bearer).map_err(io_error)?;
        let upstream_address = client
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".to_owned());
        info!(
            server = %server_authority(&config.url),
            upstream_address = %upstream_address,
            router_id = %format_uuid(&welcome.router_id),
            connection_epoch = %format_uuid(&welcome.connection_epoch),
            display_name = %welcome.display_name,
            local_cp = %format_cp(&config.local_cp),
            target_cp = %format_cp(&config.target_cp),
            "connected to concentrator"
        );
        let snapshot =
            local_route_snapshot(&welcome.connection_epoch, 1, &config.local_cp, &[], &[])?;
        client
            .send(envelope(wire::ws_envelope::Body::PublishRoutes(snapshot)))
            .map_err(io_error)?;
        info!(
            router_id = %format_uuid(&welcome.router_id),
            local_cp = %format_cp(&config.local_cp),
            route_id = 1,
            generation = 1,
            revision = 1,
            "published local CP route"
        );
        Ok(Self {
            client,
            welcome,
            local_cp: config.local_cp,
            target_cp: config.target_cp,
            target: None,
            circuit: None,
            opening: false,
            local_ready: false,
            request_id: 0,
            pending_type1: VecDeque::new(),
            pending_information: VecDeque::new(),
            downstream_sizes: VecDeque::new(),
        })
    }

    fn send_body(&mut self, body: wire::ws_envelope::Body) -> io::Result<()> {
        self.client.send(envelope(body)).map_err(io_error)
    }

    fn maybe_open(&mut self) -> io::Result<()> {
        if self.circuit.is_some() || self.opening || self.pending_type1.is_empty() {
            return Ok(());
        }
        let Some(target) = self.target.clone() else {
            return Ok(());
        };
        self.request_id = self
            .request_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("request ID exhausted"))?;
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
                if let Some(route) = snapshot.routes.into_iter().find(|route| {
                    matches!(&route.resource, Some(wire::route_export::Resource::ControlPoint(cp))
                        if *cp == self.target_cp)
                }) {
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
                        self.clear_circuit();
                        return Ok(vec![RouterEvent::Closed]);
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
                        "target CP withdrawn from route snapshot"
                    );
                    self.target = None;
                    if self.circuit.is_some() {
                        self.clear_circuit();
                        return Ok(vec![RouterEvent::Closed]);
                    }
                }
            }
            Body::OriginWithdraw(withdraw) => {
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
                        self.clear_circuit();
                        return Ok(vec![RouterEvent::Closed]);
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
                    info!(
                        target_cp = %format_cp(&self.target_cp),
                        virtual_mac = %format_mac(&binding.virtual_mac),
                        candidate_count = binding.candidates.len(),
                        "selected managed CP binding"
                    );
                    self.target = binding.candidates.into_iter().next();
                    self.maybe_open()?;
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

    fn incoming_open(&mut self, incoming: wire::IncomingOpen) -> io::Result<()> {
        if incoming.circuit_id.len() != 16 || incoming.source_router_id.len() != 16 {
            return Err(protocol("invalid incoming circuit ID"));
        }
        let target_ok = incoming.target.as_ref().is_some_and(|r| {
            r.router_id == self.welcome.router_id
                && r.epoch == self.welcome.connection_epoch
                && r.route_id == 1
                && r.route_generation == 1
        });
        let accept = target_ok && self.circuit.is_none() && !self.opening;
        let reason = if accept {
            wire::OpenFailure::Unspecified
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
            id: result.circuit_id,
            ready: true,
            send_allowance: result.peer_receive_allowance_bytes,
            sent_bytes: 0,
            receive_allowance: INITIAL_ALLOWANCE,
            received_bytes: 0,
        });
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
        self.circuit = None;
        self.opening = false;
        self.pending_type1.clear();
        self.pending_information.clear();
        self.downstream_sizes.clear();
        self.local_ready = false;
    }
}

impl RoutePort for WsRoutePort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if can_accept_information {
            if let Some(data) = self.pending_information.pop_front() {
                self.downstream_sizes.push_back(data.len());
                return Ok(Some(vec![RouterEvent::Unit(RoutedUnit::SnaInformation(
                    data,
                ))]));
            }
        }
        let Some(envelope) = self
            .client
            .recv_timeout(Duration::from_micros(100))
            .map_err(io_error)?
        else {
            return Ok(None);
        };
        let events = self.handle(envelope.body.ok_or_else(|| protocol("empty envelope"))?)?;
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
                Ok(true)
            }
        }
    }

    fn has_capacity(&self) -> bool {
        self.circuit
            .as_ref()
            .is_some_and(|c| c.ready && c.send_allowance.saturating_sub(c.sent_bytes) >= 1500)
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
        if let Some(host) = &lu.hosting_cp {
            validate_name(host)?;
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

fn validate_managed_bindings(bindings: &[wire::ManagedCpBinding]) -> io::Result<()> {
    let mut addresses = HashSet::new();
    for binding in bindings {
        if binding.virtual_mac.len() != 6
            || binding.virtual_mac[..3] != [0x02, 0x53, 0x4e]
            || !addresses.insert(binding.virtual_mac.as_slice())
        {
            return Err(protocol("invalid or duplicate managed virtual MAC"));
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

    fn name(netid: &str, name: &str) -> wire::SnaName {
        wire::SnaName {
            netid: netid.into(),
            name: name.into(),
        }
    }

    #[test]
    fn local_snapshot_exports_cp_and_lu_with_stable_distinct_ids() {
        let primary = name("SOLNET", "SNAA");
        let cp_b = name("SOLNET", "SNAB");
        let cp_c = name("SOLNET", "SNAC");
        let lu = wire::LuReachability {
            lu: Some(name("SOLNET", "USER1")),
            hosting_cp: Some(cp_b.clone()),
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
            control_point: None,
            virtual_mac: mac.to_vec(),
            candidates: vec![],
        };
        let valid = binding(&[0x02, 0x53, 0x4e, 0, 0, 1]);
        assert!(validate_managed_bindings(&[valid.clone()]).is_ok());
        assert!(validate_managed_bindings(&[valid.clone(), valid]).is_err());
        assert!(validate_managed_bindings(&[binding(&[0x02, 0x53, 0x4f, 0, 0, 1])]).is_err());
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
