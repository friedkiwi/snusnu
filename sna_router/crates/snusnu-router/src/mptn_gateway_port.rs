//! Nonblocking TCP62 ingress boundary for a virtual SNA gateway.
//!
//! The port owns bounded TCP associations and emits typed user
//! offers. It never sends a positive user Connect until the owning virtual
//! native leg returns a correlated positive BIND. Production capability sets
//! must be backed by live handlers; without X'83', V5R4 admission fails closed.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket},
};

use crate::local_status::{now_ms, LocalPeerStatus};
use router_core::session::{
    QualifiedName, SessionContract, SessionEvent, SessionIdentity, SessionUnit,
};
use std::time::Instant;
use transport_ip_sna::{
    anynet::{bind_udp, listen_tcp, TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_bind_negotiation::validate_positive_response,
    mptn_compensations::CompensationSet,
    mptn_connect::{Connect, Direction},
    mptn_ingress::{inspect_connect, IngressKind, IngressOffer, IngressPolicy, IngressSession},
    mptn_keepalive::{Keepalive, Kind as KeepaliveKind},
    mptn_management_responder::{ManagementResponder, Phase as ManagementPhase, V5Options},
    mptn_oob::{
        build_request as build_oob_request, Compensation as OobCompensation,
        Datagram as OobDatagram, Kind as OobKind,
    },
    mptn_oob_fallback::{
        Action as FallbackAction, Completion as FallbackCompletion, Fallback, Purpose,
    },
    mptn_oob_sequence::{Delivery, SequenceWindow},
    mptn_reverse_management::classify_reverse_management_connect_with_cp,
};

const MAX_INCOMING: usize = MAX_RECORD * 2;
const MAX_WRITES: usize = 2;
const MAX_ASSOCIATIONS: usize = 64;
/// Rejections before admission do not belong to a live TCP association.
pub(crate) const UNOWNED_ASSOCIATION_ID: u64 = u64::MAX;

pub(crate) struct GatewayConfig {
    pub local: SocketAddr,
    pub peer_ip: IpAddr,
    pub source_lu: String,
    pub destination_lu: String,
    pub available_compensations: CompensationSet,
    pub options: V5Options,
    pub cnos_mode: String,
    pub cnos_limit: u16,
    /// Caller asserts a prior TCP62 CNOS exchange is still valid at this
    /// peer. Set only after the corresponding native management is complete.
    pub allow_resumed_user: bool,
}

pub(crate) enum GatewayEvent {
    ManagementReady,
    UserBind(IngressOffer),
    UserNormal(TcpRecord),
    UserExpedited(TcpRecord),
    UserUdpExpedited { sequence: u16, reduced: Vec<u8> },
    UserUdpAbort { sequence: u16, reduced: Vec<u8> },
    OutboundUdpAbortAcknowledged,
    UserAbort(TcpRecord),
    Closed,
    Rejected(String),
}

enum SessionState {
    AwaitConnect,
    Management(ManagementResponder),
    UserAwaitResponse(IngressOffer),
    UserResponseQueued(IngressOffer),
    UserActive(IngressOffer),
}

enum Completion {
    ManagementConnect(Vec<u8>),
    ManagementCnos(Vec<u8>),
    ManagementBis(Vec<u8>),
    UserConnect(SessionUnit),
    UserRecord,
    TcpExpeditedAck,
}

struct PendingOob {
    compensation: OobCompensation,
    sequence: u16,
    peer: SocketAddr,
    request: Vec<u8>,
    response: Vec<u8>,
    trial: Option<SequenceWindow>,
}

struct PendingOutboundOob {
    purpose: Purpose,
    sequence: u16,
    request: Vec<u8>,
    fallback: Fallback,
}

struct Association {
    tcp: TcpSession,
    state: SessionState,
    /// Network-qualified identities admitted from this association's Connect.
    selected_lus: Option<(String, String)>,
    session: Option<SessionContract>,
    incoming: VecDeque<TcpRecord>,
    incoming_bytes: usize,
    writes: VecDeque<(usize, Completion)>,
    user_inflight: bool,
    oob: SequenceWindow,
    pending_oob: Option<PendingOob>,
    pending_tcp_expedited: Option<SequenceWindow>,
    outbound_sequence: u16,
    outbound_oob: Option<PendingOutboundOob>,
    recent_outbound_completed: VecDeque<u16>,
    late_tcp_acks_owed: u16,
    deferred_logical_ack: Option<TcpRecord>,
    outbound_abort_pending: bool,
}

/// A validated user Connect removed from the shared listener before a
/// carrier-neutral EE session source takes over its TCP and UDP scheduling.
pub(crate) struct DetachedUserAssociation {
    pub(crate) tcp: TcpSession,
    pub(crate) incoming: VecDeque<TcpRecord>,
    pub(crate) incoming_bytes: usize,
}

pub(crate) struct MptnGatewayPort {
    config: GatewayConfig,
    expected_peer_cp: Option<String>,
    dynamic_lus: bool,
    listener: TcpListener,
    udp: UdpSocket,
    active: Option<Association>,
    associations: BTreeMap<u64, Association>,
    next_association_id: u64,
    poll_cursor: u64,
    allowed_routes: Vec<(String, String)>,
    completed_by_association: BTreeMap<u64, usize>,
    management_ready: bool,
    completed_management_lus: Option<(String, String)>,
    completed_user_records: usize,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn reduced_connect_unit(data: &[u8]) -> io::Result<SessionUnit> {
    // TCP62 Connect connection data starts with the two-byte SNF. The
    // following three bytes are RH, then RU. Ingress validates this BIND.
    SessionUnit::from_reduced(data).map_err(io::Error::other)
}

fn remember_completed(recent: &mut VecDeque<u16>, sequence: u16) {
    if recent.len() == 64 {
        recent.pop_front();
    }
    recent.push_back(sequence);
}

impl MptnGatewayPort {
    /// Return the network-qualified LU pair admitted for this association.
    /// The caller uses the destination to select one circuit egress; the
    /// source is the identity learned from the peer, not a configured alias.
    pub(crate) fn offer_lus(offer: &IngressOffer) -> io::Result<(String, String)> {
        let source = offer.connect().source.qualified_lu()?;
        let destination = offer.connect().destination.qualified_lu()?;
        let identity = SessionIdentity::new(
            source.parse::<QualifiedName>().map_err(io::Error::other)?,
            destination
                .parse::<QualifiedName>()
                .map_err(io::Error::other)?,
        );
        Ok((
            identity.source_lu.to_string(),
            identity.target_lu.to_string(),
        ))
    }

    fn observe_association(&self, id: u64, event: Option<&GatewayEvent>) {
        let Some(status) = crate::status() else {
            return;
        };
        if id == UNOWNED_ASSOCIATION_ID {
            return;
        }
        let key = format!("mptn:{}:{}", self.config.local, self.config.peer_ip);
        let existing = status
            .snapshot()
            .local_peers
            .into_iter()
            .find(|peer| peer.key == key);
        let mut lus = existing
            .as_ref()
            .map(|peer| peer.lus.clone())
            .unwrap_or_default();
        let state = match event {
            Some(GatewayEvent::UserBind(offer)) => {
                let Ok(source_lu) = offer.connect().source.qualified_lu() else {
                    return;
                };
                if !lus.contains(&source_lu) {
                    lus.push(source_lu);
                    lus.sort();
                }
                "offered"
            }
            Some(GatewayEvent::ManagementReady) => {
                if let Some((source_lu, _)) = &self.completed_management_lus {
                    if !lus.contains(source_lu) {
                        lus.push(source_lu.clone());
                        lus.sort();
                    }
                }
                "management-ready"
            }
            Some(GatewayEvent::Closed | GatewayEvent::Rejected(_))
                if existing.is_some() && self.association_ids().is_empty() =>
            {
                "disconnected"
            }
            _ => {
                let active = if id == 0 {
                    self.active.as_ref()
                } else {
                    self.associations.get(&id)
                };
                if active.is_some_and(|association| {
                    matches!(association.state, SessionState::UserActive(_))
                }) && existing
                    .as_ref()
                    .is_some_and(|peer| peer.state != "connected")
                {
                    "connected"
                } else {
                    return;
                }
            }
        };
        let now = now_ms();
        status.upsert_peer(LocalPeerStatus {
            key,
            transport: "mptn".into(),
            locator: format!("{} <- {}", self.config.local, self.config.peer_ip),
            cp: None,
            lus,
            state: state.into(),
            first_seen_ms: now,
            last_seen_ms: now,
            last_error: None,
        });
    }

    pub(crate) fn bind(config: GatewayConfig) -> io::Result<Self> {
        Self::bind_with_mode(config, false)
    }

    /// Automatic routing admits a validated Connect LU pair before the
    /// destination is selected. The caller must either bind that offer to a
    /// private circuit or close its association; this does not acknowledge a
    /// user Connect on its own.
    pub(crate) fn bind_dynamic(config: GatewayConfig) -> io::Result<Self> {
        Self::bind_with_mode(config, true)
    }

    fn bind_with_mode(config: GatewayConfig, dynamic_lus: bool) -> io::Result<Self> {
        // Check the configured LU policy before reserving TCP/UDP port 397.
        if !dynamic_lus {
            IngressSession::new(IngressPolicy {
                source_lu: config.source_lu.clone(),
                destination_lu: config.destination_lu.clone(),
                user_mode: None,
                allow_blank_user_mode: true,
                available_compensations: config.available_compensations,
                forbidden_fqpcid: None,
            })?;
        }
        if config.local.ip() == config.peer_ip || config.cnos_limit == 0 {
            return Err(invalid("TCP62 gateway peer or CNOS policy invalid"));
        }
        let udp = bind_udp(config.local)?;
        let listener = listen_tcp(config.local)?;
        Ok(Self {
            config,
            expected_peer_cp: None,
            dynamic_lus,
            listener,
            udp,
            active: None,
            associations: BTreeMap::new(),
            next_association_id: 1,
            poll_cursor: 0,
            allowed_routes: Vec::new(),
            completed_by_association: BTreeMap::new(),
            management_ready: false,
            completed_management_lus: None,
            completed_user_records: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn management_ready(&self) -> bool {
        self.management_ready
    }

    /// The management FQPCID names the initiating CP, which may differ from
    /// the initiating LU named by the Connect and BIND.
    pub(crate) fn set_expected_peer_cp(&mut self, cp: String) {
        self.expected_peer_cp = Some(cp);
    }

    /// The last completed management exchange yields its validated LU pair
    /// once. Call after `GatewayEvent::ManagementReady` to publish local
    /// reachability before the peer opens a user session.
    pub(crate) fn take_management_lus(&mut self) -> Option<(String, String)> {
        self.completed_management_lus.take()
    }

    /// The duplex session manager owns UDP receive scheduling. A clone shares
    /// the same bound socket; only one side may call recv during a circuit.
    pub(crate) fn clone_udp_socket(&self) -> io::Result<UdpSocket> {
        self.udp.try_clone()
    }

    pub(crate) fn user_active(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|association| matches!(association.state, SessionState::UserActive(_)))
            || self
                .associations
                .values()
                .any(|association| matches!(association.state, SessionState::UserActive(_)))
    }

    /// Admit another exact LU pair on this listener. A peer may connect to
    /// several SNA targets through the same TCP/397 endpoint.
    pub(crate) fn allow_route(
        &mut self,
        source_lu: String,
        destination_lu: String,
    ) -> io::Result<()> {
        IngressSession::new(IngressPolicy {
            source_lu: source_lu.clone(),
            destination_lu: destination_lu.clone(),
            user_mode: None,
            allow_blank_user_mode: true,
            available_compensations: self.config.available_compensations,
            forbidden_fqpcid: None,
        })?;
        if (source_lu.as_str(), destination_lu.as_str())
            != (
                self.config.source_lu.as_str(),
                self.config.destination_lu.as_str(),
            )
            && !self
                .allowed_routes
                .contains(&(source_lu.clone(), destination_lu.clone()))
        {
            self.allowed_routes.push((source_lu, destination_lu));
        }
        Ok(())
    }

    /// One UDP receive, one TCP accept/read, one record and at most two queued
    /// writes per call. The virtual WebSocket leg supplies downstream credit.
    pub(crate) fn poll_once(
        &mut self,
        can_accept_information: bool,
    ) -> io::Result<Option<GatewayEvent>> {
        Ok(self
            .poll_association_once(can_accept_information)?
            .map(|(_, event)| event))
    }

    /// Poll every live association fairly. The identifier stays stable until
    /// close and must be passed to the matching completion or outbound call.
    pub(crate) fn poll_association_once(
        &mut self,
        can_accept_information: bool,
    ) -> io::Result<Option<(u64, GatewayEvent)>> {
        self.poll_association_once_with_credit(|_| can_accept_information)
    }

    /// Credit is specific to the association selected for this poll. A busy
    /// route cannot hold data from another TCP62 session on this listener.
    pub(crate) fn poll_association_once_with_credit(
        &mut self,
        can_accept_information: impl Fn(u64) -> bool,
    ) -> io::Result<Option<(u64, GatewayEvent)>> {
        self.poll_association_with_credit(can_accept_information, true)
    }

    /// Poll TCP only while an outbound MPTN circuit owns UDP/397. The caller
    /// must ensure the outbound circuit is the sole UDP receiver in this mode.
    pub(crate) fn poll_tcp_only_with_credit(
        &mut self,
        can_accept_information: impl Fn(u64) -> bool,
    ) -> io::Result<Option<(u64, GatewayEvent)>> {
        self.poll_association_with_credit(can_accept_information, false)
    }

    fn poll_association_with_credit(
        &mut self,
        can_accept_information: impl Fn(u64) -> bool,
        receive_udp: bool,
    ) -> io::Result<Option<(u64, GatewayEvent)>> {
        if receive_udp {
            if let Some(event) = self.poll_udp_for_association()? {
                return Ok(Some(event));
            }
        }
        // Give an already received UDP acknowledgement precedence over an
        // expiry observed in this same poll iteration.
        let ids = self.association_ids();
        for id in ids {
            let fallback = self.with_association(id, |port| {
                Self::poll_outbound_fallback_at(
                    &mut port.active,
                    port.config.peer_ip,
                    Instant::now(),
                    |bytes, peer| Self::send_oob_response(&port.udp, bytes, peer),
                )
            });
            if let Err(error) = fallback {
                if error.kind() == io::ErrorKind::TimedOut {
                    return Ok(Some((id, GatewayEvent::Rejected(error.to_string()))));
                }
                return Err(error);
            }
        }
        match self.listener.accept() {
            Ok((stream, peer)) if peer.ip() == self.config.peer_ip => {
                if self.association_ids().len() >= MAX_ASSOCIATIONS {
                    drop(stream);
                    return Ok(Some((
                        UNOWNED_ASSOCIATION_ID,
                        GatewayEvent::Rejected("TCP62 association capacity reached".into()),
                    )));
                }
                let association = Association {
                    tcp: TcpSession::new(stream)?,
                    state: SessionState::AwaitConnect,
                    selected_lus: None,
                    session: None,
                    incoming: VecDeque::new(),
                    incoming_bytes: 0,
                    writes: VecDeque::new(),
                    user_inflight: false,
                    oob: SequenceWindow::default(),
                    pending_oob: None,
                    pending_tcp_expedited: None,
                    outbound_sequence: 0,
                    outbound_oob: None,
                    recent_outbound_completed: VecDeque::new(),
                    late_tcp_acks_owed: 0,
                    deferred_logical_ack: None,
                    outbound_abort_pending: false,
                };
                if self.active.is_none() && self.associations.is_empty() {
                    self.active = Some(association);
                } else {
                    let id = self.next_association_id;
                    if id == UNOWNED_ASSOCIATION_ID {
                        return Err(invalid("TCP62 association ID exhausted"));
                    }
                    self.next_association_id = self
                        .next_association_id
                        .checked_add(1)
                        .ok_or_else(|| invalid("TCP62 association ID exhausted"))?;
                    self.associations.insert(id, association);
                }
            }
            Ok((stream, peer)) => {
                drop(stream);
                return Ok(Some((
                    UNOWNED_ASSOCIATION_ID,
                    GatewayEvent::Rejected(format!("TCP62 peer IP {peer} is not configured")),
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        let ids = self.association_ids();
        let Some(id) = ids
            .iter()
            .copied()
            .find(|id| *id >= self.poll_cursor)
            .or_else(|| ids.first().copied())
        else {
            return Ok(None);
        };
        self.poll_cursor = id.saturating_add(1);
        let completed_before = self.completed_user_records;
        let result = self.with_association(id, |port| {
            let mut association = port.active.take().unwrap();
            let result = port.poll_association(&mut association, can_accept_information(id));
            match result {
                Ok((event, keep)) => {
                    if keep {
                        port.active = Some(association);
                    }
                    Ok(event)
                }
                Err(error) => Ok(Some(GatewayEvent::Rejected(error.to_string()))),
            }
        });
        if id != 0 {
            let completed = self.completed_user_records - completed_before;
            *self.completed_by_association.entry(id).or_default() += completed;
            self.completed_user_records = completed_before;
        }
        let event = result?;
        if self.dynamic_lus {
            if let Some(GatewayEvent::UserBind(offer)) = event.as_ref() {
                let (source_lu, destination_lu) = Self::offer_lus(offer)?;
                tracing::info!(
                    association = id,
                    local_ip = %self.config.local.ip(),
                    peer_ip = %self.config.peer_ip,
                    source_lu,
                    destination_lu,
                    "TCP62 session destination discovered"
                );
            }
        }
        self.observe_association(id, event.as_ref());
        Ok(event.map(|event| (id, event)))
    }

    fn association_ids(&self) -> Vec<u64> {
        let mut ids = Vec::with_capacity(self.associations.len() + 1);
        if self.active.is_some() {
            ids.push(0);
        }
        ids.extend(self.associations.keys().copied());
        ids
    }

    fn with_association<T>(
        &mut self,
        id: u64,
        operation: impl FnOnce(&mut Self) -> io::Result<T>,
    ) -> io::Result<T> {
        if id == 0 {
            return operation(self);
        }
        let selected = self
            .associations
            .remove(&id)
            .ok_or_else(|| invalid("unknown TCP62 association ID"))?;
        let original = self.active.replace(selected);
        let result = operation(self);
        if let Some(selected) = self.active.take() {
            self.associations.insert(id, selected);
        }
        self.active = original;
        result
    }

    fn poll_outbound_fallback_at(
        active: &mut Option<Association>,
        peer_ip: IpAddr,
        now: Instant,
        mut send: impl FnMut(&[u8], SocketAddr) -> io::Result<()>,
    ) -> io::Result<()> {
        let Some(association) = active.as_mut() else {
            return Ok(());
        };
        let Some(pending) = association.outbound_oob.as_mut() else {
            return Ok(());
        };
        match pending.fallback.poll(now) {
            Some(FallbackAction::SendOob { purpose, sequence })
                if purpose == pending.purpose && sequence == pending.sequence =>
            {
                let peer = SocketAddr::new(peer_ip, 397);
                send(&pending.request, peer)?;
            }
            Some(FallbackAction::CloseUnresponsive) => {
                *active = None;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP62 expedited peer did not acknowledge TCP or UDP",
                ));
            }
            Some(_) => {
                return Err(invalid(
                    "TCP62 fallback action differs from pending expedited",
                ));
            }
            None => {}
        }
        Ok(())
    }

    fn poll_udp_for_association(&mut self) -> io::Result<Option<(u64, GatewayEvent)>> {
        let mut bytes = [0u8; MAX_RECORD];
        match self.udp.recv_from(&mut bytes) {
            Ok((len, peer)) if bytes.get(4) == Some(&0x83) && peer.ip() == self.config.peer_ip => {
                let datagram = match OobDatagram::decode(&bytes[..len]) {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        tracing::debug!(%peer, %error, "dropping malformed TCP62 OOB datagram");
                        return Ok(None);
                    }
                };
                let matching: Vec<_> = self
                    .association_ids()
                    .into_iter()
                    .filter(|id| {
                        self.association(*id).is_some_and(|association| {
                            matches!(&association.state, SessionState::UserActive(offer)
                            if datagram.matches_connect(offer.connect()))
                        })
                    })
                    .collect();
                let [id] = matching.as_slice() else {
                    tracing::debug!(%peer, sequence = datagram.sequence,
                        matches = matching.len(),
                        "dropping TCP62 OOB without unique active association");
                    return Ok(None);
                };
                let id = *id;
                self.with_association(id, |port| port.handle_udp_datagram(&bytes[..len], peer))
                    .map(|event| event.map(|event| (id, event)))
            }
            Ok((len, peer)) => self
                .handle_udp_datagram(&bytes[..len], peer)
                .map(|event| event.map(|event| (0, event))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn association(&self, id: u64) -> Option<&Association> {
        if id == 0 {
            self.active.as_ref()
        } else {
            self.associations.get(&id)
        }
    }

    fn handle_udp_datagram(
        &mut self,
        packet: &[u8],
        peer: SocketAddr,
    ) -> io::Result<Option<GatewayEvent>> {
        let mut bytes = [0u8; MAX_RECORD];
        let len = packet.len();
        bytes[..len].copy_from_slice(packet);
        match (len, peer) {
            (_, peer) if peer.ip() != self.config.peer_ip => Ok(None),
            (len, peer) if bytes.get(4) == Some(&0x84) => {
                let keepalive = Keepalive::decode(&bytes[..len])?;
                keepalive.validate_ingress(peer.ip(), self.config.local.ip())?;
                if keepalive.kind != KeepaliveKind::Request {
                    return Err(invalid("unsolicited TCP62 keepalive response"));
                }
                let response = Keepalive {
                    kind: KeepaliveKind::Response,
                    ..keepalive
                }
                .encode();
                if self.udp.send_to(&response, peer)? != response.len() {
                    return Err(invalid("partial TCP62 keepalive response"));
                }
                Ok(None)
            }
            (len, peer) if bytes.get(4) == Some(&0x83) => {
                let request = bytes[..len].to_vec();
                let datagram = OobDatagram::decode(&request)?;
                let association = self
                    .active
                    .as_mut()
                    .ok_or_else(|| invalid("TCP62 OOB without active association"))?;
                let SessionState::UserActive(offer) = &association.state else {
                    return Err(invalid("TCP62 OOB before active user BIND"));
                };
                if datagram.kind != OobKind::Request {
                    if !datagram.options.is_empty() || !datagram.matches_connect(offer.connect()) {
                        return Err(invalid(
                            "TCP62 OOB response identity or options unsupported",
                        ));
                    }
                    if association
                        .outbound_oob
                        .as_ref()
                        .is_none_or(|pending| pending.sequence != datagram.sequence)
                    {
                        if datagram.kind == OobKind::PositiveResponse
                            && association
                                .recent_outbound_completed
                                .contains(&datagram.sequence)
                        {
                            return Ok(None);
                        }
                        return Err(invalid(
                            "TCP62 OOB response options or sequence unsupported",
                        ));
                    }
                    let pending = association.outbound_oob.as_mut().unwrap();
                    let completion = pending
                        .fallback
                        .received_oob_response(&datagram, offer.connect())?;
                    match completion {
                        FallbackCompletion::ExpeditedAcknowledged => {
                            association.outbound_oob = None;
                            remember_completed(
                                &mut association.recent_outbound_completed,
                                datagram.sequence,
                            );
                            association.late_tcp_acks_owed = association
                                .late_tcp_acks_owed
                                .checked_add(1)
                                .filter(|count| *count <= 64)
                                .ok_or_else(|| invalid("TCP62 late ACK window full"))?;
                            if association.deferred_logical_ack.is_some() {
                                return Err(invalid("TCP62 logical expedited ACK queue full"));
                            }
                            association.deferred_logical_ack =
                                Some(TcpRecord::decode(vec![0, 0, 0, 5, 3])?);
                            return Ok(None);
                        }
                        FallbackCompletion::AbortAcknowledged
                            if pending.purpose == Purpose::Abort =>
                        {
                            association.outbound_oob = None;
                            remember_completed(
                                &mut association.recent_outbound_completed,
                                datagram.sequence,
                            );
                            return Ok(Some(GatewayEvent::OutboundUdpAbortAcknowledged));
                        }
                        FallbackCompletion::Rejected | FallbackCompletion::AbortAcknowledged => {
                            return Err(invalid("TCP62 OOB request was rejected"));
                        }
                    }
                }
                if datagram.kind != OobKind::Request
                    || !matches!(
                        datagram.compensation,
                        Some(OobCompensation::Expedited | OobCompensation::Abort)
                    )
                    || !datagram.options.is_empty()
                    || !datagram.matches_connect(offer.connect())
                {
                    return Err(invalid("TCP62 OOB request identity or profile unsupported"));
                }
                let response = datagram.positive_response()?;
                let sequence = datagram.sequence;
                if let Some(pending) = &association.pending_oob {
                    if pending.sequence != sequence
                        || pending.peer != peer
                        || pending.request != request
                    {
                        return Err(invalid("TCP62 OOB pending request changed"));
                    }
                    return Ok(None);
                }
                if association.pending_tcp_expedited.is_some() {
                    if datagram.compensation == Some(OobCompensation::Abort) {
                        return Err(invalid(
                            "TCP62 OOB Abort overlaps unconfirmed expedited delivery",
                        ));
                    }
                    if sequence != association.oob.next_tcp_sequence() {
                        return Err(invalid(
                            "TCP62 OOB overlaps unconfirmed TCP expedited sequence",
                        ));
                    }
                    association.pending_oob = Some(PendingOob {
                        compensation: OobCompensation::Expedited,
                        sequence,
                        peer,
                        request,
                        response,
                        trial: None,
                    });
                    return Ok(None);
                }
                let mut trial = association.oob.clone();
                match trial.receive_udp(sequence)? {
                    Delivery::Duplicate => {
                        Self::send_oob_response(&self.udp, &response, peer)?;
                        Ok(None)
                    }
                    Delivery::New => {
                        let reduced = datagram.user_data.to_vec();
                        let compensation = datagram.compensation.unwrap();
                        association.pending_oob = Some(PendingOob {
                            compensation,
                            sequence,
                            peer,
                            request,
                            response,
                            trial: Some(trial),
                        });
                        Ok(Some(match compensation {
                            OobCompensation::Expedited => {
                                GatewayEvent::UserUdpExpedited { sequence, reduced }
                            }
                            OobCompensation::Abort => {
                                GatewayEvent::UserUdpAbort { sequence, reduced }
                            }
                        }))
                    }
                }
            }
            (_, _) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP62 UDP/397 X'83' compensation handler unavailable",
            )),
        }
    }

    fn send_oob_response(socket: &UdpSocket, response: &[u8], peer: SocketAddr) -> io::Result<()> {
        if socket.send_to(response, peer)? != response.len() {
            return Err(invalid("partial TCP62 OOB response"));
        }
        Ok(())
    }

    fn poll_association(
        &mut self,
        association: &mut Association,
        can_accept_information: bool,
    ) -> io::Result<(Option<GatewayEvent>, bool)> {
        let mut completed = Vec::new();
        association
            .tcp
            .flush_with_completion(|len| completed.push(len))?;
        for len in completed {
            let (expected, completion) = association
                .writes
                .pop_front()
                .ok_or_else(|| invalid("untracked TCP62 write completion"))?;
            if len != expected {
                return Err(invalid("TCP62 write completion length mismatch"));
            }
            match (&mut association.state, completion) {
                (SessionState::Management(responder), Completion::ManagementConnect(bytes)) => {
                    responder.mark_connect_response_sent(&bytes)?;
                }
                (SessionState::Management(responder), Completion::ManagementCnos(bytes)) => {
                    responder.mark_cnos_reply_sent(&bytes)?;
                }
                (SessionState::Management(responder), Completion::ManagementBis(bytes)) => {
                    responder.mark_bis_reply_sent(&bytes)?;
                }
                (SessionState::UserResponseQueued(offer), Completion::UserConnect(unit)) => {
                    association
                        .session
                        .as_mut()
                        .ok_or_else(|| invalid("missing TCP62 user session"))?
                        .accept(&SessionEvent::BindResult {
                            accepted: true,
                            unit,
                        })
                        .map_err(io::Error::other)?;
                    association.state = SessionState::UserActive(offer.clone());
                }
                (SessionState::UserActive(_), Completion::UserRecord) => {
                    self.completed_user_records += 1;
                }
                (SessionState::UserActive(_), Completion::TcpExpeditedAck) => {}
                _ => return Err(invalid("TCP62 write completed in wrong gateway phase")),
            }
        }
        if !association.user_inflight && !association.outbound_abort_pending {
            if let Some(ack) = association.deferred_logical_ack.take() {
                association.user_inflight = true;
                return Ok((Some(GatewayEvent::UserExpedited(ack)), true));
            }
        }
        // Do not consume normal user data while the WebSocket/native leg has
        // no credit. A later Abort can still be buffered up to MAX_INCOMING.
        if let Some(records) = match association.tcp.receive_once() {
            Ok(records) => records,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                if let Some(session) = association.session.as_mut() {
                    let _ = session.accept(&SessionEvent::Reset);
                }
                return Ok((Some(GatewayEvent::Closed), false));
            }
            Err(error) => return Err(error),
        } {
            for record in records {
                let next = association
                    .incoming_bytes
                    .checked_add(record.bytes.len())
                    .ok_or_else(|| invalid("TCP62 ingress queue overflow"))?;
                if next > MAX_INCOMING {
                    return Err(invalid("TCP62 ingress queue full"));
                }
                association.incoming_bytes = next;
                association.incoming.push_back(record);
            }
        }
        let Some(front) = association.incoming.front() else {
            return Ok((None, true));
        };
        // A peer may pipeline the next record into the same TCP read. The
        // prior reply is not authoritative until its final byte was written.
        if !association.writes.is_empty() && front.kind != TcpKind::Abort {
            return Ok((None, true));
        }
        if association.outbound_abort_pending {
            return Ok((None, true));
        }
        if association.user_inflight
            || association
                .pending_oob
                .as_ref()
                .is_some_and(|pending| pending.compensation == OobCompensation::Abort)
            || (front.kind == TcpKind::Expedited
                && (association.pending_oob.is_some()
                    || association.pending_tcp_expedited.is_some()))
            || (!can_accept_information
                && matches!(association.state, SessionState::UserActive(_))
                && !matches!(front.kind, TcpKind::Abort | TcpKind::ExpeditedAck))
        {
            return Ok((None, true));
        }
        let record = association.incoming.pop_front().unwrap();
        association.incoming_bytes -= record.bytes.len();
        match &mut association.state {
            SessionState::AwaitConnect => {
                let route = if self.dynamic_lus {
                    Some(inspect_connect(&record.bytes)?)
                } else {
                    inspect_connect(&record.bytes).ok()
                };
                if !self.dynamic_lus {
                    if let Some(route) = &route {
                        let observed_netid =
                            route.source_lu.split_once('.').map(|(netid, _)| netid);
                        let configured_netid = self
                            .config
                            .source_lu
                            .split_once('.')
                            .map(|(netid, _)| netid);
                        if observed_netid != configured_netid {
                            tracing::warn!(
                                local_ip = %self.config.local.ip(),
                                peer_ip = %self.config.peer_ip,
                                source_lu = %route.source_lu,
                                destination_lu = %route.destination_lu,
                                observed_netid = observed_netid.unwrap_or("<missing>"),
                                configured_netid = configured_netid.unwrap_or("<missing>"),
                                "TCP62 source NETID rejected"
                            );
                            return Err(invalid(
                                "TCP62 source NETID differs from configured NETID",
                            ));
                        }
                    }
                }
                let (source_lu, destination_lu) = if self.dynamic_lus {
                    let route = route.as_ref().expect("dynamic Connect was inspected");
                    (route.source_lu.as_str(), route.destination_lu.as_str())
                } else {
                    route
                        .as_ref()
                        .and_then(|route| {
                            self.allowed_routes.iter().find(|pair| {
                                pair.0 == route.source_lu && pair.1 == route.destination_lu
                            })
                        })
                        .map(|pair| (pair.0.as_str(), pair.1.as_str()))
                        .unwrap_or((&self.config.source_lu, &self.config.destination_lu))
                };
                let mut ingress = IngressSession::new(IngressPolicy {
                    source_lu: source_lu.to_string(),
                    destination_lu: destination_lu.to_string(),
                    user_mode: None,
                    allow_blank_user_mode: true,
                    available_compensations: self.config.available_compensations,
                    forbidden_fqpcid: None,
                })?;
                if let Some(cp) = &self.expected_peer_cp {
                    ingress.set_expected_peer_cp(cp.clone());
                }
                let offer = ingress.receive(&record.bytes)?.clone();
                match offer.kind() {
                    IngressKind::Management => {
                        let admitted = classify_reverse_management_connect_with_cp(
                            offer.connect().clone(),
                            source_lu,
                            destination_lu,
                            self.expected_peer_cp.as_deref().unwrap_or(source_lu),
                            None,
                        )?;
                        let token = fresh_token()?;
                        let responder = ManagementResponder::new(
                            &admitted,
                            self.config.available_compensations,
                            self.config.options,
                            token,
                            &self.config.cnos_mode,
                            self.config.cnos_limit,
                        )?;
                        let bytes = responder.connect_response().to_vec();
                        association.selected_lus =
                            Some((source_lu.to_string(), destination_lu.to_string()));
                        association.state = SessionState::Management(responder);
                        Self::queue(
                            association,
                            bytes.clone(),
                            Completion::ManagementConnect(bytes),
                        )?;
                        Ok((None, true))
                    }
                    IngressKind::User { .. }
                        if self.management_ready || self.config.allow_resumed_user =>
                    {
                        let identity = SessionIdentity::new(
                            source_lu.parse().map_err(io::Error::other)?,
                            destination_lu.parse().map_err(io::Error::other)?,
                        );
                        let unit = reduced_connect_unit(offer.connect().connection_data())?;
                        let mut session = SessionContract::new(identity);
                        session
                            .accept(&SessionEvent::BindRequest(unit))
                            .map_err(io::Error::other)?;
                        association.session = Some(session);
                        association.state = SessionState::UserAwaitResponse(offer.clone());
                        Ok((Some(GatewayEvent::UserBind(offer)), true))
                    }
                    _ => Err(invalid("TCP62 user Connect before management completion")),
                }
            }
            SessionState::Management(responder) => {
                match responder.phase() {
                    ManagementPhase::AwaitCnos => {
                        let bytes = responder.accept_cnos(&record.bytes)?;
                        Self::queue(
                            association,
                            bytes.clone(),
                            Completion::ManagementCnos(bytes),
                        )?;
                    }
                    ManagementPhase::AwaitBis => {
                        let bytes = responder.accept_bis(&record.bytes)?;
                        Self::queue(association, bytes.clone(), Completion::ManagementBis(bytes))?;
                    }
                    ManagementPhase::AwaitUnbind => {
                        responder.accept_unbind(&record.bytes)?;
                        responder.mark_close_sent()?;
                        self.management_ready = true;
                        self.completed_management_lus = association.selected_lus.take();
                        return Ok((Some(GatewayEvent::ManagementReady), false));
                    }
                    _ => return Err(invalid("TCP62 management input before egress completion")),
                }
                Ok((None, true))
            }
            SessionState::UserAwaitResponse(_) | SessionState::UserResponseQueued(_) => {
                if record.kind == TcpKind::Abort {
                    if let Some(session) = association.session.as_mut() {
                        let _ = session.accept(&SessionEvent::Reset);
                    }
                    Ok((Some(GatewayEvent::UserAbort(record)), false))
                } else {
                    Err(invalid("TCP62 user data before native BIND response"))
                }
            }
            SessionState::UserActive(_) => {
                if record.kind == TcpKind::ExpeditedAck {
                    if association.late_tcp_acks_owed != 0 {
                        association.late_tcp_acks_owed -= 1;
                        return Ok((None, true));
                    }
                    let pending = association
                        .outbound_oob
                        .as_mut()
                        .ok_or_else(|| invalid("unsolicited TCP62 expedited ACK"))?;
                    pending.fallback.received_tcp_ack()?;
                    let sequence = pending.sequence;
                    association.outbound_oob = None;
                    remember_completed(&mut association.recent_outbound_completed, sequence);
                }
                if record.kind == TcpKind::Expedited {
                    let mut trial = association.oob.clone();
                    match trial.receive_tcp() {
                        Delivery::Duplicate => {
                            association.oob = trial;
                            Self::queue(
                                association,
                                vec![0, 0, 0, 5, 3],
                                Completion::TcpExpeditedAck,
                            )?;
                            return Ok((None, true));
                        }
                        Delivery::New => association.pending_tcp_expedited = Some(trial),
                    }
                }
                let event = match record.kind {
                    TcpKind::Normal | TcpKind::Segmented => GatewayEvent::UserNormal(record),
                    TcpKind::Expedited | TcpKind::ExpeditedAck => {
                        GatewayEvent::UserExpedited(record)
                    }
                    TcpKind::Abort => GatewayEvent::UserAbort(record),
                    TcpKind::Connect => return Err(invalid("duplicate TCP62 user Connect")),
                };
                association.user_inflight = true;
                Ok((Some(event), true))
            }
        }
    }

    fn queue(
        association: &mut Association,
        bytes: Vec<u8>,
        completion: Completion,
    ) -> io::Result<()> {
        if association.writes.len() >= MAX_WRITES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP62 gateway write queue full",
            ));
        }
        let len = bytes.len();
        association.tcp.queue(TcpRecord::decode(bytes)?)?;
        association.writes.push_back((len, completion));
        Ok(())
    }

    /// Accept the fully encoded TCP62 positive Connect returned only after
    /// the virtual native leg received a correlated +RSP(BIND). `false`
    /// means bounded TCP queue backpressure; caller retains its response.
    pub(crate) fn queue_user_bind_response(&mut self, bytes: &[u8]) -> io::Result<bool> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        let SessionState::UserAwaitResponse(offer) = &association.state else {
            return Err(invalid("no pending TCP62 user BIND"));
        };
        let response = Connect::decode(bytes)?;
        if response.direction != Direction::PositiveResponse
            || !offer.connect().matches_response(&response)
            || validate_positive_response(
                offer.connect().connection_data(),
                response.connection_data(),
            )
            .is_err()
        {
            return Err(invalid("TCP62 user BIND response is stale or invalid"));
        }
        if association.writes.len() >= MAX_WRITES || !association.tcp.has_capacity() {
            return Ok(false);
        }
        let unit = reduced_connect_unit(response.connection_data())?;
        association
            .session
            .as_ref()
            .ok_or_else(|| invalid("missing TCP62 user session"))?
            .clone()
            .accept(&SessionEvent::BindResult {
                accepted: true,
                unit: unit.clone(),
            })
            .map_err(io::Error::other)?;
        let offer = offer.clone();
        Self::queue(association, bytes.to_vec(), Completion::UserConnect(unit))?;
        association.state = SessionState::UserResponseQueued(offer);
        Ok(true)
    }

    /// A user record is accepted only when the virtual native/WS leg has
    /// retained it. This credit permits exactly one next TCP record.
    pub(crate) fn complete_user_record(&mut self) -> io::Result<()> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        if !matches!(association.state, SessionState::UserActive(_)) || !association.user_inflight {
            return Err(invalid("TCP62 user record completion without delivery"));
        }
        association.user_inflight = false;
        Ok(())
    }

    /// Commit an X'83' request only after the virtual native path reports
    /// exact LLC enqueue completion. Retransmissions remain unacknowledged
    /// while that delivery is pending.
    pub(crate) fn complete_udp_expedited(&mut self, sequence: u16) -> io::Result<()> {
        self.complete_udp(sequence, OobCompensation::Expedited)
    }

    /// An X'83' Abort is acknowledged only after native +RSP(UNBIND).
    pub(crate) fn complete_udp_abort(&mut self, sequence: u16) -> io::Result<()> {
        self.complete_udp(sequence, OobCompensation::Abort)?;
        self.active = None;
        Ok(())
    }

    fn complete_udp(&mut self, sequence: u16, compensation: OobCompensation) -> io::Result<()> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        let pending = association
            .pending_oob
            .as_ref()
            .ok_or_else(|| invalid("no pending TCP62 OOB request"))?;
        if pending.sequence != sequence || pending.compensation != compensation {
            return Err(invalid("TCP62 OOB completion sequence mismatch"));
        }
        let trial = pending
            .trial
            .clone()
            .ok_or_else(|| invalid("TCP62 OOB waits for TCP expedited completion"))?;
        Self::send_oob_response(&self.udp, &pending.response, pending.peer)?;
        association.oob = trial;
        association.pending_oob = None;
        Ok(())
    }

    /// TCP expedited reception and a UDP fallback copy share one sequence.
    /// The TCP copy becomes authoritative only after its native enqueue.
    pub(crate) fn complete_tcp_expedited(&mut self) -> io::Result<()> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        let trial = association
            .pending_tcp_expedited
            .take()
            .ok_or_else(|| invalid("no pending TCP expedited delivery"))?;
        if let Some(pending) = &association.pending_oob {
            if pending.trial.is_some() || pending.sequence != association.oob.next_tcp_sequence() {
                return Err(invalid("TCP62 OOB and TCP expedited sequence conflict"));
            }
            Self::send_oob_response(&self.udp, &pending.response, pending.peer)?;
            association.pending_oob = None;
        }
        association.oob = trial;
        Ok(())
    }

    /// Queue one fully converted outbound TCP62 user record. A `false`
    /// result consumes no native/WS credit. Completion is reported only
    /// after the socket accepts the record's final byte.
    pub(crate) fn queue_user_record(&mut self, record: &TcpRecord) -> io::Result<bool> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        if !matches!(association.state, SessionState::UserActive(_))
            || matches!(record.kind, TcpKind::Connect | TcpKind::Abort)
            || association.outbound_abort_pending
            || TcpRecord::decode(record.bytes.clone())?.kind != record.kind
        {
            return Err(invalid("outbound TCP62 user record is not admissible"));
        }
        if association.writes.len() >= MAX_WRITES || !association.tcp.has_capacity() {
            return Ok(false);
        }
        let outbound = if record.kind == TcpKind::Expedited {
            if association.outbound_oob.is_some() {
                return Ok(false);
            }
            let SessionState::UserActive(offer) = &association.state else {
                unreachable!()
            };
            let sequence = association.outbound_sequence;
            let request = build_oob_request(
                offer.connect(),
                sequence,
                OobCompensation::Expedited,
                &record.bytes[5..],
            )?;
            let mut fallback = Fallback::default();
            fallback.sent_tcp_expedited(sequence, Instant::now())?;
            Some(PendingOutboundOob {
                purpose: Purpose::Expedited,
                sequence,
                request,
                fallback,
            })
        } else {
            None
        };
        match Self::queue(association, record.bytes.clone(), Completion::UserRecord) {
            Ok(()) => {
                if let Some(pending) = outbound {
                    association.outbound_oob = Some(pending);
                    association.outbound_sequence = association.outbound_sequence.wrapping_add(1);
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Send native-initiated UNBIND over X'83' immediately. The candidate
    /// comes from the validated virtual native close bridge. No TCP X'10'
    /// is queued, and the native +RSP waits for the correlated UDP positive.
    pub(crate) fn queue_udp_abort(&mut self, record: &TcpRecord) -> io::Result<bool> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        Self::queue_udp_abort_with(association, self.config.peer_ip, record, |bytes, peer| {
            Self::send_oob_response(&self.udp, bytes, peer)
        })
    }

    fn queue_udp_abort_with(
        association: &mut Association,
        peer_ip: IpAddr,
        record: &TcpRecord,
        mut send: impl FnMut(&[u8], SocketAddr) -> io::Result<()>,
    ) -> io::Result<bool> {
        let SessionState::UserActive(offer) = &association.state else {
            return Err(invalid("UDP Abort requires active TCP62 user BIND"));
        };
        if record.kind != TcpKind::Abort
            || TcpRecord::decode(record.bytes.clone())?.kind != TcpKind::Abort
            || record.bytes.len() <= 5
        {
            return Err(invalid("native UNBIND is not a valid TCP62 Abort image"));
        }
        if association.outbound_abort_pending {
            return Err(invalid("duplicate outbound UDP Abort"));
        }
        // A previous TCP X'01' has an unsequenced X'03' ACK; wait for its
        // bounded completion before allocating the Abort sequence. Also
        // flush already queued TCP bytes before committing session close.
        if association.outbound_oob.is_some() || !association.writes.is_empty() {
            return Ok(false);
        }
        let sequence = association.outbound_sequence;
        let request = build_oob_request(
            offer.connect(),
            sequence,
            OobCompensation::Abort,
            &record.bytes[5..],
        )?;
        let mut fallback = Fallback::default();
        if fallback.begin_abort(sequence, Instant::now())?
            != (FallbackAction::SendOob {
                purpose: Purpose::Abort,
                sequence,
            })
        {
            return Err(invalid("TCP62 Abort fallback failed to start"));
        }
        let peer = SocketAddr::new(peer_ip, 397);
        match send(&request, peer) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
        association.outbound_sequence = sequence.wrapping_add(1);
        association.outbound_abort_pending = true;
        association.outbound_oob = Some(PendingOutboundOob {
            purpose: Purpose::Abort,
            sequence,
            request,
            fallback,
        });
        Ok(true)
    }

    pub(crate) fn take_completed_user_records(&mut self) -> usize {
        std::mem::take(&mut self.completed_user_records)
    }

    pub(crate) fn user_active_for(&self, id: u64) -> bool {
        self.association(id)
            .is_some_and(|association| matches!(association.state, SessionState::UserActive(_)))
    }

    #[cfg(test)]
    pub(crate) fn live_association_ids(&self) -> Vec<u64> {
        self.association_ids()
    }

    pub(crate) fn close_association_for(&mut self, id: u64) -> io::Result<()> {
        if id == 0 {
            self.active
                .take()
                .ok_or_else(|| invalid("unknown TCP62 association ID"))?;
        } else {
            self.associations
                .remove(&id)
                .ok_or_else(|| invalid("unknown TCP62 association ID"))?;
            self.completed_by_association.remove(&id);
        }
        Ok(())
    }

    pub(crate) fn detach_validated_user_for(
        &mut self,
        id: u64,
        offer: &IngressOffer,
    ) -> io::Result<DetachedUserAssociation> {
        let association = self
            .association(id)
            .ok_or_else(|| invalid("unknown TCP62 user association"))?;
        let SessionState::UserAwaitResponse(admitted) = &association.state else {
            return Err(invalid(
                "TCP62 association is not awaiting a user BIND response",
            ));
        };
        if !matches!(offer.kind(), IngressKind::User { .. })
            || admitted.connect() != offer.connect()
            || association.user_inflight
            || !association.writes.is_empty()
            || association.pending_oob.is_some()
            || association.outbound_oob.is_some()
            || association.pending_tcp_expedited.is_some()
        {
            return Err(invalid("TCP62 user association changed before detach"));
        }
        let detached = if id == 0 {
            self.active.take().unwrap()
        } else {
            self.completed_by_association.remove(&id);
            self.associations.remove(&id).unwrap()
        };
        Ok(DetachedUserAssociation {
            tcp: detached.tcp,
            incoming: detached.incoming,
            incoming_bytes: detached.incoming_bytes,
        })
    }

    pub(crate) fn queue_user_bind_response_for(
        &mut self,
        id: u64,
        bytes: &[u8],
    ) -> io::Result<bool> {
        self.with_association(id, |port| port.queue_user_bind_response(bytes))
    }

    pub(crate) fn complete_user_record_for(&mut self, id: u64) -> io::Result<()> {
        self.with_association(id, Self::complete_user_record)
    }

    pub(crate) fn complete_udp_expedited_for(&mut self, id: u64, sequence: u16) -> io::Result<()> {
        self.with_association(id, |port| port.complete_udp_expedited(sequence))
    }

    pub(crate) fn complete_udp_abort_for(&mut self, id: u64, sequence: u16) -> io::Result<()> {
        self.with_association(id, |port| port.complete_udp_abort(sequence))
    }

    pub(crate) fn complete_tcp_expedited_for(&mut self, id: u64) -> io::Result<()> {
        self.with_association(id, Self::complete_tcp_expedited)
    }

    pub(crate) fn queue_user_record_for(
        &mut self,
        id: u64,
        record: &TcpRecord,
    ) -> io::Result<bool> {
        self.with_association(id, |port| port.queue_user_record(record))
    }

    pub(crate) fn queue_udp_abort_for(&mut self, id: u64, record: &TcpRecord) -> io::Result<bool> {
        self.with_association(id, |port| port.queue_udp_abort(record))
    }

    pub(crate) fn take_completed_user_records_for(&mut self, id: u64) -> usize {
        if id == 0 {
            self.take_completed_user_records()
        } else {
            self.completed_by_association
                .remove(&id)
                .unwrap_or_default()
        }
    }
}

fn fresh_token() -> io::Result<[u8; 7]> {
    use std::{fs::File, io::Read};
    let mut random = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    if random == [0; 4] {
        return Err(invalid("TCP62 BIND token entropy was zero"));
    }
    Ok([0x23, random[0], random[1], random[2], random[3], 0x80, 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpStream, UdpSocket},
        thread,
        time::Duration,
    };
    use transport_ip_sna::mptn_management_initiator::ManagementInitiator;

    fn request() -> ManagementInitiator {
        request_to("QAALICE.SNAA", [0x11; 8])
    }

    fn request_to(destination: &str, correlator: [u8; 8]) -> ManagementInitiator {
        let source = [0xd8, 0xc1, 0xc2, 0xd6, 0xc2, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2];
        let mut fqpcid = vec![0x60, 19];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(10);
        fqpcid.extend_from_slice(&source);
        ManagementInitiator::new(
            "QABOB.SNAB",
            destination,
            fqpcid,
            correlator,
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap()
    }

    fn peer_socket(address: SocketAddr) -> TcpStream {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket
            .bind(&SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 0).into())
            .unwrap();
        socket.connect(&address.into()).unwrap();
        socket.into()
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn oob_request(connect: &Connect, sequence: u16) -> Vec<u8> {
        let mut bytes = vec![0; 4];
        bytes.extend_from_slice(&[0x83, 0x02, 0, 0, 0, 0]);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&[0x0b, 0x01, (connect.source.node.len() + 1) as u8]);
        bytes.extend_from_slice(&connect.source.node);
        bytes.push(1);
        bytes.push((connect.correlator.len() + 1) as u8);
        bytes.extend_from_slice(&connect.correlator);
        let command_len = (bytes.len() - 4) as u32;
        bytes[6..10].copy_from_slice(&command_len.to_be_bytes());
        bytes.extend_from_slice(&[1, 0, 0x83, 1, 0, 0]);
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        bytes
    }

    #[test]
    fn rejects_tcp62_connect_from_another_netid_before_management() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut fqpcid = vec![0x60, 20];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(11);
        fqpcid.extend_from_slice(&[
            0xd6, 0xe3, 0xc8, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2,
        ]);
        let request = ManagementInitiator::new(
            "OTHNET.SNAB",
            "QAALICE.SNAA",
            fqpcid,
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let mut peer = peer_socket(port.listener.local_addr().unwrap());
        peer.write_all(request.connect_request()).unwrap();
        let mut rejected = None;
        for _ in 0..20 {
            if let Some((_, GatewayEvent::Rejected(reason))) =
                port.poll_association_once(true).unwrap()
            {
                rejected = Some(reason);
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            rejected.as_deref(),
            Some("TCP62 source NETID differs from configured NETID")
        );
    }

    #[test]
    fn dynamic_listener_admits_inspected_lu_pair_without_configured_netid() {
        let mut port = MptnGatewayPort::bind_dynamic(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: String::new(),
            destination_lu: String::new(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut peer = peer_socket(port.listener.local_addr().unwrap());
        peer.write_all(request_to("OTHNET.SNAC", [0x33; 8]).connect_request())
            .unwrap();
        for _ in 0..40 {
            if let Some((_, GatewayEvent::Rejected(reason))) =
                port.poll_association_once(true).unwrap()
            {
                panic!("dynamic listener rejected a valid LU pair: {reason}");
            }
            if port
                .active
                .as_ref()
                .is_some_and(|association| matches!(association.state, SessionState::Management(_)))
            {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("dynamic listener did not admit the Connect");
    }

    #[test]
    fn management_lus_are_available_only_after_completed_exchange() {
        fn read_record(peer: &mut TcpStream) -> Vec<u8> {
            let mut header = [0; 4];
            peer.read_exact(&mut header).unwrap();
            let length = u32::from_be_bytes(header) as usize;
            assert!((5..=MAX_RECORD).contains(&length));
            let mut bytes = vec![0; length];
            bytes[..4].copy_from_slice(&header);
            peer.read_exact(&mut bytes[4..]).unwrap();
            bytes
        }
        fn pump(port: &mut MptnGatewayPort) -> Option<GatewayEvent> {
            for _ in 0..20 {
                if let Some(event) = port.poll_once(true).unwrap() {
                    return Some(event);
                }
                thread::sleep(Duration::from_millis(1));
            }
            None
        }
        let mut port = MptnGatewayPort::bind_dynamic(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: String::new(),
            destination_lu: String::new(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: true,
                keepalive_handler: true,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut initiator = request();
        let mut peer = peer_socket(port.listener.local_addr().unwrap());
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        peer.write_all(initiator.connect_request()).unwrap();
        assert!(pump(&mut port).is_none());
        assert_eq!(port.take_management_lus(), None);
        let positive = read_record(&mut peer);
        let cnos = initiator.accept_connect_response(&positive).unwrap();
        peer.write_all(&cnos).unwrap();
        assert!(pump(&mut port).is_none());
        let cnos_reply = read_record(&mut peer);
        let bis = initiator.accept_cnos_reply(&cnos_reply).unwrap();
        peer.write_all(&bis).unwrap();
        assert!(pump(&mut port).is_none());
        let bis_reply = read_record(&mut peer);
        let unbind = initiator.accept_bis(&bis_reply).unwrap();
        peer.write_all(&unbind).unwrap();
        assert!(matches!(
            pump(&mut port),
            Some(GatewayEvent::ManagementReady)
        ));
        assert_eq!(
            port.take_management_lus(),
            Some(("QABOB.SNAB".into(), "QAALICE.SNAA".into()))
        );
        assert_eq!(port.take_management_lus(), None);
    }

    #[test]
    fn concurrent_peers_select_distinct_lu_routes_on_one_listener() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        port.allow_route("QABOB.SNAB".into(), "QAALICE.SNAC".into())
            .unwrap();
        let address = port.listener.local_addr().unwrap();
        let mut first = peer_socket(address);
        let mut second = peer_socket(address);
        first.write_all(request().connect_request()).unwrap();
        second
            .write_all(request_to("QAALICE.SNAC", [0x22; 8]).connect_request())
            .unwrap();
        for _ in 0..20 {
            if let Some((_, GatewayEvent::Rejected(reason))) =
                port.poll_association_once(true).unwrap()
            {
                panic!("unexpected rejection: {reason}");
            }
            if port.live_association_ids().len() == 2
                && port
                    .active
                    .as_ref()
                    .is_some_and(|a| matches!(a.state, SessionState::Management(_)))
                && port
                    .associations
                    .values()
                    .all(|a| matches!(a.state, SessionState::Management(_)))
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(port.live_association_ids(), vec![0, 1]);
        assert!(matches!(
            port.active.as_ref().unwrap().state,
            SessionState::Management(_)
        ));
        assert!(matches!(
            port.associations.get(&1).unwrap().state,
            SessionState::Management(_)
        ));
        let _wrong_peer = TcpStream::connect(address).unwrap();
        assert!(matches!(
            port.poll_association_once(true).unwrap(),
            Some((UNOWNED_ASSOCIATION_ID, GatewayEvent::Rejected(_)))
        ));
        assert!(port.active.is_some());
        port.close_association_for(0).unwrap();
        assert_eq!(port.live_association_ids(), vec![1]);
    }

    #[test]
    fn udp_oob_demuxes_by_connect_correlator_across_associations() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let address = port.listener.local_addr().unwrap();
        let mut first_client = peer_socket(address);
        let mut second_client = peer_socket(address);
        let make_association = |stream, correlator| {
            let mut ingress = IngressSession::new(IngressPolicy {
                source_lu: "QABOB.SNAB".into(),
                destination_lu: "QAALICE.SNAA".into(),
                user_mode: None,
                allow_blank_user_mode: false,
                available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                    .unwrap(),
                forbidden_fqpcid: None,
            })
            .unwrap();
            let offer = ingress
                .receive(request_to("QAALICE.SNAA", correlator).connect_request())
                .unwrap()
                .clone();
            Association {
                tcp: TcpSession::new(stream).unwrap(),
                state: SessionState::UserActive(offer),
                selected_lus: None,
                session: None,
                incoming: VecDeque::new(),
                incoming_bytes: 0,
                writes: VecDeque::new(),
                user_inflight: false,
                oob: SequenceWindow::default(),
                pending_oob: None,
                pending_tcp_expedited: None,
                outbound_sequence: 0,
                outbound_oob: None,
                recent_outbound_completed: VecDeque::new(),
                late_tcp_acks_owed: 0,
                deferred_logical_ack: None,
                outbound_abort_pending: false,
            }
        };
        let (first_stream, _) = port.listener.accept().unwrap();
        let (second_stream, _) = port.listener.accept().unwrap();
        port.active = Some(make_association(first_stream, [0x11; 8]));
        port.associations
            .insert(1, make_association(second_stream, [0x22; 8]));
        port.next_association_id = 2;
        let first = match &port.active.as_ref().unwrap().state {
            SessionState::UserActive(offer) => oob_request(offer.connect(), 0),
            _ => unreachable!(),
        };
        let second = match &port.associations.get(&1).unwrap().state {
            SessionState::UserActive(offer) => oob_request(offer.connect(), 0),
            _ => unreachable!(),
        };
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.send_to(&second, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(matches!(
            port.poll_association_once(true).unwrap(),
            Some((1, GatewayEvent::UserUdpExpedited { sequence: 0, .. }))
        ));
        assert!(port.active.as_ref().unwrap().pending_oob.is_none());
        assert!(port.associations.get(&1).unwrap().pending_oob.is_some());
        peer.send_to(&first, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(matches!(
            port.poll_association_once(true).unwrap(),
            Some((0, GatewayEvent::UserUdpExpedited { sequence: 0, .. }))
        ));
        port.complete_udp_expedited_for(1, 0).unwrap();
        assert!(port.associations.get(&1).unwrap().pending_oob.is_none());
        assert!(port.active.as_ref().unwrap().pending_oob.is_some());
        port.complete_udp_expedited_for(0, 0).unwrap();
        let normal = [0, 0, 0, 8, 0, 0, 1, 2];
        first_client.write_all(&normal).unwrap();
        second_client.write_all(&normal).unwrap();
        let mut second_delivered = false;
        for _ in 0..8 {
            if matches!(
                port.poll_association_once_with_credit(|id| id == 1)
                    .unwrap(),
                Some((1, GatewayEvent::UserNormal(_)))
            ) {
                second_delivered = true;
                break;
            }
        }
        assert!(
            second_delivered,
            "ready route must advance while other route lacks credit"
        );
        assert!(port.active.as_ref().unwrap().incoming.front().is_some());
        port.complete_user_record_for(1).unwrap();
        let mut first_delivered = false;
        for _ in 0..8 {
            if matches!(
                port.poll_association_once_with_credit(|_| true).unwrap(),
                Some((0, GatewayEvent::UserNormal(_)))
            ) {
                first_delivered = true;
                break;
            }
        }
        assert!(first_delivered);
        port.complete_user_record_for(0).unwrap();
        port.close_association_for(1).unwrap();
        peer.send_to(&second, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_association_once(true).unwrap().is_none());
        assert!(port.user_active_for(0));
    }

    #[test]
    fn udp_expedited_ack_waits_for_native_delivery_and_deduplicates_retry() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut client = peer_socket(port.listener.local_addr().unwrap());
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (stream, _) = port.listener.accept().unwrap();
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            user_mode: None,
            allow_blank_user_mode: false,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        let offer = ingress
            .receive(request().connect_request())
            .unwrap()
            .clone();
        let datagram = oob_request(offer.connect(), 0);
        let fallback = oob_request(offer.connect(), 1);
        let mut abort = oob_request(offer.connect(), 2);
        let abort_header = 4 + u32::from_be_bytes(abort[6..10].try_into().unwrap()) as usize;
        abort[abort_header] = 0x10;
        port.active = Some(Association {
            tcp: TcpSession::new(stream).unwrap(),
            state: SessionState::UserActive(offer),
            selected_lus: None,
            session: None,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            user_inflight: false,
            oob: SequenceWindow::default(),
            pending_oob: None,
            pending_tcp_expedited: None,
            outbound_sequence: 0,
            outbound_oob: None,
            recent_outbound_completed: VecDeque::new(),
            late_tcp_acks_owed: 0,
            deferred_logical_ack: None,
            outbound_abort_pending: false,
        });
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.send_to(&datagram, port.udp.local_addr().unwrap())
            .unwrap();
        let event = port.poll_once(true).unwrap().unwrap();
        assert!(matches!(
            event,
            GatewayEvent::UserUdpExpedited { sequence: 0, .. }
        ));
        let mut output = [0; MAX_RECORD];
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(port.complete_udp_expedited(1).is_err());
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        port.complete_udp_expedited(0).unwrap();
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().kind,
            OobKind::PositiveResponse
        );
        peer.send_to(&datagram, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().sequence,
            0
        );
        let tcp_expedited = [0, 0, 0, 10, 1, 0, 0x83, 1, 0, 0];
        client.write_all(&tcp_expedited).unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        port.poll_once(true).unwrap();
        let mut tcp_ack = [0; 5];
        client.read_exact(&mut tcp_ack).unwrap();
        assert_eq!(tcp_ack, [0, 0, 0, 5, 3]);
        client.write_all(&tcp_expedited).unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserExpedited(_))
        ));
        port.complete_user_record().unwrap();
        peer.send_to(&fallback, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        port.complete_tcp_expedited().unwrap();
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().sequence,
            1
        );
        peer.send_to(&abort, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserUdpAbort { sequence: 2, .. })
        ));
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(port.complete_udp_expedited(2).is_err());
        client.write_all(&[0, 0, 0, 8, 0, 0, 1, 2]).unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        port.complete_udp_abort(2).unwrap();
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().sequence,
            2
        );
        assert!(port.active.is_none());
    }

    #[test]
    fn resumed_qa_user_connect_is_held_for_native_bind_response() {
        // Sanitized byte shape from Bob's autonomous user Connect. The
        // BIND's variable LU lengths are 10 (QABOB) and 12 (QAALICE).
        let request = hex(concat!(
            "000000e4800a00e02a0b010dd8c1c1d3c9c3c54be2d5c1c1010b010bd8c1c2d6c24be2d5c1c201",
            "09b023f6611b4500000f00008005000000760000007620000508000601010a02008b00006b80003100",
            "1307b0b0513303838c8c8303060200000000000000944300000ad8c1c2d6c24be2d5c1c22c0009",
            "02404040404040404009030123f661184500000b04d8c1c2d6c24be2d5c1c20a1300b023f66118",
            "450000000cd8c1c1d3c9c3c54be2d5c1c16013e8e772dd240702490ad8c1c2d6c24be2d5c1c2",
            "2c0a01087bc3d6d5d5c5c3e31800000501190a000a0020010310831a00000584"
        ));
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut client = peer_socket(port.listener.local_addr().unwrap());
        client.write_all(&request).unwrap();
        let event = (0..1000)
            .find_map(|_| {
                let event = port.poll_once(true).unwrap();
                if event.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                event
            })
            .expect("user offer");
        assert!(matches!(event, GatewayEvent::UserBind(_)));
        assert!(!port.management_ready());
        assert!(!port.user_active());
        client.set_nonblocking(true).unwrap();
        let mut output = [0; 1];
        assert_eq!(
            client.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(client);
        port.active = None;
        port.config.allow_resumed_user = false;
        let mut next = peer_socket(port.listener.local_addr().unwrap());
        next.write_all(&request).unwrap();
        let denied = (0..1000)
            .find_map(|_| {
                let event = port.poll_once(true).unwrap();
                if event.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                event
            })
            .expect("default rejection");
        assert!(matches!(denied, GatewayEvent::Rejected(_)));
    }

    #[test]
    fn dynamic_user_offer_exposes_exact_destination_before_positive_reply() {
        let request = hex(concat!(
            "000000e4800a00e02a0b010dd8c1c1d3c9c3c54be2d5c1c1010b010bd8c1c2d6c24be2d5c1c201",
            "09b023f6611b4500000f00008005000000760000007620000508000601010a02008b00006b80003100",
            "1307b0b0513303838c8c8303060200000000000000944300000ad8c1c2d6c24be2d5c1c22c0009",
            "02404040404040404009030123f661184500000b04d8c1c2d6c24be2d5c1c20a1300b023f66118",
            "450000000cd8c1c1d3c9c3c54be2d5c1c16013e8e772dd240702490ad8c1c2d6c24be2d5c1c2",
            "2c0a01087bc3d6d5d5c5c3e31800000501190a000a0020010310831a00000584"
        ));
        let mut port = MptnGatewayPort::bind_dynamic(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: String::new(),
            destination_lu: String::new(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut peer = peer_socket(port.listener.local_addr().unwrap());
        peer.write_all(&request).unwrap();
        let (id, offer) = (0..1000)
            .find_map(|_| {
                let event = port.poll_association_once(true).unwrap();
                if event.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                match event {
                    Some((id, GatewayEvent::UserBind(offer))) => Some((id, offer)),
                    Some((_, GatewayEvent::Rejected(reason))) => panic!("rejected: {reason}"),
                    _ => None,
                }
            })
            .expect("dynamic user offer");
        assert_eq!(id, 0);
        assert_eq!(
            MptnGatewayPort::offer_lus(&offer).unwrap(),
            ("QABOB.SNAB".into(), "QAALICE.SNAA".into())
        );
        let session = port.active.as_ref().unwrap().session.as_ref().unwrap();
        assert_eq!(
            session.phase(),
            router_core::session::SessionPhase::AwaitBindResult
        );
        assert_eq!(session.identity.source_lu.to_string(), "QABOB.SNAB");
        assert_eq!(session.identity.target_lu.to_string(), "QAALICE.SNAA");
        let connection_data = offer.connect().connection_data();
        let unit = reduced_connect_unit(connection_data).unwrap();
        assert_eq!(unit.as_reduced(), connection_data);
        assert_eq!(unit.snf(), &connection_data[..2]);
        assert_eq!(unit.ru()[0], 0x31);
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn captured_shape_keepalive_replies_only_to_configured_pair() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: true,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let request = Keepalive {
            kind: KeepaliveKind::Request,
            source: Ipv4Addr::new(127, 0, 0, 2),
            destination: Ipv4Addr::LOCALHOST,
        }
        .encode();
        peer.send_to(&request, port.udp.local_addr().unwrap())
            .unwrap();
        port.poll_once(false).unwrap();
        let mut response = [0u8; 24];
        let (len, from) = peer.recv_from(&mut response).unwrap();
        assert_eq!(len, 24);
        assert_eq!(from, port.udp.local_addr().unwrap());
        assert_eq!(
            Keepalive::decode(&response).unwrap().kind,
            KeepaliveKind::Response
        );
        assert!(!port.management_ready());
    }

    #[test]
    fn production_default_rejects_v5_without_oob_handler() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let address = port.listener.local_addr().unwrap();
        let mut client = peer_socket(address);
        client.write_all(request().connect_request()).unwrap();
        let mut rejected = false;
        for _ in 0..1000 {
            if let Some(GatewayEvent::Rejected(reason)) = port.poll_once(true).unwrap() {
                assert!(reason.contains("compensation"));
                rejected = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(rejected);
        assert!(!port.management_ready());
        assert!(port.active.is_none());
    }

    #[test]
    fn outbound_user_credit_waits_for_socket_write_completion() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let address = port.listener.local_addr().unwrap();
        let mut client = peer_socket(address);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (stream, _) = port.listener.accept().unwrap();
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            user_mode: None,
            allow_blank_user_mode: false,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        // The offer is only a state placeholder here; this test isolates
        // actual TCP delivery credit from BIND conversion.
        let offer = ingress
            .receive(request().connect_request())
            .unwrap()
            .clone();
        port.active = Some(Association {
            tcp: TcpSession::new(stream).unwrap(),
            state: SessionState::UserActive(offer),
            selected_lus: None,
            session: None,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            user_inflight: false,
            oob: SequenceWindow::default(),
            pending_oob: None,
            pending_tcp_expedited: None,
            outbound_sequence: 0,
            outbound_oob: None,
            recent_outbound_completed: VecDeque::new(),
            late_tcp_acks_owed: 0,
            deferred_logical_ack: None,
            outbound_abort_pending: false,
        });
        let record = TcpRecord::decode(vec![0, 0, 0, 8, 0, 0, 1, 2]).unwrap();
        assert!(port.queue_user_record(&record).unwrap());
        assert_eq!(port.take_completed_user_records(), 0);
        port.poll_once(true).unwrap();
        assert_eq!(port.take_completed_user_records(), 1);
        assert_eq!(port.take_completed_user_records(), 0);
        let mut received = [0u8; 8];
        use std::io::Read;
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, record.bytes.as_slice());
        let expedited = TcpRecord::decode(vec![0, 0, 0, 10, 1, 0, 0x83, 1, 0, 0]).unwrap();
        let start = Instant::now();
        assert!(port.queue_user_record(&expedited).unwrap());
        let mut datagrams = Vec::new();
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            start + Duration::from_secs(4),
            |bytes, peer| {
                datagrams.push((bytes.to_vec(), peer));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].1, "127.0.0.2:397".parse().unwrap());
        let first = OobDatagram::decode(&datagrams[0].0).unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(first.compensation, Some(OobCompensation::Expedited));
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            start + Duration::from_secs(15),
            |bytes, peer| {
                datagrams.push((bytes.to_vec(), peer));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(datagrams.len(), 2);
        assert_eq!(datagrams[0], datagrams[1]);
        client.write_all(&[0, 0, 0, 5, 3]).unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserExpedited(_))
        ));
        port.complete_user_record().unwrap();
        let mut late = Vec::new();
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            start + Duration::from_secs(40),
            |bytes, _| {
                late.push(bytes.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert!(late.is_empty());
    }

    #[test]
    fn udp_positive_acknowledges_once_and_late_tcp_ack_precedes_next_sequence() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let mut client = peer_socket(port.listener.local_addr().unwrap());
        let (stream, _) = port.listener.accept().unwrap();
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            user_mode: None,
            allow_blank_user_mode: false,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        let offer = ingress
            .receive(request().connect_request())
            .unwrap()
            .clone();
        port.active = Some(Association {
            tcp: TcpSession::new(stream).unwrap(),
            state: SessionState::UserActive(offer),
            selected_lus: None,
            session: None,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            user_inflight: false,
            oob: SequenceWindow::default(),
            pending_oob: None,
            pending_tcp_expedited: None,
            outbound_sequence: 0,
            outbound_oob: None,
            recent_outbound_completed: VecDeque::new(),
            late_tcp_acks_owed: 0,
            deferred_logical_ack: None,
            outbound_abort_pending: false,
        });
        let expedited = TcpRecord::decode(vec![0, 0, 0, 10, 1, 0, 0x83, 1, 0, 0]).unwrap();
        assert!(port.queue_user_record(&expedited).unwrap());
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            Instant::now() + Duration::from_secs(4),
            |_, _| Ok(()),
        )
        .unwrap();
        let request = port
            .active
            .as_ref()
            .unwrap()
            .outbound_oob
            .as_ref()
            .unwrap()
            .request
            .clone();
        let response = OobDatagram::decode(&request)
            .unwrap()
            .positive_response()
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.send_to(&response, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(
            matches!(port.poll_once(true).unwrap(), Some(GatewayEvent::UserExpedited(ref record)) if record.bytes == [0,0,0,5,3])
        );
        port.complete_user_record().unwrap();
        assert_eq!(port.active.as_ref().unwrap().late_tcp_acks_owed, 1);
        assert!(port.queue_user_record(&expedited).unwrap());
        client.write_all(&[0, 0, 0, 5, 3]).unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        assert_eq!(port.active.as_ref().unwrap().late_tcp_acks_owed, 0);
        assert!(port.active.as_ref().unwrap().outbound_oob.is_some());
        client.write_all(&[0, 0, 0, 5, 3]).unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserExpedited(_))
        ));
        port.complete_user_record().unwrap();
        assert!(port.active.as_ref().unwrap().outbound_oob.is_none());
        peer.send_to(&response, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        assert!(port.active.is_some());

        // A native UNBIND uses UDP X'83' immediately, without writing a
        // TCP X'10'. Its positive response releases only the Abort event.
        let abort = TcpRecord::decode(hex("0000003b1000006b8000320f080100006014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c13513080100000c000be2d6d3d5c5e34be2d5c1c200")).unwrap();
        let mut sent = Vec::new();
        assert!(MptnGatewayPort::queue_udp_abort_with(
            port.active.as_mut().unwrap(),
            port.config.peer_ip,
            &abort,
            |bytes, destination| {
                sent.push((bytes.to_vec(), destination));
                Ok(())
            },
        )
        .unwrap());
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, "127.0.0.2:397".parse().unwrap());
        let datagram = OobDatagram::decode(&sent[0].0).unwrap();
        assert_eq!(datagram.compensation, Some(OobCompensation::Abort));
        assert_eq!(datagram.sequence, 2);
        assert_eq!(datagram.user_data, &abort.bytes[5..]);
        assert!(port.queue_user_record(&expedited).is_err());
        assert!(port.queue_udp_abort(&abort).is_err());
        let abort_response = datagram.positive_response().unwrap();
        peer.send_to(&abort_response, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::OutboundUdpAbortAcknowledged)
        ));
        assert!(port.active.as_ref().unwrap().outbound_oob.is_none());
        peer.send_to(&abort_response, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
    }
}
