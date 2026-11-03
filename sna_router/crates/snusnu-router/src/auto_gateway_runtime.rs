//! Identity helpers for session-selected TCP62/native gateway circuits.
//!
//! A TCP62 Connect names LUs, not APPN control points. The router therefore
//! gives its virtual APPN link a stable, distinct CP name in the source LU's
//! network. The target CP must come from an actual route's `hosting_cp` (or an
//! explicit operator hint); it cannot be guessed from the target LU name.

use crate::{
    config::{self, MptnGatewayConfig},
    local_status::{self, CircuitStatus},
    mptn_bidirectional_gateway::{fresh_management, pump_virtual},
    mptn_discovery::{MptnDiscovery, MptnDiscoverySnapshot, DISCOVERY_LEASE},
    mptn_gateway_port::{GatewayConfig, GatewayEvent, MptnGatewayPort},
    mptn_outbound_port::OutboundEndpoint,
    mptn_ws_reverse::{AutoReverseWsSession, ReverseWsConfig},
    remote::{Config as RemoteConfig, WsRoutePort},
    routing::{FailureScope, IdentityObservation, RoutePort, RoutedUnit, RouterEvent},
    virtual_ws_port::VirtualWsPort,
    ws_native_responder::WsNativeResponder,
};
use router_core::{
    xid3::{Role, Xid3},
    xid3_local::LocalLlcProfile,
};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::TcpRecord, mptn_compensations::CompensationSet, mptn_ingress::IngressOffer,
    mptn_management_responder::V5Options, mptn_reverse_user_bind::NativeAddress,
};
use transport_ws::wire;

const BASE36: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn stable_hash(seed: &[u8], netid: &str, name: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed
        .iter()
        .copied()
        .chain([0xff])
        .chain(netid.bytes())
        .chain([0xff])
        .chain(name.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Build the router-owned CP for one TCP62 attachment. `seed` should contain
/// a stable router identity and attachment ID, so reconnects retain the name.
/// An explicit CP may override the generated name, but must be in the LU's
/// NETID because the concentrator can only publish this router's NETID.
pub(crate) fn virtual_cp_for_source(
    source_lu: &wire::SnaName,
    seed: &[u8],
    configured_cp: Option<&str>,
) -> io::Result<wire::SnaName> {
    let source = config::parse_cp(&format!("{}.{}", source_lu.netid, source_lu.name))?;
    if let Some(configured_cp) = configured_cp.filter(|value| !value.is_empty()) {
        let cp = config::parse_cp(configured_cp)?;
        if cp.netid != source.netid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured virtual CP is outside the source LU NETID",
            ));
        }
        return Ok(cp);
    }
    // FNV-1a has defined, repeatable output across runs and Rust versions.
    // The seven base-36 digits give a stable router-specific SNA name.
    let mut hash = stable_hash(seed, &source.netid, &source.name);
    let mut name = [b'R'; 8];
    for position in (1..8).rev() {
        name[position] = BASE36[(hash % 36) as usize];
        hash /= 36;
    }
    Ok(wire::SnaName {
        netid: source.netid,
        name: String::from_utf8(name.to_vec()).expect("base36 is ASCII"),
    })
}

/// Build a virtual native APPN profile for a selected MPTN session. This
/// node ID belongs to the router's virtual link, not to the OS/400 peer.
pub(crate) fn virtual_xid(
    cp: &wire::SnaName,
    seed: &[u8],
    configured_station: Option<&str>,
    configured_node_id: Option<&str>,
    tg_number: u8,
) -> io::Result<Xid3> {
    let cp_qualified = format!("{}.{}", cp.netid, cp.name);
    config::parse_cp(&cp_qualified)?;
    let station = configured_station
        .filter(|value| !value.is_empty())
        .unwrap_or(&cp.name);
    let node_id = if let Some(value) = configured_node_id.filter(|value| !value.is_empty()) {
        if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway local_node_id must be eight hex digits",
            ));
        }
        u32::from_str_radix(value, 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid gateway local_node_id")
        })?
    } else {
        0xfff00000 | ((stable_hash(seed, &cp.netid, &cp.name) as u32) & 0x000fffff)
    };
    LocalLlcProfile {
        cp_name: cp_qualified,
        station_name: station.into(),
        node_id: node_id.to_be_bytes(),
        tg_number,
        max_receive_btu: 1496,
        max_iframes_before_ack: 1,
        role: Role::Secondary,
    }
    .build()
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("virtual XID3: {error}"),
        )
    })
}

/// An LU route needs a proven hosting CP before native APPN conversion.
#[allow(dead_code)] // Used when an automatic local target supplies only a CP hint.
pub(crate) fn require_hosting_cp(
    target_lu: &wire::SnaName,
    hosting_cp: Option<wire::SnaName>,
    configured_cp: Option<&str>,
) -> io::Result<wire::SnaName> {
    let hint = configured_cp
        .filter(|value| !value.is_empty())
        .map(config::parse_cp)
        .transpose()?;
    let cp = match hosting_cp {
        Some(cp) => cp,
        None => hint.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "target LU has no hosting CP")
        })?,
    };
    if cp.netid != target_lu.netid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target LU hosting CP is in another NETID",
        ));
    }
    let cp = config::parse_cp(&format!("{}.{}", cp.netid, cp.name))?;
    if hint.is_some_and(|hint| hint != cp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configured target CP disagrees with advertised LU hosting CP",
        ));
    }
    Ok(cp)
}

/// One TCP62 listener and its active, independent native WebSocket circuits.
/// The owning runtime calls `poll_once` alongside LLC and upstream polling.
pub(crate) struct AutoMptnGateway<'a> {
    config: &'a MptnGatewayConfig,
    listener: MptnGatewayPort,
    sessions: HashMap<u64, MptnToWsSession>,
    reverse: Option<AutoReverseWsSession>,
    reverse_status_id: Option<String>,
    udp_leased: bool,
    identity_observations: Vec<(String, IdentityObservation)>,
    closed_local_attachments: Vec<String>,
    management_lus: Vec<(String, String, String)>,
    discovery: MptnDiscovery,
}

impl Drop for AutoMptnGateway<'_> {
    fn drop(&mut self) {
        if let Some(status) = crate::status() {
            for session in self.sessions.values() {
                status.remove_circuit(&session.status_id);
            }
            if let Some(id) = &self.reverse_status_id {
                status.remove_circuit(id);
            }
        }
    }
}

impl<'a> AutoMptnGateway<'a> {
    pub(crate) fn bind(config: &'a MptnGatewayConfig) -> io::Result<Self> {
        Self::bind_on_port(config, 397)
    }

    fn bind_on_port(config: &'a MptnGatewayConfig, port: u16) -> io::Result<Self> {
        let required =
            CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).map_err(io::Error::other)?;
        let mut listener = MptnGatewayPort::bind_dynamic(GatewayConfig {
            local: SocketAddr::new(config.local_ip, port),
            peer_ip: config.peer_ip,
            source_lu: config.source_lu.clone(),
            destination_lu: config.destination_lu.clone(),
            available_compensations: required,
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })?;
        if !config.peer_cp.is_empty() {
            listener.set_expected_peer_cp(config.peer_cp.clone());
        }
        Ok(Self {
            config,
            listener,
            sessions: HashMap::new(),
            reverse: None,
            reverse_status_id: None,
            udp_leased: false,
            identity_observations: Vec::new(),
            closed_local_attachments: Vec::new(),
            management_lus: Vec::new(),
            discovery: MptnDiscovery::new(DISCOVERY_LEASE)?,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.config.id
    }

    #[allow(dead_code)] // Local MPTN converter checks this optional CP hint.
    pub(crate) fn configured_local_cp(&self) -> io::Result<Option<wire::SnaName>> {
        if self.config.local_cp.is_empty() {
            Ok(None)
        } else {
            config::parse_cp(&self.config.local_cp).map(Some)
        }
    }

    pub(crate) fn outbound_endpoint(&self) -> OutboundEndpoint {
        OutboundEndpoint {
            local_ip: self.config.local_ip,
            peer_ip: self.config.peer_ip,
        }
    }

    #[allow(dead_code)] // Mixed local gateway routing consumes this observation queue.
    pub(crate) fn take_identity_observations(&mut self) -> Vec<(String, IdentityObservation)> {
        std::mem::take(&mut self.identity_observations)
    }

    #[allow(dead_code)] // The mixed runtime releases reserved LLC proxy MACs through this queue.
    pub(crate) fn take_closed_local_attachments(&mut self) -> Vec<String> {
        std::mem::take(&mut self.closed_local_attachments)
    }

    /// Validated management Connect names make a cold local MPTN peer's LU
    /// visible before it starts any user BIND. CP comes from FQPCID.
    #[allow(dead_code)] // The mixed runtime consumes this queue during cold-start publication.
    pub(crate) fn take_management_lus(&mut self) -> Vec<(String, String, String)> {
        std::mem::take(&mut self.management_lus)
    }

    /// Complete, attachment-owned LU/CP reachability after a membership change.
    #[allow(dead_code)] // The shared registry integration will consume this snapshot.
    pub(crate) fn take_discovery_snapshot(&mut self) -> Option<MptnDiscoverySnapshot> {
        self.discovery.take_changed_snapshot()
    }

    #[allow(dead_code)] // The shared registry runtime will use this to schedule expiry.
    pub(crate) fn next_discovery_expiry(&self) -> Option<Instant> {
        self.discovery.next_expiry()
    }

    #[allow(dead_code)] // Called when the owning attachment is explicitly lost.
    pub(crate) fn withdraw_discovery(&mut self) -> io::Result<()> {
        self.discovery.withdraw_all()
    }

    /// A successful outbound SNASVCMG exchange proves the configured LU is
    /// reachable. Its CP still comes from the operator's explicit assertion.
    pub(crate) fn observe_configured_probe(
        &mut self,
        lu: router_core::session::QualifiedName,
        cp: router_core::session::QualifiedName,
    ) -> io::Result<()> {
        self.discovery.observe(lu, cp, Instant::now())
    }

    pub(crate) fn udp_available(&self) -> bool {
        !self.udp_leased && self.sessions.is_empty() && self.reverse.is_none()
    }

    /// Poll one transport event while progressing all active converters. A
    /// validated user BIND is returned to the owning fabric for destination
    /// selection; it remains pending in the TCP62 association until accepted.
    pub(crate) fn poll_once(&mut self) -> io::Result<Option<(u64, IngressOffer)>> {
        self.discovery.expire(Instant::now())?;
        if let Some(reverse) = &mut self.reverse {
            match reverse.poll_once() {
                Ok(true) => {
                    if reverse.is_active() {
                        if let (Some(status), Some(id)) = (crate::status(), &self.reverse_status_id)
                        {
                            if let Some(mut circuit) =
                                status.snapshot().circuits.into_iter().find(|circuit| {
                                    &circuit.id == id && circuit.state != "connected"
                                })
                            {
                                circuit.state = "connected".into();
                                circuit.last_change_ms = local_status::now_ms();
                                status.upsert_circuit(circuit);
                            }
                        }
                    }
                }
                Ok(false) => {
                    self.reverse = None;
                    self.clear_reverse_status();
                    self.release_udp();
                }
                Err(error) => {
                    tracing::warn!(gateway = %self.config.id, error = %error,
                        "automatic concentrator to TCP62 circuit failed");
                    self.reverse = None;
                    self.clear_reverse_status();
                    self.release_udp();
                }
            }
        }
        let ids = self.sessions.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let session = self.sessions.get_mut(&id).expect("session ID collected");
            let result = session.pump(&mut self.listener);
            if let Some(attachment) = &session.target_attachment {
                self.identity_observations.extend(
                    session
                        .port
                        .take_inner_identity_observations()
                        .into_iter()
                        .map(|identity| (attachment.clone(), identity)),
                );
            }
            match result {
                Ok(true) => {}
                Ok(false) => {
                    self.retire_session(id);
                }
                Err(error) => {
                    tracing::warn!(gateway = %self.config.id, association = id, error = %error,
                        "automatic TCP62 circuit failed");
                    let _ = self.listener.close_association_for(id);
                    self.retire_session(id);
                }
            }
        }
        let sessions = &self.sessions;
        let can_accept = |id| sessions.get(&id).is_none_or(MptnToWsSession::can_accept);
        let event_result = if self.udp_leased {
            self.listener.poll_tcp_only_with_credit(can_accept)
        } else {
            self.listener.poll_association_once_with_credit(can_accept)
        };
        let event = match event_result {
            Ok(event) => event,
            Err(error) => {
                self.discovery.withdraw_all()?;
                return Err(error);
            }
        };
        let Some((id, event)) = event else {
            return Ok(None);
        };
        if matches!(&event, GatewayEvent::ManagementReady) {
            if let Some(lus) = self.listener.take_management_lus() {
                let source: router_core::session::QualifiedName = lus.0.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid MPTN management source LU",
                    )
                })?;
                let cp = lus.2.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid MPTN management CP")
                })?;
                self.discovery.observe(source, cp, Instant::now())?;
                self.management_lus.push(lus);
            }
        }
        if let Some(session) = self.sessions.get_mut(&id) {
            match session.on_event(event, &mut self.listener) {
                Ok(true) => {}
                Ok(false) => {
                    self.retire_session(id);
                }
                Err(error) => {
                    tracing::warn!(gateway = %self.config.id, association = id, error = %error,
                        "automatic TCP62 circuit event rejected");
                    let _ = self.listener.close_association_for(id);
                    self.retire_session(id);
                }
            }
            return Ok(None);
        }
        match event {
            GatewayEvent::UserBind(offer) if !self.udp_leased => {
                let (source, _) = Self::offer_lus(&offer)?;
                let source = source.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid MPTN user source LU")
                })?;
                let cp = offer.peer_cp().parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid MPTN user CP")
                })?;
                if !self
                    .discovery
                    .refresh_if_known(&source, &cp, Instant::now())?
                {
                    tracing::debug!(gateway = %self.config.id, source_lu = %source, source_cp = %cp,
                        "TCP62 user BIND lacks matching completed management proof");
                }
                Ok(Some((id, offer)))
            }
            GatewayEvent::UserBind(_) => {
                self.listener.close_association_for(id)?;
                tracing::warn!(gateway = %self.config.id, association = id,
                    "TCP62 offer rejected while UDP/397 belongs to another circuit");
                Ok(None)
            }
            GatewayEvent::ManagementReady | GatewayEvent::Closed => Ok(None),
            GatewayEvent::Rejected(reason) => {
                tracing::warn!(gateway = %self.config.id, association = id, reason,
                    "automatic TCP62 association rejected");
                Ok(None)
            }
            _ => {
                self.listener.close_association_for(id)?;
                Ok(None)
            }
        }
    }

    pub(crate) fn offer_lus(offer: &IngressOffer) -> io::Result<(String, String)> {
        MptnGatewayPort::offer_lus(offer)
    }

    /// Legacy native-DLC converter used by explicit routes. Automatic LU 6.2
    /// routing uses SessionV1 after the validated TCP62 association detaches.
    /// Start one independently credited converter after the runtime has
    /// selected a unique destination and obtained a WebSocket circuit port.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)] // Circuit identity and converter policy are distinct inputs.
    pub(crate) fn start_to_ws(
        &mut self,
        association: u64,
        offer: IngressOffer,
        ws: WsRoutePort,
        local_cp: &wire::SnaName,
        target_cp: &wire::SnaName,
        seed: &[u8],
        timeout: Duration,
    ) -> io::Result<()> {
        self.start_to_native(
            association,
            offer,
            Box::new(ws),
            local_cp,
            target_cp,
            seed,
            timeout,
            "concentrator",
            None,
        )
    }

    #[allow(dead_code, clippy::too_many_arguments)] // Called by the local LLC gateway path.
    pub(crate) fn start_to_local(
        &mut self,
        association: u64,
        offer: IngressOffer,
        llc: Box<dyn RoutePort>,
        target_attachment: &str,
        local_cp: &wire::SnaName,
        target_cp: &wire::SnaName,
        seed: &[u8],
        timeout: Duration,
    ) -> io::Result<()> {
        self.start_to_native(
            association,
            offer,
            llc,
            local_cp,
            target_cp,
            seed,
            timeout,
            "llc",
            Some(target_attachment.to_owned()),
        )
    }

    #[allow(clippy::too_many_arguments)] // Shared constructor for two transport adapters.
    fn start_to_native(
        &mut self,
        association: u64,
        offer: IngressOffer,
        native: Box<dyn RoutePort>,
        local_cp: &wire::SnaName,
        target_cp: &wire::SnaName,
        seed: &[u8],
        timeout: Duration,
        egress_transport: &str,
        target_attachment: Option<String>,
    ) -> io::Result<()> {
        if self.udp_leased || self.sessions.contains_key(&association) || timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP62 association already active or timeout invalid",
            ));
        }
        let (source_lu, destination_lu) = Self::offer_lus(&offer)?;
        let source = config::parse_cp(&source_lu)?;
        let destination = config::parse_cp(&destination_lu)?;
        if source.netid != local_cp.netid || destination.netid != target_cp.netid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP62 offer NETIDs disagree with selected CPs",
            ));
        }
        let xid = virtual_xid(
            local_cp,
            seed,
            Some(&self.config.local_station),
            Some(&self.config.local_node_id),
            self.config.tg_number,
        )?;
        let local = format!("{}.{}", local_cp.netid, local_cp.name);
        let target = format!("{}.{}", target_cp.netid, target_cp.name);
        let mut port = VirtualWsPort::new(NativePort(native), xid, &local, &target)?;
        port.attach_management(fresh_management(&local, &target)?)?;
        let status_id = format!("mptn:{}:{association}", self.config.id);
        self.sessions.insert(
            association,
            MptnToWsSession {
                association,
                status_id: status_id.clone(),
                target_attachment,
                port,
                pending_offer: Some(offer),
                pending_tcp: None,
                pending_udp: None,
                user_started: false,
                setup_deadline: Instant::now() + timeout,
            },
        );
        tracing::info!(gateway = %self.config.id, association, source_lu, destination_lu,
            local_cp = %local, target_cp = %target,
            egress_transport, "automatic TCP62 circuit selected destination");
        if let Some(status) = crate::status() {
            status.upsert_circuit(CircuitStatus {
                id: status_id,
                ingress: format!("mptn:{}:{source_lu}", self.config.id),
                egress: format!("{egress_transport}:{destination_lu}"),
                state: "opening".into(),
                bytes_in: 0,
                bytes_out: 0,
                last_change_ms: local_status::now_ms(),
            });
        }
        Ok(())
    }

    pub(crate) fn reject_offer(&mut self, association: u64, reason: &str) -> io::Result<()> {
        tracing::warn!(gateway = %self.config.id, association, reason,
            "automatic TCP62 offer has no route");
        self.listener.close_association_for(association)
    }

    /// One UDP socket reader owns expedited and keepalive traffic at a time.
    /// The lease must be returned when an outbound session closes.
    pub(crate) fn lease_udp(&mut self) -> io::Result<std::net::UdpSocket> {
        if !self.udp_available() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "gateway UDP/397 is already owned by an active circuit",
            ));
        }
        let socket = self.listener.clone_udp_socket()?;
        self.udp_leased = true;
        Ok(socket)
    }

    pub(crate) fn release_udp(&mut self) {
        self.udp_leased = false;
    }

    /// Move one validated inbound TCP62 user association into an independent
    /// EE session source. The listener keeps its management associations and
    /// switches to TCP-only polling while the source owns UDP/397.
    pub(crate) fn detach_user_for_hpr(
        &mut self,
        association: u64,
        offer: &IngressOffer,
    ) -> io::Result<(
        crate::mptn_gateway_port::DetachedUserAssociation,
        std::net::UdpSocket,
    )> {
        let udp = self.lease_udp()?;
        match self.listener.detach_validated_user_for(association, offer) {
            Ok(detached) => Ok((detached, udp)),
            Err(error) => {
                self.release_udp();
                Err(error)
            }
        }
    }

    fn retire_session(&mut self, id: u64) {
        if let Some(session) = self.sessions.remove(&id) {
            if let Some(attachment) = session.target_attachment {
                self.closed_local_attachments.push(attachment);
            }
            if let Some(status) = crate::status() {
                status.remove_circuit(&session.status_id);
            }
        }
    }

    fn clear_reverse_status(&mut self) {
        if let Some(id) = self.reverse_status_id.take() {
            if let Some(status) = crate::status() {
                status.remove_circuit(&id);
            }
        }
    }

    /// Start an authenticated concentrator circuit toward this gateway's
    /// MPTN peer. The caller has already selected the local hosted LU and
    /// obtained a private WebSocket port from AutoWsHub.
    #[allow(clippy::too_many_arguments)] // Incoming circuit carries two qualified LU/CP identities.
    pub(crate) fn start_from_ws(
        &mut self,
        mut ws: WsRoutePort,
        hosted_lu: &wire::SnaName,
        hosted_cp: &wire::SnaName,
        source_lu: &wire::SnaName,
        source_cp: &wire::SnaName,
        seed: &[u8],
        timeout: Duration,
    ) -> io::Result<()> {
        if !self.udp_available() || timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP62 gateway is busy",
            ));
        }
        let incoming = ws.take_inbound_open().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket circuit has no incoming Open",
            )
        })?;
        if source_lu.netid != source_cp.netid || hosted_lu.netid != hosted_cp.netid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "automatic reverse LU and hosting CP NETIDs differ",
            ));
        }
        let xid = virtual_xid(
            hosted_cp,
            seed,
            Some(&self.config.local_station),
            Some(&self.config.local_node_id),
            self.config.tg_number,
        )?;
        let hosted_cp_name = format!("{}.{}", hosted_cp.netid, hosted_cp.name);
        let hosted_lu_name = format!("{}.{}", hosted_lu.netid, hosted_lu.name);
        let source_cp_name = format!("{}.{}", source_cp.netid, source_cp.name);
        let source_lu_name = format!("{}.{}", source_lu.netid, source_lu.name);
        let reverse = ReverseWsConfig {
            remote: RemoteConfig {
                url: String::new(),
                bearer: String::new(),
                local_cp: hosted_cp.clone(),
                target_cp: source_cp.clone(),
                target_lu: Some(source_lu.clone()),
            },
            hosted_cp: hosted_cp_name.clone(),
            hosted_lu: hosted_lu_name.clone(),
            source_cp: source_cp_name.clone(),
            source_lu: source_lu_name.clone(),
            local_station: if self.config.local_station.is_empty() {
                hosted_cp.name.clone()
            } else {
                self.config.local_station.clone()
            },
            local_node_id: xid.node_id(),
            tg_number: self.config.tg_number,
            user_tp: [0; 4],
            user_mode: None,
            endpoint: OutboundEndpoint {
                local_ip: self.config.local_ip,
                peer_ip: self.config.peer_ip,
            },
            timeout,
        };
        let responder = WsNativeResponder::new(
            ws,
            xid,
            &hosted_cp_name,
            &source_cp_name,
            &source_lu_name,
            &hosted_lu_name,
        )?;
        let socket = self.lease_udp()?;
        match AutoReverseWsSession::new(reverse, responder, socket, Instant::now() + timeout) {
            Ok(session) => {
                self.reverse = Some(session);
                let status_id = format!(
                    "mptn:{}:inbound:{}",
                    self.config.id,
                    incoming
                        .circuit_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
                if let Some(status) = crate::status() {
                    status.upsert_circuit(CircuitStatus {
                        id: status_id.clone(),
                        ingress: format!("concentrator:{source_lu_name}"),
                        egress: format!("mptn:{}:{hosted_lu_name}", self.config.id),
                        state: "opening".into(),
                        bytes_in: 0,
                        bytes_out: 0,
                        last_change_ms: local_status::now_ms(),
                    });
                }
                self.reverse_status_id = Some(status_id);
                tracing::info!(gateway = %self.config.id,
                    circuit_id = ?incoming.circuit_id,
                    source_lu = %source_lu_name, hosted_lu = %hosted_lu_name,
                    "automatic concentrator circuit selected TCP62 destination");
                Ok(())
            }
            Err(error) => {
                self.release_udp();
                Err(error)
            }
        }
    }
}

struct MptnToWsSession {
    association: u64,
    status_id: String,
    target_attachment: Option<String>,
    port: VirtualWsPort<NativePort>,
    pending_offer: Option<IngressOffer>,
    pending_tcp: Option<TcpRecord>,
    pending_udp: Option<(u16, Vec<u8>, bool)>,
    user_started: bool,
    setup_deadline: Instant,
}

/// Keep each converter's native circuit independent while allowing either a
/// WebSocket or a local LLC egress behind the same semantic MPTN converter.
struct NativePort(Box<dyn RoutePort>);

impl RoutePort for NativePort {
    fn poll(&mut self, credit: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        self.0.poll(credit)
    }
    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.0.tick()
    }
    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        self.0.send(unit)
    }
    fn has_capacity(&self) -> bool {
        self.0.has_capacity()
    }
    fn available_receive_slots(&self) -> usize {
        self.0.available_receive_slots()
    }
    fn on_downstream_capacity(&mut self, slots: usize) -> io::Result<()> {
        self.0.on_downstream_capacity(slots)
    }
    fn take_completed_information_count(&mut self) -> usize {
        self.0.take_completed_information_count()
    }
    fn on_downstream_completed(&mut self, count: usize) -> io::Result<()> {
        self.0.on_downstream_completed(count)
    }
    fn take_identity_observations(&mut self) -> Vec<IdentityObservation> {
        self.0.take_identity_observations()
    }
    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.0.set_ingress_busy(busy)
    }
    fn on_peer_ready(&mut self) -> io::Result<()> {
        self.0.on_peer_ready()
    }
    fn on_managed_mac(&mut self, mac: [u8; 6]) -> io::Result<()> {
        self.0.on_managed_mac(mac)
    }
    fn failure_scope(&self, error: &io::Error) -> FailureScope {
        self.0.failure_scope(error)
    }
    fn disconnect(&mut self) -> io::Result<()> {
        self.0.disconnect()
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl MptnToWsSession {
    fn can_accept(&self) -> bool {
        self.pending_tcp.is_none() && self.pending_udp.is_none()
    }

    /// Return false when this private circuit has completed and can retire.
    fn pump(&mut self, listener: &mut MptnGatewayPort) -> io::Result<bool> {
        if !self.user_started && Instant::now() >= self.setup_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "automatic TCP62 gateway setup timed out",
            ));
        }
        pump_virtual(&mut self.port)?;
        if self.port.management_complete() {
            if let Some(offer) = self.pending_offer.take() {
                // Native address assignment remains private to this circuit.
                self.port.begin_user_bind(
                    &offer,
                    NativeAddress {
                        daf: 2,
                        oaf: 2,
                        odai: true,
                    },
                )?;
            }
        }
        if self.port.user_closed() {
            return Ok(false);
        }
        if self.port.take_expedited_native_completed() {
            listener.complete_tcp_expedited_for(self.association)?;
        }
        if let Some(sequence) = self.port.take_completed_udp_expedited() {
            listener.complete_udp_expedited_for(self.association, sequence)?;
        }
        if let Some(sequence) = self.port.take_completed_udp_abort() {
            listener.complete_udp_abort_for(self.association, sequence)?;
            return Ok(false);
        }
        if let Some((sequence, reduced, abort)) = self.pending_udp.as_ref() {
            let accepted = if *abort {
                self.port.submit_udp_abort(*sequence, reduced)?
            } else {
                self.port.submit_udp_expedited(*sequence, reduced)?
            };
            if accepted {
                self.pending_udp = None;
            }
        }
        if let Some(record) = self.pending_tcp.as_ref() {
            if self.port.submit_tcp_user_record(record)? {
                self.pending_tcp = None;
                listener.complete_user_record_for(self.association)?;
            }
        }
        if let Some(bytes) = self.port.tcp_bind_response().map(ToOwned::to_owned) {
            if listener.queue_user_bind_response_for(self.association, &bytes)? {
                self.port.mark_tcp_bind_response_enqueued(&bytes)?;
            }
        }
        let was_started = self.user_started;
        self.user_started |= listener.user_active_for(self.association);
        if self.user_started && !was_started {
            if let Some(status) = crate::status() {
                if let Some(mut circuit) = status
                    .snapshot()
                    .circuits
                    .into_iter()
                    .find(|circuit| circuit.id == self.status_id)
                {
                    circuit.state = "connected".into();
                    circuit.last_change_ms = local_status::now_ms();
                    status.upsert_circuit(circuit);
                }
            }
        }
        if self.user_started {
            if let Some(record) = self.port.udp_abort_record().cloned() {
                if listener.queue_udp_abort_for(self.association, &record)? {
                    self.port.mark_udp_abort_enqueued(&record)?;
                }
            }
            if let Some(record) = self.port.tcp_user_record().cloned() {
                if listener.queue_user_record_for(self.association, &record)? {
                    self.port.mark_tcp_user_record_enqueued(&record)?;
                }
            }
        }
        self.port.complete_tcp_user_records(
            listener.take_completed_user_records_for(self.association),
        )?;
        Ok(true)
    }

    fn on_event(
        &mut self,
        event: GatewayEvent,
        listener: &mut MptnGatewayPort,
    ) -> io::Result<bool> {
        match event {
            GatewayEvent::ManagementReady => Ok(true),
            GatewayEvent::UserBind(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate TCP62 user BIND",
            )),
            GatewayEvent::UserNormal(record)
            | GatewayEvent::UserExpedited(record)
            | GatewayEvent::UserAbort(record) => {
                if self.port.submit_tcp_user_record(&record)? {
                    listener.complete_user_record_for(self.association)?;
                } else {
                    self.pending_tcp = Some(record);
                }
                Ok(true)
            }
            GatewayEvent::UserUdpExpedited { sequence, reduced } => {
                if !self.port.submit_udp_expedited(sequence, &reduced)? {
                    self.pending_udp = Some((sequence, reduced, false));
                }
                Ok(true)
            }
            GatewayEvent::UserUdpAbort { sequence, reduced } => {
                if !self.port.submit_udp_abort(sequence, &reduced)? {
                    self.pending_udp = Some((sequence, reduced, true));
                }
                Ok(true)
            }
            GatewayEvent::OutboundUdpAbortAcknowledged => {
                self.port.complete_udp_abort_response()?;
                Ok(true)
            }
            GatewayEvent::Closed => Ok(false),
            GatewayEvent::Rejected(reason) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TCP62 peer rejected: {reason}"),
            )),
        }
    }
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
    fn generated_cp_is_stable_valid_and_source_scoped() {
        let lu = name("QABOB", "PAYROLL");
        let a = virtual_cp_for_source(&lu, b"router-one/mptn", None).unwrap();
        assert_eq!(
            a,
            virtual_cp_for_source(&lu, b"router-one/mptn", None).unwrap()
        );
        assert_eq!(a.netid, "QABOB");
        assert_eq!(a.name.len(), 8);
        assert!(a.name.starts_with('R'));
        assert_ne!(
            a,
            virtual_cp_for_source(&lu, b"router-two/mptn", None).unwrap()
        );
        assert_ne!(a.name, lu.name);
        config::parse_cp(&format!("{}.{}", a.netid, a.name)).unwrap();
    }

    #[test]
    fn configured_cp_and_hosting_cp_require_matching_netids() {
        let lu = name("QABOB", "SNAB");
        assert_eq!(
            virtual_cp_for_source(&lu, b"seed", Some("QABOB.GATEWAY"))
                .unwrap()
                .name,
            "GATEWAY"
        );
        assert!(virtual_cp_for_source(&lu, b"seed", Some("QAALICE.GATEWAY")).is_err());
        assert!(require_hosting_cp(&lu, None, None).is_err());
        assert_eq!(
            require_hosting_cp(&lu, Some(name("QABOB", "HOST")), None)
                .unwrap()
                .name,
            "HOST"
        );
        assert!(require_hosting_cp(&lu, Some(name("QAALICE", "HOST")), None).is_err());
        assert!(require_hosting_cp(&lu, Some(name("QABOB", "HOST")), Some("QABOB.OTHER")).is_err());
    }

    #[test]
    fn generated_virtual_xid_uses_router_cp() {
        let cp = virtual_cp_for_source(&name("QABOB", "SNAB"), b"seed", None).unwrap();
        let xid = virtual_xid(&cp, b"seed", None, None, 1).unwrap();
        assert_eq!(xid.cp_name().unwrap(), format!("{}.{}", cp.netid, cp.name));
        assert!(virtual_xid(&cp, b"seed", None, Some("bad"), 1).is_err());
    }

    #[test]
    fn detached_mptn_source_exclusively_leases_udp_until_release() {
        let config: crate::config::RouterConfig = toml::from_str(
            "[[mptn]]\nprofile='gateway'\nid='test'\nlocal_ip='127.0.0.1'\npeer_ip='127.0.0.2'\n",
        )
        .unwrap();
        let mut gateway = AutoMptnGateway::bind_on_port(&config.mptn_gateway[0], 0).unwrap();
        assert!(gateway.udp_available());
        let leased = gateway.lease_udp().unwrap();
        assert!(!gateway.udp_available());
        assert_eq!(
            gateway.lease_udp().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(leased);
        gateway.release_udp();
        assert!(gateway.udp_available());
    }
}
