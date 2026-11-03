//! Session-selected routing when a config has no explicit `[[route]]` table.

use crate::{
    auto_address::AutoProxyMacs,
    auto_gateway_runtime::{virtual_cp_for_source, AutoMptnGateway},
    auto_llc::{AutoLlcPort, LlcAutoListener, LlcIngressOffer},
    auto_llc_ws::AutoLlcWsBridge,
    auto_local_dispatch::AutoLocalDispatch,
    config::{self, RouterConfig},
    hpr_mptn_session_source::MptnToHprSession,
    llc_proof_registry::{AssociationId, LlcProofRegistry},
    llc_session_ws::LlcSessionWs,
    local_status::LocalProxyMacStatus,
    mptn_session_ws::MptnSessionWs,
    mptn_target_ws::MptnTargetWs,
    remote::AutoWsHub,
    routing::{AutomaticFabric, IdentityObservation, PortId, RouteAddress, SessionSide},
    runtime::LlcPeer,
    STOP,
};
use router_core::{
    route_registry::{LuType, RouteKey, RouteRecord},
    session::{QualifiedName, SessionIdentity},
};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::mptn_ingress::IngressOffer;
use transport_ws::wire;

const IDLE_POLL: Duration = Duration::from_micros(200);
const MAX_PENDING_HANDOFFS: usize = 256;

fn require_session_v1_target(route: &wire::RouteExport) -> io::Result<()> {
    if matches!(route.resource.as_ref(), Some(wire::route_export::Resource::LogicalUnit(lu))
        if lu.supported_types.contains(&(wire::LuType::LuType62 as i32)))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic MPTN target does not advertise LU 6.2 SessionV1",
        ))
    }
}

struct LlcSession {
    ingress: Option<(usize, [u8; 6])>,
    egress: Option<(usize, [u8; 6])>,
    upstream: bool,
}

struct LlcSessionCircuit {
    bridge: LlcSessionWs,
    listener: usize,
    proxy_mac: [u8; 6],
    verified_logged: bool,
}

/// Keep automatic mode separate from the explicit pair router. Each selected
/// LLC circuit receives private route ports, while TCP62 converters own their
/// own isolated WebSocket circuit state.
pub(crate) fn run(config: &RouterConfig) -> io::Result<()> {
    if !config.ee.is_empty() {
        if config.remote.is_empty() {
            return crate::auto_hpr_standalone::run_standalone(config);
        }
        return crate::auto_hpr_runtime::run_hpr(config);
    }
    run_attachments(config)
}

fn run_attachments(config: &RouterConfig) -> io::Result<()> {
    let mut runner = AutoLocalSessionRunner::new(config)?;
    let remote = config.remote.first();
    let mut hub: Option<AutoWsHub> = None;
    let mut next_connect = Instant::now();
    let mut connect_delay = Duration::from_millis(500);
    tracing::info!(
        llc_attachments = config.llc.len(),
        mptn_attachments = config.mptn_gateway.len(),
        concentrator = remote.is_some(),
        "automatic routing started"
    );
    while !STOP.load(Ordering::Relaxed) {
        if let Some(remote) = remote.filter(|_| hub.is_none() && Instant::now() >= next_connect) {
            match AutoWsHub::connect(&remote.url, &remote.bearer_token()?, &[], &[]) {
                Ok(mut connected) => {
                    runner.sync_upstream(&connected)?;
                    let (cps, lus) = runner.exports(connected.allowed_netid());
                    connected.publish_local(&cps, &lus)?;
                    hub = Some(connected);
                    connect_delay = Duration::from_millis(500);
                }
                Err(error) => {
                    tracing::warn!(upstream = %crate::remote::server_authority(&remote.url),
                        error = %error, retry_ms = connect_delay.as_millis(),
                        "automatic concentrator connection failed");
                    next_connect = Instant::now() + connect_delay;
                    connect_delay = connect_delay.saturating_mul(2).min(Duration::from_secs(30));
                }
            }
        }
        if let Some(connected) = hub.as_mut() {
            match connected.poll_incoming() {
                Ok(Some(open)) => {
                    if let OpenDisposition::Unhandled(open) =
                        runner.accept_upstream(connected, open)?
                    {
                        connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "automatic concentrator directory disconnected");
                    runner.on_hub_lost()?;
                    hub = None;
                    next_connect = Instant::now() + connect_delay;
                }
            }
        }
        if let Some(connected) = hub.as_ref() {
            runner.sync_upstream(connected)?;
        }
        let result = runner.poll_local(hub.as_mut())?;
        if result.hub_lost {
            runner.on_hub_lost()?;
            hub = None;
            next_connect = Instant::now() + connect_delay;
        } else if result.exports_changed {
            if let Some(connected) = hub.as_mut() {
                let (cps, lus) = runner.exports(connected.allowed_netid());
                connected.publish_local(&cps, &lus)?;
            }
        }
        if !result.active {
            thread::sleep(IDLE_POLL);
        }
    }
    runner.shutdown()
}

/// Owns local attachment sockets and proofs across concentrator and EE generations.
/// The coordinator owns WebSocket polling and route publication.
pub(crate) struct AutoLocalSessionRunner<'a> {
    config: &'a RouterConfig,
    proxies: AutoProxyMacs,
    fabric: AutomaticFabric,
    bridge: AutoLlcWsBridge,
    proofs: LlcProofRegistry,
    listeners: Vec<LlcAutoListener>,
    gateways: Vec<AutoMptnGateway<'a>>,
    remote_macs: HashSet<[u8; 6]>,
    mptn_exports: HashMap<String, (wire::SnaName, wire::LuReachability)>,
    mptn_owner: HashMap<(String, String), String>,
    learned_mptn_lus: HashMap<String, HashSet<(String, String)>>,
    local_dispatch: AutoLocalDispatch,
    sessions: HashMap<u64, LlcSession>,
    next_id: u64,
    mptn_ws_sessions: HashMap<u64, MptnSessionWs>,
    next_mptn_ws_id: u64,
    mptn_target_sessions: HashMap<u64, MptnTargetWs>,
    next_mptn_target_id: u64,
    llc_ws_sessions: HashMap<u64, LlcSessionCircuit>,
    next_llc_ws_id: u64,
    unhandled_llc: Vec<(String, LlcIngressOffer)>,
    unhandled_mptn: Vec<(String, u64, IngressOffer)>,
    mptn_management: Vec<(String, Vec<(String, String)>)>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LocalPoll {
    pub(crate) active: bool,
    pub(crate) exports_changed: bool,
    pub(crate) hub_lost: bool,
}

/// The coordinator must route an unhandled open to another local carrier.
pub(crate) enum OpenDisposition {
    Handled,
    Unhandled(wire::IncomingOpen),
}

#[allow(dead_code)] // HPR coordinator consumes the attachment handoff API.
impl<'a> AutoLocalSessionRunner<'a> {
    pub(crate) fn new(config: &'a RouterConfig) -> io::Result<Self> {
        let proxies = AutoProxyMacs::from_ids(
            config
                .llc
                .iter()
                .map(|peer| peer.id.as_str())
                .chain(config.mptn_gateway.iter().map(|peer| peer.id.as_str())),
        )?;
        Self::new_with_proxies(config, proxies)
    }

    fn new_with_proxies(config: &'a RouterConfig, proxies: AutoProxyMacs) -> io::Result<Self> {
        if let Some(status) = crate::status() {
            status.replace_local_proxy_macs(
                proxies
                    .iter()
                    .map(|(id, mac)| LocalProxyMacStatus {
                        attachment_id: id.into(),
                        mac: crate::endpoint::format_mac(mac),
                    })
                    .collect(),
            );
        }
        let mut fabric = AutomaticFabric::new();
        let mut bridge = AutoLlcWsBridge::default();
        let proofs = LlcProofRegistry::default();
        for peer in &config.llc {
            let mac = proxies.get(&peer.id).expect("local LLC proxy allocated");
            fabric
                .directory_mut()
                .replace(PortId::new(&peer.id), [RouteAddress::Mac(mac)])?;
            bridge.register(
                PortId::new(&peer.id),
                peer.interface.clone(),
                config::parse_mac(&peer.guest_mac)?,
            )?;
            if let Some(expected_cp) = peer.local_cp.as_deref() {
                bridge.configure_lu_hints(
                    &PortId::new(&peer.id),
                    expected_cp,
                    &peer.lus,
                    &peer.lu_types,
                )?;
            }
        }
        for gateway in &config.mptn_gateway {
            fabric.directory_mut().replace(
                PortId::new(&gateway.id),
                [RouteAddress::Mac(
                    proxies.get(&gateway.id).expect("MPTN proxy allocated"),
                )],
            )?;
        }
        let mut listeners = Vec::with_capacity(config.llc.len());
        for peer in &config.llc {
            let mut listener =
                LlcAutoListener::open(&peer.interface, config::parse_mac(&peer.guest_mac)?)?;
            for (target, mac) in proxies.iter() {
                if target != peer.id {
                    if config
                        .mptn_gateway
                        .iter()
                        .any(|gateway| gateway.id == target)
                    {
                        listener.allow_native_proxy_mac(mac)?;
                    } else {
                        listener.allow_proxy_mac(mac)?;
                    }
                }
            }
            listeners.push(listener);
        }
        let gateways = config
            .mptn_gateway
            .iter()
            .map(AutoMptnGateway::bind)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            config,
            proxies,
            fabric,
            bridge,
            proofs,
            listeners,
            gateways,
            remote_macs: HashSet::new(),
            mptn_exports: HashMap::new(),
            mptn_owner: HashMap::new(),
            learned_mptn_lus: HashMap::new(),
            local_dispatch: AutoLocalDispatch::new(),
            sessions: HashMap::new(),
            next_id: 0,
            mptn_ws_sessions: HashMap::new(),
            next_mptn_ws_id: 0,
            mptn_target_sessions: HashMap::new(),
            next_mptn_target_id: 0,
            llc_ws_sessions: HashMap::new(),
            next_llc_ws_id: 0,
            unhandled_llc: Vec::new(),
            unhandled_mptn: Vec::new(),
            mptn_management: Vec::new(),
        })
    }

    pub(crate) fn take_unhandled_llc_offers(&mut self) -> Vec<(String, LlcIngressOffer)> {
        std::mem::take(&mut self.unhandled_llc)
    }

    pub(crate) fn take_unhandled_mptn_offers(&mut self) -> Vec<(String, u64, IngressOffer)> {
        std::mem::take(&mut self.unhandled_mptn)
    }

    pub(crate) fn take_mptn_management(&mut self) -> Vec<(String, Vec<(String, String)>)> {
        std::mem::take(&mut self.mptn_management)
    }

    pub(crate) fn with_gateway<T>(
        &mut self,
        id: &str,
        f: impl FnOnce(&mut AutoMptnGateway<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let gateway = self
            .gateways
            .iter_mut()
            .find(|gateway| gateway.id() == id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "MPTN attachment is absent"))?;
        f(gateway)
    }

    pub(crate) fn allow_llc_proxy_mac(&mut self, id: &str, mac: [u8; 6]) -> io::Result<()> {
        self.llc_listener(id)?.allow_native_proxy_mac(mac)
    }

    pub(crate) fn reserve_llc(&mut self, id: &str, mac: [u8; 6]) -> io::Result<bool> {
        self.llc_listener(id)?.reserve(mac)
    }

    pub(crate) fn release_llc(&mut self, id: &str, mac: [u8; 6]) -> io::Result<()> {
        self.llc_listener(id)?.release(mac);
        Ok(())
    }

    fn llc_listener(&mut self, id: &str) -> io::Result<&mut LlcAutoListener> {
        let index = self
            .config
            .llc
            .iter()
            .position(|peer| peer.id == id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LLC attachment is absent"))?;
        Ok(&mut self.listeners[index])
    }

    pub(crate) fn exports(&self, netid: &str) -> (Vec<wire::SnaName>, Vec<wire::LuReachability>) {
        publication_records(self.fabric.directory(), netid)
    }

    pub(crate) fn sync_upstream(&mut self, connected: &AutoWsHub) -> io::Result<()> {
        let addresses = connected.advertised_addresses();
        let next_macs = addresses
            .iter()
            .filter_map(|address| match address {
                RouteAddress::Mac(mac) => Some(*mac),
                _ => None,
            })
            .collect::<HashSet<_>>();
        for mac in self.remote_macs.difference(&next_macs) {
            for listener in &mut self.listeners {
                listener.withdraw_proxy_mac(*mac);
            }
        }
        for mac in next_macs.difference(&self.remote_macs) {
            for listener in &mut self.listeners {
                listener.allow_native_proxy_mac(*mac)?;
            }
        }
        self.remote_macs = next_macs;
        if let Some(remote) = self.config.remote.first() {
            self.fabric
                .directory_mut()
                .replace_upstream(PortId::new(&remote.id), addresses)?;
        }
        refresh_mptn_exports(
            self.config,
            &self.learned_mptn_lus,
            connected,
            &mut self.mptn_exports,
            &mut self.mptn_owner,
        )?;
        Ok(())
    }

    pub(crate) fn accept_upstream(
        &mut self,
        connected: &mut AutoWsHub,
        open: wire::IncomingOpen,
    ) -> io::Result<OpenDisposition> {
        let target = open
            .target
            .as_ref()
            .and_then(|reference| connected.local_route(reference))
            .and_then(|route| match route.resource.as_ref()? {
                wire::route_export::Resource::LogicalUnit(lu) => Some(lu.clone()),
                _ => None,
            });
        let Some(target) = target else {
            return Ok(OpenDisposition::Unhandled(open));
        };
        let (Some(name), Some(cp), Some(remote)) = (
            target.lu.as_ref(),
            target.hosting_cp.as_ref(),
            self.config.remote.first(),
        ) else {
            return Ok(OpenDisposition::Unhandled(open));
        };
        let destination = RouteAddress::LogicalUnit {
            netid: name.netid.clone(),
            cp: Some(cp.name.clone()),
            name: name.name.clone(),
        };
        let Ok(selected) = self.fabric.resolve(&PortId::new(&remote.id), &destination) else {
            return Ok(OpenDisposition::Unhandled(open));
        };
        if !self.config.llc.iter().any(|peer| peer.id == selected.0)
            && !self
                .config
                .mptn_gateway
                .iter()
                .any(|peer| peer.id == selected.0)
        {
            return Ok(OpenDisposition::Unhandled(open));
        }
        let Self {
            config,
            bridge,
            fabric,
            listeners,
            gateways,
            mptn_owner,
            mptn_target_sessions,
            next_mptn_target_id,
            llc_ws_sessions,
            next_llc_ws_id,
            sessions,
            next_id,
            ..
        } = self;
        match incoming_lu_pair(connected, &open) {
            Ok((hosted_lu, hosted_cp, source_lu, source_cp)) => {
                let owner = mptn_owner.get(&(hosted_lu.netid.clone(), hosted_lu.name.clone()));
                let gateway =
                    owner.and_then(|id| gateways.iter_mut().find(|gateway| gateway.id() == id));
                if let Some(gateway) = gateway.filter(|gateway| gateway.udp_available()) {
                    if open.profile == wire::CircuitProfile::SessionV1 as i32 {
                        if let Err(error) = open_incoming_mptn_target(
                            connected,
                            open.clone(),
                            &hosted_lu,
                            &hosted_cp,
                            &source_lu,
                            &source_cp,
                            gateway,
                            mptn_target_sessions,
                            next_mptn_target_id,
                        ) {
                            tracing::warn!(gateway = gateway.id(), error = %error,
                                        "automatic SessionV1 to TCP62 session rejected");
                            connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?;
                        }
                    } else {
                        let seed =
                            format!("{}:{}.{}", gateway.id(), hosted_lu.netid, hosted_lu.name);
                        match connected.accept_incoming(open.clone())? {
                            Some(ws) => {
                                if let Err(error) = gateway.start_from_ws(
                                    ws,
                                    &hosted_lu,
                                    &hosted_cp,
                                    &source_lu,
                                    &source_cp,
                                    seed.as_bytes(),
                                    Duration::from_secs(600),
                                ) {
                                    tracing::warn!(gateway = gateway.id(), error = %error,
                                                "automatic concentrator to TCP62 session failed to start");
                                }
                            }
                            None => {
                                connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?
                            }
                        }
                    }
                } else if owner.is_some() {
                    connected.reject_incoming(&open, wire::OpenFailure::Busy)?;
                } else if let Some(remote) = config.remote.first() {
                    if open.profile == wire::CircuitProfile::SessionV1 as i32 {
                        if let Err(error) = open_incoming_llc_session(
                            bridge,
                            connected,
                            open.clone(),
                            &hosted_lu,
                            &hosted_cp,
                            config,
                            listeners,
                            llc_ws_sessions,
                            next_llc_ws_id,
                        ) {
                            tracing::warn!(error = %error,
                                        "automatic SessionV1 to LLC session rejected");
                            connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?;
                        }
                    } else if let Err(error) = open_incoming_llc(
                        bridge,
                        connected,
                        open.clone(),
                        remote,
                        config,
                        listeners,
                        fabric,
                        sessions,
                        next_id,
                    ) {
                        tracing::warn!(error = %error,
                                    "automatic concentrator to LLC session rejected");
                        connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?;
                    }
                } else {
                    return Ok(OpenDisposition::Unhandled(open));
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "automatic incoming SNA session has no TCP62 destination");
                connected.reject_incoming(&open, wire::OpenFailure::Unsupported)?;
            }
        }
        Ok(OpenDisposition::Handled)
    }

    pub(crate) fn on_hub_lost(&mut self) -> io::Result<()> {
        for (_, mut bridge) in self.mptn_ws_sessions.drain() {
            let gateway_id = bridge.gateway_id().to_owned();
            let _ = bridge.close();
            if let Some(gateway) = self
                .gateways
                .iter_mut()
                .find(|gateway| gateway.id() == gateway_id)
            {
                gateway.release_udp();
            }
        }
        for (_, mut target) in self.mptn_target_sessions.drain() {
            let gateway_id = target.gateway_id().to_owned();
            let _ = target.close();
            if let Some(gateway) = self
                .gateways
                .iter_mut()
                .find(|gateway| gateway.id() == gateway_id)
            {
                gateway.release_udp();
            }
        }
        let mut changed = HashSet::new();
        for (id, mut circuit) in self.llc_ws_sessions.drain() {
            let attachment = PortId::new(circuit.bridge.attachment_id());
            if self
                .proofs
                .withdraw(&attachment, &association("session_v1", id))
            {
                changed.insert(attachment);
            }
            let _ = circuit.bridge.close();
            self.listeners[circuit.listener].release(circuit.proxy_mac);
        }
        changed.extend(retire_upstream_pairs(
            &mut self.fabric,
            &mut self.sessions,
            &mut self.listeners,
            &mut self.proofs,
            self.config,
        )?);
        if reconcile_proofs(&self.proofs, &mut self.bridge, changed.into_iter())? {
            refresh_local_addresses(&mut self.fabric, &self.bridge, self.config, &self.proxies)?;
        }
        if let Some(remote) = self.config.remote.first() {
            self.fabric
                .directory_mut()
                .withdraw(&PortId::new(&remote.id))?;
        }
        for mac in self.remote_macs.drain() {
            for listener in &mut self.listeners {
                listener.withdraw_proxy_mac(mac);
            }
        }
        Ok(())
    }

    pub(crate) fn poll_local(&mut self, mut hub: Option<&mut AutoWsHub>) -> io::Result<LocalPoll> {
        let Self {
            config,
            proxies,
            fabric,
            bridge,
            proofs,
            listeners,
            gateways,
            mptn_exports,
            mptn_owner,
            learned_mptn_lus,
            local_dispatch,
            sessions,
            mptn_ws_sessions,
            mptn_target_sessions,
            llc_ws_sessions,
            unhandled_llc,
            unhandled_mptn,
            mptn_management,
            ..
        } = self;
        let mut next_id = self.next_id;
        let mut next_mptn_ws_id = self.next_mptn_ws_id;
        let mut changed_proofs = HashSet::<PortId>::new();
        let mut exports_changed = false;
        for id in mptn_ws_sessions.keys().copied().collect::<Vec<_>>() {
            let result = mptn_ws_sessions.get_mut(&id).unwrap().pump();
            let retired = match result {
                Ok(true) => false,
                Ok(false) => true,
                Err(error) => {
                    tracing::warn!(session = id, error = %error,
                        "automatic MPTN SessionV1 circuit failed");
                    true
                }
            };
            if retired {
                let mut bridge = mptn_ws_sessions.remove(&id).unwrap();
                let gateway_id = bridge.gateway_id().to_owned();
                let _ = bridge.close();
                if let Some(gateway) = gateways
                    .iter_mut()
                    .find(|gateway| gateway.id() == gateway_id)
                {
                    gateway.release_udp();
                }
            }
        }
        for id in mptn_target_sessions.keys().copied().collect::<Vec<_>>() {
            let result = mptn_target_sessions.get_mut(&id).unwrap().pump();
            let retired = match result {
                Ok(true) => false,
                Ok(false) => true,
                Err(error) => {
                    tracing::warn!(session = id, error = %error,
                        "automatic SessionV1 to TCP62 circuit failed");
                    true
                }
            };
            if retired {
                let mut target = mptn_target_sessions.remove(&id).unwrap();
                let gateway_id = target.gateway_id().to_owned();
                let _ = target.close();
                if let Some(gateway) = gateways
                    .iter_mut()
                    .find(|gateway| gateway.id() == gateway_id)
                {
                    gateway.release_udp();
                }
            }
        }
        for id in llc_ws_sessions.keys().copied().collect::<Vec<_>>() {
            let circuit = llc_ws_sessions.get_mut(&id).unwrap();
            let result = circuit.bridge.pump();
            if result.is_ok() && !circuit.verified_logged {
                if let Some(cp) = circuit.bridge.verified_target_cp() {
                    let attachment = PortId::new(circuit.bridge.attachment_id());
                    proofs.observe_cp(
                        &attachment,
                        association("session_v1", id),
                        &format!("{}.{}", cp.netid, cp.name),
                    )?;
                    changed_proofs.insert(attachment);
                    tracing::info!(session = id, attachment = circuit.bridge.attachment_id(),
                        target_cp = %cp, "automatic LLC SessionV1 target verified by XID");
                    circuit.verified_logged = true;
                }
            }
            let retired = match result {
                Ok(true) => false,
                Ok(false) => true,
                Err(error) => {
                    tracing::warn!(session = id, error = %error,
                        "automatic LLC SessionV1 circuit failed");
                    true
                }
            };
            if retired {
                let mut circuit = llc_ws_sessions.remove(&id).unwrap();
                let attachment = PortId::new(circuit.bridge.attachment_id());
                if proofs.withdraw(&attachment, &association("session_v1", id)) {
                    changed_proofs.insert(attachment);
                }
                let _ = circuit.bridge.close();
                listeners[circuit.listener].release(circuit.proxy_mac);
            }
        }
        let mut active = match fabric.poll_once() {
            Ok(active) => active,
            Err(error) if hub.is_some() => {
                tracing::warn!(error = %error, "automatic upstream circuit failed; retaining local routes");
                return Ok(LocalPoll {
                    active: true,
                    exports_changed,
                    hub_lost: true,
                });
            }
            Err(error) => return Err(error),
        };
        let closed_sessions = fabric.take_closed_sessions();
        for observation in fabric.take_identity_observations() {
            let Some(session) = sessions.get(&observation.session_id) else {
                continue;
            };
            let attachment = match observation.side {
                SessionSide::Ingress => session.ingress.map(|(index, _)| index),
                SessionSide::Egress => session.egress.map(|(index, _)| index),
            };
            let Some(index) = attachment else { continue };
            let id = PortId::new(&config.llc[index].id);
            let owner = association("fabric", observation.session_id);
            observe_proof(proofs, &id, owner, observation.identity)?;
            changed_proofs.insert(id);
        }
        for closed in closed_sessions {
            if let Some(session) = sessions.remove(&closed) {
                if let Some((ingress, proxy)) = session.ingress {
                    listeners[ingress].release(proxy);
                    let id = PortId::new(&config.llc[ingress].id);
                    if proofs.withdraw(&id, &association("fabric", closed)) {
                        changed_proofs.insert(id);
                    }
                }
                if let Some((egress, proxy)) = session.egress {
                    listeners[egress].release(proxy);
                    let id = PortId::new(&config.llc[egress].id);
                    if proofs.withdraw(&id, &association("fabric", closed)) {
                        changed_proofs.insert(id);
                    }
                }
                if let Some(status) = crate::status() {
                    status.remove_circuit(&format!("auto-{closed}"));
                }
                active = true;
            }
        }
        for completed in local_dispatch.poll_completed() {
            let id = PortId::new(&completed.ingress_id);
            if proofs.withdraw(&id, &association("local_dispatch", completed.id)) {
                changed_proofs.insert(id);
            }
            if let Some(gateway) = gateways
                .iter_mut()
                .find(|gateway| gateway.id() == completed.gateway_id)
            {
                gateway.release_udp();
            }
            if let Some(index) = config
                .llc
                .iter()
                .position(|peer| peer.id == completed.ingress_id)
            {
                listeners[index].release(completed.proxy_mac);
            }
            if let Err(error) = completed.result {
                tracing::warn!(ingress = %completed.ingress_id, gateway = %completed.gateway_id,
                    error = %error, "automatic LLC to TCP62 circuit failed");
            }
            active = true;
        }
        if reconcile_proofs(proofs, bridge, changed_proofs.drain())? {
            refresh_local_addresses(fabric, bridge, config, proxies)?;
            exports_changed = true;
        }
        for ingress in 0..listeners.len() {
            let Some(offer) = listeners[ingress].poll_offer()? else {
                continue;
            };
            active = true;
            let ingress_proxy = offer.proxy_mac;
            let ingress_id = PortId::new(&config.llc[ingress].id);
            let destination = RouteAddress::Mac(ingress_proxy);
            let target = match fabric.resolve(&ingress_id, &destination) {
                Ok(target) => target,
                Err(error) if !config.ee.is_empty() && error.kind() == io::ErrorKind::NotFound => {
                    if unhandled_llc.len() < MAX_PENDING_HANDOFFS {
                        unhandled_llc.push((ingress_id.0, offer));
                    } else {
                        tracing::warn!(ingress = %ingress_id.0,
                            "LLC offer handoff queue full; dropping offer");
                        listeners[ingress].release(ingress_proxy);
                    }
                    continue;
                }
                Err(error) => {
                    tracing::warn!(ingress = %ingress_id.0, proxy_mac = %crate::endpoint::format_mac(ingress_proxy), error = %error, "automatic LLC destination unresolved");
                    listeners[ingress].release(ingress_proxy);
                    continue;
                }
            };
            if let Some(gateway) = gateways.iter_mut().find(|gateway| gateway.id() == target.0) {
                let offered_cp = offer.peer_cp.clone();
                if let Some(cp) = &offer.peer_cp {
                    observe_native_llc_peer(&offer, cp);
                }
                let seed = format!("{}:{}", ingress_id.0, gateway.id());
                let target_cp = gateway.configured_local_cp().and_then(|cp| {
                    cp.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "LLC to TCP62 target CP has not been configured or discovered",
                        )
                    })
                });
                let result = target_cp.and_then(|cp| {
                    local_dispatch.start(
                        &ingress_id.0,
                        offer,
                        gateway,
                        &cp,
                        seed.as_bytes(),
                        Duration::from_secs(600),
                    )
                });
                match result {
                    Ok(worker_id) => {
                        if let Some(cp) = offered_cp {
                            proofs.observe_cp(
                                &ingress_id,
                                association("local_dispatch", worker_id),
                                &cp,
                            )?;
                            changed_proofs.insert(ingress_id.clone());
                        }
                    }
                    Err(error) => {
                        listeners[ingress].release(ingress_proxy);
                        tracing::warn!(ingress = %ingress_id.0, gateway = gateway.id(),
                            error = %error, "automatic LLC to TCP62 session rejected");
                    }
                }
                continue;
            }
            let Some(egress) = config.llc.iter().position(|peer| peer.id == target.0) else {
                tracing::warn!(ingress = %ingress_id.0, target = %target.0,
                    proxy_mac = %crate::endpoint::format_mac(ingress_proxy),
                    "automatic LLC destination requires a converter that is not active for this session");
                listeners[ingress].release(ingress_proxy);
                continue;
            };
            let egress_proxy = proxies
                .get(&config.llc[ingress].id)
                .expect("ingress local proxy allocated");
            if !listeners[egress].reserve(egress_proxy)? {
                tracing::warn!(ingress = %ingress_id.0, egress = %target.0, "automatic LLC destination busy");
                listeners[ingress].release(ingress_proxy);
                continue;
            }
            let result = (|| -> io::Result<()> {
                let ingress_port = offer.open_port()?;
                let peer = &config.llc[egress];
                let egress_port = AutoLlcPort::open_outbound(
                    &peer.interface,
                    config::parse_mac(&peer.guest_mac)?,
                    egress_proxy,
                )?;
                next_id = next_id
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("automatic session ID exhausted"))?;
                fabric.open_pair(
                    next_id,
                    &ingress_id,
                    &destination,
                    &target,
                    Box::new(ingress_port),
                    Box::new(egress_port),
                )?;
                sessions.insert(
                    next_id,
                    LlcSession {
                        ingress: Some((ingress, ingress_proxy)),
                        egress: Some((egress, egress_proxy)),
                        upstream: false,
                    },
                );
                observe_circuit(next_id, &ingress_id.0, &target.0);
                Ok(())
            })();
            if let Err(error) = result {
                listeners[ingress].release(ingress_proxy);
                listeners[egress].release(egress_proxy);
                tracing::warn!(ingress = %ingress_id.0, target = %target.0,
                    error = %error, "automatic LLC session rejected");
            }
        }
        for gateway in gateways.iter_mut() {
            let offered = gateway.poll_once()?;
            let management = gateway.take_management_lus();
            for (source, destination) in &management {
                let source = config::parse_cp(source)?;
                let destination = config::parse_cp(destination)?;
                tracing::info!(gateway = gateway.id(),
                    source_lu = %format!("{}.{}", source.netid, source.name),
                    destination_lu = %format!("{}.{}", destination.netid, destination.name),
                    "TCP62 management disclosed local LU reachability");
            }
            if !config.ee.is_empty() && !management.is_empty() {
                if mptn_management.len() == MAX_PENDING_HANDOFFS {
                    mptn_management.remove(0);
                    tracing::warn!(
                        gateway = gateway.id(),
                        "MPTN management handoff queue full; dropping oldest observation"
                    );
                }
                mptn_management.push((gateway.id().to_owned(), management));
            }
            if let Some(snapshot) = gateway.take_discovery_snapshot() {
                tracing::debug!(
                    gateway = gateway.id(),
                    revision = snapshot.revision,
                    learned_lus = snapshot.lus.len(),
                    "MPTN attachment discovery snapshot changed"
                );
                learned_mptn_lus.insert(
                    gateway.id().to_owned(),
                    snapshot
                        .lus
                        .into_iter()
                        .map(|lu| (lu.netid, lu.name))
                        .collect(),
                );
                refresh_mptn_registry(fabric, config, proxies, learned_mptn_lus)?;
                exports_changed = true;
                if let Some(connected) = hub.as_deref_mut() {
                    if refresh_mptn_exports(
                        config,
                        learned_mptn_lus,
                        connected,
                        mptn_exports,
                        mptn_owner,
                    )? {
                        exports_changed = true;
                    }
                }
            }
            let gateway_origin = format!("gateway:{}", gateway.id());
            for (association_id, attachment, identity) in gateway.take_identity_observations() {
                let id = PortId::new(attachment);
                observe_proof(
                    proofs,
                    &id,
                    association(&gateway_origin, association_id),
                    identity,
                )?;
                changed_proofs.insert(id);
            }
            for (association_id, attachment) in gateway.take_closed_local_attachments() {
                if let Some(index) = config.llc.iter().position(|peer| peer.id == attachment) {
                    listeners[index]
                        .release(proxies.get(gateway.id()).expect("gateway proxy allocated"));
                }
                let id = PortId::new(attachment);
                if proofs.withdraw(&id, &association(&gateway_origin, association_id)) {
                    changed_proofs.insert(id);
                }
            }
            if reconcile_proofs(proofs, bridge, changed_proofs.drain())? {
                refresh_local_addresses(fabric, bridge, config, proxies)?;
                exports_changed = true;
            }
            let Some((association, offer)) = offered else {
                continue;
            };
            active = true;
            if !config.ee.is_empty() {
                if let Ok((_, target)) = AutoMptnGateway::offer_lus(&offer) {
                    if let Ok(target) = config::parse_cp(&target) {
                        let local_missing = matches!(bridge.select_lu(&target),
                            Err(ref error) if error.kind() == io::ErrorKind::NotFound);
                        let upstream_missing = match hub.as_ref() {
                            Some(connected) => connected.resolve_lu(&target)?.is_none(),
                            None => true,
                        };
                        if local_missing && upstream_missing {
                            if unhandled_mptn.len() < MAX_PENDING_HANDOFFS {
                                unhandled_mptn.push((gateway.id().to_owned(), association, offer));
                            } else {
                                tracing::warn!(
                                    gateway = gateway.id(),
                                    association,
                                    "MPTN offer handoff queue full; rejecting offer"
                                );
                                gateway.reject_offer(association, "router offer queue is full")?;
                            }
                            continue;
                        }
                    }
                }
            }
            let mut detached_for_session = false;
            let result = (|| -> io::Result<()> {
                let (source, destination) = AutoMptnGateway::offer_lus(&offer)?;
                let source = config::parse_cp(&source)?;
                let destination = config::parse_cp(&destination)?;
                match bridge.select_lu(&destination) {
                    Ok(target_id) => {
                        let target_cp = bridge
                            .observed_cp(&target_id)
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "local LLC target CP is not observed",
                                )
                            })?
                            .clone();
                        let index = config
                            .llc
                            .iter()
                            .position(|peer| peer.id == target_id.0)
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "local LLC target attachment is absent",
                                )
                            })?;
                        let proxy = proxies.get(gateway.id()).expect("gateway proxy allocated");
                        if !gateway.udp_available() {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "MPTN gateway is busy",
                            ));
                        }
                        if !listeners[index].reserve(proxy)? {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "local LLC target is busy",
                            ));
                        }
                        let seed = format!("{}:{}.{}", gateway.id(), source.netid, source.name);
                        let local_cp =
                            gateway.configured_local_cp()?.map(Ok).unwrap_or_else(|| {
                                virtual_cp_for_source(&source, seed.as_bytes(), None)
                            })?;
                        let local = AutoLlcPort::open_outbound(
                            &config.llc[index].interface,
                            config::parse_mac(&config.llc[index].guest_mac)?,
                            proxy,
                        )?;
                        let result = gateway.start_to_local(
                            association,
                            offer,
                            Box::new(local),
                            &target_id.0,
                            &local_cp,
                            &target_cp,
                            seed.as_bytes(),
                            Duration::from_secs(600),
                        );
                        if result.is_err() {
                            listeners[index].release(proxy);
                        }
                        return result;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                let connected = hub.as_deref_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "concentrator is unavailable")
                })?;
                if source.netid != connected.allowed_netid() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "TCP62 source LU {}.{} is outside assigned NETID {}",
                            source.netid,
                            source.name,
                            connected.allowed_netid()
                        ),
                    ));
                }
                let (target_ref, target_cp) =
                    connected.resolve_lu(&destination)?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "TCP62 target LU is not advertised")
                    })?;
                let target_route = connected.remote_route(&target_ref).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "TCP62 target LU route changed")
                })?;
                require_session_v1_target(&target_route)?;
                let target_cp = target_cp.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "TCP62 target LU has no hosting CP")
                })?;
                tracing::debug!(gateway = gateway.id(), target_cp = %format!("{}.{}", target_cp.netid, target_cp.name),
                    "automatic TCP62 target LU resolved for SessionV1");
                if mptn_owner.get(&(source.netid.clone(), source.name.clone()))
                    != Some(&gateway.id().to_owned())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "MPTN source LU discovery is unavailable or ambiguous",
                    ));
                }
                let ws = connected
                    .open_session_lu(&destination, &source)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "TCP62 route changed before circuit open",
                        )
                    })?;
                let endpoint = gateway.outbound_endpoint();
                let (detached, udp) = gateway.detach_user_for_hpr(association, &offer)?;
                detached_for_session = true;
                let source_name = format!("{}.{}", source.netid, source.name);
                let source = MptnToHprSession::new(detached, udp, endpoint, offer)?;
                next_mptn_ws_id = next_mptn_ws_id
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("MPTN SessionV1 ID exhausted"))?;
                mptn_ws_sessions.insert(
                    next_mptn_ws_id,
                    MptnSessionWs::new(source, ws, gateway.id().to_owned()),
                );
                tracing::info!(gateway = gateway.id(), session = next_mptn_ws_id,
                    source_lu = %source_name,
                    target_lu = %format!("{}.{}", destination.netid, destination.name),
                    "automatic MPTN SessionV1 bridge installed");
                Ok(())
            })();
            if let Err(error) = result {
                tracing::warn!(gateway = gateway.id(), association, error = %error,
                    "automatic TCP62 session rejected");
                if detached_for_session {
                    gateway.release_udp();
                } else {
                    gateway.reject_offer(association, &error.to_string())?;
                }
            }
        }
        if let Some(connected) = hub {
            if refresh_mptn_exports(
                config,
                learned_mptn_lus,
                connected,
                mptn_exports,
                mptn_owner,
            )? {
                exports_changed = true;
            }
        }
        if reconcile_proofs(proofs, bridge, changed_proofs.drain())? {
            refresh_local_addresses(fabric, bridge, config, proxies)?;
            exports_changed = true;
        }
        self.next_id = next_id;
        self.next_mptn_ws_id = next_mptn_ws_id;
        Ok(LocalPoll {
            active,
            exports_changed,
            hub_lost: false,
        })
    }

    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        let Self {
            fabric,
            gateways,
            listeners,
            sessions,
            mptn_ws_sessions,
            mptn_target_sessions,
            llc_ws_sessions,
            ..
        } = self;
        for (_, mut bridge) in mptn_ws_sessions.drain() {
            let gateway_id = bridge.gateway_id().to_owned();
            let _ = bridge.close();
            if let Some(gateway) = gateways
                .iter_mut()
                .find(|gateway| gateway.id() == gateway_id)
            {
                gateway.release_udp();
            }
        }
        for (_, mut target) in mptn_target_sessions.drain() {
            let gateway_id = target.gateway_id().to_owned();
            let _ = target.close();
            if let Some(gateway) = gateways
                .iter_mut()
                .find(|gateway| gateway.id() == gateway_id)
            {
                gateway.release_udp();
            }
        }
        for (_, mut circuit) in llc_ws_sessions.drain() {
            let _ = circuit.bridge.close();
            listeners[circuit.listener].release(circuit.proxy_mac);
        }
        for session_id in sessions.keys().copied().collect::<Vec<_>>() {
            fabric.close_pair(session_id)?;
        }
        Ok(())
    }
}

fn refresh_mptn_registry(
    fabric: &mut AutomaticFabric,
    config: &RouterConfig,
    proxies: &AutoProxyMacs,
    learned: &HashMap<String, HashSet<(String, String)>>,
) -> io::Result<()> {
    for gateway in &config.mptn_gateway {
        let mut records = vec![RouteRecord::from(RouteKey::ProxyMac(
            proxies.get(&gateway.id).expect("MPTN proxy allocated"),
        ))];
        let mut control_points = HashSet::new();
        if let Some(lus) = learned.get(&gateway.id) {
            for (netid, name) in lus {
                let source = wire::SnaName {
                    netid: netid.clone(),
                    name: name.clone(),
                };
                let seed = format!("{}:{netid}.{name}", gateway.id);
                let configured_cp =
                    (!gateway.local_cp.is_empty()).then_some(gateway.local_cp.as_str());
                let cp = virtual_cp_for_source(&source, seed.as_bytes(), configured_cp)?;
                let hosting_cp = QualifiedName::new(&cp.netid, &cp.name).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid MPTN hosting CP")
                })?;
                let lu = QualifiedName::new(netid, name).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid MPTN source LU")
                })?;
                if control_points.insert(hosting_cp.clone()) {
                    records.push(RouteRecord::from(RouteKey::ControlPoint(
                        hosting_cp.clone(),
                    )));
                }
                records.push(RouteRecord {
                    key: RouteKey::LogicalUnit { lu, hosting_cp },
                    supported_types: vec![LuType::Lu62],
                });
            }
        }
        fabric
            .directory_mut()
            .replace_local_records(PortId::new(&gateway.id), records)?;
    }
    Ok(())
}

fn refresh_mptn_exports(
    config: &RouterConfig,
    learned: &HashMap<String, HashSet<(String, String)>>,
    hub: &AutoWsHub,
    exports: &mut HashMap<String, (wire::SnaName, wire::LuReachability)>,
    owner: &mut HashMap<(String, String), String>,
) -> io::Result<bool> {
    // Rebuild from complete adapter snapshots. A closed or expired peer must
    // disappear from both the upstream export and the reverse-route owner map.
    let mut counts = HashMap::<(String, String), usize>::new();
    for lus in learned.values() {
        for (netid, name) in lus {
            if netid == hub.allowed_netid() {
                *counts.entry((netid.clone(), name.clone())).or_default() += 1;
            }
        }
    }
    let mut next_exports = HashMap::new();
    let mut next_owner = HashMap::new();
    for (gateway_id, lus) in learned {
        for (netid, name) in lus {
            if netid != hub.allowed_netid() {
                tracing::warn!(gateway = gateway_id, source_lu = %format!("{netid}.{name}"),
                    assigned_netid = hub.allowed_netid(),
                    "learned TCP62 LU excluded from upstream announcement: NETID mismatch");
                continue;
            }
            let key = format!("{gateway_id}:{netid}.{name}");
            if counts.get(&(netid.clone(), name.clone())) != Some(&1) {
                tracing::warn!(source_lu = %format!("{netid}.{name}"), gateway = gateway_id,
                    "ambiguous learned TCP62 LU; route withheld");
                continue;
            }
            let source = wire::SnaName {
                netid: netid.clone(),
                name: name.clone(),
            };
            let seed = format!("{}:{netid}.{name}", gateway_id);
            let configured_cp = config
                .mptn_gateway
                .iter()
                .find(|gateway| gateway.id == *gateway_id)
                .map(|gateway| gateway.local_cp.as_str())
                .filter(|value| !value.is_empty());
            let cp = virtual_cp_for_source(&source, seed.as_bytes(), configured_cp)?;
            next_exports.insert(
                key,
                (
                    cp.clone(),
                    wire::LuReachability {
                        lu: Some(source),
                        hosting_cp: Some(cp),
                        supported_types: vec![wire::LuType::LuType62 as i32],
                    },
                ),
            );
            next_owner.insert((netid.clone(), name.clone()), gateway_id.clone());
        }
    }
    let changed = *exports != next_exports || *owner != next_owner;
    *exports = next_exports;
    *owner = next_owner;
    Ok(changed)
}

fn publication_records(
    directory: &crate::routing::AutomaticDirectory,
    allowed_netid: &str,
) -> (Vec<wire::SnaName>, Vec<wire::LuReachability>) {
    let exports = directory.local_exports(allowed_netid);
    let mut cps = Vec::new();
    let mut cp_names = HashSet::new();
    for export in &exports {
        if let RouteKey::ControlPoint(cp) = &export.key {
            cp_names.insert((cp.netid.clone(), cp.name.clone()));
            cps.push(wire_name(cp));
        }
    }
    let mut lus = Vec::new();
    for export in exports {
        if let RouteKey::LogicalUnit { lu, hosting_cp } = export.key {
            if !cp_names.contains(&(hosting_cp.netid.clone(), hosting_cp.name.clone())) {
                tracing::warn!(local_lu = %lu, hosting_cp = %hosting_cp,
                    attachment = export.attachment.as_str(),
                    "local LU withheld from concentrator: hosting CP is not advertised");
                continue;
            }
            lus.push(wire::LuReachability {
                lu: Some(wire_name(&lu)),
                hosting_cp: Some(wire_name(&hosting_cp)),
                supported_types: export
                    .supported_types
                    .into_iter()
                    .map(wire_lu_type)
                    .collect(),
            });
        }
    }
    (cps, lus)
}

fn wire_name(name: &QualifiedName) -> wire::SnaName {
    wire::SnaName {
        netid: name.netid.clone(),
        name: name.name.clone(),
    }
}

fn wire_lu_type(kind: LuType) -> i32 {
    match kind {
        LuType::Lu0 => wire::LuType::LuType0 as i32,
        LuType::Lu1 => wire::LuType::LuType1 as i32,
        LuType::Lu2 => wire::LuType::LuType2 as i32,
        LuType::Lu3 => wire::LuType::LuType3 as i32,
        LuType::Lu4 => wire::LuType::LuType4 as i32,
        LuType::Lu61 => wire::LuType::LuType61 as i32,
        LuType::Lu62 => wire::LuType::LuType62 as i32,
        LuType::Lu7 => wire::LuType::LuType7 as i32,
    }
}

fn refresh_local_addresses(
    fabric: &mut AutomaticFabric,
    bridge: &AutoLlcWsBridge,
    config: &RouterConfig,
    proxies: &AutoProxyMacs,
) -> io::Result<()> {
    for peer in &config.llc {
        let id = PortId::new(&peer.id);
        let mut records = bridge.route_records(&id)?;
        records.push(RouteRecord::from(RouteKey::ProxyMac(
            proxies.get(&peer.id).expect("LLC proxy allocated"),
        )));
        fabric.directory_mut().replace_local_records(id, records)?;
    }
    Ok(())
}

fn retire_upstream_pairs(
    fabric: &mut AutomaticFabric,
    sessions: &mut HashMap<u64, LlcSession>,
    listeners: &mut [LlcAutoListener],
    proofs: &mut LlcProofRegistry,
    config: &RouterConfig,
) -> io::Result<HashSet<PortId>> {
    let mut changed = HashSet::new();
    let upstream = sessions
        .iter()
        .filter_map(|(id, session)| session.upstream.then_some(*id))
        .collect::<Vec<_>>();
    for session_id in upstream {
        fabric.abort_pair(session_id)?;
        if let Some(session) = sessions.remove(&session_id) {
            if let Some((index, mac)) = session.ingress {
                listeners[index].release(mac);
                let id = PortId::new(&config.llc[index].id);
                if proofs.withdraw(&id, &association("fabric", session_id)) {
                    changed.insert(id);
                }
            }
            if let Some((index, mac)) = session.egress {
                listeners[index].release(mac);
                let id = PortId::new(&config.llc[index].id);
                if proofs.withdraw(&id, &association("fabric", session_id)) {
                    changed.insert(id);
                }
            }
        }
        if let Some(status) = crate::status() {
            status.remove_circuit(&format!("auto-{session_id}"));
        }
    }
    Ok(changed)
}

fn association(origin: &str, id: u64) -> AssociationId {
    AssociationId {
        origin: origin.into(),
        id,
    }
}

fn observe_proof(
    proofs: &mut LlcProofRegistry,
    attachment: &PortId,
    owner: AssociationId,
    identity: IdentityObservation,
) -> io::Result<()> {
    match identity {
        IdentityObservation::ControlPoint(cp) => proofs.observe_cp(attachment, owner, &cp),
        IdentityObservation::LogicalUnit(lu) => match proofs.observe_lu(attachment, &owner, &lu) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                tracing::warn!(attachment = %attachment.0, association_origin = %owner.origin,
                        association = owner.id, lu = %lu, error = %error,
                        "LLC LU observation rejected; retaining live CP proof");
                Ok(())
            }
            Err(error) => Err(error),
        },
        IdentityObservation::Withdraw => {
            proofs.withdraw(attachment, &owner);
            Ok(())
        }
    }
}

fn reconcile_proofs(
    proofs: &LlcProofRegistry,
    bridge: &mut AutoLlcWsBridge,
    attachments: impl Iterator<Item = PortId>,
) -> io::Result<bool> {
    let mut changed = false;
    for attachment in attachments {
        let before = bridge.route_records(&attachment)?;
        bridge.withdraw(&attachment)?;
        if let Some(snapshot) = proofs.snapshot(&attachment) {
            bridge.observe_cp(
                &attachment,
                &format!("{}.{}", snapshot.cp.netid, snapshot.cp.name),
            )?;
            for lu in snapshot.lus {
                bridge.observe_bound_lu(&attachment, &format!("{}.{}", lu.netid, lu.name))?;
            }
        }
        let after = bridge.route_records(&attachment)?;
        let normalize = |records: Vec<RouteRecord>| -> HashMap<RouteKey, Vec<LuType>> {
            records
                .into_iter()
                .map(|mut record| {
                    record.supported_types.sort();
                    (record.key, record.supported_types)
                })
                .collect()
        };
        changed |= normalize(before) != normalize(after);
    }
    Ok(changed)
}

fn observe_circuit(id: u64, ingress: &str, egress: &str) {
    if let Some(status) = crate::status() {
        status.upsert_circuit(crate::local_status::CircuitStatus {
            id: format!("auto-{id}"),
            ingress: ingress.into(),
            egress: egress.into(),
            state: "active".into(),
            bytes_in: 0,
            bytes_out: 0,
            last_change_ms: crate::local_status::now_ms(),
        });
    }
}

fn observe_native_llc_peer(offer: &crate::auto_llc::LlcIngressOffer, cp: &str) {
    if let Some(status) = crate::status() {
        let now = crate::local_status::now_ms();
        let mac = crate::endpoint::format_mac(offer.guest_mac);
        status.upsert_peer(crate::local_status::LocalPeerStatus {
            key: format!("llc:{}:{mac}", offer.interface),
            transport: "llc2".into(),
            locator: format!("{} {mac}", offer.interface),
            cp: Some(cp.into()),
            lus: Vec::new(),
            state: "observed".into(),
            first_seen_ms: now,
            last_seen_ms: now,
            last_error: None,
        });
    }
}

fn incoming_lu_pair(
    hub: &AutoWsHub,
    open: &wire::IncomingOpen,
) -> io::Result<(wire::SnaName, wire::SnaName, wire::SnaName, wire::SnaName)> {
    let target = open
        .target
        .as_ref()
        .and_then(|reference| hub.local_route(reference))
        .and_then(|route| route.resource.as_ref())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "incoming target route unavailable")
        })?;
    let source = open
        .source_route
        .as_ref()
        .filter(|reference| reference.router_id == open.source_router_id)
        .and_then(|reference| hub.remote_route(reference))
        .and_then(|route| route.resource)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "incoming source route unavailable")
        })?;
    match (target, source) {
        (
            wire::route_export::Resource::LogicalUnit(hosted),
            wire::route_export::Resource::LogicalUnit(source),
        ) => {
            if open.profile == wire::CircuitProfile::SessionV1 as i32
                && (!hosted
                    .supported_types
                    .contains(&(wire::LuType::LuType62 as i32))
                    || !source
                        .supported_types
                        .contains(&(wire::LuType::LuType62 as i32)))
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "incoming SessionV1 LU pair does not advertise LU 6.2",
                ));
            }
            Ok((
                hosted.lu.clone().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "hosted LU missing")
                })?,
                hosted.hosting_cp.clone().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "hosted CP missing")
                })?,
                source.lu.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "source LU missing")
                })?,
                source.hosting_cp.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "source CP missing")
                })?,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "incoming route is not an LU6.2 pair",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn open_incoming_mptn_target(
    hub: &mut AutoWsHub,
    open: wire::IncomingOpen,
    target_lu: &wire::SnaName,
    target_cp: &wire::SnaName,
    source_lu: &wire::SnaName,
    source_cp: &wire::SnaName,
    gateway: &mut AutoMptnGateway<'_>,
    circuits: &mut HashMap<u64, MptnTargetWs>,
    next_id: &mut u64,
) -> io::Result<()> {
    let udp = gateway.lease_udp()?;
    let mut claimed = false;
    let result = (|| -> io::Result<()> {
        let Some(ws) = hub.accept_session_incoming(open)? else {
            return Ok(());
        };
        let source_lu =
            QualifiedName::new(&source_lu.netid, &source_lu.name).map_err(io::Error::other)?;
        let target_lu =
            QualifiedName::new(&target_lu.netid, &target_lu.name).map_err(io::Error::other)?;
        let source_cp =
            QualifiedName::new(&source_cp.netid, &source_cp.name).map_err(io::Error::other)?;
        let target_cp =
            QualifiedName::new(&target_cp.netid, &target_cp.name).map_err(io::Error::other)?;
        let identity = SessionIdentity::new(source_lu, target_lu)
            .with_control_points(Some(source_cp), Some(target_cp))
            .map_err(io::Error::other)?;
        let id = next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("automatic MPTN target SessionV1 ID exhausted"))?;
        let target = MptnTargetWs::new(
            identity,
            ws,
            udp,
            gateway.outbound_endpoint(),
            gateway.id().to_owned(),
        )?;
        *next_id = id;
        circuits.insert(id, target);
        claimed = true;
        tracing::info!(
            gateway = gateway.id(),
            session = id,
            "automatic SessionV1 to TCP62 bridge installed"
        );
        Ok(())
    })();
    if result.is_err() || !claimed {
        gateway.release_udp();
    }
    result
}

// One admission needs the bridge, the live hub, both listener registries and
// the private fabric; grouping these borrows would hide the transaction.
#[allow(clippy::too_many_arguments)]
fn open_incoming_llc(
    bridge: &AutoLlcWsBridge,
    hub: &mut AutoWsHub,
    open: wire::IncomingOpen,
    remote: &config::RemoteConfig,
    config: &RouterConfig,
    listeners: &mut [LlcAutoListener],
    fabric: &mut AutomaticFabric,
    sessions: &mut HashMap<u64, LlcSession>,
    next_id: &mut u64,
) -> io::Result<()> {
    let selected = bridge.incoming_selection(hub, &open)?;
    let index = config
        .llc
        .iter()
        .position(|peer| peer.id == selected.attachment.0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "selected LLC attachment is absent")
        })?;
    let target = open
        .target
        .as_ref()
        .and_then(|reference| hub.local_route(reference))
        .and_then(|route| route.resource.as_ref())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "incoming LLC target route is absent",
            )
        })?;
    let destination = match target {
        wire::route_export::Resource::ControlPoint(cp) => RouteAddress::ControlPoint {
            netid: cp.netid.clone(),
            name: cp.name.clone(),
        },
        wire::route_export::Resource::LogicalUnit(lu) => {
            let name = lu.lu.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "incoming LLC LU name absent")
            })?;
            RouteAddress::LogicalUnit {
                netid: name.netid.clone(),
                cp: lu.hosting_cp.as_ref().map(|cp| cp.name.clone()),
                name: name.name.clone(),
            }
        }
    };
    let remote_id = PortId::new(&remote.id);
    if fabric.resolve(&remote_id, &destination)? != selected.attachment {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incoming LLC target directory changed",
        ));
    }
    listeners[index].allow_native_proxy_mac(selected.proxy_mac)?;
    if !listeners[index].reserve(selected.proxy_mac)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local LLC peer is busy",
        ));
    }
    let result = (|| -> io::Result<()> {
        let local = AutoLlcPort::open_outbound(
            &selected.interface,
            selected.guest_mac,
            selected.proxy_mac,
        )?;
        let id = next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("automatic circuit ID exhausted"))?;
        let ws = hub.accept_incoming(open)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "incoming WebSocket circuit is no longer current",
            )
        })?;
        fabric.open_pair(
            id,
            &remote_id,
            &destination,
            &selected.attachment,
            Box::new(ws),
            Box::new(local),
        )?;
        *next_id = id;
        sessions.insert(
            id,
            LlcSession {
                ingress: None,
                egress: Some((index, selected.proxy_mac)),
                upstream: true,
            },
        );
        observe_circuit(id, &remote.id, &selected.attachment.0);
        Ok(())
    })();
    if result.is_err() {
        listeners[index].release(selected.proxy_mac);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn open_incoming_llc_session(
    bridge: &AutoLlcWsBridge,
    hub: &mut AutoWsHub,
    open: wire::IncomingOpen,
    hosted_lu: &wire::SnaName,
    hosted_cp: &wire::SnaName,
    config: &RouterConfig,
    listeners: &mut [LlcAutoListener],
    circuits: &mut HashMap<u64, LlcSessionCircuit>,
    next_id: &mut u64,
) -> io::Result<()> {
    let selected = bridge.incoming_selection(hub, &open)?;
    let index = config
        .llc
        .iter()
        .position(|peer| peer.id == selected.attachment.0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "selected LLC attachment is absent")
        })?;
    if circuits.values().any(|circuit| circuit.listener == index)
        || !listeners[index].attachment_idle()
    {
        hub.reject_incoming(&open, wire::OpenFailure::Busy)?;
        return Ok(());
    }
    listeners[index].allow_native_proxy_mac(selected.proxy_mac)?;
    if !listeners[index].reserve_exclusive(selected.proxy_mac)? {
        hub.reject_incoming(&open, wire::OpenFailure::Busy)?;
        return Ok(());
    }
    let mut admitted = false;
    let result = (|| -> io::Result<()> {
        let target_lu = router_core::session::QualifiedName::new(&hosted_lu.netid, &hosted_lu.name)
            .map_err(io::Error::other)?;
        let target_cp = router_core::session::QualifiedName::new(&hosted_cp.netid, &hosted_cp.name)
            .map_err(io::Error::other)?;
        let Some((identity, ws)) = crate::llc_session_ws::admit(hub, open, &target_lu, &target_cp)?
        else {
            return Ok(());
        };
        let id = next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("automatic LLC SessionV1 ID exhausted"))?;
        let peer = LlcPeer {
            interface: &selected.interface,
            guest_mac: selected.guest_mac,
            proxy_mac: selected.proxy_mac,
        };
        let seed = format!("{}:{}", selected.attachment.0, id);
        let adjacent_cp = identity
            .source_cp
            .as_ref()
            .ok_or_else(|| io::Error::other("incoming LLC source CP missing"))?
            .clone();
        let session = LlcSessionWs::new(
            identity,
            ws,
            selected.attachment.0.clone(),
            peer,
            &adjacent_cp,
            seed.as_bytes(),
        )?;
        *next_id = id;
        circuits.insert(
            id,
            LlcSessionCircuit {
                bridge: session,
                listener: index,
                proxy_mac: selected.proxy_mac,
                verified_logged: false,
            },
        );
        admitted = true;
        Ok(())
    })();
    if result.is_err() || !admitted {
        listeners[index].release(selected.proxy_mac);
    }
    result
}

#[cfg(test)]
mod session_profile_tests {
    use super::*;

    #[test]
    fn invalid_lu_observation_does_not_remove_verified_cp_or_routes() {
        let attachment = PortId::new("llc-a");
        let owner = association("fabric", 7);
        let mut proofs = LlcProofRegistry::default();
        proofs
            .observe_cp(&attachment, owner.clone(), "LOCAL.CPA")
            .unwrap();
        observe_proof(
            &mut proofs,
            &attachment,
            owner.clone(),
            IdentityObservation::LogicalUnit("OTHER.LUA".into()),
        )
        .unwrap();
        observe_proof(
            &mut proofs,
            &attachment,
            owner.clone(),
            IdentityObservation::LogicalUnit("bad-name".into()),
        )
        .unwrap();
        let snapshot = proofs.snapshot(&attachment).unwrap();
        assert_eq!(snapshot.cp, QualifiedName::new("LOCAL", "CPA").unwrap());
        assert!(snapshot.lus.is_empty());
        observe_proof(
            &mut proofs,
            &attachment,
            owner,
            IdentityObservation::LogicalUnit("LOCAL.LUA".into()),
        )
        .unwrap();
        assert_eq!(
            proofs.snapshot(&attachment).unwrap().lus,
            vec![QualifiedName::new("LOCAL", "LUA").unwrap()]
        );
    }

    #[test]
    fn hub_loss_withdraws_upstream_but_keeps_local_discovery() {
        let config: RouterConfig = toml::from_str(
            "[[concentrator]]\nid = 'upstream'\nurl = 'ws://127.0.0.1:8081/router'\n",
        )
        .unwrap();
        let mut runner = AutoLocalSessionRunner::new(&config).unwrap();
        let local_cp = QualifiedName::new("LOCAL", "CPA").unwrap();
        let local_lu = QualifiedName::new("LOCAL", "LUA").unwrap();
        runner
            .fabric
            .directory_mut()
            .replace_local_records(
                PortId::new("llc-a"),
                vec![
                    RouteRecord::from(RouteKey::ControlPoint(local_cp.clone())),
                    RouteRecord {
                        key: RouteKey::LogicalUnit {
                            lu: local_lu.clone(),
                            hosting_cp: local_cp.clone(),
                        },
                        supported_types: vec![LuType::Lu7],
                    },
                ],
            )
            .unwrap();
        runner
            .fabric
            .directory_mut()
            .replace_upstream(
                PortId::new("upstream"),
                [RouteAddress::ControlPoint {
                    netid: "REMOTE".into(),
                    name: "CPB".into(),
                }],
            )
            .unwrap();

        runner.on_hub_lost().unwrap();
        runner.poll_local(None).unwrap();
        let (cps, lus) = runner.exports("LOCAL");
        assert_eq!(cps, vec![wire_name(&local_cp)]);
        assert_eq!(lus.len(), 1);
        assert_eq!(lus[0].lu, Some(wire_name(&local_lu)));
        assert_eq!(lus[0].supported_types, vec![wire::LuType::LuType7 as i32]);
        assert!(runner.exports("REMOTE").0.is_empty());
        assert_eq!(
            runner
                .fabric
                .resolve(
                    &PortId::new("llc-a"),
                    &RouteAddress::ControlPoint {
                        netid: "REMOTE".into(),
                        name: "CPB".into(),
                    },
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn llc_route_survives_one_association_closing_and_withdraws_on_last() {
        let attachment = PortId::new("llc-a");
        let mut bridge = AutoLlcWsBridge::default();
        bridge
            .register(attachment.clone(), "tap0".into(), [2, 0, 0, 0, 0, 1])
            .unwrap();
        let mut proofs = LlcProofRegistry::default();
        for session in [1, 2] {
            proofs
                .observe_cp(&attachment, association("fabric", session), "LOCAL.CPA")
                .unwrap();
        }
        assert!(
            reconcile_proofs(&proofs, &mut bridge, std::iter::once(attachment.clone())).unwrap()
        );
        assert_eq!(bridge.observed_cp(&attachment).unwrap().name, "CPA");
        proofs.withdraw(&attachment, &association("fabric", 1));
        assert!(
            !reconcile_proofs(&proofs, &mut bridge, std::iter::once(attachment.clone())).unwrap()
        );
        assert_eq!(bridge.observed_cp(&attachment).unwrap().name, "CPA");
        proofs.withdraw(&attachment, &association("fabric", 2));
        assert!(
            reconcile_proofs(&proofs, &mut bridge, std::iter::once(attachment.clone())).unwrap()
        );
        assert!(bridge.observed_cp(&attachment).is_none());
    }

    #[test]
    fn local_publication_preserves_lu7_and_excludes_other_netids_and_upstream() {
        let mut directory = crate::routing::AutomaticDirectory::default();
        let local_cp = QualifiedName::new("LOCAL", "CP1").unwrap();
        let local_lu = QualifiedName::new("LOCAL", "PRINTER").unwrap();
        directory
            .replace_local_records(
                PortId::new("llc-a"),
                vec![
                    RouteRecord::from(RouteKey::ControlPoint(local_cp.clone())),
                    RouteRecord {
                        key: RouteKey::LogicalUnit {
                            lu: local_lu.clone(),
                            hosting_cp: local_cp.clone(),
                        },
                        supported_types: vec![LuType::Lu7],
                    },
                ],
            )
            .unwrap();
        directory
            .replace_upstream(
                PortId::new("concentrator"),
                [RouteAddress::ControlPoint {
                    netid: "LOCAL".into(),
                    name: "REMOTE".into(),
                }],
            )
            .unwrap();
        let (cps, lus) = publication_records(&directory, "LOCAL");
        assert_eq!(cps, vec![wire_name(&local_cp)]);
        assert_eq!(lus.len(), 1);
        assert_eq!(lus[0].lu, Some(wire_name(&local_lu)));
        assert_eq!(lus[0].supported_types, vec![wire::LuType::LuType7 as i32]);
        assert_eq!(publication_records(&directory, "OTHER"), (vec![], vec![]));
    }

    #[test]
    fn ambiguous_local_identity_is_not_published() {
        let mut directory = crate::routing::AutomaticDirectory::default();
        let cp = QualifiedName::new("LOCAL", "CP1").unwrap();
        for attachment in ["llc-a", "mptn-b"] {
            directory
                .replace_local_records(
                    PortId::new(attachment),
                    vec![RouteRecord::from(RouteKey::ControlPoint(cp.clone()))],
                )
                .unwrap();
        }
        assert!(publication_records(&directory, "LOCAL").0.is_empty());
    }

    #[test]
    fn automatic_mptn_lu62_uses_session_profile_and_rejects_cp_or_untyped_lu() {
        let lu = wire::LuReachability {
            lu: Some(wire::SnaName {
                netid: "SOLNET".into(),
                name: "SNAB".into(),
            }),
            hosting_cp: Some(wire::SnaName {
                netid: "SOLNET".into(),
                name: "SNAB".into(),
            }),
            supported_types: vec![wire::LuType::LuType62 as i32],
        };
        let mut route = wire::RouteExport {
            id: 1,
            generation: 1,
            resource: Some(wire::route_export::Resource::LogicalUnit(lu.clone())),
        };
        assert!(require_session_v1_target(&route).is_ok());
        route.resource = Some(wire::route_export::Resource::ControlPoint(
            lu.hosting_cp.unwrap(),
        ));
        assert_eq!(
            require_session_v1_target(&route).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        route.resource = Some(wire::route_export::Resource::LogicalUnit(
            wire::LuReachability {
                lu: lu.lu,
                hosting_cp: None,
                supported_types: Vec::new(),
            },
        ));
        assert_eq!(
            require_session_v1_target(&route).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
