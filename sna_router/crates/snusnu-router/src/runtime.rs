//! LLC adapter and local route configuration.

use crate::{
    anynet_port::AnyNetPort,
    config::{self, BidirectionalGatewayConfig, RouterConfig},
    endpoint::{format_mac, Endpoint, EndpointRegistry, Event},
    hpr_lan_port::HprLanPort,
    ip_ports::EePort,
    local_status::{now_ms, LocalPeerStatus},
    mptn_bidirectional_gateway,
    mptn_llc_reverse::{self, ReverseLlcConfig},
    mptn_ws_reverse::{self, ReverseWsConfig},
    remote::{Config as RemoteConfig, WsRoutePort},
    routing::{PortId, RouteAddress, RoutePort, RoutedUnit, Router, RouterEvent},
};
use router_core::llc2::State;
use router_core::xid3::Xid3;
use std::{
    cell::RefCell,
    io,
    rc::Rc,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const CONNECT_BARRIER: Duration = Duration::from_millis(200);

#[derive(Clone, Copy)]
pub(crate) struct LlcPeer<'a> {
    pub(crate) interface: &'a str,
    pub(crate) guest_mac: [u8; 6],
    pub(crate) proxy_mac: [u8; 6],
}

pub(crate) struct LlcPort {
    endpoint: Endpoint,
    registry: Option<Rc<RefCell<EndpointRegistry>>>,
    cp_gate: Option<CpGate>,
    peer_ready: bool,
    interface: String,
    guest_mac: [u8; 6],
}

struct CpGate {
    expected: String,
    verified: bool,
}

impl CpGate {
    fn observe(&mut self, pdu: &[u8]) -> io::Result<bool> {
        if pdu.get(2).is_none_or(|control| control & !0x10 != 0xaf) || pdu.get(3) != Some(&0x32) {
            return Ok(false);
        }
        let xid = Xid3::decode(&pdu[3..]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid guest XID3: {error}"),
            )
        })?;
        let observed = xid.cp_name().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guest XID3 lacks CP identity: {error}"),
            )
        })?;
        let expected_netid = self.expected.split_once('.').map(|(netid, _)| netid);
        let observed_netid = observed.split_once('.').map(|(netid, _)| netid);
        if observed_netid != expected_netid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "guest XID3 NETID {} differs from configured {}",
                    observed_netid.unwrap_or("<missing>"),
                    expected_netid.unwrap_or("<missing>")
                ),
            ));
        }
        if observed != self.expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "guest XID3 CP {observed} differs from configured {}",
                    self.expected
                ),
            ));
        }
        let newly_verified = !self.verified;
        self.verified = true;
        Ok(newly_verified)
    }
}

impl LlcPort {
    fn observe_peer(&self, cp: Option<String>, state: &str) {
        let Some(status) = crate::status() else {
            return;
        };
        let key = format!("llc:{}:{}", self.interface, format_mac(self.guest_mac));
        let existing = status
            .snapshot()
            .local_peers
            .into_iter()
            .find(|peer| peer.key == key);
        if cp.is_none() && existing.is_none() {
            return;
        }
        let now = now_ms();
        status.upsert_peer(LocalPeerStatus {
            key,
            transport: "llc2".into(),
            locator: format!("{} {}", self.interface, format_mac(self.guest_mac)),
            cp: cp.or_else(|| existing.as_ref().and_then(|peer| peer.cp.clone())),
            lus: Vec::new(),
            state: state.into(),
            first_seen_ms: now,
            last_seen_ms: now,
            last_error: None,
        });
    }

    pub(crate) fn open(peer: LlcPeer<'_>) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?,
            registry: None,
            cp_gate: None,
            peer_ready: false,
            interface: peer.interface.to_owned(),
            guest_mac: peer.guest_mac,
        })
    }

    fn open_registered(
        peer: LlcPeer<'_>,
        registry: Rc<RefCell<EndpointRegistry>>,
        expected_cp: Option<&str>,
    ) -> io::Result<Self> {
        let mut endpoint = if peer.proxy_mac == [0; 6] {
            Endpoint::open_unbound(peer.interface, peer.guest_mac)?
        } else {
            Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?
        };
        if expected_cp.is_some() {
            endpoint.set_connect_allowed(false)?;
        }
        Ok(Self {
            endpoint,
            registry: Some(registry),
            cp_gate: expected_cp.map(|expected| CpGate {
                expected: expected.to_owned(),
                verified: false,
            }),
            peer_ready: false,
            interface: peer.interface.to_owned(),
            guest_mac: peer.guest_mac,
        })
    }

    fn map_events(&mut self, events: Vec<Event>) -> io::Result<Vec<RouterEvent>> {
        let mut routed = Vec::with_capacity(events.len());
        for event in events {
            match &event {
                Event::Type1(pdu) => {
                    let mut observed_cp = None;
                    if let Some(gate) = &mut self.cp_gate {
                        let newly_verified = match gate.observe(pdu) {
                            Ok(verified) => verified,
                            Err(error) => {
                                tracing::warn!(interface = %self.interface, guest_mac = %format_mac(self.guest_mac), expected_cp = %gate.expected, error = %error, "guest XID3 CP identity rejected");
                                return Err(error);
                            }
                        };
                        if newly_verified {
                            tracing::info!(interface = %self.interface, guest_mac = %format_mac(self.guest_mac), cp = %gate.expected, "guest XID3 CP identity verified");
                            self.endpoint.set_connect_allowed(true)?;
                            if self.peer_ready && self.endpoint.state() == State::Disconnected {
                                self.endpoint.begin_connect_after(CONNECT_BARRIER);
                            }
                        }
                        if gate.verified {
                            observed_cp = Some(gate.expected.clone());
                        }
                    } else if pdu.get(2).is_some_and(|control| control & !0x10 == 0xaf)
                        && pdu.get(3) == Some(&0x32)
                    {
                        observed_cp = Xid3::decode(&pdu[3..])
                            .ok()
                            .and_then(|xid| xid.cp_name().ok());
                    }
                    if let Some(cp) = observed_cp {
                        self.observe_peer(Some(cp), "observed");
                    }
                }
                Event::Connected => self.observe_peer(None, "connected"),
                Event::Disconnected | Event::TimedOut => {
                    if let Some(gate) = &mut self.cp_gate {
                        gate.verified = false;
                        self.endpoint.set_connect_allowed(false)?;
                    }
                    self.peer_ready = false;
                    self.observe_peer(None, "disconnected");
                }
                _ => {}
            }
            routed.push(map_event(event));
        }
        Ok(routed)
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
        let Some(events) = self.endpoint.poll(can_accept_information)? else {
            return Ok(None);
        };
        Ok(Some(self.map_events(events)?))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        let events = self.endpoint.tick()?;
        self.map_events(events)
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        match unit {
            RoutedUnit::DlcType1(pdu) => {
                self.endpoint.send_type1(&pdu)?;
                Ok(true)
            }
            RoutedUnit::SnaInformation(data) => self.endpoint.queue_information(data),
            RoutedUnit::AnyNetTcpRecord(_)
            | RoutedUnit::AnyNetUdpDatagram(_)
            | RoutedUnit::EeDatagram { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IP SNA encapsulation cannot be sent on an LLC2 port without a converter",
            )),
        }
    }

    fn has_capacity(&self) -> bool {
        self.endpoint.has_capacity()
    }

    fn available_receive_slots(&self) -> usize {
        self.endpoint.available_receive_slots()
    }

    fn take_completed_information_count(&mut self) -> usize {
        self.endpoint.take_completed_information_count()
    }

    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.endpoint.set_local_busy(busy)
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        self.peer_ready = true;
        if !self.endpoint.is_unbound()
            && self.endpoint.state() == State::Disconnected
            && self.cp_gate.as_ref().is_none_or(|gate| gate.verified)
        {
            self.endpoint.begin_connect_after(CONNECT_BARRIER);
        }
        Ok(())
    }

    fn on_managed_mac(&mut self, mac: [u8; 6]) -> io::Result<()> {
        if let Some(registry) = &self.registry {
            let mut registry = registry.borrow_mut();
            if self.endpoint.is_unbound() {
                registry.bind_unbound(&mut self.endpoint, mac)?;
            } else {
                registry.apply_managed_proxy_mac(&mut self.endpoint, mac)?;
            }
        } else {
            self.endpoint.set_managed_proxy_mac(mac)?;
        }
        if self.peer_ready
            && self.endpoint.state() == State::Disconnected
            && self.cp_gate.as_ref().is_none_or(|gate| gate.verified)
        {
            self.endpoint.begin_connect_after(CONNECT_BARRIER);
        }
        Ok(())
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.endpoint.disconnect()?;
        self.observe_peer(None, "disconnected");
        self.peer_ready = false;
        if let Some(gate) = &mut self.cp_gate {
            gate.verified = false;
            self.endpoint.set_connect_allowed(false)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.endpoint.flush()
    }
}

fn concentrator_llc<'a>(
    config: &'a RouterConfig,
    entry: &config::RemoteConfig,
) -> io::Result<&'a config::LlcConfig> {
    let local_id = config.concentrator_local_id(entry)?;
    config
        .llc
        .iter()
        .find(|peer| peer.id == local_id)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "concentrator requires LLC peer",
            )
        })
}

fn configured_proxy_mac(config: &RouterConfig, peer: &config::LlcConfig) -> io::Result<[u8; 6]> {
    Ok(config.llc_proxy_mac(&peer.id)?.unwrap_or([0; 6]))
}

/// Start all configured local associations and the optional concentrator hop.
/// The route table is checked before any raw socket is opened.
pub(crate) fn run_config(config: &RouterConfig) -> io::Result<()> {
    config.validate()?;
    if config.automatic() {
        return crate::auto_runtime::run(config);
    }
    if let Some(duplex) = config.bidirectional_gateway_config()? {
        return run_bidirectional_gateway(duplex);
    }
    if let Some(reverse) = config.reverse_llc_config()? {
        return run_reverse_llc(reverse);
    }
    if let Some(reverse) = config.reverse_ws_config()? {
        return run_reverse_ws(reverse);
    }
    if !config.mptn_gateway.is_empty() {
        return crate::mptn_ws_gateway_lab::run_config(config, false);
    }
    const FIRST_RETRY: Duration = Duration::from_millis(500);
    const MAX_RETRY: Duration = Duration::from_secs(30);
    let mut delay = FIRST_RETRY;
    while !crate::STOP.load(Ordering::Relaxed) {
        let mut registry = EndpointRegistry::default();
        for peer in &config.llc {
            if config.llc_proxy_mac(&peer.id)?.is_some() {
                registry.register(
                    &peer.interface,
                    config::parse_mac(&peer.guest_mac)?,
                    configured_proxy_mac(config, peer)?,
                )?;
            }
        }
        let registry = Rc::new(RefCell::new(registry));
        let mut router = Router::new();
        for peer in &config.llc {
            let id = PortId::new(&peer.id);
            router.register_port(
                id,
                Box::new(LlcPort::open_registered(
                    LlcPeer {
                        interface: &peer.interface,
                        guest_mac: config::parse_mac(&peer.guest_mac)?,
                        proxy_mac: configured_proxy_mac(config, peer)?,
                    },
                    registry.clone(),
                    peer.local_cp.as_deref(),
                )?),
            )?;
        }
        for peer in &config.ee {
            router.register_port(
                PortId::new(&peer.id),
                Box::new(EePort::open(peer.local_ip, peer.peer_ip)?),
            )?;
        }
        for peer in &config.hpr_lan {
            router.register_port(
                PortId::new(&peer.id),
                Box::new(HprLanPort::open(
                    &peer.interface,
                    config::parse_mac(&peer.proxy_mac)?,
                    config::parse_mac(&peer.guest_mac)?,
                    0x04,
                    0x04,
                )?),
            )?;
        }
        for peer in &config.anynet {
            router.register_port(
                PortId::new(&peer.id),
                Box::new(AnyNetPort::open_with_lus(
                    peer.local_ip,
                    peer.peer_ip,
                    peer.local_lu.clone(),
                    peer.remote_lu.clone(),
                )?),
            )?;
        }
        // Opening the WebSocket publishes local CP/LU routes immediately.
        // Keep that publication behind successful local port initialization.
        let remote_ports = if let Some(remote) = config.remote.first() {
            let options = config
                .remote
                .iter()
                .map(|entry| {
                    let peer = concentrator_llc(config, entry)?;
                    Ok(RemoteConfig {
                        url: entry.url.clone(),
                        bearer: entry.bearer_token()?,
                        local_cp: config::parse_cp(peer.local_cp.as_deref().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "LLC peer has no local CP")
                        })?)?,
                        target_cp: config::parse_cp(entry.target_cp.as_deref().ok_or_else(
                            || {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "concentrator has no target CP",
                                )
                            },
                        )?)?,
                        target_lu: entry
                            .target_lu
                            .as_deref()
                            .map(config::parse_cp)
                            .transpose()?,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            let mut logical_units = Vec::new();
            for entry in &config.remote {
                let peer = concentrator_llc(config, entry)?;
                let hosting_cp = config::parse_cp(peer.local_cp.as_deref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "LLC peer has no local CP")
                })?)?;
                for name in &peer.lus {
                    logical_units.push(transport_ws::wire::LuReachability {
                        lu: Some(config::parse_cp(name)?),
                        hosting_cp: Some(hosting_cp.clone()),
                        supported_types: peer
                            .lu_types
                            .get(name)
                            .into_iter()
                            .flatten()
                            .map(|lu_type| lu_type.wire_value())
                            .collect(),
                    });
                }
            }
            let connected = if config.remote[0].target_lu.is_some() {
                let source_lus = config
                    .remote
                    .iter()
                    .map(|entry| {
                        let peer = concentrator_llc(config, entry)?;
                        peer.lus.first().map(|lu| config::parse_cp(lu)).transpose()
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                WsRoutePort::connect_many_v2(options, logical_units, source_lus)
            } else {
                WsRoutePort::connect_many(options, logical_units)
            };
            match connected {
                Ok(ports) => Some(ports),
                Err(error) if retryable_remote_error(&error) => {
                    tracing::warn!(upstream = upstream_authority(&remote.url), error = %error, retry_ms = delay.as_millis(), "concentrator connection failed");
                    wait_or_stop(delay);
                    delay = delay.saturating_mul(2).min(MAX_RETRY);
                    continue;
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let connected_at = Instant::now();
        if let Some(remote_ports) = remote_ports {
            for (remote, port) in config.remote.iter().zip(remote_ports) {
                router.register_port(PortId::new(&remote.id), Box::new(port))?;
            }
        }
        for route in &config.route {
            let source = PortId::new(&route.from);
            let target = PortId::new(&route.to);
            install_config_route(&mut router, config, &source, &target)?;
            if route.bidirectional {
                install_config_route(&mut router, config, &target, &source)?;
            }
        }
        match router.run() {
            Ok(()) => return Ok(()),
            Err(error) if !config.remote.is_empty() && retryable_remote_error(&error) => {
                for peer in &config.llc {
                    router.disconnect_port(&PortId::new(&peer.id))?;
                }
                if connected_at.elapsed() >= MAX_RETRY {
                    delay = FIRST_RETRY;
                }
                let url = &config.remote.first().expect("checked").url;
                tracing::warn!(upstream = upstream_authority(url), error = %error, retry_ms = delay.as_millis(), "concentrator link lost");
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(MAX_RETRY);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn run_bidirectional_gateway(config: BidirectionalGatewayConfig<'_>) -> io::Result<()> {
    let mut delay = Duration::from_millis(500);
    tracing::info!(
        local_ip=%config.gateway.local_ip,
        peer_ip=%config.gateway.peer_ip,
        hosted_lu=%config.gateway.source_lu,
        remote_lu=%config.gateway.destination_lu,
        upstream=%upstream_authority(&config.concentrator.url),
        "duplex MPTN gateway starting"
    );
    while !crate::STOP.load(Ordering::Relaxed) {
        match mptn_bidirectional_gateway::run_once(&config) {
            Ok(()) => {
                delay = Duration::from_millis(500);
                tracing::info!(hosted_lu=%config.gateway.source_lu, "duplex gateway circuit closed");
                wait_or_stop(Duration::from_millis(200));
            }
            Err(error) if retryable_reverse_error(&error) || retryable_remote_error(&error) => {
                tracing::warn!(peer_ip=%config.gateway.peer_ip, upstream=%upstream_authority(&config.concentrator.url), error=%error, retry_ms=delay.as_millis(), "duplex gateway circuit failed");
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(Duration::from_secs(30));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A native-to-TCP62 converter owns one private LLC/TCP/UDP circuit at a
/// time. Reopen it after a completed or transiently failed session so the
/// configured route remains available for the next OS/400 contact.
fn run_reverse_llc(config: ReverseLlcConfig) -> io::Result<()> {
    config.validate()?;
    let mut delay = Duration::from_millis(500);
    tracing::info!(
        interface = %config.interface,
        guest_cp = %config.guest_cp,
        source_lu = %config.source_lu,
        destination_lu = %config.destination_lu,
        local_ip = %config.endpoint.local_ip,
        peer_ip = %config.endpoint.peer_ip,
        "native LLC to MPTN route starting"
    );
    while !crate::STOP.load(Ordering::Relaxed) {
        match mptn_llc_reverse::run_once(&config) {
            Ok(()) => {
                delay = Duration::from_millis(500);
                tracing::info!(source_lu = %config.source_lu, destination_lu = %config.destination_lu, "native LLC to MPTN circuit closed");
                wait_or_stop(Duration::from_millis(200));
            }
            Err(error) if retryable_reverse_error(&error) => {
                tracing::warn!(
                    peer_ip = %config.endpoint.peer_ip,
                    source_lu = %config.source_lu,
                    destination_lu = %config.destination_lu,
                    error = %error,
                    retry_ms = delay.as_millis(),
                    "native LLC to MPTN circuit failed"
                );
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(Duration::from_secs(30));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// One hosted MPTN LU accepts concentrator-initiated native circuits. Each
/// completed or transiently failed circuit gets fresh management state and
/// a new TCP62 correlator on the next attempt.
fn run_reverse_ws(config: ReverseWsConfig) -> io::Result<()> {
    config.validate()?;
    let mut delay = Duration::from_millis(500);
    tracing::info!(
        hosted_cp = %config.hosted_cp,
        hosted_lu = %config.hosted_lu,
        source_cp = %config.source_cp,
        source_lu = %config.source_lu,
        local_ip = %config.endpoint.local_ip,
        peer_ip = %config.endpoint.peer_ip,
        "concentrator to MPTN route starting"
    );
    while !crate::STOP.load(Ordering::Relaxed) {
        match mptn_ws_reverse::run_once(&config) {
            Ok(()) => {
                delay = Duration::from_millis(500);
                tracing::info!(source_lu = %config.source_lu, hosted_lu = %config.hosted_lu, "concentrator to MPTN circuit closed");
                wait_or_stop(Duration::from_millis(200));
            }
            Err(error) if retryable_reverse_error(&error) || retryable_remote_error(&error) => {
                tracing::warn!(
                    source_lu = %config.source_lu,
                    hosted_lu = %config.hosted_lu,
                    peer_ip = %config.endpoint.peer_ip,
                    error = %error,
                    retry_ms = delay.as_millis(),
                    "concentrator to MPTN circuit failed"
                );
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(Duration::from_secs(30));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn retryable_reverse_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn install_config_route(
    router: &mut Router,
    config: &RouterConfig,
    source: &PortId,
    target: &PortId,
) -> io::Result<()> {
    let address = if let Some(peer) = config.llc.iter().find(|peer| peer.id == source.0) {
        Some(match config.llc_proxy_mac(&peer.id)? {
            Some(mac) => RouteAddress::Mac(mac),
            None => RouteAddress::UnboundManagedMac,
        })
    } else if let Some(peer) = config.hpr_lan.iter().find(|peer| peer.id == source.0) {
        Some(RouteAddress::Mac(config::parse_mac(&peer.proxy_mac)?))
    } else if let Some(remote) = config.remote.iter().find(|remote| remote.id == source.0) {
        let peer = concentrator_llc(config, remote)?;
        let cp = config::parse_cp(peer.local_cp.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "LLC peer has no local CP")
        })?)?;
        Some(RouteAddress::ControlPoint {
            netid: cp.netid,
            name: cp.name,
        })
    } else if let Some(anynet) = config.anynet.iter().find(|peer| peer.id == source.0) {
        if let Some(lu) = &anynet.remote_lu {
            let lu = config::parse_cp(lu)?;
            Some(RouteAddress::LogicalUnit {
                netid: lu.netid,
                cp: None,
                name: lu.name,
            })
        } else {
            None
        }
    } else {
        None
    };
    if let Some(address) = address {
        router.add_address_route(source, address.clone(), target)?;
        router.bind_destination(source, address)
    } else {
        router.add_route(source, target)
    }
}

pub(crate) fn run(a: LlcPeer<'_>, b: LlcPeer<'_>) -> io::Result<()> {
    tracing::info!(interface_a = a.interface, guest_mac_a = %format_mac(a.guest_mac), proxy_mac_a = %format_mac(a.proxy_mac), interface_b = b.interface, guest_mac_b = %format_mac(b.guest_mac), proxy_mac_b = %format_mac(b.proxy_mac), sap = 4, "standalone LLC route starting");
    let mut router = Router::new();
    let a_id = PortId::new("local-a");
    let b_id = PortId::new("local-b");
    router.register_port(a_id.clone(), Box::new(LlcPort::open(a)?))?;
    router.register_port(b_id.clone(), Box::new(LlcPort::open(b)?))?;
    router.add_route(&a_id, &b_id)?;
    router.add_route(&b_id, &a_id)?;
    router.run()
}

pub(crate) fn run_remote(local: LlcPeer<'_>, config: RemoteConfig) -> io::Result<()> {
    const FIRST_RETRY: Duration = Duration::from_millis(500);
    const MAX_RETRY: Duration = Duration::from_secs(30);
    let mut delay = FIRST_RETRY;
    tracing::info!(interface = local.interface, guest_mac = %format_mac(local.guest_mac), proxy_mac = %format_mac(local.proxy_mac), local_cp = %format!("{}.{}", config.local_cp.netid, config.local_cp.name), target_cp = %format!("{}.{}", config.target_cp.netid, config.target_cp.name), upstream = upstream_authority(&config.url), "remote LLC route starting");
    while !crate::STOP.load(Ordering::Relaxed) {
        let remote = match WsRoutePort::connect(config.clone()) {
            Ok(port) => port,
            Err(error) if retryable_remote_error(&error) => {
                tracing::warn!(upstream = upstream_authority(&config.url), error = %error, retry_ms = delay.as_millis(), "concentrator connection failed");
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(MAX_RETRY);
                continue;
            }
            Err(error) => return Err(error),
        };
        let connected_at = Instant::now();
        let local_id = PortId::new("local-llc");
        let remote_id = PortId::new("concentrator");
        let mut router = Router::new();
        router.register_port(local_id.clone(), Box::new(LlcPort::open(local)?))?;
        router.register_port(remote_id.clone(), Box::new(remote))?;
        router.add_route(&local_id, &remote_id)?;
        router.add_route(&remote_id, &local_id)?;
        match router.run() {
            Ok(()) => return Ok(()),
            Err(error) => {
                // The old server epoch and circuit cannot be reused. Notify
                // the OS/400 LLC peer before constructing a fresh router.
                router.disconnect_port(&local_id)?;
                if !retryable_remote_error(&error) {
                    return Err(error);
                }
                if connected_at.elapsed() >= MAX_RETRY {
                    delay = FIRST_RETRY;
                }
                tracing::warn!(upstream = upstream_authority(&config.url), error = %error, retry_ms = delay.as_millis(), "concentrator link lost");
                wait_or_stop(delay);
                delay = delay.saturating_mul(2).min(MAX_RETRY);
            }
        }
    }
    Ok(())
}

fn retryable_remote_error(error: &io::Error) -> bool {
    use transport_ws::Error as WsError;
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<WsError>())
        .is_some_and(WsError::is_retryable)
}

fn upstream_authority(url: &str) -> &str {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    authority.rsplit('@').next().unwrap_or("")
}

fn wait_or_stop(delay: Duration) {
    let mut remaining = delay;
    while !remaining.is_zero() && !crate::STOP.load(Ordering::Relaxed) {
        let step = remaining.min(Duration::from_millis(100));
        thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn rejects_permanent_router_protocol_errors() {
        let invalid = io::Error::other(transport_ws::Error::InvalidBearer);
        assert!(!retryable_remote_error(&invalid));
        let closed = io::Error::other(transport_ws::Error::Protocol("server closed connection"));
        assert!(retryable_remote_error(&closed));
        assert!(!retryable_remote_error(&io::Error::other(
            "local TAP failed"
        )));
        assert!(retryable_reverse_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "TCP62 reset"
        )));
        assert!(!retryable_reverse_error(&io::Error::new(
            io::ErrorKind::Unsupported,
            "MPTN abort compensation unavailable"
        )));
    }

    #[test]
    fn upstream_log_field_omits_url_credentials_and_query() {
        assert_eq!(
            upstream_authority("wss://hidden@example.org:443/router/v1/ws?token=secret"),
            "example.org:443"
        );
    }

    #[test]
    fn rejects_missing_local_cp_before_opening_local_or_upstream_port() {
        let config: RouterConfig = toml::from_str(
            r#"
[[llc]]
id = "guest"
interface = "definitely-missing-sna-tap"
guest_mac = "02:00:35:27:23:01"
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:9/router/v1/ws"
target_cp = "SOLNET.SNAB"
token = ""
[[route]]
from = "guest"
to = "upstream"
"#,
        )
        .unwrap();
        let error = run_config(&config).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot publish CP"));
    }

    #[test]
    fn guest_xid3_cp_must_match_before_llc_activation() {
        // Sanitized V4R4 XID3 with SOLNET.SNAB in CV0E/F4.
        let xid = [
            0x32, 0x2f, 0xff, 0xf1, 0x23, 0x45, 0x00, 0x00, 0x00, 0xb4, 0xc0, 0x00, 0x00, 0x00,
            0x00, 0x80, 0x01, 0x01, 0x0b, 0x50, 0x00, 0x05, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x00, 0x0e, 0x0c, 0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1,
            0xc2, 0x10, 0x02, 0x11, 0x01,
        ];
        let mut pdu = vec![0x04, 0x04, 0xaf];
        pdu.extend_from_slice(&xid);
        let mut matching = CpGate {
            expected: "SOLNET.SNAB".into(),
            verified: false,
        };
        assert!(!matching.observe(&[0x04, 0x04, 0xaf]).unwrap());
        assert!(!matching.verified);
        assert!(matching.observe(&pdu).unwrap());
        assert!(matching.verified);
        assert!(!matching.observe(&pdu).unwrap());
        let mut wrong = CpGate {
            expected: "SOLNET.SNAA".into(),
            verified: false,
        };
        assert_eq!(
            wrong.observe(&pdu).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!wrong.verified);
        let mut wrong_netid = CpGate {
            expected: "OTHNET.SNAB".into(),
            verified: false,
        };
        let error = wrong_netid.observe(&pdu).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("NETID SOLNET differs from configured OTHNET"));
        assert!(!wrong_netid.verified);
        let mut malformed = pdu;
        malformed[4] = 0x2e; // Declared XID length no longer matches.
        assert_eq!(
            matching.observe(&malformed).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
