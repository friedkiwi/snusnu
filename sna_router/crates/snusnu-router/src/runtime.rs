//! LLC adapter and local route configuration.

use crate::{
    config::{self, RouterConfig},
    endpoint::{format_mac, Endpoint, EndpointRegistry, Event},
    ip_ports::EePort,
    remote::{Config as RemoteConfig, WsRoutePort},
    routing::{PortId, RouteAddress, RoutePort, RoutedUnit, Router, RouterEvent},
};
use router_core::llc2::State;
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
}

impl LlcPort {
    pub(crate) fn open(peer: LlcPeer<'_>) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?,
            registry: None,
        })
    }

    fn open_registered(
        peer: LlcPeer<'_>,
        registry: Rc<RefCell<EndpointRegistry>>,
    ) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?,
            registry: Some(registry),
        })
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
        self.endpoint
            .poll(can_accept_information)
            .map(|events| events.map(|events| events.into_iter().map(map_event).collect()))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.endpoint
            .tick()
            .map(|events| events.into_iter().map(map_event).collect())
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
        if self.endpoint.state() == State::Disconnected {
            self.endpoint.begin_connect_after(CONNECT_BARRIER);
        }
        Ok(())
    }

    fn on_managed_mac(&mut self, mac: [u8; 6]) -> io::Result<()> {
        if let Some(registry) = &self.registry {
            registry
                .borrow_mut()
                .apply_managed_proxy_mac(&mut self.endpoint, mac)
        } else {
            self.endpoint.set_managed_proxy_mac(mac)
        }
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.endpoint.disconnect()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.endpoint.flush()
    }
}

/// Start all configured local associations and the optional remote hop. The
/// route table is checked before any raw socket is opened, so a typo cannot
/// leave a partially attached router running.
pub(crate) fn run_config(config: &RouterConfig) -> io::Result<()> {
    config.validate()?;
    const FIRST_RETRY: Duration = Duration::from_millis(500);
    const MAX_RETRY: Duration = Duration::from_secs(30);
    let mut delay = FIRST_RETRY;
    while !crate::STOP.load(Ordering::Relaxed) {
        let remote_ports = if let Some(remote) = config.remote.first() {
            let bearer = std::env::var("SNUSNU_ROUTER_TOKEN").map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SNUSNU_ROUTER_TOKEN is required",
                )
            })?;
            let options = config
                .remote
                .iter()
                .map(|entry| {
                    Ok(RemoteConfig {
                        url: entry.url.clone(),
                        bearer: bearer.clone(),
                        local_cp: config::parse_cp(&entry.local_cp)?,
                        target_cp: config::parse_cp(&entry.target_cp)?,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            let logical_units = config
                .remote
                .iter()
                .flat_map(|entry| {
                    entry.lus.iter().map(|name| {
                        Ok(transport_ws::wire::LuReachability {
                            lu: Some(config::parse_cp(name)?),
                            hosting_cp: Some(config::parse_cp(&entry.local_cp)?),
                        })
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            match WsRoutePort::connect_many(options, logical_units) {
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
        let mut registry = EndpointRegistry::default();
        for peer in &config.llc {
            registry.register(
                &peer.interface,
                config::parse_mac(&peer.guest_mac)?,
                config::parse_mac(&peer.proxy_mac)?,
            )?;
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
                        proxy_mac: config::parse_mac(&peer.proxy_mac)?,
                    },
                    registry.clone(),
                )?),
            )?;
        }
        for peer in &config.ee {
            router.register_port(
                PortId::new(&peer.id),
                Box::new(EePort::open(peer.local_ip, peer.peer_ip)?),
            )?;
        }
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

fn install_config_route(
    router: &mut Router,
    config: &RouterConfig,
    source: &PortId,
    target: &PortId,
) -> io::Result<()> {
    let address = if let Some(peer) = config.llc.iter().find(|peer| peer.id == source.0) {
        Some(RouteAddress::Mac(config::parse_mac(&peer.proxy_mac)?))
    } else if let Some(remote) = config.remote.iter().find(|remote| remote.id == source.0) {
        let cp = config::parse_cp(&remote.local_cp)?;
        Some(RouteAddress::ControlPoint {
            netid: cp.netid,
            name: cp.name,
        })
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
    }

    #[test]
    fn upstream_log_field_omits_url_credentials_and_query() {
        assert_eq!(
            upstream_authority("wss://hidden@example.org:443/router/v1/ws?token=secret"),
            "example.org:443"
        );
    }
}
