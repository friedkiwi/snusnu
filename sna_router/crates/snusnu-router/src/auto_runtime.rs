//! Session-selected routing when a config has no explicit `[[route]]` table.

use crate::{
    auto_address::AutoProxyMacs,
    auto_gateway_runtime::{virtual_cp_for_source, AutoMptnGateway},
    auto_llc::{AutoLlcPort, LlcAutoListener},
    auto_llc_ws::AutoLlcWsBridge,
    config::{self, RouterConfig},
    local_status::LocalProxyMacStatus,
    remote::AutoWsHub,
    routing::{AutomaticFabric, IdentityObservation, PortId, RouteAddress, SessionSide},
    STOP,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ws::wire;

const IDLE_POLL: Duration = Duration::from_micros(200);

struct LlcSession {
    ingress: usize,
    ingress_proxy: [u8; 6],
    egress: Option<(usize, [u8; 6])>,
}

/// Keep automatic mode separate from the explicit pair router. Each selected
/// LLC circuit receives private route ports, while TCP62 converters own their
/// own isolated WebSocket circuit state.
pub(crate) fn run(config: &RouterConfig) -> io::Result<()> {
    let proxies = AutoProxyMacs::from_ids(
        config
            .llc
            .iter()
            .map(|peer| peer.id.as_str())
            .chain(config.mptn_gateway.iter().map(|peer| peer.id.as_str())),
    )?;
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
    run_attachments(config, proxies)
}

fn run_attachments(config: &RouterConfig, proxies: AutoProxyMacs) -> io::Result<()> {
    let mut fabric = AutomaticFabric::new();
    let mut bridge = AutoLlcWsBridge::default();
    for peer in &config.llc {
        let mac = proxies.get(&peer.id).expect("local LLC proxy allocated");
        fabric
            .directory_mut()
            .replace(PortId::new(&peer.id), [RouteAddress::Mac(mac)]);
        bridge.register(
            PortId::new(&peer.id),
            peer.interface.clone(),
            config::parse_mac(&peer.guest_mac)?,
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
    let mut gateways = config
        .mptn_gateway
        .iter()
        .map(AutoMptnGateway::bind)
        .collect::<io::Result<Vec<_>>>()?;
    let remote = config.remote.first();
    let mut hub: Option<AutoWsHub> = None;
    let mut next_connect = Instant::now();
    let mut connect_delay = Duration::from_millis(500);
    let mut remote_macs = HashSet::<[u8; 6]>::new();
    let mut mptn_exports = HashMap::<String, (wire::SnaName, wire::LuReachability)>::new();
    let mut sessions = HashMap::<u64, LlcSession>::new();
    let mut next_id = 0u64;
    tracing::info!(
        llc_attachments = listeners.len(),
        mptn_attachments = gateways.len(),
        concentrator = remote.is_some(),
        "automatic routing started"
    );
    while !STOP.load(Ordering::Relaxed) {
        if hub.is_none() && remote.is_some() && Instant::now() >= next_connect {
            let remote = remote.expect("checked");
            match AutoWsHub::connect(&remote.url, &remote.bearer_token()?, &[], &[]) {
                Ok(mut connected) => {
                    publish_local(&bridge, &mptn_exports, &mut connected)?;
                    fabric
                        .directory_mut()
                        .replace(PortId::new(&remote.id), connected.advertised_addresses());
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
                    // Incoming target selection is installed below once its
                    // local attachment has been observed and reserved.
                    connected.reject_incoming(&open, wire::OpenFailure::Unsupported)?;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "automatic concentrator directory disconnected");
                    hub = None;
                    next_connect = Instant::now() + connect_delay;
                    if let Some(remote) = remote {
                        fabric.directory_mut().withdraw(&PortId::new(&remote.id));
                    }
                }
            }
        }
        if let (Some(connected), Some(remote)) = (hub.as_ref(), remote) {
            let addresses = connected.advertised_addresses();
            let next_macs = addresses
                .iter()
                .filter_map(|address| match address {
                    RouteAddress::Mac(mac) => Some(*mac),
                    _ => None,
                })
                .collect::<HashSet<_>>();
            for mac in remote_macs.difference(&next_macs) {
                for listener in &mut listeners {
                    listener.withdraw_proxy_mac(*mac);
                }
            }
            for mac in next_macs.difference(&remote_macs) {
                for listener in &mut listeners {
                    listener.allow_native_proxy_mac(*mac)?;
                }
            }
            remote_macs = next_macs;
            fabric
                .directory_mut()
                .replace(PortId::new(&remote.id), addresses);
        }
        let mut active = fabric.poll_once()?;
        for closed in fabric.take_closed_sessions() {
            if let Some(session) = sessions.remove(&closed) {
                listeners[session.ingress].release(session.ingress_proxy);
                if let Some((egress, proxy)) = session.egress {
                    listeners[egress].release(proxy);
                }
                if let Some(status) = crate::status() {
                    status.remove_circuit(&format!("auto-{closed}"));
                }
                active = true;
            }
        }
        let mut learned = false;
        for observation in fabric.take_identity_observations() {
            let Some(session) = sessions.get(&observation.session_id) else {
                continue;
            };
            let attachment = match observation.side {
                SessionSide::Ingress => Some(session.ingress),
                SessionSide::Egress => session.egress.map(|(index, _)| index),
            };
            let Some(index) = attachment else { continue };
            let id = PortId::new(&config.llc[index].id);
            let changed = match observation.identity {
                IdentityObservation::ControlPoint(cp) => bridge.observe_cp(&id, &cp)?,
                IdentityObservation::LogicalUnit(lu) => bridge.observe_bound_lu(&id, &lu)?,
            };
            learned |= changed;
        }
        if learned {
            if let Some(connected) = hub.as_mut() {
                publish_local(&bridge, &mptn_exports, connected)?;
            }
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
                Err(error) => {
                    tracing::warn!(ingress = %ingress_id.0, proxy_mac = %crate::endpoint::format_mac(ingress_proxy), error = %error, "automatic LLC destination unresolved");
                    listeners[ingress].release(ingress_proxy);
                    continue;
                }
            };
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
                        ingress,
                        ingress_proxy,
                        egress: Some((egress, egress_proxy)),
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
        for gateway in &mut gateways {
            let Some((association, offer)) = gateway.poll_once()? else {
                continue;
            };
            active = true;
            let result = (|| -> io::Result<()> {
                let (source, destination) = AutoMptnGateway::offer_lus(&offer)?;
                let source = config::parse_cp(&source)?;
                let destination = config::parse_cp(&destination)?;
                let connected = hub.as_mut().ok_or_else(|| {
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
                let (_, target_cp) = connected.resolve_lu(&destination)?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "TCP62 target LU is not advertised")
                })?;
                let target_cp = target_cp.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "TCP62 target LU has no hosting CP")
                })?;
                let seed = format!(
                    "{}:{}",
                    gateway.id(),
                    crate::remote::server_authority(&remote.expect("hub requires remote").url)
                );
                let local_cp = virtual_cp_for_source(&source, seed.as_bytes(), None)?;
                mptn_exports.insert(
                    format!("{}:{}.{}", gateway.id(), source.netid, source.name),
                    (
                        local_cp.clone(),
                        wire::LuReachability {
                            lu: Some(source.clone()),
                            hosting_cp: Some(local_cp.clone()),
                            supported_types: vec![wire::LuType::LuType62 as i32],
                        },
                    ),
                );
                publish_local(&bridge, &mptn_exports, connected)?;
                let ws = connected.open_lu(&destination, &source)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "TCP62 route changed before circuit open",
                    )
                })?;
                gateway.start_to_ws(
                    association,
                    offer,
                    ws,
                    &local_cp,
                    &target_cp,
                    seed.as_bytes(),
                    Duration::from_secs(600),
                )
            })();
            if let Err(error) = result {
                tracing::warn!(gateway = gateway.id(), association, error = %error,
                    "automatic TCP62 session rejected");
                gateway.reject_offer(association, &error.to_string())?;
            }
        }
        if !active {
            thread::sleep(IDLE_POLL);
        }
    }
    for session_id in sessions.keys().copied().collect::<Vec<_>>() {
        fabric.close_pair(session_id)?;
    }
    Ok(())
}

fn publish_local(
    bridge: &AutoLlcWsBridge,
    mptn: &HashMap<String, (wire::SnaName, wire::LuReachability)>,
    hub: &mut AutoWsHub,
) -> io::Result<()> {
    let (mut cps, mut lus) = bridge.advertisements(hub.allowed_netid())?;
    for (cp, lu) in mptn.values() {
        if cp.netid == hub.allowed_netid() {
            cps.push(cp.clone());
            lus.push(lu.clone());
        } else {
            tracing::warn!(local_cp = %format!("{}.{}", cp.netid, cp.name),
                assigned_netid = hub.allowed_netid(),
                "local TCP62 identity excluded from upstream announcement: NETID mismatch");
        }
    }
    hub.publish_local(&cps, &lus)
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
