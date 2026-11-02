//! Session-selected routing when a config has no explicit `[[route]]` table.

use crate::{
    auto_address::AutoProxyMacs,
    auto_gateway_runtime::{virtual_cp_for_source, AutoMptnGateway},
    auto_llc::{AutoLlcPort, LlcAutoListener},
    auto_llc_ws::AutoLlcWsBridge,
    auto_local_dispatch::AutoLocalDispatch,
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
    ingress: Option<(usize, [u8; 6])>,
    egress: Option<(usize, [u8; 6])>,
    upstream: bool,
}

/// Keep automatic mode separate from the explicit pair router. Each selected
/// LLC circuit receives private route ports, while TCP62 converters own their
/// own isolated WebSocket circuit state.
pub(crate) fn run(config: &RouterConfig) -> io::Result<()> {
    if !config.ee.is_empty() {
        return crate::auto_hpr_runtime::run_hpr(config);
    }
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
    for gateway in &config.mptn_gateway {
        fabric.directory_mut().replace(
            PortId::new(&gateway.id),
            [RouteAddress::Mac(
                proxies.get(&gateway.id).expect("MPTN proxy allocated"),
            )],
        );
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
    let mut mptn_owner = HashMap::<(String, String), String>::new();
    let mut learned_mptn_lus = HashMap::<String, HashSet<(String, String)>>::new();
    let mut local_dispatch = AutoLocalDispatch::new();
    let mut sessions = HashMap::<u64, LlcSession>::new();
    let mut next_id = 0u64;
    tracing::info!(
        llc_attachments = listeners.len(),
        mptn_attachments = gateways.len(),
        concentrator = remote.is_some(),
        "automatic routing started"
    );
    while !STOP.load(Ordering::Relaxed) {
        if let Some(remote) = remote.filter(|_| hub.is_none() && Instant::now() >= next_connect) {
            match AutoWsHub::connect(&remote.url, &remote.bearer_token()?, &[], &[]) {
                Ok(mut connected) => {
                    mptn_exports.clear();
                    mptn_owner.clear();
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
                Ok(Some(open)) => match incoming_lu_pair(connected, &open) {
                    Ok((hosted_lu, hosted_cp, source_lu, source_cp)) => {
                        let owner =
                            mptn_owner.get(&(hosted_lu.netid.clone(), hosted_lu.name.clone()));
                        let gateway = owner
                            .and_then(|id| gateways.iter_mut().find(|gateway| gateway.id() == id));
                        if let Some(gateway) = gateway.filter(|gateway| gateway.udp_available()) {
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
                                None => connected
                                    .reject_incoming(&open, wire::OpenFailure::RouteGone)?,
                            }
                        } else if owner.is_some() {
                            connected.reject_incoming(&open, wire::OpenFailure::Busy)?;
                        } else if let Some(remote) = remote {
                            if let Err(error) = open_incoming_llc(
                                &bridge,
                                connected,
                                open.clone(),
                                remote,
                                config,
                                &mut listeners,
                                &mut fabric,
                                &mut sessions,
                                &mut next_id,
                            ) {
                                tracing::warn!(error = %error,
                                    "automatic concentrator to LLC session rejected");
                                connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?;
                            }
                        } else {
                            connected.reject_incoming(&open, wire::OpenFailure::RouteGone)?;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "automatic incoming SNA session has no TCP62 destination");
                        connected.reject_incoming(&open, wire::OpenFailure::Unsupported)?;
                    }
                },
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "automatic concentrator directory disconnected");
                    retire_upstream_pairs(&mut fabric, &mut sessions, &mut listeners)?;
                    hub = None;
                    next_connect = Instant::now() + connect_delay;
                    if let Some(remote) = remote {
                        fabric.directory_mut().withdraw(&PortId::new(&remote.id));
                    }
                    for mac in remote_macs.drain() {
                        for listener in &mut listeners {
                            listener.withdraw_proxy_mac(mac);
                        }
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
        let mut active = match fabric.poll_once() {
            Ok(active) => active,
            Err(error) if remote.is_some() => {
                tracing::warn!(error = %error,
                    "automatic upstream circuit failed; retaining local routes");
                retire_upstream_pairs(&mut fabric, &mut sessions, &mut listeners)?;
                hub = None;
                next_connect = Instant::now() + connect_delay;
                if let Some(remote) = remote {
                    fabric.directory_mut().withdraw(&PortId::new(&remote.id));
                }
                for mac in remote_macs.drain() {
                    for listener in &mut listeners {
                        listener.withdraw_proxy_mac(mac);
                    }
                }
                true
            }
            Err(error) => return Err(error),
        };
        for closed in fabric.take_closed_sessions() {
            if let Some(session) = sessions.remove(&closed) {
                if let Some((ingress, proxy)) = session.ingress {
                    listeners[ingress].release(proxy);
                }
                if let Some((egress, proxy)) = session.egress {
                    listeners[egress].release(proxy);
                }
                if let Some(status) = crate::status() {
                    status.remove_circuit(&format!("auto-{closed}"));
                }
                active = true;
            }
        }
        for completed in local_dispatch.poll_completed() {
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
        let mut learned = false;
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
            let changed = match observation.identity {
                IdentityObservation::ControlPoint(cp) => bridge.observe_cp(&id, &cp)?,
                IdentityObservation::LogicalUnit(lu) => bridge.observe_bound_lu(&id, &lu)?,
            };
            learned |= changed;
        }
        if learned {
            refresh_local_addresses(&mut fabric, &bridge, config, &proxies);
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
            if let Some(gateway) = gateways.iter_mut().find(|gateway| gateway.id() == target.0) {
                if let Some(cp) = &offer.peer_cp {
                    if bridge.observe_cp(&ingress_id, cp)? {
                        refresh_local_addresses(&mut fabric, &bridge, config, &proxies);
                        if let Some(connected) = hub.as_mut() {
                            publish_local(&bridge, &mptn_exports, connected)?;
                        }
                    }
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
                if let Err(error) = result {
                    listeners[ingress].release(ingress_proxy);
                    tracing::warn!(ingress = %ingress_id.0, gateway = gateway.id(),
                        error = %error, "automatic LLC to TCP62 session rejected");
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
        for gateway in &mut gateways {
            let offered = gateway.poll_once()?;
            for (source, destination) in gateway.take_management_lus() {
                let source = config::parse_cp(&source)?;
                let destination = config::parse_cp(&destination)?;
                tracing::info!(gateway = gateway.id(),
                    source_lu = %format!("{}.{}", source.netid, source.name),
                    destination_lu = %format!("{}.{}", destination.netid, destination.name),
                    "TCP62 management disclosed local LU reachability");
                learned_mptn_lus
                    .entry(gateway.id().into())
                    .or_default()
                    .insert((source.netid, source.name));
            }
            for attachment in gateway.take_closed_local_attachments() {
                if let Some(index) = config.llc.iter().position(|peer| peer.id == attachment) {
                    listeners[index]
                        .release(proxies.get(gateway.id()).expect("gateway proxy allocated"));
                }
            }
            let mut learned_local = false;
            for (attachment, identity) in gateway.take_identity_observations() {
                let id = PortId::new(attachment);
                learned_local |= match identity {
                    IdentityObservation::ControlPoint(cp) => bridge.observe_cp(&id, &cp)?,
                    IdentityObservation::LogicalUnit(lu) => bridge.observe_bound_lu(&id, &lu)?,
                };
            }
            if learned_local {
                refresh_local_addresses(&mut fabric, &bridge, config, &proxies);
                if let Some(connected) = hub.as_mut() {
                    publish_local(&bridge, &mptn_exports, connected)?;
                }
            }
            let Some((association, offer)) = offered else {
                continue;
            };
            active = true;
            let result = (|| -> io::Result<()> {
                let (source, destination) = AutoMptnGateway::offer_lus(&offer)?;
                let source = config::parse_cp(&source)?;
                let destination = config::parse_cp(&destination)?;
                learned_mptn_lus
                    .entry(gateway.id().into())
                    .or_default()
                    .insert((source.netid.clone(), source.name.clone()));
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
                let seed = format!("{}:{}.{}", gateway.id(), source.netid, source.name);
                let local_cp = gateway
                    .configured_local_cp()?
                    .map(Ok)
                    .unwrap_or_else(|| virtual_cp_for_source(&source, seed.as_bytes(), None))?;
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
                mptn_owner.insert(
                    (source.netid.clone(), source.name.clone()),
                    gateway.id().into(),
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
        if let Some(connected) = hub.as_mut() {
            if refresh_mptn_exports(
                config,
                &learned_mptn_lus,
                connected,
                &mut mptn_exports,
                &mut mptn_owner,
            )? {
                publish_local(&bridge, &mptn_exports, connected)?;
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

fn refresh_mptn_exports(
    config: &RouterConfig,
    learned: &HashMap<String, HashSet<(String, String)>>,
    hub: &AutoWsHub,
    exports: &mut HashMap<String, (wire::SnaName, wire::LuReachability)>,
    owner: &mut HashMap<(String, String), String>,
) -> io::Result<bool> {
    let mut changed = false;
    for (gateway_id, lus) in learned {
        for (netid, name) in lus {
            if netid != hub.allowed_netid() {
                tracing::warn!(gateway = gateway_id, source_lu = %format!("{netid}.{name}"),
                    assigned_netid = hub.allowed_netid(),
                    "learned TCP62 LU excluded from upstream announcement: NETID mismatch");
                continue;
            }
            let key = format!("{gateway_id}:{netid}.{name}");
            if exports.contains_key(&key) {
                continue;
            }
            if let Some(previous) = owner.get(&(netid.clone(), name.clone())) {
                if previous != gateway_id {
                    tracing::warn!(source_lu = %format!("{netid}.{name}"),
                        first_gateway = previous, second_gateway = gateway_id,
                        "ambiguous learned TCP62 LU; second route excluded");
                    continue;
                }
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
            exports.insert(
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
            owner.insert((netid.clone(), name.clone()), gateway_id.clone());
            changed = true;
        }
    }
    Ok(changed)
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

fn refresh_local_addresses(
    fabric: &mut AutomaticFabric,
    bridge: &AutoLlcWsBridge,
    config: &RouterConfig,
    proxies: &AutoProxyMacs,
) {
    for peer in &config.llc {
        let id = PortId::new(&peer.id);
        let mut addresses = vec![RouteAddress::Mac(
            proxies.get(&peer.id).expect("LLC proxy allocated"),
        )];
        addresses.extend(bridge.local_addresses(&id));
        fabric.directory_mut().replace(id, addresses);
    }
}

fn retire_upstream_pairs(
    fabric: &mut AutomaticFabric,
    sessions: &mut HashMap<u64, LlcSession>,
    listeners: &mut [LlcAutoListener],
) -> io::Result<()> {
    let upstream = sessions
        .iter()
        .filter_map(|(id, session)| session.upstream.then_some(*id))
        .collect::<Vec<_>>();
    for id in upstream {
        fabric.abort_pair(id)?;
        if let Some(session) = sessions.remove(&id) {
            if let Some((index, mac)) = session.ingress {
                listeners[index].release(mac);
            }
            if let Some((index, mac)) = session.egress {
                listeners[index].release(mac);
            }
        }
        if let Some(status) = crate::status() {
            status.remove_circuit(&format!("auto-{id}"));
        }
    }
    Ok(())
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
