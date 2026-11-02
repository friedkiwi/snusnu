//! Explicit experimental TCP62 to virtual native WebSocket gateway.
//!
//! The socket adapter handles X'83' UDP expedited and Abort exchanges. This
//! gateway remains opt-in because its native user address is QA-specific.

use crate::{
    config,
    mptn_gateway_port::{GatewayConfig, GatewayEvent, MptnGatewayPort},
    remote::{Config as RemoteConfig, WsRoutePort},
    routing::{FailureScope, RoutePort, RouterEvent},
    virtual_ws_port::VirtualWsPort,
    STOP,
};
use router_core::{
    native_management_initiator::NativeManagementInitiator, xid3::Role, xid3_local::LocalLlcProfile,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::TcpRecord, mptn_compensations::CompensationSet, mptn_ingress::IngressOffer,
    mptn_management_responder::V5Options, mptn_reverse_user_bind::NativeAddress,
};
use transport_ws::wire;

const TIMEOUT: Duration = Duration::from_secs(180);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn node_id(value: &str) -> io::Result<[u8; 4]> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("gateway local_node_id must be eight hex digits"));
    }
    Ok(u32::from_str_radix(value, 16)
        .map_err(|_| invalid("invalid gateway local_node_id"))?
        .to_be_bytes())
}

fn check_shape(config: &config::RouterConfig) -> io::Result<()> {
    if config.mptn_gateway.len() != 1
        || config.remote.len() != 1
        || config.route.len() != 1
        || !config.llc.is_empty()
        || !config.ee.is_empty()
        || !config.anynet.is_empty()
        || !config.hpr_lan.is_empty()
    {
        return Err(invalid(
            "experimental gateway requires one MPTN gateway-profile peer, concentrator and route",
        ));
    }
    Ok(())
}

fn pump_virtual(port: &mut VirtualWsPort<WsRoutePort>) -> io::Result<()> {
    if let Some(events) = port.poll(false)? {
        for event in events {
            match event {
                RouterEvent::Ready => tracing::info!("virtual native LLC link ready"),
                RouterEvent::Closed | RouterEvent::TimedOut => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "virtual WS link closed",
                    ));
                }
                RouterEvent::Unit(_) | RouterEvent::ManagedMac(_) => {
                    return Err(invalid("unexpected virtual gateway route event"));
                }
            }
        }
    }
    for event in port.tick()? {
        if matches!(event, RouterEvent::Closed | RouterEvent::TimedOut) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "virtual WS link closed",
            ));
        }
    }
    port.flush()
}

pub(crate) fn run(path: &Path) -> io::Result<()> {
    let config = config::load(path)?;
    run_config(&config, true)
}

/// Shared gateway runtime entry. Production remains gated while native user
/// addressing is specific to the QA fixture.
pub(crate) fn run_config(config: &config::RouterConfig, experimental: bool) -> io::Result<()> {
    if !experimental {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "production TCP62 gateway requires generalized native user addressing and session lifecycle",
        ));
    }
    if config.mptn_gateway.len() == 1 {
        let routes = config.gateway_routes(&config.mptn_gateway[0].id);
        if routes.len() > 1
            || routes
                .iter()
                .any(|(route, _)| route.destination_lu.is_some())
        {
            return run_multi_target(config);
        }
    }
    check_shape(config)?;
    let gateway = &config.mptn_gateway[0];
    let remote = &config.remote[0];
    let bearer = remote.bearer_token()?;
    let profile = LocalLlcProfile {
        cp_name: gateway.local_cp.clone(),
        station_name: gateway.local_station.clone(),
        node_id: node_id(&gateway.local_node_id)?,
        tg_number: gateway.tg_number,
        max_receive_btu: 1496,
        max_iframes_before_ack: 1,
        role: Role::Secondary,
    };
    let local_xid = profile
        .build()
        .map_err(|error| invalid(format!("local XID3: {error}")))?;
    let source_lu = config::parse_cp(&gateway.source_lu)?;
    let route = RemoteConfig {
        url: remote.url.clone(),
        bearer,
        local_cp: config::parse_cp(&gateway.local_cp)?,
        target_cp: config::parse_cp(&gateway.peer_cp)?,
        target_lu: Some(config::parse_cp(&gateway.destination_lu)?),
    };
    let source = wire::LuReachability {
        lu: Some(source_lu.clone()),
        hosting_cp: Some(route.local_cp.clone()),
        supported_types: vec![wire::LuType::LuType62 as i32],
    };
    let ws = WsRoutePort::connect_gateway_v2(route, vec![source], source_lu)?;
    let mut virtual_port = VirtualWsPort::new(ws, local_xid, &gateway.local_cp, &gateway.peer_cp)?;
    let mut random = [0u8; 14];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut token = [0u8; 7];
    token[0] = 0x23;
    token[1..].copy_from_slice(&random[8..]);
    let management = NativeManagementInitiator::new(
        &gateway.local_cp,
        &gateway.peer_cp,
        0x2f,
        1,
        2,
        random[..8].try_into().expect("eight bytes"),
        token,
        "",
        8,
    )
    .map_err(|error| invalid(format!("native management: {error}")))?;
    virtual_port.attach_management(management)?;
    let required =
        CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).map_err(io::Error::other)?;
    let mut tcp = MptnGatewayPort::bind(GatewayConfig {
        local: SocketAddr::new(gateway.local_ip, 397),
        peer_ip: gateway.peer_ip,
        source_lu: gateway.source_lu.clone(),
        destination_lu: gateway.destination_lu.clone(),
        available_compensations: required,
        options: V5Options {
            son_handler: false,
            keepalive_handler: false,
        },
        cnos_mode: String::new(),
        cnos_limit: 8,
        // Bob may retain prior TCP62 CNOS state. An early user offer is
        // strictly validated and held until native management completes.
        allow_resumed_user: true,
    })?;
    tracing::info!(local_ip=%gateway.local_ip, peer_ip=%gateway.peer_ip, "experimental TCP62 gateway listening");
    let deadline = Instant::now() + TIMEOUT;
    let mut pending_offer: Option<IngressOffer> = None;
    let mut offer_deadline: Option<Instant> = None;
    while !STOP.load(Ordering::Relaxed) && Instant::now() < deadline {
        pump_virtual(&mut virtual_port)?;
        if virtual_port.management_complete() {
            break;
        }
        if let Some(event) = tcp.poll_once(false)? {
            match event {
                GatewayEvent::ManagementReady => {
                    tracing::info!("TCP62 management ready before native management")
                }
                GatewayEvent::UserBind(offer) if pending_offer.is_none() => {
                    pending_offer = Some(offer);
                    offer_deadline = Some(Instant::now() + Duration::from_secs(30));
                    tracing::info!("TCP62 user BIND held until native management is ready");
                }
                GatewayEvent::Rejected(reason) => {
                    return Err(invalid(format!("early TCP62 peer rejected: {reason}")))
                }
                GatewayEvent::Closed => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "early TCP62 peer closed",
                    ))
                }
                _ => {
                    return Err(invalid(
                        "unexpected TCP62 user record before native management",
                    ))
                }
            }
        }
        if offer_deadline.is_some_and(|until| Instant::now() >= until) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "early TCP62 user BIND offer timed out",
            ));
        }
        thread::sleep(Duration::from_micros(200));
    }
    if STOP.load(Ordering::Relaxed) {
        return Ok(());
    }
    if !virtual_port.management_complete() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "native management timed out",
        ));
    }
    tracing::info!(local_cp=%gateway.local_cp, peer_cp=%gateway.peer_cp, "native management ready");
    if let Some(offer) = pending_offer.take() {
        virtual_port.begin_user_bind(
            &offer,
            NativeAddress {
                daf: 2,
                oaf: 2,
                odai: true,
            },
        )?;
        tracing::info!("held TCP62 user BIND offered to virtual native link");
    }
    let mut pending_user_input: Option<TcpRecord> = None;
    let mut pending_udp_input: Option<(u16, Vec<u8>, bool)> = None;
    // The deadline bounds setup only. An established user conversation runs
    // until STOP or a correlated transport/session close.
    while !STOP.load(Ordering::Relaxed) && (tcp.user_active() || Instant::now() < deadline) {
        pump_virtual(&mut virtual_port)?;
        if virtual_port.user_closed() {
            tracing::info!("TCP62 user session closed after native teardown");
            return Ok(());
        }
        if virtual_port.take_expedited_native_completed() {
            tcp.complete_tcp_expedited()?;
        }
        if let Some(sequence) = virtual_port.take_completed_udp_expedited() {
            tcp.complete_udp_expedited(sequence)?;
        }
        if let Some(sequence) = virtual_port.take_completed_udp_abort() {
            tcp.complete_udp_abort(sequence)?;
            tracing::info!(
                sequence,
                "TCP62 UDP Abort completed after native UNBIND response"
            );
            return Ok(());
        }
        if let Some((sequence, reduced, abort)) = pending_udp_input.as_ref() {
            let accepted = if *abort {
                virtual_port.submit_udp_abort(*sequence, reduced)?
            } else {
                virtual_port.submit_udp_expedited(*sequence, reduced)?
            };
            if accepted {
                pending_udp_input = None;
            }
        }
        if let Some(record) = pending_user_input.as_ref() {
            if virtual_port.submit_tcp_user_record(record)? {
                pending_user_input = None;
                tcp.complete_user_record()?;
            }
        }
        if let Some(bytes) = virtual_port.tcp_bind_response().map(ToOwned::to_owned) {
            if tcp.queue_user_bind_response(&bytes)? {
                virtual_port.mark_tcp_bind_response_enqueued(&bytes)?;
                tracing::info!("native user BIND accepted; TCP62 positive queued");
            }
        }
        if let Some(event) = tcp.poll_once(pending_user_input.is_none())? {
            match event {
                GatewayEvent::ManagementReady => tracing::info!("TCP62 management ready"),
                GatewayEvent::UserBind(offer) => {
                    // Observed successful V4 answer-side profile. Only valid
                    // for this explicit QA fixture, not a production address rule.
                    virtual_port.begin_user_bind(
                        &offer,
                        NativeAddress {
                            daf: 2,
                            oaf: 2,
                            odai: true,
                        },
                    )?;
                    tracing::info!("TCP62 user BIND offered to virtual native link");
                }
                GatewayEvent::UserNormal(record)
                | GatewayEvent::UserExpedited(record)
                | GatewayEvent::UserAbort(record) => {
                    if virtual_port.submit_tcp_user_record(&record)? {
                        tcp.complete_user_record()?;
                    } else {
                        pending_user_input = Some(record);
                    }
                }
                GatewayEvent::UserUdpExpedited { sequence, reduced } => {
                    if !virtual_port.submit_udp_expedited(sequence, &reduced)? {
                        pending_udp_input = Some((sequence, reduced, false));
                    }
                }
                GatewayEvent::UserUdpAbort { sequence, reduced } => {
                    if !virtual_port.submit_udp_abort(sequence, &reduced)? {
                        pending_udp_input = Some((sequence, reduced, true));
                    }
                }
                GatewayEvent::OutboundUdpAbortAcknowledged => {
                    virtual_port.complete_udp_abort_response()?;
                    tracing::info!("native UNBIND acknowledged by TCP62 UDP peer");
                }
                GatewayEvent::Closed => {
                    if virtual_port.user_closed() {
                        tracing::info!("TCP62 user session closed after native teardown");
                        return Ok(());
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "TCP62 peer closed",
                    ));
                }
                GatewayEvent::Rejected(reason) => {
                    return Err(invalid(format!("TCP62 peer rejected: {reason}")))
                }
            }
        }
        if tcp.user_active() {
            if let Some(record) = virtual_port.udp_abort_record().cloned() {
                if tcp.queue_udp_abort(&record)? {
                    virtual_port.mark_udp_abort_enqueued(&record)?;
                }
            }
            if let Some(record) = virtual_port.tcp_user_record().cloned() {
                if tcp.queue_user_record(&record)? {
                    virtual_port.mark_tcp_user_record_enqueued(&record)?;
                }
            }
        }
        virtual_port.complete_tcp_user_records(tcp.take_completed_user_records())?;
        thread::sleep(Duration::from_micros(200));
    }
    if STOP.load(Ordering::Relaxed) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "experimental gateway timed out",
        ))
    }
}

struct TargetCircuit {
    destination_lu: String,
    peer_cp: String,
    native: VirtualWsPort<WsRoutePort>,
    association: Option<u64>,
    pending_offer: Option<IngressOffer>,
    pending_since: Option<Instant>,
    pending_tcp: Option<TcpRecord>,
    pending_udp: Option<(u16, Vec<u8>, bool)>,
    needs_rearm: bool,
    retired: bool,
}

fn fresh_native_management(local_cp: &str, peer_cp: &str) -> io::Result<NativeManagementInitiator> {
    let mut random = [0u8; 14];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut token = [0u8; 7];
    token[0] = 0x23;
    token[1..].copy_from_slice(&random[8..]);
    NativeManagementInitiator::new(
        local_cp,
        peer_cp,
        0x2f,
        1,
        2,
        random[..8].try_into().expect("eight bytes"),
        token,
        "",
        8,
    )
    .map_err(|error| invalid(format!("native management: {error}")))
}

fn select_target<'a>(
    source: &str,
    destination: &str,
    expected_source: &str,
    candidates: impl Iterator<Item = (&'a str, bool)>,
) -> Option<usize> {
    if source != expected_source {
        return None;
    }
    candidates
        .enumerate()
        .find_map(|(index, (lu, available))| (lu == destination && available).then_some(index))
}

/// The bounded QA bridge keeps one native circuit for each configured target.
/// A target is busy until its prior native session is fully torn down. Other
/// target circuits continue while that target is busy or closing.
fn run_multi_target(config: &config::RouterConfig) -> io::Result<()> {
    config.validate()?;
    if config.mptn_gateway.len() != 1
        || !config.llc.is_empty()
        || !config.ee.is_empty()
        || !config.anynet.is_empty()
        || !config.hpr_lan.is_empty()
    {
        return Err(invalid(
            "experimental multi-target gateway requires one MPTN listener and concentrator targets",
        ));
    }
    let gateway = &config.mptn_gateway[0];
    let routes = config.gateway_routes(&gateway.id);
    if routes.len() != config.remote.len() || routes.len() != config.route.len() {
        return Err(invalid(
            "experimental multi-target gateway requires one concentrator route per target",
        ));
    }
    let source_lu = config::parse_cp(&gateway.source_lu)?;
    let local_cp = config::parse_cp(&gateway.local_cp)?;
    let profile = LocalLlcProfile {
        cp_name: gateway.local_cp.clone(),
        station_name: gateway.local_station.clone(),
        node_id: node_id(&gateway.local_node_id)?,
        tg_number: gateway.tg_number,
        max_receive_btu: 1496,
        max_iframes_before_ack: 1,
        role: Role::Secondary,
    };
    let local_xid = profile
        .build()
        .map_err(|error| invalid(format!("local XID3: {error}")))?;
    let mut ws_configs = Vec::with_capacity(routes.len());
    let mut destinations = Vec::with_capacity(routes.len());
    for (route, destination) in &routes {
        if route.from != gateway.id
            || !matches!(route.converter, Some(config::RouteConverter::MptnLu62))
            || !route.bidirectional
        {
            return Err(invalid("experimental multi-target gateway requires bidirectional MPTN LU6.2 routes from the listener"));
        }
        let remote = config
            .remote
            .iter()
            .find(|remote| remote.id == route.to)
            .ok_or_else(|| invalid(format!("route {} does not target a concentrator", route.to)))?;
        let target_cp = remote.target_cp.as_deref().unwrap_or(&gateway.peer_cp);
        ws_configs.push(RemoteConfig {
            url: remote.url.clone(),
            bearer: remote.bearer_token()?,
            local_cp: local_cp.clone(),
            target_cp: config::parse_cp(target_cp)?,
            target_lu: Some(config::parse_cp(destination)?),
        });
        destinations.push((*destination).to_owned());
    }
    let export = wire::LuReachability {
        lu: Some(source_lu.clone()),
        hosting_cp: Some(local_cp),
        supported_types: vec![wire::LuType::LuType62 as i32],
    };
    let ws_ports = WsRoutePort::connect_gateway_targets_v2(ws_configs, vec![export], source_lu)?;
    let mut targets = Vec::with_capacity(ws_ports.len());
    for ((ws, destination_lu), (_, route)) in ws_ports.into_iter().zip(destinations).zip(
        routes
            .iter()
            .map(|(route, destination)| (destination, route)),
    ) {
        let remote = config
            .remote
            .iter()
            .find(|remote| remote.id == route.to)
            .expect("validated target");
        let peer_cp = remote.target_cp.as_deref().unwrap_or(&gateway.peer_cp);
        let mut native = VirtualWsPort::new(ws, local_xid.clone(), &gateway.local_cp, peer_cp)?;
        native.attach_management(fresh_native_management(&gateway.local_cp, peer_cp)?)?;
        targets.push(TargetCircuit {
            destination_lu,
            peer_cp: peer_cp.to_owned(),
            native,
            association: None,
            pending_offer: None,
            pending_since: None,
            pending_tcp: None,
            pending_udp: None,
            needs_rearm: false,
            retired: false,
        });
    }
    let required =
        CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).map_err(io::Error::other)?;
    let mut tcp = MptnGatewayPort::bind(GatewayConfig {
        local: SocketAddr::new(gateway.local_ip, 397),
        peer_ip: gateway.peer_ip,
        source_lu: gateway.source_lu.clone(),
        destination_lu: gateway.destination_lu.clone(),
        available_compensations: required,
        options: V5Options {
            son_handler: false,
            keepalive_handler: false,
        },
        cnos_mode: String::new(),
        cnos_limit: 8,
        allow_resumed_user: true,
    })?;
    for target in &targets {
        tcp.allow_route(gateway.source_lu.clone(), target.destination_lu.clone())?;
    }
    tracing::info!(local_ip=%gateway.local_ip, peer_ip=%gateway.peer_ip, targets=targets.len(), "experimental multi-target TCP62 gateway listening");
    let mut owners = HashMap::<u64, usize>::new();
    while !STOP.load(Ordering::Relaxed) {
        for (index, target) in targets.iter_mut().enumerate() {
            if target.retired {
                continue;
            }
            if target.needs_rearm {
                match target
                    .native
                    .rearm_management(fresh_native_management(&gateway.local_cp, &target.peer_cp)?)
                {
                    Ok(()) => {
                        target.needs_rearm = false;
                        tracing::info!(target=index, destination_lu=%target.destination_lu, "native target circuit rearmed");
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => {
                        target.retired = true;
                        tracing::warn!(target=index, destination_lu=%target.destination_lu, error=%error, "native target could not be rearmed");
                        continue;
                    }
                }
            }
            if let Err(error) = pump_virtual(&mut target.native) {
                if target.native.failure_scope(&error) == FailureScope::SharedTransport {
                    return Err(error);
                }
                if let Some(id) = target.association.take() {
                    let _ = tcp.close_association_for(id);
                    owners.remove(&id);
                }
                target.retired = true;
                tracing::warn!(target=index, destination_lu=%target.destination_lu, error=%error, "native target circuit failed");
            }
        }
        for (index, target) in targets.iter_mut().enumerate() {
            let Some(id) = target.association else {
                continue;
            };
            if target
                .pending_since
                .is_some_and(|since| since.elapsed() > Duration::from_secs(30))
            {
                tcp.close_association_for(id)?;
                owners.remove(&id);
                target.association = None;
                target.pending_offer = None;
                target.pending_since = None;
                tracing::warn!(
                    association = id,
                    target = index,
                    "native management not ready for TCP62 BIND"
                );
                continue;
            }
            if target.pending_offer.is_some() && target.native.management_complete() {
                let offer = target.pending_offer.take().expect("checked");
                target.pending_since = None;
                target.native.begin_user_bind(
                    &offer,
                    NativeAddress {
                        daf: 2,
                        oaf: 2,
                        odai: true,
                    },
                )?;
                tracing::info!(association=id, destination_lu=%target.destination_lu, "TCP62 user BIND offered to native circuit");
            }
            if target.native.user_closed() {
                tcp.close_association_for(id)?;
                owners.remove(&id);
                target.association = None;
                target.pending_tcp = None;
                target.pending_udp = None;
                target.needs_rearm = true;
                tracing::info!(
                    association = id,
                    target = index,
                    "TCP62 target session closed; native circuit will rearm"
                );
                continue;
            }
            if target.native.take_expedited_native_completed() {
                tcp.complete_tcp_expedited_for(id)?;
            }
            if let Some(sequence) = target.native.take_completed_udp_expedited() {
                tcp.complete_udp_expedited_for(id, sequence)?;
            }
            if let Some(sequence) = target.native.take_completed_udp_abort() {
                tcp.complete_udp_abort_for(id, sequence)?;
            }
            if let Some((sequence, reduced, abort)) = target.pending_udp.as_ref() {
                let accepted = if *abort {
                    target.native.submit_udp_abort(*sequence, reduced)?
                } else {
                    target.native.submit_udp_expedited(*sequence, reduced)?
                };
                if accepted {
                    target.pending_udp = None;
                }
            }
            if let Some(record) = target.pending_tcp.as_ref() {
                if target.native.submit_tcp_user_record(record)? {
                    target.pending_tcp = None;
                    tcp.complete_user_record_for(id)?;
                }
            }
            if let Some(bytes) = target.native.tcp_bind_response().map(ToOwned::to_owned) {
                if tcp.queue_user_bind_response_for(id, &bytes)? {
                    target.native.mark_tcp_bind_response_enqueued(&bytes)?;
                }
            }
            if tcp.user_active_for(id) {
                if let Some(record) = target.native.udp_abort_record().cloned() {
                    if tcp.queue_udp_abort_for(id, &record)? {
                        target.native.mark_udp_abort_enqueued(&record)?;
                    }
                }
                if let Some(record) = target.native.tcp_user_record().cloned() {
                    if tcp.queue_user_record_for(id, &record)? {
                        target.native.mark_tcp_user_record_enqueued(&record)?;
                    }
                }
            }
            target
                .native
                .complete_tcp_user_records(tcp.take_completed_user_records_for(id))?;
        }
        if let Some((id, event)) = tcp.poll_association_once_with_credit(|id| {
            owners.get(&id).is_none_or(|index| {
                targets[*index].pending_tcp.is_none() && targets[*index].pending_udp.is_none()
            })
        })? {
            let udp_abort = matches!(&event, GatewayEvent::UserUdpAbort { .. });
            let rejection = match &event {
                GatewayEvent::Rejected(reason) => Some(reason.clone()),
                _ => None,
            };
            match event {
                GatewayEvent::ManagementReady => {
                    tracing::info!(association = id, "TCP62 management ready")
                }
                GatewayEvent::UserBind(offer) => {
                    let destination = offer.connect().destination.qualified_lu()?;
                    let source = offer.connect().source.qualified_lu()?;
                    let selected = select_target(
                        &source,
                        &destination,
                        &gateway.source_lu,
                        targets.iter().map(|target| {
                            (
                                target.destination_lu.as_str(),
                                target.association.is_none()
                                    && !target.retired
                                    && !target.needs_rearm,
                            )
                        }),
                    );
                    match selected {
                        Some(index) => {
                            targets[index].association = Some(id);
                            targets[index].pending_offer = Some(offer);
                            targets[index].pending_since = Some(Instant::now());
                            owners.insert(id, index);
                            tracing::info!(association=id, source_lu=%source, destination_lu=%destination, target=index, "TCP62 route selected");
                        }
                        _ => {
                            tcp.close_association_for(id)?;
                            tracing::warn!(association=id, source_lu=%source, destination_lu=%destination, "TCP62 target unavailable or not configured");
                        }
                    }
                }
                GatewayEvent::UserNormal(record)
                | GatewayEvent::UserExpedited(record)
                | GatewayEvent::UserAbort(record) => {
                    let index = *owners
                        .get(&id)
                        .ok_or_else(|| invalid("TCP62 user record without route owner"))?;
                    let target = &mut targets[index];
                    if target.native.submit_tcp_user_record(&record)? {
                        tcp.complete_user_record_for(id)?;
                    } else {
                        target.pending_tcp = Some(record);
                    }
                }
                GatewayEvent::UserUdpExpedited { sequence, reduced }
                | GatewayEvent::UserUdpAbort { sequence, reduced } => {
                    let index = *owners
                        .get(&id)
                        .ok_or_else(|| invalid("TCP62 UDP record without route owner"))?;
                    let target = &mut targets[index];
                    let accepted = if udp_abort {
                        target.native.submit_udp_abort(sequence, &reduced)?
                    } else {
                        target.native.submit_udp_expedited(sequence, &reduced)?
                    };
                    if !accepted {
                        target.pending_udp = Some((sequence, reduced, udp_abort));
                    }
                }
                GatewayEvent::OutboundUdpAbortAcknowledged => {
                    let index = *owners
                        .get(&id)
                        .ok_or_else(|| invalid("TCP62 abort ACK without route owner"))?;
                    targets[index].native.complete_udp_abort_response()?;
                }
                GatewayEvent::Closed | GatewayEvent::Rejected(_) => {
                    if let Some(reason) = rejection.as_deref() {
                        tracing::warn!(association = id, reason, "TCP62 association rejected");
                    }
                    if let Some(index) = owners.remove(&id) {
                        let target = &mut targets[index];
                        target.association = None;
                        target.pending_offer = None;
                        target.pending_since = None;
                        target.pending_tcp = None;
                        target.pending_udp = None;
                        match target.native.disconnect() {
                            Ok(()) => {
                                target.needs_rearm = true;
                                tracing::info!(
                                    association = id,
                                    target = index,
                                    "TCP62 association ended; native circuit will rearm"
                                );
                            }
                            Err(error) => {
                                target.retired = true;
                                tracing::warn!(association = id, target = index, error=%error, "native circuit disconnect failed");
                            }
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_micros(200));
    }
    Ok(())
}

#[cfg(test)]
mod multi_target_tests {
    use super::select_target;

    #[test]
    fn connect_selects_exact_lu_and_only_an_idle_target() {
        let candidates = [("SNAA.LUA", true), ("SNAB.LUB", false), ("SNAC.LUC", true)];
        let choose = |source, destination| {
            select_target(source, destination, "QABOB.LUB", candidates.iter().copied())
        };
        assert_eq!(choose("QABOB.LUB", "SNAC.LUC"), Some(2));
        assert_eq!(choose("QABOB.LUB", "SNAB.LUB"), None);
        assert_eq!(choose("QABOB.LUB", "SNAD.LUD"), None);
        assert_eq!(choose("OTHER.LUB", "SNAA.LUA"), None);
    }
}
