//! One configured MPTN gateway with initiation from either local TCP62 or
//! an authenticated concentrator circuit. Each direction owns private
//! circuit credit; the WebSocket and UDP/397 publication are shared.

use crate::{
    config::{self, BidirectionalGatewayConfig},
    mptn_gateway_port::{GatewayConfig, GatewayEvent, MptnGatewayPort},
    mptn_ws_reverse,
    remote::WsRoutePort,
    routing::{RoutePort, RouterEvent},
    virtual_ws_port::VirtualWsPort,
    ws_native_responder::WsNativeResponder,
    STOP,
};
use router_core::{
    native_management_initiator::NativeManagementInitiator, xid3::Role, xid3_local::LocalLlcProfile,
};
use std::{
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::TcpRecord, mptn_compensations::CompensationSet, mptn_ingress::IngressOffer,
    mptn_management_responder::V5Options, mptn_reverse_user_bind::NativeAddress,
};
use transport_ws::wire;

const IDLE_POLL: Duration = Duration::from_micros(200);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn fresh_management(
    local_cp: &str,
    peer_cp: &str,
) -> io::Result<NativeManagementInitiator> {
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
        random[..8].try_into().expect("eight random bytes"),
        token,
        "",
        8,
    )
    .map_err(|error| invalid(format!("native management: {error}")))
}

pub(crate) fn pump_virtual<P: RoutePort>(port: &mut VirtualWsPort<P>) -> io::Result<()> {
    if let Some(events) = port.poll(false)? {
        for event in events {
            match event {
                RouterEvent::Ready => {}
                RouterEvent::Closed | RouterEvent::TimedOut => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "native WebSocket circuit closed",
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
                "native WebSocket circuit closed",
            ));
        }
    }
    port.flush()
}

pub(crate) fn run_mptn_initiated(
    listener: &mut MptnGatewayPort,
    association: u64,
    offer: IngressOffer,
    mut virtual_port: VirtualWsPort<WsRoutePort>,
    setup_deadline: Instant,
) -> io::Result<()> {
    let mut pending_offer = Some(offer);
    let mut pending_tcp: Option<TcpRecord> = None;
    let mut pending_udp: Option<(u16, Vec<u8>, bool)> = None;
    let mut user_started = false;
    loop {
        if STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        if !user_started && Instant::now() >= setup_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native gateway setup timed out",
            ));
        }
        pump_virtual(&mut virtual_port)?;
        if virtual_port.management_complete() {
            if let Some(offer) = pending_offer.take() {
                // The first user address follows the management address on
                // this virtual FID2 link. Address allocation must become
                // per-circuit before concurrent sessions use this adapter.
                virtual_port.begin_user_bind(
                    &offer,
                    NativeAddress {
                        daf: 2,
                        oaf: 2,
                        odai: true,
                    },
                )?;
            }
        }
        if virtual_port.user_closed() {
            return Ok(());
        }
        if virtual_port.take_expedited_native_completed() {
            listener.complete_tcp_expedited_for(association)?;
        }
        if let Some(sequence) = virtual_port.take_completed_udp_expedited() {
            listener.complete_udp_expedited_for(association, sequence)?;
        }
        if let Some(sequence) = virtual_port.take_completed_udp_abort() {
            listener.complete_udp_abort_for(association, sequence)?;
            return Ok(());
        }
        if let Some((sequence, reduced, abort)) = pending_udp.as_ref() {
            let accepted = if *abort {
                virtual_port.submit_udp_abort(*sequence, reduced)?
            } else {
                virtual_port.submit_udp_expedited(*sequence, reduced)?
            };
            if accepted {
                pending_udp = None;
            }
        }
        if let Some(record) = pending_tcp.as_ref() {
            if virtual_port.submit_tcp_user_record(record)? {
                pending_tcp = None;
                listener.complete_user_record_for(association)?;
            }
        }
        if let Some(bytes) = virtual_port.tcp_bind_response().map(ToOwned::to_owned) {
            if listener.queue_user_bind_response_for(association, &bytes)? {
                virtual_port.mark_tcp_bind_response_enqueued(&bytes)?;
            }
        }
        if let Some((id, event)) = listener.poll_association_once_with_credit(|id| {
            id != association || (pending_tcp.is_none() && pending_udp.is_none())
        })? {
            if id != association {
                if matches!(event, GatewayEvent::UserBind(_)) {
                    listener.close_association_for(id)?;
                }
            } else {
                match event {
                    GatewayEvent::ManagementReady => {}
                    GatewayEvent::UserBind(_) => return Err(invalid("duplicate TCP62 user BIND")),
                    GatewayEvent::UserNormal(record)
                    | GatewayEvent::UserExpedited(record)
                    | GatewayEvent::UserAbort(record) => {
                        if virtual_port.submit_tcp_user_record(&record)? {
                            listener.complete_user_record_for(id)?;
                        } else {
                            pending_tcp = Some(record);
                        }
                    }
                    GatewayEvent::UserUdpExpedited { sequence, reduced } => {
                        if !virtual_port.submit_udp_expedited(sequence, &reduced)? {
                            pending_udp = Some((sequence, reduced, false));
                        }
                    }
                    GatewayEvent::UserUdpAbort { sequence, reduced } => {
                        if !virtual_port.submit_udp_abort(sequence, &reduced)? {
                            pending_udp = Some((sequence, reduced, true));
                        }
                    }
                    GatewayEvent::OutboundUdpAbortAcknowledged => {
                        virtual_port.complete_udp_abort_response()?
                    }
                    GatewayEvent::Closed => return Ok(()),
                    GatewayEvent::Rejected(reason) => {
                        return Err(invalid(format!("TCP62 peer rejected: {reason}")))
                    }
                }
            }
        }
        user_started |= listener.user_active_for(association);
        if user_started {
            if let Some(record) = virtual_port.udp_abort_record().cloned() {
                if listener.queue_udp_abort_for(association, &record)? {
                    virtual_port.mark_udp_abort_enqueued(&record)?;
                }
            }
            if let Some(record) = virtual_port.tcp_user_record().cloned() {
                if listener.queue_user_record_for(association, &record)? {
                    virtual_port.mark_tcp_user_record_enqueued(&record)?;
                }
            }
        }
        virtual_port
            .complete_tcp_user_records(listener.take_completed_user_records_for(association))?;
        thread::sleep(IDLE_POLL);
    }
}

/// Serve one session from either side, then return so the caller can create
/// a fresh pair of circuit ports on the same configured route.
pub(crate) fn run_once(config: &BidirectionalGatewayConfig<'_>) -> io::Result<()> {
    config.reverse.validate()?;
    let gateway = config.gateway;
    let reverse = &config.reverse;
    let hosted = config::parse_cp(&gateway.source_lu)?;
    let export = wire::LuReachability {
        lu: Some(hosted.clone()),
        hosting_cp: Some(config::parse_cp(&gateway.local_cp)?),
        supported_types: vec![wire::LuType::LuType62 as i32],
    };
    let (outbound_port, inbound_port) =
        WsRoutePort::connect_gateway_duplex_v2(reverse.remote.clone(), vec![export], hosted)?;
    let mut responder = WsNativeResponder::new(
        inbound_port,
        LocalLlcProfile {
            cp_name: gateway.local_cp.clone(),
            station_name: gateway.local_station.clone(),
            node_id: u32::from_str_radix(&gateway.local_node_id, 16)
                .map_err(|_| invalid("invalid gateway node ID"))?
                .to_be_bytes(),
            tg_number: gateway.tg_number,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: Role::Secondary,
        }
        .build()
        .map_err(|error| invalid(format!("local XID3: {error}")))?,
        &gateway.local_cp,
        &gateway.peer_cp,
        &gateway.destination_lu,
        &gateway.source_lu,
    )?;
    let required =
        CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).map_err(io::Error::other)?;
    let mut listener = MptnGatewayPort::bind(GatewayConfig {
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
    listener.set_expected_peer_cp(gateway.local_cp.clone());
    tracing::info!(
        local_ip=%gateway.local_ip, peer_ip=%gateway.peer_ip,
        source_lu=%gateway.source_lu, target_lu=%gateway.destination_lu,
        "duplex MPTN gateway listening"
    );
    loop {
        if STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        if let Some(open) = responder.poll_inbound_open_once()? {
            return mptn_ws_reverse::run_from_open(
                reverse,
                responder,
                listener.clone_udp_socket()?,
                open,
                Instant::now() + reverse.timeout,
            )
            .map_err(session_error);
        }
        if let Some((id, event)) = listener.poll_association_once(false)? {
            match event {
                GatewayEvent::UserBind(offer) => {
                    let xid = LocalLlcProfile {
                        cp_name: gateway.local_cp.clone(),
                        station_name: gateway.local_station.clone(),
                        node_id: u32::from_str_radix(&gateway.local_node_id, 16)
                            .map_err(|_| invalid("invalid gateway node ID"))?
                            .to_be_bytes(),
                        tg_number: gateway.tg_number,
                        max_receive_btu: 1496,
                        max_iframes_before_ack: 1,
                        role: Role::Secondary,
                    }
                    .build()
                    .map_err(|error| invalid(format!("local XID3: {error}")))?;
                    let mut virtual_port = VirtualWsPort::new(
                        outbound_port,
                        xid,
                        &gateway.local_cp,
                        &gateway.peer_cp,
                    )?;
                    virtual_port.attach_management(fresh_management(
                        &gateway.local_cp,
                        &gateway.peer_cp,
                    )?)?;
                    tracing::info!(association = id, "TCP62 peer initiated duplex session");
                    return run_mptn_initiated(
                        &mut listener,
                        id,
                        offer,
                        virtual_port,
                        Instant::now() + reverse.timeout,
                    )
                    .map_err(session_error);
                }
                GatewayEvent::ManagementReady | GatewayEvent::Closed => {}
                GatewayEvent::Rejected(reason) => {
                    tracing::warn!(association = id, reason, "TCP62 association rejected")
                }
                _ => {
                    listener.close_association_for(id)?;
                }
            }
        }
        thread::sleep(IDLE_POLL);
    }
}

fn session_error(error: io::Error) -> io::Error {
    // Peer protocol failures affect this circuit. Recreate its WebSocket and
    // TCP62 state so a subsequent contact can still use the configured route.
    if error.kind() == io::ErrorKind::InvalidData {
        io::Error::new(io::ErrorKind::ConnectionAborted, error)
    } else {
        error
    }
}
