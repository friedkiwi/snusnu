//! One concentrator-initiated native circuit to a local MPTN peer.
//!
//! Setup is bounded; an established user circuit runs until peer close or
//! router shutdown so an idle sign-on screen can remain connected.

use crate::{
    config::parse_cp,
    mptn_outbound_port::{OutboundEndpoint, OutboundUdp, OutboundUdpAction},
    remote::{Config as RemoteConfig, InboundOpen, WsRoutePort},
    ws_native_responder::WsNativeResponder,
    STOP,
};
use router_core::{xid3::Role, xid3_local::LocalLlcProfile};
use std::{
    fs::File,
    io::{self, Read},
    net::{SocketAddr, UdpSocket},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::MAX_RECORD,
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_gateway_edge::{GatewayEdge, NativeLeg},
    mptn_native_bridge::Bridge,
    mptn_oob::Compensation,
    mptn_session::{connect_template_for_route, BindPolicy},
};
use transport_ws::wire;

const IDLE_POLL: Duration = Duration::from_micros(200);

#[derive(Clone)]
pub(crate) struct ReverseWsConfig {
    pub(crate) remote: RemoteConfig,
    /// CP and LU hosted by the local MPTN peer.
    pub(crate) hosted_cp: String,
    pub(crate) hosted_lu: String,
    /// The only concentrator-originated source accepted by this runner.
    pub(crate) source_cp: String,
    pub(crate) source_lu: String,
    pub(crate) local_station: String,
    pub(crate) local_node_id: [u8; 4],
    pub(crate) tg_number: u8,
    pub(crate) user_tp: [u8; 4],
    pub(crate) endpoint: OutboundEndpoint,
    /// Maximum time to establish the native circuit and management session.
    pub(crate) timeout: Duration,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl ReverseWsConfig {
    pub(crate) fn validate(&self) -> io::Result<()> {
        self.validate_for_tp(true)
    }

    pub(crate) fn validate_dynamic_tp(&self) -> io::Result<()> {
        self.validate_for_tp(false)
    }

    fn validate_for_tp(&self, fixed_tp: bool) -> io::Result<()> {
        let hosted_cp = parse_cp(&self.hosted_cp)?;
        let hosted_lu = parse_cp(&self.hosted_lu)?;
        let source_cp = parse_cp(&self.source_cp)?;
        let source_lu = parse_cp(&self.source_lu)?;
        if hosted_cp != self.remote.local_cp
            || hosted_lu.netid != hosted_cp.netid
            || source_cp != self.remote.target_cp
            || self.remote.target_lu.as_ref() != Some(&source_lu)
            || source_lu.netid != source_cp.netid
            || source_lu == hosted_lu
            || self.local_station.is_empty()
            || self.tg_number == 0
            || (fixed_tp && self.user_tp == [0; 4])
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(600)
            || self.endpoint.local_ip.is_unspecified()
            || self.endpoint.peer_ip.is_unspecified()
            || self.endpoint.local_ip == self.endpoint.peer_ip
            || self.endpoint.local_ip.is_ipv4() != self.endpoint.peer_ip.is_ipv4()
        {
            return Err(invalid("invalid WebSocket to MPTN reverse route"));
        }
        let _ = connect_template_for_route(&self.source_lu, &self.hosted_lu, [1; 8])?;
        self.local_xid()?;
        Ok(())
    }

    fn local_xid(&self) -> io::Result<router_core::xid3::Xid3> {
        LocalLlcProfile {
            cp_name: self.hosted_cp.clone(),
            station_name: self.local_station.clone(),
            node_id: self.local_node_id,
            tg_number: self.tg_number,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: Role::Secondary,
        }
        .build()
        .map_err(|error| invalid(format!("local XID3: {error}")))
    }
}

fn new_correlator() -> io::Result<[u8; 8]> {
    let mut value = [0; 8];
    File::open("/dev/urandom")?.read_exact(&mut value)?;
    if value == [0; 8] {
        value[0] = 1;
    }
    Ok(value)
}

fn poll_udp<L: NativeLeg>(
    socket: &UdpSocket,
    oob: &mut OutboundUdp,
    edge: &mut GatewayEdge<L>,
) -> io::Result<()> {
    let mut packet = [0u8; MAX_RECORD];
    match socket.recv_from(&mut packet) {
        Ok((length, source)) => match oob.receive(&packet[..length], source) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::WouldBlock
                ) =>
            {
                tracing::debug!(peer = %source, error = %error, "unmatched MPTN UDP packet dropped");
            }
            Err(error) => return Err(error),
            Ok(OutboundUdpAction::Reply(response)) => {
                if socket.send_to(&response, source)? != response.len() {
                    return Err(invalid("partial MPTN UDP response"));
                }
            }
            Ok(OutboundUdpAction::PendingDuplicate) => {}
            Ok(OutboundUdpAction::Deliver {
                compensation: Compensation::Expedited,
                sequence,
                reduced,
            }) => match edge.submit_udp_expedited(&reduced) {
                Ok(()) => oob.mark_native_submitted(sequence)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            },
            Ok(OutboundUdpAction::Deliver {
                compensation: Compensation::Abort,
                sequence,
                reduced,
            }) => match edge.submit_udp_abort(&reduced) {
                Ok(()) => oob.mark_native_submitted(sequence)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            },
        },
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    if let Some(OutboundUdpAction::Deliver {
        compensation,
        sequence,
        reduced,
    }) = oob.unsubmitted_delivery()
    {
        let submitted = match compensation {
            Compensation::Expedited => edge.submit_udp_expedited(&reduced),
            Compensation::Abort => edge.submit_udp_abort(&reduced),
        };
        match submitted {
            Ok(()) => oob.mark_native_submitted(sequence)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    let completed_expedited = edge.take_completed_udp_expedited();
    let completed_abort = edge.take_completed_udp_abort();
    if completed_expedited || completed_abort {
        let sequence = oob
            .pending_sequence()
            .ok_or_else(|| invalid("missing UDP sequence"))?;
        let (reply, peer) = oob.complete_native_delivery(sequence)?;
        if socket.send_to(&reply, peer)? != reply.len() {
            return Err(invalid("partial MPTN UDP acknowledgement"));
        }
    }
    Ok(())
}

/// A concentrator-initiated TCP62 conversion advanced by the automatic
/// router's shared event loop. TCP62 setup may wait for the peer briefly,
/// while established sessions never monopolize the other attachments.
pub(crate) struct AutoReverseWsSession {
    config: ReverseWsConfig,
    phase: Option<AutoReversePhase>,
}

enum AutoReversePhase {
    Management {
        native: Box<WsNativeResponder<WsRoutePort>>,
        socket: UdpSocket,
        deadline: Instant,
    },
    Active {
        edge: Box<GatewayEdge<WsNativeResponder<WsRoutePort>>>,
        socket: UdpSocket,
        oob: Box<OutboundUdp>,
        first_attach_seen: bool,
    },
}

impl AutoReverseWsSession {
    pub(crate) fn is_active(&self) -> bool {
        matches!(self.phase, Some(AutoReversePhase::Active { .. }))
    }

    pub(crate) fn new(
        config: ReverseWsConfig,
        mut native: WsNativeResponder<WsRoutePort>,
        socket: UdpSocket,
        deadline: Instant,
    ) -> io::Result<Self> {
        config.validate_dynamic_tp()?;
        native.arm_inbound()?;
        Ok(Self {
            config,
            phase: Some(AutoReversePhase::Management {
                native: Box::new(native),
                socket,
                deadline,
            }),
        })
    }

    /// Returns false after the circuit ends; the caller may then remove it.
    pub(crate) fn poll_once(&mut self) -> io::Result<bool> {
        let phase = self
            .phase
            .take()
            .ok_or_else(|| invalid("reverse circuit already closed"))?;
        match phase {
            AutoReversePhase::Management {
                mut native,
                socket,
                deadline,
            } => {
                if Instant::now() >= deadline {
                    native.close()?;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "automatic native management timed out",
                    ));
                }
                native.poll_management_once()?;
                if !native.management_ready() {
                    self.phase = Some(AutoReversePhase::Management {
                        native,
                        socket,
                        deadline,
                    });
                    return Ok(true);
                }
                let management = native
                    .management_bind()
                    .ok_or_else(|| invalid("native management BIND absent"))?
                    .clone();
                self.config.endpoint.establish_v5_management(
                    self.config.timeout.min(Duration::from_secs(5)),
                    &self.config.source_lu,
                    &self.config.hosted_lu,
                )?;
                let bridge = Bridge::new_dynamic_tp(
                    BindPolicy {
                        plu: self.config.source_lu.clone(),
                        slu: self.config.hosted_lu.clone(),
                        mode: None,
                        allow_blank_mode: true,
                        max_pending_bytes: MAX_RECORD,
                    },
                    CompensationSet::from_codes(&TCP62_REQUIRED)
                        .map_err(|error| invalid(error.to_string()))?,
                    management,
                    1,
                )?;
                let connect = connect_template_for_route(
                    &self.config.source_lu,
                    &self.config.hosted_lu,
                    new_correlator()?,
                )?;
                let oob = OutboundUdp::new(self.config.endpoint, connect.clone())?;
                let edge = self.config.endpoint.open_edge(
                    Duration::from_secs(5),
                    *native,
                    bridge,
                    connect,
                )?;
                self.phase = Some(AutoReversePhase::Active {
                    edge: Box::new(edge),
                    socket,
                    oob: Box::new(oob),
                    first_attach_seen: false,
                });
                Ok(true)
            }
            AutoReversePhase::Active {
                mut edge,
                socket,
                mut oob,
                mut first_attach_seen,
            } => {
                let result = (|| -> io::Result<bool> {
                    poll_udp(&socket, &mut oob, &mut edge)?;
                    edge.poll_native_once()?;
                    if edge.is_closed() {
                        return Ok(false);
                    }
                    edge.flush_tcp()?;
                    first_attach_seen |= edge.first_attach_delivery_complete();
                    if first_attach_seen || !edge.ipr_ack_outstanding() {
                        match edge.poll_tcp_once() {
                            Ok(()) => {}
                            Err(error)
                                if error.kind() == io::ErrorKind::UnexpectedEof
                                    && first_attach_seen =>
                            {
                                return Ok(false)
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    poll_udp(&socket, &mut oob, &mut edge)?;
                    Ok(true)
                })();
                match result {
                    Ok(true) => {
                        self.phase = Some(AutoReversePhase::Active {
                            edge,
                            socket,
                            oob,
                            first_attach_seen,
                        });
                        Ok(true)
                    }
                    Ok(false) => {
                        edge.close()?;
                        if !first_attach_seen {
                            Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "MPTN session ended before first Attach",
                            ))
                        } else {
                            Ok(false)
                        }
                    }
                    Err(error) => {
                        let _ = edge.close();
                        Err(error)
                    }
                }
            }
        }
    }
}

/// Serve one authenticated inbound WebSocket circuit and its MPTN session.
/// The caller owns reconnection and any later circuit on the published LU.
pub(crate) fn run_once(config: &ReverseWsConfig) -> io::Result<()> {
    config.validate()?;
    let setup_deadline = Instant::now() + config.timeout;
    let socket = UdpSocket::bind(SocketAddr::new(config.endpoint.local_ip, 397))?;
    socket.set_nonblocking(true)?;
    let hosted = parse_cp(&config.hosted_lu)?;
    let port = WsRoutePort::connect_gateway_v2(
        config.remote.clone(),
        vec![wire::LuReachability {
            lu: Some(hosted.clone()),
            hosting_cp: Some(config.remote.local_cp.clone()),
            supported_types: vec![wire::LuType::LuType62 as i32],
        }],
        hosted,
    )?;
    let mut native = WsNativeResponder::new(
        port,
        config.local_xid()?,
        &config.hosted_cp,
        &config.source_cp,
        &config.source_lu,
        &config.hosted_lu,
    )?;
    let open = loop {
        if STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        if Instant::now() >= setup_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "inbound WebSocket Open timed out",
            ));
        }
        if let Some(open) = native.poll_inbound_open_once()? {
            break open;
        }
        thread::sleep(IDLE_POLL);
    };
    run_from_open(config, native, socket, open, setup_deadline)
}

/// Continue an inbound native circuit selected by a duplex gateway. Its UDP
/// socket is a clone of that gateway's sole bound UDP/397 socket.
pub(crate) fn run_from_open(
    config: &ReverseWsConfig,
    mut native: WsNativeResponder<WsRoutePort>,
    socket: UdpSocket,
    open: InboundOpen,
    setup_deadline: Instant,
) -> io::Result<()> {
    tracing::info!(
        circuit_id = ?open.circuit_id,
        source_router_id = ?open.source_router_id,
        source_route = ?open.source_route,
        hosted_lu = %config.hosted_lu,
        peer_ip = %config.endpoint.peer_ip,
        "authenticated inbound circuit selected local MPTN peer"
    );
    while !native.management_ready()
        && !STOP.load(Ordering::Relaxed)
        && Instant::now() < setup_deadline
    {
        native.poll_management_once()?;
        thread::sleep(IDLE_POLL);
    }
    if STOP.load(Ordering::Relaxed) {
        native.close()?;
        return Ok(());
    }
    if !native.management_ready() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "native management timed out",
        ));
    }
    let management = native
        .management_bind()
        .ok_or_else(|| invalid("native management BIND absent"))?
        .clone();
    config.endpoint.establish_v5_management(
        config.timeout.min(Duration::from_secs(5)),
        &config.source_lu,
        &config.hosted_lu,
    )?;
    let policy = BindPolicy {
        plu: config.source_lu.clone(),
        slu: config.hosted_lu.clone(),
        mode: None,
        allow_blank_mode: true,
        max_pending_bytes: MAX_RECORD,
    };
    let available =
        CompensationSet::from_codes(&TCP62_REQUIRED).map_err(|error| invalid(error.to_string()))?;
    let bridge = Bridge::new(policy, available, management, config.user_tp, 1)?;
    let connect =
        connect_template_for_route(&config.source_lu, &config.hosted_lu, new_correlator()?)?;
    let mut oob = OutboundUdp::new(config.endpoint, connect.clone())?;
    let mut edge = config
        .endpoint
        .open_edge(Duration::from_secs(5), native, bridge, connect)?;
    let mut first_attach_seen = false;
    let result = (|| -> io::Result<()> {
        loop {
            if STOP.load(Ordering::Relaxed) {
                return Ok(());
            }
            poll_udp(&socket, &mut oob, &mut edge)?;
            edge.poll_native_once()?;
            if edge.is_closed() {
                return Ok(());
            }
            edge.flush_tcp()?;
            first_attach_seen |= edge.first_attach_delivery_complete();
            if first_attach_seen || !edge.ipr_ack_outstanding() {
                match edge.poll_tcp_once() {
                    Ok(()) => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::UnexpectedEof && first_attach_seen =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            poll_udp(&socket, &mut oob, &mut edge)?;
            thread::sleep(IDLE_POLL);
        }
    })();
    let close = edge.close();
    result?;
    close?;
    if !first_attach_seen && !STOP.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "MPTN session ended before first Attach",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ReverseWsConfig {
        ReverseWsConfig {
            remote: RemoteConfig {
                url: "ws://127.0.0.1:8081/router/v1/ws".to_owned(),
                bearer: String::new(),
                local_cp: parse_cp("QABOB.SNAB").unwrap(),
                target_cp: parse_cp("QAALICE.SNAA").unwrap(),
                target_lu: Some(parse_cp("QAALICE.SNAA").unwrap()),
            },
            hosted_cp: "QABOB.SNAB".to_owned(),
            hosted_lu: "QABOB.SNAB".to_owned(),
            source_cp: "QAALICE.SNAA".to_owned(),
            source_lu: "QAALICE.SNAA".to_owned(),
            local_station: "BOB".to_owned(),
            local_node_id: [0xff, 0xf1, 0x23, 0x45],
            tg_number: 1,
            user_tp: *b"QCMD",
            endpoint: OutboundEndpoint {
                local_ip: "10.99.4.11".parse().unwrap(),
                peer_ip: "10.99.4.3".parse().unwrap(),
            },
            timeout: Duration::from_secs(180),
        }
    }

    #[test]
    fn automatic_reverse_route_accepts_tp_learned_from_attach() {
        let mut route = config();
        route.user_tp = [0; 4];
        assert!(route.validate().is_err());
        route.validate_dynamic_tp().unwrap();
    }

    #[test]
    fn reverse_route_uses_mptn_hosted_lu_as_outbound_destination() {
        let config = config();
        config.validate().unwrap();
        let connect =
            connect_template_for_route(&config.source_lu, &config.hosted_lu, [1; 8]).unwrap();
        assert_eq!(connect.source.qualified_lu().unwrap(), "QAALICE.SNAA");
        assert_eq!(connect.destination.qualified_lu().unwrap(), "QABOB.SNAB");
    }

    #[test]
    fn reverse_route_rejects_mismatched_source_or_target_identity() {
        let mut route = config();
        route.remote.target_lu = Some(parse_cp("QAALICE.OTHER").unwrap());
        assert!(route.validate().is_err());
        route = config();
        route.hosted_lu = "OTHER.SNAB".to_owned();
        assert!(route.validate().is_err());
    }
}
