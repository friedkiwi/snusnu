//! A session-local native LLC to MPTN gateway runner.
//!
//! The caller selects a qualified LU route and owns retry policy. This module
//! keeps one LLC association, one TCP62 association and one UDP correlator
//! together, so credit and teardown cannot cross sessions.

use crate::{
    config::{parse_cp, parse_mac},
    mptn_outbound_port::{OutboundEndpoint, OutboundUdp, OutboundUdpAction},
    native_llc_port::NativeLlcPort,
    native_peer_port::NativeLlcEvent,
    native_probe::{parse_tp, ProbeConfig},
    runtime::LlcPeer,
    STOP,
};
use router_core::{
    fid2_bind::classify_bind, fid2_session_control::ManagementBind, xid3::Role,
    xid3_local::LocalLlcProfile,
};
use std::{
    fs::File,
    io::{self, Read},
    net::{IpAddr, SocketAddr, UdpSocket},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::MAX_RECORD,
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_gateway_edge::GatewayEdge,
    mptn_native_bridge::Bridge,
    mptn_oob::Compensation,
    mptn_session::{connect_template_for_route, BindPolicy},
};

const IDLE_POLL: Duration = Duration::from_micros(200);

struct BridgeRun<'a> {
    endpoint: OutboundEndpoint,
    interface: &'a str,
    source_lu: &'a str,
    destination_lu: &'a str,
    user_tp: Option<[u8; 4]>,
    management: ManagementBind,
    cancel: Option<&'a AtomicBool>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReverseLlcConfig {
    pub(crate) interface: String,
    pub(crate) guest_mac: [u8; 6],
    pub(crate) proxy_mac: [u8; 6],
    /// Router CP identity presented over LLC2 to the native guest.
    pub(crate) local_cp: String,
    /// Native guest CP, checked against XID3.
    pub(crate) guest_cp: String,
    pub(crate) local_station: String,
    pub(crate) local_node_id: [u8; 4],
    pub(crate) tg_number: u8,
    pub(crate) role: Role,
    /// The native initiating LU, then the MPTN-hosted destination LU.
    pub(crate) source_lu: String,
    pub(crate) destination_lu: String,
    pub(crate) user_tp: [u8; 4],
    pub(crate) endpoint: OutboundEndpoint,
    /// Maximum time to establish the native management session.
    pub(crate) timeout: Duration,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl ReverseLlcConfig {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.interface.is_empty()
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(600)
            || self.source_lu == self.destination_lu
            || self.tg_number == 0
            || self.user_tp == [0; 4]
        {
            return Err(invalid("invalid native LLC to MPTN route identity"));
        }
        let source = parse_cp(&self.source_lu)?;
        let destination = parse_cp(&self.destination_lu)?;
        if source.netid != parse_cp(&self.guest_cp)?.netid
            || destination.netid != parse_cp(&self.local_cp)?.netid
        {
            return Err(invalid("native LU and CP NETIDs differ"));
        }
        if self.endpoint.local_ip.is_unspecified()
            || self.endpoint.peer_ip.is_unspecified()
            || self.endpoint.local_ip == self.endpoint.peer_ip
            || self.endpoint.local_ip.is_ipv4() != self.endpoint.peer_ip.is_ipv4()
        {
            return Err(invalid("invalid native LLC to MPTN IP pair"));
        }
        let _ = connect_template_for_route(&self.source_lu, &self.destination_lu, [1; 8])?;
        Ok(())
    }

    fn profile(&self) -> LocalLlcProfile {
        LocalLlcProfile {
            cp_name: self.local_cp.clone(),
            station_name: self.local_station.clone(),
            node_id: self.local_node_id,
            tg_number: self.tg_number,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: self.role,
        }
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

fn poll_udp(
    socket: &UdpSocket,
    oob: &mut OutboundUdp,
    edge: &mut GatewayEdge<NativeLlcPort>,
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
                ..
            }) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "MPTN abort compensation is unavailable",
                ));
            }
        },
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    if let Some(OutboundUdpAction::Deliver {
        compensation: Compensation::Expedited,
        sequence,
        reduced,
    }) = oob.unsubmitted_delivery()
    {
        match edge.submit_udp_expedited(&reduced) {
            Ok(()) => oob.mark_native_submitted(sequence)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    if edge.take_completed_udp_expedited() {
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

/// Run one native-initiated LU6.2 circuit. `Ok` means the circuit closed
/// after its first Attach; callers may start a new circuit with fresh IDs.
pub(crate) fn run_once(config: &ReverseLlcConfig) -> io::Result<()> {
    config.validate()?;
    tracing::info!(
        interface = %config.interface,
        guest_mac = %format_mac(config.guest_mac),
        proxy_mac = %format_mac(config.proxy_mac),
        guest_cp = %config.guest_cp,
        local_cp = %config.local_cp,
        source_lu = %config.source_lu,
        destination_lu = %config.destination_lu,
        local_ip = %config.endpoint.local_ip,
        peer_ip = %config.endpoint.peer_ip,
        setup_timeout_seconds = config.timeout.as_secs(),
        "LLC to MPTN reverse session starting"
    );
    let setup_deadline = Instant::now() + config.timeout;
    let socket = UdpSocket::bind(SocketAddr::new(config.endpoint.local_ip, 397))?;
    socket.set_nonblocking(true)?;
    config.endpoint.establish_v5_management(
        config.timeout.min(Duration::from_secs(5)),
        &config.source_lu,
        &config.destination_lu,
    )?;
    tracing::debug!(peer_ip = %config.endpoint.peer_ip, source_lu = %config.source_lu, destination_lu = %config.destination_lu, "MPTN management complete");
    let xid = config
        .profile()
        .build()
        .map_err(|error| invalid(format!("local XID3: {error}")))?;
    let mut native = NativeLlcPort::open(
        LlcPeer {
            interface: &config.interface,
            guest_mac: config.guest_mac,
            proxy_mac: config.proxy_mac,
        },
        xid,
        config.guest_cp.clone(),
        config.local_cp.clone(),
        config.source_lu.clone(),
        config.destination_lu.clone(),
    )?;
    while native.management_bind().is_none()
        && !STOP.load(Ordering::Relaxed)
        && Instant::now() < setup_deadline
    {
        match native.receive_once()? {
            None => thread::sleep(IDLE_POLL),
            Some(NativeLlcEvent::Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "native contact closed before management BIND",
                ))
            }
            Some(_) => return Err(invalid("native user event before management BIND")),
        }
    }
    let management = native
        .management_bind()
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "native management BIND timed out"))?
        .clone();
    run_bridge(
        native,
        socket,
        BridgeRun {
            endpoint: config.endpoint,
            interface: &config.interface,
            source_lu: &config.source_lu,
            destination_lu: &config.destination_lu,
            user_tp: Some(config.user_tp),
            management,
            cancel: None,
        },
    )
}

fn run_bridge(native: NativeLlcPort, socket: UdpSocket, settings: BridgeRun<'_>) -> io::Result<()> {
    let BridgeRun {
        endpoint,
        interface,
        source_lu,
        destination_lu,
        user_tp,
        management,
        cancel,
    } = settings;
    let policy = BindPolicy {
        plu: source_lu.to_owned(),
        slu: destination_lu.to_owned(),
        mode: None,
        allow_blank_mode: true,
        max_pending_bytes: MAX_RECORD,
    };
    let available =
        CompensationSet::from_codes(&TCP62_REQUIRED).map_err(|error| invalid(error.to_string()))?;
    let bridge = match user_tp {
        Some(tp) => Bridge::new(policy, available, management, tp, 1)?,
        None => Bridge::new_dynamic_tp(policy, available, management, 1)?,
    };
    let connect = connect_template_for_route(source_lu, destination_lu, new_correlator()?)?;
    let mut oob = OutboundUdp::new(endpoint, connect.clone())?;
    let mut edge = endpoint.open_edge(Duration::from_secs(5), native, bridge, connect)?;
    let mut first_attach_seen = false;
    let result = (|| -> io::Result<()> {
        loop {
            if STOP.load(Ordering::Relaxed)
                || cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed))
            {
                return Ok(());
            }
            poll_udp(&socket, &mut oob, &mut edge)?;
            edge.poll_native_once()?;
            if edge.is_closed() {
                return Ok(());
            }
            edge.flush_tcp()?;
            if !first_attach_seen && edge.first_attach_delivery_complete() {
                first_attach_seen = true;
                tracing::info!(interface, peer_ip = %endpoint.peer_ip, source_lu, destination_lu, "first LU6.2 Attach delivered to MPTN peer");
            }
            if first_attach_seen || !edge.ipr_ack_outstanding() {
                match edge.poll_tcp_once() {
                    Ok(()) => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::UnexpectedEof && first_attach_seen =>
                    {
                        return Ok(())
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
    if !first_attach_seen
        && !STOP.load(Ordering::Relaxed)
        && !cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed))
    {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "MPTN session ended before first Attach",
        ));
    }
    tracing::info!(interface, peer_ip = %endpoint.peer_ip, first_attach_seen, "LLC to MPTN reverse session closed");
    Ok(())
}

/// Run an automatic LLC-originated circuit from an already selected native
/// association and an exclusive UDP/397 socket. The management BIND supplies
/// the network-qualified LU pair; the first validated Attach supplies the TP.
/// The caller retains ownership of listener admission and destination choice.
pub(crate) fn run_with_native(
    mut native: NativeLlcPort,
    socket: UdpSocket,
    endpoint: OutboundEndpoint,
    interface: &str,
    timeout: Duration,
    cancel: &AtomicBool,
) -> io::Result<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(600) {
        return Err(invalid("automatic LLC to MPTN setup timeout is invalid"));
    }
    socket.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    while native.management_bind().is_none()
        && !STOP.load(Ordering::Relaxed)
        && !cancel.load(Ordering::Relaxed)
        && Instant::now() < deadline
    {
        match native.receive_once()? {
            None => thread::sleep(IDLE_POLL),
            Some(NativeLlcEvent::Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "native contact closed before management BIND",
                ));
            }
            Some(_) => return Err(invalid("native user event before management BIND")),
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "automatic local circuit cancelled",
        ));
    }
    let management = native
        .management_bind()
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "native management BIND timed out"))?
        .clone();
    let management_plu = management.plu().to_owned();
    let management_slu = management.slu().to_owned();
    parse_cp(&management_plu)?;
    parse_cp(&management_slu)?;
    endpoint.establish_v5_management(
        timeout.min(Duration::from_secs(5)),
        &management_plu,
        &management_slu,
    )?;
    tracing::info!(interface, peer_ip = %endpoint.peer_ip, management_plu, management_slu,
        "automatic LLC to MPTN management established");
    let user_bind = loop {
        if cancel.load(Ordering::Relaxed) || STOP.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "automatic local circuit cancelled",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native user BIND timed out",
            ));
        }
        match native.receive_once()? {
            Some(NativeLlcEvent::UserBind(piu)) => break piu,
            Some(NativeLlcEvent::Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "native contact closed before user BIND",
                ))
            }
            Some(_) => return Err(invalid("native user event before user BIND")),
            None => thread::sleep(IDLE_POLL),
        }
    };
    let bind = classify_bind(&user_bind)
        .map_err(|error| invalid(format!("native user BIND: {error}")))?
        .ok_or_else(|| invalid("native user BIND is absent"))?;
    let source_lu = bind.plu;
    let destination_lu = bind.slu;
    parse_cp(&source_lu)?;
    parse_cp(&destination_lu)?;
    native.replay_user_bind(user_bind)?;
    tracing::info!(
        interface,
        source_lu,
        destination_lu,
        "automatic native user LU pair selected"
    );
    run_bridge(
        native,
        socket,
        BridgeRun {
            endpoint,
            interface,
            source_lu: &source_lu,
            destination_lu: &destination_lu,
            user_tp: None,
            management,
            cancel: Some(cancel),
        },
    )
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// The staged lab diagnostic uses the same session runner as a future
/// ordinary route. The fixture supplies the native XID and LU6.2 TP policy;
/// the command line chooses the two MPTN addresses.
pub(crate) fn run_probe(path: &Path, local_ip: IpAddr, peer_ip: IpAddr) -> io::Result<()> {
    let fixture = ProbeConfig::load(path)?;
    if fixture.active_xid {
        return Err(invalid("active_xid is unavailable for native converter"));
    }
    let source_lu = fixture
        .user_plu
        .clone()
        .ok_or_else(|| invalid("user_plu required"))?;
    let destination_lu = fixture
        .user_slu
        .clone()
        .ok_or_else(|| invalid("user_slu required"))?;
    let node_id = fixture.profile()?.node_id;
    let config = ReverseLlcConfig {
        interface: fixture.interface,
        guest_mac: parse_mac(&fixture.guest_mac)?,
        proxy_mac: parse_mac(&fixture.proxy_mac)?,
        local_cp: fixture.local_cp,
        guest_cp: fixture
            .remote_cp
            .ok_or_else(|| invalid("remote_cp required"))?,
        local_station: fixture.local_station,
        local_node_id: node_id,
        tg_number: fixture.tg_number,
        role: fixture.role.into(),
        source_lu,
        destination_lu,
        user_tp: parse_tp(
            fixture
                .user_tp_hex
                .as_deref()
                .ok_or_else(|| invalid("user_tp_hex required"))?,
        )?,
        endpoint: OutboundEndpoint { local_ip, peer_ip },
        timeout: Duration::from_secs(fixture.timeout_seconds),
    };
    run_once(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ReverseLlcConfig {
        ReverseLlcConfig {
            interface: "sol5".into(),
            guest_mac: [2, 0, 0, 0, 0, 1],
            proxy_mac: [2, 0x53, 0x4e, 0, 0, 2],
            local_cp: "SOLNET.SNAB".into(),
            guest_cp: "SOLNET.SNAA".into(),
            local_station: "SNAB".into(),
            local_node_id: [0xff, 0xf1, 0x23, 0x45],
            tg_number: 1,
            role: Role::Secondary,
            source_lu: "SOLNET.SNAA".into(),
            destination_lu: "SOLNET.SNAB".into(),
            user_tp: [1, 2, 3, 4],
            endpoint: OutboundEndpoint {
                local_ip: "10.99.4.10".parse().unwrap(),
                peer_ip: "10.99.4.3".parse().unwrap(),
            },
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn route_identity_is_checked_before_opening_raw_sockets() {
        config().validate().unwrap();
        let mut distinct_lus = config();
        distinct_lus.source_lu = "SOLNET.PAYROLL".into();
        distinct_lus.destination_lu = "SOLNET.LEDGER".into();
        distinct_lus.validate().unwrap();
        let mut wrong = config();
        wrong.source_lu = "OTHERNET.OTHER".into();
        assert!(wrong.validate().is_err());
        let mut wrong = config();
        wrong.endpoint.peer_ip = wrong.endpoint.local_ip;
        assert!(wrong.validate().is_err());
    }
}
