//! Opt-in process harness: real native LLC leg, in-process mock TCP62 peer.
//!
//! The mock advertises all six TCP62 compensation codes only inside this
//! loopback fixture. The production route loader still rejects this gateway
//! because UDP X'83' and later APPC traffic lack complete runtime handlers.

use crate::{
    config::parse_mac,
    native_llc_port::NativeLlcPort,
    native_peer_port::NativeLlcEvent,
    native_probe::{parse_tp, ProbeConfig},
    runtime::LlcPeer,
    STOP,
};
use router_core::user_bind::UserBindOffer;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::File,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    sync::{atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_connect::{Address, Connect, Direction, OptionalField, TransportRequirements},
    mptn_gateway_edge::GatewayEdge,
    mptn_management_initiator::ManagementInitiator,
    mptn_native_bridge::{Bridge, Phase as BridgePhase},
    mptn_session::BindPolicy,
};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn ebcdic_lu(value: &str) -> io::Result<Address> {
    let mut node = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        node.push(match byte {
            b'A'..=b'I' => 0xc1 + (byte - b'A'),
            b'J'..=b'R' => 0xd1 + (byte - b'J'),
            b'S'..=b'Z' => 0xe2 + (byte - b'S'),
            b'0'..=b'9' => 0xf0 + (byte - b'0'),
            b'.' => 0x4b,
            _ => return Err(invalid("mock TCP62 LU names must be NETID.LU ASCII")),
        });
    }
    Ok(Address { node })
}

fn template(plu: &str, slu: &str) -> io::Result<Connect> {
    Ok(Connect {
        direction: Direction::Request,
        processing: 0x0a,
        ttl: 8,
        source: ebcdic_lu(plu)?,
        destination: ebcdic_lu(slu)?,
        correlator: vec![0x12, 0x34],
        requirements: TransportRequirements {
            max_record: 4096,
            max_expedited: 256,
            max_termination: 256,
        },
        options: vec![
            OptionalField {
                kind: 0x0a,
                processing: 0x02,
                value: vec![0x31],
            },
            OptionalField {
                kind: 0x19,
                processing: 0x0a,
                value: TCP62_REQUIRED.to_vec(),
            },
        ],
    })
}

fn v5_template(plu: &str, slu: &str) -> io::Result<Connect> {
    let mut connect = template(plu, slu)?;
    // Direct V5R4 A→B p7: request flags 0x0a, TTL 42, eight-byte
    // correlator, transport sizes 0x8005/0x76/0x76 and ordered optional
    // fields 05, 0a, 18, 19. Captured optional 1a/84 is omitted because
    // this bounded diagnostic does not answer UDP keepalives.
    connect.ttl = 42;
    let mut correlator = [0; 8];
    File::open("/dev/urandom")?.read_exact(&mut correlator)?;
    connect.correlator = correlator.to_vec();
    connect.requirements = TransportRequirements {
        max_record: 0x8005,
        max_expedited: 0x76,
        max_termination: 0x76,
    };
    connect.options.insert(
        0,
        OptionalField {
            kind: 0x05,
            processing: 0x08,
            value: vec![0x01, 0x01],
        },
    );
    connect.options.insert(
        2,
        OptionalField {
            kind: 0x18,
            processing: 0x00,
            value: vec![0x01],
        },
    );
    connect.options[3].value = vec![0x00, 0x20, 0x01, 0x03, 0x10, 0x83];
    Ok(connect)
}

fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if !(8..=MAX_RECORD).contains(&length) {
        return Err(invalid("mock TCP62 record length outside bound"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}

fn establish_v5_management(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    local_lu: &str,
    remote_lu: &str,
    udp: &UdpSocket,
) -> io::Result<()> {
    // This is a single-use isolated V5R4 diagnostic. Each transport and
    // session identifier is fresh, and the captured management profile is
    // never installed in the production route loader.
    let mut entropy = [0u8; 20];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let local_name = ebcdic_lu(local_lu)?.node;
    if local_name.len() != 11 {
        return Err(invalid("V5 management lab requires an 11-byte local LU"));
    }
    let mut fqpcid = [0u8; 22];
    fqpcid[..2].copy_from_slice(&[0x60, 0x14]);
    fqpcid[2..10].copy_from_slice(&entropy[..8]);
    fqpcid[10] = 11;
    fqpcid[11..].copy_from_slice(&local_name);
    let correlator: [u8; 8] = entropy[8..16].try_into().unwrap();
    let mut bind_token = [0x23, 0, 0, 0, 0, 0x80, 0];
    bind_token[1..5].copy_from_slice(&entropy[16..20]);
    let mut management =
        ManagementInitiator::new(local_lu, remote_lu, fqpcid, correlator, bind_token, "", 8)?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::new(local_ip.into(), 0).into())?;
    socket.connect_timeout(
        &SocketAddr::new(remote_ip.into(), 397).into(),
        Duration::from_secs(5),
    )?;
    let mut stream: TcpStream = socket.into();
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    tracing::warn!(local_lu, remote_lu, local_ip = %local_ip, remote_ip = %remote_ip, "experimental V5 outbound SNASVCMG/CNOS started");
    stream.write_all(management.connect_request())?;
    observe_udp(udp)?;
    let cnos = management.accept_connect_response(&read_record(&mut stream)?)?;
    stream.write_all(&cnos)?;
    observe_udp(udp)?;
    let bis = management.accept_cnos_reply(&read_record(&mut stream)?)?;
    stream.write_all(&bis)?;
    observe_udp(udp)?;
    let unbind = management.accept_bis(&read_record(&mut stream)?)?;
    stream.write_all(&unbind)?;
    management.mark_unbind_sent(&unbind)?;
    observe_udp(udp)?;
    let mut tail = [0u8; 1];
    if stream.read(&mut tail)? != 0 {
        return Err(invalid("V5 management peer sent data after UNBIND"));
    }
    management.observe_peer_close()?;
    observe_udp(udp)?;
    if !management.ready() {
        return Err(invalid("V5 management did not complete"));
    }
    tracing::info!(
        local_lu,
        remote_lu,
        "experimental V5 SNASVCMG/CNOS completed before user Connect"
    );
    Ok(())
}

fn mock_peer(
    mut stream: TcpStream,
    management: router_core::fid2_session_control::ManagementBind,
    timeout: Duration,
    delivered: mpsc::Sender<usize>,
    shutdown: mpsc::Receiver<()>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    let request = Connect::decode(&read_record(&mut stream)?)?;
    if request.direction != Direction::Request || request.connection_data().len() < 9 {
        return Err(invalid("mock expected one TCP62 Connect request"));
    }
    // TCP62 strips the first four FID2 TH bytes. Recreate an address pair
    // solely for the isolated V4R4 fixture, then derive response FQPCID and
    // LU fields from the received BIND; no captured dynamic token is replayed.
    let mut synthetic = vec![
        0x2d,
        0,
        management.request_addresses().0.saturating_add(1),
        management.request_addresses().1,
    ];
    synthetic.extend_from_slice(request.connection_data());
    let offer = UserBindOffer::from_request(&synthetic, &management, "")
        .map_err(|error| invalid(format!("mock Connect BIND: {error}")))?;
    let mut response = request.clone();
    response.direction = Direction::PositiveResponse;
    response.processing = 0x8a;
    let bind_response = offer
        .build_fixed_response(1)
        .map_err(|error| invalid(format!("mock response BIND: {error}")))?;
    response
        .options
        .iter_mut()
        .find(|option| option.kind == 0x0a)
        .ok_or_else(|| invalid("mock Connect has no BIND option"))?
        .value = bind_response[4..].to_vec();
    stream.write_all(&response.encode()?)?;
    let normal = TcpRecord::decode(read_record(&mut stream)?)?;
    if normal.kind != TcpKind::Normal
        || normal.bytes.len() != 243
        || normal.bytes.get(5..12) != Some(&[0, 1, 0x0b, 0x90, 0x20, 0x24, 0x05])
    {
        return Err(invalid("mock expected first 242-byte APPC FMH5 Attach"));
    }
    delivered
        .send(normal.bytes.len())
        .map_err(|_| invalid("mock delivery receiver closed"))?;
    // Keep TCP62 connected until the native LLC egress ACK is observed.
    // Dropping this socket immediately after read races GatewayEdge's
    // final `poll_tcp_once` and makes a successful Attach look like EOF.
    shutdown
        .recv_timeout(timeout)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mock shutdown timed out"))?;
    Ok(())
}

fn open_native(
    path: &Path,
) -> io::Result<(ProbeConfig, NativeLlcPort, String, String, [u8; 4], Instant)> {
    let config = ProbeConfig::load(path)?;
    let remote_cp = config
        .remote_cp
        .clone()
        .ok_or_else(|| invalid("remote_cp required"))?;
    let user_plu = config
        .user_plu
        .clone()
        .ok_or_else(|| invalid("user_plu required"))?;
    let user_slu = config
        .user_slu
        .clone()
        .ok_or_else(|| invalid("user_slu required"))?;
    if user_plu != remote_cp || user_slu != config.local_cp {
        return Err(invalid(
            "converter fixture requires user LU pair equal configured CP pair",
        ));
    }
    let tp = parse_tp(
        config
            .user_tp_hex
            .as_deref()
            .ok_or_else(|| invalid("user_tp_hex required"))?,
    )?;
    let xid = config
        .profile()?
        .build()
        .map_err(|error| invalid(format!("local XID3: {error}")))?;
    let mut native = NativeLlcPort::open(
        LlcPeer {
            interface: &config.interface,
            guest_mac: parse_mac(&config.guest_mac)?,
            proxy_mac: parse_mac(&config.proxy_mac)?,
        },
        xid,
        remote_cp.clone(),
        config.local_cp.clone(),
        user_plu.clone(),
        user_slu.clone(),
    )?;
    let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
    tracing::warn!(interface = %config.interface, "isolated native converter harness opened; no production route advertised");
    // Construct the gateway as soon as the validated management BIND exists.
    // Waiting until BIS completes could consume and discard a UserBind event
    // delivered in the same LLC poll as the final management ACK.
    while native.management_bind().is_none()
        && !STOP.load(Ordering::Relaxed)
        && Instant::now() < deadline
    {
        match native.receive_once()? {
            None => thread::sleep(Duration::from_micros(200)),
            Some(NativeLlcEvent::Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "native APPN contact closed before management BIND",
                ));
            }
            Some(_) => return Err(invalid("user event before validated management BIND")),
        }
    }
    if native.management_bind().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "converter did not receive APPN management BIND",
        ));
    }
    Ok((config, native, user_plu, user_slu, tp, deadline))
}

fn bridge(
    native: &NativeLlcPort,
    user_plu: &str,
    user_slu: &str,
    tp: [u8; 4],
) -> io::Result<Bridge> {
    let policy = BindPolicy {
        plu: user_plu.to_owned(),
        slu: user_slu.to_owned(),
        mode: None,
        allow_blank_mode: true,
        max_pending_bytes: MAX_RECORD,
    };
    Bridge::new(
        policy,
        CompensationSet::from_codes(&TCP62_REQUIRED).map_err(|error| invalid(error.to_string()))?,
        native
            .management_bind()
            .ok_or_else(|| invalid("management BIND missing"))?
            .clone(),
        tp,
        1,
    )
}

pub(crate) fn run(path: &Path) -> io::Result<()> {
    let (config, native, user_plu, user_slu, tp, deadline) = open_native(path)?;
    let management = native
        .management_bind()
        .ok_or_else(|| invalid("management BIND missing"))?
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let sender = TcpStream::connect(listener.local_addr()?)?;
    let (peer, _) = listener.accept()?;
    let timeout = Duration::from_secs(config.timeout_seconds);
    let (delivered_tx, delivered_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let mock =
        thread::spawn(move || mock_peer(peer, management, timeout, delivered_tx, shutdown_rx));
    let mut mock_bytes = None;
    // All six codes are injected only because this peer is an in-process
    // mock on loopback. Never derive production handler availability here.
    let bridge = bridge(&native, &user_plu, &user_slu, tp)?;
    let mut edge = GatewayEdge::new(
        native,
        TcpSession::new(sender)?,
        bridge,
        template(&user_plu, &user_slu)?,
    );
    while !STOP.load(Ordering::Relaxed) && Instant::now() < deadline {
        edge.poll_native_once()?;
        edge.poll_tcp_once()?;
        edge.flush_tcp()?;
        if let Ok(bytes) = delivered_rx.try_recv() {
            mock_bytes = Some(bytes);
        } else if mock.is_finished() && mock_bytes.is_none() {
            mock.join()
                .map_err(|_| invalid("mock TCP62 peer panicked"))??;
            return Err(invalid("mock closed before first APPC Attach"));
        }
        if mock_bytes.is_some() && edge.first_attach_delivery_complete() {
            break;
        }
        thread::sleep(Duration::from_micros(200));
    }
    if !edge.first_attach_delivery_complete() || mock_bytes.is_none() {
        edge.close()?;
        let _ = shutdown_tx.send(());
        let _ = mock.join();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "mock Attach delivery or native IPR acknowledgement incomplete",
        ));
    }
    let bytes = mock_bytes.unwrap();
    tracing::info!(
        tcp_record_bytes = bytes,
        "first native user Attach reached in-process TCP62 mock; route remains disabled"
    );
    edge.close()?;
    shutdown_tx
        .send(())
        .map_err(|_| invalid("mock shutdown receiver closed"))?;
    mock.join()
        .map_err(|_| invalid("mock TCP62 peer panicked"))??;
    Ok(())
}

fn observe_udp(socket: &UdpSocket) -> io::Result<()> {
    let mut packet = [0u8; 65_536];
    match socket.recv_from(&mut packet) {
        Ok((length, source)) => {
            tracing::warn!(source = %source, bytes = length, code = ?packet.get(4), "experimental V5 AnyNet UDP received; stopping before unsupported X83 handling");
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "experimental AnyNet UDP/X83 response handling is unavailable",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error),
    }
}

/// Inspect one reverse TCP/397 connection from the configured V5 peer. A
/// TCP62 connection begins with MPTN_Connect (IBM TCP62 draft §5.3.1). This
/// diagnostic deliberately provides no response or management session.
struct ReverseConnectProbe {
    listener: Option<TcpListener>,
    peer: Option<TcpSession>,
    expected_ip: Ipv4Addr,
}

impl ReverseConnectProbe {
    fn bind(local: SocketAddr, expected_ip: Ipv4Addr) -> io::Result<Self> {
        let listener = TcpListener::bind(local)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: Some(listener),
            peer: None,
            expected_ip,
        })
    }

    fn poll(&mut self) -> io::Result<Option<Connect>> {
        if self.peer.is_none() {
            let Some(listener) = self.listener.as_ref() else {
                return Ok(None);
            };
            match listener.accept() {
                Ok((stream, source)) => {
                    if source.ip() != self.expected_ip {
                        return Err(invalid("reverse TCP62 connection from unexpected IP"));
                    }
                    tracing::warn!(source = %source, "isolated V5 reverse TCP/397 connection accepted for first-record diagnosis");
                    self.listener = None; // at most one reverse connection
                    self.peer = Some(TcpSession::new(stream)?);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let Some(records) = self.peer.as_mut().unwrap().receive_once()? else {
            return Ok(None);
        };
        if records.is_empty() {
            return Ok(None);
        }
        if records.len() != 1 || records[0].kind != TcpKind::Connect {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "reverse TCP62 peer sent an unsupported first record sequence",
            ));
        }
        let connect = Connect::decode(&records[0].bytes)?;
        if connect.direction != Direction::Request {
            return Err(invalid("reverse TCP62 first Connect is not a request"));
        }
        self.peer = None; // never leave an unhandled session open
        Ok(Some(connect))
    }
}

/// Explicit one-shot diagnostic against an isolated real V5R4 TCP62 peer.
/// The X'19' claim is restricted to this command and is never installed in
/// the production route loader. Any UDP packet ends the diagnostic before an
/// unimplemented X'83' control flow could be silently ignored.
pub(crate) fn run_v5(path: &Path, local_ip: Ipv4Addr, remote_ip: Ipv4Addr) -> io::Result<()> {
    if local_ip.is_unspecified()
        || local_ip.is_loopback()
        || local_ip.is_multicast()
        || remote_ip.is_unspecified()
        || remote_ip.is_loopback()
        || remote_ip.is_multicast()
        || local_ip == remote_ip
    {
        return Err(invalid(
            "isolated V5 lab needs two distinct unicast IPv4 addresses",
        ));
    }
    let mut reverse = ReverseConnectProbe::bind(SocketAddr::new(local_ip.into(), 397), remote_ip)?;
    let udp = UdpSocket::bind(SocketAddr::new(local_ip.into(), 397))?;
    udp.set_nonblocking(true)?;
    let probe = ProbeConfig::load(path)?;
    let local_lu = probe
        .user_plu
        .as_deref()
        .ok_or_else(|| invalid("user_plu required for V5 management"))?;
    let remote_lu = probe
        .user_slu
        .as_deref()
        .ok_or_else(|| invalid("user_slu required for V5 management"))?;
    establish_v5_management(local_ip, remote_ip, local_lu, remote_lu, &udp)?;
    let (config, native, user_plu, user_slu, tp, deadline) = open_native(path)?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::new(local_ip.into(), 0).into())?;
    let remote = SocketAddr::new(remote_ip.into(), 397);
    socket.connect_timeout(&remote.into(), Duration::from_secs(5))?;
    let stream: TcpStream = socket.into();
    let bridge = bridge(&native, &user_plu, &user_slu, tp)?;
    let mut edge = GatewayEdge::new(
        native,
        TcpSession::new(stream)?,
        bridge,
        v5_template(&user_plu, &user_slu)?,
    );
    tracing::warn!(interface = %config.interface, local_ip = %local_ip, remote_ip = %remote_ip, "experimental V5 TCP62 diagnostic opened; X83 unavailable; no production route advertised");
    while !STOP.load(Ordering::Relaxed) && Instant::now() < deadline {
        if let Some(connect) = reverse.poll()? {
            tracing::warn!(source_lu = ?connect.source.node, destination_lu = ?connect.destination.node, options = ?connect.options.iter().map(|field| field.kind).collect::<Vec<_>>(), bind_data_bytes = connect.connection_data().len(), "isolated V5 reverse MPTN Connect observed; management responder unavailable");
        }
        observe_udp(&udp)?;
        edge.poll_native_once()?;
        edge.flush_tcp()?;
        if edge.first_attach_delivery_complete() {
            break;
        }
        // The first application reply is outside this bounded diagnostic.
        // Once its Attach is queued, leave TCP readable for the next gateway
        // implementation, while continuing to observe native ACK and UDP.
        if !edge.ipr_ack_outstanding() {
            edge.poll_tcp_once()?;
        }
        observe_udp(&udp)?;
        if edge.first_attach_delivery_complete() {
            break;
        }
        thread::sleep(Duration::from_micros(200));
    }
    if !edge.first_attach_delivery_complete() {
        edge.close()?;
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "V5 TCP62 Connect, first Attach, or native IPR ACK incomplete",
        ));
    }
    observe_udp(&udp)?;
    tracing::info!(remote_ip = %remote_ip, "first native Attach written to isolated V5 TCP62 peer and native IPR acknowledged; application conversation unsupported");
    edge.close()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FlowSnapshot {
    phase: BridgePhase,
    pending_tcp: usize,
    pending_native: usize,
    ipr_ack_outstanding: bool,
}

fn flow_snapshot(edge: &GatewayEdge<NativeLlcPort>) -> FlowSnapshot {
    let (pending_tcp, pending_native) = edge.pending_gateway_bytes();
    FlowSnapshot {
        phase: edge.phase(),
        pending_tcp,
        pending_native,
        ipr_ack_outstanding: edge.ipr_ack_outstanding(),
    }
}

fn log_flow_change(
    edge: &GatewayEdge<NativeLlcPort>,
    before: FlowSnapshot,
    leg: &'static str,
    remote_ip: Ipv4Addr,
) {
    let after = flow_snapshot(edge);
    if after != before {
        tracing::debug!(
            leg,
            remote_ip = %remote_ip,
            phase = ?after.phase,
            pending_tcp = after.pending_tcp,
            pending_native = after.pending_native,
            ipr_ack_outstanding = after.ipr_ack_outstanding,
            "experimental V5 flow advanced"
        );
    }
}

fn flow_poll_tcp(first_attach_seen: bool, ipr_ack_outstanding: bool) -> bool {
    first_attach_seen || !ipr_ack_outstanding
}

/// Continue the isolated V5R4 experiment after the first Attach. The native
/// and TCP62 legs retain GatewayEdge's bounded credit; any UDP/397 traffic or
/// reverse Connect remains unsupported and ends this explicit lab run.
pub(crate) fn run_v5_flow(path: &Path, local_ip: Ipv4Addr, remote_ip: Ipv4Addr) -> io::Result<()> {
    if local_ip.is_unspecified()
        || local_ip.is_loopback()
        || local_ip.is_multicast()
        || remote_ip.is_unspecified()
        || remote_ip.is_loopback()
        || remote_ip.is_multicast()
        || local_ip == remote_ip
    {
        return Err(invalid(
            "isolated V5 lab needs two distinct unicast IPv4 addresses",
        ));
    }
    let mut reverse = ReverseConnectProbe::bind(SocketAddr::new(local_ip.into(), 397), remote_ip)?;
    let udp = UdpSocket::bind(SocketAddr::new(local_ip.into(), 397))?;
    udp.set_nonblocking(true)?;
    let probe = ProbeConfig::load(path)?;
    let local_lu = probe
        .user_plu
        .as_deref()
        .ok_or_else(|| invalid("user_plu required for V5 management"))?;
    let remote_lu = probe
        .user_slu
        .as_deref()
        .ok_or_else(|| invalid("user_slu required for V5 management"))?;
    establish_v5_management(local_ip, remote_ip, local_lu, remote_lu, &udp)?;
    let (config, native, user_plu, user_slu, tp, deadline) = open_native(path)?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::new(local_ip.into(), 0).into())?;
    let remote = SocketAddr::new(remote_ip.into(), 397);
    socket.connect_timeout(&remote.into(), Duration::from_secs(5))?;
    let stream: TcpStream = socket.into();
    let bridge = bridge(&native, &user_plu, &user_slu, tp)?;
    let mut edge = GatewayEdge::new(
        native,
        TcpSession::new(stream)?,
        bridge,
        v5_template(&user_plu, &user_slu)?,
    );
    tracing::warn!(
        interface = %config.interface,
        guest_mac = %config.guest_mac,
        proxy_mac = %config.proxy_mac,
        local_ip = %local_ip,
        remote_ip = %remote_ip,
        local_lu = %local_lu,
        remote_lu = %remote_lu,
        "experimental V5 flow lab opened; X83 unavailable; no production route advertised"
    );
    let mut first_attach_seen = false;
    let outcome = (|| -> io::Result<&'static str> {
        loop {
            if STOP.load(Ordering::Relaxed) {
                return Ok("stop signal");
            }
            if Instant::now() >= deadline {
                return Ok("configured timeout");
            }
            if let Some(connect) = reverse.poll()? {
                tracing::warn!(
                    source_lu = ?connect.source.node,
                    destination_lu = ?connect.destination.node,
                    remote_ip = %remote_ip,
                    "unsupported reverse V5 Connect in flow lab"
                );
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "reverse V5 management Connect requires a responder",
                ));
            }
            observe_udp(&udp)?;
            let before = flow_snapshot(&edge);
            edge.poll_native_once()?;
            log_flow_change(&edge, before, "native", remote_ip);
            if edge.is_closed() {
                return Ok("native peer closed");
            }
            let before = flow_snapshot(&edge);
            edge.flush_tcp()?;
            log_flow_change(&edge, before, "tcp write", remote_ip);
            if edge.first_attach_delivery_complete() && !first_attach_seen {
                first_attach_seen = true;
                tracing::info!(
                    interface = %config.interface,
                    local_ip = %local_ip,
                    remote_ip = %remote_ip,
                    "first native Attach delivered; continuing V5 application flow"
                );
            }
            if flow_poll_tcp(first_attach_seen, edge.ipr_ack_outstanding()) {
                let before = flow_snapshot(&edge);
                match edge.poll_tcp_once() {
                    Ok(()) => log_flow_change(&edge, before, "tcp receive", remote_ip),
                    Err(error)
                        if error.kind() == io::ErrorKind::UnexpectedEof && first_attach_seen =>
                    {
                        return Ok("remote TCP peer closed");
                    }
                    Err(error) => return Err(error),
                }
            }
            observe_udp(&udp)?;
            thread::sleep(Duration::from_micros(200));
        }
    })();
    let close_result = edge.close();
    match outcome {
        Ok(reason) => {
            tracing::info!(reason, first_attach_seen, remote_ip = %remote_ip, "experimental V5 flow lab stopped");
            close_result?;
            if !first_attach_seen && reason != "stop signal" {
                return Err(io::Error::new(
                    if reason == "configured timeout" {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::ConnectionAborted
                    },
                    format!("V5 flow lab ended before first Attach delivery: {reason}"),
                ));
            }
            Ok(())
        }
        Err(error) => {
            tracing::error!(reason = %error, first_attach_seen, remote_ip = %remote_ip, "experimental V5 flow lab failed");
            let _ = close_result;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::fid2_session_control::ManagementBind;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn real_v5_template_matches_captured_nonvolatile_connect_profile() {
        let request = v5_template("SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        assert_eq!(request.processing, 0x0a);
        assert_eq!(request.ttl, 42);
        assert_eq!(request.correlator.len(), 8);
        assert_eq!(request.requirements.max_record, 0x8005);
        assert_eq!(request.requirements.max_expedited, 0x76);
        assert_eq!(request.requirements.max_termination, 0x76);
        assert_eq!(
            request
                .options
                .iter()
                .map(|option| option.kind)
                .collect::<Vec<_>>(),
            [0x05, 0x0a, 0x18, 0x19]
        );
        assert_eq!(request.options[0].value, [0x01, 0x01]);
        assert_eq!(request.options[2].value, [0x01]);
        assert_eq!(
            request.options[3].value,
            [0x00, 0x20, 0x01, 0x03, 0x10, 0x83]
        );
        assert_eq!(
            Connect::decode(&request.encode().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn real_v5_diagnostic_stops_on_udp_before_claiming_delivery() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(
                &[0, 0, 0, 10, 0x83, 0, 0, 0, 0, 6],
                receiver.local_addr().unwrap(),
            )
            .unwrap();
        assert_eq!(
            observe_udp(&receiver).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn flow_lab_continues_tcp_polling_after_first_attach_even_with_ipr_pending() {
        // The one-shot diagnostic holds TCP reads while the first native IPR
        // is outstanding. Once that Attach has completed, the flow lab must
        // keep reading so remote application data or Abort can make progress.
        assert!(!flow_poll_tcp(false, true));
        assert!(flow_poll_tcp(false, false));
        assert!(flow_poll_tcp(true, false));
        assert!(flow_poll_tcp(true, true));
    }

    #[test]
    fn reverse_v5_probe_decodes_one_connect_from_configured_peer() {
        let mut probe =
            ReverseConnectProbe::bind("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST).unwrap();
        let address = probe.listener.as_ref().unwrap().local_addr().unwrap();
        assert!(probe.poll().unwrap().is_none());
        let mut peer = TcpStream::connect(address).unwrap();
        let request = v5_template("SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        peer.write_all(&request.encode().unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let observed = loop {
            if let Some(connect) = probe.poll().unwrap() {
                break connect;
            }
            assert!(Instant::now() < deadline, "reverse Connect was not decoded");
            thread::yield_now();
        };
        assert_eq!(observed, request);
        assert!(probe.listener.is_none());
        assert!(probe.peer.is_none());
        assert!(probe.poll().unwrap().is_none());
    }

    #[test]
    fn reverse_v5_probe_rejects_first_record_from_wrong_source() {
        let mut probe =
            ReverseConnectProbe::bind("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(127, 0, 0, 2))
                .unwrap();
        let _peer =
            TcpStream::connect(probe.listener.as_ref().unwrap().local_addr().unwrap()).unwrap();
        assert_eq!(
            probe.poll().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn mock_keeps_tcp_open_after_attach_until_native_completion_gate() {
        let management_piu = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let management =
            ManagementBind::from_request(&management_piu, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let user_piu = hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260142222222222222222222222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        let mut connect = template("SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        connect.options[0].value = user_piu[4..].to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let (delivered_tx, delivered_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let mock = thread::spawn(move || {
            mock_peer(
                peer,
                management,
                Duration::from_secs(2),
                delivered_tx,
                shutdown_rx,
            )
        });
        client.write_all(&connect.encode().unwrap()).unwrap();
        let response = Connect::decode(&read_record(&mut client).unwrap()).unwrap();
        assert_eq!(response.direction, Direction::PositiveResponse);
        let mut normal = vec![0; 243];
        normal[..4].copy_from_slice(&243u32.to_be_bytes());
        normal[5..12].copy_from_slice(&[0, 1, 0x0b, 0x90, 0x20, 0x24, 0x05]);
        client.write_all(&normal).unwrap();
        assert_eq!(
            delivered_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            243
        );
        client
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let mut byte = [0];
        assert!(matches!(
            client.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        shutdown_tx.send(()).unwrap();
        mock.join().unwrap().unwrap();
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    }
}
