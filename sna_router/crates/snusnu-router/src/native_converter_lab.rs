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
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_connect::{Address, Connect, Direction, OptionalField, TransportRequirements},
    mptn_gateway_edge::GatewayEdge,
    mptn_native_bridge::Bridge,
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

fn mock_peer(
    mut stream: TcpStream,
    management: router_core::fid2_session_control::ManagementBind,
    timeout: Duration,
) -> io::Result<usize> {
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
    Ok(normal.bytes.len())
}

pub(crate) fn run(path: &Path) -> io::Result<()> {
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
            "mock converter fixture requires user LU pair equal configured CP pair",
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
    tracing::warn!(interface = %config.interface, "isolated native converter mock harness opened; no production route advertised");
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
            "mock converter did not receive APPN management BIND",
        ));
    }
    let management = native
        .management_bind()
        .ok_or_else(|| invalid("management BIND missing"))?
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let sender = TcpStream::connect(listener.local_addr()?)?;
    let (peer, _) = listener.accept()?;
    let timeout = Duration::from_secs(config.timeout_seconds);
    let mut mock = Some(thread::spawn(move || mock_peer(peer, management, timeout)));
    let mut mock_bytes = None;
    // All six codes are injected only because this peer is an in-process
    // mock on loopback. Never derive production handler availability here.
    let policy = BindPolicy {
        plu: user_plu.clone(),
        slu: user_slu.clone(),
        mode: None,
        allow_blank_mode: true,
        max_pending_bytes: MAX_RECORD,
    };
    let bridge = Bridge::new(
        policy,
        CompensationSet::from_codes(&TCP62_REQUIRED).map_err(|error| invalid(error.to_string()))?,
        native.management_bind().unwrap().clone(),
        tp,
        1,
    )?;
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
        if mock.as_ref().is_some_and(|handle| handle.is_finished()) {
            mock_bytes = Some(
                mock.take()
                    .unwrap()
                    .join()
                    .map_err(|_| invalid("mock TCP62 peer panicked"))??,
            );
        }
        if mock_bytes.is_some() && edge.first_attach_delivery_complete() {
            break;
        }
        thread::sleep(Duration::from_micros(200));
    }
    if !edge.first_attach_delivery_complete() || mock_bytes.is_none() {
        edge.close()?;
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
    Ok(())
}
