//! Pure V4R4 user-session path through the bounded LLC-to-TCP62 gateway.
//! This does not activate a runtime route or assert that UDP X'83' works.

use router_core::fid2_session_control::ManagementBind;
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_connect::{Address, Connect, Direction, OptionalField, TransportRequirements},
    mptn_gateway_edge::{GatewayEdge, NativeEvent, NativeLeg},
    mptn_native_bridge::{Bridge, Phase as BridgePhase},
    mptn_session::{BindPolicy, GatewaySession, Phase},
};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn ebcdic_lu(value: &str) -> Address {
    let node = value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'I' => 0xc1 + (byte - b'A'),
            b'J'..=b'R' => 0xd1 + (byte - b'J'),
            b'S'..=b'Z' => 0xe2 + (byte - b'S'),
            b'.' => 0x4b,
            _ => panic!("unsupported test LU name"),
        })
        .collect();
    Address { node }
}

fn policy() -> BindPolicy {
    BindPolicy {
        plu: "SOLNET.SNAA".into(),
        slu: "SOLNET.SNAB".into(),
        mode: None,
        allow_blank_mode: true,
        max_pending_bytes: MAX_RECORD,
    }
}

fn template() -> Connect {
    Connect {
        direction: Direction::Request,
        processing: 0x0a,
        ttl: 8,
        source: ebcdic_lu("SOLNET.SNAA"),
        destination: ebcdic_lu("SOLNET.SNAB"),
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
    }
}

fn user_bind() -> Vec<u8> {
    // V4R4 p71 user BIND: only FID2 addresses/ODAI and volatile identifiers
    // are normalized. Its blank/default mode and LU6.2 negotiation remain.
    let mut piu = vec![0x2d, 0, 1, 2];
    piu.extend(hex(concat!(
        "00006b850031001307b0b051330383c7c7830306020000000000000094434000",
        "0be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301235069de6780000c04",
        "e2d6d3d5c5e34be2d5c1c10a1300b0235069de678000000b",
        "e2d6d3d5c5e34be2d5c1c26014cec37477b5dbed8d0b",
        "e2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e3"
    )));
    piu
}

fn positive_response(request: &Connect) -> TcpRecord {
    let mut response = request.clone();
    response.direction = Direction::PositiveResponse;
    response.processing = 0x8a;
    // Sanitized V4R4 p78 RSP(BIND), including negotiated LU6.2 flags.
    response.options[0].value = hex(concat!(
        "0000eb800031001307b0b051330080c7c7800006020000000000000094434000",
        "002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20",
        "a1300b023506a33da800000006014cec37477b5dbed8d0b",
        "e2d6d3d5c5e34be2d5c1c1"
    ));
    TcpRecord::decode(response.encode().unwrap()).unwrap()
}

fn first_user_attach() -> Vec<u8> {
    // V4R4 p86/p51: TH/RH, FMH5 route fields and PIP lengths retained;
    // application-specific PIP body redacted.
    let mut piu = hex(concat!(
        "2c00010200010b9120",
        "240502ff0803d000400430f0f0f500140b",
        "e2d6d3d5c5e34be2d5c1c1",
        "0102030405060001",
        "00c512f500c112e2"
    ));
    piu.extend_from_slice(&[0; 189]);
    assert_eq!(piu.len(), 242);
    piu
}

fn next_user_normal() -> Vec<u8> {
    // Same user-session address/ODAI, next SNF, FM request with hop-local PI.
    hex("2c0001020002039120c1")
}

fn management_bind() -> ManagementBind {
    // Independent sanitized management BIND; FID2 address pair is kept
    // distinct from the normalized user session pair.
    let mut piu = hex(concat!(
        "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
        "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
        "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
        "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
        "2c0a00000000000000000000"
    ));
    piu[2..4].copy_from_slice(&[3, 4]);
    ManagementBind::from_request(&piu, "SOLNET.SNAA", "SOLNET.SNAB").unwrap()
}

#[test]
fn bind_connect_response_then_first_fmh5_normal_record() {
    // The full capability set is injected only to exercise pure conversion.
    // Runtime must derive this from installed handlers, not test fixtures.
    let mut session = GatewaySession::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
    )
    .unwrap();
    let bind = user_bind();
    let connect_record = session.begin_native_bind(&bind, template()).unwrap();
    assert_eq!(session.phase(), Phase::Opening);
    let connect = Connect::decode(&connect_record.bytes).unwrap();
    assert_eq!(connect.connection_data()[..5], [0, 0, 0x6b, 0x84, 0]);

    let bind_response = session
        .receive_connect_response(&positive_response(&connect))
        .unwrap();
    assert_eq!(session.phase(), Phase::Established);
    assert_eq!(
        &bind_response[..10],
        &[0x2d, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x31]
    );

    let attach = first_user_attach();
    assert!(session.native_normal(&attach).is_err());
    let (record, pacing_requested) = session.native_normal_observe_pacing(&attach).unwrap();
    assert!(pacing_requested);
    assert_eq!(record.kind, TcpKind::Normal);
    assert_eq!(record.bytes.len(), 243);
    assert_eq!(&record.bytes[5..8], &attach[4..7]);
    assert_eq!(record.bytes[8], attach[7] & !0x01);
    assert_eq!(&record.bytes[9..], &attach[8..]);
    assert_eq!(
        &record.bytes[7..16],
        &[0x0b, 0x90, 0x20, 0x24, 0x05, 0x02, 0xff, 0x08, 0x03]
    );
    assert_eq!(session.pending_bytes(), (243, 0));
    session.complete_tcp_delivery(243).unwrap();
    assert_eq!(session.pending_bytes(), (0, 0));
}

#[test]
fn missing_oob_handler_blocks_the_same_bind_before_connect() {
    let supported = CompensationSet::from_codes(&[0x00, 0x01, 0x03, 0x10, 0x20]).unwrap();
    let mut session = GatewaySession::new(policy(), supported).unwrap();
    assert!(session.begin_native_bind(&user_bind(), template()).is_err());
    assert_eq!(session.phase(), Phase::Idle);
}

#[test]
fn pure_bridge_waits_for_remote_bind_and_native_ack_before_attach() {
    let mut bridge = Bridge::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
        management_bind(),
        [0x30, 0xf0, 0xf0, 0xf5],
        1,
    )
    .unwrap();
    let attach = first_user_attach();
    assert!(bridge.first_attach(&attach).is_err());
    let connect_record = bridge.begin_native_bind(&user_bind(), template()).unwrap();
    assert_eq!(bridge.phase(), BridgePhase::AwaitConnect);
    assert!(bridge.first_attach(&attach).is_err());
    let connect = Connect::decode(&connect_record.bytes).unwrap();
    let local_response = bridge
        .accept_connect_response(&positive_response(&connect))
        .unwrap();
    assert_eq!(bridge.phase(), BridgePhase::NativeBindPrepared);
    assert_eq!(local_response[9 + 9], 1); // local fixed receive window
    assert_eq!(local_response[9 + 24], 0x23); // CONFIRM, no SYNCPT
    assert!(bridge.acknowledge_native_bind(1).is_err());
    assert!(bridge
        .mark_native_bind_enqueued(&local_response[..9])
        .is_err());
    bridge.mark_native_bind_enqueued(&local_response).unwrap();
    assert!(bridge.first_attach(&attach).is_err());
    bridge.acknowledge_native_bind(1).unwrap();
    let mut wrong_tp = attach.clone();
    wrong_tp[9 + 10] ^= 1;
    assert!(bridge.first_attach(&wrong_tp).is_err());
    assert_eq!(bridge.phase(), BridgePhase::Active);
    let (record, route) = bridge.first_attach(&attach).unwrap();
    assert_eq!(route.transaction_program, [0x30, 0xf0, 0xf0, 0xf5]);
    assert_eq!(record.bytes.len(), 243);
    assert_eq!(bridge.phase(), BridgePhase::AttachPrepared);
    let mut wrong_record = record.clone();
    wrong_record.bytes[9] ^= 1;
    assert!(bridge.mark_attach_enqueued(&wrong_record, 1).is_err());
    assert!(bridge.mark_attach_enqueued(&record, 0).is_err());
    let ipr = bridge.mark_attach_enqueued(&record, 1).unwrap();
    assert_eq!(ipr, hex("2d0002010000830100"));
    assert!(bridge.mark_ipr_enqueued(&ipr[..8]).is_err());
    bridge.mark_ipr_enqueued(&ipr).unwrap();
    bridge.complete_tcp_delivery(record.bytes.len()).unwrap();
    assert_eq!(bridge.phase(), BridgePhase::Active);
}

#[test]
fn pure_bridge_rejects_unavailable_oob_before_opening() {
    let mut bridge = Bridge::new(
        policy(),
        CompensationSet::from_codes(&[0x00, 0x01, 0x03, 0x10, 0x20]).unwrap(),
        management_bind(),
        [0x30, 0xf0, 0xf0, 0xf5],
        1,
    )
    .unwrap();
    assert!(bridge.begin_native_bind(&user_bind(), template()).is_err());
    assert_eq!(bridge.phase(), BridgePhase::Idle);
}

#[test]
fn post_attach_fm_request_preserves_credit_and_requires_native_pacing_grant() {
    let mut bridge = Bridge::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
        management_bind(),
        [0x30, 0xf0, 0xf0, 0xf5],
        1,
    )
    .unwrap();
    assert!(bridge.next_native_normal(&next_user_normal()).is_err());
    let connect_record = bridge.begin_native_bind(&user_bind(), template()).unwrap();
    let connect = Connect::decode(&connect_record.bytes).unwrap();
    let response = bridge
        .accept_connect_response(&positive_response(&connect))
        .unwrap();
    bridge.mark_native_bind_enqueued(&response).unwrap();
    bridge.acknowledge_native_bind(1).unwrap();
    let (attach, _) = bridge.first_attach(&first_user_attach()).unwrap();
    let ipr = bridge.mark_attach_enqueued(&attach, 1).unwrap();
    bridge.mark_ipr_enqueued(&ipr).unwrap();
    bridge.complete_tcp_delivery(attach.bytes.len()).unwrap();

    let mut wrong_session = next_user_normal();
    wrong_session[2] = 3;
    assert!(bridge.next_native_normal(&wrong_session).is_err());
    let mut dfc = next_user_normal();
    dfc[6] |= 0x40;
    assert!(bridge.next_native_normal(&dfc).is_err());
    let mut missing_pi = next_user_normal();
    missing_pi[7] &= !0x01;
    assert!(bridge.next_native_normal(&missing_pi).is_err());
    assert_eq!(bridge.pending_bytes(), (0, 0));

    let (record, pacing_requested) = bridge.next_native_normal(&next_user_normal()).unwrap();
    assert!(pacing_requested);
    assert_eq!(record.bytes, hex("0000000b000002039020c1"));
    assert_eq!(bridge.pending_bytes(), (11, 0));
    let mut wrong_record = record.clone();
    wrong_record.bytes[10] ^= 1;
    assert!(bridge.mark_normal_enqueued(&wrong_record, 1).is_err());
    assert_eq!(bridge.phase(), BridgePhase::NormalPrepared);
    assert_eq!(
        bridge.mark_normal_enqueued(&record, 0).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let ipr = bridge.mark_normal_enqueued(&record, 1).unwrap().unwrap();
    assert_eq!(ipr, hex("2d0002010000830100"));
    assert!(bridge.mark_ipr_enqueued(&ipr[..8]).is_err());
    bridge.mark_ipr_enqueued(&ipr).unwrap();
    bridge.complete_tcp_delivery(record.bytes.len()).unwrap();
    assert_eq!(bridge.pending_bytes(), (0, 0));
    assert_eq!(bridge.phase(), BridgePhase::Active);
}

#[test]
fn gateway_tcp_credit_releases_after_complete_socket_write() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut receiver, _) = listener.accept().unwrap();
    let mut transport = TcpSession::new(sender).unwrap();

    let mut gateway = GatewaySession::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
    )
    .unwrap();
    let connect_record = gateway.begin_native_bind(&user_bind(), template()).unwrap();
    let connect = Connect::decode(&connect_record.bytes).unwrap();
    gateway
        .receive_connect_response(&positive_response(&connect))
        .unwrap();
    let (record, pacing_requested) = gateway
        .native_normal_observe_pacing(&first_user_attach())
        .unwrap();
    assert!(pacing_requested);
    assert_eq!(gateway.pending_bytes(), (record.bytes.len(), 0));
    transport.queue(record.clone()).unwrap();
    assert_eq!(gateway.pending_bytes(), (record.bytes.len(), 0));

    let mut completed = Vec::new();
    transport
        .flush_with_completion(|bytes| completed.push(bytes))
        .unwrap();
    assert_eq!(completed, [record.bytes.len()]);
    for bytes in &completed {
        gateway.complete_tcp_delivery(*bytes).unwrap();
    }
    assert_eq!(gateway.pending_bytes(), (0, 0));
    let mut received = vec![0; record.bytes.len()];
    receiver.read_exact(&mut received).unwrap();
    assert_eq!(received, record.bytes);
    transport
        .flush_with_completion(|bytes| completed.push(bytes))
        .unwrap();
    assert_eq!(completed.len(), 1);
}

#[derive(Default)]
struct MockNative {
    events: VecDeque<NativeEvent>,
    sent: Vec<Vec<u8>>,
    ingress_capacity: Vec<bool>,
    accepts: bool,
    closed: bool,
}

impl NativeLeg for MockNative {
    fn receive_once(&mut self, can_accept_information: bool) -> io::Result<Option<NativeEvent>> {
        self.ingress_capacity.push(can_accept_information);
        Ok(self.events.pop_front())
    }
    fn enqueue(&mut self, piu: &[u8]) -> io::Result<bool> {
        if self.accepts {
            self.sent.push(piu.to_vec());
        }
        Ok(self.accepts)
    }
    fn available_slots(&self) -> usize {
        usize::from(self.accepts)
    }
    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

fn read_record(stream: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let len = u32::from_be_bytes(prefix) as usize;
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut bytes[4..]).unwrap();
    bytes
}

#[test]
fn unregistered_edge_uses_typed_native_events_and_socket_completions() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let bridge = Bridge::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
        management_bind(),
        [0x30, 0xf0, 0xf0, 0xf5],
        1,
    )
    .unwrap();
    let mut native = MockNative {
        accepts: true,
        ..Default::default()
    };
    native.events.push_back(NativeEvent::UserBind(user_bind()));
    let mut edge = GatewayEdge::new(native, TcpSession::new(sender).unwrap(), bridge, template());

    edge.poll_native_once().unwrap();
    assert_eq!(edge.phase(), BridgePhase::AwaitConnect);
    edge.flush_tcp().unwrap();
    let connect = Connect::decode(&read_record(&mut peer)).unwrap();
    peer.write_all(&positive_response(&connect).bytes).unwrap();
    edge.native_mut().accepts = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while edge.phase() == BridgePhase::AwaitConnect && Instant::now() < deadline {
        edge.poll_tcp_once().unwrap();
        std::thread::yield_now();
    }
    assert_eq!(edge.phase(), BridgePhase::NativeBindPrepared);
    assert!(edge.native_mut().sent.is_empty()); // Native backpressure.
    edge.native_mut().accepts = true;
    edge.poll_native_once().unwrap();
    assert_eq!(edge.phase(), BridgePhase::AwaitNativeBindAck);
    assert_eq!(edge.native_mut().sent.len(), 1);

    edge.native_mut()
        .events
        .push_back(NativeEvent::BindResponseAck(1));
    edge.poll_native_once().unwrap();
    assert_eq!(edge.phase(), BridgePhase::Active);
    edge.native_mut()
        .events
        .push_back(NativeEvent::FirstAttach(first_user_attach()));
    edge.poll_native_once().unwrap();
    assert_eq!(edge.pending_gateway_bytes(), (243, 0));
    // The first Attach is held for TCP delivery. A later native information
    // frame must not be LLC-acknowledged while this edge has no APPC handler.
    edge.poll_native_once().unwrap();
    assert_eq!(edge.native_mut().ingress_capacity.last(), Some(&false));
    assert_eq!(edge.native_mut().sent[1], hex("2d0002010000830100"));
    assert!(edge.ipr_ack_outstanding());
    assert!(!edge.first_attach_delivery_complete());
    edge.flush_tcp().unwrap();
    assert_eq!(edge.pending_gateway_bytes(), (0, 0));
    assert!(!edge.first_attach_delivery_complete());
    let normal = TcpRecord::decode(read_record(&mut peer)).unwrap();
    assert_eq!(normal.kind, TcpKind::Normal);
    assert_eq!(normal.bytes.len(), 243);

    edge.native_mut()
        .events
        .push_back(NativeEvent::EgressAck(1));
    edge.poll_native_once().unwrap();
    assert!(!edge.ipr_ack_outstanding());
    assert!(edge.first_attach_delivery_complete());
    edge.native_mut()
        .events
        .push_back(NativeEvent::EgressAck(1));
    assert!(edge.poll_native_once().is_err()); // Duplicate ACK aborts the edge.
    assert!(edge.is_closed());
    assert!(!edge.first_attach_delivery_complete());
    assert!(edge.native_mut().closed);
}

#[test]
fn gateway_rejects_connect_response_before_request_reaches_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut independent_gateway = GatewaySession::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
    )
    .unwrap();
    let expected_connect = independent_gateway
        .begin_native_bind(&user_bind(), template())
        .unwrap();
    let response = positive_response(&Connect::decode(&expected_connect.bytes).unwrap());
    let bridge = Bridge::new(
        policy(),
        CompensationSet::from_codes(&TCP62_REQUIRED).unwrap(),
        management_bind(),
        [0x30, 0xf0, 0xf0, 0xf5],
        1,
    )
    .unwrap();
    let mut native = MockNative {
        accepts: true,
        ..Default::default()
    };
    native.events.push_back(NativeEvent::UserBind(user_bind()));
    let mut edge = GatewayEdge::new(native, TcpSession::new(sender).unwrap(), bridge, template());
    edge.poll_native_once().unwrap(); // Queues Connect, but does not write it.
    assert_eq!(edge.phase(), BridgePhase::AwaitConnect);
    let mut scratch = [0; 1];
    assert!(matches!(
        peer.read(&mut scratch).unwrap_err().kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));

    peer.write_all(&response.bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let error = loop {
        match edge.poll_tcp_once() {
            Err(error) => break error,
            Ok(()) => assert!(Instant::now() < deadline, "early response was not rejected"),
        }
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(edge.is_closed());
    assert!(edge.native_mut().closed);
    assert!(edge.native_mut().sent.is_empty());
}
