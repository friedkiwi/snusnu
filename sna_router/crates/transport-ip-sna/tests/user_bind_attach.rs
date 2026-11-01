//! Pure V4R4 user-session path through the bounded LLC-to-TCP62 gateway.
//! This does not activate a runtime route or assert that UDP X'83' works.

use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord, MAX_RECORD},
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_connect::{Address, Connect, Direction, OptionalField, TransportRequirements},
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
    // V4R4 first user-session normal PIU: TH/RH and 36-byte FMH5 shape are
    // retained; the following application/conversation bytes are redacted.
    let mut piu = vec![0x2c, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20];
    piu.extend_from_slice(&[0x24, 0x05, 0x02, 0xff, 0x08, 0x03, 0xd0]);
    piu.resize(242, 0);
    piu
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
