//! Replay the direct V5R4 RouteSetup reply through a locally originated RTP
//! connection, then use the authorized directional labels for a user BIND.

use router_core::{
    hpr_control_bootstrap::{
        encode_network_name_component, ControlAdvertisement, HprControlBootstrap,
    },
    hpr_cv61::{ArbMode, ControlFlowsTower},
    hpr_fid5::encode_whole_biu,
    hpr_route_setup_initiator::{DirectLinkMetrics, DirectRouteSetupInitiator},
    hpr_rtp::RtpPacket,
    hpr_rtp_outbound::{OutboundPhase, RtpOutboundEndpoint},
    hpr_rtp_outbound_setup::UserSetupConfig,
    hpr_rtp_reply::{encode_setup_reply, CallerStatus, ReplyPath},
    hpr_rtp_setup::{classify_setup_topic, RtpSetupTopic},
    session::{Flow, SessionUnit},
    ConnectionGeneration,
};

const ASSIGNOR: u64 = 1 << 63;
const ROUTE_TCID: u64 = ASSIGNOR | 0x1234;
const USER_TCID: u64 = ASSIGNOR | 0x1235;
const REPLY: &str = "009412ce8001a0000003a980000000001a800000000005b500000114000010cc000000000667040080021660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e30e0ef4e2d6d3d5c5e34be2d5c1c20426a400063900000004162b010012461080010be2d6d3d5c5e34be2d5c1c1211a808000000005b500000114000010cc00000000066704008002";

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn advertisement(cp: &str, node: u8) -> ControlAdvertisement {
    ControlAdvertisement {
        cp: cp.parse().unwrap(),
        node_id: [0, 0, 0, node],
        hpr_sap: 0xc8,
        link_label: vec![0x80, 2],
        tower: ControlFlowsTower {
            max_send_packet_size: 1461,
            path_switch_time_ms: 60_000,
            mobile: false,
            multilink_tg: false,
            arb_mode: ArbMode::Responsive,
            cp_nce_instance: [0, 0, 0, 4],
            route_setup_nce_instance: [0, 0, 0, 4],
            cp_nce_label: vec![0xa4, 0],
            route_setup_nce_label: vec![0xa4, 0],
        },
    }
}

fn user_bind() -> Vec<u8> {
    let name = |value: &str| {
        let (netid, lu) = value.split_once('.').unwrap();
        let mut result = encode_network_name_component(netid).unwrap();
        result.push(0x4b);
        result.extend_from_slice(&encode_network_name_component(lu).unwrap());
        result
    };
    let plu = name("SOLNET.SNAA");
    let slu = name("SOLNET.SNAB");
    let mut ru = vec![0; 27];
    ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
    ru[14..16].copy_from_slice(&[6, 2]);
    ru.push(plu.len() as u8);
    ru.extend_from_slice(&plu);
    ru.extend_from_slice(&[1, 0, 0]);
    ru.push(slu.len() as u8);
    ru.extend_from_slice(&slu);
    let mut reduced = vec![0x80, 1, 0x6b, 0x80, 0];
    reduced.extend_from_slice(&ru);
    encode_whole_biu(
        (ASSIGNOR | 0x3456).to_be_bytes(),
        Flow::Expedited,
        &SessionUnit::from_reduced(&reduced).unwrap(),
    )
    .unwrap()
}

fn peer_reply(origin: u64, rseq: u32, local_label: &[u8], priority: u8) -> Vec<u8> {
    encode_setup_reply(
        origin,
        ASSIGNOR | ((origin & !ASSIGNOR) + 0x1000),
        ReplyPath {
            anr_label: local_label,
            priority,
        },
        CallerStatus {
            sync: 0,
            echo: 0,
            rseq,
            outbound_bsn: 0,
        },
    )
    .unwrap()
}

fn peer_data(origin: u64, local_label: &[u8], priority: u8, data: &[u8]) -> Vec<u8> {
    let mut nlp = vec![0xc0 | (priority << 1), 0];
    nlp.extend_from_slice(local_label);
    nlp.extend_from_slice(&[0xff, 0]);
    nlp.extend_from_slice(&(origin & !ASSIGNOR).to_be_bytes());
    nlp.extend_from_slice(&[0x30, 0, 0, 5]);
    nlp.extend_from_slice(&(data.len() as u32).to_be_bytes());
    nlp.extend_from_slice(&0u32.to_be_bytes());
    nlp.extend_from_slice(data);
    nlp
}

#[test]
fn route_reply_authorizes_user_rtp_bind_to_same_guest() {
    let generation = ConnectionGeneration::new(1).unwrap();
    let bootstrap = HprControlBootstrap::new(
        generation,
        advertisement("SOLNET.SNAA", 1),
        advertisement("SOLNET.SNAB", 2),
    )
    .unwrap();
    let mut route = DirectRouteSetupInitiator::new(
        bootstrap.clone(),
        "SOLNET.SNAB".parse().unwrap(),
        1,
        [0xce, 0xc3, 0x74, 0x77, 0xb5, 0xdc, 0x29, 0x97],
        vec![0xa4, 1],
        [0, 0, 0, 5],
        DirectLinkMetrics {
            transmission_time_us: 276,
            capacity_kbps: 4300,
            liveness_seconds: 0,
        },
    )
    .unwrap();
    let request = route.request().to_vec();
    let mut route_rtp =
        RtpOutboundEndpoint::new_route_setup(bootstrap.clone(), 1, ROUTE_TCID).unwrap();
    let setup = route_rtp.prepare_setup(&request).unwrap();
    assert_eq!(
        classify_setup_topic(RtpPacket::parse(&setup).unwrap()).unwrap(),
        RtpSetupTopic::RouteSetup
    );
    route_rtp.confirm_setup_sent(&setup, 1_000).unwrap();
    route.confirm_request_sent(&request).unwrap();
    let reply = peer_reply(
        ROUTE_TCID,
        RtpPacket::parse(&setup)
            .unwrap()
            .next_byte_sequence_number(),
        &bootstrap.local.tower.route_setup_nce_label,
        3,
    );
    let status = route_rtp.prepare_reply_status(&reply).unwrap();
    route_rtp.confirm_status_sent(&status).unwrap();
    assert_eq!(route_rtp.phase(), OutboundPhase::Active);
    let delivered = route_rtp
        .receive(&peer_data(
            ROUTE_TCID,
            &bootstrap.local.tower.route_setup_nce_label,
            3,
            &unhex(REPLY),
        ))
        .unwrap();
    assert_eq!(delivered.messages.len(), 1);
    let authorized = route
        .observe_reply(generation, &delivered.messages[0])
        .unwrap();
    let config = UserSetupConfig {
        local_nce_label: authorized.local_user_nce_label,
        local_nce_instance: authorized.local_user_nce_instance,
        peer_nce_label: authorized.peer_user_nce_label,
        peer_nce_instance: authorized.peer_user_nce_instance,
        peer_link_label: authorized.peer_link_label,
        cos_tpf: authorized.cos_tpf,
        target_lu: authorized.target_lu.to_string(),
        maximum_packet_size: authorized.maximum_packet_size,
    };
    let mut user_rtp = RtpOutboundEndpoint::new_user(bootstrap, 1, USER_TCID, config).unwrap();
    let bind = user_bind();
    let user_setup = user_rtp.prepare_setup(&bind).unwrap();
    let packet = RtpPacket::parse(&user_setup).unwrap();
    assert_eq!(
        classify_setup_topic(packet).unwrap(),
        RtpSetupTopic::User {
            cos_tpf: vec![12, 0x2c, 1, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3]
        }
    );
    assert_eq!(packet.data, bind);
    user_rtp.confirm_setup_sent(&user_setup, 2_000).unwrap();
    let reply = peer_reply(USER_TCID, packet.next_byte_sequence_number(), &[0xa4, 1], 1);
    let status = user_rtp.prepare_reply_status(&reply).unwrap();
    user_rtp.confirm_status_sent(&status).unwrap();
    assert_eq!(user_rtp.phase(), OutboundPhase::Active);
}
