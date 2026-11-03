//! One qualified outbound CPSVCMG RTP setup for the reciprocal CP-CP session.
//!
//! Identifiers and ANR labels come from the active, validated EE XID3 pair.
//! The caller owns UDP peer/SAP validation, TCID allocation, retransmission,
//! STATUS+CIE processing, and the CP-CP BIND transaction.

use crate::{
    fid2_bind::BindClass,
    hpr_control_bootstrap::{encode_network_name_component, HprControlBootstrap},
    hpr_fid5::Fid5WholeBiu,
    hpr_route_setup::{RouteSetupGds, RouteSetupKind},
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const CPSVCMG: [u8; 7] = [0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
const RSETUP: [u8; 6] = [0xd9, 0xe2, 0xc5, 0xe3, 0xe4, 0xd7];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSetupError {
    InvalidTg,
    InvalidTcid,
    InvalidIdentity,
    InvalidBind,
    InvalidRouteSetup,
    TooLarge,
}

/// Encode a direct Route Setup request as the first message of a locally
/// originated RTP connection to the adjacent peer's Route Setup tower.
/// The GDS must already be constructed from the active XID/TG agreement.
pub fn encode_route_setup_setup(
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
    origin_tcid: u64,
    request: &[u8],
) -> Result<Vec<u8>, OutboundSetupError> {
    let gds = RouteSetupGds::parse(request).map_err(|_| OutboundSetupError::InvalidRouteSetup)?;
    if gds.kind != RouteSetupKind::Request
        || gds.path_switch
        || gds.origin_cp_name != bootstrap.local.cp.to_string()
        || gds.destination_lu_name.as_ref().is_none_or(|name| {
            name.split_once('.').map(|(netid, _)| netid) != Some(bootstrap.peer.cp.netid.as_str())
        })
    {
        return Err(OutboundSetupError::InvalidRouteSetup);
    }
    let mut topic = vec![0];
    topic.extend_from_slice(&RSETUP);
    encode_setup(
        bootstrap,
        tg_number,
        origin_tcid,
        request,
        SetupWire {
            local_nce_label: &bootstrap.local.tower.route_setup_nce_label,
            local_nce_instance: &bootstrap.local.tower.route_setup_nce_instance,
            peer_nce_label: &bootstrap.peer.tower.route_setup_nce_label,
            peer_nce_instance: &bootstrap.peer.tower.route_setup_nce_instance,
            peer_link_label: &bootstrap.peer.link_label,
            topic,
            priority: 3,
            user: false,
            maximum_packet_size: bootstrap.max_packet_size,
        },
    )
}

/// RouteSetup-authorized values for a locally originated LU RTP connection.
/// Both NCEs are directional: `local_nce_label` receives peer traffic and
/// `peer_nce_label` is the destination of our NLPs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSetupConfig {
    pub local_nce_label: Vec<u8>,
    pub local_nce_instance: [u8; 4],
    pub peer_nce_label: Vec<u8>,
    pub peer_nce_instance: [u8; 4],
    pub peer_link_label: Vec<u8>,
    /// Complete LT-encoded COS/TPF X'2C' vector from the validated route.
    pub cos_tpf: Vec<u8>,
    pub target_lu: String,
    /// Maximum NLP size granted by the positive RouteSetup reverse path.
    pub maximum_packet_size: u16,
}

impl UserSetupConfig {
    pub fn priority(&self) -> Result<u8, OutboundSetupError> {
        if self.cos_tpf.len() < 3
            || usize::from(self.cos_tpf[0]) != self.cos_tpf.len()
            || self.cos_tpf[1] != 0x2c
            || self.cos_tpf[2] & !0x07 != 0
            || self.cos_tpf[2] & 3 == 3
        {
            return Err(OutboundSetupError::InvalidIdentity);
        }
        Ok(if self.cos_tpf[2] & 4 != 0 {
            3
        } else {
            self.cos_tpf[2] & 3
        })
    }
}

struct SetupWire<'a> {
    local_nce_label: &'a [u8],
    local_nce_instance: &'a [u8; 4],
    peer_nce_label: &'a [u8],
    peer_nce_instance: &'a [u8; 4],
    peer_link_label: &'a [u8],
    topic: Vec<u8>,
    priority: u8,
    user: bool,
    maximum_packet_size: u16,
}

/// Encode the first RTP NLP, beginning at NHDR, with BSN zero and the whole
/// FID5 CPSVCMG BIND as its first complete message. `origin_tcid` is locally
/// allocated and has the assignor bit set. No EE UI header is included.
pub fn encode_cp_setup(
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
    origin_tcid: u64,
    bind: &[u8],
) -> Result<Vec<u8>, OutboundSetupError> {
    let fid5 = Fid5WholeBiu::parse_complete(bind).map_err(|_| OutboundSetupError::InvalidBind)?;
    let identity = fid5
        .classify_bind()
        .map_err(|_| OutboundSetupError::InvalidBind)?
        .ok_or(OutboundSetupError::InvalidBind)?;
    if identity.class
        != (BindClass::Management {
            mode: "CPSVCMG".into(),
        })
        || identity.plu != bootstrap.local.cp.to_string()
        || identity.slu != bootstrap.peer.cp.to_string()
    {
        return Err(OutboundSetupError::InvalidBind);
    }
    let mut topic = vec![0];
    topic.extend_from_slice(&CPSVCMG);
    encode_setup(
        bootstrap,
        tg_number,
        origin_tcid,
        bind,
        SetupWire {
            local_nce_label: &bootstrap.local.tower.cp_nce_label,
            local_nce_instance: &bootstrap.local.tower.cp_nce_instance,
            peer_nce_label: &bootstrap.peer.tower.cp_nce_label,
            peer_nce_instance: &bootstrap.peer.tower.cp_nce_instance,
            peer_link_label: &bootstrap.peer.link_label,
            topic,
            priority: 3,
            user: false,
            maximum_packet_size: bootstrap.max_packet_size,
        },
    )
}

/// Encode a complete, RouteSetup-authorized user BIND as the first RTP NLP.
/// The caller must validate the route and bind the NCE labels to that route.
pub fn encode_user_setup(
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
    origin_tcid: u64,
    bind: &[u8],
    config: &UserSetupConfig,
) -> Result<Vec<u8>, OutboundSetupError> {
    let fid5 = Fid5WholeBiu::parse_complete(bind).map_err(|_| OutboundSetupError::InvalidBind)?;
    let identity = fid5
        .classify_bind()
        .map_err(|_| OutboundSetupError::InvalidBind)?
        .ok_or(OutboundSetupError::InvalidBind)?;
    let external_cp_management = matches!(
        &identity.class,
        BindClass::Management { mode } if mode == "SNASVCMG"
            && identity.slu == bootstrap.peer.cp.to_string()
    );
    if (matches!(identity.class, BindClass::Management { .. }) && !external_cp_management)
        || identity.slu != config.target_lu
        || identity.slu.split_once('.').map(|(netid, _)| netid)
            != Some(bootstrap.peer.cp.netid.as_str())
    {
        return Err(OutboundSetupError::InvalidBind);
    }
    let priority = config.priority()?;
    if config.local_nce_label.is_empty()
        || config.local_nce_label.len() > 8
        || config.peer_nce_label.is_empty()
        || config.peer_nce_label.len() > 8
        || config.peer_link_label.is_empty()
        || config.peer_link_label.len() > 8
    {
        return Err(OutboundSetupError::InvalidIdentity);
    }
    let mut topic = vec![0x80];
    topic.extend_from_slice(&config.cos_tpf);
    encode_setup(
        bootstrap,
        tg_number,
        origin_tcid,
        bind,
        SetupWire {
            local_nce_label: &config.local_nce_label,
            local_nce_instance: &config.local_nce_instance,
            peer_nce_label: &config.peer_nce_label,
            peer_nce_instance: &config.peer_nce_instance,
            peer_link_label: &config.peer_link_label,
            topic,
            priority,
            user: true,
            maximum_packet_size: config.maximum_packet_size,
        },
    )
}

fn encode_setup(
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
    origin_tcid: u64,
    bind: &[u8],
    wire: SetupWire<'_>,
) -> Result<Vec<u8>, OutboundSetupError> {
    if tg_number == 0 {
        return Err(OutboundSetupError::InvalidTg);
    }
    if wire.maximum_packet_size == 0 || wire.maximum_packet_size > bootstrap.max_packet_size {
        return Err(OutboundSetupError::InvalidIdentity);
    }
    if origin_tcid & (ASSIGNOR | RESERVED) != ASSIGNOR || origin_tcid & !(ASSIGNOR | RESERVED) == 0
    {
        return Err(OutboundSetupError::InvalidTcid);
    }
    let local_netid = component(&bootstrap.local.cp.netid)?;
    let local_cp = component(&bootstrap.local.cp.name)?;
    let peer_netid = component(&bootstrap.peer.cp.netid)?;
    let peer_cp = component(&bootstrap.peer.cp.name)?;

    let mut qualifier = vec![0, 0x05, 0x80, 0];
    append_cv(&mut qualifier, 0x03, &local_netid)?;
    append_cv(&mut qualifier, 0x00, &local_cp)?;
    append_cv(&mut qualifier, 0x26, wire.local_nce_label)?;
    append_cv(&mut qualifier, 0x39, wire.local_nce_instance)?;
    // CV05's LT length excludes the final nested CV39's two word-padding
    // bytes, while those bytes still align the following X0D segment. The
    // preserved V5R4 qualified setup uses length 0x1e followed by two zeroes.
    qualifier[0] = u8::try_from(qualifier.len() - 2).map_err(|_| OutboundSetupError::TooLarge)?;
    align4(&mut qualifier);

    let mut cs = vec![0, 0x0d, 1, 1, 0x98, 0, 0, 0];
    append_cv(&mut cs, 0x28, &wire.topic)?;
    append_cv(&mut cs, 0x03, &peer_netid)?;
    append_cv(&mut cs, 0x00, &peer_cp)?;
    append_cv(&mut cs, 0x39, wire.peer_nce_instance)?;
    finish_segment(&mut cs)?;

    let mut si = vec![0, 0x14, 0, 0];
    let mut cv83 = vec![if wire.user { 0xb8 } else { 0xa8 }, 0];
    cv83.extend_from_slice(&u32::from(wire.maximum_packet_size).to_be_bytes());
    cv83.extend_from_slice(&bootstrap.local.tower.path_switch_time_ms.to_be_bytes());
    cv83.extend_from_slice(&180u32.to_be_bytes());
    cv83.extend_from_slice(&[
        u8::try_from(4 + wire.peer_link_label.len()).map_err(|_| OutboundSetupError::TooLarge)?,
        0x67,
        u8::try_from(2 + wire.peer_link_label.len()).map_err(|_| OutboundSetupError::TooLarge)?,
        0,
    ]);
    cv83.extend_from_slice(wire.peer_link_label);
    append_cv(&mut si, 0x83, &cv83)?;

    let mut fq_local = local_netid;
    fq_local.push(0x4b);
    fq_local.extend_from_slice(&local_cp);
    let mut descriptor = vec![
        0,
        0x80,
        tg_number,
        u8::try_from(fq_local.len()).map_err(|_| OutboundSetupError::TooLarge)?,
    ];
    descriptor.extend_from_slice(&fq_local);
    descriptor.push(0x21);
    descriptor.extend_from_slice(&[0; 4]);
    descriptor[0] = u8::try_from(descriptor.len()).map_err(|_| OutboundSetupError::TooLarge)?;
    let mut cv85 = vec![0, 1, 0, 0x46];
    cv85.extend_from_slice(&descriptor);
    cv85[2] = u8::try_from(cv85.len() - 2).map_err(|_| OutboundSetupError::TooLarge)?;
    append_cv(&mut si, 0x85, &cv85)?;
    finish_segment(&mut si)?;

    // Captured Base ARB initial operating range: 4 ms nominal, 40 ms upper,
    // conservative 4.3 Mbps reverse capacity, 276 us transmission time.
    let arb: [u8; 20] = [
        5, 0x22, 0, 0, 0, 0, 0x0f, 0xa0, 0, 0, 0x9c, 0x40, 0, 0, 0x10, 0xcc, 0, 0, 1, 0x14,
    ];
    let mut thdr = Vec::new();
    thdr.extend_from_slice(&origin_tcid.to_be_bytes());
    thdr.extend_from_slice(&[0x7c, 0x0c, 0, 0]); // SOM/EOM, qualifier and optional segments.
    thdr.extend_from_slice(&(bind.len() as u32).to_be_bytes());
    thdr.extend_from_slice(&0u32.to_be_bytes()); // Initial byte sequence number.
    thdr.extend_from_slice(&qualifier);
    thdr.extend_from_slice(&cs);
    thdr.extend_from_slice(&si);
    thdr.extend_from_slice(&arb);
    if !thdr.len().is_multiple_of(4) || thdr.len() / 4 > u16::MAX as usize {
        return Err(OutboundSetupError::TooLarge);
    }
    let data_offset_words = (thdr.len() / 4) as u16;
    thdr[10..12].copy_from_slice(&data_offset_words.to_be_bytes());
    let mut nlp = vec![0xc0 | (wire.priority << 1), 8];
    nlp.extend_from_slice(wire.peer_nce_label);
    nlp.extend_from_slice(&[0xff, 0]);
    nlp.extend_from_slice(&thdr);
    nlp.extend_from_slice(bind);
    if nlp.len() > usize::from(wire.maximum_packet_size) {
        return Err(OutboundSetupError::TooLarge);
    }
    Ok(nlp)
}

fn component(value: &str) -> Result<Vec<u8>, OutboundSetupError> {
    encode_network_name_component(value).map_err(|_| OutboundSetupError::InvalidIdentity)
}

fn append_cv(parent: &mut Vec<u8>, key: u8, value: &[u8]) -> Result<(), OutboundSetupError> {
    parent.push(u8::try_from(value.len() + 2).map_err(|_| OutboundSetupError::TooLarge)?);
    parent.push(key);
    parent.extend_from_slice(value);
    align4(parent);
    Ok(())
}

fn align4(value: &mut Vec<u8>) {
    while !value.len().is_multiple_of(4) {
        value.push(0);
    }
}

fn finish_segment(segment: &mut Vec<u8>) -> Result<(), OutboundSetupError> {
    align4(segment);
    segment[0] = u8::try_from(segment.len() / 4).map_err(|_| OutboundSetupError::TooLarge)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cp_initiator::ReciprocalCpSession,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        hpr_fid5::encode_whole_biu,
        hpr_rtp::RtpPacket,
        hpr_rtp_setup::{classify_setup_topic, RtpSetupTopic},
        hpr_switching_path::{validate_inbound_switching_path, AuthorizedUserRoute},
        session::{Flow, QualifiedName, SessionUnit},
        ConnectionGeneration,
    };

    fn advertisement(
        cp: &str,
        node_id: u8,
        link: &[u8],
        label: &[u8],
        instance: [u8; 4],
    ) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse::<QualifiedName>().unwrap(),
            node_id: [0, 0, 0, node_id],
            hpr_sap: 4,
            link_label: link.to_vec(),
            tower: ControlFlowsTower {
                max_send_packet_size: 1461,
                path_switch_time_ms: 60_000,
                mobile: false,
                multilink_tg: false,
                arb_mode: ArbMode::Base,
                cp_nce_instance: instance,
                route_setup_nce_instance: instance,
                cp_nce_label: label.to_vec(),
                route_setup_nce_label: label.to_vec(),
            },
        }
    }

    fn bind_with_mode(plu: &str, slu: &str, mode: Option<&str>) -> Vec<u8> {
        let name = |value: &str| {
            let (netid, lu) = value.split_once('.').unwrap();
            let mut value = encode_network_name_component(netid).unwrap();
            value.push(0x4b);
            value.extend_from_slice(&encode_network_name_component(lu).unwrap());
            value
        };
        let plu = name(plu);
        let slu = name(slu);
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        ru.push(plu.len() as u8);
        ru.extend_from_slice(&plu);
        if let Some(mode) = mode {
            let encoded = encode_network_name_component(mode).unwrap();
            ru.push((encoded.len() + 3) as u8);
            ru.extend_from_slice(&[0, (encoded.len() + 1) as u8, 2]);
            ru.extend_from_slice(&encoded);
        } else {
            ru.extend_from_slice(&[1, 0]);
        }
        ru.push(0); // no user request correlation data
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

    #[test]
    fn reciprocal_cp_setup_is_valid_from_live_guest_perspective() {
        let local = advertisement(
            "SNUSNU.SVC",
            2,
            &[0x80, 0x80],
            &[0xa4, 0x80],
            [0xff, 0xf2, 0xc4, 0x80],
        );
        let guest = advertisement("SOLNET.SNAB", 1, &[0x80, 2], &[0xa4, 0], [0, 0, 0, 7]);
        let generation = ConnectionGeneration::new(1).unwrap();
        let bootstrap = HprControlBootstrap::new(generation, local.clone(), guest.clone()).unwrap();
        let bind = ReciprocalCpSession::new(bootstrap.clone(), 0x0102_0304_0506_0708).unwrap();
        let wire = encode_cp_setup(
            &bootstrap,
            1,
            ASSIGNOR | 0x1234,
            bind.prepare_bind().unwrap(),
        )
        .unwrap();
        let packet = RtpPacket::parse(&wire).unwrap();
        // NHDR (6 bytes), THDR fixed (20 bytes), then CV05. Its LT length is
        // 30, and the two trailing zero bytes align the following segment.
        assert_eq!(&wire[..6], &[0xc6, 8, 0xa4, 0, 0xff, 0]);
        assert_eq!(&wire[26..30], &[0x1e, 0x05, 0x80, 0]);
        assert_eq!(&wire[56..58], &[0, 0]);
        assert_eq!(packet.data, bind.prepare_bind().unwrap());
        assert_eq!(packet.byte_sequence_number, 0);
        assert!(packet.start_of_message && packet.end_of_message);
        assert_eq!(packet.tcid, ASSIGNOR | 0x1234);
        let guest_view = HprControlBootstrap::new(generation, guest, local).unwrap();
        let path =
            validate_inbound_switching_path(packet, &guest_view, 1, &RtpSetupTopic::CpSvcMg, None)
                .unwrap();
        assert_eq!(path.peer_nce_label, [0xa4, 0x80]);
        assert_eq!(path.priority, 3);
        let segments = packet.optional_segments().unwrap();
        assert_eq!(
            segments
                .iter()
                .map(|segment| segment.key)
                .collect::<Vec<_>>(),
            [0x0d, 0x14, 0x22]
        );
    }

    #[test]
    fn outbound_user_setup_is_valid_from_peer_perspective() {
        let local = advertisement(
            "SNUSNU.SVC",
            2,
            &[0x80, 0x80],
            &[0xa4, 0x80],
            [0xff, 0xf2, 0xc4, 0x80],
        );
        let guest = advertisement("SOLNET.SNAB", 1, &[0x80, 2], &[0xa4, 0], [0, 0, 0, 7]);
        let generation = ConnectionGeneration::new(1).unwrap();
        let bootstrap = HprControlBootstrap::new(generation, local.clone(), guest.clone()).unwrap();
        let cos_tpf = vec![
            0x0c, 0x2c, 0x01, 0x08, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
        ];
        let config = UserSetupConfig {
            local_nce_label: vec![0xa4, 0x81],
            local_nce_instance: [0xff, 0xf2, 0xc4, 0x80],
            peer_nce_label: vec![0xa4, 0x01],
            peer_nce_instance: [0, 0, 0, 7],
            peer_link_label: guest.link_label.clone(),
            cos_tpf: cos_tpf.clone(),
            target_lu: "SOLNET.SNAB".into(),
            maximum_packet_size: bootstrap.max_packet_size,
        };
        // APPN can route a source LU in a different NETID through this CP.
        let bind = bind_with_mode("QAALICE.PING", "SOLNET.SNAB", None);
        let bytes = encode_user_setup(&bootstrap, 1, ASSIGNOR | 0x1234, &bind, &config).unwrap();
        let packet = RtpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.data, bind);
        let mut too_small = config.clone();
        too_small.maximum_packet_size = 100;
        assert_eq!(
            encode_user_setup(&bootstrap, 1, ASSIGNOR | 0x1234, &bind, &too_small),
            Err(OutboundSetupError::TooLarge)
        );
        let mut too_large = config.clone();
        too_large.maximum_packet_size = bootstrap.max_packet_size + 1;
        assert_eq!(
            encode_user_setup(&bootstrap, 1, ASSIGNOR | 0x1234, &bind, &too_large),
            Err(OutboundSetupError::InvalidIdentity)
        );
        assert_eq!((packet.nhdr[0] >> 1) & 3, 1);
        assert_eq!(
            classify_setup_topic(packet).unwrap(),
            RtpSetupTopic::User {
                cos_tpf: cos_tpf.clone()
            }
        );
        let management = bind_with_mode("QAALICE.SNAA", "SOLNET.SNAB", Some("SNASVCMG"));
        assert!(encode_user_setup(&bootstrap, 1, ASSIGNOR | 0x1235, &management, &config).is_ok());
        let other_management = bind_with_mode("QAALICE.SNAA", "SOLNET.SNAB", Some("CPSVCMG"));
        assert_eq!(
            encode_user_setup(&bootstrap, 1, ASSIGNOR | 0x1236, &other_management, &config),
            Err(OutboundSetupError::InvalidBind)
        );
        let guest_view = HprControlBootstrap::new(generation, guest, local).unwrap();
        let route = AuthorizedUserRoute {
            generation,
            target_lu: "SOLNET.SNAB".parse().unwrap(),
            verified_external_cp: None,
            local_nce_label: config.peer_nce_label.clone(),
            local_nce_instance: config.peer_nce_instance,
            cos_tpf,
            tg_number: 1,
            return_link_label: guest_view.local.link_label.clone(),
            maximum_packet_size: guest_view.max_packet_size,
        };
        validate_inbound_switching_path(
            packet,
            &guest_view,
            1,
            &RtpSetupTopic::User {
                cos_tpf: route.cos_tpf.clone(),
            },
            Some(&route),
        )
        .unwrap();
    }
}
