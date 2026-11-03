//! Validate the direct EE return path in an inbound RTP Connection Setup.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 2-20–2-22 defines Switching
//! Information X'14', CV83 return ANR path, and CV85 return TG descriptors.
//! The X'67' path excludes the endpoint NCE label: that label comes from the
//! validated source qualifier CV X'05'/X'26'. A matching NHDR label alone is
//! insufficient because control and user RTP can share one label.

use crate::{
    hpr_control_bootstrap::{encode_network_name_component, HprControlBootstrap},
    hpr_rtp::{RtpError, RtpPacket},
    hpr_rtp_setup::{classify_setup_topic, RtpSetupTopic, SetupError},
    session::QualifiedName,
    ConnectionGeneration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    InvalidRtp(RtpError),
    InvalidTopic(SetupError),
    WrongTopic,
    WrongPeer,
    WrongTarget,
    WrongPriority,
    InvalidSwitchingInformation,
    InvalidReturnPath,
    InvalidReturnTg,
    MissingUserAuthorization,
    InvalidUserAuthorization,
}

/// The local user NCE allocation and COS must be tied to a previously sent
/// positive Route Setup reply. It is not derived from the untrusted setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedUserRoute {
    pub generation: ConnectionGeneration,
    pub target_lu: QualifiedName,
    /// Present only for a RouteSetup service whose local egress verified the
    /// adjacent hosting CP and its binding to this target LU.
    pub verified_external_cp: Option<QualifiedName>,
    pub local_nce_label: Vec<u8>,
    pub local_nce_instance: [u8; 4],
    pub cos_tpf: Vec<u8>,
    pub tg_number: u8,
    pub return_link_label: Vec<u8>,
    pub maximum_packet_size: u16,
}

impl AuthorizedUserRoute {
    pub fn target_netid_authorized(&self, local_cp: &QualifiedName) -> bool {
        match &self.verified_external_cp {
            None => self.target_lu.netid == local_cp.netid,
            Some(cp) => self.target_lu.netid != local_cp.netid && self.target_lu.netid == cp.netid,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedReturnPath {
    /// Sender-owned NCE label from the source qualifier, validated against
    /// its CP and the return TG. For control towers it must match CV61 X'81'.
    pub peer_nce_label: Vec<u8>,
    /// 0=low, 1=medium, 2=high, 3=network (for the reply NLP).
    pub priority: u8,
    pub maximum_packet_size: u32,
    pub path_switch_time_ms: u32,
    pub alive_seconds: u32,
}

/// Validate one qualified setup against an active, independently negotiated
/// EE adjacency. The caller also checks UDP source IP/port, SAPs, link
/// generation, and the RTP setup/TCID state before using the returned path.
pub fn validate_inbound_switching_path(
    packet: RtpPacket<'_>,
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
    expected_topic: &RtpSetupTopic,
    user_route: Option<&AuthorizedUserRoute>,
) -> Result<TrustedReturnPath, PathError> {
    if tg_number == 0 {
        return Err(PathError::InvalidReturnTg);
    }
    let topic = classify_setup_topic(packet).map_err(PathError::InvalidTopic)?;
    if &topic != expected_topic {
        return Err(PathError::WrongTopic);
    }
    let source = packet
        .connection_qualifier()
        .map_err(PathError::InvalidRtp)?
        .ok_or(PathError::WrongPeer)?;
    let peer_netid = encode_network_name_component(&bootstrap.peer.cp.netid)
        .map_err(|_| PathError::WrongPeer)?;
    let peer_cp =
        encode_network_name_component(&bootstrap.peer.cp.name).map_err(|_| PathError::WrongPeer)?;
    if source.network_id != peer_netid
        || source.node_id != peer_cp
        || !valid_anr_label(source.nce_id)
    {
        return Err(PathError::WrongPeer);
    }
    let (local_nce, expected_instance, priority) = match &topic {
        RtpSetupTopic::RouteSetup => (
            bootstrap.local.tower.route_setup_nce_label.as_slice(),
            bootstrap.local.tower.route_setup_nce_instance,
            3,
        ),
        RtpSetupTopic::CpSvcMg => (
            bootstrap.local.tower.cp_nce_label.as_slice(),
            bootstrap.local.tower.cp_nce_instance,
            3,
        ),
        RtpSetupTopic::User { cos_tpf } => {
            let authorized = user_route.ok_or(PathError::MissingUserAuthorization)?;
            if authorized.generation != bootstrap.generation
                || !authorized.target_netid_authorized(&bootstrap.local.cp)
                || authorized.tg_number != tg_number
                || authorized.return_link_label != bootstrap.local.link_label
                || authorized.maximum_packet_size > bootstrap.max_packet_size
            {
                return Err(PathError::InvalidUserAuthorization);
            }
            if authorized.cos_tpf != *cos_tpf || cos_tpf.len() < 3 {
                return Err(PathError::WrongTopic);
            }
            let tpf = cos_tpf[2];
            if tpf & !0x07 != 0 || tpf & 3 == 3 {
                return Err(PathError::WrongPriority);
            }
            (
                authorized.local_nce_label.as_slice(),
                authorized.local_nce_instance,
                if tpf & 0x04 != 0 { 3 } else { tpf & 3 },
            )
        }
    };
    if !valid_anr_label(local_nce) || !valid_anr_label(source.nce_id) {
        return Err(PathError::WrongTarget);
    }
    if packet.nhdr.len() < 5 || packet.nhdr[2..packet.nhdr.len() - 2] != *local_nce {
        return Err(PathError::WrongTarget);
    }
    let wire_priority = (packet.nhdr[0] >> 1) & 3;
    if wire_priority != priority {
        return Err(PathError::WrongPriority);
    }
    validate_cs_target(packet, bootstrap, expected_instance)?;
    let segments = packet.optional_segments().map_err(PathError::InvalidRtp)?;
    let mut switching = segments.iter().filter(|segment| segment.key == 0x14);
    let si = switching
        .next()
        .ok_or(PathError::InvalidSwitchingInformation)?;
    if switching.next().is_some() || si.data.len() < 2 || si.data[..2] != [0, 0] {
        return Err(PathError::InvalidSwitchingInformation);
    }
    let (cv83, rest) = take_aligned(&si.data[2..])?;
    let (cv85, rest) = take_aligned(rest)?;
    if !rest.is_empty() || cv83[1] != 0x83 || cv85[1] != 0x85 {
        return Err(PathError::InvalidSwitchingInformation);
    }
    let (max_packet, path_switch_ms, alive_seconds) = validate_cv83(cv83, bootstrap)?;
    if let Some(authorized) = user_route {
        if matches!(topic, RtpSetupTopic::User { .. })
            && max_packet > u32::from(authorized.maximum_packet_size)
        {
            return Err(PathError::InvalidUserAuthorization);
        }
    }
    validate_cv85(cv85, bootstrap, tg_number)?;
    if matches!(topic, RtpSetupTopic::RouteSetup)
        && source.nce_id != bootstrap.peer.tower.route_setup_nce_label
    {
        return Err(PathError::WrongPeer);
    }
    if matches!(topic, RtpSetupTopic::CpSvcMg) && source.nce_id != bootstrap.peer.tower.cp_nce_label
    {
        return Err(PathError::WrongPeer);
    }
    Ok(TrustedReturnPath {
        peer_nce_label: source.nce_id.to_vec(),
        priority,
        maximum_packet_size: max_packet,
        path_switch_time_ms: path_switch_ms,
        alive_seconds,
    })
}

fn validate_cs_target(
    packet: RtpPacket<'_>,
    bootstrap: &HprControlBootstrap,
    instance: [u8; 4],
) -> Result<(), PathError> {
    let segments = packet.optional_segments().map_err(PathError::InvalidRtp)?;
    let mut setup = segments.iter().filter(|segment| segment.key == 0x0d);
    let cs = setup.next().ok_or(PathError::WrongTarget)?;
    if setup.next().is_some() || cs.data.len() < 6 {
        return Err(PathError::WrongTarget);
    }
    let mut remaining = &cs.data[6..];
    let mut vectors = Vec::new();
    while !remaining.is_empty() {
        let (cv, rest) = take_aligned(remaining)?;
        vectors.push(cv);
        remaining = rest;
    }
    if vectors.len() != 4
        || vectors.iter().map(|cv| cv[1]).collect::<Vec<_>>() != [0x28, 0x03, 0x00, 0x39]
    {
        return Err(PathError::WrongTarget);
    }
    let local_netid = encode_network_name_component(&bootstrap.local.cp.netid)
        .map_err(|_| PathError::WrongTarget)?;
    let local_cp = encode_network_name_component(&bootstrap.local.cp.name)
        .map_err(|_| PathError::WrongTarget)?;
    if vectors[1][2..] != local_netid || vectors[2][2..] != local_cp || vectors[3][2..] != instance
    {
        return Err(PathError::WrongTarget);
    }
    Ok(())
}

fn validate_cv83(cv: &[u8], bootstrap: &HprControlBootstrap) -> Result<(u32, u32, u32), PathError> {
    // X'10' is the architected limited-resource-link indicator (bit 3).
    // The V5R4 LU-LU setup sets it while its control connections do not.
    if cv.len() < 21 || cv[3] != 0 || cv[2] & !0xb8 != 0 {
        return Err(PathError::InvalidReturnPath);
    }
    let max_packet = u32::from_be_bytes(cv[4..8].try_into().unwrap());
    if max_packet < 768 || max_packet > u32::from(bootstrap.max_packet_size) {
        return Err(PathError::InvalidReturnPath);
    }
    let path = &cv[16..];
    // The return ANR path points *toward us*, so its link label is the one
    // advertised in our CV61, not the peer's label for the forward direction.
    let label = &bootstrap.local.link_label;
    if path.len() != 4 + label.len()
        || path[0] as usize != path.len()
        || path[1] != 0x67
        || path[2] as usize != 2 + label.len()
        || path[3] != 0
        || path[4..] != *label
    {
        return Err(PathError::InvalidReturnPath);
    }
    Ok((
        max_packet,
        u32::from_be_bytes(cv[8..12].try_into().unwrap()),
        u32::from_be_bytes(cv[12..16].try_into().unwrap()),
    ))
}

fn validate_cv85(
    cv: &[u8],
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
) -> Result<(), PathError> {
    if cv.len() < 11 || cv[2] != 0 || cv[3] != 1 || cv[4] as usize != cv.len() - 4 || cv[5] != 0x46
    {
        return Err(PathError::InvalidReturnTg);
    }
    let descriptor = &cv[6..];
    if descriptor.len() < 6
        || descriptor[0] as usize != descriptor.len()
        || descriptor[1] != 0x80
        || descriptor[2] != tg_number
    {
        return Err(PathError::InvalidReturnTg);
    }
    let name_len = usize::from(descriptor[3]);
    if name_len == 0 || name_len > 17 || descriptor.len() < 5 + name_len {
        return Err(PathError::InvalidReturnTg);
    }
    let expected_short = encode_network_name_component(&bootstrap.peer.cp.name)
        .map_err(|_| PathError::InvalidReturnTg)?;
    let expected_full = {
        let mut value = encode_network_name_component(&bootstrap.peer.cp.netid)
            .map_err(|_| PathError::InvalidReturnTg)?;
        value.push(0x4b);
        value.extend_from_slice(&expected_short);
        value
    };
    if descriptor[4..4 + name_len] != expected_short && descriptor[4..4 + name_len] != expected_full
    {
        return Err(PathError::InvalidReturnTg);
    }
    if descriptor[4 + name_len] != 0x21
        || (descriptor.len() != 5 + name_len
            && (descriptor.len() != 9 + name_len
                || descriptor[5 + name_len..].iter().any(|byte| *byte != 0)))
    {
        return Err(PathError::InvalidReturnTg);
    }
    Ok(())
}

fn take_aligned(bytes: &[u8]) -> Result<(&[u8], &[u8]), PathError> {
    let length = usize::from(
        *bytes
            .first()
            .ok_or(PathError::InvalidSwitchingInformation)?,
    );
    let aligned = length.div_ceil(4) * 4;
    if length < 2 || aligned > bytes.len() || bytes[length..aligned].iter().any(|b| *b != 0) {
        return Err(PathError::InvalidSwitchingInformation);
    }
    Ok((&bytes[..length], &bytes[aligned..]))
}

fn valid_anr_label(label: &[u8]) -> bool {
    (1..=8).contains(&label.len()) && label[0] & 0x80 != 0 && !label.contains(&0xff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        session::QualifiedName,
        ConnectionGeneration,
    };

    fn advertisement(cp: &str, node: u8) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse::<QualifiedName>().unwrap(),
            node_id: [0, 0, 0, node],
            hpr_sap: 4,
            link_label: if node == 2 {
                vec![0x80, 0x80]
            } else {
                vec![0x80, 2]
            },
            tower: ControlFlowsTower {
                max_send_packet_size: 1461,
                path_switch_time_ms: 60_000,
                mobile: false,
                multilink_tg: false,
                arb_mode: ArbMode::Base,
                cp_nce_instance: [0, 0, 0, 4],
                route_setup_nce_instance: [0, 0, 0, 4],
                cp_nce_label: vec![0xa4, 0],
                route_setup_nce_label: vec![0xa4, 0],
            },
        }
    }

    fn bootstrap() -> HprControlBootstrap {
        HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SOLNET.SNAB", 2),
            advertisement("SOLNET.SNAA", 1),
        )
        .unwrap()
    }

    fn nlp(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // Preserved V5R4 direct EE setup headers (packets 14/18). User payloads
    // are removed and THDR data lengths set to zero; only XID-derived
    // identifiers, CS X0D, SI X14 and ARB X22 remain.
    const CONTROL: &str = "c608a400ff008015f7e9930000407c0c002b00000000000000001e0580000803e2d6d3d5c5e30600e2d5c1c100000426a40006390000000400000b0d010198000000092800d9e2c5e3e4d70000000803e2d6d3d5c5e30600e2d5c1c2000006390000000400000e1400001683a800000005b50000ea60000000b406670400808000001a85000116461480010be2d6d3d5c5e34be2d5c1c1210000000000000522000000000fa000009c40000010cc00000114";
    const USER: &str = "c208a400ff008015f7e9940000487c0c002b00000000000000001e0580000803e2d6d3d5c5e30600e2d5c1c100000426a40006390000000400000c0d0101980000000f28800c2c01087bc3d6d5d5c5c3e3000803e2d6d3d5c5e30600e2d5c1c2000006390000000400000d14000016832800000005b50003a980000000b406670400808000001685000112461080010be2d6d3d5c5e34be2d5c1c12100000522000000000fa000009c40000010cc00000114";
    // Live V5R4 EN -> SNUSNU.SVC CPSVCMG setup, retransmission with no data.
    // Captured 2026-11-02 16:40:08 UTC; only the three-byte EE UI header is
    // removed. Its reverse X'67' label 80 80 is our advertised link label,
    // while the guest advertised 80 02 for traffic in the other direction.
    const LIVE_CPSVCMG: &str = "c608a480ff0080e8992c8f0000204c0c002b00000000000000911e0580000803e2d6d3d5c5e30600e2d5c1c200000426a40006390000000700000b0d0101980000000a2800c3d7e2e5c3d4c700000803e2d5e4e2d5e40500e2e5c30000000639fff2c48000000e1400001683a800000005b50000ea60000000b406670400808000001a85000116461480010be2d6d3d5c5e34be2d5c1c2210000000000000522000000000fa000009c40000010cc00000114";
    // Live APING LU-LU setup retransmission at 17:51:53 UTC, after the
    // positive RouteSetup reply. The 3-byte EE header and BIND data are
    // absent; all CS, SI, ARB and directional labels are preserved.
    const LIVE_USER: &str = "c208a481ff0080e8992ccc0002084c0c002b00000000000000941e0580000803e2d6d3d5c5e30600e2d5c1c200000426a40006390000000700000c0d0101980000000f28800c2c01087bc3d6d5d5c5c3e3000803e2d5e4e2d5e40500e2e5c30000000639fff2c48000000d1400001683b800000005b50003a9800000000506670400808000001685000112461080010be2d6d3d5c5e34be2d5c1c22100000522000000000fa000009c40000186a0000003e8";

    #[test]
    fn live_cross_netid_cp_management_uses_local_reverse_link_label() {
        let mut local = advertisement("SNUSNU.SVC", 2);
        local.tower.cp_nce_label = vec![0xa4, 0x80];
        local.tower.cp_nce_instance = [0xff, 0xf2, 0xc4, 0x80];
        let mut peer = advertisement("SOLNET.SNAB", 1);
        peer.tower.cp_nce_label = vec![0xa4, 0];
        let bootstrap =
            HprControlBootstrap::new(ConnectionGeneration::new(1).unwrap(), local, peer).unwrap();
        let bytes = nlp(LIVE_CPSVCMG);
        let packet = RtpPacket::parse(&bytes).unwrap();
        let path =
            validate_inbound_switching_path(packet, &bootstrap, 1, &RtpSetupTopic::CpSvcMg, None)
                .unwrap();
        assert_eq!(path.peer_nce_label, [0xa4, 0]);
        assert_eq!(path.priority, 3);
        let mut wrong_direction = bootstrap.clone();
        wrong_direction.local.link_label = vec![0x80, 2];
        assert_eq!(
            validate_inbound_switching_path(
                packet,
                &wrong_direction,
                1,
                &RtpSetupTopic::CpSvcMg,
                None
            ),
            Err(PathError::InvalidReturnPath)
        );
    }

    #[test]
    fn live_user_limited_resource_path_uses_authorized_lu_and_local_label() {
        let mut local = advertisement("SNUSNU.SVC", 2);
        local.tower.cp_nce_instance = [0xff, 0xf2, 0xc4, 0x80];
        let peer = advertisement("SOLNET.SNAB", 1);
        let bootstrap =
            HprControlBootstrap::new(ConnectionGeneration::new(1).unwrap(), local, peer).unwrap();
        let route = AuthorizedUserRoute {
            generation: bootstrap.generation,
            target_lu: "SNUSNU.PING".parse().unwrap(),
            verified_external_cp: None,
            local_nce_label: vec![0xa4, 0x81],
            local_nce_instance: [0xff, 0xf2, 0xc4, 0x80],
            cos_tpf: nlp("0c2c01087bc3d6d5d5c5c3e3"),
            tg_number: 1,
            return_link_label: bootstrap.local.link_label.clone(),
            maximum_packet_size: bootstrap.max_packet_size,
        };
        let bytes = nlp(LIVE_USER);
        let packet = RtpPacket::parse(&bytes).unwrap();
        let topic = classify_setup_topic(packet).unwrap();
        let path =
            validate_inbound_switching_path(packet, &bootstrap, 1, &topic, Some(&route)).unwrap();
        assert_eq!(path.priority, 1);
        assert_eq!(path.peer_nce_label, [0xa4, 0]);
        assert_eq!(path.alive_seconds, 5);
        let mut external = route.clone();
        external.target_lu = "QABOB.APP".parse().unwrap();
        assert_eq!(
            validate_inbound_switching_path(packet, &bootstrap, 1, &topic, Some(&external)),
            Err(PathError::InvalidUserAuthorization)
        );
        external.verified_external_cp = Some("QAEVE.SNAC".parse().unwrap());
        assert_eq!(
            validate_inbound_switching_path(packet, &bootstrap, 1, &topic, Some(&external)),
            Err(PathError::InvalidUserAuthorization)
        );
        external.verified_external_cp = Some("QABOB.SNAB".parse().unwrap());
        validate_inbound_switching_path(packet, &bootstrap, 1, &topic, Some(&external)).unwrap();
        let mut reserved = bytes.clone();
        let flags = reserved
            .windows(3)
            .position(|cv| cv == [0x16, 0x83, 0xb8])
            .unwrap()
            + 2;
        reserved[flags] |= 0x01;
        assert_eq!(
            validate_inbound_switching_path(
                RtpPacket::parse(&reserved).unwrap(),
                &bootstrap,
                1,
                &topic,
                Some(&route),
            ),
            Err(PathError::InvalidReturnPath)
        );
    }

    #[test]
    fn negotiated_user_cap_may_be_below_adjacency_cap() {
        let mut local = advertisement("SNUSNU.SVC", 2);
        local.tower.cp_nce_instance = [0xff, 0xf2, 0xc4, 0x80];
        let peer = advertisement("SOLNET.SNAB", 1);
        let bootstrap =
            HprControlBootstrap::new(ConnectionGeneration::new(1).unwrap(), local, peer).unwrap();
        let mut route = AuthorizedUserRoute {
            generation: bootstrap.generation,
            target_lu: "SNUSNU.PING".parse().unwrap(),
            verified_external_cp: None,
            local_nce_label: vec![0xa4, 0x81],
            local_nce_instance: [0xff, 0xf2, 0xc4, 0x80],
            cos_tpf: nlp("0c2c01087bc3d6d5d5c5c3e3"),
            tg_number: 1,
            return_link_label: bootstrap.local.link_label.clone(),
            maximum_packet_size: 1200,
        };
        let mut bytes = nlp(LIVE_USER);
        let cv83 = bytes
            .windows(3)
            .position(|cv| cv == [0x16, 0x83, 0xb8])
            .unwrap();
        bytes[cv83 + 4..cv83 + 8].copy_from_slice(&1200u32.to_be_bytes());
        let packet = RtpPacket::parse(&bytes).unwrap();
        let topic = classify_setup_topic(packet).unwrap();
        assert!(
            validate_inbound_switching_path(packet, &bootstrap, 1, &topic, Some(&route)).is_ok()
        );
        route.maximum_packet_size = bootstrap.max_packet_size + 1;
        assert_eq!(
            validate_inbound_switching_path(packet, &bootstrap, 1, &topic, Some(&route)),
            Err(PathError::InvalidUserAuthorization)
        );
    }

    #[test]
    fn direct_v5r4_control_and_user_switching_paths_are_distinct_topics() {
        for (number, packet_hex, topic, authorized) in [
            (14, CONTROL, RtpSetupTopic::RouteSetup, None),
            (
                18,
                USER,
                RtpSetupTopic::User {
                    cos_tpf: vec![
                        12, 0x2c, 1, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
                    ],
                },
                Some(AuthorizedUserRoute {
                    generation: ConnectionGeneration::new(1).unwrap(),
                    target_lu: "SOLNET.SNAB".parse().unwrap(),
                    verified_external_cp: None,
                    local_nce_label: vec![0xa4, 0],
                    local_nce_instance: [0, 0, 0, 4],
                    cos_tpf: vec![
                        12, 0x2c, 1, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
                    ],
                    tg_number: 1,
                    return_link_label: vec![0x80, 0x80],
                    maximum_packet_size: 1461,
                }),
            ),
        ] {
            let bytes = nlp(packet_hex);
            let parsed = RtpPacket::parse(&bytes).unwrap();
            assert_eq!(classify_setup_topic(parsed).unwrap(), topic);
            let path = validate_inbound_switching_path(
                parsed,
                &bootstrap(),
                1,
                &topic,
                authorized.as_ref(),
            )
            .unwrap();
            assert_eq!(path.peer_nce_label, [0xa4, 0]);
            assert_eq!(path.priority, if number == 14 { 3 } else { 1 });
        }
    }

    #[test]
    fn wrong_return_anr_tg_and_target_nce_are_rejected() {
        let check = |bytes: &[u8]| {
            validate_inbound_switching_path(
                RtpPacket::parse(bytes).unwrap(),
                &bootstrap(),
                1,
                &RtpSetupTopic::RouteSetup,
                None,
            )
        };
        let mut wrong_path = nlp(CONTROL);
        let cv83 = wrong_path
            .windows(3)
            .position(|part| part == [0x16, 0x83, 0xa8])
            .unwrap();
        wrong_path[cv83 + 21] ^= 1;
        assert_eq!(check(&wrong_path), Err(PathError::InvalidReturnPath));

        let mut wrong_tg = nlp(CONTROL);
        let cv85 = wrong_tg
            .windows(4)
            .position(|part| part == [0x1a, 0x85, 0, 1])
            .unwrap();
        wrong_tg[cv85 + 8] = 2; // Nested X'80' TG number.
        assert_eq!(check(&wrong_tg), Err(PathError::InvalidReturnTg));

        let mut wrong_target = nlp(CONTROL);
        wrong_target[2] ^= 1;
        assert_eq!(check(&wrong_target), Err(PathError::WrongTarget));

        let mut wrong_priority = nlp(CONTROL);
        wrong_priority[0] = 0xc2;
        assert_eq!(check(&wrong_priority), Err(PathError::WrongPriority));
    }

    #[test]
    fn user_setup_requires_prior_route_authorization() {
        let bytes = nlp(USER);
        let packet = RtpPacket::parse(&bytes).unwrap();
        let topic = classify_setup_topic(packet).unwrap();
        assert_eq!(
            validate_inbound_switching_path(packet, &bootstrap(), 1, &topic, None),
            Err(PathError::MissingUserAuthorization)
        );
    }
}
