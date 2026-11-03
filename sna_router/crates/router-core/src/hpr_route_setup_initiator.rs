//! Direct, one-TG APPN Route Setup initiated toward an adjacent EE peer.
//!
//! The request grants no user RTP by itself. A positive reply must correlate
//! to this request and validate the reverse route and user NCE before the
//! caller may use its result to open an outbound user RTP connection.

use crate::{
    hpr_control_bootstrap::{encode_network_name_component, HprControlBootstrap},
    hpr_route_setup::{RouteSetupGds, RouteSetupKind},
    session::QualifiedName,
    ConnectionGeneration,
};

const MAX_GDS: usize = 4096;
const CONNECT_COS_TPF: [u8; 12] = [
    12, 0x2c, 1, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitiatorError {
    InvalidIdentity,
    InvalidLink,
    InvalidMetrics,
    InvalidPhase,
    InvalidReply,
    InvalidRoute,
    StaleGeneration,
    WrongPcid,
    WrongPeer,
    WrongRoute,
    MissingUserNce,
    TooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectLinkMetrics {
    pub transmission_time_us: u32,
    pub capacity_kbps: u32,
    pub liveness_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundUserRoute {
    pub generation: ConnectionGeneration,
    pub target_lu: QualifiedName,
    pub target_cp: QualifiedName,
    pub tg_number: u8,
    pub local_user_nce_label: Vec<u8>,
    pub local_user_nce_instance: [u8; 4],
    pub peer_user_nce_label: Vec<u8>,
    pub peer_user_nce_instance: [u8; 4],
    /// Complete CV X'2C', including length and key.
    pub cos_tpf: Vec<u8>,
    /// The peer's ANR label from the validated return path.
    pub peer_link_label: Vec<u8>,
    pub maximum_packet_size: u16,
}

pub struct DirectRouteSetupInitiator {
    bootstrap: HprControlBootstrap,
    target_lu: QualifiedName,
    tg_number: u8,
    pcid: [u8; 8],
    local_user_nce_label: Vec<u8>,
    local_user_nce_instance: [u8; 4],
    request: Vec<u8>,
    sent: bool,
    completed: bool,
}

impl DirectRouteSetupInitiator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bootstrap: HprControlBootstrap,
        target_lu: QualifiedName,
        tg_number: u8,
        pcid: [u8; 8],
        local_user_nce_label: Vec<u8>,
        local_user_nce_instance: [u8; 4],
        metrics: DirectLinkMetrics,
    ) -> Result<Self, InitiatorError> {
        if target_lu.netid != bootstrap.peer.cp.netid {
            return Err(InitiatorError::InvalidIdentity);
        }
        if tg_number == 0
            || !valid_label(&bootstrap.local.link_label)
            || !valid_label(&bootstrap.peer.link_label)
            || !valid_label(&local_user_nce_label)
        {
            return Err(InitiatorError::InvalidLink);
        }
        if metrics.capacity_kbps == 0 {
            return Err(InitiatorError::InvalidMetrics);
        }
        let request = encode_request(&bootstrap, &target_lu, tg_number, pcid, metrics)?;
        Ok(Self {
            bootstrap,
            target_lu,
            tg_number,
            pcid,
            local_user_nce_label,
            local_user_nce_instance,
            request,
            sent: false,
            completed: false,
        })
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn confirm_request_sent(&mut self, request: &[u8]) -> Result<(), InitiatorError> {
        if self.sent || request != self.request {
            return Err(InitiatorError::InvalidPhase);
        }
        self.sent = true;
        Ok(())
    }

    pub fn observe_reply(
        &mut self,
        generation: ConnectionGeneration,
        reply: &[u8],
    ) -> Result<OutboundUserRoute, InitiatorError> {
        if !self.sent || self.completed {
            return Err(InitiatorError::InvalidPhase);
        }
        if generation != self.bootstrap.generation {
            return Err(InitiatorError::StaleGeneration);
        }
        let parsed = RouteSetupGds::parse(reply).map_err(|_| InitiatorError::InvalidReply)?;
        if parsed.kind != RouteSetupKind::PositiveReply
            || parsed.path_switch
            || parsed.destination_hop_index != 1
        {
            return Err(InitiatorError::InvalidReply);
        }
        if parsed.pcid != self.pcid {
            return Err(InitiatorError::WrongPcid);
        }
        if parsed.origin_cp_name != self.bootstrap.local.cp.to_string()
            || parsed.destination_cp_name.as_deref() != Some(&self.bootstrap.peer.cp.to_string())
        {
            return Err(InitiatorError::WrongPeer);
        }
        let cos = unique(&parsed, 0x2c).ok_or(InitiatorError::WrongRoute)?;
        if cos != CONNECT_COS_TPF {
            return Err(InitiatorError::WrongRoute);
        }
        let rscv = unique(&parsed, 0x2b).ok_or(InitiatorError::WrongRoute)?;
        validate_rscv(rscv, &self.bootstrap.local.cp, self.tg_number, false)?;
        let infos = parsed
            .vectors
            .iter()
            .filter(|cv| cv.key == 0x80)
            .map(|cv| cv.wire)
            .collect::<Vec<_>>();
        if infos.len() != 2 {
            return Err(InitiatorError::WrongRoute);
        }
        let first_label = route_label(infos[0])?;
        let second_label = route_label(infos[1])?;
        if first_label != self.bootstrap.local.link_label
            || second_label != self.bootstrap.peer.link_label
            || infos[1][2] & 0x80 == 0
        {
            return Err(InitiatorError::WrongRoute);
        }
        let maximum_packet_size = u32::from_be_bytes(infos[1][4..8].try_into().unwrap())
            .min(u32::from(self.bootstrap.max_packet_size));
        let maximum_packet_size =
            u16::try_from(maximum_packet_size).map_err(|_| InitiatorError::WrongRoute)?;
        if maximum_packet_size == 0 {
            return Err(InitiatorError::WrongRoute);
        }
        let nce = unique(&parsed, 0x26).ok_or(InitiatorError::MissingUserNce)?;
        let instance = unique(&parsed, 0x39).ok_or(InitiatorError::MissingUserNce)?;
        if !(3..=10).contains(&nce.len()) || !valid_label(&nce[2..]) || instance.len() != 6 {
            return Err(InitiatorError::MissingUserNce);
        }
        self.completed = true;
        Ok(OutboundUserRoute {
            generation,
            target_lu: self.target_lu.clone(),
            target_cp: self.bootstrap.peer.cp.clone(),
            tg_number: self.tg_number,
            local_user_nce_label: self.local_user_nce_label.clone(),
            local_user_nce_instance: self.local_user_nce_instance,
            peer_user_nce_label: nce[2..].to_vec(),
            peer_user_nce_instance: instance[2..6].try_into().unwrap(),
            cos_tpf: cos.to_vec(),
            peer_link_label: second_label.to_vec(),
            maximum_packet_size,
        })
    }
}

fn encode_request(
    bootstrap: &HprControlBootstrap,
    target_lu: &QualifiedName,
    tg_number: u8,
    pcid: [u8; 8],
    metrics: DirectLinkMetrics,
) -> Result<Vec<u8>, InitiatorError> {
    let mut result = vec![0, 0, 0x12, 0xce, 0, 1];
    result.extend_from_slice(&[0; 10]);
    let mut name = vec![0xf3];
    name.extend(encode_qualified(target_lu)?);
    append_lt(&mut result, 0x0e, &name)?;
    result.extend(build_rscv(&bootstrap.peer.cp, tg_number, true)?);
    let mut fqpcid = pcid.to_vec();
    let cp_name = encode_qualified(&bootstrap.local.cp)?;
    fqpcid.push(cp_name.len() as u8);
    fqpcid.extend(cp_name);
    append_lt(&mut result, 0x60, &fqpcid)?;
    result.extend_from_slice(&CONNECT_COS_TPF);
    result.extend(build_route_info(
        bootstrap.max_packet_size,
        &bootstrap.local.link_label,
        metrics,
    )?);
    if result.len() > MAX_GDS {
        return Err(InitiatorError::TooLarge);
    }
    let len = u16::try_from(result.len()).map_err(|_| InitiatorError::TooLarge)?;
    result[..2].copy_from_slice(&len.to_be_bytes());
    RouteSetupGds::parse(&result).map_err(|_| InitiatorError::InvalidRoute)?;
    Ok(result)
}

fn build_rscv(cp: &QualifiedName, tg_number: u8, forward: bool) -> Result<Vec<u8>, InitiatorError> {
    let name = encode_qualified(cp)?;
    let tg_len = 5 + name.len();
    let descriptor_len = 2 + tg_len;
    let mut result = vec![
        u8::try_from(4 + descriptor_len).map_err(|_| InitiatorError::TooLarge)?,
        0x2b,
        1,
        u8::from(forward),
        u8::try_from(descriptor_len).map_err(|_| InitiatorError::TooLarge)?,
        0x46,
        u8::try_from(tg_len).map_err(|_| InitiatorError::TooLarge)?,
        0x80,
        tg_number,
        u8::try_from(name.len()).map_err(|_| InitiatorError::TooLarge)?,
    ];
    result.extend_from_slice(&name);
    result.push(0x21);
    Ok(result)
}

fn build_route_info(
    max_packet_size: u16,
    label: &[u8],
    metrics: DirectLinkMetrics,
) -> Result<Vec<u8>, InitiatorError> {
    let mut result = vec![0, 0x80, 0, 0];
    result.extend_from_slice(&u32::from(max_packet_size).to_be_bytes());
    result.extend_from_slice(&metrics.transmission_time_us.to_be_bytes());
    result.extend_from_slice(&metrics.capacity_kbps.to_be_bytes());
    result.extend_from_slice(&metrics.liveness_seconds.to_be_bytes());
    result.extend_from_slice(&[
        u8::try_from(4 + label.len()).map_err(|_| InitiatorError::TooLarge)?,
        0x67,
        u8::try_from(2 + label.len()).map_err(|_| InitiatorError::TooLarge)?,
        0,
    ]);
    result.extend_from_slice(label);
    result[0] = u8::try_from(result.len()).map_err(|_| InitiatorError::TooLarge)?;
    Ok(result)
}

fn validate_rscv(
    wire: &[u8],
    cp: &QualifiedName,
    tg_number: u8,
    forward: bool,
) -> Result<(), InitiatorError> {
    if wire != build_rscv(cp, tg_number, forward)? {
        return Err(InitiatorError::WrongRoute);
    }
    Ok(())
}

fn route_label(wire: &[u8]) -> Result<&[u8], InitiatorError> {
    if wire.len() < 25
        || usize::from(wire[0]) != wire.len()
        || wire[1] != 0x80
        || wire[3] != 0
        || wire[20] as usize != wire.len() - 20
        || wire[21] != 0x67
        || wire[22] as usize != wire.len() - 22
        || wire[23] != 0
    {
        return Err(InitiatorError::WrongRoute);
    }
    let label = &wire[24..];
    if !valid_label(label) {
        return Err(InitiatorError::WrongRoute);
    }
    Ok(label)
}

fn valid_label(label: &[u8]) -> bool {
    (1..=8).contains(&label.len()) && label[0] & 0x80 != 0 && !label.contains(&0xff)
}

fn unique<'a>(gds: &'a RouteSetupGds<'_>, key: u8) -> Option<&'a [u8]> {
    let mut matches = gds.vectors.iter().filter(|vector| vector.key == key);
    let first = matches.next()?;
    matches.next().is_none().then_some(first.wire)
}

fn append_lt(result: &mut Vec<u8>, key: u8, body: &[u8]) -> Result<(), InitiatorError> {
    let len = u8::try_from(2 + body.len()).map_err(|_| InitiatorError::TooLarge)?;
    result.extend_from_slice(&[len, key]);
    result.extend_from_slice(body);
    Ok(())
}

fn encode_qualified(name: &QualifiedName) -> Result<Vec<u8>, InitiatorError> {
    let mut result =
        encode_network_name_component(&name.netid).map_err(|_| InitiatorError::InvalidIdentity)?;
    result.push(0x4b);
    result.extend(
        encode_network_name_component(&name.name).map_err(|_| InitiatorError::InvalidIdentity)?,
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        hpr_rtp::RtpPacket,
        hpr_rtp_outbound_setup::encode_route_setup_setup,
        hpr_rtp_setup::{classify_setup_topic, RtpSetupTopic},
    };

    const PCID: [u8; 8] = [0xce, 0xc3, 0x74, 0x77, 0xb5, 0xdc, 0x29, 0x97];
    const REQUEST: &str = "007012ce0001000000000000000000000e0ef3e2d6d3d5c5e34be2d5c1c2162b010112461080010be2d6d3d5c5e34be2d5c1c2211660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e31a800000000005b500000114000010cc00000000066704008002";
    const REPLY: &str = "009412ce8001a0000003a980000000001a800000000005b500000114000010cc000000000667040080021660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e30e0ef4e2d6d3d5c5e34be2d5c1c20426a400063900000004162b010012461080010be2d6d3d5c5e34be2d5c1c1211a808000000005b500000114000010cc00000000066704008002";

    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn ad(cp: &str, node: u8) -> ControlAdvertisement {
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

    fn initiator() -> DirectRouteSetupInitiator {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            ad("SOLNET.SNAA", 1),
            ad("SOLNET.SNAB", 2),
        )
        .unwrap();
        DirectRouteSetupInitiator::new(
            bootstrap,
            "SOLNET.SNAB".parse().unwrap(),
            1,
            PCID,
            vec![0xa4, 1],
            [0, 0, 0, 5],
            DirectLinkMetrics {
                transmission_time_us: 276,
                capacity_kbps: 4300,
                liveness_seconds: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn encodes_preserved_direct_route_setup_and_validates_reply() {
        let mut initiator = initiator();
        assert_eq!(initiator.request(), unhex(REQUEST));
        let request = initiator.request().to_vec();
        assert_eq!(
            initiator.observe_reply(ConnectionGeneration::new(1).unwrap(), &unhex(REPLY)),
            Err(InitiatorError::InvalidPhase)
        );
        initiator.confirm_request_sent(&request).unwrap();
        let route = initiator
            .observe_reply(ConnectionGeneration::new(1).unwrap(), &unhex(REPLY))
            .unwrap();
        assert_eq!(route.peer_user_nce_label, [0xa4, 0]);
        assert_eq!(route.peer_user_nce_instance, [0, 0, 0, 4]);
        assert_eq!(route.local_user_nce_label, [0xa4, 1]);
        assert_eq!(route.local_user_nce_instance, [0, 0, 0, 5]);
        assert_eq!(route.peer_link_label, [0x80, 2]);
        assert_eq!(route.maximum_packet_size, 1461);
        assert_eq!(
            initiator.observe_reply(ConnectionGeneration::new(1).unwrap(), &unhex(REPLY)),
            Err(InitiatorError::InvalidPhase)
        );
    }

    #[test]
    fn rejects_unrelated_and_stale_route_setup_replies() {
        let mut initiator = initiator();
        let request = initiator.request().to_vec();
        initiator.confirm_request_sent(&request).unwrap();
        assert_eq!(
            initiator.observe_reply(ConnectionGeneration::new(2).unwrap(), &unhex(REPLY)),
            Err(InitiatorError::StaleGeneration)
        );
        let mut bad = unhex(REPLY);
        bad[44] ^= 1;
        assert_eq!(
            initiator.observe_reply(ConnectionGeneration::new(1).unwrap(), &bad),
            Err(InitiatorError::WrongPcid)
        );
        bad = unhex(REPLY);
        bad[92] ^= 0x80;
        assert!(matches!(
            initiator.observe_reply(ConnectionGeneration::new(1).unwrap(), &bad),
            Err(InitiatorError::MissingUserNce | InitiatorError::WrongRoute)
        ));
    }

    #[test]
    fn route_setup_request_opens_the_route_setup_rtp_topic() {
        let initiator = initiator();
        let setup =
            encode_route_setup_setup(&initiator.bootstrap, 1, (1 << 63) | 23, initiator.request())
                .unwrap();
        let packet = RtpPacket::parse(&setup).unwrap();
        assert_eq!(
            classify_setup_topic(packet).unwrap(),
            RtpSetupTopic::RouteSetup
        );
        assert_eq!(packet.data, initiator.request());
    }
}
