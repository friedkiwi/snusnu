//! A bounded positive Route Setup reply for one directly adjacent HPR peer.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 13-67–13-73 defines X'12CE' and its
//! forward/reverse CV80 and RSCV fields. This builder only accepts a
//! single-TG request addressed to a caller-authorized local LU, including an
//! end node in a different NETID from its network-node server.
//! It does not forward through an APPN network, grant an RTP connection, or
//! infer LU reachability from a CP XID3.

use crate::{
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_route_setup::{RouteSetupGds, RouteSetupKind},
    session::QualifiedName,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectReplyError {
    NotRequest,
    UnsupportedPathSwitch,
    WrongOrigin,
    WrongDestination,
    InvalidRoute,
    InvalidLinkLabel,
    InvalidLuNce,
    InvalidMetrics,
    TooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReverseLinkMetrics {
    pub transmission_time_us: u32,
    pub capacity_kbps: u32,
    pub liveness_seconds: u32,
}

/// All values beyond the XID bootstrap must be supplied by local routing
/// policy. In particular, `local_lu` is not inferred from the peer CP name.
pub struct DirectReplyTarget<'a> {
    pub bootstrap: &'a HprControlBootstrap,
    pub local_lu: &'a QualifiedName,
    pub lu_nce_label: &'a [u8],
    pub lu_nce_instance: [u8; 4],
    pub tg_number: u8,
    pub reverse_metrics: ReverseLinkMetrics,
}

impl DirectReplyTarget<'_> {
    pub fn encode_positive(
        &self,
        request: &RouteSetupGds<'_>,
    ) -> Result<Vec<u8>, DirectReplyError> {
        if request.kind != RouteSetupKind::Request {
            return Err(DirectReplyError::NotRequest);
        }
        if request.path_switch {
            return Err(DirectReplyError::UnsupportedPathSwitch);
        }
        if request.origin_cp_name != self.bootstrap.peer.cp.to_string() {
            return Err(DirectReplyError::WrongOrigin);
        }
        if request.destination_lu_name.as_deref() != Some(&self.local_lu.to_string())
            || self.local_lu.netid != self.bootstrap.local.cp.netid
        {
            return Err(DirectReplyError::WrongDestination);
        }
        let route = unique_vector(request, 0x2b).ok_or(DirectReplyError::InvalidRoute)?;
        validate_direct_route(route, self)?;
        let fqpcid = unique_vector(request, 0x60).ok_or(DirectReplyError::InvalidRoute)?;
        let cos = unique_vector(request, 0x2c).ok_or(DirectReplyError::InvalidRoute)?;
        let forward = unique_vector(request, 0x80).ok_or(DirectReplyError::InvalidRoute)?;
        let mut forward = forward.to_vec();
        // The origin appends its outbound ANR label to the forward path. The
        // return path is built below from our outbound label. Keep the two
        // directions distinct even when an attachment uses similar labels.
        validate_forward_route_information(&forward, &self.bootstrap.peer.link_label)?;
        forward[2] |= 0x40; // IP hop requires REFIFO (RFC 2353 §2.6.5).
        let max_packet = u32::from(self.bootstrap.max_packet_size);
        let advertised = u32::from_be_bytes(forward[4..8].try_into().unwrap());
        forward[4..8].copy_from_slice(&advertised.min(max_packet).to_be_bytes());

        if !(1..=8).contains(&self.lu_nce_label.len())
            || self.lu_nce_label[0] & 0x80 == 0
            || self.lu_nce_label.contains(&0xff)
        {
            return Err(DirectReplyError::InvalidLuNce);
        }
        if self.reverse_metrics.capacity_kbps == 0 {
            return Err(DirectReplyError::InvalidMetrics);
        }
        let mut reply = vec![0, 0, 0x12, 0xce, 0, request.destination_hop_index];
        // Select Base ARB on this route. A peer's support for Responsive ARB
        // does not prove that this endpoint has implemented that mode.
        reply[4] = 0x80;
        // No mobility, NCE scope, or dedicated RTP promise. A network node
        // responding for its own LU does not require directory search.
        reply.extend_from_slice(&[0, 0]);
        reply.extend_from_slice(&self.bootstrap.local.tower.path_switch_time_ms.to_be_bytes());
        reply.extend_from_slice(&[0; 4]);
        reply.extend_from_slice(&forward);
        reply.extend_from_slice(fqpcid);
        reply.extend_from_slice(cos);

        let cp_wire = encode_qualified_name(&self.bootstrap.local.cp);
        let mut cp_name = vec![0xf4];
        cp_name.extend_from_slice(&cp_wire);
        append_lt(&mut reply, 0x0e, &cp_name)?;
        append_lt(&mut reply, 0x26, self.lu_nce_label)?;
        append_lt(&mut reply, 0x39, &self.lu_nce_instance)?;
        let reverse_rscv = build_reverse_rscv(self)?;
        reply.extend_from_slice(&reverse_rscv);
        let reverse_info = build_reverse_route_information(self)?;
        reply.extend_from_slice(&reverse_info);
        let length: u16 = reply
            .len()
            .try_into()
            .map_err(|_| DirectReplyError::TooLarge)?;
        if length > 4096 {
            return Err(DirectReplyError::TooLarge);
        }
        reply[..2].copy_from_slice(&length.to_be_bytes());
        Ok(reply)
    }
}

fn unique_vector<'a>(request: &'a RouteSetupGds<'_>, key: u8) -> Option<&'a [u8]> {
    let mut matching = request.vectors.iter().filter(|cv| cv.key == key);
    let one = matching.next()?;
    matching.next().is_none().then_some(one.wire)
}

fn validate_direct_route(
    route: &[u8],
    target: &DirectReplyTarget<'_>,
) -> Result<(), DirectReplyError> {
    if route.len() < 11
        || route[2] != 1
        || route[3] != 1
        || target.tg_number == 0
        || route[4] as usize != route.len() - 4
        || route[5] != 0x46
    {
        return Err(DirectReplyError::InvalidRoute);
    }
    let tg = &route[6..];
    if tg.len() < 6
        || tg[0] as usize != tg.len()
        || tg[1] != 0x80
        || tg[2] != target.tg_number
        || tg.len() != 5 + usize::from(tg[3])
        || tg[tg.len() - 1] != 0x21
    {
        return Err(DirectReplyError::InvalidRoute);
    }
    let name = &tg[4..tg.len() - 1];
    let expected_qualified = encode_qualified_name(&target.bootstrap.local.cp);
    let expected_short = encode_name(&target.bootstrap.local.cp.name);
    if name != expected_qualified && name != expected_short {
        return Err(DirectReplyError::InvalidRoute);
    }
    Ok(())
}

fn validate_forward_route_information(
    info: &[u8],
    peer_link_label: &[u8],
) -> Result<(), DirectReplyError> {
    if info.len() < 25
        || info[0] as usize != info.len()
        || info[1] != 0x80
        || info[2] & 0x80 != 0
        || info[3] != 0
    {
        return Err(DirectReplyError::InvalidRoute);
    }
    let path = &info[20..];
    if path.len() != 4 + peer_link_label.len()
        || path[0] as usize != path.len()
        || path[1] != 0x67
        || path[2] as usize != 2 + peer_link_label.len()
        || path[3] != 0
        || path[4..] != *peer_link_label
    {
        return Err(DirectReplyError::InvalidLinkLabel);
    }
    Ok(())
}

fn build_reverse_route_information(
    target: &DirectReplyTarget<'_>,
) -> Result<Vec<u8>, DirectReplyError> {
    let label = &target.bootstrap.local.link_label;
    if !(1..=8).contains(&label.len()) || label[0] & 0x80 == 0 || label.contains(&0xff) {
        return Err(DirectReplyError::InvalidLinkLabel);
    }
    let mut info = vec![0, 0x80, 0xc0, 0]; // Reverse + REFIFO.
    info.extend_from_slice(&u32::from(target.bootstrap.max_packet_size).to_be_bytes());
    info.extend_from_slice(&target.reverse_metrics.transmission_time_us.to_be_bytes());
    info.extend_from_slice(&target.reverse_metrics.capacity_kbps.to_be_bytes());
    info.extend_from_slice(&target.reverse_metrics.liveness_seconds.to_be_bytes());
    info.push((4 + label.len()) as u8);
    info.push(0x67);
    info.push((2 + label.len()) as u8);
    info.push(0);
    info.extend_from_slice(label);
    info[0] = info
        .len()
        .try_into()
        .map_err(|_| DirectReplyError::TooLarge)?;
    Ok(info)
}

fn build_reverse_rscv(target: &DirectReplyTarget<'_>) -> Result<Vec<u8>, DirectReplyError> {
    let name = encode_qualified_name(&target.bootstrap.peer.cp);
    let tg_len = 5 + name.len();
    let descriptor_len = 2 + tg_len;
    let rscv_len = 4 + descriptor_len;
    if rscv_len > u8::MAX as usize {
        return Err(DirectReplyError::TooLarge);
    }
    let mut result = vec![rscv_len as u8, 0x2b, 1, 0, descriptor_len as u8, 0x46];
    result.extend_from_slice(&[tg_len as u8, 0x80, target.tg_number, name.len() as u8]);
    result.extend_from_slice(&name);
    result.push(0x21); // HPR + RTP, regular TG.
    Ok(result)
}

fn append_lt(result: &mut Vec<u8>, key: u8, data: &[u8]) -> Result<(), DirectReplyError> {
    let length: u8 = (2 + data.len())
        .try_into()
        .map_err(|_| DirectReplyError::TooLarge)?;
    result.extend_from_slice(&[length, key]);
    result.extend_from_slice(data);
    Ok(())
}

fn encode_qualified_name(name: &QualifiedName) -> Vec<u8> {
    let mut result = encode_name(&name.netid);
    result.push(0x4b);
    result.extend_from_slice(&encode_name(&name.name));
    result
}

fn encode_name(name: &str) -> Vec<u8> {
    name.bytes()
        .map(|byte| match byte {
            b'A'..=b'I' => 0xc1 + (byte - b'A'),
            b'J'..=b'R' => 0xd1 + (byte - b'J'),
            b'S'..=b'Z' => 0xe2 + (byte - b'S'),
            b'0'..=b'9' => 0xf0 + (byte - b'0'),
            b'@' => 0x7c,
            b'#' => 0x7b,
            b'$' => 0x5b,
            _ => unreachable!("QualifiedName guarantees encoding"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        ConnectionGeneration,
    };

    fn advertisement(cp: &str, link_label: &[u8]) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse().unwrap(),
            node_id: if cp.ends_with('A') {
                [0, 0, 0, 1]
            } else {
                [0, 0, 0, 2]
            },
            hpr_sap: 4,
            link_label: link_label.to_vec(),
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

    fn setup<'a>(
        bootstrap: &'a HprControlBootstrap,
        lu: &'a QualifiedName,
    ) -> DirectReplyTarget<'a> {
        DirectReplyTarget {
            bootstrap,
            local_lu: lu,
            lu_nce_label: &[0xa4, 0],
            lu_nce_instance: [0, 0, 0, 4],
            tg_number: 1,
            reverse_metrics: ReverseLinkMetrics {
                transmission_time_us: 276,
                capacity_kbps: 4300,
                liveness_seconds: 0,
            },
        }
    }

    fn request() -> Vec<u8> {
        // Preserved direct V5R4 EE Route Setup request shape, with the
        // origin's outbound label in its single-hop forward ANR path.
        let hex = "007012ce0001000000000000000000000e0ef3e2d6d3d5c5e34be2d5c1c2162b010112461080010be2d6d3d5c5e34be2d5c1c2211660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e31a800000000005b500000114000010cc00000000066704008002";
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn builds_single_hop_positive_reply_for_authorized_lu() {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SOLNET.SNAB", &[0x80, 2]),
            advertisement("SOLNET.SNAA", &[0x80, 2]),
        )
        .unwrap();
        let lu: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let bytes = request();
        let parsed = RouteSetupGds::parse(&bytes).unwrap();
        let reply = setup(&bootstrap, &lu).encode_positive(&parsed).unwrap();
        let decoded = RouteSetupGds::parse(&reply).unwrap();
        assert_eq!(decoded.kind, RouteSetupKind::PositiveReply);
        assert_eq!(decoded.origin_cp_name, "SOLNET.SNAA");
        assert_eq!(decoded.destination_cp_name.as_deref(), Some("SOLNET.SNAB"));
        assert_eq!(decoded.pcid, parsed.pcid);
        assert_eq!(decoded.vectors.len(), 8);
        assert_eq!(decoded.vectors[0].wire[2] & 0x40, 0x40);
        assert_eq!(decoded.vectors[7].wire[2], 0xc0);
    }

    #[test]
    fn rejects_unknown_lu_and_wrong_tg_without_mutating_request() {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SOLNET.SNAB", &[0x80, 2]),
            advertisement("SOLNET.SNAA", &[0x80, 2]),
        )
        .unwrap();
        let bytes = request();
        let parsed = RouteSetupGds::parse(&bytes).unwrap();
        let lu: QualifiedName = "SOLNET.OTHER".parse().unwrap();
        assert_eq!(
            setup(&bootstrap, &lu).encode_positive(&parsed),
            Err(DirectReplyError::WrongDestination)
        );
        let lu: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let mut target = setup(&bootstrap, &lu);
        target.tg_number = 2;
        assert_eq!(
            target.encode_positive(&parsed),
            Err(DirectReplyError::InvalidRoute)
        );
    }

    #[test]
    fn live_cross_netid_request_keeps_directional_anr_labels() {
        // V5R4 EE 2026-11-02 17:43:44Z, initial X'12CE' after both CP-CP
        // sessions came up. The guest's forward X'67' is 80 02; our reverse
        // X'67' must be 80 80 from our own CV61 advertisement.
        let hex = "006f12ce0001000000000000000000000e0ef3e2d5e4e2d5e44bd7c9d5c7152b010111460f80010ae2d5e4e2d5e44be2e5c3211660cec370e7b283a2960be2d6d3d5c5e34be2d5c1c20c2c01087bc3d6d5d5c5c3e31a800000000005b500000114000010cc00000000066704008002";
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let mut peer = advertisement("SOLNET.SNAB", &[0x80, 0x02]);
        peer.node_id = [0, 0, 0, 3];
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", &[0x80, 0x80]),
            peer,
        )
        .unwrap();
        let lu: QualifiedName = "SNUSNU.PING".parse().unwrap();
        let parsed = RouteSetupGds::parse(&bytes).unwrap();
        let reply = setup(&bootstrap, &lu).encode_positive(&parsed).unwrap();
        let decoded = RouteSetupGds::parse(&reply).unwrap();
        let forward = decoded.vectors.iter().find(|cv| cv.key == 0x80).unwrap();
        assert!(forward.wire.ends_with(&[0x06, 0x67, 0x04, 0, 0x80, 0x02]));
        let reverse = decoded
            .vectors
            .iter()
            .rev()
            .find(|cv| cv.key == 0x80)
            .unwrap();
        assert!(reverse.wire.ends_with(&[0x06, 0x67, 0x04, 0, 0x80, 0x80]));

        let mut wrong_path = bytes.clone();
        *wrong_path.last_mut().unwrap() = 0x80;
        let wrong = RouteSetupGds::parse(&wrong_path).unwrap();
        assert_eq!(
            setup(&bootstrap, &lu).encode_positive(&wrong),
            Err(DirectReplyError::InvalidLinkLabel)
        );
    }
}
