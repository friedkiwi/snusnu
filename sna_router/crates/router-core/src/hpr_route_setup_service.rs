//! Generation-scoped Route Setup responder for one locally authorized LU.
//!
//! A validated control RTP connection delivers one complete X'12CE' GDS
//! message to this service. The service returns a positive reply only for an
//! exact direct-TG route to its registered LU, and retains bounded reply
//! bytes for duplicate request retransmissions. The caller owns RTP STATUS,
//! reply transmission, session admission, and topology publication.

use std::collections::VecDeque;

use crate::{
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_route_setup::{RouteSetupError, RouteSetupGds, RouteSetupKind},
    hpr_route_setup_reply::{DirectReplyError, DirectReplyTarget, ReverseLinkMetrics},
    hpr_switching_path::AuthorizedUserRoute,
    session::QualifiedName,
    ConnectionGeneration,
};

const MAX_REPLIES: usize = 32;
const MAX_REQUEST_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    InvalidLocalLu,
    InvalidIdentity,
    InvalidLimit,
    StaleGeneration,
    InvalidRequest(RouteSetupError),
    NotRequest,
    ConflictingPcid,
    Reply(DirectReplyError),
    UnknownPcid,
    WrongReply,
    ReplyNotSent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedReply {
    pcid: [u8; 8],
    request: Vec<u8>,
    reply: Vec<u8>,
    cos_tpf: Vec<u8>,
    sent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRouteSetupReply {
    /// Complete X'12CE' GDS to transmit over the validated control RTP
    /// connection. Returning it does not mark it sent or authorize an LU
    /// session; the runtime must verify successful RTP egress separately.
    pub gds: Vec<u8>,
    pub duplicate: bool,
    pub pcid: [u8; 8],
}

/// One direct EE adjacency and one LU for which local policy has explicitly
/// granted route setup. The entire cache is discarded on link generation
/// change, so old control RTP replies cannot be replayed into a new link.
#[derive(Clone, Debug)]
pub struct DirectRouteSetupService {
    bootstrap: HprControlBootstrap,
    local_lu: QualifiedName,
    lu_nce_label: Vec<u8>,
    lu_nce_instance: [u8; 4],
    tg_number: u8,
    reverse_metrics: ReverseLinkMetrics,
    limit: usize,
    replies: VecDeque<CachedReply>,
}

impl DirectRouteSetupService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bootstrap: HprControlBootstrap,
        local_lu: QualifiedName,
        lu_nce_label: Vec<u8>,
        lu_nce_instance: [u8; 4],
        tg_number: u8,
        reverse_metrics: ReverseLinkMetrics,
        max_cached_replies: usize,
    ) -> Result<Self, ServiceError> {
        if local_lu.netid != bootstrap.local.cp.netid
            || tg_number == 0
            || !(1..=8).contains(&lu_nce_label.len())
            || lu_nce_label[0] & 0x80 == 0
            || lu_nce_label.contains(&0xff)
        {
            return Err(ServiceError::InvalidLocalLu);
        }
        if max_cached_replies == 0 || max_cached_replies > MAX_REPLIES {
            return Err(ServiceError::InvalidLimit);
        }
        Ok(Self {
            bootstrap,
            local_lu,
            lu_nce_label,
            lu_nce_instance,
            tg_number,
            reverse_metrics,
            limit: max_cached_replies,
            replies: VecDeque::new(),
        })
    }

    pub fn generation(&self) -> ConnectionGeneration {
        self.bootstrap.generation
    }

    pub fn local_lu(&self) -> &QualifiedName {
        &self.local_lu
    }

    pub fn cached_replies(&self) -> usize {
        self.replies.len()
    }

    pub fn prepare_reply(
        &mut self,
        generation: ConnectionGeneration,
        message: &[u8],
    ) -> Result<PreparedRouteSetupReply, ServiceError> {
        if generation != self.bootstrap.generation {
            return Err(ServiceError::StaleGeneration);
        }
        if message.len() > MAX_REQUEST_BYTES {
            return Err(ServiceError::InvalidRequest(RouteSetupError::TooLarge));
        }
        let request = RouteSetupGds::parse(message).map_err(ServiceError::InvalidRequest)?;
        if request.kind != RouteSetupKind::Request {
            return Err(ServiceError::NotRequest);
        }
        if let Some(cached) = self.replies.iter().find(|reply| reply.pcid == request.pcid) {
            if cached.request != message {
                return Err(ServiceError::ConflictingPcid);
            }
            return Ok(PreparedRouteSetupReply {
                gds: cached.reply.clone(),
                duplicate: true,
                pcid: request.pcid,
            });
        }
        let target = DirectReplyTarget {
            bootstrap: &self.bootstrap,
            local_lu: &self.local_lu,
            lu_nce_label: &self.lu_nce_label,
            lu_nce_instance: self.lu_nce_instance,
            tg_number: self.tg_number,
            reverse_metrics: self.reverse_metrics,
        };
        let reply = target
            .encode_positive(&request)
            .map_err(ServiceError::Reply)?;
        let cos_tpf = request
            .vectors
            .iter()
            .find(|cv| cv.key == 0x2c)
            .ok_or(ServiceError::InvalidRequest(
                RouteSetupError::MissingRequiredVector,
            ))?
            .wire
            .to_vec();
        if self.replies.len() == self.limit {
            self.replies.pop_front();
        }
        self.replies.push_back(CachedReply {
            pcid: request.pcid,
            request: message.to_vec(),
            reply: reply.clone(),
            cos_tpf,
            sent: false,
        });
        Ok(PreparedRouteSetupReply {
            gds: reply,
            duplicate: false,
            pcid: request.pcid,
        })
    }

    /// Call only after the exact positive GDS was successfully handed to the
    /// RTP egress. A prepared reply alone never admits a user RTP connection.
    pub fn confirm_reply_sent(
        &mut self,
        generation: ConnectionGeneration,
        pcid: [u8; 8],
        gds: &[u8],
    ) -> Result<AuthorizedUserRoute, ServiceError> {
        if generation != self.bootstrap.generation {
            return Err(ServiceError::StaleGeneration);
        }
        let cached = self
            .replies
            .iter_mut()
            .find(|reply| reply.pcid == pcid)
            .ok_or(ServiceError::UnknownPcid)?;
        if cached.reply != gds {
            return Err(ServiceError::WrongReply);
        }
        cached.sent = true;
        self.authorized_route(generation, pcid)
    }

    /// Retrieve authorization for a route whose positive reply was sent.
    pub fn authorized_route(
        &self,
        generation: ConnectionGeneration,
        pcid: [u8; 8],
    ) -> Result<AuthorizedUserRoute, ServiceError> {
        if generation != self.bootstrap.generation {
            return Err(ServiceError::StaleGeneration);
        }
        let cached = self
            .replies
            .iter()
            .find(|reply| reply.pcid == pcid)
            .ok_or(ServiceError::UnknownPcid)?;
        if !cached.sent {
            return Err(ServiceError::ReplyNotSent);
        }
        Ok(AuthorizedUserRoute {
            generation,
            target_lu: self.local_lu.clone(),
            local_nce_label: self.lu_nce_label.clone(),
            local_nce_instance: self.lu_nce_instance,
            cos_tpf: cached.cos_tpf.clone(),
            tg_number: self.tg_number,
            return_link_label: self.bootstrap.local.link_label.clone(),
            maximum_packet_size: self.bootstrap.max_packet_size,
        })
    }

    /// The runtime obtains a new bootstrap only after a fresh XID/TG
    /// exchange; route replies from the former generation are dropped.
    pub fn reset(&mut self, bootstrap: HprControlBootstrap) -> Result<(), ServiceError> {
        if bootstrap.generation.get() <= self.bootstrap.generation.get() {
            return Err(ServiceError::StaleGeneration);
        }
        if bootstrap.local.cp.netid != self.local_lu.netid {
            return Err(ServiceError::InvalidLocalLu);
        }
        if bootstrap.local.cp != self.bootstrap.local.cp
            || bootstrap.peer.cp != self.bootstrap.peer.cp
        {
            return Err(ServiceError::InvalidIdentity);
        }
        self.bootstrap = bootstrap;
        self.replies.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cv61::{ArbMode, ControlFlowsTower},
    };

    const REQUEST: &str = "007012ce0001000000000000000000000e0ef3e2d6d3d5c5e34be2d5c1c2162b010112461080010be2d6d3d5c5e34be2d5c1c2211660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e31a800000000005b500000114000010cc00000000066704008002";

    fn unhex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn qualified(name: &str) -> Vec<u8> {
        let (netid, cp) = name.split_once('.').unwrap();
        let mut result =
            crate::hpr_control_bootstrap::encode_network_name_component(netid).unwrap();
        result.push(0x4b);
        result.extend_from_slice(
            &crate::hpr_control_bootstrap::encode_network_name_component(cp).unwrap(),
        );
        result
    }

    fn advertisement(cp: &str, node: u8) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse().unwrap(),
            node_id: [0, 0, 0, node],
            hpr_sap: 4,
            link_label: vec![0x80, 2],
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

    fn service(generation: u64, limit: usize) -> DirectRouteSetupService {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(generation).unwrap(),
            advertisement("SOLNET.SNAB", 2),
            advertisement("SOLNET.SNAA", 1),
        )
        .unwrap();
        DirectRouteSetupService::new(
            bootstrap,
            "SOLNET.SNAB".parse().unwrap(),
            vec![0xa4, 0],
            [0, 0, 0, 4],
            1,
            ReverseLinkMetrics {
                transmission_time_us: 276,
                capacity_kbps: 4300,
                liveness_seconds: 0,
            },
            limit,
        )
        .unwrap()
    }

    fn cross_netid_aping_request() -> Vec<u8> {
        // An EN in SOLNET reaches the concentrator-owned NN proxy CP and LU
        // in SNUSNU. The RTP link remains one direct regular TG.
        let mut wire = vec![0, 0, 0x12, 0xce, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut lu_name = vec![0xf3];
        lu_name.extend_from_slice(&qualified("SNUSNU.PING"));
        wire.extend_from_slice(&[(2 + lu_name.len()) as u8, 0x0e]);
        wire.extend_from_slice(&lu_name);
        let cp_name = qualified("SNUSNU.SVC");
        let tg_len = 5 + cp_name.len();
        wire.extend_from_slice(&[
            (6 + tg_len) as u8,
            0x2b,
            1,
            1,
            (2 + tg_len) as u8,
            0x46,
            tg_len as u8,
            0x80,
            1,
            cp_name.len() as u8,
        ]);
        wire.extend_from_slice(&cp_name);
        wire.push(0x21);
        let origin = qualified("SOLNET.SNAB");
        wire.extend_from_slice(&[(11 + origin.len()) as u8, 0x60]);
        wire.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        wire.push(origin.len() as u8);
        wire.extend_from_slice(&origin);
        wire.extend_from_slice(&[4, 0x2c, 1, 0]);
        wire.extend_from_slice(&[
            26, 0x80, 0, 0, 0, 0, 5, 0xb5, 0, 0, 1, 0x14, 0, 0, 0x10, 0xcc, 0, 0, 0, 0, 6, 0x67, 4,
            0, 0x80, 2,
        ]);
        let length = wire.len() as u16;
        wire[..2].copy_from_slice(&length.to_be_bytes());
        wire
    }

    #[test]
    fn captured_request_gets_stable_reply_and_replay_is_bounded() {
        let mut service = service(1, 1);
        let request = unhex(REQUEST);
        let first = service
            .prepare_reply(ConnectionGeneration::new(1).unwrap(), &request)
            .unwrap();
        assert!(!first.duplicate);
        let again = service
            .prepare_reply(ConnectionGeneration::new(1).unwrap(), &request)
            .unwrap();
        assert!(again.duplicate);
        assert_eq!(first.gds, again.gds);
        assert_eq!(service.cached_replies(), 1);
        assert_eq!(
            service.authorized_route(ConnectionGeneration::new(1).unwrap(), first.pcid),
            Err(ServiceError::ReplyNotSent)
        );
        assert_eq!(
            service.confirm_reply_sent(ConnectionGeneration::new(1).unwrap(), first.pcid, &request),
            Err(ServiceError::WrongReply)
        );
        let authorized = service
            .confirm_reply_sent(
                ConnectionGeneration::new(1).unwrap(),
                first.pcid,
                &first.gds,
            )
            .unwrap();
        assert_eq!(authorized.generation, ConnectionGeneration::new(1).unwrap());
        assert_eq!(authorized.target_lu, "SOLNET.SNAB".parse().unwrap());
        assert_eq!(authorized.local_nce_label, [0xa4, 0]);
        assert_eq!(authorized.cos_tpf[1], 0x2c);

        let mut conflicting = request.clone();
        conflicting[85] = 0xe4; // COS name changed while PCID stayed the same.
        assert_eq!(
            service.prepare_reply(ConnectionGeneration::new(1).unwrap(), &conflicting),
            Err(ServiceError::ConflictingPcid)
        );
        assert_eq!(service.cached_replies(), 1);
    }

    #[test]
    fn old_generation_and_unregistered_lu_do_not_prepare_reply() {
        let mut service = service(2, 2);
        let request = unhex(REQUEST);
        assert_eq!(
            service.prepare_reply(ConnectionGeneration::new(1).unwrap(), &request),
            Err(ServiceError::StaleGeneration)
        );
        let mut other = request.clone();
        // Change only the destination LU's last EBCDIC character B -> C.
        other[29] = 0xc3;
        assert_eq!(
            service.prepare_reply(ConnectionGeneration::new(2).unwrap(), &other),
            Err(ServiceError::Reply(DirectReplyError::WrongDestination))
        );
        assert_eq!(service.cached_replies(), 0);
    }

    #[test]
    fn new_link_generation_discards_cached_route_decisions() {
        let mut service = service(1, 2);
        let request = unhex(REQUEST);
        service
            .prepare_reply(ConnectionGeneration::new(1).unwrap(), &request)
            .unwrap();
        assert_eq!(service.cached_replies(), 1);
        let replacement = HprControlBootstrap::new(
            ConnectionGeneration::new(2).unwrap(),
            advertisement("SOLNET.SNAB", 2),
            advertisement("SOLNET.SNAA", 1),
        )
        .unwrap();
        service.reset(replacement).unwrap();
        assert_eq!(service.cached_replies(), 0);
        assert_eq!(
            service.prepare_reply(ConnectionGeneration::new(1).unwrap(), &request),
            Err(ServiceError::StaleGeneration)
        );
        assert!(
            !service
                .prepare_reply(ConnectionGeneration::new(2).unwrap(), &request)
                .unwrap()
                .duplicate
        );
    }

    #[test]
    fn end_node_in_other_netid_can_reach_authorized_aping_lu() {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", 2),
            advertisement("SOLNET.SNAB", 1),
        )
        .unwrap();
        let mut service = DirectRouteSetupService::new(
            bootstrap,
            "SNUSNU.PING".parse().unwrap(),
            vec![0xa4, 0],
            [0, 0, 0, 4],
            1,
            ReverseLinkMetrics {
                transmission_time_us: 276,
                capacity_kbps: 4300,
                liveness_seconds: 0,
            },
            2,
        )
        .unwrap();
        let request = cross_netid_aping_request();
        let parsed = RouteSetupGds::parse(&request).unwrap();
        assert_eq!(parsed.origin_cp_name, "SOLNET.SNAB");
        assert_eq!(parsed.destination_lu_name.as_deref(), Some("SNUSNU.PING"));
        let prepared = service
            .prepare_reply(ConnectionGeneration::new(1).unwrap(), &request)
            .unwrap();
        let reply = RouteSetupGds::parse(&prepared.gds).unwrap();
        assert_eq!(reply.destination_cp_name.as_deref(), Some("SNUSNU.SVC"));
        assert_eq!(reply.pcid, parsed.pcid);
    }
}
