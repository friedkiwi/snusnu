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
    /// Present only when a caller has independently verified the adjacent
    /// CP and its ownership of this LU through local route discovery.
    verified_external_cp: Option<QualifiedName>,
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
        if local_lu.netid != bootstrap.local.cp.netid {
            return Err(ServiceError::InvalidLocalLu);
        }
        Self::new_scoped(
            bootstrap,
            local_lu,
            None,
            lu_nce_label,
            lu_nce_instance,
            tg_number,
            reverse_metrics,
            max_cached_replies,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_scoped(
        bootstrap: HprControlBootstrap,
        local_lu: QualifiedName,
        verified_external_cp: Option<QualifiedName>,
        lu_nce_label: Vec<u8>,
        lu_nce_instance: [u8; 4],
        tg_number: u8,
        reverse_metrics: ReverseLinkMetrics,
        max_cached_replies: usize,
    ) -> Result<Self, ServiceError> {
        if tg_number == 0
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
            verified_external_cp,
            lu_nce_label,
            lu_nce_instance,
            tg_number,
            reverse_metrics,
            limit: max_cached_replies,
            replies: VecDeque::new(),
        })
    }

    /// Authorize a route to an LU behind a verified adjacent CP. The caller
    /// must have observed the CP on the egress attachment and learned that
    /// this exact LU is hosted by it. A RouteSetup request alone is never
    /// evidence of either property.
    #[allow(clippy::too_many_arguments)]
    pub fn new_verified_external(
        bootstrap: HprControlBootstrap,
        target_lu: QualifiedName,
        verified_target_cp: QualifiedName,
        lu_nce_label: Vec<u8>,
        lu_nce_instance: [u8; 4],
        tg_number: u8,
        reverse_metrics: ReverseLinkMetrics,
        max_cached_replies: usize,
    ) -> Result<Self, ServiceError> {
        if verified_target_cp == bootstrap.local.cp || target_lu.netid != verified_target_cp.netid {
            return Err(ServiceError::InvalidIdentity);
        }
        Self::new_scoped(
            bootstrap,
            target_lu,
            Some(verified_target_cp),
            lu_nce_label,
            lu_nce_instance,
            tg_number,
            reverse_metrics,
            max_cached_replies,
        )
    }

    pub fn generation(&self) -> ConnectionGeneration {
        self.bootstrap.generation
    }

    pub fn local_lu(&self) -> &QualifiedName {
        &self.local_lu
    }

    pub fn lu_nce_label(&self) -> &[u8] {
        &self.lu_nce_label
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
        let reply = match &self.verified_external_cp {
            Some(cp) => target.encode_positive_for_external(&request, cp),
            None => target.encode_positive(&request),
        }
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

    /// Re-establish a route to an already active LU NCE. A path-switch
    /// request omits the LU name, so the caller must supply the *live* RTP
    /// authorization for this exact target, not just a directory entry.
    pub fn prepare_path_switch_reply(
        &mut self,
        generation: ConnectionGeneration,
        message: &[u8],
        active: &AuthorizedUserRoute,
    ) -> Result<PreparedRouteSetupReply, ServiceError> {
        if generation != self.bootstrap.generation || active.generation != generation {
            return Err(ServiceError::StaleGeneration);
        }
        if message.len() > MAX_REQUEST_BYTES {
            return Err(ServiceError::InvalidRequest(RouteSetupError::TooLarge));
        }
        let request = RouteSetupGds::parse(message).map_err(ServiceError::InvalidRequest)?;
        if request.kind != RouteSetupKind::Request
            || !request.path_switch
            || request.destination_lu_name.is_some()
        {
            return Err(ServiceError::NotRequest);
        }
        let cos = request
            .vectors
            .iter()
            .filter(|cv| cv.key == 0x2c)
            .map(|cv| cv.wire)
            .collect::<Vec<_>>();
        if cos.len() != 1
            || active.target_lu != self.local_lu
            || active.verified_external_cp != self.verified_external_cp
            || active.local_nce_label != self.lu_nce_label
            || active.local_nce_instance != self.lu_nce_instance
            || active.cos_tpf != cos[0]
            || active.tg_number != self.tg_number
            || active.return_link_label != self.bootstrap.local.link_label
            || active.maximum_packet_size != self.bootstrap.max_packet_size
            || !self
                .replies
                .iter()
                .any(|cached| cached.sent && cached.cos_tpf == cos[0])
        {
            return Err(ServiceError::InvalidIdentity);
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
            .encode_positive_path_switch(&request, self.verified_external_cp.as_ref())
            .map_err(ServiceError::Reply)?;
        if self.replies.len() == self.limit {
            self.replies.pop_front();
        }
        self.replies.push_back(CachedReply {
            pcid: request.pcid,
            request: message.to_vec(),
            reply: reply.clone(),
            cos_tpf: cos[0].to_vec(),
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
            verified_external_cp: self.verified_external_cp.clone(),
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
        // The adjacent CP/LU observation belongs to the old association.
        // Recreate an external service only after the new egress is verified.
        if self.verified_external_cp.is_some() {
            return Err(ServiceError::InvalidIdentity);
        }
        let expected_netid = self
            .verified_external_cp
            .as_ref()
            .map_or(&bootstrap.local.cp.netid, |cp| &cp.netid);
        if expected_netid != &self.local_lu.netid {
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
    const LIVE_EXTERNAL_REQUEST: &str = "006f12ce0001000000000000000000000e0ef3e2d6d3d5c5e34be2d5c1c1152b010111460f80010ae2d5e4e2d5e44be2e5c3211660cec370e7b283a34d0be2d6d3d5c5e34be2d5c1c20c2c01087bc3d6d5d5c5c3e31a800000000005b500000114000010cc00000000066704008002";
    const LIVE_PATH_SWITCH: &str = "006512ce400100000000000000000000152b010111460f80010ae2d5e4e2d5e44be2e5c3211660cec370e7b283a34f0be2d6d3d5c5e34be2d5c1c20c2c01087bc3d6d5d5c5c3e30426a4241a800000000005b500000114000010cc00000000066704008002";

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

    fn live_external_service() -> DirectRouteSetupService {
        let mut local = advertisement("SNUSNU.SVC", 3);
        local.link_label = vec![0x80, 0x80];
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            local,
            advertisement("SOLNET.SNAB", 2),
        )
        .unwrap();
        DirectRouteSetupService::new_verified_external(
            bootstrap,
            "SOLNET.SNAA".parse().unwrap(),
            "SOLNET.SNAA".parse().unwrap(),
            vec![0xa4, 0x24],
            [0xff, 0xfa, 0x77, 0x24],
            1,
            ReverseLinkMetrics {
                transmission_time_us: 1000,
                capacity_kbps: 100_000,
                liveness_seconds: 10,
            },
            16,
        )
        .unwrap()
    }

    #[test]
    fn live_lu_less_path_switch_requires_active_exact_route_and_replies_positive() {
        let mut service = live_external_service();
        let generation = service.generation();
        let initial = service
            .prepare_reply(generation, &unhex(LIVE_EXTERNAL_REQUEST))
            .unwrap();
        let active = service
            .confirm_reply_sent(generation, initial.pcid, &initial.gds)
            .unwrap();
        let switch = unhex(LIVE_PATH_SWITCH);
        let prepared = service
            .prepare_path_switch_reply(generation, &switch, &active)
            .unwrap();
        assert!(!prepared.duplicate);
        let parsed = RouteSetupGds::parse(&prepared.gds).unwrap();
        assert_eq!(parsed.kind, RouteSetupKind::PositiveReply);
        assert_eq!(parsed.pcid, RouteSetupGds::parse(&switch).unwrap().pcid);
        assert_eq!(
            prepared
                .gds
                .windows(4)
                .filter(|part| *part == [4, 0x26, 0xa4, 0x24])
                .count(),
            1
        );
        assert!(
            service
                .prepare_path_switch_reply(generation, &switch, &active)
                .unwrap()
                .duplicate
        );
        let renewed = service
            .confirm_reply_sent(generation, prepared.pcid, &prepared.gds)
            .unwrap();
        assert_eq!(renewed, active);

        let mut wrong_active = active.clone();
        wrong_active.verified_external_cp = None;
        assert_eq!(
            service.prepare_path_switch_reply(generation, &switch, &wrong_active),
            Err(ServiceError::InvalidIdentity)
        );
        let mut wrong_nce = switch.clone();
        let nce = wrong_nce
            .windows(4)
            .position(|part| part == [4, 0x26, 0xa4, 0x24])
            .unwrap();
        wrong_nce[nce + 3] ^= 1;
        let pcid = wrong_nce
            .windows(8)
            .position(|part| part == [0xce, 0xc3, 0x70, 0xe7, 0xb2, 0x83, 0xa3, 0x4f])
            .unwrap();
        wrong_nce[pcid + 7] = 0x50;
        assert_eq!(
            service.prepare_path_switch_reply(generation, &wrong_nce, &active),
            Err(ServiceError::Reply(DirectReplyError::InvalidPathSwitch))
        );
        let mut wrong_pcid_replay = switch.clone();
        wrong_pcid_replay[nce + 3] ^= 1;
        assert_eq!(
            service.prepare_path_switch_reply(generation, &wrong_pcid_replay, &active),
            Err(ServiceError::ConflictingPcid)
        );
    }

    fn cross_netid_request(lu: &str) -> Vec<u8> {
        // An EN in SOLNET reaches the concentrator-owned NN proxy CP and LU
        // in SNUSNU. The RTP link remains one direct regular TG.
        let mut wire = vec![0, 0, 0x12, 0xce, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut lu_name = vec![0xf3];
        lu_name.extend_from_slice(&qualified(lu));
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
        let request = cross_netid_request("SNUSNU.PING");
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

    #[test]
    fn external_lu_requires_verified_cp_in_same_netid() {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", 2),
            advertisement("SOLNET.SNAB", 1),
        )
        .unwrap();
        let target_lu: QualifiedName = "QABOB.APP".parse().unwrap();
        let metrics = ReverseLinkMetrics {
            transmission_time_us: 276,
            capacity_kbps: 4300,
            liveness_seconds: 0,
        };
        let request = cross_netid_request("QABOB.APP");
        assert_eq!(
            DirectRouteSetupService::new(
                bootstrap.clone(),
                target_lu.clone(),
                vec![0xa4, 0],
                [0, 0, 0, 4],
                1,
                metrics,
                2,
            )
            .unwrap_err(),
            ServiceError::InvalidLocalLu,
        );
        assert_eq!(
            DirectRouteSetupService::new_verified_external(
                bootstrap.clone(),
                target_lu.clone(),
                "QAEVE.SNAC".parse().unwrap(),
                vec![0xa4, 0],
                [0, 0, 0, 4],
                1,
                metrics,
                2,
            )
            .unwrap_err(),
            ServiceError::InvalidIdentity,
        );
        let mut service = DirectRouteSetupService::new_verified_external(
            bootstrap.clone(),
            target_lu.clone(),
            "QABOB.SNAB".parse().unwrap(),
            vec![0xa4, 0],
            [0, 0, 0, 4],
            1,
            metrics,
            2,
        )
        .unwrap();
        let prepared = service
            .prepare_reply(bootstrap.generation, &request)
            .unwrap();
        let authorized = service
            .confirm_reply_sent(bootstrap.generation, prepared.pcid, &prepared.gds)
            .unwrap();
        assert_eq!(authorized.target_lu, target_lu);
        assert_eq!(
            authorized.verified_external_cp,
            Some("QABOB.SNAB".parse().unwrap())
        );
        let replacement = HprControlBootstrap::new(
            ConnectionGeneration::new(2).unwrap(),
            advertisement("SNUSNU.SVC", 2),
            advertisement("SOLNET.SNAB", 1),
        )
        .unwrap();
        assert_eq!(
            service.reset(replacement),
            Err(ServiceError::InvalidIdentity)
        );
        let mut wrong_request = cross_netid_request("QABOB.OTHER");
        let pcid_offset = wrong_request
            .windows(2)
            .position(|part| part[1] == 0x60 && (14..=28).contains(&part[0]))
            .unwrap()
            + 4;
        wrong_request[pcid_offset] ^= 1;
        assert_eq!(
            service.prepare_reply(bootstrap.generation, &wrong_request),
            Err(ServiceError::Reply(DirectReplyError::WrongDestination)),
        );
    }

    #[test]
    fn verified_adjacent_cp_may_share_proxy_netid() {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", 2),
            advertisement("SOLNET.SNAB", 1),
        )
        .unwrap();
        let metrics = ReverseLinkMetrics {
            transmission_time_us: 276,
            capacity_kbps: 4300,
            liveness_seconds: 0,
        };
        let lu = "SNUSNU.APP".parse().unwrap();
        assert_eq!(
            DirectRouteSetupService::new_verified_external(
                bootstrap.clone(),
                lu,
                "SNUSNU.SVC".parse().unwrap(),
                vec![0xa4, 0],
                [0, 0, 0, 4],
                1,
                metrics,
                2,
            )
            .unwrap_err(),
            ServiceError::InvalidIdentity
        );
        let mut service = DirectRouteSetupService::new_verified_external(
            bootstrap.clone(),
            "SNUSNU.APP".parse().unwrap(),
            "SNUSNU.REMOTE".parse().unwrap(),
            vec![0xa4, 0],
            [0, 0, 0, 4],
            1,
            metrics,
            2,
        )
        .unwrap();
        let reply = service
            .prepare_reply(bootstrap.generation, &cross_netid_request("SNUSNU.APP"))
            .unwrap();
        let route = service
            .confirm_reply_sent(bootstrap.generation, reply.pcid, &reply.gds)
            .unwrap();
        assert!(route.target_netid_authorized(&bootstrap.local.cp));
    }
}
