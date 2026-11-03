//! One concentrator-originated LU session headed toward an adjacent EE peer.
//!
//! This state contains no socket operations. The runtime confirms each
//! RouteSetup and RTP transmission before committing the candidate adapter,
//! so backpressure cannot advance SNA addressing or pacing state.

use std::io;

use router_core::{
    fid2_bind::BindClass,
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_fid5::{encode_whole_biu, Fid5WholeBiu},
    hpr_route_setup_initiator::{DirectLinkMetrics, DirectRouteSetupInitiator, OutboundUserRoute},
    hpr_rtp_outbound_setup::UserSetupConfig,
    hpr_session_adapter::{HprEgress, HprIngress, HprSessionAdapter, HprSessionRole},
    hpr_session_address::{RtpAssociationScope, RtpObservation},
    session::{Flow, SessionEvent, SessionIdentity, SessionUnit},
    ConnectionGeneration,
};

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

pub(crate) struct ReverseHprUser {
    bootstrap: HprControlBootstrap,
    identity: SessionIdentity,
    bind_request: SessionUnit,
    initial_bind: Vec<u8>,
    local_sa: u64,
    route_setup: DirectRouteSetupInitiator,
    route: Option<OutboundUserRoute>,
    adapter: Option<HprSessionAdapter>,
}

impl ReverseHprUser {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        bootstrap: HprControlBootstrap,
        identity: SessionIdentity,
        bind_request: SessionUnit,
        tg_number: u8,
        pcid: [u8; 8],
        local_user_nce_label: Vec<u8>,
        local_user_nce_instance: [u8; 4],
        local_sa: u64,
        metrics: DirectLinkMetrics,
    ) -> io::Result<Self> {
        if identity.target_cp.as_ref() != Some(&bootstrap.peer.cp)
            || identity.source_cp.is_none()
            || identity.target_lu.netid != bootstrap.peer.cp.netid
            || local_sa & (3u64 << 62) != 1u64 << 63
            || local_sa & ((1u64 << 62) - 1) == 0
        {
            return Err(invalid("reverse HPR identity or local SA invalid"));
        }
        let initial_bind = encode_whole_biu(local_sa.to_be_bytes(), Flow::Expedited, &bind_request)
            .map_err(|error| invalid(format!("reverse HPR BIND encoding: {error:?}")))?;
        let fid5 = Fid5WholeBiu::parse_complete(&initial_bind)
            .map_err(|error| invalid(format!("reverse HPR BIND shape: {error:?}")))?;
        let parsed = fid5
            .classify_bind()
            .map_err(|error| invalid(format!("reverse HPR BIND identity: {error:?}")))?
            .ok_or_else(|| invalid("reverse HPR first unit is not BIND"))?;
        if matches!(parsed.class, BindClass::Management { .. })
            || parsed.plu != identity.source_lu.to_string()
            || parsed.slu != identity.target_lu.to_string()
        {
            return Err(invalid(
                "reverse HPR BIND differs from authenticated routes",
            ));
        }
        let route_setup = DirectRouteSetupInitiator::new(
            bootstrap.clone(),
            identity.target_lu.clone(),
            tg_number,
            pcid,
            local_user_nce_label,
            local_user_nce_instance,
            metrics,
        )
        .map_err(|error| invalid(format!("reverse HPR RouteSetup: {error:?}")))?;
        Ok(Self {
            bootstrap,
            identity,
            bind_request,
            initial_bind,
            local_sa,
            route_setup,
            route: None,
            adapter: None,
        })
    }

    pub(crate) fn route_request(&self) -> &[u8] {
        self.route_setup.request()
    }

    pub(crate) fn mark_route_sent(&mut self, request: &[u8]) -> io::Result<()> {
        self.route_setup
            .confirm_request_sent(request)
            .map_err(|error| invalid(format!("reverse HPR RouteSetup send: {error:?}")))
    }

    pub(crate) fn accept_route_reply(
        &mut self,
        generation: ConnectionGeneration,
        reply: &[u8],
    ) -> io::Result<UserSetupConfig> {
        let route = self
            .route_setup
            .observe_reply(generation, reply)
            .map_err(|error| invalid(format!("reverse HPR RouteSetup reply: {error:?}")))?;
        let config = UserSetupConfig {
            local_nce_label: route.local_user_nce_label.clone(),
            local_nce_instance: route.local_user_nce_instance,
            peer_nce_label: route.peer_user_nce_label.clone(),
            peer_nce_instance: route.peer_user_nce_instance,
            peer_link_label: route.peer_link_label.clone(),
            cos_tpf: route.cos_tpf.clone(),
            target_lu: route.target_lu.to_string(),
            maximum_packet_size: route.maximum_packet_size,
        };
        self.route = Some(route);
        Ok(config)
    }

    pub(crate) fn initial_bind_fid5(&self) -> &[u8] {
        &self.initial_bind
    }

    pub(crate) fn bind_request(&self) -> &SessionUnit {
        &self.bind_request
    }

    /// The first BIND was carried in the outbound user RTP setup. Once the
    /// peer's CIE supplies the subsequent TCID, replay that event on a fresh
    /// adapter and confirm it produces the exact FID5 bytes already sent.
    pub(crate) fn activate_user(&mut self, scope: RtpAssociationScope) -> io::Result<()> {
        if self.route.is_none()
            || self.adapter.is_some()
            || scope.generation != self.bootstrap.generation
        {
            return Err(invalid("reverse HPR user RTP not ready"));
        }
        let adapter = HprSessionAdapter::new(
            HprSessionRole::RouterPlu,
            scope,
            self.local_sa,
            self.identity.source_cp.clone(),
            self.identity.target_cp.clone(),
        )
        .map_err(|error| invalid(format!("reverse HPR adapter: {error:?}")))?;
        let (candidate, egress) = adapter
            .preview_egress(SessionEvent::BindRequest(self.bind_request.clone()))
            .map_err(|error| invalid(format!("reverse HPR BIND replay: {error:?}")))?;
        let egress = egress.ok_or_else(|| invalid("reverse HPR BIND replay has no BIU"))?;
        if egress.message != self.initial_bind || egress.observation.tcid != scope.initial_plu_tcid
        {
            return Err(invalid("reverse HPR BIND replay differs from RTP setup"));
        }
        self.adapter = Some(candidate);
        Ok(())
    }

    pub(crate) fn preview_ws_event(
        &self,
        event: SessionEvent,
    ) -> io::Result<(HprSessionAdapter, Option<HprEgress>)> {
        self.adapter
            .as_ref()
            .ok_or_else(|| invalid("reverse HPR user RTP not active"))?
            .preview_egress(event)
            .map_err(|error| invalid(format!("reverse HPR WS event: {error:?}")))
    }

    pub(crate) fn preview_hpr_message(
        &self,
        observation: RtpObservation,
        bytes: &[u8],
    ) -> io::Result<(HprSessionAdapter, HprIngress)> {
        self.adapter
            .as_ref()
            .ok_or_else(|| invalid("reverse HPR user RTP not active"))?
            .preview_ingress(observation, bytes)
            .map_err(|error| invalid(format!("reverse HPR peer BIU: {error:?}")))
    }

    pub(crate) fn commit_adapter(&mut self, adapter: HprSessionAdapter) {
        self.adapter = Some(adapter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::{
        hpr_control_bootstrap::{encode_network_name_component, ControlAdvertisement},
        hpr_cv61::{ArbMode, ControlFlowsTower},
        hpr_route_setup::{RouteSetupGds, RouteSetupKind},
        hpr_route_setup_reply::{DirectReplyTarget, ReverseLinkMetrics},
        hpr_rtp::RtpPacket,
        hpr_rtp_outbound_setup::encode_user_setup,
        hpr_rtp_setup::{classify_setup_topic, RtpSetupTopic},
    };

    fn advertisement(cp: &str, node_id: u8) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse().unwrap(),
            node_id: [0, 0, 0, node_id],
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

    fn bind(identity: &SessionIdentity) -> SessionUnit {
        let name = |qualified: &router_core::session::QualifiedName| {
            let mut bytes = encode_network_name_component(&qualified.netid).unwrap();
            bytes.push(0x4b);
            bytes.extend(encode_network_name_component(&qualified.name).unwrap());
            bytes
        };
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        let plu = name(&identity.source_lu);
        let slu = name(&identity.target_lu);
        ru.push(plu.len() as u8);
        ru.extend_from_slice(&plu);
        ru.extend_from_slice(&[1, 0, 0]);
        ru.push(slu.len() as u8);
        ru.extend_from_slice(&slu);
        let mut reduced = vec![0x80, 1, 0x6b, 0x80, 0];
        reduced.extend_from_slice(&ru);
        SessionUnit::from_reduced(&reduced).unwrap()
    }

    fn setup() -> (HprControlBootstrap, SessionIdentity, SessionUnit) {
        let generation = ConnectionGeneration::new(1).unwrap();
        let bootstrap = HprControlBootstrap::new(
            generation,
            advertisement("SNUSNU.SVC", 1),
            advertisement("SOLNET.SNAB", 2),
        )
        .unwrap();
        let identity = SessionIdentity::new(
            "OTHERNET.CLIENT".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
        )
        .with_control_points(
            Some("OTHERNET.CP".parse().unwrap()),
            Some("SOLNET.SNAB".parse().unwrap()),
        )
        .unwrap();
        let bind = bind(&identity);
        (bootstrap, identity, bind)
    }

    #[test]
    fn reverse_session_correlates_route_reply_and_replays_first_bind() {
        let (bootstrap, identity, bind) = setup();
        let mut reverse = ReverseHprUser::new(
            bootstrap.clone(),
            identity,
            bind,
            1,
            [1, 2, 3, 4, 5, 6, 7, 8],
            vec![0xa4, 1],
            [0, 0, 0, 5],
            0x8000_0000_0000_0023,
            DirectLinkMetrics {
                transmission_time_us: 1000,
                capacity_kbps: 100_000,
                liveness_seconds: 10,
            },
        )
        .unwrap();
        let request = reverse.route_request().to_vec();
        assert_eq!(
            RouteSetupGds::parse(&request).unwrap().kind,
            RouteSetupKind::Request
        );
        let peer_bootstrap = HprControlBootstrap::new(
            bootstrap.generation,
            bootstrap.peer.clone(),
            bootstrap.local.clone(),
        )
        .unwrap();
        let target_lu: router_core::session::QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let reply = DirectReplyTarget {
            bootstrap: &peer_bootstrap,
            local_lu: &target_lu,
            lu_nce_label: &[0xa4, 2],
            lu_nce_instance: [0, 0, 0, 6],
            tg_number: 1,
            reverse_metrics: ReverseLinkMetrics {
                transmission_time_us: 1000,
                capacity_kbps: 100_000,
                liveness_seconds: 10,
            },
        }
        .encode_positive(&RouteSetupGds::parse(&request).unwrap())
        .unwrap();
        reverse.mark_route_sent(&request).unwrap();
        let config = reverse
            .accept_route_reply(bootstrap.generation, &reply)
            .unwrap();
        assert_eq!(config.local_nce_label, [0xa4, 1]);
        assert_eq!(config.peer_nce_label, [0xa4, 2]);
        assert_eq!(config.peer_nce_instance, [0, 0, 0, 6]);
        let first = Fid5WholeBiu::parse_complete(reverse.initial_bind_fid5()).unwrap();
        assert_eq!(
            first.session_address,
            0x8000_0000_0000_0023u64.to_be_bytes()
        );
        let user_setup = encode_user_setup(
            &bootstrap,
            1,
            0x8000_0000_0000_1000,
            reverse.initial_bind_fid5(),
            &config,
        )
        .unwrap();
        assert!(matches!(
            classify_setup_topic(RtpPacket::parse(&user_setup).unwrap()),
            Ok(RtpSetupTopic::User { .. })
        ));
        let scope = RtpAssociationScope {
            generation: bootstrap.generation,
            initial_plu_tcid: 0x8000_0000_0000_1000,
            subsequent_plu_tcid: 0x0000_0000_0000_2000,
            slu_tcid: 0x0000_0000_0000_1000,
        };
        reverse.activate_user(scope).unwrap();
        assert!(reverse.adapter.is_some());
    }

    #[test]
    fn rejects_bind_identity_mismatch_before_route_setup() {
        let (bootstrap, identity, _) = setup();
        let other = SessionIdentity::new(
            "OTHERNET.OTHER".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
        )
        .with_control_points(
            Some("OTHERNET.CP".parse().unwrap()),
            Some("SOLNET.SNAB".parse().unwrap()),
        )
        .unwrap();
        assert!(ReverseHprUser::new(
            bootstrap,
            identity,
            bind(&other),
            1,
            [1; 8],
            vec![0xa4, 1],
            [0, 0, 0, 5],
            0x8000_0000_0000_0023,
            DirectLinkMetrics {
                transmission_time_us: 1000,
                capacity_kbps: 100_000,
                liveness_seconds: 10,
            },
        )
        .is_err());
    }
}
