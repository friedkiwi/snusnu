//! One direct EE adjacency's bounded inbound HPR RTP connections.
//!
//! The opaque `EePort` relay remains separate. This adapter receives only
//! datagrams that `EeLdlcEndpoint` has already admitted by IP, SAP, and link
//! generation. It validates CS Topic and Switching Information before
//! creating RouteSetup, CP management, or one user RTP connection.

use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};

use router_core::{
    hpr_control_bootstrap::{encode_network_name_component, HprControlBootstrap},
    hpr_ip_activation::Phase,
    hpr_rtp::RtpPacket,
    hpr_rtp_endpoint::{
        EndpointError, EndpointPath, EndpointPeer, InboundEndpointConfig, RtpInboundEndpoint,
    },
    hpr_rtp_outbound::{OutboundPhase, RtpOutboundEndpoint},
    hpr_rtp_setup::{classify_setup_topic, RtpLocalTarget, RtpSetupTopic},
    hpr_session_address::{RtpAssociationScope, RtpObservation},
    hpr_switching_path::{validate_inbound_switching_path, AuthorizedUserRoute, TrustedReturnPath},
};
use transport_ip_sna::ee::{Datagram, LdlcKind};

use crate::ee_ldlc_endpoint::EeLdlcEndpoint;

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const MAX_MESSAGE_BYTES: usize = 1_048_576;
const MAX_WINDOW_BYTES: usize = 1_048_576;
const RETRANSMIT_TIMEOUT_US: u64 = 250_000;
static NEXT_TCID: AtomicU64 = AtomicU64::new(1);

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

fn endpoint_error(error: EndpointError) -> io::Error {
    invalid(format!("invalid HPR RTP endpoint state: {error:?}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RtpIngressKind {
    RouteSetup,
    CpSvcMg,
    CpSvcMgOut,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RtpIngress {
    pub(crate) kind: RtpIngressKind,
    pub(crate) observation: RtpObservation,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct HprRtpPort {
    bootstrap: HprControlBootstrap,
    route_setup: Option<RtpInboundEndpoint>,
    cp_svc_mg: Option<RtpInboundEndpoint>,
    cp_svc_mg_out: Option<RtpOutboundEndpoint>,
    user: Option<RtpInboundEndpoint>,
    authorized_user_route: Option<AuthorizedUserRoute>,
}

impl HprRtpPort {
    pub(crate) fn new(bootstrap: HprControlBootstrap) -> Self {
        Self {
            bootstrap,
            route_setup: None,
            cp_svc_mg: None,
            cp_svc_mg_out: None,
            user: None,
            authorized_user_route: None,
        }
    }

    /// Call only after the positive RouteSetup reply has reached the EE
    /// socket. The RTP user topic's COS/TPF and local NCE are then pinned to
    /// this link generation; a later link activation creates a new port.
    pub(crate) fn authorize_user_route(&mut self, route: AuthorizedUserRoute) -> io::Result<()> {
        if self.authorized_user_route.is_some()
            || self.user.is_some()
            || route.generation != self.bootstrap.generation
            || route.target_lu.netid != self.bootstrap.local.cp.netid
            || route.tg_number == 0
            || route.return_link_label != self.bootstrap.local.link_label
            || route.maximum_packet_size > self.bootstrap.max_packet_size
        {
            return Err(invalid("invalid or duplicate HPR user route authorization"));
        }
        self.authorized_user_route = Some(route);
        Ok(())
    }

    pub(crate) fn user_scope(&self) -> Option<RtpAssociationScope> {
        let user = self.user.as_ref()?;
        self.scope_for(user)
    }

    /// Directional identifiers for the validated CP management RTP topic.
    /// The first qualified BIND uses the origin TCID; subsequent peer BIUs
    /// use our CIE-assigned TCID after the link generation is pinned.
    pub(crate) fn cp_scope(&self) -> Option<RtpAssociationScope> {
        self.scope_for(self.cp_svc_mg.as_ref()?)
    }

    pub(crate) fn cp_out_scope(&self) -> Option<RtpAssociationScope> {
        let endpoint = self.cp_svc_mg_out.as_ref()?;
        if endpoint.phase() != OutboundPhase::Active {
            return None;
        }
        let origin = endpoint.origin_tcid();
        Some(RtpAssociationScope {
            generation: endpoint.generation(),
            initial_plu_tcid: origin,
            subsequent_plu_tcid: endpoint.peer_assigned_tcid()?,
            slu_tcid: origin & !ASSIGNOR,
        })
    }

    pub(crate) fn cp_out_ready(&self) -> bool {
        self.cp_out_scope().is_some()
    }

    /// Originate the reciprocal CPSVCMG RTP connection on the same EE TG.
    /// A false result means transient UDP backpressure; the caller retries
    /// the same first BIU without allocating a second TCID.
    pub(crate) fn open_cp(
        &mut self,
        ee: &EeLdlcEndpoint,
        first_biu: &[u8],
        now_us: u64,
    ) -> io::Result<bool> {
        self.check_link(ee)?;
        if self.cp_svc_mg_out.is_none() {
            let tg = ee.tg_number().ok_or_else(|| invalid("EE TG not active"))?;
            let id = allocate_tcid(self.bootstrap.generation.get())?;
            let mut endpoint =
                RtpOutboundEndpoint::new(self.bootstrap.clone(), tg, id).map_err(endpoint_error)?;
            endpoint.prepare_setup(first_biu).map_err(endpoint_error)?;
            self.cp_svc_mg_out = Some(endpoint);
        }
        let endpoint = self.cp_svc_mg_out.as_mut().unwrap();
        let Some(packet) = endpoint.pending_setup_nlp().map(ToOwned::to_owned) else {
            return Ok(true);
        };
        match ee.send_nlp(12001, &packet) {
            Ok(()) => endpoint
                .confirm_setup_sent(&packet, now_us)
                .map_err(endpoint_error)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
        Ok(true)
    }

    pub(crate) fn send_cp(
        &mut self,
        ee: &EeLdlcEndpoint,
        message: &[u8],
        now_us: u64,
    ) -> io::Result<bool> {
        self.check_link(ee)?;
        let endpoint = self
            .cp_svc_mg_out
            .as_mut()
            .ok_or_else(|| invalid("outbound CP RTP not started"))?;
        if endpoint.phase() != OutboundPhase::Active {
            return Ok(false);
        }
        let packet = match endpoint.prepare_message(message, now_us) {
            Ok(packet) => packet,
            Err(
                EndpointError::RateLimited
                | EndpointError::Send(
                    router_core::hpr_rtp_send::SendError::BufferFull
                    | router_core::hpr_rtp_send::SendError::TooManyPackets,
                ),
            ) => return Ok(false),
            Err(error) => return Err(endpoint_error(error)),
        };
        match ee.send_nlp(12001, &packet) {
            Ok(()) => endpoint
                .confirm_message_sent(&packet, now_us)
                .map_err(endpoint_error)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                endpoint
                    .cancel_unsent_message(&packet)
                    .map_err(endpoint_error)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        Ok(true)
    }

    fn scope_for(&self, endpoint: &RtpInboundEndpoint) -> Option<RtpAssociationScope> {
        let origin = endpoint.origin_tcid()?;
        Some(RtpAssociationScope {
            generation: self.bootstrap.generation,
            initial_plu_tcid: origin,
            subsequent_plu_tcid: endpoint.assigned_tcid()?,
            slu_tcid: origin & !ASSIGNOR,
        })
    }

    pub(crate) fn on_ee_ui(
        &mut self,
        ee: &EeLdlcEndpoint,
        datagram: &Datagram,
        _now_us: u64,
    ) -> io::Result<Vec<RtpIngress>> {
        self.check_link(ee)?;
        if datagram.kind != LdlcKind::UiNlp || datagram.payload.len() < 4 {
            return Err(invalid("RTP port requires one EE UI NLP"));
        }
        let nlp = &datagram.payload[3..];
        let packet = RtpPacket::parse(nlp)
            .map_err(|error| invalid(format!("invalid RTP NLP: {error:?}")))?;
        if packet.tcid & ASSIGNOR != 0 {
            return self.on_setup(ee, datagram, packet);
        }
        if self
            .cp_svc_mg_out
            .as_ref()
            .is_some_and(|endpoint| endpoint.origin_tcid() & !ASSIGNOR == packet.tcid)
        {
            return self.on_outbound_cp(ee, datagram, packet);
        }
        self.on_established_packet(ee, datagram, packet)
    }

    pub(crate) fn send(
        &mut self,
        ee: &EeLdlcEndpoint,
        kind: RtpIngressKind,
        message: &[u8],
        now_us: u64,
    ) -> io::Result<bool> {
        self.check_link(ee)?;
        let endpoint = self
            .endpoint_mut(kind)
            .ok_or_else(|| invalid("HPR RTP egress has no connection"))?;
        let packet = match endpoint.prepare_message(message, now_us) {
            Ok(packet) => packet,
            Err(
                EndpointError::RateLimited
                | EndpointError::Send(
                    router_core::hpr_rtp_send::SendError::BufferFull
                    | router_core::hpr_rtp_send::SendError::TooManyPackets,
                ),
            ) => return Ok(false),
            Err(error) => return Err(endpoint_error(error)),
        };
        let port = priority_port(packet[0])?;
        if let Err(error) = ee.send_nlp(port, &packet) {
            if error.kind() == io::ErrorKind::WouldBlock {
                endpoint
                    .cancel_unsent_message(&packet)
                    .map_err(endpoint_error)?;
                return Ok(false);
            }
            return Err(error);
        }
        endpoint
            .confirm_message_sent(&packet, now_us)
            .map_err(endpoint_error)?;
        Ok(true)
    }

    pub(crate) fn tick(&mut self, ee: &EeLdlcEndpoint, now_us: u64) -> io::Result<()> {
        self.check_link(ee)?;
        for kind in [
            RtpIngressKind::RouteSetup,
            RtpIngressKind::CpSvcMg,
            RtpIngressKind::User,
        ] {
            let Some(endpoint) = self.endpoint_mut(kind) else {
                continue;
            };
            if let Some(status) = endpoint.pending_status_nlp().map(ToOwned::to_owned) {
                let port = priority_port(status[0])?;
                match ee.send_nlp(port, &status) {
                    Ok(()) => endpoint
                        .confirm_status_sent(&status)
                        .map_err(endpoint_error)?,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                }
            }
            let packet = if let Some(pending) = endpoint.pending_retransmission_nlp() {
                pending.to_vec()
            } else if let Some(due) = endpoint.retransmit_due(now_us).map_err(endpoint_error)? {
                due
            } else {
                continue;
            };
            let port = priority_port(packet[0])?;
            match ee.send_nlp(port, &packet) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
            endpoint
                .confirm_retransmission_sent(&packet, now_us)
                .map_err(endpoint_error)?;
        }
        self.tick_outbound_cp(ee, now_us)?;
        Ok(())
    }

    fn tick_outbound_cp(&mut self, ee: &EeLdlcEndpoint, now_us: u64) -> io::Result<()> {
        let Some(endpoint) = self.cp_svc_mg_out.as_mut() else {
            return Ok(());
        };
        if let Some(packet) = endpoint
            .setup_retransmit_due(now_us)
            .map_err(endpoint_error)?
        {
            let packet = packet.to_vec();
            match ee.send_nlp(12001, &packet) {
                Ok(()) => endpoint
                    .confirm_setup_retransmitted(&packet, now_us)
                    .map_err(endpoint_error)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        if let Some(packet) = endpoint.pending_status_nlp() {
            let packet = packet.to_vec();
            match ee.send_nlp(12001, &packet) {
                Ok(()) => endpoint
                    .confirm_status_sent(&packet)
                    .map_err(endpoint_error)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        if endpoint.phase() != OutboundPhase::Active {
            return Ok(());
        }
        let packet = if let Some(pending) = endpoint.pending_retransmission_nlp() {
            pending.to_vec()
        } else if let Some(due) = endpoint.retransmit_due(now_us).map_err(endpoint_error)? {
            due
        } else {
            return Ok(());
        };
        match ee.send_nlp(12001, &packet) {
            Ok(()) => endpoint
                .confirm_retransmission_sent(&packet, now_us)
                .map_err(endpoint_error)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn on_outbound_cp(
        &mut self,
        ee: &EeLdlcEndpoint,
        datagram: &Datagram,
        packet: RtpPacket<'_>,
    ) -> io::Result<Vec<RtpIngress>> {
        if datagram.port != 12001 || (packet.nhdr[0] >> 1) & 3 != 3 {
            return Err(invalid("outbound CP RTP on wrong EE priority port"));
        }
        let endpoint = self.cp_svc_mg_out.as_mut().unwrap();
        if endpoint.phase() == OutboundPhase::AwaitReply
            || endpoint.phase() == OutboundPhase::AwaitStatusSent
        {
            if endpoint.phase() == OutboundPhase::AwaitReply
                && packet
                    .connection_identifier_exchange()
                    .map_err(|error| invalid(format!("invalid outbound CP CIE: {error:?}")))?
                    .is_none()
            {
                endpoint
                    .buffer_before_reply(&datagram.payload[3..])
                    .map_err(endpoint_error)?;
                return Ok(Vec::new());
            }
            let reply = endpoint
                .prepare_reply_status(&datagram.payload[3..])
                .map_err(endpoint_error)?;
            match ee.send_nlp(12001, &reply) {
                Ok(()) => endpoint
                    .confirm_status_sent(&reply)
                    .map_err(endpoint_error)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            let mut ingress = Vec::new();
            for held in endpoint.take_pre_status_nlps() {
                let received = endpoint.receive(&held).map_err(endpoint_error)?;
                ingress.extend(received.messages.into_iter().map(|bytes| RtpIngress {
                    kind: RtpIngressKind::CpSvcMgOut,
                    observation: RtpObservation {
                        generation: received.generation,
                        tcid: received.inbound_tcid,
                    },
                    bytes,
                }));
            }
            return Ok(ingress);
        }
        if let Some(reply) = endpoint.reply_to_duplicate_cie(&datagram.payload[3..]) {
            ee.send_nlp(12001, reply)?;
            return Ok(Vec::new());
        }
        let received = endpoint
            .receive(&datagram.payload[3..])
            .map_err(endpoint_error)?;
        if received.status_due {
            let reply = if let Some(pending) = endpoint.pending_status_nlp() {
                pending.to_vec()
            } else {
                endpoint.prepare_status().map_err(endpoint_error)?
            };
            match ee.send_nlp(12001, &reply) {
                Ok(()) => endpoint
                    .confirm_status_sent(&reply)
                    .map_err(endpoint_error)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(received
            .messages
            .into_iter()
            .map(|bytes| RtpIngress {
                kind: RtpIngressKind::CpSvcMgOut,
                observation: RtpObservation {
                    generation: received.generation,
                    tcid: received.inbound_tcid,
                },
                bytes,
            })
            .collect())
    }

    fn on_setup(
        &mut self,
        ee: &EeLdlcEndpoint,
        datagram: &Datagram,
        packet: RtpPacket<'_>,
    ) -> io::Result<Vec<RtpIngress>> {
        let topic = classify_setup_topic(packet)
            .map_err(|error| invalid(format!("invalid RTP setup topic: {error:?}")))?;
        let kind = kind_for(&topic);
        if let Some(existing) = self.endpoint_mut(kind) {
            if let Some(reply) = existing.reply_to_duplicate_setup(&datagram.payload[3..]) {
                if datagram.port != 12004 - u16::from(existing.priority()) {
                    return Err(invalid("duplicate RTP setup on wrong EE priority port"));
                }
                ee.send_nlp(datagram.port, reply)?;
                return Ok(Vec::new());
            }
            return Err(invalid("second HPR RTP setup on occupied topic"));
        }
        let tg = ee.tg_number().ok_or_else(|| invalid("EE TG not active"))?;
        let trusted = validate_inbound_switching_path(
            packet,
            &self.bootstrap,
            tg,
            &topic,
            self.authorized_user_route.as_ref(),
        )
        .map_err(|error| invalid(format!("untrusted HPR return path: {error:?}")))?;
        let port = 12004 - u16::from(trusted.priority);
        if datagram.port != port {
            return Err(invalid("RTP priority does not match EE UDP port"));
        }
        let config = self.config_for(kind, &trusted)?;
        let mut endpoint = RtpInboundEndpoint::new(config).map_err(endpoint_error)?;
        let reply = endpoint
            .prepare_inbound_setup(&datagram.payload[3..])
            .map_err(endpoint_error)?;
        ee.send_nlp(port, &reply)?;
        let messages = endpoint
            .confirm_setup_reply_sent(&reply)
            .map_err(endpoint_error)?;
        let observation = RtpObservation {
            generation: self.bootstrap.generation,
            tcid: endpoint
                .origin_tcid()
                .ok_or_else(|| invalid("RTP setup missing origin identifier"))?,
        };
        *self.slot_mut(kind) = Some(endpoint);
        Ok(messages
            .into_iter()
            .map(|bytes| RtpIngress {
                kind,
                observation,
                bytes,
            })
            .collect())
    }

    fn on_established_packet(
        &mut self,
        ee: &EeLdlcEndpoint,
        datagram: &Datagram,
        packet: RtpPacket<'_>,
    ) -> io::Result<Vec<RtpIngress>> {
        let kind = [
            RtpIngressKind::RouteSetup,
            RtpIngressKind::CpSvcMg,
            RtpIngressKind::User,
        ]
        .into_iter()
        .find(|kind| {
            self.endpoint(*kind)
                .is_some_and(|endpoint| endpoint.assigned_tcid() == Some(packet.tcid))
        })
        .ok_or_else(|| invalid("unknown HPR RTP connection identifier"))?;
        let endpoint = self.endpoint_mut(kind).unwrap();
        let priority = (packet.nhdr[0] >> 1) & 3;
        let expected_port = 12004 - u16::from(endpoint.priority());
        if priority != endpoint.priority() || datagram.port != expected_port {
            return Err(invalid("RTP packet on wrong EE priority port"));
        }
        let result = endpoint
            .receive(&datagram.payload[3..])
            .map_err(endpoint_error)?;
        if result.status_due {
            let reply = if let Some(pending) = endpoint.pending_status_nlp() {
                pending.to_vec()
            } else {
                endpoint.prepare_status().map_err(endpoint_error)?
            };
            match ee.send_nlp(datagram.port, &reply) {
                Ok(()) => endpoint
                    .confirm_status_sent(&reply)
                    .map_err(endpoint_error)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        // Fast retransmit candidates are retained by the bounded send window;
        // the pacing timer handles them without allowing a peer STATUS to
        // cause an unbounded immediate burst.
        Ok(result
            .messages
            .into_iter()
            .map(|bytes| RtpIngress {
                kind,
                observation: RtpObservation {
                    generation: result.generation,
                    tcid: result.inbound_tcid,
                },
                bytes,
            })
            .collect())
    }

    fn config_for(
        &self,
        kind: RtpIngressKind,
        path: &TrustedReturnPath,
    ) -> io::Result<InboundEndpointConfig> {
        let encode = |name: &str| {
            encode_network_name_component(name).map_err(|_| invalid("invalid APPN CP component"))
        };
        let local_nce_instance = match kind {
            RtpIngressKind::RouteSetup => self.bootstrap.local.tower.route_setup_nce_instance,
            RtpIngressKind::CpSvcMg => self.bootstrap.local.tower.cp_nce_instance,
            RtpIngressKind::CpSvcMgOut => {
                return Err(invalid("outbound CP RTP has separate setup"))
            }
            RtpIngressKind::User => {
                self.authorized_user_route
                    .as_ref()
                    .ok_or_else(|| invalid("user RTP lacks RouteSetup authorization"))?
                    .local_nce_instance
            }
        };
        let expected_peer_nce = match kind {
            RtpIngressKind::RouteSetup => {
                Some(self.bootstrap.peer.tower.route_setup_nce_label.clone())
            }
            RtpIngressKind::CpSvcMg => Some(self.bootstrap.peer.tower.cp_nce_label.clone()),
            RtpIngressKind::CpSvcMgOut => return Err(invalid("outbound CP RTP has separate peer")),
            RtpIngressKind::User => None,
        };
        let id = allocate_tcid(self.bootstrap.generation.get())?;
        Ok(InboundEndpointConfig {
            generation: self.bootstrap.generation,
            local_target: RtpLocalTarget {
                network_id: encode(&self.bootstrap.local.cp.netid)?,
                node_id: encode(&self.bootstrap.local.cp.name)?,
                nce_instance: local_nce_instance,
            },
            peer: EndpointPeer {
                network_id: encode(&self.bootstrap.peer.cp.netid)?,
                node_id: encode(&self.bootstrap.peer.cp.name)?,
                nce_id: expected_peer_nce,
            },
            path: EndpointPath {
                peer_anr_label: path.peer_nce_label.clone(),
                priority: path.priority,
            },
            assigned_tcid: id,
            initial_outbound_bsn: 0,
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_window_bytes: MAX_WINDOW_BYTES,
            max_nlp_bytes: usize::from(self.bootstrap.max_packet_size)
                .min(path.maximum_packet_size as usize),
            retransmit_timeout_us: RETRANSMIT_TIMEOUT_US,
        })
    }

    fn check_link(&self, ee: &EeLdlcEndpoint) -> io::Result<()> {
        if ee.phase() != Phase::Active || ee.generation() != self.bootstrap.generation {
            Err(invalid("HPR RTP link generation is no longer active"))
        } else {
            Ok(())
        }
    }

    fn endpoint(&self, kind: RtpIngressKind) -> Option<&RtpInboundEndpoint> {
        match kind {
            RtpIngressKind::RouteSetup => self.route_setup.as_ref(),
            RtpIngressKind::CpSvcMg => self.cp_svc_mg.as_ref(),
            RtpIngressKind::CpSvcMgOut => None,
            RtpIngressKind::User => self.user.as_ref(),
        }
    }

    fn endpoint_mut(&mut self, kind: RtpIngressKind) -> Option<&mut RtpInboundEndpoint> {
        match kind {
            RtpIngressKind::CpSvcMgOut => None,
            _ => self.slot_mut(kind).as_mut(),
        }
    }

    fn slot_mut(&mut self, kind: RtpIngressKind) -> &mut Option<RtpInboundEndpoint> {
        match kind {
            RtpIngressKind::RouteSetup => &mut self.route_setup,
            RtpIngressKind::CpSvcMg => &mut self.cp_svc_mg,
            RtpIngressKind::CpSvcMgOut => panic!("outbound CP RTP has its own slot"),
            RtpIngressKind::User => &mut self.user,
        }
    }
}

fn allocate_tcid(generation: u64) -> io::Result<u64> {
    let serial = NEXT_TCID.fetch_add(1, Ordering::Relaxed);
    if serial > u64::from(u32::MAX) {
        return Err(invalid("HPR RTP identifier space exhausted"));
    }
    let id = ASSIGNOR | ((generation & 0x3fff_ffff) << 32) | (serial & 0xffff_ffff);
    if id & RESERVED != 0 {
        return Err(invalid("invalid allocated RTP identifier"));
    }
    Ok(id)
}

fn kind_for(topic: &RtpSetupTopic) -> RtpIngressKind {
    match topic {
        RtpSetupTopic::RouteSetup => RtpIngressKind::RouteSetup,
        RtpSetupTopic::CpSvcMg => RtpIngressKind::CpSvcMg,
        RtpSetupTopic::User { .. } => RtpIngressKind::User,
    }
}

fn priority_port(first_nhdr_byte: u8) -> io::Result<u16> {
    if first_nhdr_byte & 0xe0 != 0xc0 {
        return Err(invalid("invalid HPR NHDR priority"));
    }
    Ok(12004 - u16::from((first_nhdr_byte >> 1) & 3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        ConnectionGeneration,
    };

    fn advertisement(cp: &str, id: u8) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse().unwrap(),
            node_id: [0, 0, 0, id],
            hpr_sap: 4,
            link_label: vec![0x80, id],
            tower: ControlFlowsTower {
                max_send_packet_size: 1461,
                path_switch_time_ms: 0,
                mobile: false,
                multilink_tg: false,
                arb_mode: ArbMode::Base,
                cp_nce_instance: [0, 0, 0, id],
                route_setup_nce_instance: [0, 0, 0, id],
                cp_nce_label: vec![0xa0, id],
                route_setup_nce_label: vec![0xa4, id],
            },
        }
    }

    fn bootstrap() -> HprControlBootstrap {
        HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", 1),
            advertisement("SOLNET.SNAA", 2),
        )
        .unwrap()
    }

    fn path() -> TrustedReturnPath {
        TrustedReturnPath {
            peer_nce_label: vec![0xa4, 2],
            priority: 3,
            maximum_packet_size: 1461,
            path_switch_time_ms: 0,
            alive_seconds: 0,
        }
    }

    #[test]
    fn config_uses_cp_name_not_fixed_xid_node_id_and_unique_tcid() {
        let port = HprRtpPort::new(bootstrap());
        let first = port
            .config_for(RtpIngressKind::RouteSetup, &path())
            .unwrap();
        let second = port
            .config_for(RtpIngressKind::RouteSetup, &path())
            .unwrap();
        assert_eq!(
            first.local_target.network_id,
            vec![0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4]
        );
        assert_eq!(first.local_target.node_id, vec![0xe2, 0xe5, 0xc3]);
        assert_eq!(first.peer.node_id, vec![0xe2, 0xd5, 0xc1, 0xc1]);
        assert_eq!(first.peer.nce_id, Some(vec![0xa4, 2]));
        assert_ne!(first.assigned_tcid, second.assigned_tcid);
        assert_eq!(first.assigned_tcid & (ASSIGNOR | RESERVED), ASSIGNOR);
        assert_eq!(first.path.priority, 3);
    }

    #[test]
    fn user_connection_requires_route_authorization() {
        let mut port = HprRtpPort::new(bootstrap());
        assert!(port.config_for(RtpIngressKind::User, &path()).is_err());
        // A distinct peer CV61 link label must not authorize the return
        // path that the guest addressed to this local link generation.
        assert!(port
            .authorize_user_route(AuthorizedUserRoute {
                generation: ConnectionGeneration::new(1).unwrap(),
                target_lu: "SNUSNU.PING".parse().unwrap(),
                local_nce_label: vec![0xb0, 1],
                local_nce_instance: [0, 0, 0, 9],
                cos_tpf: vec![4, 0x2c, 1, 0],
                tg_number: 1,
                return_link_label: vec![0x80, 2],
                maximum_packet_size: 1461,
            })
            .is_err());
        port.authorize_user_route(AuthorizedUserRoute {
            generation: ConnectionGeneration::new(1).unwrap(),
            target_lu: "SNUSNU.PING".parse().unwrap(),
            local_nce_label: vec![0xb0, 1],
            local_nce_instance: [0, 0, 0, 9],
            cos_tpf: vec![4, 0x2c, 1, 0],
            tg_number: 1,
            return_link_label: vec![0x80, 1],
            maximum_packet_size: 1461,
        })
        .unwrap();
        let user = port.config_for(RtpIngressKind::User, &path()).unwrap();
        assert_eq!(user.local_target.nce_instance, [0, 0, 0, 9]);
        assert_eq!(user.peer.nce_id, None);
        assert!(port
            .authorize_user_route(AuthorizedUserRoute {
                generation: ConnectionGeneration::new(1).unwrap(),
                target_lu: "SNUSNU.PING".parse().unwrap(),
                local_nce_label: vec![0xb0, 2],
                local_nce_instance: [0, 0, 0, 10],
                cos_tpf: vec![4, 0x2c, 1, 0],
                tg_number: 1,
                return_link_label: vec![0x80, 1],
                maximum_packet_size: 1461,
            })
            .is_err());
    }

    #[test]
    fn priority_maps_to_ee_udp_ports() {
        assert_eq!(priority_port(0xc6).unwrap(), 12001);
        assert_eq!(priority_port(0xc2).unwrap(), 12003);
        assert!(priority_port(0x80).is_err());
    }
}
