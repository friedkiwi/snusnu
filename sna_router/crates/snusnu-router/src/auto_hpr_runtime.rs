//! Session-level switching for an HPR attachment and any other carrier.
//!
//! This module is deliberately below the attachment runtime: it accepts only
//! verified LU identities and complete reduced SNA units. The EE/APPN/RTP
//! adapters own their wire protocols, while `SessionFabric` selects a route.
//! Each outbound event has an explicit delivery lease so a carrier that
//! temporarily cannot send cannot lose an event popped from the fabric.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    auto_hpr_identity::AuthorizedEeIdentity,
    config::RouterConfig,
    ee_ldlc_endpoint::EeLdlcEndpoint,
    hpr_rtp_port::{HprRtpPort, RtpIngress, RtpIngressKind},
    remote::{AutoWsHub, SessionWsPort, SessionWsUpdate},
    STOP,
};
use router_core::{
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_cp_initiator::{CpInitiatorPhase, ReciprocalCpSession},
    hpr_cp_management::CpManagementResponder,
    hpr_fid5::Fid5WholeBiu,
    hpr_ip_activation::Phase,
    hpr_route_setup::{RouteSetupGds, RouteSetupKind},
    hpr_route_setup_reply::{encode_stale_path_switch_negative, ReverseLinkMetrics},
    hpr_route_setup_service::{DirectRouteSetupService, PreparedRouteSetupReply},
    hpr_session_adapter::{negotiated_fixed_windows, HprSessionAdapter, HprSessionRole},
    session::{Flow, SessionEvent, SessionIdentity, SessionUnit},
    session_fabric::{
        AdapterId, FabricError, FabricLimits, FabricSessionId, Reachability, SessionFabric,
    },
};
use transport_ws::wire;

const HPR_ADAPTER: AdapterId = AdapterId(1);
const WS_ADAPTER: AdapterId = AdapterId(2);
const IDLE_POLL: Duration = Duration::from_micros(200);
const CONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_PENDING_RTP_MESSAGES: usize = 64;
const MAX_PENDING_RTP_BYTES: usize = 128 * 1024;
const MAX_PENDING_CP_REPLIES: usize = 16;
const MAX_PENDING_CP_REPLY_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_HPR_SESSIONS: usize = 64;
static NEXT_CP_NONCE: AtomicU64 = AtomicU64::new(1);
static CP_NONCE_SEED: OnceLock<u64> = OnceLock::new();

fn protocol(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

fn as_wire_name(value: &router_core::session::QualifiedName) -> wire::SnaName {
    wire::SnaName {
        netid: value.netid.clone(),
        name: value.name.clone(),
    }
}

fn reciprocal_nonce() -> u64 {
    let seed = *CP_NONCE_SEED.get_or_init(|| {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        time ^ u64::from(std::process::id()).rotate_left(32)
    });
    let serial = NEXT_CP_NONCE.fetch_add(1, Ordering::Relaxed);
    let span = (1u64 << 62) - 1;
    ((u128::from(seed) + u128::from(serial)) % u128::from(span)) as u64 + 1
}

fn user_nce_label(control: &[u8]) -> io::Result<Vec<u8>> {
    let mut label = control.to_vec();
    let last = label
        .last_mut()
        .ok_or_else(|| protocol("empty HPR NCE label"))?;
    // 0xff is reserved. Rotate through the other 255 suffixes, including
    // when the control label already ends in 0xfe or 0xff.
    *last = if *last >= 0xfe { 0 } else { *last + 1 };
    if label == control {
        return Err(protocol("HPR LU NCE label space exhausted"));
    }
    Ok(label)
}

struct ActiveHprSession {
    handle: u64,
    peer_sa: u64,
    bind_message: Vec<u8>,
    fabric_id: FabricSessionId,
    identity: SessionIdentity,
    bind_request: SessionUnit,
    adapter: HprSessionAdapter,
    ws: Option<SessionWsPort>,
    ws_closed: bool,
    pending_ws: Option<(SessionEvent, bool)>,
    pending_credit: Option<SessionEvent>,
}

struct DirectHprRuntime {
    bootstrap: HprControlBootstrap,
    rtp: HprRtpPort,
    route_setup: Option<DirectRouteSetupService>,
    route_reply: Option<PreparedRouteSetupReply>,
    negative_route_reply: Option<Vec<u8>>,
    cp_management: Option<CpManagementResponder>,
    pending_cp_replies: VecDeque<Vec<u8>>,
    pending_cp_reply_bytes: usize,
    reciprocal_cp: Option<ReciprocalCpSession>,
    pending_reciprocal_replies: VecDeque<Vec<u8>>,
    pending_reciprocal_reply_bytes: usize,
    switch: SessionSwitch,
    sessions: BTreeMap<u64, ActiveHprSession>,
    pending_rtp: std::collections::VecDeque<RtpIngress>,
    pending_rtp_bytes: usize,
    next_handle: u64,
    bound_user_scope: Option<router_core::hpr_session_address::RtpAssociationScope>,
    user_route_authorized: bool,
}

impl DirectHprRuntime {
    fn new(bootstrap: HprControlBootstrap) -> Self {
        let mut switch = SessionSwitch::new();
        switch.register(HPR_ADAPTER);
        switch.register(WS_ADAPTER);
        Self {
            rtp: HprRtpPort::new(bootstrap.clone()),
            cp_management: None,
            bootstrap,
            route_setup: None,
            route_reply: None,
            negative_route_reply: None,
            pending_cp_replies: VecDeque::new(),
            pending_cp_reply_bytes: 0,
            reciprocal_cp: None,
            pending_reciprocal_replies: VecDeque::new(),
            pending_reciprocal_reply_bytes: 0,
            switch,
            sessions: BTreeMap::new(),
            pending_rtp: std::collections::VecDeque::new(),
            pending_rtp_bytes: 0,
            next_handle: 1,
            bound_user_scope: None,
            user_route_authorized: false,
        }
    }

    fn queue_rtp(&mut self, messages: Vec<RtpIngress>) -> io::Result<()> {
        for message in messages {
            if self.pending_rtp.len() >= MAX_PENDING_RTP_MESSAGES
                || message.bytes.len() > MAX_PENDING_RTP_BYTES - self.pending_rtp_bytes
            {
                return Err(protocol("HPR session ingress backlog full"));
            }
            self.pending_rtp_bytes += message.bytes.len();
            self.pending_rtp.push_back(message);
        }
        Ok(())
    }

    fn pump(&mut self, link: &EeLdlcEndpoint, hub: &mut AutoWsHub, now_us: u64) -> io::Result<()> {
        self.try_open_reciprocal_cp(link, now_us)?;
        self.try_route_reply(link, now_us)?;
        self.try_cp_replies(link, now_us)?;
        self.try_reciprocal_replies(link, now_us)?;
        while let Some(message) = self.pending_rtp.front().cloned() {
            let result = match message.kind {
                RtpIngressKind::RouteSetup => self.route_message(link, hub, &message, now_us),
                RtpIngressKind::User => self.user_message(hub, &message),
                RtpIngressKind::CpSvcMg => self.cp_message(&message),
                RtpIngressKind::CpSvcMgOut => self.reciprocal_cp_message(&message),
            };
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
            {
                break;
            }
            result?;
            self.pending_rtp.pop_front();
            self.pending_rtp_bytes -= message.bytes.len();
            self.try_route_reply(link, now_us)?;
            self.try_cp_replies(link, now_us)?;
            self.try_reciprocal_replies(link, now_us)?;
        }
        self.pump_sessions(link, hub, now_us)
    }

    fn try_open_reciprocal_cp(&mut self, link: &EeLdlcEndpoint, now_us: u64) -> io::Result<()> {
        if !self.reciprocal_cp_ready() {
            return Ok(());
        }
        if self.reciprocal_cp.is_none() {
            let nonce = reciprocal_nonce();
            self.reciprocal_cp = Some(
                ReciprocalCpSession::new(self.bootstrap.clone(), nonce)
                    .map_err(|error| protocol(format!("HPR reciprocal CP BIND: {error}")))?,
            );
        }
        let session = self.reciprocal_cp.as_mut().unwrap();
        if session.phase() != CpInitiatorPhase::BindPrepared {
            return Ok(());
        }
        let bind = session
            .prepare_bind()
            .map_err(|error| protocol(format!("HPR reciprocal CP BIND: {error}")))?;
        if self.rtp.open_cp(link, bind, now_us)? {
            session
                .mark_bind_sent()
                .map_err(|error| protocol(format!("HPR reciprocal CP BIND send: {error}")))?;
            tracing::info!(local_cp = %self.bootstrap.local.cp,
                peer_cp = %self.bootstrap.peer.cp,
                generation = self.bootstrap.generation.get(),
                "HPR reciprocal CP BIND transmitted");
        }
        Ok(())
    }

    fn reciprocal_cp_ready(&self) -> bool {
        self.pending_cp_replies.is_empty()
            && self
                .cp_management
                .as_ref()
                .is_some_and(CpManagementResponder::ready_for_reciprocal)
    }

    fn reciprocal_cp_message(&mut self, message: &RtpIngress) -> io::Result<()> {
        if !self.pending_reciprocal_replies.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "HPR reciprocal CP response pending",
            ));
        }
        let scope = self
            .rtp
            .cp_out_scope()
            .ok_or_else(|| protocol("HPR reciprocal CP RTP scope missing"))?;
        let mut candidate = self
            .reciprocal_cp
            .as_ref()
            .ok_or_else(|| protocol("HPR reciprocal CP session missing"))?
            .clone();
        let replies = candidate
            .ingest(scope, message.observation, &message.bytes)
            .map_err(|error| protocol(format!("HPR reciprocal CP BIU rejected: {error}")))?;
        let reply_bytes = replies.iter().try_fold(0usize, |used, reply| {
            used.checked_add(reply.len())
                .ok_or_else(|| protocol("HPR reciprocal CP reply size overflow"))
        })?;
        if replies.len() > MAX_PENDING_CP_REPLIES || reply_bytes > MAX_PENDING_CP_REPLY_BYTES {
            return Err(protocol("HPR reciprocal CP response exceeds queue limits"));
        }
        if candidate.phase() == CpInitiatorPhase::Active {
            tracing::info!(local_cp = %self.bootstrap.local.cp,
                peer_cp = %self.bootstrap.peer.cp,
                generation = self.bootstrap.generation.get(),
                "HPR reciprocal CP session active");
        }
        self.reciprocal_cp = Some(candidate);
        self.pending_reciprocal_reply_bytes = reply_bytes;
        self.pending_reciprocal_replies.extend(replies);
        Ok(())
    }

    fn try_reciprocal_replies(&mut self, link: &EeLdlcEndpoint, now_us: u64) -> io::Result<()> {
        while let Some(reply) = self.pending_reciprocal_replies.front() {
            let marks_capabilities = self
                .reciprocal_cp
                .as_ref()
                .is_some_and(|session| session.phase() == CpInitiatorPhase::CapabilitiesPrepared);
            if marks_capabilities {
                let prepared = self
                    .reciprocal_cp
                    .as_ref()
                    .unwrap()
                    .prepare_capabilities()
                    .map_err(|error| {
                        protocol(format!("HPR reciprocal CP capabilities: {error}"))
                    })?;
                if prepared != reply {
                    return Err(protocol(
                        "HPR reciprocal CP reply differs from prepared capabilities",
                    ));
                }
            }
            if !self.rtp.send_cp(link, reply, now_us)? {
                break;
            }
            self.pending_reciprocal_reply_bytes -= reply.len();
            self.pending_reciprocal_replies.pop_front();
            if marks_capabilities {
                self.reciprocal_cp
                    .as_mut()
                    .unwrap()
                    .mark_capabilities_sent()
                    .map_err(|error| {
                        protocol(format!("HPR reciprocal CP capabilities send: {error}"))
                    })?;
            }
        }
        Ok(())
    }

    fn cp_message(&mut self, message: &RtpIngress) -> io::Result<()> {
        // A response remains queued until RTP accepts it. Withhold the next
        // management BIU while that response is pending so protocol state
        // cannot advance ahead of its wire delivery.
        if !self.pending_cp_replies.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "HPR CP management response pending",
            ));
        }
        let responder = match self.cp_management.as_ref() {
            Some(responder) => responder.clone(),
            None => {
                let scope = self
                    .rtp
                    .cp_scope()
                    .ok_or_else(|| protocol("HPR CP management RTP scope missing"))?;
                CpManagementResponder::new(self.bootstrap.clone(), scope)
            }
        };
        let mut candidate = responder;
        let replies = candidate
            .ingest(message.observation, &message.bytes)
            .map_err(|error| protocol(format!("HPR CP management BIU rejected: {error}")))?;
        let reply_bytes = replies.iter().try_fold(0usize, |used, reply| {
            used.checked_add(reply.len())
                .ok_or_else(|| protocol("HPR CP management reply size overflow"))
        })?;
        if replies.len() > MAX_PENDING_CP_REPLIES || reply_bytes > MAX_PENDING_CP_REPLY_BYTES {
            return Err(protocol("HPR CP management response exceeds queue limits"));
        }
        self.cp_management = Some(candidate);
        self.pending_cp_reply_bytes = reply_bytes;
        self.pending_cp_replies.extend(replies);
        Ok(())
    }

    fn try_cp_replies(&mut self, link: &EeLdlcEndpoint, now_us: u64) -> io::Result<()> {
        while let Some(reply) = self.pending_cp_replies.front() {
            if !self
                .rtp
                .send(link, RtpIngressKind::CpSvcMg, reply, now_us)?
            {
                break;
            }
            self.pending_cp_reply_bytes -= reply.len();
            self.pending_cp_replies.pop_front();
        }
        Ok(())
    }

    fn route_message(
        &mut self,
        link: &EeLdlcEndpoint,
        hub: &AutoWsHub,
        message: &RtpIngress,
        _now_us: u64,
    ) -> io::Result<()> {
        if self.route_reply.is_some() || self.negative_route_reply.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "route reply pending",
            ));
        }
        let request = RouteSetupGds::parse(&message.bytes)
            .map_err(|error| protocol(format!("invalid HPR RouteSetup: {error:?}")))?;
        if request.kind != RouteSetupKind::Request {
            return Err(protocol("unexpected HPR RouteSetup reply"));
        }
        let Some(target_name) = request.destination_lu_name.as_deref() else {
            let tg = link
                .tg_number()
                .ok_or_else(|| protocol("HPR route has no active TG"))?;
            let reply = encode_stale_path_switch_negative(&self.bootstrap, tg, &message.bytes)
                .map_err(|error| {
                    protocol(format!("invalid HPR path-switch RouteSetup: {error:?}"))
                })?;
            self.negative_route_reply = Some(reply);
            tracing::warn!(pcid = ?request.pcid, generation = self.bootstrap.generation.get(),
                "rejecting stale HPR path-switch RouteSetup without LU");
            return Ok(());
        };
        let target: router_core::session::QualifiedName = target_name
            .parse()
            .map_err(|_| protocol("invalid HPR RouteSetup target LU"))?;
        let Some((_, Some(hosting_cp))) = hub.resolve_lu(&as_wire_name(&target))? else {
            return Err(protocol(format!(
                "HPR RouteSetup target {target} unavailable"
            )));
        };
        if hosting_cp != as_wire_name(&self.bootstrap.local.cp) {
            return Err(protocol(
                "HPR RouteSetup target is not hosted by EE proxy CP",
            ));
        }
        if self.route_setup.is_none() {
            let tg = link
                .tg_number()
                .ok_or_else(|| protocol("HPR route has no active TG"))?;
            let user_label = user_nce_label(&self.bootstrap.local.tower.route_setup_nce_label)?;
            let service = DirectRouteSetupService::new(
                self.bootstrap.clone(),
                target.clone(),
                user_label,
                self.bootstrap.local.tower.route_setup_nce_instance,
                tg,
                ReverseLinkMetrics {
                    transmission_time_us: 1000,
                    capacity_kbps: 100_000,
                    liveness_seconds: 10,
                },
                16,
            )
            .map_err(|error| protocol(format!("HPR RouteSetup service: {error:?}")))?;
            self.route_setup = Some(service);
        }
        if self.route_setup.as_ref().unwrap().local_lu() != &target {
            return Err(protocol("second HPR RouteSetup target on one direct TG"));
        }
        self.route_reply = Some(
            self.route_setup
                .as_mut()
                .unwrap()
                .prepare_reply(self.bootstrap.generation, &message.bytes)
                .map_err(|error| protocol(format!("HPR RouteSetup rejected: {error:?}")))?,
        );
        Ok(())
    }

    fn try_route_reply(&mut self, link: &EeLdlcEndpoint, now_us: u64) -> io::Result<()> {
        if let Some(reply) = self.negative_route_reply.as_ref() {
            if self
                .rtp
                .send(link, RtpIngressKind::RouteSetup, reply, now_us)?
            {
                self.negative_route_reply = None;
                tracing::info!(
                    generation = self.bootstrap.generation.get(),
                    "HPR stale path-switch negative RouteSetup reply transmitted"
                );
            }
            return Ok(());
        }
        let Some(reply) = self.route_reply.as_ref() else {
            return Ok(());
        };
        if !self
            .rtp
            .send(link, RtpIngressKind::RouteSetup, &reply.gds, now_us)?
        {
            return Ok(());
        }
        let reply = self.route_reply.take().unwrap();
        let authorized = self
            .route_setup
            .as_mut()
            .unwrap()
            .confirm_reply_sent(self.bootstrap.generation, reply.pcid, &reply.gds)
            .map_err(|error| protocol(format!("HPR RouteSetup confirmation: {error:?}")))?;
        if !self.user_route_authorized {
            self.rtp.authorize_user_route(authorized)?;
            self.user_route_authorized = true;
        }
        tracing::info!(target_lu = %self.route_setup.as_ref().unwrap().local_lu(),
            generation = self.bootstrap.generation.get(),
            "HPR direct RouteSetup reply transmitted and user route authorized");
        Ok(())
    }

    fn user_message(&mut self, hub: &mut AutoWsHub, message: &RtpIngress) -> io::Result<()> {
        let fid5 = Fid5WholeBiu::parse_complete(&message.bytes)
            .map_err(|error| protocol(format!("invalid HPR user BIU: {error:?}")))?;
        if fid5
            .classify_bind()
            .map_err(|error| protocol(format!("invalid HPR BIND: {error:?}")))?
            .is_some()
        {
            let peer_sa = u64::from_be_bytes(fid5.session_address);
            if let Some(session) = self
                .sessions
                .values()
                .find(|session| session.peer_sa == peer_sa)
            {
                if session.bind_message == message.bytes {
                    let scope = self
                        .rtp
                        .user_scope()
                        .ok_or_else(|| protocol("user RTP scope missing"))?;
                    if message.observation.generation != scope.generation
                        || ![scope.initial_plu_tcid, scope.subsequent_plu_tcid]
                            .contains(&message.observation.tcid)
                    {
                        return Err(protocol("duplicate HPR BIND on wrong RTP connection"));
                    }
                    tracing::debug!(
                        peer_sa = format_args!("{peer_sa:016x}"),
                        "duplicate HPR BIND ignored on existing session"
                    );
                    return Ok(());
                }
                return Err(protocol(format!(
                    "conflicting HPR BIND peer session address={peer_sa:016x}"
                )));
            }
            self.start_user_session(hub, message)?;
            return Ok(());
        }
        let handle = u64::from_be_bytes(fid5.session_address);
        let session = self.sessions.get_mut(&handle).ok_or_else(|| {
            protocol(format!(
                "HPR user BIU has no verified session address={handle:016x}"
            ))
        })?;
        if let Some(credit) = session.pending_credit.take() {
            if let Err(error) = self
                .switch
                .submit(HPR_ADAPTER, session.handle, credit.clone())
            {
                session.pending_credit = Some(credit);
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("HPR credit backpressure: {error:?}"),
                ));
            }
        }
        let (candidate, ingress) = session
            .adapter
            .preview_ingress(message.observation, &message.bytes)
            .map_err(|error| protocol(format!("invalid HPR session BIU: {error:?}")))?;
        match self
            .switch
            .submit(HPR_ADAPTER, session.handle, ingress.event)
        {
            Ok(()) => {}
            Err(SwitchError::Fabric(FabricError::Capacity)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "HPR fabric backpressure",
                ));
            }
            Err(error) => return Err(protocol(format!("HPR session event rejected: {error:?}"))),
        }
        session.adapter = candidate;
        if let Some(credit) = ingress.extra_credit {
            if self
                .switch
                .submit(HPR_ADAPTER, session.handle, credit.clone())
                .is_err()
            {
                session.pending_credit = Some(credit);
            }
        }
        Ok(())
    }

    fn publish_reachability(
        &self,
        hub: &mut AutoWsHub,
        extra: Option<&SessionIdentity>,
    ) -> io::Result<()> {
        let identities = self
            .sessions
            .values()
            .map(|session| &session.identity)
            .chain(extra);
        let mut cps = HashSet::new();
        let mut lus = HashSet::new();
        for identity in identities {
            if let Some(cp) = identity.source_cp.as_ref() {
                cps.insert(cp.clone());
                lus.insert((identity.source_lu.clone(), cp.clone()));
            }
        }
        let mut cps = cps.into_iter().collect::<Vec<_>>();
        cps.sort_by(|a, b| (&a.netid, &a.name).cmp(&(&b.netid, &b.name)));
        let mut lus = lus.into_iter().collect::<Vec<_>>();
        lus.sort_by(|a, b| {
            (&a.0.netid, &a.0.name, &a.1.netid, &a.1.name)
                .cmp(&(&b.0.netid, &b.0.name, &b.1.netid, &b.1.name))
        });
        hub.publish_local(
            &cps.iter().map(as_wire_name).collect::<Vec<_>>(),
            &lus.iter()
                .map(|(lu, cp)| wire::LuReachability {
                    lu: Some(as_wire_name(lu)),
                    hosting_cp: Some(as_wire_name(cp)),
                    supported_types: vec![wire::LuType::LuType62 as i32],
                })
                .collect::<Vec<_>>(),
        )
    }

    fn start_user_session(&mut self, hub: &mut AutoWsHub, message: &RtpIngress) -> io::Result<()> {
        if self.sessions.len() >= MAX_ACTIVE_HPR_SESSIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "HPR active session limit reached",
            ));
        }
        let fid5 = Fid5WholeBiu::parse_complete(&message.bytes)
            .map_err(|error| protocol(format!("invalid HPR BIND BIU: {error:?}")))?;
        let peer_sa = u64::from_be_bytes(fid5.session_address);
        let scope = self
            .rtp
            .user_scope()
            .ok_or_else(|| protocol("user RTP scope missing"))?;
        let handle = self.next_handle;
        if handle >= (1u64 << 62) {
            return Err(protocol("HPR session address space exhausted"));
        }
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or_else(|| protocol("HPR session handles exhausted"))?;
        let local_sa = (1u64 << 63) | handle;
        let constructor = if self.bound_user_scope == Some(scope) {
            HprSessionAdapter::new_subsequent
        } else {
            HprSessionAdapter::new
        };
        let adapter = constructor(
            HprSessionRole::PeerPlu,
            scope,
            local_sa,
            Some(self.bootstrap.local.cp.clone()),
            Some(self.bootstrap.peer.cp.clone()),
        )
        .map_err(|error| protocol(format!("HPR session address: {error:?}")))?;
        let (adapter, ingress) = adapter
            .preview_ingress(message.observation, &message.bytes)
            .map_err(|error| protocol(format!("HPR BIND rejected: {error:?}")))?;
        let identity = ingress
            .identity
            .ok_or_else(|| protocol("HPR user RTP lacks BIND identity"))?;
        if identity.source_lu.netid != hub.allowed_netid()
            || identity.source_cp.as_ref() != Some(&self.bootstrap.peer.cp)
            || self.route_setup.as_ref().map(|route| route.local_lu()) != Some(&identity.target_lu)
        {
            return Err(protocol(
                "HPR BIND identity conflicts with authenticated route",
            ));
        }
        let source_lu = as_wire_name(&identity.source_lu);
        let target_lu = as_wire_name(&identity.target_lu);
        self.publish_reachability(hub, Some(&identity))?;
        self.switch
            .replace_routes(
                WS_ADAPTER,
                vec![Reachability {
                    lu: Some(identity.target_lu.clone()),
                    cp: identity.target_cp.clone(),
                }],
            )
            .map_err(|error| protocol(format!("HPR route admission: {error:?}")))?;
        let bind_request = match ingress.event {
            SessionEvent::BindRequest(ref unit) => unit.clone(),
            _ => return Err(protocol("HPR first session unit is not BIND")),
        };
        let (fabric_id, egress) = self
            .switch
            .open(HPR_ADAPTER, handle, identity.clone(), bind_request.clone())
            .map_err(|error| protocol(format!("HPR BIND route unavailable: {error:?}")))?;
        if egress != WS_ADAPTER {
            return Err(protocol("HPR session selected unexpected egress"));
        }
        let ws = hub.open_session_lu(&target_lu, &source_lu)?;
        if ws.is_some() {
            self.switch
                .bind_egress(fabric_id, WS_ADAPTER, handle)
                .map_err(|error| protocol(format!("HPR WS bind failed: {error:?}")))?;
        }
        tracing::info!(source_lu = %identity.source_lu, target_lu = %identity.target_lu,
            peer_cp = %self.bootstrap.peer.cp, proxy_cp = %self.bootstrap.local.cp,
            "HPR LU session routed to concentrator");
        self.sessions.insert(
            handle,
            ActiveHprSession {
                handle,
                peer_sa,
                bind_message: message.bytes.clone(),
                fabric_id,
                identity,
                bind_request,
                adapter,
                ws,
                ws_closed: false,
                pending_ws: None,
                pending_credit: ingress.extra_credit,
            },
        );
        self.bound_user_scope = Some(scope);
        Ok(())
    }

    fn pump_sessions(
        &mut self,
        link: &EeLdlcEndpoint,
        hub: &mut AutoWsHub,
        now_us: u64,
    ) -> io::Result<()> {
        let handles = self.sessions.keys().copied().collect::<Vec<_>>();
        for handle in handles {
            self.pump_session(handle, link, hub, now_us)?;
        }
        let previous_count = self.sessions.len();
        let switch = &self.switch;
        self.sessions
            .retain(|handle, _| switch.lookup(HPR_ADAPTER, *handle).is_ok());
        if self.sessions.len() != previous_count {
            self.publish_reachability(hub, None)?;
        }
        Ok(())
    }

    fn pump_session(
        &mut self,
        handle: u64,
        link: &EeLdlcEndpoint,
        hub: &mut AutoWsHub,
        now_us: u64,
    ) -> io::Result<()> {
        let Some(session) = self.sessions.get_mut(&handle) else {
            return Ok(());
        };
        if let Some(credit) = session.pending_credit.take() {
            match self
                .switch
                .submit(HPR_ADAPTER, session.handle, credit.clone())
            {
                Ok(()) => {}
                Err(SwitchError::Fabric(FabricError::Capacity)) => {
                    session.pending_credit = Some(credit);
                }
                Err(error) => {
                    return Err(protocol(format!("HPR pacing credit rejected: {error:?}")))
                }
            }
        }
        if session.ws.is_none() {
            let target = as_wire_name(&session.identity.target_lu);
            let source = as_wire_name(&session.identity.source_lu);
            if let Some(port) = hub.open_session_lu(&target, &source)? {
                self.switch
                    .bind_egress(session.fabric_id, WS_ADAPTER, session.handle)
                    .map_err(|error| protocol(format!("HPR WS open: {error:?}")))?;
                session.ws = Some(port);
            } else {
                return Ok(());
            }
        }
        let ws = session.ws.as_mut().unwrap();
        if session.pending_ws.is_none() && !session.ws_closed {
            match ws.poll()? {
                Some(SessionWsUpdate::Event(event)) => {
                    let event = from_session_wire(event)?;
                    let charge = !matches!(event, SessionEvent::Credit { .. });
                    session.pending_ws = Some((event, charge));
                }
                Some(SessionWsUpdate::Closed) => {
                    self.switch
                        .submit(WS_ADAPTER, session.handle, SessionEvent::Reset)
                        .map_err(|error| protocol(format!("HPR WS close: {error:?}")))?;
                    session.ws_closed = true;
                }
                Some(SessionWsUpdate::Opened) | None => {}
            }
        }
        if let Some((event, charge)) = session.pending_ws.clone() {
            match self.switch.submit(WS_ADAPTER, session.handle, event) {
                Ok(()) => {
                    if charge {
                        ws.complete_received(1)?;
                    }
                    session.pending_ws = None;
                }
                Err(SwitchError::Fabric(FabricError::Capacity)) => {}
                Err(error) => {
                    return Err(protocol(format!(
                        "HPR WS session event rejected: {error:?}"
                    )))
                }
            }
        }
        if let Some(event) = self
            .switch
            .next_delivery(WS_ADAPTER, session.handle)
            .map_err(|error| protocol(format!("HPR WS delivery: {error:?}")))?
        {
            if session.ws_closed {
                self.switch
                    .mark_sent(WS_ADAPTER, session.handle)
                    .map_err(|error| protocol(format!("HPR WS closed completion: {error:?}")))?;
            } else if let Some(wire_event) = to_session_wire(&event) {
                if ws.send(wire_event)? {
                    self.switch
                        .mark_sent(WS_ADAPTER, session.handle)
                        .map_err(|error| protocol(format!("HPR WS completion: {error:?}")))?;
                }
            } else {
                ws.close()?;
                self.switch
                    .mark_sent(WS_ADAPTER, session.handle)
                    .map_err(|error| protocol(format!("HPR WS reset: {error:?}")))?;
            }
        }
        if let Some(event) = self
            .switch
            .next_delivery(HPR_ADAPTER, session.handle)
            .map_err(|error| protocol(format!("HPR egress delivery: {error:?}")))?
        {
            let (mut candidate, egress) = session
                .adapter
                .preview_egress(event.clone())
                .map_err(|error| protocol(format!("HPR egress conversion: {error:?}")))?;
            if let SessionEvent::BindResult {
                accepted: true,
                ref unit,
            } = event
            {
                let (send, receive) =
                    negotiated_fixed_windows(HprSessionRole::PeerPlu, &session.bind_request, unit)
                        .map_err(|error| protocol(format!("HPR BIND pacing: {error:?}")))?;
                candidate
                    .configure_fixed_pacing(send, receive)
                    .map_err(|error| protocol(format!("HPR pacing setup: {error:?}")))?;
            }
            let sent = match egress {
                Some(egress) => {
                    self.rtp
                        .send(link, RtpIngressKind::User, &egress.message, now_us)?
                }
                None => true,
            };
            if sent {
                session.adapter = candidate;
                self.switch
                    .mark_sent(HPR_ADAPTER, session.handle)
                    .map_err(|error| protocol(format!("HPR egress completion: {error:?}")))?;
            }
        }
        let _ = ws.take_completed_send_count();
        Ok(())
    }
}

/// The initial direct EE rollout serves one attachment while the remaining
/// automatic LLC/MPTN runtime keeps its existing route loop. The destination
/// is taken from a validated RouteSetup/BIND and the live upstream directory.
/// A disconnected upstream drops EE/RTP state and reconnects with fresh
/// generations; an XID CP alone never publishes a user LU.
pub(crate) fn run_hpr(config: &RouterConfig) -> io::Result<()> {
    let attachment = config
        .ee
        .first()
        .ok_or_else(|| protocol("HPR runtime requires one EE attachment"))?;
    let remote = config
        .remote
        .first()
        .ok_or_else(|| protocol("HPR runtime requires one concentrator"))?;
    while !STOP.load(Ordering::Relaxed) {
        match AutoWsHub::connect(&remote.url, &remote.bearer_token()?, &[], &[]) {
            Ok(mut hub) => {
                if let Err(error) = run_connected(attachment, &mut hub) {
                    tracing::warn!(attachment = %attachment.id, error = %error,
                        "HPR upstream or EE adjacency reset");
                }
            }
            Err(error) => tracing::warn!(attachment = %attachment.id, error = %error,
                "HPR concentrator connection failed"),
        }
        if !STOP.load(Ordering::Relaxed) {
            thread::sleep(CONNECT_BACKOFF);
        }
    }
    Ok(())
}

fn run_connected(attachment: &crate::config::EeConfig, hub: &mut AutoWsHub) -> io::Result<()> {
    let identity = loop {
        if STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        poll_unsolicited(hub)?;
        if let Some(identity) = AuthorizedEeIdentity::resolve(hub, attachment)? {
            break identity;
        }
        thread::sleep(IDLE_POLL);
    };
    let peer_identity = identity.clone();
    let mut link =
        EeLdlcEndpoint::bind_dynamic(attachment.local_ip, attachment.peer_ip, move |xid| {
            peer_identity.build_xids(xid, true)
        })?;
    let clock = Instant::now();
    let mut active: Option<DirectHprRuntime> = None;
    tracing::info!(attachment = %attachment.id, local_ip = %attachment.local_ip,
        peer_ip = %attachment.peer_ip, proxy_cp = %identity.local_cp,
        "HPR EE attachment listening");
    while !STOP.load(Ordering::Relaxed) {
        poll_unsolicited(hub)?;
        if !identity.still_authorized(hub)? {
            return Err(protocol("EE proxy CP route withdrawn"));
        }
        let now = Instant::now();
        link.tick(now)?;
        if link.phase() == Phase::Active {
            if active
                .as_ref()
                .is_none_or(|runtime| runtime.bootstrap.generation != link.generation())
            {
                let bootstrap = link
                    .control_bootstrap()?
                    .ok_or_else(|| protocol("active EE link lacks control bootstrap"))?;
                active = Some(DirectHprRuntime::new(bootstrap));
                tracing::info!(attachment = %attachment.id, generation = link.generation().get(),
                    peer_cp = ?link.peer_cp(), "HPR EE link activated");
            }
        } else if active.take().is_some() {
            hub.publish_local(&[], &[])?;
            tracing::warn!(attachment = %attachment.id, "HPR EE link deactivated; sessions withdrawn");
        }
        if let Some(datagram) = link.poll(now)? {
            if let Some(runtime) = active.as_mut() {
                let no_user_work = runtime.sessions.is_empty()
                    && runtime
                        .pending_rtp
                        .iter()
                        .all(|message| message.kind != RtpIngressKind::User);
                let replace_route = no_user_work
                    && runtime.route_reply.is_none()
                    && runtime.negative_route_reply.is_none()
                    && runtime
                        .pending_rtp
                        .iter()
                        .all(|message| message.kind != RtpIngressKind::RouteSetup);
                let replace_cp = no_user_work
                    && runtime.pending_cp_replies.is_empty()
                    && runtime.pending_reciprocal_replies.is_empty()
                    && runtime.pending_rtp.iter().all(|message| {
                        !matches!(
                            message.kind,
                            RtpIngressKind::CpSvcMg | RtpIngressKind::CpSvcMgOut
                        )
                    });
                let old_route_scope = runtime.rtp.route_setup_scope();
                let old_cp_scope = runtime.rtp.cp_scope();
                let old_user_scope = runtime.rtp.user_scope();
                let messages = match runtime.rtp.on_ee_ui(
                    &link,
                    &datagram,
                    clock.elapsed().as_micros() as u64,
                    |kind| match kind {
                        RtpIngressKind::RouteSetup => replace_route,
                        RtpIngressKind::CpSvcMg => replace_cp,
                        RtpIngressKind::CpSvcMgOut => false,
                        RtpIngressKind::User => no_user_work,
                    },
                ) {
                    Ok(messages) => messages,
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        tracing::warn!(attachment = %attachment.id, peer_ip = %attachment.peer_ip,
                            udp_port = datagram.port, dsap = datagram.dsap,
                            ssap = datagram.ssap, generation = link.generation().get(),
                            error = %error, "discarded invalid HPR datagram");
                        Vec::new()
                    }
                    Err(error) => return Err(error),
                };
                if old_route_scope.is_some() && runtime.rtp.route_setup_scope() != old_route_scope {
                    runtime.route_setup = None;
                    runtime.route_reply = None;
                    runtime.negative_route_reply = None;
                    runtime.user_route_authorized = false;
                    runtime.bound_user_scope = None;
                    tracing::info!(attachment = %attachment.id,
                        generation = link.generation().get(),
                        "HPR RouteSetup RTP restarted on active EE link");
                }
                if old_cp_scope.is_some() && runtime.rtp.cp_scope() != old_cp_scope {
                    runtime.cp_management = None;
                    runtime.reciprocal_cp = None;
                    runtime.rtp.reset_cp_out();
                    tracing::info!(attachment = %attachment.id,
                        generation = link.generation().get(),
                        "HPR CP management RTP restarted on active EE link");
                }
                if old_user_scope.is_some() && runtime.rtp.user_scope() != old_user_scope {
                    runtime.bound_user_scope = None;
                    tracing::info!(attachment = %attachment.id,
                        generation = link.generation().get(),
                        "HPR user RTP restarted on active EE link");
                }
                runtime.queue_rtp(messages)?;
            }
        }
        if let Some(runtime) = active.as_mut() {
            runtime
                .rtp
                .tick(&link, clock.elapsed().as_micros() as u64)?;
            runtime.pump(&link, hub, clock.elapsed().as_micros() as u64)?;
        }
        thread::sleep(IDLE_POLL);
    }
    Ok(())
}

fn poll_unsolicited(hub: &mut AutoWsHub) -> io::Result<()> {
    if let Some(open) = hub.poll_incoming()? {
        hub.reject_incoming(&open, wire::OpenFailure::Unsupported)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SwitchError {
    Fabric(FabricError),
    DuplicateHandle,
    UnknownHandle,
    WrongEgress,
    InvalidBind,
    DeliveryNotLeased,
}

impl From<FabricError> for SwitchError {
    fn from(error: FabricError) -> Self {
        Self::Fabric(error)
    }
}

/// A `handle` belongs to one carrier attachment, not to the shared fabric.
/// HPR may use a directional SA and generation, while WebSocket uses a circuit
/// ID. The adapter maps its own opaque value to this integer before calling.
type CarrierHandle = u64;

#[derive(Debug)]
pub(crate) struct SessionSwitch {
    fabric: SessionFabric,
    handles: HashMap<(AdapterId, CarrierHandle), FabricSessionId>,
    leased: HashMap<(FabricSessionId, AdapterId), SessionEvent>,
}

impl SessionSwitch {
    pub(crate) fn new() -> Self {
        Self {
            fabric: SessionFabric::new(FabricLimits::default()),
            handles: HashMap::new(),
            leased: HashMap::new(),
        }
    }

    pub(crate) fn register(&mut self, adapter: AdapterId) {
        self.fabric.register_adapter(adapter);
    }

    pub(crate) fn replace_routes(
        &mut self,
        adapter: AdapterId,
        routes: Vec<Reachability>,
    ) -> Result<(), SwitchError> {
        self.fabric.replace_routes(adapter, routes)?;
        Ok(())
    }

    /// Admit an HPR or other carrier BIND after its adapter has verified the
    /// peer, RTP generation, directional session address and LU names. The
    /// route is pinned for this session; later directory refreshes affect only
    /// new BINDs. The egress handle is attached after its carrier opens.
    pub(crate) fn open(
        &mut self,
        ingress: AdapterId,
        handle: CarrierHandle,
        identity: SessionIdentity,
        bind: SessionUnit,
    ) -> Result<(FabricSessionId, AdapterId), SwitchError> {
        if self.handles.contains_key(&(ingress, handle)) {
            return Err(SwitchError::DuplicateHandle);
        }
        if bind.ru().is_empty() {
            return Err(SwitchError::InvalidBind);
        }
        let (id, egress) = self.fabric.open(ingress, identity)?;
        // Default fabric limits always admit one validated SessionUnit. The
        // BIND is the first event on a new session, so no queue can be full.
        if let Err(error) = self
            .fabric
            .submit(id, ingress, SessionEvent::BindRequest(bind))
        {
            let _ = self.fabric.discard_unopened(id);
            return Err(error.into());
        }
        self.handles.insert((ingress, handle), id);
        Ok((id, egress))
    }

    /// Associate the selected egress's new private carrier circuit. This
    /// prevents a WebSocket circuit or HPR SA from being reused by two sessions.
    pub(crate) fn bind_egress(
        &mut self,
        id: FabricSessionId,
        egress: AdapterId,
        handle: CarrierHandle,
    ) -> Result<(), SwitchError> {
        if self.handles.contains_key(&(egress, handle)) {
            return Err(SwitchError::DuplicateHandle);
        }
        let details = self.fabric.details(id).ok_or(SwitchError::UnknownHandle)?;
        if details.egress != egress {
            return Err(SwitchError::WrongEgress);
        }
        self.handles.insert((egress, handle), id);
        Ok(())
    }

    /// If the selected carrier cannot open its private circuit, notify the
    /// ingress through the same session contract. No egress handle exists yet.
    pub(crate) fn fail_egress(&mut self, id: FabricSessionId) -> Result<(), SwitchError> {
        let details = self.fabric.details(id).ok_or(SwitchError::UnknownHandle)?;
        self.fabric
            .submit(id, details.egress, SessionEvent::Reset)?;
        Ok(())
    }

    /// Submit one complete session event. On `Capacity`, the carrier must
    /// retain its input and withhold its own transport acknowledgement.
    pub(crate) fn submit(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
        event: SessionEvent,
    ) -> Result<(), SwitchError> {
        let id = self.lookup(adapter, handle)?;
        self.fabric.submit(id, adapter, event)?;
        Ok(())
    }

    /// Return the same event until `mark_sent` confirms the destination
    /// carrier accepted it. A failed socket send therefore retains the lease.
    pub(crate) fn next_delivery(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<Option<SessionEvent>, SwitchError> {
        let id = self.lookup(adapter, handle)?;
        if let Some(event) = self.leased.get(&(id, adapter)) {
            return Ok(Some(event.clone()));
        }
        let Some(event) = self.fabric.poll(id, adapter)? else {
            return Ok(None);
        };
        self.leased.insert((id, adapter), event.clone());
        Ok(Some(event))
    }

    pub(crate) fn mark_sent(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<(), SwitchError> {
        let id = self.lookup(adapter, handle)?;
        if self.leased.remove(&(id, adapter)).is_none() {
            return Err(SwitchError::DeliveryNotLeased);
        }
        self.reap(id);
        Ok(())
    }

    /// Withdraw one failed attachment and reset only its affected sessions.
    /// Surviving adapters may still drain their terminal Reset events.
    pub(crate) fn withdraw(&mut self, adapter: AdapterId) {
        let unopened = self
            .handles
            .iter()
            .filter_map(|(&(owner, _), &id)| {
                (owner == adapter
                    && !self
                        .handles
                        .iter()
                        .any(|(&(other, _), &other_id)| other != adapter && other_id == id))
                .then_some(id)
            })
            .collect::<Vec<_>>();
        for id in unopened {
            let _ = self.fabric.discard_unopened(id);
        }
        self.handles.retain(|(owner, _), _| *owner != adapter);
        self.leased.retain(|(_, owner), _| *owner != adapter);
        self.fabric.unregister_adapter(adapter);
        let ids = self.handles.values().copied().collect::<Vec<_>>();
        for id in ids {
            self.reap(id);
        }
    }

    pub(crate) fn session_count(&self) -> usize {
        self.fabric.session_count()
    }

    fn lookup(
        &self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<FabricSessionId, SwitchError> {
        self.handles
            .get(&(adapter, handle))
            .copied()
            .ok_or(SwitchError::UnknownHandle)
    }

    fn reap(&mut self, id: FabricSessionId) {
        if self.fabric.phase(id).is_none() && !self.leased.keys().any(|(key, _)| *key == id) {
            self.handles.retain(|_, key| *key != id);
        }
    }
}

/// The `session_v1` WebSocket profile carries the same complete reduced SNA
/// unit as the fabric. Transport byte credit is handled by SessionWsPort;
/// this conversion does not grant or consume application pacing credit.
pub(crate) fn to_session_wire(event: &SessionEvent) -> Option<wire::SessionEvent> {
    use wire::session_event::Event;
    let event = match event {
        SessionEvent::BindRequest(unit) => Event::BindRequest(unit.as_reduced().to_vec()),
        SessionEvent::BindResult { accepted, unit } => Event::BindResult(wire::SessionBindResult {
            accepted: *accepted,
            reduced_unit: unit.as_reduced().to_vec(),
        }),
        SessionEvent::Information { flow, unit } => Event::Information(wire::SessionInformation {
            expedited: *flow == Flow::Expedited,
            reduced_unit: unit.as_reduced().to_vec(),
        }),
        SessionEvent::Credit { normal, expedited } => {
            Event::PacingCredit(wire::SessionPacingCredit {
                normal: *normal,
                expedited: *expedited,
            })
        }
        SessionEvent::Unbind(unit) => Event::Unbind(unit.as_reduced().to_vec()),
        SessionEvent::Reset => return None,
    };
    Some(wire::SessionEvent { event: Some(event) })
}

pub(crate) fn from_session_wire(value: wire::SessionEvent) -> io::Result<SessionEvent> {
    use wire::session_event::Event;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid session_v1 event");
    let unit = |bytes: Vec<u8>| SessionUnit::from_reduced(&bytes).map_err(|_| invalid());
    match value.event.ok_or_else(invalid)? {
        Event::BindRequest(bytes) => Ok(SessionEvent::BindRequest(unit(bytes)?)),
        Event::BindResult(result) => Ok(SessionEvent::BindResult {
            accepted: result.accepted,
            unit: unit(result.reduced_unit)?,
        }),
        Event::Information(info) => Ok(SessionEvent::Information {
            flow: if info.expedited {
                Flow::Expedited
            } else {
                Flow::Normal
            },
            unit: unit(info.reduced_unit)?,
        }),
        Event::PacingCredit(credit) => Ok(SessionEvent::Credit {
            normal: credit.normal,
            expedited: credit.expedited,
        }),
        Event::Unbind(bytes) => Ok(SessionEvent::Unbind(unit(bytes)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::session::{Flow, QualifiedName};
    use router_core::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        hpr_session_address::RtpObservation,
        ConnectionGeneration,
    };

    fn q(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn identity() -> SessionIdentity {
        SessionIdentity::new(q("PEERNET.PINGER"), q("SNUSNU.PING"))
            .with_control_points(Some(q("PEERNET.HOST")), Some(q("SNUSNU.SVC")))
            .unwrap()
    }

    fn unit(opcode: u8) -> SessionUnit {
        SessionUnit::from_reduced(&[0x80, 1, 0x6b, 0x80, 0, opcode]).unwrap()
    }

    fn advertisement(cp: &str, id: u8) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: q(cp),
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

    #[test]
    fn cp_reply_backpressure_keeps_setup_ingress_and_route_setup_unopened() {
        let generation = ConnectionGeneration::new(1).unwrap();
        let bootstrap = HprControlBootstrap::new(
            generation,
            advertisement("SNUSNU.SVC", 1),
            advertisement("SOLNET.SNAB", 2),
        )
        .unwrap();
        let mut runtime = DirectHprRuntime::new(bootstrap);
        assert!(!runtime.reciprocal_cp_ready());
        assert!(runtime.reciprocal_cp.is_none());
        runtime.pending_cp_replies.push_back(vec![0x5d, 0]);
        runtime.pending_cp_reply_bytes = 2;
        let bind = RtpIngress {
            kind: RtpIngressKind::CpSvcMg,
            observation: RtpObservation {
                generation,
                tcid: 0x8000_0000_0000_0001,
            },
            bytes: vec![0x5d, 0],
        };
        assert_eq!(
            runtime.cp_message(&bind).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(runtime.pending_cp_replies.len(), 1);
        assert_eq!(runtime.pending_cp_reply_bytes, 2);
        assert!(!runtime.reciprocal_cp_ready());
        assert!(runtime.route_setup.is_none());
        assert!(!runtime.user_route_authorized);
    }

    #[test]
    fn reciprocal_cp_nonce_is_distinct_and_valid_for_bind_address() {
        let first = reciprocal_nonce();
        let second = reciprocal_nonce();
        assert_ne!(first, second);
        assert_ne!(first, 0);
        assert_eq!(first >> 62, 0);
        assert_eq!(second >> 62, 0);
    }

    #[test]
    fn user_nce_avoids_control_label_and_reserved_suffix_at_boundary() {
        for control in [[0xa4, 0xfd], [0xa4, 0xfe], [0xa4, 0xff]] {
            let user = user_nce_label(&control).unwrap();
            assert_ne!(user, control);
            assert_ne!(user[1], 0xff);
        }
        assert!(user_nce_label(&[]).is_err());
    }

    fn switch() -> SessionSwitch {
        let mut switch = SessionSwitch::new();
        switch.register(AdapterId(1));
        switch.register(AdapterId(2));
        switch
            .replace_routes(
                AdapterId(2),
                vec![Reachability {
                    lu: Some(q("SNUSNU.PING")),
                    cp: Some(q("SNUSNU.SVC")),
                }],
            )
            .unwrap();
        switch
    }

    #[test]
    fn bind_is_routed_to_aping_and_delivery_is_retried_until_confirmed() {
        let mut switch = switch();
        let (id, egress) = switch
            .open(AdapterId(1), 0x1234, identity(), unit(0x31))
            .unwrap();
        assert_eq!(egress, AdapterId(2));
        switch.bind_egress(id, egress, 0x55).unwrap();
        assert_eq!(
            switch.next_delivery(egress, 0x55).unwrap(),
            Some(SessionEvent::BindRequest(unit(0x31)))
        );
        assert_eq!(
            switch.next_delivery(egress, 0x55).unwrap(),
            Some(SessionEvent::BindRequest(unit(0x31)))
        );
        switch.mark_sent(egress, 0x55).unwrap();
        assert_eq!(switch.next_delivery(egress, 0x55).unwrap(), None);
        switch
            .submit(
                egress,
                0x55,
                SessionEvent::BindResult {
                    accepted: true,
                    unit: unit(0x31),
                },
            )
            .unwrap();
        assert!(matches!(
            switch.next_delivery(AdapterId(1), 0x1234).unwrap(),
            Some(SessionEvent::BindResult { accepted: true, .. })
        ));
        switch.mark_sent(AdapterId(1), 0x1234).unwrap();
        switch
            .submit(
                AdapterId(1),
                0x1234,
                SessionEvent::Information {
                    flow: Flow::Normal,
                    unit: unit(0x01),
                },
            )
            .unwrap();
        assert!(matches!(
            switch.next_delivery(egress, 0x55).unwrap(),
            Some(SessionEvent::Information { .. })
        ));
    }

    #[test]
    fn overlapping_management_and_application_circuits_retire_independently() {
        let mut switch = switch();
        for handle in [1, 2] {
            let (id, egress) = switch
                .open(AdapterId(1), handle, identity(), unit(0x31))
                .unwrap();
            assert_eq!(egress, AdapterId(2));
            switch.bind_egress(id, egress, handle).unwrap();
            assert!(matches!(
                switch.next_delivery(egress, handle).unwrap(),
                Some(SessionEvent::BindRequest(_))
            ));
            switch.mark_sent(egress, handle).unwrap();
            switch
                .submit(
                    egress,
                    handle,
                    SessionEvent::BindResult {
                        accepted: true,
                        unit: unit(0x31),
                    },
                )
                .unwrap();
            switch.next_delivery(AdapterId(1), handle).unwrap();
            switch.mark_sent(AdapterId(1), handle).unwrap();
        }
        assert_eq!(switch.session_count(), 2);
        switch.submit(AdapterId(2), 1, SessionEvent::Reset).unwrap();
        assert_eq!(
            switch.next_delivery(AdapterId(1), 1).unwrap(),
            Some(SessionEvent::Reset)
        );
        switch.mark_sent(AdapterId(1), 1).unwrap();
        assert_eq!(switch.session_count(), 1);
        assert!(switch.lookup(AdapterId(1), 1).is_err());
        assert!(switch.lookup(AdapterId(1), 2).is_ok());
        switch
            .submit(
                AdapterId(1),
                2,
                SessionEvent::Information {
                    flow: Flow::Normal,
                    unit: unit(0x01),
                },
            )
            .unwrap();
        assert!(matches!(
            switch.next_delivery(AdapterId(2), 2).unwrap(),
            Some(SessionEvent::Information { .. })
        ));
    }

    #[test]
    fn withdrawal_resets_only_affected_session() {
        let mut switch = switch();
        let (id, egress) = switch
            .open(AdapterId(1), 1, identity(), unit(0x31))
            .unwrap();
        switch.bind_egress(id, egress, 2).unwrap();
        switch.withdraw(AdapterId(1));
        assert_eq!(
            switch.next_delivery(egress, 2).unwrap(),
            Some(SessionEvent::Reset)
        );
        switch.mark_sent(egress, 2).unwrap();
        assert_eq!(switch.session_count(), 0);
        assert_eq!(
            switch.submit(AdapterId(1), 1, SessionEvent::Reset),
            Err(SwitchError::UnknownHandle)
        );
    }

    #[test]
    fn failed_egress_open_resets_ingress_without_a_phantom_handle() {
        let mut switch = switch();
        let (id, _) = switch
            .open(AdapterId(1), 1, identity(), unit(0x31))
            .unwrap();
        switch.fail_egress(id).unwrap();
        assert_eq!(
            switch.next_delivery(AdapterId(1), 1).unwrap(),
            Some(SessionEvent::Reset)
        );
        switch.mark_sent(AdapterId(1), 1).unwrap();
        assert_eq!(switch.session_count(), 0);
    }

    #[test]
    fn withdrawn_ingress_without_egress_circuit_releases_admission() {
        let mut switch = switch();
        switch
            .open(AdapterId(1), 1, identity(), unit(0x31))
            .unwrap();
        switch.withdraw(AdapterId(1));
        assert_eq!(switch.session_count(), 0);
    }

    #[test]
    fn session_wire_roundtrips_reduced_snf_rh_ru_and_credit() {
        for event in [
            SessionEvent::BindRequest(unit(0x31)),
            SessionEvent::BindResult {
                accepted: true,
                unit: unit(0x31),
            },
            SessionEvent::Information {
                flow: Flow::Expedited,
                unit: unit(0x01),
            },
            SessionEvent::Credit {
                normal: 8,
                expedited: 1,
            },
            SessionEvent::Unbind(unit(0x32)),
        ] {
            let wire = to_session_wire(&event).unwrap();
            assert_eq!(from_session_wire(wire).unwrap(), event);
        }
        assert!(to_session_wire(&SessionEvent::Reset).is_none());
        assert!(from_session_wire(wire::SessionEvent { event: None }).is_err());
    }
}
