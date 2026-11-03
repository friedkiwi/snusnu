//! Experimental native APPN LLC port, currently bounded to link activation.
//!
//! It answers TEST/XID with a caller-provided local XID3 profile and permits
//! SABME only after the XID role exchange completes. It deliberately closes
//! on the first SNA information PIU: a positive management BIND response
//! needs session parameter negotiation that is not yet implemented. This
//! port never emits `RouterEvent::Ready` and cannot carry routed user data.

use crate::{
    endpoint::{Endpoint, Event},
    native_type1::NativeType1,
    routing::{RoutePort, RoutedUnit, RouterEvent},
    runtime::LlcPeer,
};
use router_core::{
    fid2_bind::{classify_bind, BindClass},
    llc2::State,
    native_management::{ManagementSession, Phase as ManagementPhase},
    user_bind::{UserBindOffer, UserBindPolicy},
    user_fmh5::parse_first_user_attach,
    user_pacing::UserPacingSession,
    xid3::{Role, Xid3},
    xid3_activation::Phase,
};
use std::{collections::VecDeque, io, time::Duration};

#[derive(Debug)]
pub(crate) enum NativeLlcEvent {
    UserBind(Vec<u8>),
    FirstAttach(Vec<u8>),
    UserInformation(Vec<u8>),
    BindResponseAck,
    EgressAck(usize),
    Closed,
}

pub(crate) struct NativePeerPort {
    endpoint: Endpoint,
    type1: NativeType1,
    local_xid: Xid3,
    activation_announced: bool,
    reached_management_bind: bool,
    management: Option<ManagementSession>,
    user_probe: UserProbeState,
    user_offer: Option<UserBindOffer>,
    user_pacing: Option<UserPacingSession>,
    pacing_probe: Option<PacingProbePolicy>,
    first_user_attach: Option<Vec<u8>>,
    converter_policy: Option<(String, String)>,
    converter_expected_cp: Option<String>,
    converter_dynamic: bool,
    converter_events: VecDeque<NativeLlcEvent>,
    converter_offer: Option<UserBindOffer>,
    converter_bind_waits_for_bis_ack: bool,
    converter_bind_response_pending: bool,
    converter_negative_bind_pending: bool,
    converter_bind_response_acked: bool,
    converter_first_attach_seen: bool,
    reverse_user_mode: bool,
    reverse_completed: usize,
}

struct PacingProbePolicy {
    plu: String,
    slu: String,
    tp: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserProbeState {
    Off,
    AwaitBind,
    AwaitResponseAck,
    AwaitFollowup,
    AwaitPacingIprAck,
    AwaitPacingFollowup,
}

fn exclusive_bind_ack(completed: usize) -> io::Result<bool> {
    match completed {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "converter user BIND ACK includes another LLC completion",
        )),
    }
}

fn negative_user_bind_reply(mut positive: Vec<u8>, sense: [u8; 4]) -> io::Result<Vec<u8>> {
    if positive.len() < 10 || positive[6..9] != [0xeb, 0x80, 0] || positive[9] != 0x31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "validated native user BIND response has invalid profile",
        ));
    }
    positive.truncate(6);
    positive.extend_from_slice(&[0xeb, 0x90, 0]);
    positive.extend_from_slice(&sense);
    Ok(positive)
}

fn converter_rejection_ready(
    offer_present: bool,
    response_pending: bool,
    response_acked: bool,
    negative_pending: bool,
    phase: Option<ManagementPhase>,
) -> io::Result<bool> {
    if !offer_present || response_pending || response_acked || negative_pending {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native user BIND is not awaiting a response",
        ));
    }
    Ok(phase == Some(ManagementPhase::Closed))
}

fn reverse_management_available(phase: Option<ManagementPhase>, reached_bind: bool) -> bool {
    phase.is_none()
        || (phase == Some(ManagementPhase::AwaitBind) && !reached_bind)
        || phase == Some(ManagementPhase::Closed)
}

impl NativePeerPort {
    pub(crate) fn open(peer: LlcPeer<'_>, local_xid: Xid3) -> io::Result<Self> {
        let mut endpoint = Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?;
        endpoint.set_connect_allowed(false)?;
        Self::open_with_endpoint(endpoint, peer.interface, local_xid)
    }

    fn open_with_endpoint(
        mut endpoint: Endpoint,
        interface: &str,
        local_xid: Xid3,
    ) -> io::Result<Self> {
        let type1 = NativeType1::new(local_xid.clone())?;
        endpoint.set_connect_allowed(false)?;
        tracing::info!(
            interface,
            local_cp = %local_xid.cp_name().map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            "native APPN XID-only port opened"
        );
        Ok(Self {
            endpoint,
            type1,
            local_xid,
            activation_announced: false,
            reached_management_bind: false,
            management: None,
            user_probe: UserProbeState::Off,
            user_offer: None,
            user_pacing: None,
            pacing_probe: None,
            first_user_attach: None,
            converter_policy: None,
            converter_expected_cp: None,
            converter_dynamic: false,
            converter_events: VecDeque::new(),
            converter_offer: None,
            converter_bind_waits_for_bis_ack: false,
            converter_bind_response_pending: false,
            converter_negative_bind_pending: false,
            converter_bind_response_acked: false,
            converter_first_attach_seen: false,
            reverse_user_mode: false,
            reverse_completed: 0,
        })
    }

    pub(crate) fn open_management(
        peer: LlcPeer<'_>,
        local_xid: Xid3,
        remote_plu: String,
        local_slu: String,
    ) -> io::Result<Self> {
        let mut port = Self::open(peer, local_xid)?;
        port.management = Some(ManagementSession::new(remote_plu, local_slu));
        Ok(port)
    }

    pub(crate) fn management_complete(&self) -> bool {
        matches!(
            self.management.as_ref().map(ManagementSession::phase),
            Some(ManagementPhase::Closed)
        )
    }

    pub(crate) fn open_user_bind_probe(
        peer: LlcPeer<'_>,
        local_xid: Xid3,
        remote_plu: String,
        local_slu: String,
    ) -> io::Result<Self> {
        let mut port = Self::open_management(peer, local_xid, remote_plu, local_slu)?;
        port.user_probe = UserProbeState::AwaitBind;
        Ok(port)
    }

    pub(crate) fn open_user_pacing_probe(
        peer: LlcPeer<'_>,
        local_xid: Xid3,
        remote_plu: String,
        local_slu: String,
        user_plu: String,
        user_slu: String,
        tp: [u8; 4],
    ) -> io::Result<Self> {
        let mut port = Self::open_user_bind_probe(peer, local_xid, remote_plu, local_slu)?;
        port.pacing_probe = Some(PacingProbePolicy {
            plu: user_plu,
            slu: user_slu,
            tp,
        });
        Ok(port)
    }

    pub(crate) fn open_converter(
        peer: LlcPeer<'_>,
        local_xid: Xid3,
        remote_cp: String,
        local_cp: String,
        user_plu: String,
        user_slu: String,
    ) -> io::Result<Self> {
        let mut port = Self::open_management(peer, local_xid, remote_cp.clone(), local_cp)?;
        port.converter_policy = Some((user_plu, user_slu));
        port.converter_expected_cp = Some(remote_cp);
        Ok(port)
    }

    /// Learn the native CP from XID3 after a null-XID offer. The virtual CP
    /// comes from the route target's local XID profile, while the management
    /// and user LU pair are validated against the peer's subsequent BINDs.
    pub(crate) fn open_dynamic_converter_from_endpoint(
        endpoint: Endpoint,
        first_events: Vec<Event>,
        interface: &str,
        local_xid: Xid3,
        observed_cp: Option<String>,
    ) -> io::Result<Self> {
        let mut port = Self::open_with_endpoint(endpoint, interface, local_xid)?;
        port.converter_dynamic = true;
        port.converter_expected_cp = observed_cp;
        port.process(first_events)?;
        Ok(port)
    }

    pub(crate) fn take_converter_event(&mut self) -> Option<NativeLlcEvent> {
        self.converter_events.pop_front()
    }

    /// The CP from XID3 is usable for local route admission only after the
    /// full Type1 role exchange has validated the peer and link activation.
    pub(crate) fn converter_peer_cp(&self) -> Option<&str> {
        (self.converter_dynamic && self.activation_announced)
            .then(|| self.type1.peer_name())
            .flatten()
    }

    pub(crate) fn local_xid(&self) -> &Xid3 {
        &self.local_xid
    }

    /// The native BIND response must use the negotiated management profile;
    /// a remote carrier's positive reduced response cannot be sent verbatim.
    pub(crate) fn converter_positive_bind_response(&self) -> io::Result<Vec<u8>> {
        self.converter_offer
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "native user BIND offer missing")
            })?
            .build_fixed_response(1)
            .map_err(management_error)
    }

    /// Refuse a user BIND without retiring its verified LLC2 adjacency.
    /// The fixed positive template supplies the exact TH address/SNF pair;
    /// only the response type and four-byte SNA sense are changed.
    pub(crate) fn reject_converter_user_bind(&mut self, sense: [u8; 4]) -> io::Result<bool> {
        if !converter_rejection_ready(
            self.converter_offer.is_some(),
            self.converter_bind_response_pending,
            self.converter_bind_response_acked,
            self.converter_negative_bind_pending,
            self.management.as_ref().map(ManagementSession::phase),
        )? {
            return Ok(false);
        }
        if self.endpoint.buffered_information_count() != 0 {
            return Ok(false);
        }
        let reply = negative_user_bind_reply(self.converter_positive_bind_response()?, sense)?;
        if !self.endpoint.queue_information(reply)? {
            return Ok(false);
        }
        self.converter_bind_response_pending = true;
        self.converter_negative_bind_pending = true;
        Ok(true)
    }

    pub(crate) fn replay_converter_user_bind(&mut self, piu: Vec<u8>) -> io::Result<()> {
        if self
            .converter_offer
            .as_ref()
            .is_none_or(|offer| offer.request() != piu)
            || self
                .converter_events
                .iter()
                .any(|event| matches!(event, NativeLlcEvent::UserBind(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "converter user BIND cannot be replayed",
            ));
        }
        self.converter_events
            .push_front(NativeLlcEvent::UserBind(piu));
        Ok(())
    }

    /// Begin XID from this fixed-role link toward a passive OS/400 controller.
    /// The caller must enable this explicitly for an inbound routed session;
    /// a responder-only port continues waiting for the guest's first XID.
    pub(crate) fn begin_active_xid(&mut self) -> io::Result<()> {
        let null = self.type1.prepare_active_null_xid()?;
        self.endpoint.send_type1(&null.pdu)?;
        self.type1.confirm_sent(&null)?;
        tracing::info!(peer_cp = ?self.converter_expected_cp, "native active null XID sent to passive peer");
        Ok(())
    }

    pub(crate) fn link_established(&self) -> bool {
        self.type1.phase() == Phase::ReadyForSabme && self.endpoint.state() == State::Connected
    }

    pub(crate) fn enqueue_converter_piu(&mut self, piu: &[u8]) -> io::Result<bool> {
        if self.converter_policy.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native converter mode disabled",
            ));
        }
        if self.converter_offer.is_some()
            && !self.converter_bind_response_acked
            && !self.converter_bind_response_pending
        {
            // Management BIS must have drained before this first user egress.
            // Keep its LLC completion exclusive, even if a future management
            // handler queues another frame in this phase.
            if self.endpoint.buffered_information_count() != 0 {
                return Ok(false);
            }
            let offer = self.converter_offer.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "converter user BIND offer missing",
                )
            })?;
            if piu != offer.build_fixed_response(1).map_err(management_error)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native user BIND response differs from validated fixed profile",
                ));
            }
            if self.endpoint.queue_information(piu.to_vec())? {
                self.converter_bind_response_pending = true;
                return Ok(true);
            }
            return Ok(false);
        }
        if !self.converter_bind_response_acked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native user BIND not acknowledged",
            ));
        }
        if self.management.as_ref().map(ManagementSession::phase) != Some(ManagementPhase::Closed) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "user PIU before management teardown",
            ));
        }
        self.endpoint.queue_information(piu.to_vec())
    }

    pub(crate) fn converter_available_slots(&self) -> usize {
        self.endpoint.available_receive_slots()
    }

    pub(crate) fn converter_management_bind(
        &self,
    ) -> Option<&router_core::fid2_session_control::ManagementBind> {
        self.management.as_ref().and_then(ManagementSession::bind)
    }

    /// Lease the already authenticated LLC2 association for a remotely
    /// initiated user BIND. The V4R4 management pair allocates address two
    /// for the first user session in both directions after its UNBIND.
    pub(crate) fn begin_reverse_user_mode(
        &mut self,
    ) -> io::Result<transport_ip_sna::mptn_reverse_user_bind::NativeAddress> {
        if !self.reverse_idle_ready() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "verified native LLC adjacency is not idle for reverse user BIND",
            ));
        }
        let bind = self.converter_management_bind().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "native management BIND missing")
        })?;
        let (management_daf, management_oaf) = bind.request_addresses();
        let address = transport_ip_sna::mptn_reverse_user_bind::NativeAddress {
            daf: management_oaf,
            oaf: management_daf.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "native user address exhausted")
            })?,
            odai: true,
        };
        self.reverse_user_mode = true;
        self.reverse_completed = 0;
        Ok(address)
    }

    pub(crate) fn begin_reverse_management_mode(&mut self) -> io::Result<()> {
        if !self.reverse_link_available() || !self.reverse_needs_management() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native LLC link is not idle for reverse management",
            ));
        }
        // XID installs a passive responder before the guest sends any BIND.
        // Transfer that untouched role to VirtualWsPort, which can process a
        // reciprocal guest BIND while initiating our own SNASVCMG exchange.
        self.management = None;
        self.converter_policy = None;
        self.reverse_user_mode = true;
        self.reverse_completed = 0;
        Ok(())
    }

    pub(crate) fn reverse_needs_management(&self) -> bool {
        self.management.is_none()
            || (self.management.as_ref().map(ManagementSession::phase)
                == Some(ManagementPhase::AwaitBind)
                && !self.reached_management_bind)
    }

    pub(crate) fn reverse_link_available(&self) -> bool {
        !self.reverse_user_mode
            && self.link_established()
            && self.converter_offer.is_none()
            && !self.converter_bind_response_pending
            && self.converter_events.is_empty()
            && reverse_management_available(
                self.management.as_ref().map(ManagementSession::phase),
                self.reached_management_bind,
            )
    }

    pub(crate) fn reverse_idle_ready(&self) -> bool {
        self.reverse_link_available()
            && self.management.is_some()
            && self
                .converter_management_bind()
                .is_some_and(|bind| bind.request_addresses().0 < u8::MAX)
    }

    pub(crate) fn end_reverse_user_mode(&mut self) -> io::Result<()> {
        if !self.reverse_user_mode || self.reverse_completed != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native reverse user mode has pending LLC completion",
            ));
        }
        self.reverse_user_mode = false;
        if self.management.is_none() {
            let peer_cp = self
                .type1
                .peer_name()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "verified LLC peer CP disappeared",
                    )
                })?
                .to_owned();
            let local_cp = self.local_xid.cp_name().map_err(management_error)?;
            self.management = Some(ManagementSession::new(peer_cp.clone(), local_cp.clone()));
            self.converter_policy = Some((peer_cp, local_cp));
            self.reached_management_bind = false;
        }
        Ok(())
    }

    pub(crate) fn reached_management_bind(&self) -> bool {
        self.reached_management_bind
    }

    fn process(&mut self, events: Vec<Event>) -> io::Result<Vec<RouterEvent>> {
        if self.reverse_user_mode {
            self.reverse_completed = self
                .reverse_completed
                .saturating_add(self.endpoint.take_completed_information_count());
        }
        if let Some(management) = self.management.as_mut() {
            let completed = if self.reverse_user_mode {
                0
            } else {
                self.endpoint.take_completed_information_count()
            };
            if self.reverse_user_mode {
            } else if self.converter_bind_response_pending && exclusive_bind_ack(completed)? {
                self.converter_bind_response_pending = false;
                if self.converter_negative_bind_pending {
                    self.converter_negative_bind_pending = false;
                    self.converter_offer = None;
                    self.converter_policy = None;
                    self.converter_bind_waits_for_bis_ack = false;
                    self.converter_bind_response_acked = false;
                    self.converter_first_attach_seen = false;
                    tracing::info!(peer_cp = ?self.type1.peer_name(),
                        "native user BIND rejected; LLC2 adjacency remains available");
                } else {
                    self.converter_bind_response_acked = true;
                }
                self.converter_events
                    .push_back(NativeLlcEvent::BindResponseAck);
            } else if self.converter_policy.is_some()
                && management.phase() == ManagementPhase::Closed
                && completed != 0
            {
                self.converter_events
                    .push_back(NativeLlcEvent::EgressAck(completed));
            } else if self.user_probe == UserProbeState::AwaitResponseAck && completed == 1 {
                if let Some(pacing) = self.user_pacing.as_mut() {
                    pacing
                        .acknowledge_bind(completed)
                        .map_err(management_error)?;
                }
                self.user_probe = UserProbeState::AwaitFollowup;
                tracing::info!("experimental native user BIND response acknowledged by LLC2; awaiting peer follow-up");
            } else if self.user_probe == UserProbeState::AwaitPacingIprAck && completed == 1 {
                self.user_probe = UserProbeState::AwaitPacingFollowup;
                tracing::info!(
                    "experimental user pacing IPR acknowledged by LLC2; awaiting next user PIU"
                );
            } else {
                match management.phase() {
                    ManagementPhase::AwaitBindAck if completed != 0 => management
                        .acknowledge_bind(completed)
                        .map_err(management_error)?,
                    ManagementPhase::AwaitCnosAck if completed != 0 => management
                        .acknowledge_attach_replies(completed)
                        .map_err(management_error)?,
                    ManagementPhase::AwaitBisAck if completed != 0 => management
                        .acknowledge_bis(completed)
                        .map_err(management_error)?,
                    ManagementPhase::AwaitUnbindAck if completed != 0 => management
                        .acknowledge_unbind(completed)
                        .map_err(management_error)?,
                    _ if completed != 0 => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected native LLC completion",
                        ))
                    }
                    _ => {}
                }
            }
            publish_pending_converter_bind(
                management.phase(),
                &self.converter_offer,
                &mut self.converter_bind_waits_for_bis_ack,
                &mut self.converter_events,
            )?;
            if let Some(attach) = management.take_early_attach() {
                if let Err(error) = self.process_management_piu(attach) {
                    self.endpoint.disconnect()?;
                    return Err(error);
                }
            }
        }
        let mut routed = Vec::new();
        for event in events {
            match event {
                Event::Type1(pdu) => {
                    if let Some(outbound) = self.type1.on_pdu(&pdu)? {
                        self.endpoint.send_type1(&outbound.pdu)?;
                        if self.type1.confirm_sent(&outbound)? == Phase::ReadyForSabme
                            && !self.activation_announced
                        {
                            if let Some(expected) = &self.converter_expected_cp {
                                if self.type1.peer_name() != Some(expected.as_str()) {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "native XID3 CP differs from converter peer policy",
                                    ));
                                }
                            }
                            if self.converter_dynamic && self.management.is_none() {
                                let peer_cp = self
                                    .type1
                                    .peer_name()
                                    .ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "native XID3 CP missing",
                                        )
                                    })?
                                    .to_owned();
                                let local_cp =
                                    self.local_xid.cp_name().map_err(management_error)?;
                                self.management =
                                    Some(ManagementSession::new(peer_cp.clone(), local_cp));
                                self.converter_policy = Some((
                                    peer_cp.clone(),
                                    self.local_xid.cp_name().map_err(management_error)?,
                                ));
                                self.converter_expected_cp = Some(peer_cp);
                            }
                            self.endpoint.set_connect_allowed(true)?;
                            if self.type1.local_role() == Role::Primary {
                                // Let any crossed final XID command/response
                                // settle before the primary sets LLC2 mode.
                                self.endpoint.begin_connect_after(Duration::from_millis(50));
                            }
                            self.activation_announced = true;
                            tracing::info!(peer_cp = ?self.type1.peer_name(), local_role = ?self.type1.local_role(), "APPN XID3 negotiation complete; SABME permitted");
                        }
                    }
                }
                Event::Connected => {
                    if self.type1.phase() != Phase::ReadyForSabme {
                        self.endpoint.disconnect()?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "LLC2 contact before APPN XID3 completion",
                        ));
                    }
                    tracing::info!(peer_cp = ?self.type1.peer_name(), "native APPN LLC2 contact established; awaiting management BIND");
                }
                Event::Information(piu) => {
                    if self.reverse_user_mode {
                        routed.push(RouterEvent::Unit(RoutedUnit::SnaInformation(piu)));
                        continue;
                    }
                    if self.management.is_some() {
                        if let Err(error) = self.process_management_piu(piu) {
                            self.endpoint.disconnect()?;
                            return Err(error);
                        }
                        continue;
                    }
                    let bind = match classify_bind(&piu) {
                        Ok(bind) => bind,
                        Err(error) => {
                            self.endpoint.disconnect()?;
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unsupported native BIND: {error}"),
                            ));
                        }
                    };
                    let Some(bind) = bind else {
                        self.endpoint.disconnect()?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "first native PIU is not a BIND",
                        ));
                    };
                    if !matches!(&bind.class, BindClass::Management { mode } if mode == "SNASVCMG")
                    {
                        self.endpoint.disconnect()?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "first native BIND is not SNASVCMG",
                        ));
                    }
                    self.reached_management_bind = true;
                    tracing::warn!(plu = %bind.plu, slu = %bind.slu, daf = bind.daf, oaf = bind.oaf, bytes = piu.len(), "native APPN SNASVCMG BIND reached XID-only port; responder unavailable, disconnecting");
                    self.endpoint.disconnect()?;
                }
                Event::Disconnected | Event::TimedOut => {
                    if self.reverse_user_mode {
                        routed.push(match event {
                            Event::TimedOut => RouterEvent::TimedOut,
                            _ => RouterEvent::Closed,
                        });
                        continue;
                    }
                    if self.converter_policy.is_some() {
                        self.converter_events.push_back(NativeLlcEvent::Closed);
                        return Ok(Vec::new());
                    }
                    if self.management.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "native management probe lost LLC association",
                        ));
                    }
                    if self.endpoint.state() == State::Disconnected {
                        self.endpoint.set_connect_allowed(false)?;
                        self.type1 = NativeType1::new(self.local_xid.clone())?;
                        self.activation_announced = false;
                    }
                }
            }
        }
        // The native port is not ready for user traffic until management
        // BIND/CNOS and a gateway session are implemented.
        Ok(routed)
    }

    fn process_management_piu(&mut self, piu: Vec<u8>) -> io::Result<()> {
        if self.converter_dynamic
            && self.converter_offer.is_none()
            && self.management.as_ref().is_some_and(|management| {
                matches!(
                    management.phase(),
                    ManagementPhase::AwaitBisAck
                        | ManagementPhase::BisComplete
                        | ManagementPhase::Closed
                )
            })
        {
            if let Some(bind) = classify_bind(&piu).map_err(management_error)? {
                self.converter_policy = Some((bind.plu, bind.slu));
            }
        }
        let management = self.management.as_mut().expect("management mode");
        let management_unbind = piu.len() >= 10 && piu[6..9] == [0x6b, 0x80, 0] && piu[9] == 0x32;
        if self.converter_policy.is_some() && management.phase() == ManagementPhase::Closed {
            if self.converter_offer.is_none() {
                let bind = management.bind().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "management BIND missing")
                })?;
                let (plu, slu) = self.converter_policy.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "converter policy missing")
                })?;
                return queue_converter_bind(
                    management.phase(),
                    &piu,
                    bind,
                    plu,
                    slu,
                    &mut self.converter_offer,
                    &mut self.converter_bind_waits_for_bis_ack,
                    &mut self.converter_events,
                );
            }
            if !self.converter_bind_response_acked {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "user BIND response not acknowledged",
                ));
            }
            if !self.converter_first_attach_seen {
                let offer = self.converter_offer.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "converter user BIND missing")
                })?;
                parse_first_user_attach(&piu, offer).map_err(management_error)?;
                self.converter_first_attach_seen = true;
                self.converter_events
                    .push_back(NativeLlcEvent::FirstAttach(piu));
            } else {
                self.converter_events
                    .push_back(NativeLlcEvent::UserInformation(piu));
            }
            return Ok(());
        }
        if self.user_probe == UserProbeState::AwaitFollowup
            && !management_unbind
            && self.pacing_probe.is_some()
        {
            if management.phase() != ManagementPhase::Closed || self.first_user_attach.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "user Attach before management teardown or duplicate Attach",
                ));
            }
            let policy = self.pacing_probe.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "pacing probe missing")
            })?;
            let offer = self.user_offer.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "user BIND offer missing")
            })?;
            let pacing = self.user_pacing.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "user pacing session missing")
            })?;
            let route = pacing
                .observe_first_attach(offer, &policy.tp, &piu)
                .map_err(management_error)?;
            self.first_user_attach = Some(piu);
            let ipr = pacing.prepare_ipr(1).map_err(management_error)?.to_vec();
            if !self.endpoint.queue_information(ipr.clone())? {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "user pacing IPR queue full",
                ));
            }
            pacing
                .mark_egress_enqueued(&ipr)
                .map_err(management_error)?;
            self.user_probe = UserProbeState::AwaitPacingIprAck;
            tracing::info!(remote_lu = %route.remote_lu, local_lu = %route.local_lu, mode = %route.mode, tp = ?route.transaction_program, pip_bytes = route.pip_bytes, "native user Attach buffered and fixed pacing IPR queued; no application gateway active");
            return Ok(());
        }
        if self.user_probe == UserProbeState::AwaitResponseAck
            || (self.user_probe == UserProbeState::AwaitFollowup && !management_unbind)
            || matches!(
                self.user_probe,
                UserProbeState::AwaitPacingIprAck | UserProbeState::AwaitPacingFollowup
            )
        {
            if self.user_probe == UserProbeState::AwaitFollowup {
                if let Some(offer) = &self.user_offer {
                    match parse_first_user_attach(&piu, offer) {
                        Ok(attach) => tracing::info!(
                            daf = attach.daf,
                            oaf = attach.oaf,
                            sequence = attach.sequence,
                            fmh5_bytes = attach.fmh5_bytes,
                            opaque_tail_bytes = attach.opaque_tail_bytes,
                            "native user FMH-5 Attach recognized; no application gateway active"
                        ),
                        Err(error) => {
                            tracing::warn!(error = %error, "native user follow-up differs from captured FMH-5 Attach")
                        }
                    }
                }
            }
            tracing::warn!(bytes = piu.len(), th = ?piu.get(..6), rh = ?piu.get(6..9), "native user BIND probe reached peer follow-up; closing before unsupported user traffic");
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native user session follow-up is not implemented",
            ));
        }
        if piu.len() >= 9 && piu[6] == 0x83 {
            management.observe_ipr(&piu).map_err(management_error)?;
            tracing::debug!("native management fixed pacing IPR accepted");
            return Ok(());
        }
        match management.phase() {
            ManagementPhase::AwaitBind => {
                let bind = management.observe_bind(&piu).map_err(management_error)?;
                let (daf, oaf) = bind.request_addresses();
                tracing::info!(
                    daf,
                    oaf,
                    bytes = piu.len(),
                    "native SNASVCMG BIND validated"
                );
                let response = management
                    .prepare_bind_response()
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(response.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIND response queue full",
                    ));
                }
                management
                    .mark_bind_enqueued(&response)
                    .map_err(management_error)?;
                self.reached_management_bind = true;
            }
            ManagementPhase::AwaitBindAck => management
                .buffer_early_attach(&piu)
                .map_err(management_error)?,
            ManagementPhase::AwaitAttach => {
                // Both responses must fit before pacing is consumed. If an
                // I/O error occurs after enqueue, this one-shot probe exits
                // and the entire LLC association is discarded.
                if self.endpoint.available_receive_slots() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native CNOS needs two LLC egress slots",
                    ));
                }
                let (ipr, cnos) = management.observe_attach(&piu).map_err(management_error)?;
                let (ipr, cnos) = (ipr.to_vec(), cnos.to_vec());
                for reply in [&ipr, &cnos] {
                    if !self.endpoint.queue_information(reply.clone())? {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "native CNOS response queue full",
                        ));
                    }
                }
                management
                    .mark_attach_replies_enqueued(&ipr, &cnos)
                    .map_err(management_error)?;
                tracing::info!(
                    "native CNOS accepted-pending response queued; no user route active"
                );
            }
            ManagementPhase::CnosComplete => {
                if self.endpoint.available_receive_slots() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIS needs two LLC egress slots",
                    ));
                }
                let ipr = management
                    .observe_remote_bis(&piu)
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(ipr.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIS IPR queue full",
                    ));
                }
                management
                    .mark_bis_ipr_enqueued(&ipr)
                    .map_err(management_error)?;
                let local_bis = management
                    .prepare_local_bis(true)
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(local_bis.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIS egress queue full",
                    ));
                }
                management
                    .mark_local_bis_enqueued(&local_bis)
                    .map_err(management_error)?;
                tracing::info!(
                    "native bilateral BIS exchange queued; awaiting LLC acknowledgement"
                );
            }
            ManagementPhase::AwaitBisAck if self.converter_policy.is_some() => {
                let bind = management.bind().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "management BIND missing")
                })?;
                let (plu, slu) = self.converter_policy.as_ref().unwrap();
                queue_converter_bind(
                    management.phase(),
                    &piu,
                    bind,
                    plu,
                    slu,
                    &mut self.converter_offer,
                    &mut self.converter_bind_waits_for_bis_ack,
                    &mut self.converter_events,
                )?;
            }
            ManagementPhase::BisComplete => {
                if matches!(classify_bind(&piu), Ok(Some(_))) {
                    let bind = management.bind().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "management BIND missing")
                    })?;
                    if let Some((plu, slu)) = &self.converter_policy {
                        queue_converter_bind(
                            management.phase(),
                            &piu,
                            bind,
                            plu,
                            slu,
                            &mut self.converter_offer,
                            &mut self.converter_bind_waits_for_bis_ack,
                            &mut self.converter_events,
                        )?;
                        return Ok(());
                    }
                    let offer = if let Some(policy) = &self.pacing_probe {
                        UserBindOffer::from_request_with_policy(
                            &piu,
                            bind,
                            UserBindPolicy {
                                plu: &policy.plu,
                                slu: &policy.slu,
                                mode: "",
                            },
                        )
                        .map_err(management_error)?
                    } else {
                        UserBindOffer::from_request(&piu, bind, "").map_err(management_error)?
                    };
                    tracing::warn!(plu = %offer.plu, slu = %offer.slu, daf = offer.daf, oaf = offer.oaf, mode = %offer.mode, bytes = offer.request().len(), experimental_response = self.user_probe == UserProbeState::AwaitBind, "native user BIND offer validated; user gateway unavailable");
                    if self.user_probe == UserProbeState::AwaitBind {
                        let mut pacing = if self.pacing_probe.is_some() {
                            Some(
                                UserPacingSession::new(&offer, bind, 1)
                                    .map_err(management_error)?,
                            )
                        } else {
                            None
                        };
                        let response = if let Some(session) = &pacing {
                            session.prepared_bind_response().to_vec()
                        } else {
                            offer.build_fixed_response(1).map_err(management_error)?
                        };
                        if !self.endpoint.queue_information(response.clone())? {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "native user BIND response queue full",
                            ));
                        }
                        if let Some(session) = pacing.as_mut() {
                            session
                                .mark_bind_enqueued(&response)
                                .map_err(management_error)?;
                        }
                        self.user_pacing = pacing;
                        self.user_offer = Some(offer);
                        self.user_probe = UserProbeState::AwaitResponseAck;
                        tracing::warn!("experimental fixed-window native user BIND response queued; no user gateway active");
                        return Ok(());
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "native user BIND gateway is not implemented",
                    ));
                }
                let response = management
                    .prepare_unbind_response(&piu)
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(response.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native UNBIND response queue full",
                    ));
                }
                management
                    .mark_unbind_enqueued(&response)
                    .map_err(management_error)?;
                tracing::info!("native management UNBIND response queued; no user route active");
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported native management PIU",
                ))
            }
        }
        Ok(())
    }
}

fn management_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn validate_converter_bind(
    piu: &[u8],
    management: &router_core::fid2_session_control::ManagementBind,
    plu: &str,
    slu: &str,
    management_closed: bool,
) -> io::Result<UserBindOffer> {
    // A complete supported FID2 BIND is at most a 256-byte RU plus TH/RH.
    // Bound the one deferred offer before copying it into session state.
    if piu.len() > 265 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "converter user BIND exceeds bounded PIU",
        ));
    }
    let policy = UserBindPolicy { plu, slu, mode: "" };
    let offer = if management_closed {
        UserBindOffer::from_request_after_management(piu, management, policy)
    } else {
        UserBindOffer::from_request_with_policy(piu, management, policy)
    }
    .map_err(management_error)?;
    offer.build_fixed_response(1).map_err(management_error)?;
    Ok(offer)
}

#[expect(
    clippy::too_many_arguments,
    reason = "BIND transition updates three independent session outputs"
)]
fn queue_converter_bind(
    phase: ManagementPhase,
    piu: &[u8],
    management: &router_core::fid2_session_control::ManagementBind,
    plu: &str,
    slu: &str,
    offer: &mut Option<UserBindOffer>,
    waiting_for_bis_ack: &mut bool,
    events: &mut VecDeque<NativeLlcEvent>,
) -> io::Result<()> {
    if !matches!(
        phase,
        ManagementPhase::AwaitBisAck | ManagementPhase::BisComplete | ManagementPhase::Closed
    ) || !matches!(classify_bind(piu), Ok(Some(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "converter user PIU is not a BIND at the BIS boundary",
        ));
    }
    if offer.is_some() || *waiting_for_bis_ack {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "duplicate converter user BIND",
        ));
    }
    let validated =
        validate_converter_bind(piu, management, plu, slu, phase == ManagementPhase::Closed)?;
    tracing::info!(
        daf = validated.daf,
        oaf = validated.oaf,
        bytes = piu.len(),
        pending_bis_ack = phase == ManagementPhase::AwaitBisAck,
        "native converter user BIND validated"
    );
    *offer = Some(validated);
    if phase == ManagementPhase::AwaitBisAck {
        *waiting_for_bis_ack = true;
    } else {
        events.push_back(NativeLlcEvent::UserBind(piu.to_vec()));
    }
    Ok(())
}

fn publish_pending_converter_bind(
    phase: ManagementPhase,
    offer: &Option<UserBindOffer>,
    waiting_for_bis_ack: &mut bool,
    events: &mut VecDeque<NativeLlcEvent>,
) -> io::Result<()> {
    if phase != ManagementPhase::BisComplete || !*waiting_for_bis_ack {
        return Ok(());
    }
    let piu = offer
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pending user BIND missing"))?
        .request()
        .to_vec();
    *waiting_for_bis_ack = false;
    events.push_back(NativeLlcEvent::UserBind(piu));
    Ok(())
}

impl RoutePort for NativePeerPort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        self.endpoint
            .poll(
                (!self.reverse_user_mode && self.converter_policy.is_none())
                    || can_accept_information,
            )?
            .map(|events| self.process(events))
            .transpose()
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        let events = self.endpoint.tick()?;
        self.process(events)
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        match unit {
            RoutedUnit::SnaInformation(piu) if self.reverse_user_mode => {
                self.endpoint.queue_information(piu)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native APPN session gateway is not active",
            )),
        }
    }

    fn has_capacity(&self) -> bool {
        if self.reverse_user_mode {
            self.endpoint.has_capacity()
        } else {
            !self.reached_management_bind
        }
    }

    fn available_receive_slots(&self) -> usize {
        self.endpoint.available_receive_slots()
    }

    fn take_completed_information_count(&mut self) -> usize {
        std::mem::take(&mut self.reverse_completed)
    }

    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.endpoint.set_local_busy(busy)
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        // The remote route has no bearing on the local XID exchange.
        Ok(())
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.endpoint.disconnect()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.endpoint.flush()
    }
}

#[cfg(test)]
mod completion_tests {
    use super::{
        converter_rejection_ready, exclusive_bind_ack, negative_user_bind_reply,
        publish_pending_converter_bind, queue_converter_bind, reverse_management_available,
        NativeLlcEvent,
    };
    use router_core::{fid2_session_control::ManagementBind, native_management::Phase};
    use std::collections::VecDeque;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rejected_user_bind_preserves_native_correlation_and_carries_sense() {
        let positive = hex("2f0002011234eb8000310000");
        let negative = negative_user_bind_reply(positive, [0x08, 0xa0, 0, 2]).unwrap();
        assert_eq!(negative, hex("2f0002011234eb900008a00002"));
        assert!(negative_user_bind_reply(hex("2f0002011234eb900031"), [0; 4]).is_err());
    }

    #[test]
    fn early_remote_close_waits_for_management_unbind_ack_before_rejecting_user_bind() {
        assert!(
            !converter_rejection_ready(true, false, false, false, Some(Phase::AwaitBisAck))
                .unwrap()
        );
        assert!(
            !converter_rejection_ready(true, false, false, false, Some(Phase::AwaitUnbindAck))
                .unwrap()
        );
        assert!(converter_rejection_ready(true, false, false, false, Some(Phase::Closed)).unwrap());
        assert!(
            converter_rejection_ready(false, false, false, false, Some(Phase::Closed)).is_err()
        );
    }

    #[test]
    fn untouched_passive_management_on_dialout_link_can_be_leased_for_reverse() {
        assert!(reverse_management_available(Some(Phase::AwaitBind), false));
        assert!(!reverse_management_available(Some(Phase::AwaitBind), true));
        assert!(!reverse_management_available(
            Some(Phase::AwaitBisAck),
            true
        ));
        assert!(reverse_management_available(Some(Phase::Closed), true));
    }

    fn bind_pair() -> (ManagementBind, Vec<u8>) {
        let management_piu = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601411111111111111110b1111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let user_piu = hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601422222222222222220b2222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        (
            ManagementBind::from_request(&management_piu, "SOLNET.SNAA", "SOLNET.SNAB").unwrap(),
            user_piu,
        )
    }

    #[test]
    fn user_bind_before_bis_ack_is_validated_once_and_published_after_both_acks() {
        let (management, piu) = bind_pair();
        let mut offer = None;
        let mut pending = false;
        let mut events = VecDeque::new();
        let mut wrong_session = piu.clone();
        wrong_session[2] = 1;
        assert!(queue_converter_bind(
            Phase::AwaitBisAck,
            &wrong_session,
            &management,
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            &mut offer,
            &mut pending,
            &mut events,
        )
        .is_err());
        assert!(offer.is_none());
        assert!(!pending);
        assert!(events.is_empty());
        queue_converter_bind(
            Phase::AwaitBisAck,
            &piu,
            &management,
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            &mut offer,
            &mut pending,
            &mut events,
        )
        .unwrap();
        assert!(pending);
        assert_eq!(offer.as_ref().unwrap().request(), piu);
        publish_pending_converter_bind(Phase::AwaitBisAck, &offer, &mut pending, &mut events)
            .unwrap(); // first BIS completion only
        assert!(events.is_empty());
        assert!(queue_converter_bind(
            Phase::AwaitBisAck,
            &piu,
            &management,
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            &mut offer,
            &mut pending,
            &mut events,
        )
        .is_err());
        publish_pending_converter_bind(Phase::BisComplete, &offer, &mut pending, &mut events)
            .unwrap();
        assert!(!pending);
        assert!(matches!(events.pop_front(), Some(NativeLlcEvent::UserBind(sent)) if sent == piu));
        publish_pending_converter_bind(Phase::BisComplete, &offer, &mut pending, &mut events)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn user_bind_after_management_unbind_is_published_immediately() {
        let (management, mut piu) = bind_pair();
        piu[2] = 1; // OS/400 can reuse the retired management DAF.
        let mut offer = None;
        let mut pending = false;
        let mut events = VecDeque::new();
        queue_converter_bind(
            Phase::Closed,
            &piu,
            &management,
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            &mut offer,
            &mut pending,
            &mut events,
        )
        .unwrap();
        assert!(!pending);
        assert_eq!(offer.as_ref().unwrap().request(), piu);
        assert!(matches!(events.pop_front(), Some(NativeLlcEvent::UserBind(sent)) if sent == piu));
        assert!(queue_converter_bind(
            Phase::Closed,
            &piu,
            &management,
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            &mut offer,
            &mut pending,
            &mut events,
        )
        .is_err());
    }

    #[test]
    fn bis_ack_coalesced_with_user_bind_publishes_immediately() {
        // NativePeerPort processes LLC completion counts before I-frame
        // events from the same poll. This is the resulting phase at dispatch.
        let (management, piu) = bind_pair();
        let mut offer = None;
        let mut pending = false;
        let mut events = VecDeque::new();
        queue_converter_bind(
            Phase::BisComplete,
            &piu,
            &management,
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            &mut offer,
            &mut pending,
            &mut events,
        )
        .unwrap();
        assert!(!pending);
        assert!(matches!(events.pop_front(), Some(NativeLlcEvent::UserBind(sent)) if sent == piu));
        assert!(events.is_empty());
    }

    #[test]
    fn converter_bind_ack_cannot_claim_another_frame_completion() {
        assert!(!exclusive_bind_ack(0).unwrap());
        assert!(exclusive_bind_ack(1).unwrap());
        assert!(exclusive_bind_ack(2).is_err());
    }
}
