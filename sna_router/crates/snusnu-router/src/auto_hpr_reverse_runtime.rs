//! One reverse SessionV1 circuit from a concentrator to an adjacent EE peer.
//!
//! The WebSocket circuit and HPR RTP connections share `SessionSwitch` with
//! guest-originated sessions. The first BIND is held as a leased fabric event
//! until RouteSetup and user RTP have actually carried it to the peer.

use std::{collections::VecDeque, io};

use router_core::{
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_route_setup_initiator::DirectLinkMetrics,
    hpr_rtp_outbound_setup::UserSetupConfig,
    hpr_session_adapter::{negotiated_fixed_windows, HprSessionRole},
    hpr_session_address::RtpObservation,
    session::{SessionEvent, SessionIdentity},
    session_fabric::AdapterId,
};

use crate::{
    auto_hpr_reverse::ReverseHprUser,
    auto_hpr_runtime::{from_session_wire, to_session_wire},
    ee_ldlc_endpoint::EeLdlcEndpoint,
    hpr_rtp_port::{HprRtpPort, RtpIngress, RtpIngressKind},
    hpr_session_source::{SessionSource, SourceUpdate},
    remote::{SessionWsPort, SessionWsUpdate},
    session_switch::{SessionSwitch, SwitchError, HPR_ADAPTER, WS_ADAPTER},
};

const MAX_EARLY_USER_BIUS: usize = 16;
const MAX_EARLY_USER_BYTES: usize = 64 * 1024;

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

fn switch_error(context: &str, error: SwitchError) -> io::Error {
    invalid(format!("{context}: {error:?}"))
}

struct WsSessionSource {
    port: SessionWsPort,
    pending: Option<SourceUpdate>,
}

impl WsSessionSource {
    fn new(port: SessionWsPort) -> Self {
        Self {
            port,
            pending: None,
        }
    }
}

impl SessionSource for WsSessionSource {
    fn poll(&mut self) -> io::Result<Option<SourceUpdate>> {
        if let Some(update) = &self.pending {
            return Ok(Some(update.clone()));
        }
        self.pending = match self.port.poll()? {
            Some(SessionWsUpdate::Event(wire)) => {
                Some(SourceUpdate::Event(from_session_wire(wire)?))
            }
            Some(SessionWsUpdate::Closed) => Some(SourceUpdate::Closed),
            Some(SessionWsUpdate::Opened) | None => None,
        };
        Ok(self.pending.clone())
    }

    fn complete_received(&mut self, charge: bool) -> io::Result<()> {
        if !matches!(self.pending, Some(SourceUpdate::Event(_))) {
            return Err(invalid("WebSocket source has no event to complete"));
        }
        if charge {
            self.port.complete_received(1)?;
        }
        self.pending = None;
        Ok(())
    }

    fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        let Some(wire) = to_session_wire(event) else {
            return Ok(true);
        };
        let sent = self.port.send(wire)?;
        let _ = self.port.take_completed_send_count();
        Ok(sent)
    }

    fn close(&mut self) -> io::Result<()> {
        self.port.close()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    AwaitBind,
    SendRoute,
    AwaitRoute,
    SendUser,
    AwaitUserCie,
    Active,
    Done,
}

pub(crate) struct ReverseRuntime {
    identity: SessionIdentity,
    source: Box<dyn SessionSource>,
    source_adapter: AdapterId,
    bootstrap: HprControlBootstrap,
    handle: u64,
    tg_number: u8,
    pcid: [u8; 8],
    local_user_nce_label: Vec<u8>,
    local_user_nce_instance: [u8; 4],
    metrics: DirectLinkMetrics,
    phase: Phase,
    reverse: Option<ReverseHprUser>,
    user_config: Option<UserSetupConfig>,
    pending_credit: Option<SessionEvent>,
    early_user: VecDeque<RtpIngress>,
    early_user_bytes: usize,
    source_closed: bool,
}

impl ReverseRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        identity: SessionIdentity,
        ws: SessionWsPort,
        bootstrap: HprControlBootstrap,
        handle: u64,
        tg_number: u8,
        pcid: [u8; 8],
        local_user_nce_label: Vec<u8>,
        local_user_nce_instance: [u8; 4],
        metrics: DirectLinkMetrics,
    ) -> Self {
        Self::with_source(
            identity,
            Box::new(WsSessionSource::new(ws)),
            WS_ADAPTER,
            bootstrap,
            handle,
            tg_number,
            pcid,
            local_user_nce_label,
            local_user_nce_instance,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_source(
        identity: SessionIdentity,
        source: Box<dyn SessionSource>,
        source_adapter: AdapterId,
        bootstrap: HprControlBootstrap,
        handle: u64,
        tg_number: u8,
        pcid: [u8; 8],
        local_user_nce_label: Vec<u8>,
        local_user_nce_instance: [u8; 4],
        metrics: DirectLinkMetrics,
    ) -> Self {
        Self {
            identity,
            source,
            source_adapter,
            bootstrap,
            handle,
            tg_number,
            pcid,
            local_user_nce_label,
            local_user_nce_instance,
            metrics,
            phase: Phase::AwaitBind,
            reverse: None,
            user_config: None,
            pending_credit: None,
            early_user: VecDeque::new(),
            early_user_bytes: 0,
            source_closed: false,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    pub(crate) fn route_reply_key(&self) -> Option<(router_core::ConnectionGeneration, [u8; 8])> {
        (self.phase == Phase::AwaitRoute).then_some((self.bootstrap.generation, self.pcid))
    }

    pub(crate) fn abort_route(&mut self, switch: &mut SessionSwitch) -> io::Result<()> {
        if self.phase != Phase::AwaitRoute {
            return Err(invalid("reverse HPR RouteSetup is not awaiting a reply"));
        }
        switch
            .discard_unopened(self.source_adapter, self.handle)
            .map_err(|error| switch_error("reverse HPR RouteSetup abort", error))?;
        self.phase = Phase::Done;
        self.source.close()?;
        self.source_closed = true;
        Ok(())
    }

    pub(crate) fn on_rtp(
        &mut self,
        message: RtpIngress,
        switch: &mut SessionSwitch,
    ) -> io::Result<()> {
        match message.kind {
            RtpIngressKind::RouteSetup | RtpIngressKind::RouteSetupOut
                if self.phase == Phase::AwaitRoute =>
            {
                let reverse = self
                    .reverse
                    .as_mut()
                    .ok_or_else(|| invalid("reverse HPR RouteSetup lacks BIND"))?;
                let config =
                    reverse.accept_route_reply(message.observation.generation, &message.bytes)?;
                self.user_config = Some(config);
                self.phase = Phase::SendUser;
                tracing::info!(handle = self.handle, source_lu = %self.identity.source_lu,
                    target_lu = %self.identity.target_lu, pcid = ?self.pcid,
                    "reverse HPR RouteSetup reply accepted");
                Ok(())
            }
            RtpIngressKind::UserOut if self.phase == Phase::AwaitUserCie => {
                if self.early_user.len() >= MAX_EARLY_USER_BIUS
                    || message.bytes.len() > MAX_EARLY_USER_BYTES - self.early_user_bytes
                {
                    return Err(invalid("reverse HPR early user BIU backlog full"));
                }
                self.early_user_bytes += message.bytes.len();
                self.early_user.push_back(message);
                Ok(())
            }
            RtpIngressKind::UserOut if self.phase == Phase::Active => {
                self.ingest_user(message.observation, &message.bytes, switch)
            }
            _ => Err(invalid("unexpected reverse HPR RTP message")),
        }
    }

    pub(crate) fn pump(
        &mut self,
        link: &EeLdlcEndpoint,
        rtp: &mut HprRtpPort,
        switch: &mut SessionSwitch,
        now_us: u64,
    ) -> io::Result<()> {
        if self.phase == Phase::Done {
            return self.finish(rtp);
        }
        self.poll_source(switch)?;
        if self.phase == Phase::Done {
            return self.finish(rtp);
        }
        if self.phase == Phase::SendRoute {
            let reverse = self.reverse.as_mut().unwrap();
            let request = reverse.route_request().to_vec();
            if rtp.open_route_out(link, &request, now_us)? {
                reverse.mark_route_sent(&request)?;
                self.phase = Phase::AwaitRoute;
                tracing::info!(handle = self.handle, source_lu = %self.identity.source_lu,
                    target_lu = %self.identity.target_lu, pcid = ?self.pcid,
                    "reverse HPR RouteSetup sent to EE peer");
            }
        }
        if self.phase == Phase::SendUser {
            let reverse = self.reverse.as_ref().unwrap();
            let route = self.user_config.as_ref().unwrap().clone();
            if rtp.open_user_out(link, reverse.initial_bind_fid5(), route, now_us)? {
                self.phase = Phase::AwaitUserCie;
                tracing::info!(handle = self.handle, target_lu = %self.identity.target_lu,
                    "reverse HPR user BIND sent to EE peer");
            }
        }
        if self.phase == Phase::AwaitUserCie {
            if let Some(scope) = rtp.user_out_scope() {
                self.reverse.as_mut().unwrap().activate_user(scope)?;
                let first = switch
                    .next_delivery(HPR_ADAPTER, self.handle)
                    .map_err(|error| switch_error("reverse HPR first BIND lease", error))?;
                if !matches!(first, Some(SessionEvent::BindRequest(_))) {
                    return Err(invalid("reverse HPR first fabric event is not BIND"));
                }
                switch
                    .mark_sent(HPR_ADAPTER, self.handle)
                    .map_err(|error| switch_error("reverse HPR first BIND completion", error))?;
                self.phase = Phase::Active;
                tracing::info!(handle = self.handle, source_lu = %self.identity.source_lu,
                    target_lu = %self.identity.target_lu, "reverse HPR user RTP active");
            }
        }
        while self.phase == Phase::Active {
            let Some(message) = self.early_user.front().cloned() else {
                break;
            };
            match self.ingest_user(message.observation, &message.bytes, switch) {
                Ok(()) => {
                    self.early_user.pop_front();
                    self.early_user_bytes -= message.bytes.len();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if self.phase == Phase::Active {
            self.deliver_hpr(link, rtp, switch, now_us)?;
        }
        if self.phase != Phase::Done {
            self.deliver_source(switch)?;
        }
        if self.phase != Phase::AwaitBind
            && !switch.has_handle(self.source_adapter, self.handle)
            && !switch.has_handle(HPR_ADAPTER, self.handle)
        {
            self.phase = Phase::Done;
        }
        if self.phase == Phase::Done {
            self.finish(rtp)?;
        }
        Ok(())
    }

    fn finish(&mut self, rtp: &mut HprRtpPort) -> io::Result<()> {
        rtp.reset_route_out();
        rtp.reset_user_out();
        if !self.source_closed {
            self.source.close()?;
            self.source_closed = true;
        }
        Ok(())
    }

    fn poll_source(&mut self, switch: &mut SessionSwitch) -> io::Result<()> {
        if self.source_closed {
            return Ok(());
        }
        let Some(update) = self.source.poll()? else {
            return Ok(());
        };
        let event = match update {
            SourceUpdate::Event(event) => event,
            SourceUpdate::Closed => {
                self.source_closed = true;
                match self.phase {
                    Phase::AwaitBind => self.phase = Phase::Done,
                    Phase::Active => {
                        switch
                            .submit(self.source_adapter, self.handle, SessionEvent::Reset)
                            .map_err(|error| switch_error("reverse HPR source close", error))?;
                    }
                    Phase::Done => {}
                    _ => {
                        switch
                            .discard_unopened(self.source_adapter, self.handle)
                            .map_err(|error| switch_error("reverse HPR source close", error))?;
                        self.phase = Phase::Done;
                    }
                }
                return Ok(());
            }
        };
        let charge = !matches!(event, SessionEvent::Credit { .. });
        if self.phase == Phase::AwaitBind {
            let SessionEvent::BindRequest(bind) = event else {
                return Err(invalid("reverse HPR circuit must start with BIND"));
            };
            let local_sa = (1u64 << 63) | self.handle;
            let reverse = ReverseHprUser::new(
                self.bootstrap.clone(),
                self.identity.clone(),
                bind.clone(),
                self.tg_number,
                self.pcid,
                self.local_user_nce_label.clone(),
                self.local_user_nce_instance,
                local_sa,
                self.metrics,
            )?;
            let (id, egress) = switch
                .open(
                    self.source_adapter,
                    self.handle,
                    self.identity.clone(),
                    bind,
                )
                .map_err(|error| switch_error("reverse HPR route selection", error))?;
            if egress != HPR_ADAPTER {
                return Err(invalid("reverse HPR selected non-EE egress"));
            }
            switch
                .bind_egress(id, HPR_ADAPTER, self.handle)
                .map_err(|error| switch_error("reverse HPR egress bind", error))?;
            self.reverse = Some(reverse);
            self.phase = Phase::SendRoute;
            self.source.complete_received(charge)?;
            tracing::info!(handle = self.handle, source_lu = %self.identity.source_lu,
                target_lu = %self.identity.target_lu,
                "reverse HPR BIND received from session source");
            return Ok(());
        }
        match switch.submit(self.source_adapter, self.handle, event) {
            Ok(()) => {
                self.source.complete_received(charge)?;
            }
            Err(SwitchError::Fabric(router_core::session_fabric::FabricError::Capacity)) => {}
            Err(error) => return Err(switch_error("reverse HPR source event", error)),
        }
        Ok(())
    }

    fn ingest_user(
        &mut self,
        observation: RtpObservation,
        bytes: &[u8],
        switch: &mut SessionSwitch,
    ) -> io::Result<()> {
        if let Some(credit) = self.pending_credit.take() {
            if let Err(error) = switch.submit(HPR_ADAPTER, self.handle, credit.clone()) {
                self.pending_credit = Some(credit);
                if matches!(
                    error,
                    SwitchError::Fabric(router_core::session_fabric::FabricError::Capacity)
                ) {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "HPR credit backlog",
                    ));
                }
                return Err(switch_error("reverse HPR credit", error));
            }
        }
        let reverse = self.reverse.as_mut().unwrap();
        let (mut candidate, ingress) = reverse.preview_hpr_message(observation, bytes)?;
        if let SessionEvent::BindResult {
            accepted: true,
            ref unit,
        } = ingress.event
        {
            let (send, receive) =
                negotiated_fixed_windows(HprSessionRole::RouterPlu, reverse.bind_request(), unit)
                    .map_err(|error| invalid(format!("reverse HPR BIND pacing: {error:?}")))?;
            candidate
                .configure_fixed_pacing(send, receive)
                .map_err(|error| invalid(format!("reverse HPR pacing setup: {error:?}")))?;
        }
        match switch.submit(HPR_ADAPTER, self.handle, ingress.event) {
            Ok(()) => reverse.commit_adapter(candidate),
            Err(SwitchError::Fabric(router_core::session_fabric::FabricError::Capacity)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "HPR fabric backpressure",
                ));
            }
            Err(error) => return Err(switch_error("reverse HPR peer event", error)),
        }
        if let Some(credit) = ingress.extra_credit {
            match switch.submit(HPR_ADAPTER, self.handle, credit.clone()) {
                Ok(()) => {}
                Err(SwitchError::Fabric(router_core::session_fabric::FabricError::Capacity)) => {
                    self.pending_credit = Some(credit)
                }
                Err(error) => return Err(switch_error("reverse HPR additional credit", error)),
            }
        }
        Ok(())
    }

    fn deliver_hpr(
        &mut self,
        link: &EeLdlcEndpoint,
        rtp: &mut HprRtpPort,
        switch: &mut SessionSwitch,
        now_us: u64,
    ) -> io::Result<()> {
        let event = match switch.next_delivery(HPR_ADAPTER, self.handle) {
            Ok(event) => event,
            Err(SwitchError::UnknownHandle) => {
                self.phase = Phase::Done;
                return Ok(());
            }
            Err(error) => return Err(switch_error("reverse HPR delivery", error)),
        };
        let Some(event) = event else {
            return Ok(());
        };
        let reset = matches!(event, SessionEvent::Reset);
        let reverse = self.reverse.as_mut().unwrap();
        let (candidate, egress) = reverse.preview_ws_event(event)?;
        let sent = match egress {
            Some(egress) => rtp.send_user_out(link, &egress.message, now_us)?,
            None => true,
        };
        if sent {
            reverse.commit_adapter(candidate);
            if reset {
                // A closed upstream before RSP(BIND) must not leave a live
                // outbound user RTP holding the guest's pending BIND.
                rtp.reset_user_out();
            }
            switch
                .mark_sent(HPR_ADAPTER, self.handle)
                .map_err(|error| switch_error("reverse HPR delivery completion", error))?;
        }
        Ok(())
    }

    fn deliver_source(&mut self, switch: &mut SessionSwitch) -> io::Result<()> {
        if self.phase == Phase::AwaitBind {
            return Ok(());
        }
        let event = match switch.next_delivery(self.source_adapter, self.handle) {
            Ok(event) => event,
            Err(SwitchError::UnknownHandle) => {
                self.phase = Phase::Done;
                return Ok(());
            }
            Err(error) => return Err(switch_error("reverse HPR source delivery", error)),
        };
        let Some(event) = event else {
            return Ok(());
        };
        if self.source_closed {
            switch
                .mark_sent(self.source_adapter, self.handle)
                .map_err(|error| switch_error("reverse HPR closed source completion", error))?;
            self.phase = Phase::Done;
            return Ok(());
        }
        if self.source.send(&event)? {
            switch
                .mark_sent(self.source_adapter, self.handle)
                .map_err(|error| switch_error("reverse HPR source completion", error))?;
            if matches!(event, SessionEvent::Reset) {
                self.source.close()?;
                self.source_closed = true;
                self.phase = Phase::Done;
            }
        }
        Ok(())
    }
}
