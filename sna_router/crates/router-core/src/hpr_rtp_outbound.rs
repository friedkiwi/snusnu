//! One locally originated CP management RTP connection on an active EE TG.
//! The reciprocal guest connection has independent TCIDs, windows and timers.

use crate::{
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_rtp::RtpPacket,
    hpr_rtp_endpoint::{
        encode_data_nlp, encode_status_nlp, BaseArb, EndpointError, EndpointPath, EndpointReceive,
    },
    hpr_rtp_message::OrderedMessageAssembler,
    hpr_rtp_outbound_setup::{
        encode_cp_setup, encode_route_setup_setup, encode_user_setup, UserSetupConfig,
    },
    hpr_rtp_receive::{ReceiveResult, ReliableReceiveWindow},
    hpr_rtp_send::{parse_peer_status, ReliableSendWindow, SendError},
    ConnectionGeneration,
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const RETRANSMIT_US: u64 = 250_000;
const MAX_WINDOW: usize = 1_048_576;
const MAX_MESSAGE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundPhase {
    Idle,
    AwaitReply,
    AwaitStatusSent,
    Active,
}

pub struct RtpOutboundEndpoint {
    bootstrap: HprControlBootstrap,
    tg_number: u8,
    origin_tcid: u64,
    peer_tcid: Option<u64>,
    path: EndpointPath,
    local_nce_label: Vec<u8>,
    user_setup: Option<UserSetupConfig>,
    route_setup: bool,
    phase: OutboundPhase,
    setup_nlp: Option<Vec<u8>>,
    setup_last_sent_us: Option<u64>,
    setup_next_bsn: u32,
    pending_status: Option<Vec<u8>>,
    sent_initial_status: Option<Vec<u8>>,
    pending_data: Option<Vec<u8>>,
    pending_retransmission: Option<Vec<u8>>,
    pre_status_nlps: Vec<Vec<u8>>,
    receive: Option<ReliableReceiveWindow>,
    send: Option<ReliableSendWindow>,
    assembly: OrderedMessageAssembler,
    arb: Option<BaseArb>,
    next_sync: u16,
    last_peer_sync: u16,
    last_retransmit_us: Option<u64>,
}

impl RtpOutboundEndpoint {
    pub fn new(
        bootstrap: HprControlBootstrap,
        tg_number: u8,
        origin_tcid: u64,
    ) -> Result<Self, EndpointError> {
        if tg_number == 0 || origin_tcid & (ASSIGNOR | RESERVED) != ASSIGNOR {
            return Err(EndpointError::InvalidConfig);
        }
        let path = EndpointPath {
            peer_anr_label: bootstrap.peer.tower.cp_nce_label.clone(),
            priority: 3,
        };
        let local_nce_label = bootstrap.local.tower.cp_nce_label.clone();
        Ok(Self {
            bootstrap,
            tg_number,
            origin_tcid,
            peer_tcid: None,
            path,
            local_nce_label,
            user_setup: None,
            route_setup: false,
            phase: OutboundPhase::Idle,
            setup_nlp: None,
            setup_last_sent_us: None,
            setup_next_bsn: 0,
            pending_status: None,
            sent_initial_status: None,
            pending_data: None,
            pending_retransmission: None,
            pre_status_nlps: Vec::new(),
            receive: None,
            send: None,
            assembly: OrderedMessageAssembler::new(MAX_MESSAGE).map_err(EndpointError::Assembly)?,
            arb: None,
            next_sync: 1,
            last_peer_sync: 0,
            last_retransmit_us: None,
        })
    }

    /// Create a user RTP connection only after a validated RouteSetup reply
    /// has supplied both directional user NCEs and the selected COS/TPF.
    pub fn new_user(
        bootstrap: HprControlBootstrap,
        tg_number: u8,
        origin_tcid: u64,
        config: UserSetupConfig,
    ) -> Result<Self, EndpointError> {
        let priority = config
            .priority()
            .map_err(|_| EndpointError::InvalidConfig)?;
        let mut endpoint = Self::new(bootstrap, tg_number, origin_tcid)?;
        endpoint.path = EndpointPath {
            peer_anr_label: config.peer_nce_label.clone(),
            priority,
        };
        endpoint.local_nce_label = config.local_nce_label.clone();
        endpoint.user_setup = Some(config);
        Ok(endpoint)
    }

    /// Create the RouteSetup RTP connection to the adjacent peer's control
    /// tower. Its first message is a RouteSetup GDS rather than a FID5 BIND.
    pub fn new_route_setup(
        bootstrap: HprControlBootstrap,
        tg_number: u8,
        origin_tcid: u64,
    ) -> Result<Self, EndpointError> {
        let mut endpoint = Self::new(bootstrap, tg_number, origin_tcid)?;
        endpoint.path.peer_anr_label = endpoint.bootstrap.peer.tower.route_setup_nce_label.clone();
        endpoint.local_nce_label = endpoint.bootstrap.local.tower.route_setup_nce_label.clone();
        endpoint.route_setup = true;
        Ok(endpoint)
    }

    pub fn phase(&self) -> OutboundPhase {
        self.phase
    }

    pub fn generation(&self) -> ConnectionGeneration {
        self.bootstrap.generation
    }

    pub fn origin_tcid(&self) -> u64 {
        self.origin_tcid
    }

    pub fn peer_assigned_tcid(&self) -> Option<u64> {
        self.peer_tcid
    }

    pub fn priority(&self) -> u8 {
        self.path.priority
    }

    pub fn prepare_setup(&mut self, first_biu: &[u8]) -> Result<Vec<u8>, EndpointError> {
        if self.phase != OutboundPhase::Idle || self.setup_nlp.is_some() {
            return Err(EndpointError::WrongPhase);
        }
        let nlp = match (self.route_setup, self.user_setup.as_ref()) {
            (true, _) => encode_route_setup_setup(
                &self.bootstrap,
                self.tg_number,
                self.origin_tcid,
                first_biu,
            ),
            (false, Some(config)) => encode_user_setup(
                &self.bootstrap,
                self.tg_number,
                self.origin_tcid,
                first_biu,
                config,
            ),
            (false, None) => {
                encode_cp_setup(&self.bootstrap, self.tg_number, self.origin_tcid, first_biu)
            }
        }
        .map_err(|_| EndpointError::InvalidConfig)?;
        if nlp.len() > usize::from(self.bootstrap.max_packet_size) || first_biu.len() > MAX_MESSAGE
        {
            return Err(EndpointError::TooLarge);
        }
        let packet = RtpPacket::parse(&nlp).map_err(EndpointError::InvalidRtp)?;
        let segment = packet
            .optional_segments()
            .map_err(EndpointError::InvalidRtp)?
            .into_iter()
            .find(|segment| segment.key == 0x22)
            .ok_or(EndpointError::InvalidArb)?;
        self.arb = Some(BaseArb::from_setup(segment)?);
        self.setup_next_bsn = packet.next_byte_sequence_number();
        self.setup_nlp = Some(nlp.clone());
        Ok(nlp)
    }

    pub fn pending_setup_nlp(&self) -> Option<&[u8]> {
        (self.phase == OutboundPhase::Idle)
            .then_some(self.setup_nlp.as_deref())
            .flatten()
    }

    pub fn confirm_setup_sent(&mut self, nlp: &[u8], now_us: u64) -> Result<(), EndpointError> {
        if self.phase != OutboundPhase::Idle || self.setup_nlp.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.phase = OutboundPhase::AwaitReply;
        self.setup_last_sent_us = Some(now_us);
        Ok(())
    }

    pub fn setup_retransmit_due(&self, now_us: u64) -> Result<Option<&[u8]>, EndpointError> {
        if self.phase != OutboundPhase::AwaitReply {
            return Ok(None);
        }
        let last = self.setup_last_sent_us.ok_or(EndpointError::WrongPhase)?;
        if now_us < last {
            return Err(EndpointError::ClockMovedBackwards);
        }
        Ok((now_us - last >= RETRANSMIT_US)
            .then_some(self.setup_nlp.as_deref())
            .flatten())
    }

    pub fn confirm_setup_retransmitted(
        &mut self,
        nlp: &[u8],
        now_us: u64,
    ) -> Result<(), EndpointError> {
        if self.phase != OutboundPhase::AwaitReply || self.setup_nlp.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.setup_last_sent_us = Some(now_us);
        Ok(())
    }

    /// Validate the peer's unqualified STATUS+CIE. The caller sends the
    /// returned STATUS echo on the same authenticated EE adjacency, then
    /// confirms that send before using the connection for later CP BIUs.
    pub fn prepare_reply_status(&mut self, nlp: &[u8]) -> Result<Vec<u8>, EndpointError> {
        if self.phase == OutboundPhase::AwaitStatusSent {
            return self.pending_status.clone().ok_or(EndpointError::WrongPhase);
        }
        if self.phase != OutboundPhase::AwaitReply {
            return Err(EndpointError::WrongPhase);
        }
        let packet = RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?;
        if packet.tcid != self.origin_tcid & !ASSIGNOR
            || packet.nhdr.len() < 5
            || packet.nhdr[2..packet.nhdr.len() - 2] != self.local_nce_label
            || (packet.nhdr[0] >> 1) & 3 != self.path.priority
            || !packet.data.is_empty()
        {
            return Err(EndpointError::WrongPeer);
        }
        let segments = packet
            .optional_segments()
            .map_err(EndpointError::InvalidRtp)?;
        if segments
            .iter()
            .filter(|segment| segment.key == 0x0e)
            .count()
            != 1
            || segments
                .iter()
                .filter(|segment| segment.key == 0x10)
                .count()
                != 1
            || segments
                .iter()
                .filter(|segment| segment.key == 0x22)
                .count()
                > 1
            || segments
                .iter()
                .any(|segment| !matches!(segment.key, 0x0e | 0x10 | 0x22))
        {
            return Err(EndpointError::UnsupportedSegment);
        }
        let status = parse_peer_status(packet).map_err(EndpointError::Send)?;
        if status.rseq != self.setup_next_bsn || !status.spans.is_empty() || status.echo != 0 {
            return Err(EndpointError::Send(SendError::InvalidStatus));
        }
        let assigned = packet
            .connection_identifier_exchange()
            .map_err(EndpointError::InvalidRtp)?
            .ok_or(EndpointError::WrongPeer)?;
        if assigned & (ASSIGNOR | RESERVED) != ASSIGNOR {
            return Err(EndpointError::WrongPeer);
        }
        let mut arb = self.arb.unwrap();
        if let Some(segment) = segments.iter().find(|segment| segment.key == 0x22) {
            arb.observe(*segment)?;
        }
        let receive = ReliableReceiveWindow::new(
            self.bootstrap.generation,
            self.origin_tcid & !ASSIGNOR,
            packet.next_byte_sequence_number(),
            MAX_WINDOW,
        )
        .map_err(EndpointError::Receive)?;
        let mut send = ReliableSendWindow::new(
            self.bootstrap.generation,
            assigned & !ASSIGNOR,
            self.origin_tcid & !ASSIGNOR,
            self.setup_next_bsn,
            MAX_WINDOW,
        )
        .map_err(EndpointError::Send)?;
        send.observe_status(self.bootstrap.generation, packet)
            .map_err(EndpointError::Send)?;
        let reply = encode_status_nlp(
            assigned & !ASSIGNOR,
            &self.path,
            self.next_sync,
            status.sync,
            self.setup_next_bsn,
            &receive.status(),
            false,
        )?;
        self.peer_tcid = Some(assigned & !ASSIGNOR);
        self.receive = Some(receive);
        self.send = Some(send);
        self.last_peer_sync = status.sync;
        self.arb = Some(arb);
        self.pending_status = Some(reply.clone());
        self.phase = OutboundPhase::AwaitStatusSent;
        Ok(reply)
    }

    pub fn pending_status_nlp(&self) -> Option<&[u8]> {
        self.pending_status.as_deref()
    }

    /// The peer may send its BIND response before its setup STATUS+CIE. Keep
    /// such NLPs bounded and process them only after the CIE is validated and
    /// our reciprocal STATUS has reached the EE socket.
    pub fn buffer_before_reply(&mut self, nlp: &[u8]) -> Result<(), EndpointError> {
        if self.phase != OutboundPhase::AwaitReply {
            return Err(EndpointError::WrongPhase);
        }
        let packet = RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?;
        if packet.tcid != self.origin_tcid & !ASSIGNOR
            || packet.nhdr.len() < 5
            || packet.nhdr[2..packet.nhdr.len() - 2] != self.local_nce_label
            || (packet.nhdr[0] >> 1) & 3 != self.path.priority
            || packet
                .connection_identifier_exchange()
                .map_err(EndpointError::InvalidRtp)?
                .is_some()
        {
            return Err(EndpointError::WrongPeer);
        }
        if self.pre_status_nlps.iter().any(|previous| previous == nlp) {
            return Ok(());
        }
        let retained = self.pre_status_nlps.iter().map(Vec::len).sum::<usize>();
        if retained
            .checked_add(nlp.len())
            .is_none_or(|size| size > MAX_WINDOW)
        {
            return Err(EndpointError::TooLarge);
        }
        self.pre_status_nlps.push(nlp.to_vec());
        Ok(())
    }

    pub fn take_pre_status_nlps(&mut self) -> Vec<Vec<u8>> {
        if self.phase == OutboundPhase::Active {
            std::mem::take(&mut self.pre_status_nlps)
        } else {
            Vec::new()
        }
    }

    pub fn confirm_status_sent(&mut self, nlp: &[u8]) -> Result<(), EndpointError> {
        if self.pending_status.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.send
            .as_mut()
            .unwrap()
            .record_local_sync(self.bootstrap.generation, self.next_sync)
            .map_err(EndpointError::Send)?;
        self.next_sync = self.next_sync.wrapping_add(1);
        self.pending_status = None;
        if self.phase == OutboundPhase::AwaitStatusSent {
            self.sent_initial_status = Some(nlp.to_vec());
            self.phase = OutboundPhase::Active;
        }
        Ok(())
    }

    pub fn reply_to_duplicate_cie(&self, nlp: &[u8]) -> Option<&[u8]> {
        if self.phase != OutboundPhase::Active {
            return None;
        }
        let packet = RtpPacket::parse(nlp).ok()?;
        (packet.tcid == self.origin_tcid & !ASSIGNOR
            && packet.nhdr.len() >= 5
            && packet.nhdr[2..packet.nhdr.len() - 2] == self.local_nce_label
            && (packet.nhdr[0] >> 1) & 3 == self.path.priority
            && packet.data.is_empty()
            && packet.connection_identifier_exchange().ok().flatten()
                == self.peer_tcid.map(|id| id | ASSIGNOR))
        .then_some(self.sent_initial_status.as_deref())
        .flatten()
    }

    pub fn receive(&mut self, nlp: &[u8]) -> Result<EndpointReceive, EndpointError> {
        if self.phase != OutboundPhase::Active {
            return Err(EndpointError::WrongPhase);
        }
        let packet = RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?;
        if packet.tcid != self.origin_tcid & !ASSIGNOR
            || packet.nhdr.len() < 5
            || packet.nhdr[2..packet.nhdr.len() - 2] != self.local_nce_label
            || (packet.nhdr[0] >> 1) & 3 != self.path.priority
        {
            return Err(EndpointError::WrongPeer);
        }
        let segments = packet
            .optional_segments()
            .map_err(EndpointError::InvalidRtp)?;
        if segments
            .iter()
            .any(|s| !matches!(s.key, 0x0e | 0x10 | 0x22))
            || packet
                .connection_identifier_exchange()
                .map_err(EndpointError::InvalidRtp)?
                .is_some_and(|tcid| Some(tcid & !ASSIGNOR) != self.peer_tcid)
        {
            return Err(EndpointError::UnsupportedSegment);
        }
        let mut arb = self.arb.unwrap();
        for segment in segments.iter().filter(|segment| segment.key == 0x22) {
            arb.observe(*segment)?;
        }
        let mut send = self.send.as_ref().unwrap().clone();
        let has_status = segments.iter().any(|segment| segment.key == 0x0e);
        let status = if has_status {
            match send.observe_status(self.bootstrap.generation, packet) {
                Ok(effect) => Some(effect),
                Err(SendError::DuplicateStatus) => None,
                Err(error) => return Err(EndpointError::Send(error)),
            }
        } else {
            None
        };
        let mut receive = self.receive.as_ref().unwrap().clone();
        let delivered = receive
            .observe(self.bootstrap.generation, packet)
            .map_err(EndpointError::Receive)?;
        let status_due = match &delivered {
            ReceiveResult::Buffered => true,
            ReceiveResult::Delivered(fragments) => fragments
                .iter()
                .any(|fragment| !fragment.data.is_empty() || fragment.end_of_message),
            ReceiveResult::Duplicate => false,
        };
        let mut assembly = self.assembly.clone();
        let messages = match delivered {
            ReceiveResult::Delivered(fragments) => assembly
                .observe(&fragments)
                .map_err(EndpointError::Assembly)?,
            ReceiveResult::Buffered | ReceiveResult::Duplicate => Vec::new(),
        };
        let peer_sync = has_status
            .then(|| parse_peer_status(packet).map_err(EndpointError::Send))
            .transpose()?
            .map(|status| status.sync);
        self.send = Some(send);
        self.receive = Some(receive);
        self.assembly = assembly;
        self.arb = Some(arb);
        if self.pending_retransmission.as_deref()
            != self.send.as_ref().unwrap().oldest_retained_nlp()
        {
            self.pending_retransmission = None;
        }
        if let Some(sync) = peer_sync {
            self.last_peer_sync = sync;
        }
        Ok(EndpointReceive {
            generation: self.bootstrap.generation,
            inbound_tcid: packet.tcid,
            messages,
            retransmit_nlps: status.map_or_else(Vec::new, |effect| effect.retransmit_nlps),
            status_due,
        })
    }

    pub fn prepare_status(&mut self) -> Result<Vec<u8>, EndpointError> {
        if self.phase != OutboundPhase::Active || self.pending_status.is_some() {
            return Err(EndpointError::WrongPhase);
        }
        let nlp = encode_status_nlp(
            self.peer_tcid.unwrap(),
            &self.path,
            self.next_sync,
            self.last_peer_sync,
            self.send.as_ref().unwrap().next_bsn(),
            &self.receive.as_ref().unwrap().status(),
            false,
        )?;
        self.pending_status = Some(nlp.clone());
        Ok(nlp)
    }

    pub fn prepare_message(
        &mut self,
        message: &[u8],
        now_us: u64,
    ) -> Result<Vec<u8>, EndpointError> {
        if self.phase != OutboundPhase::Active || self.pending_data.is_some() {
            return Err(EndpointError::WrongPhase);
        }
        self.arb.unwrap().check_send_time(now_us)?;
        if message.is_empty() || message.len() + 38 > usize::from(self.bootstrap.max_packet_size) {
            return Err(EndpointError::TooLarge);
        }
        let nlp = encode_data_nlp(
            self.peer_tcid.unwrap(),
            &self.path,
            self.send.as_ref().unwrap().next_bsn(),
            message,
            self.arb.unwrap().measurement_us(now_us),
            None,
        )?;
        let mut preview = self.send.as_ref().unwrap().clone();
        preview
            .record_transmitted(
                self.bootstrap.generation,
                RtpPacket::parse(&nlp).map_err(EndpointError::InvalidRtp)?,
            )
            .map_err(EndpointError::Send)?;
        self.pending_data = Some(nlp.clone());
        Ok(nlp)
    }

    pub fn cancel_unsent_message(&mut self, nlp: &[u8]) -> Result<(), EndpointError> {
        if self.pending_data.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.pending_data = None;
        Ok(())
    }

    pub fn confirm_message_sent(&mut self, nlp: &[u8], now_us: u64) -> Result<(), EndpointError> {
        if self.pending_data.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.arb.unwrap().check_send_time(now_us)?;
        self.send
            .as_mut()
            .unwrap()
            .record_transmitted(
                self.bootstrap.generation,
                RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?,
            )
            .map_err(EndpointError::Send)?;
        self.arb.as_mut().unwrap().sent(now_us, nlp.len())?;
        self.pending_data = None;
        Ok(())
    }

    pub fn pending_retransmission_nlp(&self) -> Option<&[u8]> {
        self.pending_retransmission.as_deref()
    }

    pub fn retransmit_due(&mut self, now_us: u64) -> Result<Option<Vec<u8>>, EndpointError> {
        if self.phase != OutboundPhase::Active || self.pending_retransmission.is_some() {
            return Ok(None);
        }
        let Some(nlp) = self.send.as_ref().unwrap().oldest_retained_nlp() else {
            return Ok(None);
        };
        let last = self
            .last_retransmit_us
            .unwrap_or(0)
            .max(self.arb.unwrap().last_sent_us());
        if now_us < last {
            return Err(EndpointError::ClockMovedBackwards);
        }
        if now_us - last < RETRANSMIT_US {
            return Ok(None);
        }
        match self.arb.unwrap().check_send_time(now_us) {
            Ok(()) => {}
            Err(EndpointError::RateLimited) => return Ok(None),
            Err(error) => return Err(error),
        }
        let nlp = nlp.to_vec();
        self.pending_retransmission = Some(nlp.clone());
        Ok(Some(nlp))
    }

    pub fn confirm_retransmission_sent(
        &mut self,
        nlp: &[u8],
        now_us: u64,
    ) -> Result<(), EndpointError> {
        if self.pending_retransmission.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.arb.as_mut().unwrap().sent(now_us, nlp.len())?;
        self.last_retransmit_us = Some(now_us);
        self.pending_retransmission = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::{encode_network_name_component, ControlAdvertisement},
        hpr_cp_initiator::ReciprocalCpSession,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        hpr_fid5::encode_whole_biu,
        hpr_rtp_reply::{encode_setup_reply, CallerStatus, ReplyPath},
        session::{Flow, QualifiedName, SessionUnit},
    };

    const ORIGIN: u64 = ASSIGNOR | 0x1234;
    const PEER_ASSIGNED: u64 = ASSIGNOR | 0x5678;

    fn advertisement(cp: &str, node: u8, link: &[u8], nce: &[u8]) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse::<QualifiedName>().unwrap(),
            node_id: [0, 0, 0, node],
            hpr_sap: 4,
            link_label: link.to_vec(),
            tower: ControlFlowsTower {
                max_send_packet_size: 1461,
                path_switch_time_ms: 60_000,
                mobile: false,
                multilink_tg: false,
                arb_mode: ArbMode::Base,
                cp_nce_instance: [0, 0, 0, node],
                route_setup_nce_instance: [0, 0, 0, node],
                cp_nce_label: nce.to_vec(),
                route_setup_nce_label: nce.to_vec(),
            },
        }
    }

    fn fixture() -> (RtpOutboundEndpoint, Vec<u8>) {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", 2, &[0x80, 0x80], &[0xa4, 0x80]),
            advertisement("SOLNET.SNAB", 1, &[0x80, 2], &[0xa4, 0]),
        )
        .unwrap();
        let cp = ReciprocalCpSession::new(bootstrap.clone(), 0x0102_0304_0506_0708).unwrap();
        let bind = cp.prepare_bind().unwrap().to_vec();
        (
            RtpOutboundEndpoint::new(bootstrap, 1, ORIGIN).unwrap(),
            bind,
        )
    }

    fn user_fixture() -> (RtpOutboundEndpoint, Vec<u8>) {
        let bootstrap = HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            advertisement("SNUSNU.SVC", 2, &[0x80, 0x80], &[0xa4, 0x80]),
            advertisement("SOLNET.SNAB", 1, &[0x80, 2], &[0xa4, 0]),
        )
        .unwrap();
        let config = UserSetupConfig {
            local_nce_label: vec![0xa4, 0x81],
            local_nce_instance: [0, 0, 0, 2],
            peer_nce_label: vec![0xa4, 1],
            peer_nce_instance: [0, 0, 0, 1],
            peer_link_label: vec![0x80, 2],
            cos_tpf: vec![
                0x0c, 0x2c, 1, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
            ],
            target_lu: "SOLNET.SNAB".into(),
        };
        let encode_name = |netid: &str, name: &str| {
            let mut result = encode_network_name_component(netid).unwrap();
            result.push(0x4b);
            result.extend_from_slice(&encode_network_name_component(name).unwrap());
            result
        };
        let plu = encode_name("QAALICE", "PING");
        let slu = encode_name("SOLNET", "SNAB");
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        ru.push(plu.len() as u8);
        ru.extend_from_slice(&plu);
        ru.extend_from_slice(&[1, 0, 0]);
        ru.push(slu.len() as u8);
        ru.extend_from_slice(&slu);
        let mut reduced = vec![0x80, 1, 0x6b, 0x80, 0];
        reduced.extend_from_slice(&ru);
        let bind = encode_whole_biu(
            (ASSIGNOR | 0x3456).to_be_bytes(),
            Flow::Expedited,
            &SessionUnit::from_reduced(&reduced).unwrap(),
        )
        .unwrap();
        (
            RtpOutboundEndpoint::new_user(bootstrap, 1, ORIGIN, config).unwrap(),
            bind,
        )
    }

    fn peer_reply(rseq: u32) -> Vec<u8> {
        encode_setup_reply(
            ORIGIN,
            PEER_ASSIGNED,
            ReplyPath {
                anr_label: &[0xa4, 0x80],
                priority: 3,
            },
            CallerStatus {
                sync: 0,
                echo: 0,
                rseq,
                outbound_bsn: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn user_setup_accepts_only_its_route_priority_and_nce() {
        let (mut endpoint, bind) = user_fixture();
        let setup = endpoint.prepare_setup(&bind).unwrap();
        assert_eq!(endpoint.priority(), 1);
        assert_eq!(&setup[..4], &[0xc2, 8, 0xa4, 1]);
        endpoint.confirm_setup_sent(&setup, 10_000).unwrap();
        let rseq = RtpPacket::parse(&setup)
            .unwrap()
            .next_byte_sequence_number();
        let make_reply = |priority| {
            encode_setup_reply(
                ORIGIN,
                PEER_ASSIGNED,
                ReplyPath {
                    anr_label: &[0xa4, 0x81],
                    priority,
                },
                CallerStatus {
                    sync: 0,
                    echo: 0,
                    rseq,
                    outbound_bsn: 0,
                },
            )
            .unwrap()
        };
        assert_eq!(
            endpoint.prepare_reply_status(&make_reply(3)),
            Err(EndpointError::WrongPeer)
        );
        let status = endpoint.prepare_reply_status(&make_reply(1)).unwrap();
        assert_eq!(&status[..4], &[0xc2, 8, 0xa4, 1]);
        endpoint.confirm_status_sent(&status).unwrap();
        assert_eq!(endpoint.phase(), OutboundPhase::Active);
    }

    fn peer_data(data: &[u8]) -> Vec<u8> {
        let mut nlp = vec![0xc6, 0, 0xa4, 0x80, 0xff, 0];
        nlp.extend_from_slice(&(ORIGIN & !ASSIGNOR).to_be_bytes());
        nlp.extend_from_slice(&[0x30, 0, 0, 5]);
        nlp.extend_from_slice(&(data.len() as u32).to_be_bytes());
        nlp.extend_from_slice(&0u32.to_be_bytes());
        nlp.extend_from_slice(data);
        nlp
    }

    fn peer_data_with_cie(data: &[u8]) -> Vec<u8> {
        let mut nlp = vec![0xc6, 8, 0xa4, 0x80, 0xff, 0];
        nlp.extend_from_slice(&(ORIGIN & !ASSIGNOR).to_be_bytes());
        nlp.extend_from_slice(&[0x3c, 4, 0, 8]);
        nlp.extend_from_slice(&(data.len() as u32).to_be_bytes());
        nlp.extend_from_slice(&0u32.to_be_bytes());
        nlp.extend_from_slice(&[3, 0x10, 0, 0]);
        nlp.extend_from_slice(&PEER_ASSIGNED.to_be_bytes());
        nlp.extend_from_slice(data);
        nlp
    }

    #[test]
    fn setup_reply_status_and_early_bind_response_are_ordered() {
        let (mut endpoint, bind) = fixture();
        let setup = endpoint.prepare_setup(&bind).unwrap();
        assert_eq!(RtpPacket::parse(&setup).unwrap().tcid, ORIGIN);
        endpoint.confirm_setup_sent(&setup, 10_000).unwrap();
        assert_eq!(endpoint.phase(), OutboundPhase::AwaitReply);
        assert_eq!(endpoint.setup_retransmit_due(259_999).unwrap(), None);
        assert_eq!(
            endpoint.setup_retransmit_due(260_000).unwrap(),
            Some(setup.as_slice())
        );
        let early = peer_data(b"BIND-RSP");
        endpoint.buffer_before_reply(&early).unwrap();
        endpoint.buffer_before_reply(&early).unwrap();
        assert_eq!(endpoint.pre_status_nlps.len(), 1);
        let reply = peer_reply(endpoint.setup_next_bsn);
        let mut malformed = reply.clone();
        let cie_tcid_start = malformed.len() - 8;
        malformed[cie_tcid_start] &= !0x80;
        assert!(endpoint.prepare_reply_status(&malformed).is_err());
        assert_eq!(endpoint.phase(), OutboundPhase::AwaitReply);
        let status = endpoint.prepare_reply_status(&reply).unwrap();
        assert_eq!(endpoint.phase(), OutboundPhase::AwaitStatusSent);
        assert!(endpoint.take_pre_status_nlps().is_empty());
        endpoint.confirm_status_sent(&status).unwrap();
        assert_eq!(endpoint.phase(), OutboundPhase::Active);
        assert_eq!(
            endpoint.peer_assigned_tcid(),
            Some(PEER_ASSIGNED & !ASSIGNOR)
        );
        let queued = endpoint.take_pre_status_nlps();
        assert_eq!(queued, [early]);
        let received = endpoint.receive(&queued[0]).unwrap();
        assert_eq!(received.messages, [b"BIND-RSP".to_vec()]);
        assert_eq!(
            endpoint.receive(&queued[0]).unwrap().messages,
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            endpoint.reply_to_duplicate_cie(&reply),
            Some(status.as_slice())
        );
    }

    #[test]
    fn outbound_data_is_retained_until_peer_acknowledges() {
        let (mut endpoint, bind) = fixture();
        let setup = endpoint.prepare_setup(&bind).unwrap();
        endpoint.confirm_setup_sent(&setup, 10_000).unwrap();
        let reply = peer_reply(endpoint.setup_next_bsn);
        let status = endpoint.prepare_reply_status(&reply).unwrap();
        endpoint.confirm_status_sent(&status).unwrap();
        let message = endpoint.prepare_message(b"CAPS", 20_000).unwrap();
        assert_eq!(
            RtpPacket::parse(&message).unwrap().tcid,
            PEER_ASSIGNED & !ASSIGNOR
        );
        endpoint.confirm_message_sent(&message, 20_000).unwrap();
        assert_eq!(endpoint.send.as_ref().unwrap().retained_packets(), 1);
        assert_eq!(
            endpoint.retransmit_due(270_000).unwrap(),
            Some(message.clone())
        );
        endpoint
            .confirm_retransmission_sent(&message, 270_000)
            .unwrap();
        let mut ack = encode_status_nlp(
            ORIGIN & !ASSIGNOR,
            &EndpointPath {
                peer_anr_label: vec![0xa4, 0x80],
                priority: 3,
            },
            0,
            1,
            0,
            &crate::hpr_rtp_receive::ReceiveStatus {
                rseq: endpoint.send.as_ref().unwrap().next_bsn(),
                spans: Vec::new(),
            },
            false,
        )
        .unwrap();
        ack[2] = 0xa4;
        let received = endpoint.receive(&ack).unwrap();
        assert!(received.messages.is_empty());
        assert_eq!(endpoint.send.as_ref().unwrap().retained_packets(), 0);
    }

    #[test]
    fn live_bind_response_with_repeated_cie_delivers_data_once() {
        let (mut endpoint, bind) = fixture();
        let setup = endpoint.prepare_setup(&bind).unwrap();
        endpoint.confirm_setup_sent(&setup, 10_000).unwrap();
        let reply = peer_reply(endpoint.setup_next_bsn);
        let status = endpoint.prepare_reply_status(&reply).unwrap();
        endpoint.confirm_status_sent(&status).unwrap();
        // V5R4's first +RSP(BIND) at 17:20:22 has both CIE X'10' and
        // FID5 data. It is a new BIU, not an empty duplicate setup reply.
        let first = peer_data_with_cie(b"BIND-RSP");
        assert_eq!(endpoint.reply_to_duplicate_cie(&first), None);
        assert_eq!(
            endpoint.receive(&first).unwrap().messages,
            [b"BIND-RSP".to_vec()]
        );
        assert!(endpoint.receive(&first).unwrap().messages.is_empty());
        assert_eq!(
            endpoint.reply_to_duplicate_cie(&reply),
            Some(status.as_slice())
        );
        let mut wrong = first.clone();
        let cie_tcid_start = wrong.len() - b"BIND-RSP".len() - 8;
        wrong[cie_tcid_start + 7] ^= 1;
        assert_eq!(
            endpoint.receive(&wrong),
            Err(EndpointError::UnsupportedSegment)
        );
    }
}
