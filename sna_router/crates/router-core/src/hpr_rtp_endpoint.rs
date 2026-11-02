//! One inbound HPR RTP connection after an EE adjacency and return path have
//! been independently validated by APPN control. It has no socket ownership.
//!
//! This state connects setup/CIE, reliable windows, ordered message assembly,
//! and STATUS exchange. The caller owns UDP peer/port/SAP validation, APPN
//! control authorization, ARB rate control, packet timers, and wire send
//! confirmation. Until those are integrated, this is not a complete HPR node.

use crate::{
    hpr_rtp::{RtpError, RtpPacket},
    hpr_rtp_message::{MessageError, OrderedMessageAssembler},
    hpr_rtp_receive::{ReceiveError, ReceiveResult, ReceiveStatus, ReliableReceiveWindow},
    hpr_rtp_reply::{
        encode_setup_reply_from_snapshot, ReplyEncodeError, ReplyPath, StatusExchange,
    },
    hpr_rtp_send::{parse_peer_status, ReliableSendWindow, SendError, StatusEffect},
    hpr_rtp_setup::{RtpInboundSetup, RtpLocalTarget, SetupError},
    ConnectionGeneration,
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const MAX_NLP: usize = 65_507 - 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointPath {
    /// Bootstrap label allocated by the adjacent peer, not copied from an
    /// untrusted inbound packet.
    pub peer_anr_label: Vec<u8>,
    /// 0=low, 1=medium, 2=high, 3=network.
    pub priority: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointPeer {
    /// On-wire APPN identifiers established from the same XID3/CV61
    /// adjacency. `node_id` is the encoded CP name, not the XID fixed ID.
    pub network_id: Vec<u8>,
    pub node_id: Vec<u8>,
    pub nce_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundEndpointConfig {
    pub generation: ConnectionGeneration,
    pub local_target: RtpLocalTarget,
    pub peer: EndpointPeer,
    pub path: EndpointPath,
    /// Sender-assigned ID we will advertise to the peer in CIE.
    pub assigned_tcid: u64,
    pub initial_outbound_bsn: u32,
    pub max_message_bytes: usize,
    pub max_window_bytes: usize,
    /// Negotiated maximum NLP bytes; excludes the three-byte LDLC UI header.
    pub max_nlp_bytes: usize,
    /// Caller-selected retransmission timeout; bounded to 10 ms–60 s.
    pub retransmit_timeout_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPhase {
    AwaitSetup,
    AwaitReplySent,
    AwaitPeerStatus,
    Active,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    InvalidConfig,
    WrongPhase,
    InvalidRtp(RtpError),
    Setup(SetupError),
    Reply(ReplyEncodeError),
    Receive(ReceiveError),
    Send(SendError),
    Assembly(MessageError),
    WrongPeer,
    MissingStatus,
    UnsupportedSegment,
    InvalidTransmittedPacket,
    TooLarge,
    InvalidArb,
    RateLimited,
    ClockMovedBackwards,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BaseArb {
    /// Conservative interval derived from the peer's Base setup operating
    /// range, in microseconds. Rate replies can lengthen it.
    interval_us: u64,
    /// Field 3 is the bottleneck capacity of the reverse path, the direction
    /// in which this endpoint sends data back to the setup originator.
    reverse_capacity_kbps: u32,
    pending_rate_reply: bool,
    next_send_not_before_us: u64,
    last_sent_us: Option<u64>,
}

impl BaseArb {
    fn from_setup(segment: crate::hpr_rtp::RtpOptionalSegment<'_>) -> Result<Self, EndpointError> {
        let data = segment.data;
        if data.len() != 18 || data[0] != 0 || data[1] != 0 {
            return Err(EndpointError::InvalidArb);
        }
        let interval = u32::from_be_bytes(data[2..6].try_into().unwrap());
        let upper = u32::from_be_bytes(data[6..10].try_into().unwrap());
        let capacity = u32::from_be_bytes(data[10..14].try_into().unwrap());
        if interval == 0 || upper < interval || capacity == 0 {
            return Err(EndpointError::InvalidArb);
        }
        Ok(Self {
            interval_us: u64::from(interval),
            reverse_capacity_kbps: capacity,
            pending_rate_reply: false,
            next_send_not_before_us: 0,
            last_sent_us: None,
        })
    }

    fn observe(
        &mut self,
        segment: crate::hpr_rtp::RtpOptionalSegment<'_>,
    ) -> Result<(), EndpointError> {
        let data = segment.data;
        if data.len() != 10 || data[1] != 0 || data[0] & 0x07 != 0 {
            return Err(EndpointError::InvalidArb);
        }
        let message_type = data[0] & 0xc0;
        let action = (data[0] & 0x38) >> 3;
        let field1 = u32::from_be_bytes(data[2..6].try_into().unwrap());
        let field2 = u32::from_be_bytes(data[6..10].try_into().unwrap());
        match message_type {
            0x80 if action == 0 && field1 > 0 && field2 == 0 => {
                self.pending_rate_reply = true;
            }
            0x40 if field1 == 0 && action <= 4 => {
                self.apply_reply(action, field2)?;
            }
            0xc0 if field1 > 0 && action <= 4 => {
                self.pending_rate_reply = true;
                self.apply_reply(action, field2)?;
            }
            _ => return Err(EndpointError::InvalidArb),
        }
        Ok(())
    }

    fn apply_reply(&mut self, action: u8, field2: u32) -> Result<(), EndpointError> {
        if field2 != 0 && !matches!(action, 2 | 3) {
            return Err(EndpointError::InvalidArb);
        }
        self.interval_us = match action {
            0 => self
                .interval_us
                .saturating_sub(self.interval_us / 16)
                .max(1),
            1 => self.interval_us,
            2 => self.interval_us.saturating_mul(8).div_ceil(7),
            3 => self.interval_us.saturating_mul(4).div_ceil(3),
            4 => self.interval_us.saturating_mul(2),
            _ => return Err(EndpointError::InvalidArb),
        }
        .min(1_000_000);
        Ok(())
    }

    fn check_send_time(&self, now_us: u64) -> Result<(), EndpointError> {
        if self.last_sent_us.is_some_and(|last| now_us < last) {
            return Err(EndpointError::ClockMovedBackwards);
        }
        if now_us < self.next_send_not_before_us {
            return Err(EndpointError::RateLimited);
        }
        Ok(())
    }

    fn sent(&mut self, now_us: u64, nlp_bytes: usize) -> Result<(), EndpointError> {
        self.check_send_time(now_us)?;
        self.last_sent_us = Some(now_us);
        let capacity_interval_us = (nlp_bytes as u64)
            .saturating_mul(8_000)
            .div_ceil(u64::from(self.reverse_capacity_kbps));
        self.next_send_not_before_us =
            now_us.saturating_add(self.interval_us.max(capacity_interval_us));
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointReceive {
    pub generation: ConnectionGeneration,
    pub inbound_tcid: u64,
    pub messages: Vec<Vec<u8>>,
    /// NLPs retained by the send ledger and named by a peer gap report.
    pub retransmit_nlps: Vec<Vec<u8>>,
    /// Whether a fresh STATUS should be sent after this packet.
    pub status_due: bool,
}

#[derive(Clone, Debug)]
pub struct RtpInboundEndpoint {
    config: InboundEndpointConfig,
    phase: EndpointPhase,
    setup: RtpInboundSetup,
    origin_tcid: Option<u64>,
    pending_setup_reply: Option<Vec<u8>>,
    pending_data: Option<Vec<u8>>,
    pending_status: Option<Vec<u8>>,
    pending_retransmission: Option<Vec<u8>>,
    pending_messages: Vec<Vec<u8>>,
    receive: Option<ReliableReceiveWindow>,
    send: Option<ReliableSendWindow>,
    assembly: OrderedMessageAssembler,
    next_sync: u16,
    last_peer_sync: u16,
    arb: Option<BaseArb>,
    last_retransmit_us: Option<u64>,
}

impl RtpInboundEndpoint {
    pub fn new(config: InboundEndpointConfig) -> Result<Self, EndpointError> {
        if config.assigned_tcid & (ASSIGNOR | RESERVED) != ASSIGNOR
            || config.peer.network_id.is_empty()
            || config.peer.network_id.len() > 8
            || config.peer.node_id.is_empty()
            || config.peer.node_id.len() > 8
            || config.peer.nce_id.is_empty()
            || config.peer.nce_id.len() > 8
            || config.max_nlp_bytes < 768
            || config.max_nlp_bytes > MAX_NLP
            || config.path.priority > 3
            || !(10_000..=60_000_000).contains(&config.retransmit_timeout_us)
        {
            return Err(EndpointError::InvalidConfig);
        }
        let setup = RtpInboundSetup::new(config.generation, config.local_target.clone())
            .map_err(EndpointError::Setup)?;
        let assembly = OrderedMessageAssembler::new(config.max_message_bytes)
            .map_err(EndpointError::Assembly)?;
        // Probe the shared window limits before any state is stored.
        ReliableReceiveWindow::new(
            config.generation,
            config.assigned_tcid & !ASSIGNOR,
            0,
            config.max_window_bytes,
        )
        .map_err(EndpointError::Receive)?;
        Ok(Self {
            config,
            phase: EndpointPhase::AwaitSetup,
            setup,
            origin_tcid: None,
            pending_setup_reply: None,
            pending_data: None,
            pending_status: None,
            pending_retransmission: None,
            pending_messages: Vec::new(),
            receive: None,
            send: None,
            assembly,
            next_sync: 1,
            last_peer_sync: 0,
            arb: None,
            last_retransmit_us: None,
        })
    }

    pub fn phase(&self) -> EndpointPhase {
        self.phase
    }

    pub fn generation(&self) -> ConnectionGeneration {
        self.config.generation
    }

    pub fn inbound_tcid(&self) -> Option<u64> {
        (self.phase != EndpointPhase::AwaitSetup).then_some(self.config.assigned_tcid & !ASSIGNOR)
    }

    /// Accept a qualified setup NLP only after the caller has validated the
    /// EE neighbor, priority, directional SAP, active link generation, and
    /// bootstrap target label. Returns an NLP to transmit on that adjacency.
    /// The caller must invoke `confirm_setup_reply_sent` after actual send.
    pub fn prepare_inbound_setup(&mut self, nlp: &[u8]) -> Result<Vec<u8>, EndpointError> {
        if self.phase != EndpointPhase::AwaitSetup {
            return Err(EndpointError::WrongPhase);
        }
        if nlp.len() > self.config.max_nlp_bytes {
            return Err(EndpointError::TooLarge);
        }
        let packet = RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?;
        let qualifier = packet
            .connection_qualifier()
            .map_err(EndpointError::InvalidRtp)?
            .ok_or(EndpointError::WrongPeer)?;
        if qualifier.network_id != self.config.peer.network_id
            || qualifier.node_id != self.config.peer.node_id
            || qualifier.nce_id != self.config.peer.nce_id
        {
            return Err(EndpointError::WrongPeer);
        }
        let mut setup = self.setup.clone();
        setup
            .observe_inbound_setup(self.config.generation, packet)
            .map_err(EndpointError::Setup)?;
        let segments = packet
            .optional_segments()
            .map_err(EndpointError::InvalidRtp)?;
        let mut arb_segments = segments.iter().filter(|segment| segment.key == 0x22);
        let arb_segment = arb_segments.next().ok_or(EndpointError::InvalidArb)?;
        if arb_segments.next().is_some() {
            return Err(EndpointError::InvalidArb);
        }
        let arb = BaseArb::from_setup(*arb_segment)?;
        let mut assembly = self.assembly.clone();
        let initial_messages = assembly
            .observe(&[crate::hpr_rtp_receive::ReceivedFragment {
                data: packet.data.to_vec(),
                start_of_message: packet.start_of_message,
                end_of_message: packet.end_of_message,
            }])
            .map_err(EndpointError::Assembly)?;
        let first_rseq = packet.next_byte_sequence_number();
        let receive = ReliableReceiveWindow::new(
            self.config.generation,
            self.config.assigned_tcid & !ASSIGNOR,
            first_rseq,
            self.config.max_window_bytes,
        )
        .map_err(EndpointError::Receive)?;
        let reply = encode_setup_reply_from_snapshot(
            packet.tcid,
            self.config.assigned_tcid,
            ReplyPath {
                anr_label: &self.config.path.peer_anr_label,
                priority: self.config.path.priority,
            },
            StatusExchange {
                sync: self.next_sync,
                echo: 0,
                outbound_bsn: self.config.initial_outbound_bsn,
            },
            &ReceiveStatus {
                rseq: first_rseq,
                spans: Vec::new(),
            },
        )
        .map_err(EndpointError::Reply)?;
        if reply.len() > self.config.max_nlp_bytes {
            return Err(EndpointError::TooLarge);
        }
        self.setup = setup;
        self.assembly = assembly;
        self.origin_tcid = Some(packet.tcid);
        self.receive = Some(receive);
        self.arb = Some(arb);
        self.pending_messages = initial_messages;
        self.pending_setup_reply = Some(reply.clone());
        self.phase = EndpointPhase::AwaitReplySent;
        Ok(reply)
    }

    /// A queued datagram is not enough: call this only after the socket
    /// confirms that the setup reply was transmitted. The qualified setup
    /// may itself contain a complete Route Setup or BIND message. Return it
    /// now so the local APPN/session layer can reply before the peer's first
    /// STATUS arrives (the ordering observed in V5R4 EE captures).
    pub fn confirm_setup_reply_sent(&mut self, nlp: &[u8]) -> Result<Vec<Vec<u8>>, EndpointError> {
        if self.phase != EndpointPhase::AwaitReplySent
            || self.pending_setup_reply.as_deref() != Some(nlp)
        {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        let packet = RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?;
        self.setup
            .observe_outbound_reply_sent(self.config.generation, packet)
            .map_err(EndpointError::Setup)?;
        let origin = self.origin_tcid.unwrap() & !ASSIGNOR;
        let mut send = ReliableSendWindow::new(
            self.config.generation,
            origin,
            self.config.assigned_tcid & !ASSIGNOR,
            self.config.initial_outbound_bsn,
            self.config.max_window_bytes,
        )
        .map_err(EndpointError::Send)?;
        send.record_local_sync(self.config.generation, self.next_sync)
            .map_err(EndpointError::Send)?;
        self.next_sync = self.next_sync.wrapping_add(1);
        self.send = Some(send);
        self.pending_setup_reply = None;
        self.phase = EndpointPhase::AwaitPeerStatus;
        Ok(std::mem::take(&mut self.pending_messages))
    }

    /// Process one unqualified NLP. The first packet must both use the
    /// CIE-assigned TCID and echo our setup STATUS. The initial qualified
    /// message was already released after the CIE send; the peer can receive
    /// our application reply before sending this STATUS. STATUS and data may
    /// share an NLP.
    pub fn receive(&mut self, nlp: &[u8]) -> Result<EndpointReceive, EndpointError> {
        if !matches!(
            self.phase,
            EndpointPhase::AwaitPeerStatus | EndpointPhase::Active
        ) {
            return Err(EndpointError::WrongPhase);
        }
        if nlp.len() > self.config.max_nlp_bytes {
            return Err(EndpointError::TooLarge);
        }
        let packet = RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?;
        if packet.tcid != self.config.assigned_tcid & !ASSIGNOR {
            return Err(EndpointError::WrongPeer);
        }
        let segments = packet
            .optional_segments()
            .map_err(EndpointError::InvalidRtp)?;
        if segments.iter().any(|s| !matches!(s.key, 0x0e | 0x22)) {
            return Err(EndpointError::UnsupportedSegment);
        }
        let mut arb = self.arb.unwrap();
        let mut arb_segments = segments.iter().filter(|segment| segment.key == 0x22);
        if let Some(segment) = arb_segments.next() {
            arb.observe(*segment)?;
        }
        if arb_segments.next().is_some() {
            return Err(EndpointError::InvalidArb);
        }
        let has_status = segments.iter().any(|s| s.key == 0x0e);
        if self.phase == EndpointPhase::AwaitPeerStatus && !has_status {
            return Err(EndpointError::MissingStatus);
        }
        let mut setup = self.setup.clone();
        if self.phase == EndpointPhase::AwaitPeerStatus {
            setup
                .observe_inbound_peer_use(self.config.generation, packet)
                .map_err(EndpointError::Setup)?;
        }
        let mut send = self.send.as_ref().unwrap().clone();
        let status: Option<StatusEffect> = if has_status {
            Some(
                send.observe_status(self.config.generation, packet)
                    .map_err(EndpointError::Send)?,
            )
        } else {
            None
        };
        let mut receive = self.receive.as_ref().unwrap().clone();
        let delivered = receive
            .observe(self.config.generation, packet)
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
        if self.phase == EndpointPhase::AwaitPeerStatus {
            self.phase = EndpointPhase::Active;
        }
        self.setup = setup;
        self.send = Some(send);
        self.receive = Some(receive);
        self.assembly = assembly;
        self.arb = Some(arb);
        if self.pending_retransmission.as_deref()
            != self.send.as_ref().unwrap().oldest_retained_nlp()
        {
            self.pending_retransmission = None;
        }
        if let Some(status) = &status {
            self.last_peer_sync = parse_peer_status(packet).map_err(EndpointError::Send)?.sync;
            return Ok(EndpointReceive {
                generation: self.config.generation,
                inbound_tcid: packet.tcid,
                messages,
                retransmit_nlps: status.retransmit_nlps.clone(),
                status_due,
            });
        }
        Ok(EndpointReceive {
            generation: self.config.generation,
            inbound_tcid: packet.tcid,
            messages,
            retransmit_nlps: Vec::new(),
            status_due,
        })
    }

    /// Prepare a STATUS-only NLP from the current receive window. The caller
    /// must confirm actual transmission before preparing another STATUS.
    pub fn prepare_status(&mut self) -> Result<Vec<u8>, EndpointError> {
        if !matches!(
            self.phase,
            EndpointPhase::AwaitPeerStatus | EndpointPhase::Active
        ) || self.pending_status.is_some()
        {
            return Err(EndpointError::WrongPhase);
        }
        let snapshot = self.receive.as_ref().unwrap().status();
        let tcid = self.origin_tcid.unwrap() & !ASSIGNOR;
        let bsn = self.send.as_ref().unwrap().next_bsn();
        let nlp = encode_status_nlp(
            tcid,
            &self.config.path,
            self.next_sync,
            self.last_peer_sync,
            bsn,
            &snapshot,
            self.arb.unwrap().pending_rate_reply,
        )?;
        if nlp.len() > self.config.max_nlp_bytes {
            return Err(EndpointError::TooLarge);
        }
        self.pending_status = Some(nlp.clone());
        Ok(nlp)
    }

    pub fn confirm_status_sent(&mut self, nlp: &[u8]) -> Result<(), EndpointError> {
        if self.pending_status.as_deref() != Some(nlp) {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.send
            .as_mut()
            .unwrap()
            .record_local_sync(self.config.generation, self.next_sync)
            .map_err(EndpointError::Send)?;
        self.next_sync = self.next_sync.wrapping_add(1);
        self.arb.as_mut().unwrap().pending_rate_reply = false;
        self.pending_status = None;
        Ok(())
    }

    /// Prepare one complete RTP message as one packet. Segmentation and ARB
    /// pacing are required before this can be enabled for unrestricted data.
    pub fn prepare_message(
        &mut self,
        message: &[u8],
        now_us: u64,
    ) -> Result<Vec<u8>, EndpointError> {
        if !matches!(
            self.phase,
            EndpointPhase::AwaitPeerStatus | EndpointPhase::Active
        ) || self.pending_data.is_some()
        {
            return Err(EndpointError::WrongPhase);
        }
        self.arb.unwrap().check_send_time(now_us)?;
        let include_cie = self.phase == EndpointPhase::AwaitPeerStatus;
        if message.is_empty()
            || message.len() + 38 + if include_cie { 12 } else { 0 } > self.config.max_nlp_bytes
        {
            return Err(EndpointError::TooLarge);
        }
        let tcid = self.origin_tcid.unwrap() & !ASSIGNOR;
        let bsn = self.send.as_ref().unwrap().next_bsn();
        let measurement_us = self
            .arb
            .unwrap()
            .last_sent_us
            .map_or(self.arb.unwrap().interval_us, |last| {
                now_us.saturating_sub(last).max(1)
            })
            .min(u64::from(u32::MAX)) as u32;
        let nlp = encode_data_nlp(
            tcid,
            &self.config.path,
            bsn,
            message,
            measurement_us,
            include_cie.then_some(self.config.assigned_tcid),
        )?;
        if nlp.len() > self.config.max_nlp_bytes {
            return Err(EndpointError::TooLarge);
        }
        let mut preview = self.send.as_ref().unwrap().clone();
        preview
            .record_transmitted(
                self.config.generation,
                RtpPacket::parse(&nlp).map_err(EndpointError::InvalidRtp)?,
            )
            .map_err(EndpointError::Send)?;
        self.pending_data = Some(nlp.clone());
        Ok(nlp)
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
                self.config.generation,
                RtpPacket::parse(nlp).map_err(EndpointError::InvalidRtp)?,
            )
            .map_err(EndpointError::Send)?;
        self.arb.as_mut().unwrap().sent(now_us, nlp.len())?;
        self.pending_data = None;
        Ok(())
    }

    /// Return the oldest still-unacknowledged NLP when a caller-owned timer
    /// fires. Sequence state is unchanged; the socket owner confirms a real
    /// retransmission with `confirm_retransmission_sent`.
    pub fn retransmit_due(&mut self, now_us: u64) -> Result<Option<Vec<u8>>, EndpointError> {
        if !matches!(
            self.phase,
            EndpointPhase::AwaitPeerStatus | EndpointPhase::Active
        ) {
            return Err(EndpointError::WrongPhase);
        }
        if self.pending_retransmission.is_some() {
            return Ok(None);
        }
        let Some(nlp) = self.send.as_ref().unwrap().oldest_retained_nlp() else {
            return Ok(None);
        };
        let last_attempt = self
            .last_retransmit_us
            .unwrap_or(0)
            .max(self.arb.unwrap().last_sent_us.unwrap_or(0));
        if now_us < last_attempt {
            return Err(EndpointError::ClockMovedBackwards);
        }
        if now_us - last_attempt < self.config.retransmit_timeout_us {
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
        if self.pending_retransmission.as_deref() != Some(nlp)
            || self.send.as_ref().unwrap().oldest_retained_nlp() != Some(nlp)
        {
            return Err(EndpointError::InvalidTransmittedPacket);
        }
        self.arb.as_mut().unwrap().sent(now_us, nlp.len())?;
        self.last_retransmit_us = Some(now_us);
        self.pending_retransmission = None;
        Ok(())
    }

    pub fn close(&mut self) {
        self.phase = EndpointPhase::Closed;
        self.setup.close();
        self.pending_messages.clear();
        self.pending_setup_reply = None;
        self.pending_data = None;
        self.pending_status = None;
        self.pending_retransmission = None;
        self.receive = None;
        self.send = None;
        self.arb = None;
        self.last_retransmit_us = None;
        self.assembly.reset();
    }
}

fn encode_data_nlp(
    tcid: u64,
    path: &EndpointPath,
    bsn: u32,
    message: &[u8],
    measurement_us: u32,
    cie_tcid: Option<u64>,
) -> Result<Vec<u8>, EndpointError> {
    if message.len() > u32::MAX as usize {
        return Err(EndpointError::TooLarge);
    }
    let mut nlp = vec![0xc0 | (path.priority << 1), 0];
    nlp.extend_from_slice(&path.peer_anr_label);
    nlp.extend_from_slice(&[0xff, 0]);
    nlp.extend_from_slice(&tcid.to_be_bytes());
    nlp.extend_from_slice(&[0x30, 4]);
    nlp.extend_from_slice(&(8u16 + if cie_tcid.is_some() { 3 } else { 0 }).to_be_bytes());
    nlp.extend_from_slice(&(message.len() as u32).to_be_bytes());
    nlp.extend_from_slice(&bsn.to_be_bytes());
    if let Some(tcid) = cie_tcid {
        nlp.extend_from_slice(&[3, 0x10, 0, 0]);
        nlp.extend_from_slice(&tcid.to_be_bytes());
    }
    nlp.extend_from_slice(&[3, 0x22, 0x80, 0]);
    nlp.extend_from_slice(&measurement_us.to_be_bytes());
    nlp.extend_from_slice(&0u32.to_be_bytes());
    nlp.extend_from_slice(message);
    RtpPacket::parse(&nlp).map_err(EndpointError::InvalidRtp)?;
    Ok(nlp)
}

fn encode_status_nlp(
    tcid: u64,
    path: &EndpointPath,
    sync: u16,
    echo: u16,
    bsn: u32,
    status: &ReceiveStatus,
    arb_reply_due: bool,
) -> Result<Vec<u8>, EndpointError> {
    if status.spans.len() > 125 {
        return Err(EndpointError::TooLarge);
    }
    let thdr_len = 40 + status.spans.len() * 8 + if arb_reply_due { 12 } else { 0 };
    let mut nlp = vec![0xc0 | (path.priority << 1), 0x08];
    nlp.extend_from_slice(&path.peer_anr_label);
    nlp.extend_from_slice(&[0xff, 0]);
    nlp.extend_from_slice(&tcid.to_be_bytes());
    nlp.extend_from_slice(&[0, 4]);
    nlp.extend_from_slice(&((thdr_len / 4) as u16).to_be_bytes());
    nlp.extend_from_slice(&0u32.to_be_bytes());
    nlp.extend_from_slice(&bsn.to_be_bytes());
    nlp.push((5 + 2 * status.spans.len()) as u8);
    nlp.push(0x0e);
    nlp.push(if status.spans.is_empty() { 0 } else { 0x80 });
    nlp.push(status.spans.len() as u8);
    nlp.extend_from_slice(&sync.to_be_bytes());
    nlp.extend_from_slice(&echo.to_be_bytes());
    nlp.extend_from_slice(&status.rseq.to_be_bytes());
    nlp.extend_from_slice(&[0; 8]);
    for span in &status.spans {
        nlp.extend_from_slice(&span.begin.to_be_bytes());
        nlp.extend_from_slice(&span.end.to_be_bytes());
    }
    if arb_reply_due {
        nlp.extend_from_slice(&[3, 0x22, 0x40, 0]);
        nlp.extend_from_slice(&[0; 8]);
    }
    let packet = RtpPacket::parse(&nlp).map_err(EndpointError::InvalidRtp)?;
    parse_peer_status(packet).map_err(EndpointError::Send)?;
    Ok(nlp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: u64 = 0x8015_0001_0000_0040;
    const ASSIGNED: u64 = 0x8016_0002_0000_0040;

    fn config() -> InboundEndpointConfig {
        InboundEndpointConfig {
            generation: ConnectionGeneration::new(1).unwrap(),
            local_target: RtpLocalTarget {
                network_id: b"NET001".to_vec(),
                node_id: b"NODE".to_vec(),
                nce_instance: [0, 0, 0, 4],
            },
            peer: EndpointPeer {
                network_id: b"SRC001".to_vec(),
                node_id: b"ORIG".to_vec(),
                nce_id: vec![0x12, 0x34],
            },
            path: EndpointPath {
                peer_anr_label: vec![0xa4, 0],
                priority: 3,
            },
            assigned_tcid: ASSIGNED,
            initial_outbound_bsn: 200,
            max_message_bytes: 1024,
            max_window_bytes: 4096,
            max_nlp_bytes: 1461,
            retransmit_timeout_us: 250_000,
        }
    }

    fn lt(key: u8, body: &[u8]) -> Vec<u8> {
        let mut cv = vec![(body.len() + 2) as u8, key];
        cv.extend_from_slice(body);
        cv.resize(cv.len().div_ceil(4) * 4, 0);
        cv
    }

    fn segment(key: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, key];
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().div_ceil(4) * 4, 0);
        bytes[0] = (bytes.len() / 4) as u8;
        bytes
    }

    fn setup_packet(cfg: &InboundEndpointConfig) -> Vec<u8> {
        let qualifier = [
            30, 5, 0x80, 0, 8, 3, b'S', b'R', b'C', b'0', b'0', b'1', 6, 0, b'O', b'R', b'I', b'G',
            0, 0, 4, 0x26, 0x12, 0x34, 6, 0x39, 0, 0, 0, 8, 0, 0,
        ];
        let mut cs = vec![1, 1, 0x98, 0, 0, 0];
        cs.extend_from_slice(&lt(0x28, b"\0RSETUP"));
        cs.extend_from_slice(&lt(0x03, &cfg.local_target.network_id));
        cs.extend_from_slice(&lt(0x00, &cfg.local_target.node_id));
        cs.extend_from_slice(&lt(0x39, &cfg.local_target.nce_instance));
        let mut si = vec![0, 0];
        si.extend_from_slice(&lt(0x83, &[0; 20]));
        si.extend_from_slice(&lt(0x85, &[0; 24]));
        let mut segments = segment(0x0d, &cs);
        segments.extend_from_slice(&segment(0x14, &si));
        segments.extend_from_slice(&segment(
            0x22,
            &[
                0, 0, 0, 0, 0x0f, 0xa0, 0, 0, 0x9c, 0x40, 0, 0, 0x10, 0xcc, 0, 0, 1, 0x14,
            ],
        ));
        let mut packet = vec![0xc6, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&ORIGIN.to_be_bytes());
        thdr[8] = 0x7c;
        thdr[9] = 0x0c;
        thdr[10..12]
            .copy_from_slice(&((20 + qualifier.len() + segments.len()) as u16 / 4).to_be_bytes());
        thdr[12..16].copy_from_slice(&6u32.to_be_bytes());
        thdr[16..20].copy_from_slice(&100u32.to_be_bytes());
        packet.extend_from_slice(&thdr);
        packet.extend_from_slice(&qualifier);
        packet.extend_from_slice(&segments);
        packet.extend_from_slice(b"RSETUP");
        packet
    }

    fn peer_packet(tcid: u64, bsn: u32, data: &[u8], status: Option<(u16, u16, u32)>) -> Vec<u8> {
        let mut nlp = vec![0xc6, u8::from(status.is_some()) * 8, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&tcid.to_be_bytes());
        thdr[8] = if data.is_empty() { 0 } else { 0x30 };
        thdr[9] = if status.is_some() { 4 } else { 0 };
        thdr[10..12].copy_from_slice(&(if status.is_some() { 10u16 } else { 5 }).to_be_bytes());
        thdr[12..16].copy_from_slice(&(data.len() as u32).to_be_bytes());
        thdr[16..20].copy_from_slice(&bsn.to_be_bytes());
        nlp.extend_from_slice(&thdr);
        if let Some((sync, echo, rseq)) = status {
            nlp.extend_from_slice(&[5, 0x0e, 0, 0]);
            nlp.extend_from_slice(&sync.to_be_bytes());
            nlp.extend_from_slice(&echo.to_be_bytes());
            nlp.extend_from_slice(&rseq.to_be_bytes());
            nlp.extend_from_slice(&[0; 8]);
        }
        nlp.extend_from_slice(data);
        nlp
    }

    #[test]
    fn qualified_setup_requires_peer_and_confirmed_reply() {
        let cfg = config();
        let mut endpoint = RtpInboundEndpoint::new(cfg.clone()).unwrap();
        let setup = setup_packet(&cfg);
        let mut wrong = setup.clone();
        wrong[32] = b'X';
        assert_eq!(
            endpoint.prepare_inbound_setup(&wrong),
            Err(EndpointError::WrongPeer)
        );
        assert_eq!(endpoint.phase(), EndpointPhase::AwaitSetup);
        let reply = endpoint.prepare_inbound_setup(&setup).unwrap();
        assert_eq!(endpoint.phase(), EndpointPhase::AwaitReplySent);
        assert_eq!(
            endpoint.confirm_setup_reply_sent(&setup),
            Err(EndpointError::InvalidTransmittedPacket)
        );
        assert_eq!(
            endpoint.confirm_setup_reply_sent(&reply).unwrap(),
            vec![b"RSETUP".to_vec()]
        );
        assert_eq!(endpoint.phase(), EndpointPhase::AwaitPeerStatus);
        let response = endpoint.prepare_message(b"RSETUP-OK", 10_000).unwrap();
        assert_eq!(
            RtpPacket::parse(&response)
                .unwrap()
                .connection_identifier_exchange(),
            Ok(Some(ASSIGNED))
        );
        endpoint.confirm_message_sent(&response, 10_000).unwrap();
        let peer = peer_packet(ASSIGNED & !ASSIGNOR, 107, &[], Some((1, 1, 210)));
        let event = endpoint.receive(&peer).unwrap();
        assert_eq!(endpoint.phase(), EndpointPhase::Active);
        assert!(event.messages.is_empty());
        assert_eq!(event.inbound_tcid, ASSIGNED & !ASSIGNOR);
        assert_eq!(endpoint.send.as_ref().unwrap().retained_packets(), 0);
    }

    #[test]
    fn complete_data_and_outbound_status_roundtrip() {
        let cfg = config();
        let mut endpoint = RtpInboundEndpoint::new(cfg.clone()).unwrap();
        let reply = endpoint.prepare_inbound_setup(&setup_packet(&cfg)).unwrap();
        endpoint.confirm_setup_reply_sent(&reply).unwrap();
        endpoint
            .receive(&peer_packet(
                ASSIGNED & !ASSIGNOR,
                107,
                &[],
                Some((1, 1, 200)),
            ))
            .unwrap();
        let data = endpoint
            .receive(&peer_packet(ASSIGNED & !ASSIGNOR, 107, b"BIU", None))
            .unwrap();
        assert_eq!(data.messages, vec![b"BIU".to_vec()]);
        assert!(data.status_due);
        let status = endpoint.prepare_status().unwrap();
        let parsed = parse_peer_status(RtpPacket::parse(&status).unwrap()).unwrap();
        assert_eq!((parsed.sync, parsed.echo, parsed.rseq), (2, 1, 111));
        endpoint.confirm_status_sent(&status).unwrap();
        let output = endpoint.prepare_message(b"REPLY", 10_000).unwrap();
        endpoint.confirm_message_sent(&output, 10_000).unwrap();
        assert_eq!(RtpPacket::parse(&output).unwrap().byte_sequence_number, 200);
        assert_eq!(endpoint.retransmit_due(259_999), Ok(None));
        assert_eq!(endpoint.retransmit_due(260_000), Ok(Some(output.clone())));
        endpoint
            .confirm_retransmission_sent(&output, 260_000)
            .unwrap();
        let ack = endpoint
            .receive(&peer_packet(
                ASSIGNED & !ASSIGNOR,
                111,
                &[],
                Some((2, 2, 206)),
            ))
            .unwrap();
        assert!(ack.retransmit_nlps.is_empty());
        assert_eq!(endpoint.retransmit_due(600_000), Ok(None));
        endpoint.close();
        assert_eq!(endpoint.phase(), EndpointPhase::Closed);
    }

    #[test]
    fn base_arb_rate_request_generates_reply_and_limits_send() {
        let cfg = config();
        let mut endpoint = RtpInboundEndpoint::new(cfg.clone()).unwrap();
        let reply = endpoint.prepare_inbound_setup(&setup_packet(&cfg)).unwrap();
        endpoint.confirm_setup_reply_sent(&reply).unwrap();
        endpoint
            .receive(&peer_packet(
                ASSIGNED & !ASSIGNOR,
                107,
                &[],
                Some((1, 1, 200)),
            ))
            .unwrap();
        let mut rate_request = peer_packet(ASSIGNED & !ASSIGNOR, 107, &[], Some((2, 1, 200)));
        let mut thdr = rate_request.split_off(6);
        thdr[10..12].copy_from_slice(&13u16.to_be_bytes());
        thdr.extend_from_slice(&[3, 0x22, 0x80, 0, 0, 0, 0x12, 0x28, 0, 0, 0, 0]);
        rate_request.extend_from_slice(&thdr);
        endpoint.receive(&rate_request).unwrap();
        let status = endpoint.prepare_status().unwrap();
        let parsed = RtpPacket::parse(&status).unwrap();
        assert_eq!(parsed.optional_segments().unwrap().len(), 2);
        assert_eq!(parsed.optional_segments().unwrap()[1].key, 0x22);
        endpoint.confirm_status_sent(&status).unwrap();
        let first = endpoint.prepare_message(b"A", 100_000).unwrap();
        endpoint.confirm_message_sent(&first, 100_000).unwrap();
        assert_eq!(
            endpoint.prepare_message(b"B", 100_001),
            Err(EndpointError::RateLimited)
        );
        endpoint.prepare_message(b"B", 104_000).unwrap();
    }

    #[test]
    fn malformed_arb_and_wrong_peer_status_do_not_activate() {
        let cfg = config();
        let mut endpoint = RtpInboundEndpoint::new(cfg.clone()).unwrap();
        let mut setup = setup_packet(&cfg);
        let arb_offset = setup.windows(2).position(|part| part == [5, 0x22]).unwrap();
        setup[arb_offset + 2] = 1; // Responsive mode is not implemented.
        assert_eq!(
            endpoint.prepare_inbound_setup(&setup),
            Err(EndpointError::InvalidArb)
        );
        assert_eq!(endpoint.phase(), EndpointPhase::AwaitSetup);
        let reply = endpoint.prepare_inbound_setup(&setup_packet(&cfg)).unwrap();
        endpoint.confirm_setup_reply_sent(&reply).unwrap();
        assert_eq!(
            endpoint.receive(&peer_packet(
                ASSIGNED & !ASSIGNOR,
                107,
                &[],
                Some((1, 1, 201))
            )),
            Err(EndpointError::Send(SendError::AcknowledgesUnsent))
        );
        assert_eq!(endpoint.phase(), EndpointPhase::AwaitPeerStatus);
        assert_eq!(
            endpoint
                .receive(&peer_packet(
                    ASSIGNED & !ASSIGNOR,
                    107,
                    &[],
                    Some((1, 1, 200))
                ))
                .unwrap()
                .messages,
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn reordered_packets_ack_gaps_then_release_both_messages() {
        let cfg = config();
        let mut endpoint = RtpInboundEndpoint::new(cfg.clone()).unwrap();
        let reply = endpoint.prepare_inbound_setup(&setup_packet(&cfg)).unwrap();
        endpoint.confirm_setup_reply_sent(&reply).unwrap();
        endpoint
            .receive(&peer_packet(
                ASSIGNED & !ASSIGNOR,
                107,
                &[],
                Some((1, 1, 200)),
            ))
            .unwrap();
        let ahead = endpoint
            .receive(&peer_packet(ASSIGNED & !ASSIGNOR, 111, b"Z", None))
            .unwrap();
        assert!(ahead.messages.is_empty() && ahead.status_due);
        let gap_status = endpoint.prepare_status().unwrap();
        let status = parse_peer_status(RtpPacket::parse(&gap_status).unwrap()).unwrap();
        assert_eq!(status.rseq, 107);
        assert_eq!(status.spans.len(), 1);
        assert_eq!((status.spans[0].begin, status.spans[0].end), (111, 113));
        endpoint.confirm_status_sent(&gap_status).unwrap();
        let released = endpoint
            .receive(&peer_packet(ASSIGNED & !ASSIGNOR, 107, b"ABC", None))
            .unwrap();
        assert_eq!(released.messages, vec![b"ABC".to_vec(), b"Z".to_vec()]);
        let final_status = endpoint.prepare_status().unwrap();
        assert_eq!(
            parse_peer_status(RtpPacket::parse(&final_status).unwrap())
                .unwrap()
                .rseq,
            113
        );
    }
}
