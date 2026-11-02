//! Nonblocking TCP62 ingress boundary for a virtual SNA gateway.
//!
//! The port owns one bounded TCP association at a time and emits typed user
//! offers. It never sends a positive user Connect until the owning virtual
//! native leg returns a correlated positive BIND. Production capability sets
//! must be backed by live handlers; without X'83', V5R4 admission fails closed.

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket},
};

use std::time::Instant;
use transport_ip_sna::{
    anynet::{bind_udp, listen_tcp, TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_bind_negotiation::validate_positive_response,
    mptn_compensations::CompensationSet,
    mptn_connect::{Connect, Direction},
    mptn_ingress::{IngressKind, IngressOffer, IngressPolicy, IngressSession},
    mptn_keepalive::{Keepalive, Kind as KeepaliveKind},
    mptn_management_responder::{ManagementResponder, Phase as ManagementPhase, V5Options},
    mptn_oob::{
        build_request as build_oob_request, Compensation as OobCompensation,
        Datagram as OobDatagram, Kind as OobKind,
    },
    mptn_oob_fallback::{
        Action as FallbackAction, Completion as FallbackCompletion, Fallback, Purpose,
    },
    mptn_oob_sequence::{Delivery, SequenceWindow},
    mptn_reverse_management::classify_reverse_management_connect,
};

const MAX_INCOMING: usize = MAX_RECORD * 2;
const MAX_WRITES: usize = 2;

pub(crate) struct GatewayConfig {
    pub local: SocketAddr,
    pub peer_ip: IpAddr,
    pub source_lu: String,
    pub destination_lu: String,
    pub available_compensations: CompensationSet,
    pub options: V5Options,
    pub cnos_mode: String,
    pub cnos_limit: u16,
    /// Caller asserts a prior TCP62 CNOS exchange is still valid at this
    /// peer. Set only after the corresponding native management is complete.
    pub allow_resumed_user: bool,
}

pub(crate) enum GatewayEvent {
    ManagementReady,
    UserBind(IngressOffer),
    UserNormal(TcpRecord),
    UserExpedited(TcpRecord),
    UserUdpExpedited { sequence: u16, reduced: Vec<u8> },
    UserUdpAbort { sequence: u16, reduced: Vec<u8> },
    UserAbort(TcpRecord),
    Closed,
    Rejected(String),
}

enum SessionState {
    AwaitConnect,
    Management(ManagementResponder),
    UserAwaitResponse(IngressOffer),
    UserResponseQueued(IngressOffer),
    UserActive(IngressOffer),
}

enum Completion {
    ManagementConnect(Vec<u8>),
    ManagementCnos(Vec<u8>),
    ManagementBis(Vec<u8>),
    UserConnect,
    UserRecord,
    TcpExpeditedAck,
}

struct PendingOob {
    compensation: OobCompensation,
    sequence: u16,
    peer: SocketAddr,
    request: Vec<u8>,
    response: Vec<u8>,
    trial: Option<SequenceWindow>,
}

struct PendingOutboundOob {
    sequence: u16,
    request: Vec<u8>,
    fallback: Fallback,
}

struct Association {
    tcp: TcpSession,
    state: SessionState,
    incoming: VecDeque<TcpRecord>,
    incoming_bytes: usize,
    writes: VecDeque<(usize, Completion)>,
    user_inflight: bool,
    oob: SequenceWindow,
    pending_oob: Option<PendingOob>,
    pending_tcp_expedited: Option<SequenceWindow>,
    outbound_sequence: u16,
    outbound_oob: Option<PendingOutboundOob>,
    recent_outbound_completed: VecDeque<u16>,
    late_tcp_acks_owed: u16,
    deferred_logical_ack: Option<TcpRecord>,
}

pub(crate) struct MptnGatewayPort {
    config: GatewayConfig,
    listener: TcpListener,
    udp: UdpSocket,
    active: Option<Association>,
    management_ready: bool,
    completed_user_records: usize,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn remember_completed(recent: &mut VecDeque<u16>, sequence: u16) {
    if recent.len() == 64 {
        recent.pop_front();
    }
    recent.push_back(sequence);
}

impl MptnGatewayPort {
    pub(crate) fn bind(config: GatewayConfig) -> io::Result<Self> {
        // Check the configured LU policy before reserving TCP/UDP port 397.
        IngressSession::new(IngressPolicy {
            source_lu: config.source_lu.clone(),
            destination_lu: config.destination_lu.clone(),
            user_mode: None,
            allow_blank_user_mode: true,
            available_compensations: config.available_compensations,
            forbidden_fqpcid: None,
        })?;
        if config.local.ip() == config.peer_ip || config.cnos_limit == 0 {
            return Err(invalid("TCP62 gateway peer or CNOS policy invalid"));
        }
        let udp = bind_udp(config.local)?;
        let listener = listen_tcp(config.local)?;
        Ok(Self {
            config,
            listener,
            udp,
            active: None,
            management_ready: false,
            completed_user_records: 0,
        })
    }

    pub(crate) fn management_ready(&self) -> bool {
        self.management_ready
    }

    pub(crate) fn user_active(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|association| matches!(association.state, SessionState::UserActive(_)))
    }

    /// One UDP receive, one TCP accept/read, one record and at most two queued
    /// writes per call. The virtual WebSocket leg supplies downstream credit.
    pub(crate) fn poll_once(
        &mut self,
        can_accept_information: bool,
    ) -> io::Result<Option<GatewayEvent>> {
        Self::poll_outbound_fallback_at(
            &mut self.active,
            self.config.peer_ip,
            Instant::now(),
            |bytes, peer| Self::send_oob_response(&self.udp, bytes, peer),
        )?;
        match self.poll_udp_once() {
            Ok(Some(event)) => return Ok(Some(event)),
            Ok(None) => {}
            Err(error) => {
                self.active = None;
                return Err(error);
            }
        }
        if self.active.is_none() {
            match self.listener.accept() {
                Ok((stream, peer)) if peer.ip() == self.config.peer_ip => {
                    self.active = Some(Association {
                        tcp: TcpSession::new(stream)?,
                        state: SessionState::AwaitConnect,
                        incoming: VecDeque::new(),
                        incoming_bytes: 0,
                        writes: VecDeque::new(),
                        user_inflight: false,
                        oob: SequenceWindow::default(),
                        pending_oob: None,
                        pending_tcp_expedited: None,
                        outbound_sequence: 0,
                        outbound_oob: None,
                        recent_outbound_completed: VecDeque::new(),
                        late_tcp_acks_owed: 0,
                        deferred_logical_ack: None,
                    });
                }
                Ok((stream, peer)) => {
                    drop(stream);
                    return Ok(Some(GatewayEvent::Rejected(format!(
                        "TCP62 peer IP {peer} is not configured"
                    ))));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let mut association = self.active.take().unwrap();
        let result = self.poll_association(&mut association, can_accept_information);
        match result {
            Ok((event, keep)) => {
                if keep {
                    self.active = Some(association);
                }
                Ok(event)
            }
            Err(error) => Ok(Some(GatewayEvent::Rejected(error.to_string()))),
        }
    }

    fn poll_outbound_fallback_at(
        active: &mut Option<Association>,
        peer_ip: IpAddr,
        now: Instant,
        mut send: impl FnMut(&[u8], SocketAddr) -> io::Result<()>,
    ) -> io::Result<()> {
        let Some(association) = active.as_mut() else {
            return Ok(());
        };
        let Some(pending) = association.outbound_oob.as_mut() else {
            return Ok(());
        };
        match pending.fallback.poll(now) {
            Some(FallbackAction::SendOob {
                purpose: Purpose::Expedited,
                sequence,
            }) if sequence == pending.sequence => {
                let peer = SocketAddr::new(peer_ip, 397);
                send(&pending.request, peer)?;
            }
            Some(FallbackAction::CloseUnresponsive) => {
                *active = None;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP62 expedited peer did not acknowledge TCP or UDP",
                ));
            }
            Some(_) => {
                return Err(invalid(
                    "TCP62 fallback action differs from pending expedited",
                ))
            }
            None => {}
        }
        Ok(())
    }

    fn poll_udp_once(&mut self) -> io::Result<Option<GatewayEvent>> {
        let mut bytes = [0u8; MAX_RECORD];
        match self.udp.recv_from(&mut bytes) {
            Ok((_, peer)) if peer.ip() != self.config.peer_ip => Ok(None),
            Ok((len, peer)) if bytes.get(4) == Some(&0x84) => {
                let keepalive = Keepalive::decode(&bytes[..len])?;
                keepalive.validate_ingress(peer.ip(), self.config.local.ip())?;
                if keepalive.kind != KeepaliveKind::Request {
                    return Err(invalid("unsolicited TCP62 keepalive response"));
                }
                let response = Keepalive {
                    kind: KeepaliveKind::Response,
                    ..keepalive
                }
                .encode();
                if self.udp.send_to(&response, peer)? != response.len() {
                    return Err(invalid("partial TCP62 keepalive response"));
                }
                Ok(None)
            }
            Ok((len, peer)) if bytes.get(4) == Some(&0x83) => {
                let request = bytes[..len].to_vec();
                let datagram = OobDatagram::decode(&request)?;
                let association = self
                    .active
                    .as_mut()
                    .ok_or_else(|| invalid("TCP62 OOB without active association"))?;
                let SessionState::UserActive(offer) = &association.state else {
                    return Err(invalid("TCP62 OOB before active user BIND"));
                };
                if datagram.kind != OobKind::Request {
                    if !datagram.options.is_empty() || !datagram.matches_connect(offer.connect()) {
                        return Err(invalid(
                            "TCP62 OOB response identity or options unsupported",
                        ));
                    }
                    if association
                        .outbound_oob
                        .as_ref()
                        .is_none_or(|pending| pending.sequence != datagram.sequence)
                    {
                        if datagram.kind == OobKind::PositiveResponse
                            && association
                                .recent_outbound_completed
                                .contains(&datagram.sequence)
                        {
                            return Ok(None);
                        }
                        return Err(invalid(
                            "TCP62 OOB response options or sequence unsupported",
                        ));
                    }
                    let pending = association.outbound_oob.as_mut().unwrap();
                    let completion = pending
                        .fallback
                        .received_oob_response(&datagram, offer.connect())?;
                    match completion {
                        FallbackCompletion::ExpeditedAcknowledged => {
                            association.outbound_oob = None;
                            remember_completed(
                                &mut association.recent_outbound_completed,
                                datagram.sequence,
                            );
                            association.late_tcp_acks_owed = association
                                .late_tcp_acks_owed
                                .checked_add(1)
                                .filter(|count| *count <= 64)
                                .ok_or_else(|| invalid("TCP62 late ACK window full"))?;
                            if association.deferred_logical_ack.is_some() {
                                return Err(invalid("TCP62 logical expedited ACK queue full"));
                            }
                            association.deferred_logical_ack =
                                Some(TcpRecord::decode(vec![0, 0, 0, 5, 3])?);
                            return Ok(None);
                        }
                        FallbackCompletion::Rejected | FallbackCompletion::AbortAcknowledged => {
                            return Err(invalid("TCP62 OOB expedited request was rejected"));
                        }
                    }
                }
                if datagram.kind != OobKind::Request
                    || !matches!(
                        datagram.compensation,
                        Some(OobCompensation::Expedited | OobCompensation::Abort)
                    )
                    || !datagram.options.is_empty()
                    || !datagram.matches_connect(offer.connect())
                {
                    return Err(invalid("TCP62 OOB request identity or profile unsupported"));
                }
                let response = datagram.positive_response()?;
                let sequence = datagram.sequence;
                if let Some(pending) = &association.pending_oob {
                    if pending.sequence != sequence
                        || pending.peer != peer
                        || pending.request != request
                    {
                        return Err(invalid("TCP62 OOB pending request changed"));
                    }
                    return Ok(None);
                }
                if association.pending_tcp_expedited.is_some() {
                    if datagram.compensation == Some(OobCompensation::Abort) {
                        return Err(invalid(
                            "TCP62 OOB Abort overlaps unconfirmed expedited delivery",
                        ));
                    }
                    if sequence != association.oob.next_tcp_sequence() {
                        return Err(invalid(
                            "TCP62 OOB overlaps unconfirmed TCP expedited sequence",
                        ));
                    }
                    association.pending_oob = Some(PendingOob {
                        compensation: OobCompensation::Expedited,
                        sequence,
                        peer,
                        request,
                        response,
                        trial: None,
                    });
                    return Ok(None);
                }
                let mut trial = association.oob.clone();
                match trial.receive_udp(sequence)? {
                    Delivery::Duplicate => {
                        Self::send_oob_response(&self.udp, &response, peer)?;
                        Ok(None)
                    }
                    Delivery::New => {
                        let reduced = datagram.user_data.to_vec();
                        let compensation = datagram.compensation.unwrap();
                        association.pending_oob = Some(PendingOob {
                            compensation,
                            sequence,
                            peer,
                            request,
                            response,
                            trial: Some(trial),
                        });
                        Ok(Some(match compensation {
                            OobCompensation::Expedited => {
                                GatewayEvent::UserUdpExpedited { sequence, reduced }
                            }
                            OobCompensation::Abort => {
                                GatewayEvent::UserUdpAbort { sequence, reduced }
                            }
                        }))
                    }
                }
            }
            Ok((_, _)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP62 UDP/397 X'83' compensation handler unavailable",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn send_oob_response(socket: &UdpSocket, response: &[u8], peer: SocketAddr) -> io::Result<()> {
        if socket.send_to(response, peer)? != response.len() {
            return Err(invalid("partial TCP62 OOB response"));
        }
        Ok(())
    }

    fn poll_association(
        &mut self,
        association: &mut Association,
        can_accept_information: bool,
    ) -> io::Result<(Option<GatewayEvent>, bool)> {
        let mut completed = Vec::new();
        association
            .tcp
            .flush_with_completion(|len| completed.push(len))?;
        for len in completed {
            let (expected, completion) = association
                .writes
                .pop_front()
                .ok_or_else(|| invalid("untracked TCP62 write completion"))?;
            if len != expected {
                return Err(invalid("TCP62 write completion length mismatch"));
            }
            match (&mut association.state, completion) {
                (SessionState::Management(responder), Completion::ManagementConnect(bytes)) => {
                    responder.mark_connect_response_sent(&bytes)?;
                }
                (SessionState::Management(responder), Completion::ManagementCnos(bytes)) => {
                    responder.mark_cnos_reply_sent(&bytes)?;
                }
                (SessionState::Management(responder), Completion::ManagementBis(bytes)) => {
                    responder.mark_bis_reply_sent(&bytes)?;
                }
                (SessionState::UserResponseQueued(offer), Completion::UserConnect) => {
                    association.state = SessionState::UserActive(offer.clone());
                }
                (SessionState::UserActive(_), Completion::UserRecord) => {
                    self.completed_user_records += 1;
                }
                (SessionState::UserActive(_), Completion::TcpExpeditedAck) => {}
                _ => return Err(invalid("TCP62 write completed in wrong gateway phase")),
            }
        }
        if !association.user_inflight {
            if let Some(ack) = association.deferred_logical_ack.take() {
                association.user_inflight = true;
                return Ok((Some(GatewayEvent::UserExpedited(ack)), true));
            }
        }
        // Do not consume normal user data while the WebSocket/native leg has
        // no credit. A later Abort can still be buffered up to MAX_INCOMING.
        if let Some(records) = match association.tcp.receive_once() {
            Ok(records) => records,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok((Some(GatewayEvent::Closed), false));
            }
            Err(error) => return Err(error),
        } {
            for record in records {
                let next = association
                    .incoming_bytes
                    .checked_add(record.bytes.len())
                    .ok_or_else(|| invalid("TCP62 ingress queue overflow"))?;
                if next > MAX_INCOMING {
                    return Err(invalid("TCP62 ingress queue full"));
                }
                association.incoming_bytes = next;
                association.incoming.push_back(record);
            }
        }
        let Some(front) = association.incoming.front() else {
            return Ok((None, true));
        };
        // A peer may pipeline the next record into the same TCP read. The
        // prior reply is not authoritative until its final byte was written.
        if !association.writes.is_empty() && front.kind != TcpKind::Abort {
            return Ok((None, true));
        }
        if association.user_inflight
            || (front.kind == TcpKind::Expedited
                && (association.pending_oob.is_some()
                    || association.pending_tcp_expedited.is_some()))
            || (!can_accept_information
                && matches!(association.state, SessionState::UserActive(_))
                && !matches!(front.kind, TcpKind::Abort | TcpKind::ExpeditedAck))
        {
            return Ok((None, true));
        }
        let record = association.incoming.pop_front().unwrap();
        association.incoming_bytes -= record.bytes.len();
        match &mut association.state {
            SessionState::AwaitConnect => {
                let mut ingress = IngressSession::new(IngressPolicy {
                    source_lu: self.config.source_lu.clone(),
                    destination_lu: self.config.destination_lu.clone(),
                    user_mode: None,
                    allow_blank_user_mode: true,
                    available_compensations: self.config.available_compensations,
                    forbidden_fqpcid: None,
                })?;
                let offer = ingress.receive(&record.bytes)?.clone();
                match offer.kind() {
                    IngressKind::Management => {
                        let admitted = classify_reverse_management_connect(
                            offer.connect().clone(),
                            &self.config.source_lu,
                            &self.config.destination_lu,
                            None,
                        )?;
                        let token = fresh_token()?;
                        let responder = ManagementResponder::new(
                            &admitted,
                            self.config.available_compensations,
                            self.config.options,
                            token,
                            &self.config.cnos_mode,
                            self.config.cnos_limit,
                        )?;
                        let bytes = responder.connect_response().to_vec();
                        association.state = SessionState::Management(responder);
                        Self::queue(
                            association,
                            bytes.clone(),
                            Completion::ManagementConnect(bytes),
                        )?;
                        Ok((None, true))
                    }
                    IngressKind::User { .. }
                        if self.management_ready || self.config.allow_resumed_user =>
                    {
                        association.state = SessionState::UserAwaitResponse(offer.clone());
                        Ok((Some(GatewayEvent::UserBind(offer)), true))
                    }
                    _ => Err(invalid("TCP62 user Connect before management completion")),
                }
            }
            SessionState::Management(responder) => {
                match responder.phase() {
                    ManagementPhase::AwaitCnos => {
                        let bytes = responder.accept_cnos(&record.bytes)?;
                        Self::queue(
                            association,
                            bytes.clone(),
                            Completion::ManagementCnos(bytes),
                        )?;
                    }
                    ManagementPhase::AwaitBis => {
                        let bytes = responder.accept_bis(&record.bytes)?;
                        Self::queue(association, bytes.clone(), Completion::ManagementBis(bytes))?;
                    }
                    ManagementPhase::AwaitUnbind => {
                        responder.accept_unbind(&record.bytes)?;
                        responder.mark_close_sent()?;
                        self.management_ready = true;
                        return Ok((Some(GatewayEvent::ManagementReady), false));
                    }
                    _ => return Err(invalid("TCP62 management input before egress completion")),
                }
                Ok((None, true))
            }
            SessionState::UserAwaitResponse(_) | SessionState::UserResponseQueued(_) => {
                if record.kind == TcpKind::Abort {
                    Ok((Some(GatewayEvent::UserAbort(record)), false))
                } else {
                    Err(invalid("TCP62 user data before native BIND response"))
                }
            }
            SessionState::UserActive(_) => {
                if record.kind == TcpKind::ExpeditedAck {
                    if association.late_tcp_acks_owed != 0 {
                        association.late_tcp_acks_owed -= 1;
                        return Ok((None, true));
                    }
                    let pending = association
                        .outbound_oob
                        .as_mut()
                        .ok_or_else(|| invalid("unsolicited TCP62 expedited ACK"))?;
                    pending.fallback.received_tcp_ack()?;
                    let sequence = pending.sequence;
                    association.outbound_oob = None;
                    remember_completed(&mut association.recent_outbound_completed, sequence);
                }
                if record.kind == TcpKind::Expedited {
                    let mut trial = association.oob.clone();
                    match trial.receive_tcp() {
                        Delivery::Duplicate => {
                            association.oob = trial;
                            Self::queue(
                                association,
                                vec![0, 0, 0, 5, 3],
                                Completion::TcpExpeditedAck,
                            )?;
                            return Ok((None, true));
                        }
                        Delivery::New => association.pending_tcp_expedited = Some(trial),
                    }
                }
                let event = match record.kind {
                    TcpKind::Normal | TcpKind::Segmented => GatewayEvent::UserNormal(record),
                    TcpKind::Expedited | TcpKind::ExpeditedAck => {
                        GatewayEvent::UserExpedited(record)
                    }
                    TcpKind::Abort => GatewayEvent::UserAbort(record),
                    TcpKind::Connect => return Err(invalid("duplicate TCP62 user Connect")),
                };
                association.user_inflight = true;
                Ok((Some(event), true))
            }
        }
    }

    fn queue(
        association: &mut Association,
        bytes: Vec<u8>,
        completion: Completion,
    ) -> io::Result<()> {
        if association.writes.len() >= MAX_WRITES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP62 gateway write queue full",
            ));
        }
        let len = bytes.len();
        association.tcp.queue(TcpRecord::decode(bytes)?)?;
        association.writes.push_back((len, completion));
        Ok(())
    }

    /// Accept the fully encoded TCP62 positive Connect returned only after
    /// the virtual native leg received a correlated +RSP(BIND). `false`
    /// means bounded TCP queue backpressure; caller retains its response.
    pub(crate) fn queue_user_bind_response(&mut self, bytes: &[u8]) -> io::Result<bool> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        let SessionState::UserAwaitResponse(offer) = &association.state else {
            return Err(invalid("no pending TCP62 user BIND"));
        };
        let response = Connect::decode(bytes)?;
        if response.direction != Direction::PositiveResponse
            || !offer.connect().matches_response(&response)
            || validate_positive_response(
                offer.connect().connection_data(),
                response.connection_data(),
            )
            .is_err()
        {
            return Err(invalid("TCP62 user BIND response is stale or invalid"));
        }
        if association.writes.len() >= MAX_WRITES || !association.tcp.has_capacity() {
            return Ok(false);
        }
        let offer = offer.clone();
        Self::queue(association, bytes.to_vec(), Completion::UserConnect)?;
        association.state = SessionState::UserResponseQueued(offer);
        Ok(true)
    }

    /// A user record is accepted only when the virtual native/WS leg has
    /// retained it. This credit permits exactly one next TCP record.
    pub(crate) fn complete_user_record(&mut self) -> io::Result<()> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        if !matches!(association.state, SessionState::UserActive(_)) || !association.user_inflight {
            return Err(invalid("TCP62 user record completion without delivery"));
        }
        association.user_inflight = false;
        Ok(())
    }

    /// Commit an X'83' request only after the virtual native path reports
    /// exact LLC enqueue completion. Retransmissions remain unacknowledged
    /// while that delivery is pending.
    pub(crate) fn complete_udp_expedited(&mut self, sequence: u16) -> io::Result<()> {
        self.complete_udp(sequence, OobCompensation::Expedited)
    }

    /// An X'83' Abort is acknowledged only after native +RSP(UNBIND).
    pub(crate) fn complete_udp_abort(&mut self, sequence: u16) -> io::Result<()> {
        self.complete_udp(sequence, OobCompensation::Abort)?;
        self.active = None;
        Ok(())
    }

    fn complete_udp(&mut self, sequence: u16, compensation: OobCompensation) -> io::Result<()> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        let pending = association
            .pending_oob
            .as_ref()
            .ok_or_else(|| invalid("no pending TCP62 OOB request"))?;
        if pending.sequence != sequence || pending.compensation != compensation {
            return Err(invalid("TCP62 OOB completion sequence mismatch"));
        }
        let trial = pending
            .trial
            .clone()
            .ok_or_else(|| invalid("TCP62 OOB waits for TCP expedited completion"))?;
        Self::send_oob_response(&self.udp, &pending.response, pending.peer)?;
        association.oob = trial;
        association.pending_oob = None;
        Ok(())
    }

    /// TCP expedited reception and a UDP fallback copy share one sequence.
    /// The TCP copy becomes authoritative only after its native enqueue.
    pub(crate) fn complete_tcp_expedited(&mut self) -> io::Result<()> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        let trial = association
            .pending_tcp_expedited
            .take()
            .ok_or_else(|| invalid("no pending TCP expedited delivery"))?;
        if let Some(pending) = &association.pending_oob {
            if pending.trial.is_some() || pending.sequence != association.oob.next_tcp_sequence() {
                return Err(invalid("TCP62 OOB and TCP expedited sequence conflict"));
            }
            Self::send_oob_response(&self.udp, &pending.response, pending.peer)?;
            association.pending_oob = None;
        }
        association.oob = trial;
        Ok(())
    }

    /// Queue one fully converted outbound TCP62 user record. A `false`
    /// result consumes no native/WS credit. Completion is reported only
    /// after the socket accepts the record's final byte.
    pub(crate) fn queue_user_record(&mut self, record: &TcpRecord) -> io::Result<bool> {
        let association = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("no TCP62 user association"))?;
        if !matches!(association.state, SessionState::UserActive(_))
            || record.kind == TcpKind::Connect
            || TcpRecord::decode(record.bytes.clone())?.kind != record.kind
        {
            return Err(invalid("outbound TCP62 user record is not admissible"));
        }
        if association.writes.len() >= MAX_WRITES || !association.tcp.has_capacity() {
            return Ok(false);
        }
        let outbound = if record.kind == TcpKind::Expedited {
            if association.outbound_oob.is_some() {
                return Ok(false);
            }
            let SessionState::UserActive(offer) = &association.state else {
                unreachable!()
            };
            let sequence = association.outbound_sequence;
            let request = build_oob_request(
                offer.connect(),
                sequence,
                OobCompensation::Expedited,
                &record.bytes[5..],
            )?;
            let mut fallback = Fallback::default();
            fallback.sent_tcp_expedited(sequence, Instant::now())?;
            Some(PendingOutboundOob {
                sequence,
                request,
                fallback,
            })
        } else {
            None
        };
        match Self::queue(association, record.bytes.clone(), Completion::UserRecord) {
            Ok(()) => {
                if let Some(pending) = outbound {
                    association.outbound_oob = Some(pending);
                    association.outbound_sequence = association.outbound_sequence.wrapping_add(1);
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn take_completed_user_records(&mut self) -> usize {
        std::mem::take(&mut self.completed_user_records)
    }
}

fn fresh_token() -> io::Result<[u8; 7]> {
    use std::{fs::File, io::Read};
    let mut random = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    if random == [0; 4] {
        return Err(invalid("TCP62 BIND token entropy was zero"));
    }
    Ok([0x23, random[0], random[1], random[2], random[3], 0x80, 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpStream, UdpSocket},
        thread,
        time::Duration,
    };
    use transport_ip_sna::mptn_management_initiator::ManagementInitiator;

    fn request() -> ManagementInitiator {
        let source = [0xd8, 0xc1, 0xc2, 0xd6, 0xc2, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2];
        let mut fqpcid = vec![0x60, 19];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(10);
        fqpcid.extend_from_slice(&source);
        ManagementInitiator::new(
            "QABOB.SNAB",
            "QAALICE.SNAA",
            fqpcid,
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap()
    }

    fn peer_socket(address: SocketAddr) -> TcpStream {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket
            .bind(&SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 0).into())
            .unwrap();
        socket.connect(&address.into()).unwrap();
        socket.into()
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn oob_request(connect: &Connect, sequence: u16) -> Vec<u8> {
        let mut bytes = vec![0; 4];
        bytes.extend_from_slice(&[0x83, 0x02, 0, 0, 0, 0]);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&[0x0b, 0x01, (connect.source.node.len() + 1) as u8]);
        bytes.extend_from_slice(&connect.source.node);
        bytes.push(1);
        bytes.push((connect.correlator.len() + 1) as u8);
        bytes.extend_from_slice(&connect.correlator);
        let command_len = (bytes.len() - 4) as u32;
        bytes[6..10].copy_from_slice(&command_len.to_be_bytes());
        bytes.extend_from_slice(&[1, 0, 0x83, 1, 0, 0]);
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        bytes
    }

    #[test]
    fn udp_expedited_ack_waits_for_native_delivery_and_deduplicates_retry() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut client = peer_socket(port.listener.local_addr().unwrap());
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (stream, _) = port.listener.accept().unwrap();
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            user_mode: None,
            allow_blank_user_mode: false,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        let offer = ingress
            .receive(request().connect_request())
            .unwrap()
            .clone();
        let datagram = oob_request(offer.connect(), 0);
        let fallback = oob_request(offer.connect(), 1);
        let mut abort = oob_request(offer.connect(), 2);
        let abort_header = 4 + u32::from_be_bytes(abort[6..10].try_into().unwrap()) as usize;
        abort[abort_header] = 0x10;
        port.active = Some(Association {
            tcp: TcpSession::new(stream).unwrap(),
            state: SessionState::UserActive(offer),
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            user_inflight: false,
            oob: SequenceWindow::default(),
            pending_oob: None,
            pending_tcp_expedited: None,
            outbound_sequence: 0,
            outbound_oob: None,
            recent_outbound_completed: VecDeque::new(),
            late_tcp_acks_owed: 0,
            deferred_logical_ack: None,
        });
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.send_to(&datagram, port.udp.local_addr().unwrap())
            .unwrap();
        let event = port.poll_once(true).unwrap().unwrap();
        assert!(matches!(
            event,
            GatewayEvent::UserUdpExpedited { sequence: 0, .. }
        ));
        let mut output = [0; MAX_RECORD];
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(port.complete_udp_expedited(1).is_err());
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        port.complete_udp_expedited(0).unwrap();
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().kind,
            OobKind::PositiveResponse
        );
        peer.send_to(&datagram, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().sequence,
            0
        );
        let tcp_expedited = [0, 0, 0, 10, 1, 0, 0x83, 1, 0, 0];
        client.write_all(&tcp_expedited).unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        port.poll_once(true).unwrap();
        let mut tcp_ack = [0; 5];
        client.read_exact(&mut tcp_ack).unwrap();
        assert_eq!(tcp_ack, [0, 0, 0, 5, 3]);
        client.write_all(&tcp_expedited).unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserExpedited(_))
        ));
        port.complete_user_record().unwrap();
        peer.send_to(&fallback, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        port.complete_tcp_expedited().unwrap();
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().sequence,
            1
        );
        peer.send_to(&abort, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserUdpAbort { sequence: 2, .. })
        ));
        assert_eq!(
            peer.recv(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(port.complete_udp_expedited(2).is_err());
        port.complete_udp_abort(2).unwrap();
        let received = peer.recv(&mut output).unwrap();
        assert_eq!(
            OobDatagram::decode(&output[..received]).unwrap().sequence,
            2
        );
        assert!(port.active.is_none());
    }

    #[test]
    fn resumed_qa_user_connect_is_held_for_native_bind_response() {
        // Sanitized byte shape from Bob's autonomous user Connect. The
        // BIND's variable LU lengths are 10 (QABOB) and 12 (QAALICE).
        let request = hex(concat!(
            "000000e4800a00e02a0b010dd8c1c1d3c9c3c54be2d5c1c1010b010bd8c1c2d6c24be2d5c1c201",
            "09b023f6611b4500000f00008005000000760000007620000508000601010a02008b00006b80003100",
            "1307b0b0513303838c8c8303060200000000000000944300000ad8c1c2d6c24be2d5c1c22c0009",
            "02404040404040404009030123f661184500000b04d8c1c2d6c24be2d5c1c20a1300b023f66118",
            "450000000cd8c1c1d3c9c3c54be2d5c1c16013e8e772dd240702490ad8c1c2d6c24be2d5c1c2",
            "2c0a01087bc3d6d5d5c5c3e31800000501190a000a0020010310831a00000584"
        ));
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })
        .unwrap();
        let mut client = peer_socket(port.listener.local_addr().unwrap());
        client.write_all(&request).unwrap();
        let event = (0..1000)
            .find_map(|_| {
                let event = port.poll_once(true).unwrap();
                if event.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                event
            })
            .expect("user offer");
        assert!(matches!(event, GatewayEvent::UserBind(_)));
        assert!(!port.management_ready());
        assert!(!port.user_active());
        client.set_nonblocking(true).unwrap();
        let mut output = [0; 1];
        assert_eq!(
            client.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(client);
        port.active = None;
        port.config.allow_resumed_user = false;
        let mut next = peer_socket(port.listener.local_addr().unwrap());
        next.write_all(&request).unwrap();
        let denied = (0..1000)
            .find_map(|_| {
                let event = port.poll_once(true).unwrap();
                if event.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                event
            })
            .expect("default rejection");
        assert!(matches!(denied, GatewayEvent::Rejected(_)));
    }

    #[test]
    fn captured_shape_keepalive_replies_only_to_configured_pair() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: true,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let request = Keepalive {
            kind: KeepaliveKind::Request,
            source: Ipv4Addr::new(127, 0, 0, 2),
            destination: Ipv4Addr::LOCALHOST,
        }
        .encode();
        peer.send_to(&request, port.udp.local_addr().unwrap())
            .unwrap();
        port.poll_once(false).unwrap();
        let mut response = [0u8; 24];
        let (len, from) = peer.recv_from(&mut response).unwrap();
        assert_eq!(len, 24);
        assert_eq!(from, port.udp.local_addr().unwrap());
        assert_eq!(
            Keepalive::decode(&response).unwrap().kind,
            KeepaliveKind::Response
        );
        assert!(!port.management_ready());
    }

    #[test]
    fn production_default_rejects_v5_without_oob_handler() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let address = port.listener.local_addr().unwrap();
        let mut client = peer_socket(address);
        client.write_all(request().connect_request()).unwrap();
        let mut rejected = false;
        for _ in 0..1000 {
            if let Some(GatewayEvent::Rejected(reason)) = port.poll_once(true).unwrap() {
                assert!(reason.contains("compensation"));
                rejected = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(rejected);
        assert!(!port.management_ready());
        assert!(port.active.is_none());
    }

    #[test]
    fn outbound_user_credit_waits_for_socket_write_completion() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let address = port.listener.local_addr().unwrap();
        let mut client = peer_socket(address);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (stream, _) = port.listener.accept().unwrap();
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            user_mode: None,
            allow_blank_user_mode: false,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        // The offer is only a state placeholder here; this test isolates
        // actual TCP delivery credit from BIND conversion.
        let offer = ingress
            .receive(request().connect_request())
            .unwrap()
            .clone();
        port.active = Some(Association {
            tcp: TcpSession::new(stream).unwrap(),
            state: SessionState::UserActive(offer),
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            user_inflight: false,
            oob: SequenceWindow::default(),
            pending_oob: None,
            pending_tcp_expedited: None,
            outbound_sequence: 0,
            outbound_oob: None,
            recent_outbound_completed: VecDeque::new(),
            late_tcp_acks_owed: 0,
            deferred_logical_ack: None,
        });
        let record = TcpRecord::decode(vec![0, 0, 0, 8, 0, 0, 1, 2]).unwrap();
        assert!(port.queue_user_record(&record).unwrap());
        assert_eq!(port.take_completed_user_records(), 0);
        port.poll_once(true).unwrap();
        assert_eq!(port.take_completed_user_records(), 1);
        assert_eq!(port.take_completed_user_records(), 0);
        let mut received = [0u8; 8];
        use std::io::Read;
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, record.bytes.as_slice());
        let expedited = TcpRecord::decode(vec![0, 0, 0, 10, 1, 0, 0x83, 1, 0, 0]).unwrap();
        let start = Instant::now();
        assert!(port.queue_user_record(&expedited).unwrap());
        let mut datagrams = Vec::new();
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            start + Duration::from_secs(4),
            |bytes, peer| {
                datagrams.push((bytes.to_vec(), peer));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].1, "127.0.0.2:397".parse().unwrap());
        let first = OobDatagram::decode(&datagrams[0].0).unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(first.compensation, Some(OobCompensation::Expedited));
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            start + Duration::from_secs(15),
            |bytes, peer| {
                datagrams.push((bytes.to_vec(), peer));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(datagrams.len(), 2);
        assert_eq!(datagrams[0], datagrams[1]);
        client.write_all(&[0, 0, 0, 5, 3]).unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserExpedited(_))
        ));
        port.complete_user_record().unwrap();
        let mut late = Vec::new();
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            start + Duration::from_secs(40),
            |bytes, _| {
                late.push(bytes.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert!(late.is_empty());
    }

    #[test]
    fn udp_positive_acknowledges_once_and_late_tcp_ack_precedes_next_sequence() {
        let mut port = MptnGatewayPort::bind(GatewayConfig {
            local: "127.0.0.1:0".parse().unwrap(),
            peer_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            available_compensations: CompensationSet::default(),
            options: V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: false,
        })
        .unwrap();
        let mut client = peer_socket(port.listener.local_addr().unwrap());
        let (stream, _) = port.listener.accept().unwrap();
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "QABOB.SNAB".into(),
            destination_lu: "QAALICE.SNAA".into(),
            user_mode: None,
            allow_blank_user_mode: false,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        let offer = ingress
            .receive(request().connect_request())
            .unwrap()
            .clone();
        port.active = Some(Association {
            tcp: TcpSession::new(stream).unwrap(),
            state: SessionState::UserActive(offer),
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            user_inflight: false,
            oob: SequenceWindow::default(),
            pending_oob: None,
            pending_tcp_expedited: None,
            outbound_sequence: 0,
            outbound_oob: None,
            recent_outbound_completed: VecDeque::new(),
            late_tcp_acks_owed: 0,
            deferred_logical_ack: None,
        });
        let expedited = TcpRecord::decode(vec![0, 0, 0, 10, 1, 0, 0x83, 1, 0, 0]).unwrap();
        assert!(port.queue_user_record(&expedited).unwrap());
        MptnGatewayPort::poll_outbound_fallback_at(
            &mut port.active,
            port.config.peer_ip,
            Instant::now() + Duration::from_secs(4),
            |_, _| Ok(()),
        )
        .unwrap();
        let request = port
            .active
            .as_ref()
            .unwrap()
            .outbound_oob
            .as_ref()
            .unwrap()
            .request
            .clone();
        let response = OobDatagram::decode(&request)
            .unwrap()
            .positive_response()
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.send_to(&response, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(
            matches!(port.poll_once(true).unwrap(), Some(GatewayEvent::UserExpedited(ref record)) if record.bytes == [0,0,0,5,3])
        );
        port.complete_user_record().unwrap();
        assert_eq!(port.active.as_ref().unwrap().late_tcp_acks_owed, 1);
        assert!(port.queue_user_record(&expedited).unwrap());
        client.write_all(&[0, 0, 0, 5, 3]).unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        assert_eq!(port.active.as_ref().unwrap().late_tcp_acks_owed, 0);
        assert!(port.active.as_ref().unwrap().outbound_oob.is_some());
        client.write_all(&[0, 0, 0, 5, 3]).unwrap();
        assert!(matches!(
            port.poll_once(true).unwrap(),
            Some(GatewayEvent::UserExpedited(_))
        ));
        port.complete_user_record().unwrap();
        assert!(port.active.as_ref().unwrap().outbound_oob.is_none());
        peer.send_to(&response, port.udp.local_addr().unwrap())
            .unwrap();
        assert!(port.poll_once(true).unwrap().is_none());
        assert!(port.active.is_some());
    }
}
