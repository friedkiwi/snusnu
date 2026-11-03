//! One EE-originated user session to a selected local TCP62/MPTN peer.
//!
//! The gateway lends its UDP/397 socket exclusively to this session. Native
//! management and the TCP dial run on a worker so the EE receive loop stays
//! responsive. Socket records are leased to the fabric until confirmation.

use crate::{
    hpr_local_llc::offer_from_bind,
    mptn_outbound_port::{OutboundEndpoint, OutboundUdp, OutboundUdpAction},
};
use router_core::session::{Flow, SessionEvent, SessionIdentity, SessionUnit};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read},
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_bind_negotiation::validate_positive_response,
    mptn_connect::{Connect, Direction},
    mptn_oob::{build_request, Compensation, Datagram, Kind},
    mptn_session_unit::{normal_record_to_unit, unit_to_normal_record},
};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

enum Phase {
    Connecting,
    Ready,
    AwaitBind,
    Bound,
    Closed,
}

enum PendingSource {
    Tcp,
    Udp { sequence: u16, peer: SocketAddr },
    LocalAbort,
}

struct PendingEvent {
    event: SessionEvent,
    source: PendingSource,
}

struct PendingAbort {
    packet: Vec<u8>,
    snf: [u8; 2],
    last_sent: Instant,
    retries: u8,
    sequence: u16,
}

/// The owning gateway must hold the UDP lease until this object is closed or
/// dropped, then call `AutoMptnGateway::release_udp`.
pub(crate) struct HprToMptnSession {
    endpoint: OutboundEndpoint,
    peer_udp_port: u16,
    udp: UdpSocket,
    connect: Connect,
    oob: OutboundUdp,
    bind: SessionUnit,
    phase: Phase,
    connected: Receiver<io::Result<TcpSession>>,
    worker: Option<JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
    tcp: Option<TcpSession>,
    incoming: VecDeque<TcpRecord>,
    incoming_bytes: usize,
    pending: Option<PendingEvent>,
    pending_abort: Option<PendingAbort>,
    pending_udp_reply: Option<(Vec<u8>, SocketAddr)>,
    next_oob_sequence: u16,
    expedited_ack_pending: bool,
    outbound_expedited_sent_at: Option<Instant>,
    native_abort_snf: Option<[u8; 2]>,
    recent_expedited: VecDeque<Vec<u8>>,
}

impl HprToMptnSession {
    pub(crate) fn new(
        endpoint: OutboundEndpoint,
        udp: UdpSocket,
        identity: &SessionIdentity,
        bind: &SessionUnit,
        timeout: Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(600) {
            return Err(invalid("MPTN setup timeout is invalid"));
        }
        if identity.source_lu == identity.target_lu
            || identity
                .source_cp
                .as_ref()
                .is_some_and(|cp| cp.netid != identity.source_lu.netid)
            || identity
                .target_cp
                .as_ref()
                .is_some_and(|cp| cp.netid != identity.target_lu.netid)
        {
            return Err(invalid("MPTN route has inconsistent LU or CP identity"));
        }
        if udp.local_addr()? != SocketAddr::new(endpoint.local_ip, 397) {
            return Err(invalid(
                "MPTN UDP socket does not belong to selected gateway",
            ));
        }
        udp.set_nonblocking(true)?;
        let mut correlator = [0u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut correlator)?;
        correlator[0] |= 1;
        let offer = offer_from_bind(
            bind,
            &identity.source_lu.to_string(),
            &identity.target_lu.to_string(),
            correlator,
        )?;
        let connect = offer.connect().clone();
        let oob = OutboundUdp::new(endpoint, connect.clone())?;
        let (tx, connected) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let source_lu = identity.source_lu.to_string();
        let target_lu = identity.target_lu.to_string();
        let worker = thread::Builder::new()
            .name("sna-ee-mptn-connect".into())
            .spawn(move || {
                let result = endpoint
                    .establish_v5_management(
                        timeout.min(Duration::from_secs(5)),
                        &source_lu,
                        &target_lu,
                    )
                    .and_then(|()| {
                        if worker_cancel.load(Ordering::Relaxed) {
                            Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "MPTN route cancelled",
                            ))
                        } else {
                            endpoint.dial(timeout)
                        }
                    });
                let _ = tx.send(result);
            })?;
        Ok(Self {
            endpoint,
            peer_udp_port: 397,
            udp,
            connect,
            oob,
            bind: bind.clone(),
            phase: Phase::Connecting,
            connected,
            worker: Some(worker),
            cancel,
            tcp: None,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            pending: None,
            pending_abort: None,
            pending_udp_reply: None,
            next_oob_sequence: 1,
            expedited_ack_pending: false,
            outbound_expedited_sent_at: None,
            native_abort_snf: None,
            recent_expedited: VecDeque::new(),
        })
    }

    fn progress(&mut self) -> io::Result<()> {
        if let Some((reply, peer)) = &self.pending_udp_reply {
            match self.udp.send_to(reply, *peer) {
                Ok(n) if n == reply.len() => self.pending_udp_reply = None,
                Ok(_) => return Err(invalid("partial MPTN UDP acknowledgement")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        if matches!(self.phase, Phase::Connecting) {
            match self.connected.try_recv() {
                Ok(result) => {
                    self.tcp = Some(result?);
                    self.phase = Phase::Ready;
                    if let Some(worker) = self.worker.take() {
                        worker
                            .join()
                            .map_err(|_| io::Error::other("MPTN setup worker panicked"))?;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => return Ok(()),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other(
                        "MPTN setup worker exited without a result",
                    ))
                }
            }
        }
        if let Some(tcp) = &mut self.tcp {
            tcp.flush()?;
            if self.incoming_bytes < MAX_RECORD {
                if let Some(records) = tcp.receive_once()? {
                    let bytes = records
                        .iter()
                        .map(|record| record.bytes.len())
                        .sum::<usize>();
                    if self.incoming_bytes + bytes > MAX_RECORD * 2 {
                        return Err(invalid("MPTN inbound record queue full"));
                    }
                    self.incoming_bytes += bytes;
                    self.incoming.extend(records);
                }
            }
        }
        if self
            .outbound_expedited_sent_at
            .is_some_and(|sent| sent.elapsed() > Duration::from_secs(5))
            && !self
                .incoming
                .iter()
                .any(|record| record.kind == TcpKind::ExpeditedAck)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MPTN TCP expedited acknowledgement timed out",
            ));
        }
        if self.expedited_ack_pending {
            if let Some(tcp) = &mut self.tcp {
                let ack = TcpRecord::decode(vec![0, 0, 0, 5, 3])?;
                if tcp.has_capacity() {
                    tcp.queue(ack)?;
                    self.expedited_ack_pending = false;
                }
            }
        }
        if let Some(abort) = &mut self.pending_abort {
            if abort.last_sent.elapsed() >= Duration::from_secs(1) {
                if abort.retries >= 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "MPTN UNBIND acknowledgement timed out",
                    ));
                }
                let peer = SocketAddr::new(self.endpoint.peer_ip, self.peer_udp_port);
                match self.udp.send_to(&abort.packet, peer) {
                    Ok(n) if n == abort.packet.len() => {
                        abort.retries += 1;
                        abort.last_sent = Instant::now();
                    }
                    Ok(_) => return Err(invalid("partial MPTN OOB send")),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// Returns false when the selected MPTN carrier has not yet admitted the
    /// exact event; the caller must re-offer the same lease later.
    pub(crate) fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        self.progress()?;
        match event {
            SessionEvent::BindRequest(unit) => {
                if unit != &self.bind {
                    return Err(invalid("MPTN BIND differs from selected EE route"));
                }
                if !matches!(self.phase, Phase::Ready) {
                    return Ok(false);
                }
                let record = TcpRecord::decode(self.connect.encode()?)?;
                match self.tcp.as_mut().unwrap().queue(record) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(error) => return Err(error),
                }
                self.phase = Phase::AwaitBind;
                Ok(true)
            }
            SessionEvent::Information { flow, unit } if matches!(self.phase, Phase::Bound) => {
                if *flow == Flow::Expedited && self.outbound_expedited_sent_at.is_some() {
                    return Ok(false);
                }
                let mut record = unit_to_normal_record(unit)?;
                if *flow == Flow::Expedited {
                    record.bytes[4] = 1;
                    record = TcpRecord::decode(record.bytes)?;
                }
                match self.tcp.as_mut().unwrap().queue(record) {
                    Ok(()) => {
                        if *flow == Flow::Expedited {
                            self.outbound_expedited_sent_at = Some(Instant::now());
                        }
                        Ok(true)
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                    Err(error) => Err(error),
                }
            }
            SessionEvent::Credit { .. } => Ok(matches!(self.phase, Phase::Bound)),
            SessionEvent::Unbind(unit)
                if matches!(self.phase, Phase::Bound) && unit.rh()[0] & 0x80 == 0 =>
            {
                if unit.ru().first() != Some(&0x32) {
                    return Err(invalid("MPTN UNBIND request has wrong RU"));
                }
                if self.pending_abort.is_some() {
                    return Ok(false);
                }
                let sequence = self.next_oob_sequence;
                let mut reduced = unit.as_reduced().to_vec();
                reduced[..2].fill(0);
                let packet = build_request(&self.connect, sequence, Compensation::Abort, &reduced)?;
                let peer = SocketAddr::new(self.endpoint.peer_ip, self.peer_udp_port);
                match self.udp.send_to(&packet, peer) {
                    Ok(n) if n == packet.len() => {}
                    Ok(_) => return Err(invalid("partial MPTN OOB send")),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(error) => return Err(error),
                }
                self.next_oob_sequence = sequence.wrapping_add(1);
                self.pending_abort = Some(PendingAbort {
                    packet,
                    snf: unit.snf().try_into().unwrap(),
                    last_sent: Instant::now(),
                    retries: 0,
                    sequence,
                });
                Ok(true)
            }
            SessionEvent::Unbind(unit) if unit.rh()[0] & 0x80 != 0 => {
                if self.native_abort_snf.as_ref().map(|snf| snf.as_slice()) != Some(unit.snf()) {
                    return Err(invalid("MPTN UNBIND response has wrong SNF"));
                }
                self.native_abort_snf = None;
                self.phase = Phase::Closed;
                Ok(true)
            }
            SessionEvent::Reset => {
                self.phase = Phase::Closed;
                self.cancel.store(true, Ordering::Relaxed);
                self.tcp.take();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Return one result repeatedly until `confirm_polled` accepts it.
    pub(crate) fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
        if let Some(pending) = &self.pending {
            return Ok(Some(pending.event.clone()));
        }
        if matches!(self.phase, Phase::Closed) {
            self.progress()?;
            return Ok(None);
        }
        self.progress()?;
        if let Some(record) = self.incoming.front() {
            let event = match record.kind {
                TcpKind::Connect if matches!(self.phase, Phase::AwaitBind) => {
                    let response = Connect::decode(&record.bytes)?;
                    if !self.connect.matches_response(&response) {
                        return Err(invalid("MPTN Connect response identity mismatch"));
                    }
                    let accepted = match response.direction {
                        Direction::PositiveResponse => true,
                        Direction::NegativeResponse => false,
                        Direction::Request => {
                            return Err(invalid("MPTN Connect returned a request"))
                        }
                    };
                    if accepted {
                        validate_positive_response(
                            self.connect.connection_data(),
                            response.connection_data(),
                        )
                        .map_err(io::Error::other)?;
                    }
                    let mut reduced = response.connection_data().to_vec();
                    if reduced.len() < 5 {
                        return Err(invalid("MPTN BIND response truncated"));
                    }
                    reduced[..2].copy_from_slice(self.bind.snf());
                    SessionEvent::BindResult {
                        accepted,
                        unit: SessionUnit::from_reduced(&reduced).map_err(io::Error::other)?,
                    }
                }
                TcpKind::Normal | TcpKind::Expedited if matches!(self.phase, Phase::Bound) => {
                    let mut normal = record.clone();
                    normal.bytes[4] = 0;
                    normal.kind = TcpKind::Normal;
                    SessionEvent::Information {
                        flow: if record.kind == TcpKind::Expedited {
                            Flow::Expedited
                        } else {
                            Flow::Normal
                        },
                        unit: normal_record_to_unit(&normal)?,
                    }
                }
                TcpKind::ExpeditedAck => {
                    if self.outbound_expedited_sent_at.take().is_none() {
                        return Err(invalid("unsolicited MPTN expedited acknowledgement"));
                    }
                    let ack = self.incoming.pop_front().unwrap();
                    self.incoming_bytes -= ack.bytes.len();
                    return self.poll();
                }
                TcpKind::Abort => SessionEvent::Reset,
                _ => return Err(invalid("MPTN record arrived in wrong session phase")),
            };
            if let SessionEvent::Information {
                flow: Flow::Expedited,
                ref unit,
            } = event
            {
                if self
                    .recent_expedited
                    .iter()
                    .any(|seen| seen == unit.as_reduced())
                {
                    let duplicate = self.incoming.pop_front().unwrap();
                    self.incoming_bytes -= duplicate.bytes.len();
                    self.expedited_ack_pending = true;
                    return self.poll();
                }
            }
            self.pending = Some(PendingEvent {
                event: event.clone(),
                source: PendingSource::Tcp,
            });
            return Ok(Some(event));
        }
        let mut packet = [0u8; MAX_RECORD];
        match self.udp.recv_from(&mut packet) {
            Ok((length, peer)) => {
                if let Some(abort) = &self.pending_abort {
                    if peer.ip() == self.endpoint.peer_ip && packet.get(4) == Some(&0x83) {
                        let reply = Datagram::decode(&packet[..length])?;
                        if reply.sequence == abort.sequence
                            && reply.kind != Kind::Request
                            && reply.matches_connect(&self.connect)
                        {
                            if reply.kind != Kind::PositiveResponse {
                                return Err(invalid("MPTN UNBIND rejected"));
                            }
                            let snf = abort.snf;
                            self.pending_abort = None;
                            let mut reduced = snf.to_vec();
                            reduced.extend_from_slice(&[0xeb, 0x80, 0, 0x32]);
                            let event = SessionEvent::Unbind(
                                SessionUnit::from_reduced(&reduced).map_err(io::Error::other)?,
                            );
                            self.pending = Some(PendingEvent {
                                event: event.clone(),
                                source: PendingSource::LocalAbort,
                            });
                            return Ok(Some(event));
                        }
                    }
                }
                let action = match self.oob.receive(&packet[..length], peer) {
                    Ok(action) => action,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::PermissionDenied
                                | io::ErrorKind::InvalidData
                                | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        tracing::debug!(peer = %peer, error = %error, "unmatched MPTN UDP packet dropped");
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
                match action {
                    OutboundUdpAction::Reply(reply) => match self.udp.send_to(&reply, peer) {
                        Ok(n) if n == reply.len() => {}
                        Ok(_) => return Err(invalid("partial MPTN UDP acknowledgement")),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            self.pending_udp_reply = Some((reply, peer))
                        }
                        Err(error) => return Err(error),
                    },
                    OutboundUdpAction::PendingDuplicate => {}
                    OutboundUdpAction::Deliver {
                        sequence,
                        compensation,
                        reduced,
                    } => {
                        if compensation == Compensation::Expedited
                            && self.recent_expedited.iter().any(|seen| seen == &reduced)
                        {
                            self.oob.mark_native_submitted(sequence)?;
                            let (reply, target) = self.oob.complete_native_delivery(sequence)?;
                            self.send_or_hold_udp_reply(reply, target)?;
                            return Ok(None);
                        }
                        let event = match compensation {
                            Compensation::Expedited => SessionEvent::Information {
                                flow: Flow::Expedited,
                                unit: SessionUnit::from_reduced(&reduced)
                                    .map_err(io::Error::other)?,
                            },
                            Compensation::Abort if reduced.is_empty() => SessionEvent::Reset,
                            Compensation::Abort => {
                                let unit = SessionUnit::from_reduced(&reduced)
                                    .map_err(io::Error::other)?;
                                if unit.ru().first() != Some(&0x32) {
                                    return Err(invalid("MPTN OOB abort has wrong UNBIND RU"));
                                }
                                SessionEvent::Unbind(unit)
                            }
                        };
                        self.pending = Some(PendingEvent {
                            event: event.clone(),
                            source: PendingSource::Udp { sequence, peer },
                        });
                        return Ok(Some(event));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        Ok(None)
    }

    pub(crate) fn confirm_polled(&mut self) -> io::Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| invalid("no MPTN event to confirm"))?;
        match pending.source {
            PendingSource::Tcp => {
                let record = self
                    .incoming
                    .pop_front()
                    .ok_or_else(|| invalid("MPTN record lease missing"))?;
                self.incoming_bytes -= record.bytes.len();
                match pending.event {
                    SessionEvent::BindResult { accepted, .. } => {
                        self.phase = if accepted {
                            Phase::Bound
                        } else {
                            Phase::Closed
                        }
                    }
                    SessionEvent::Information {
                        flow: Flow::Expedited,
                        ref unit,
                    } => {
                        self.expedited_ack_pending = true;
                        self.remember_expedited(unit);
                    }
                    SessionEvent::Reset => self.phase = Phase::Closed,
                    _ => {}
                }
                debug_assert!(matches!(
                    record.kind,
                    TcpKind::Connect | TcpKind::Normal | TcpKind::Expedited | TcpKind::Abort
                ));
            }
            PendingSource::Udp { sequence, peer } => {
                self.oob.mark_native_submitted(sequence)?;
                let (reply, target) = self.oob.complete_native_delivery(sequence)?;
                if target != peer {
                    return Err(invalid("MPTN UDP lease peer changed"));
                }
                self.send_or_hold_udp_reply(reply, target)?;
                match pending.event {
                    SessionEvent::Information {
                        flow: Flow::Expedited,
                        ref unit,
                    } => self.remember_expedited(unit),
                    SessionEvent::Unbind(ref unit) => {
                        self.native_abort_snf = Some(unit.snf().try_into().unwrap())
                    }
                    SessionEvent::Reset => self.phase = Phase::Closed,
                    _ => {}
                }
            }
            PendingSource::LocalAbort => self.phase = Phase::Closed,
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) {
        self.phase = Phase::Closed;
        self.cancel.store(true, Ordering::Relaxed);
        self.tcp.take();
    }

    fn remember_expedited(&mut self, unit: &SessionUnit) {
        if self.recent_expedited.len() == 64 {
            self.recent_expedited.pop_front();
        }
        self.recent_expedited.push_back(unit.as_reduced().to_vec());
    }

    fn send_or_hold_udp_reply(&mut self, reply: Vec<u8>, target: SocketAddr) -> io::Result<()> {
        match self.udp.send_to(&reply, target) {
            Ok(n) if n == reply.len() => Ok(()),
            Ok(_) => Err(invalid("partial MPTN UDP acknowledgement")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if self.pending_udp_reply.is_some() {
                    return Err(invalid("MPTN UDP acknowledgement queue full"));
                }
                self.pending_udp_reply = Some((reply, target));
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for HprToMptnSession {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
    };
    use transport_ip_sna::mptn_session::connect_template_for_route;

    fn session(udp: UdpSocket, phase: Phase, tcp: Option<TcpSession>) -> HprToMptnSession {
        udp.set_nonblocking(true).unwrap();
        let endpoint = OutboundEndpoint {
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.2".parse().unwrap(),
        };
        let connect = connect_template_for_route("SOLNET.SNAB", "SNUSNU.PING", [1; 8]).unwrap();
        let oob = OutboundUdp::new(endpoint, connect.clone()).unwrap();
        let (_, connected) = mpsc::sync_channel(1);
        HprToMptnSession {
            endpoint,
            peer_udp_port: 397,
            udp,
            connect,
            oob,
            bind: SessionUnit::from_reduced(&[0, 7, 0x6b, 0x80, 0, 0x31]).unwrap(),
            phase,
            connected,
            worker: None,
            cancel: Arc::new(AtomicBool::new(false)),
            tcp,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            pending: None,
            pending_abort: None,
            pending_udp_reply: None,
            next_oob_sequence: 1,
            expedited_ack_pending: false,
            outbound_expedited_sent_at: None,
            native_abort_snf: None,
            recent_expedited: VecDeque::new(),
        }
    }

    #[test]
    fn tcp_bind_result_is_leased_until_fabric_confirms_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut session = session(udp, Phase::Ready, Some(TcpSession::new(client).unwrap()));
        let bind = session.bind.clone();
        assert!(session.send(&SessionEvent::BindRequest(bind)).unwrap());
        session.progress().unwrap();
        let mut len = [0u8; 4];
        peer.read_exact(&mut len).unwrap();
        let mut request = vec![0u8; u32::from_be_bytes(len) as usize];
        request[..4].copy_from_slice(&len);
        peer.read_exact(&mut request[4..]).unwrap();
        let request = Connect::decode(&request).unwrap();
        assert_eq!(request.direction, Direction::Request);
        let mut response = request.clone();
        response.direction = Direction::NegativeResponse;
        response.processing = 0xca;
        response
            .options
            .iter_mut()
            .find(|option| option.kind == 0x0a)
            .unwrap()
            .value = vec![0, 0, 0xeb, 0x80, 0, 0x31];
        peer.write_all(&response.encode().unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let event = loop {
            if let Some(event) = session.poll().unwrap() {
                break event;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert!(matches!(
            event,
            SessionEvent::BindResult {
                accepted: false,
                ..
            }
        ));
        assert_eq!(session.poll().unwrap(), Some(event));
        session.confirm_polled().unwrap();
        assert!(matches!(session.phase, Phase::Closed));
    }

    #[test]
    fn udp_expedited_ack_waits_for_fabric_confirmation() {
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut session = session(local, Phase::Bound, None);
        let packet = build_request(
            &session.connect,
            42,
            Compensation::Expedited,
            &[0, 1, 3, 0, 0, 0xc9],
        )
        .unwrap();
        peer.send_to(&packet, session.udp.local_addr().unwrap())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let event = loop {
            if let Some(event) = session.poll().unwrap() {
                break event;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert!(matches!(
            event,
            SessionEvent::Information {
                flow: Flow::Expedited,
                ..
            }
        ));
        assert_eq!(session.poll().unwrap(), Some(event));
        let mut response = [0u8; 64];
        assert_eq!(
            peer.recv_from(&mut response).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        session.confirm_polled().unwrap();
        let (length, _) = peer.recv_from(&mut response).unwrap();
        let ack = Datagram::decode(&response[..length]).unwrap();
        assert_eq!(ack.kind, Kind::PositiveResponse);
        assert_eq!(ack.sequence, 42);
        // The same expedited unit can be retransmitted on the TCP carrier.
        // It must be acknowledged there without a second fabric delivery.
        let mut duplicate = vec![0, 0, 0, 11, 1];
        duplicate.extend_from_slice(&[0, 1, 3, 0, 0, 0xc9]);
        let duplicate = TcpRecord::decode(duplicate).unwrap();
        session.incoming_bytes += duplicate.bytes.len();
        session.incoming.push_back(duplicate);
        assert_eq!(session.poll().unwrap(), None);
        assert!(session.expedited_ack_pending);
    }

    #[test]
    fn outbound_unbind_uses_correlated_udp_abort_and_replies_once() {
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.2:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut session = session(local, Phase::Bound, None);
        session.peer_udp_port = peer.local_addr().unwrap().port();
        let unbind = SessionUnit::from_reduced(&[0, 7, 0x6b, 0x80, 0, 0x32]).unwrap();
        assert!(session.send(&SessionEvent::Unbind(unbind)).unwrap());
        let mut request = [0u8; 256];
        let (length, source) = peer.recv_from(&mut request).unwrap();
        let abort = Datagram::decode(&request[..length]).unwrap();
        assert_eq!(abort.kind, Kind::Request);
        assert_eq!(abort.compensation, Some(Compensation::Abort));
        assert!(abort.matches_connect(&session.connect));
        peer.send_to(&abort.positive_response().unwrap(), source)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let event = loop {
            if let Some(event) = session.poll().unwrap() {
                break event;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        let SessionEvent::Unbind(result) = &event else {
            panic!("expected UNBIND response");
        };
        assert_eq!(result.as_reduced(), &[0, 7, 0xeb, 0x80, 0, 0x32]);
        assert_eq!(session.poll().unwrap(), Some(event));
        session.confirm_polled().unwrap();
        assert!(matches!(session.phase, Phase::Closed));
    }

    #[test]
    fn tcp_expedited_requires_its_exact_ack_before_next_send() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut session = session(udp, Phase::Bound, Some(TcpSession::new(client).unwrap()));
        let unit = SessionUnit::from_reduced(&[0, 1, 3, 0, 0, 0xc9]).unwrap();
        let event = SessionEvent::Information {
            flow: Flow::Expedited,
            unit,
        };
        assert!(session.send(&event).unwrap());
        assert!(!session.send(&event).unwrap());
        let mut record = [0u8; 11];
        peer.read_exact(&mut record).unwrap();
        assert_eq!(record[4], 1);
        peer.write_all(&[0, 0, 0, 5, 3]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while session.outbound_expedited_sent_at.is_some() {
            assert!(session.poll().unwrap().is_none());
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(session.send(&event).unwrap());
    }
}
