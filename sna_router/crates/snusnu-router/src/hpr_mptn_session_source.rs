//! One validated MPTN user Connect routed toward an EE peer.
//!
//! The shared gateway detaches exactly the admitted TCP association and lends
//! UDP/397 before constructing this source. Events remain leased until the
//! session fabric confirms admission; UDP X'83' replies follow that admission.

use std::{
    collections::VecDeque,
    io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use router_core::session::{Flow, SessionEvent, SessionUnit};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_bind_negotiation::validate_positive_response,
    mptn_connect::{Connect, Direction},
    mptn_ingress::{IngressKind, IngressOffer},
    mptn_oob::{build_request, Compensation, Datagram, Kind},
    mptn_session_unit::{normal_record_to_unit, unit_to_normal_record},
};

use crate::{
    hpr_session_source::{SessionSource, SourceUpdate},
    mptn_gateway_port::DetachedUserAssociation,
    mptn_outbound_port::{OutboundEndpoint, OutboundUdp, OutboundUdpAction},
};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

enum Phase {
    InitialBind,
    AwaitBindResult,
    BindResultQueued { accepted: bool },
    Bound,
    Closed,
}

enum PendingKind {
    Bind,
    Tcp,
    Udp { sequence: u16, peer: SocketAddr },
    OutboundAbort,
    Closed,
}

struct Pending {
    update: SourceUpdate,
    kind: PendingKind,
}

struct PendingAbort {
    packet: Vec<u8>,
    sequence: u16,
    snf: [u8; 2],
    last_sent: Instant,
    retries: u8,
}

pub(crate) struct MptnToHprSession {
    tcp: TcpSession,
    udp: UdpSocket,
    endpoint: OutboundEndpoint,
    connect: Connect,
    oob: OutboundUdp,
    bind: SessionUnit,
    phase: Phase,
    incoming: VecDeque<TcpRecord>,
    incoming_bytes: usize,
    pending: Option<Pending>,
    pending_abort: Option<PendingAbort>,
    inbound_abort: Option<(u16, [u8; 2])>,
    pending_udp_reply: Option<(Vec<u8>, SocketAddr)>,
    next_oob_sequence: u16,
    expedited_ack_pending: bool,
    outbound_expedited_sent_at: Option<Instant>,
    tcp_closed: bool,
    closed_reported: bool,
}

impl MptnToHprSession {
    pub(crate) fn new(
        detached: DetachedUserAssociation,
        udp: UdpSocket,
        endpoint: OutboundEndpoint,
        offer: IngressOffer,
    ) -> io::Result<Self> {
        if udp.local_addr()? != SocketAddr::new(endpoint.local_ip, 397) {
            return Err(invalid("MPTN source UDP lease belongs to another gateway"));
        }
        udp.set_nonblocking(true)?;
        let connect = offer.connect().clone();
        if connect.direction != Direction::Request
            || !matches!(offer.kind(), IngressKind::User { .. })
        {
            return Err(invalid("MPTN source requires a validated Connect request"));
        }
        let bind =
            SessionUnit::from_reduced(connect.connection_data()).map_err(io::Error::other)?;
        if bind.rh() != [0x6b, 0x80, 0] || bind.ru().first() != Some(&0x31) {
            return Err(invalid("MPTN source Connect does not carry user BIND"));
        }
        let oob = OutboundUdp::new(endpoint, connect.clone())?;
        Ok(Self {
            tcp: detached.tcp,
            udp,
            endpoint,
            connect,
            oob,
            bind,
            phase: Phase::InitialBind,
            incoming: detached.incoming,
            incoming_bytes: detached.incoming_bytes,
            pending: None,
            pending_abort: None,
            inbound_abort: None,
            pending_udp_reply: None,
            next_oob_sequence: 1,
            expedited_ack_pending: false,
            outbound_expedited_sent_at: None,
            tcp_closed: false,
            closed_reported: false,
        })
    }

    fn progress(&mut self) -> io::Result<()> {
        if let Some((reply, peer)) = &self.pending_udp_reply {
            match self.udp.send_to(reply, *peer) {
                Ok(n) if n == reply.len() => self.pending_udp_reply = None,
                Ok(_) => return Err(invalid("partial MPTN source UDP response")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        let mut completed = 0usize;
        self.tcp.flush_with_completion(|_| completed += 1)?;
        if completed != 0 {
            if let Phase::BindResultQueued { accepted } = self.phase {
                self.phase = if accepted {
                    Phase::Bound
                } else {
                    Phase::Closed
                };
            }
        }
        if !self.tcp_closed && self.incoming_bytes < MAX_RECORD {
            match self.tcp.receive_once() {
                Ok(Some(records)) => {
                    let bytes = records
                        .iter()
                        .map(|record| record.bytes.len())
                        .sum::<usize>();
                    if self.incoming_bytes + bytes > MAX_RECORD * 2 {
                        return Err(invalid("MPTN source receive queue full"));
                    }
                    self.incoming_bytes += bytes;
                    self.incoming.extend(records);
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.tcp_closed = true
                }
                Err(error) => return Err(error),
            }
        }
        if self.expedited_ack_pending && self.tcp.has_capacity() {
            self.tcp.queue(TcpRecord::decode(vec![0, 0, 0, 5, 3])?)?;
            self.expedited_ack_pending = false;
        }
        if self
            .outbound_expedited_sent_at
            .is_some_and(|at| at.elapsed() > Duration::from_secs(5))
            && !self
                .incoming
                .iter()
                .any(|record| record.kind == TcpKind::ExpeditedAck)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MPTN source expedited ACK timed out",
            ));
        }
        if let Some(abort) = &mut self.pending_abort {
            if abort.last_sent.elapsed() >= Duration::from_secs(1) {
                if abort.retries >= 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "MPTN source UNBIND ACK timed out",
                    ));
                }
                let peer = SocketAddr::new(self.endpoint.peer_ip, 397);
                match self.udp.send_to(&abort.packet, peer) {
                    Ok(n) if n == abort.packet.len() => {
                        abort.last_sent = Instant::now();
                        abort.retries += 1;
                    }
                    Ok(_) => return Err(invalid("partial MPTN source UDP abort")),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn send_udp_reply(&mut self, reply: Vec<u8>, peer: SocketAddr) -> io::Result<()> {
        match self.udp.send_to(&reply, peer) {
            Ok(n) if n == reply.len() => Ok(()),
            Ok(_) => Err(invalid("partial MPTN source UDP response")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if self.pending_udp_reply.is_some() {
                    return Err(invalid("MPTN source UDP response queue full"));
                }
                self.pending_udp_reply = Some((reply, peer));
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn take_tcp_record(&mut self) -> io::Result<Option<SourceUpdate>> {
        let Some(record) = self.incoming.front() else {
            return Ok(None);
        };
        let update = match record.kind {
            TcpKind::Normal | TcpKind::Expedited if matches!(self.phase, Phase::Bound) => {
                let mut normal = record.clone();
                normal.bytes[4] = 0;
                normal.kind = TcpKind::Normal;
                SourceUpdate::Event(SessionEvent::Information {
                    flow: if record.kind == TcpKind::Expedited {
                        Flow::Expedited
                    } else {
                        Flow::Normal
                    },
                    unit: normal_record_to_unit(&normal)?,
                })
            }
            TcpKind::ExpeditedAck => {
                if self.outbound_expedited_sent_at.take().is_none() {
                    return Err(invalid("unsolicited MPTN source expedited ACK"));
                }
                let ack = self.incoming.pop_front().unwrap();
                self.incoming_bytes -= ack.bytes.len();
                return self.take_tcp_record();
            }
            TcpKind::Abort => {
                if record.bytes.len() == 5 {
                    SourceUpdate::Closed
                } else {
                    let unit =
                        SessionUnit::from_reduced(&record.bytes[5..]).map_err(io::Error::other)?;
                    if unit.ru().first() != Some(&0x32) {
                        return Err(invalid("MPTN source Abort lacks UNBIND"));
                    }
                    SourceUpdate::Event(SessionEvent::Unbind(unit))
                }
            }
            _ => return Err(invalid("MPTN source TCP record in wrong phase")),
        };
        self.pending = Some(Pending {
            update: update.clone(),
            kind: PendingKind::Tcp,
        });
        Ok(Some(update))
    }
}

impl SessionSource for MptnToHprSession {
    fn poll(&mut self) -> io::Result<Option<SourceUpdate>> {
        if let Some(pending) = &self.pending {
            return Ok(Some(pending.update.clone()));
        }
        if matches!(self.phase, Phase::Closed) {
            self.progress()?;
            if self.closed_reported {
                return Ok(None);
            }
            self.pending = Some(Pending {
                update: SourceUpdate::Closed,
                kind: PendingKind::Closed,
            });
            return Ok(Some(SourceUpdate::Closed));
        }
        if matches!(self.phase, Phase::InitialBind) {
            let update = SourceUpdate::Event(SessionEvent::BindRequest(self.bind.clone()));
            self.pending = Some(Pending {
                update: update.clone(),
                kind: PendingKind::Bind,
            });
            return Ok(Some(update));
        }
        self.progress()?;
        if matches!(
            self.phase,
            Phase::AwaitBindResult | Phase::BindResultQueued { .. }
        ) {
            return Ok(None);
        }
        if let Some(update) = self.take_tcp_record()? {
            return Ok(Some(update));
        }
        if self.tcp_closed {
            self.pending = Some(Pending {
                update: SourceUpdate::Closed,
                kind: PendingKind::Closed,
            });
            return Ok(Some(SourceUpdate::Closed));
        }
        let mut bytes = [0u8; MAX_RECORD];
        match self.udp.recv_from(&mut bytes) {
            Ok((length, peer)) => {
                if let Some(abort) = &self.pending_abort {
                    if peer.ip() == self.endpoint.peer_ip && bytes.get(4) == Some(&0x83) {
                        let reply = Datagram::decode(&bytes[..length])?;
                        if reply.sequence == abort.sequence
                            && reply.kind != Kind::Request
                            && reply.matches_connect(&self.connect)
                        {
                            if reply.kind != Kind::PositiveResponse {
                                return Err(invalid("MPTN source UNBIND rejected"));
                            }
                            let mut reduced = abort.snf.to_vec();
                            reduced.extend_from_slice(&[0xeb, 0x80, 0, 0x32]);
                            let update = SourceUpdate::Event(SessionEvent::Unbind(
                                SessionUnit::from_reduced(&reduced).map_err(io::Error::other)?,
                            ));
                            self.pending_abort = None;
                            self.pending = Some(Pending {
                                update: update.clone(),
                                kind: PendingKind::OutboundAbort,
                            });
                            return Ok(Some(update));
                        }
                    }
                }
                let action = match self.oob.receive(&bytes[..length], peer) {
                    Ok(action) => action,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::PermissionDenied
                                | io::ErrorKind::InvalidData
                                | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        tracing::debug!(peer = %peer, error = %error, "unmatched MPTN source UDP packet dropped");
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
                match action {
                    OutboundUdpAction::Reply(reply) => self.send_udp_reply(reply, peer)?,
                    OutboundUdpAction::PendingDuplicate => {}
                    OutboundUdpAction::Deliver {
                        sequence,
                        compensation,
                        reduced,
                    } => {
                        let update = match compensation {
                            Compensation::Expedited => {
                                SourceUpdate::Event(SessionEvent::Information {
                                    flow: Flow::Expedited,
                                    unit: SessionUnit::from_reduced(&reduced)
                                        .map_err(io::Error::other)?,
                                })
                            }
                            Compensation::Abort if reduced.is_empty() => SourceUpdate::Closed,
                            Compensation::Abort => {
                                let unit = SessionUnit::from_reduced(&reduced)
                                    .map_err(io::Error::other)?;
                                if unit.ru().first() != Some(&0x32) {
                                    return Err(invalid("MPTN source UDP Abort lacks UNBIND"));
                                }
                                SourceUpdate::Event(SessionEvent::Unbind(unit))
                            }
                        };
                        self.pending = Some(Pending {
                            update: update.clone(),
                            kind: PendingKind::Udp { sequence, peer },
                        });
                        return Ok(Some(update));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        Ok(None)
    }

    fn complete_received(&mut self, _charge: bool) -> io::Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| invalid("no MPTN source event to confirm"))?;
        match pending.kind {
            PendingKind::Bind => self.phase = Phase::AwaitBindResult,
            PendingKind::Tcp => {
                let record = self
                    .incoming
                    .pop_front()
                    .ok_or_else(|| invalid("MPTN source TCP lease lost"))?;
                self.incoming_bytes -= record.bytes.len();
                if record.kind == TcpKind::Expedited {
                    self.expedited_ack_pending = true;
                }
                if matches!(pending.update, SourceUpdate::Closed) {
                    self.phase = Phase::Closed;
                }
            }
            PendingKind::Udp { sequence, peer } => {
                self.oob.mark_native_submitted(sequence)?;
                if let SourceUpdate::Event(SessionEvent::Unbind(ref unit)) = pending.update {
                    self.inbound_abort = Some((sequence, unit.snf().try_into().unwrap()));
                } else {
                    let (reply, target) = self.oob.complete_native_delivery(sequence)?;
                    if target != peer {
                        return Err(invalid("MPTN source UDP peer changed"));
                    }
                    self.send_udp_reply(reply, target)?;
                    if pending.update == SourceUpdate::Closed {
                        self.phase = Phase::Closed;
                    }
                }
            }
            PendingKind::OutboundAbort | PendingKind::Closed => {
                self.phase = Phase::Closed;
                self.closed_reported = true;
            }
        }
        Ok(())
    }

    fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        self.progress()?;
        match event {
            SessionEvent::BindResult { accepted, unit }
                if matches!(self.phase, Phase::AwaitBindResult) =>
            {
                let mut response = self.connect.clone();
                response.direction = if *accepted {
                    Direction::PositiveResponse
                } else {
                    Direction::NegativeResponse
                };
                response.processing = if *accepted { 0x8a } else { 0xca };
                let field = response
                    .options
                    .iter_mut()
                    .find(|field| field.kind == 0x0a)
                    .ok_or_else(|| invalid("MPTN Connect lacks BIND option"))?;
                let mut reduced = unit.as_reduced().to_vec();
                reduced[..2].copy_from_slice(self.bind.snf());
                field.value = reduced;
                if *accepted {
                    validate_positive_response(
                        self.connect.connection_data(),
                        response.connection_data(),
                    )
                    .map_err(io::Error::other)?;
                }
                let record = TcpRecord::decode(response.encode()?)?;
                match self.tcp.queue(record) {
                    Ok(()) => {
                        self.phase = Phase::BindResultQueued {
                            accepted: *accepted,
                        };
                        Ok(true)
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                    Err(error) => Err(error),
                }
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
                match self.tcp.queue(record) {
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
            SessionEvent::Unbind(unit) if unit.rh()[0] & 0x80 != 0 => {
                let Some((sequence, snf)) = self.inbound_abort else {
                    return Err(invalid("MPTN source unexpected UNBIND response"));
                };
                if unit.snf() != snf {
                    return Err(invalid("MPTN source UNBIND response SNF mismatch"));
                }
                let (reply, peer) = self.oob.complete_native_delivery(sequence)?;
                self.send_udp_reply(reply, peer)?;
                self.inbound_abort = None;
                self.phase = Phase::Closed;
                Ok(true)
            }
            SessionEvent::Unbind(unit) if matches!(self.phase, Phase::Bound) => {
                if unit.ru().first() != Some(&0x32) || self.pending_abort.is_some() {
                    return Ok(false);
                }
                let sequence = self.next_oob_sequence;
                let mut reduced = unit.as_reduced().to_vec();
                reduced[..2].fill(0);
                let packet = build_request(&self.connect, sequence, Compensation::Abort, &reduced)?;
                let peer = SocketAddr::new(self.endpoint.peer_ip, 397);
                match self.udp.send_to(&packet, peer) {
                    Ok(n) if n == packet.len() => {}
                    Ok(_) => return Err(invalid("partial MPTN source UDP abort")),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(error) => return Err(error),
                }
                self.pending_abort = Some(PendingAbort {
                    packet,
                    sequence,
                    snf: unit.snf().try_into().unwrap(),
                    last_sent: Instant::now(),
                    retries: 0,
                });
                self.next_oob_sequence = sequence.wrapping_add(1);
                Ok(true)
            }
            SessionEvent::Reset => {
                self.phase = Phase::Closed;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        self.phase = Phase::Closed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use transport_ip_sna::mptn_session::connect_template_for_route;

    fn source() -> (MptnToHprSession, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (tcp, _) = listener.accept().unwrap();
        let endpoint = OutboundEndpoint {
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.2".parse().unwrap(),
        };
        let connect = connect_template_for_route("SOLNET.SNAB", "SNUSNU.PING", [1; 8]).unwrap();
        let oob = OutboundUdp::new(endpoint, connect.clone()).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let bind = SessionUnit::from_reduced(&[0, 7, 0x6b, 0x80, 0, 0x31]).unwrap();
        (
            MptnToHprSession {
                tcp: TcpSession::new(tcp).unwrap(),
                udp,
                endpoint,
                connect,
                oob,
                bind,
                phase: Phase::InitialBind,
                incoming: VecDeque::new(),
                incoming_bytes: 0,
                pending: None,
                pending_abort: None,
                inbound_abort: None,
                pending_udp_reply: None,
                next_oob_sequence: 1,
                expedited_ack_pending: false,
                outbound_expedited_sent_at: None,
                tcp_closed: false,
                closed_reported: false,
            },
            peer,
        )
    }

    #[test]
    fn initial_bind_remains_leased_until_session_accepts_it() {
        let (mut source, _peer) = source();
        let first = source.poll().unwrap().unwrap();
        assert!(matches!(
            first,
            SourceUpdate::Event(SessionEvent::BindRequest(_))
        ));
        assert_eq!(source.poll().unwrap(), Some(first));
        source.complete_received(true).unwrap();
        assert!(source.poll().unwrap().is_none());
        assert!(matches!(source.phase, Phase::AwaitBindResult));
    }

    #[test]
    fn closed_source_reports_one_leased_close_then_stays_quiet() {
        let (mut source, _peer) = source();
        source.close().unwrap();
        assert_eq!(source.poll().unwrap(), Some(SourceUpdate::Closed));
        assert_eq!(source.poll().unwrap(), Some(SourceUpdate::Closed));
        source.complete_received(false).unwrap();
        assert_eq!(source.poll().unwrap(), None);
    }
}
