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

use transport_ip_sna::{
    anynet::{bind_udp, listen_tcp, TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_bind_negotiation::validate_positive_response,
    mptn_compensations::CompensationSet,
    mptn_connect::{Connect, Direction},
    mptn_ingress::{IngressKind, IngressOffer, IngressPolicy, IngressSession},
    mptn_management_responder::{ManagementResponder, Phase as ManagementPhase, V5Options},
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
}

pub(crate) enum GatewayEvent {
    ManagementReady,
    UserBind(IngressOffer),
    UserNormal(TcpRecord),
    UserExpedited(TcpRecord),
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
}

struct Association {
    tcp: TcpSession,
    state: SessionState,
    incoming: VecDeque<TcpRecord>,
    incoming_bytes: usize,
    writes: VecDeque<(usize, Completion)>,
    user_inflight: bool,
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
        if let Err(error) = self.poll_udp_once() {
            self.active = None;
            return Err(error);
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

    fn poll_udp_once(&mut self) -> io::Result<()> {
        let mut bytes = [0u8; MAX_RECORD];
        match self.udp.recv_from(&mut bytes) {
            Ok((_, peer)) if peer.ip() != self.config.peer_ip => Ok(()),
            Ok((_, _)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP62 UDP/397 compensation handler unavailable",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
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
                _ => return Err(invalid("TCP62 write completed in wrong gateway phase")),
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
            || (!can_accept_information
                && matches!(association.state, SessionState::UserActive(_))
                && front.kind != TcpKind::Abort)
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
                    IngressKind::User { .. } if self.management_ready => {
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
        match Self::queue(association, record.bytes.clone(), Completion::UserRecord) {
            Ok(()) => Ok(true),
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
        io::Write,
        net::{Ipv4Addr, TcpStream},
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
    }
}
