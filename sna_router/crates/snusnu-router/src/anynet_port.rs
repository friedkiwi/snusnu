//! One bounded TCP62/AnyNet session attachment.
//!
//! This relays complete TCP62 records between equivalent AnyNet peers. It
//! translates IPv4 UDP/397 node-pair keepalives across router-facing IP
//! adjacencies. Unsupported expedited UDP commands fail closed.

use crate::routing::{RoutePort, RoutedUnit, RouterEvent};
use router_core::packet_log::hex_dump;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
};
use transport_ip_sna::anynet::{self, TcpKind, TcpRecord, TcpSession};
use transport_ip_sna::{
    mptn_connect::{Connect, Direction},
    mptn_keepalive::{Exchange, Keepalive},
};

const PENDING_LIMIT: usize = anynet::MAX_RECORD * 4;
const UDP_QUEUE_LIMIT: usize = 64;

struct SessionIdentity {
    source: Vec<u8>,
    destination: Vec<u8>,
    correlator: Vec<u8>,
    accepted: bool,
}

pub(crate) struct AnyNetPort {
    local_ip: IpAddr,
    peer_ip: IpAddr,
    port: u16,
    listener: TcpListener,
    udp: UdpSocket,
    session: Option<TcpSession>,
    connecting: Option<TcpStream>,
    incoming: VecDeque<TcpRecord>,
    incoming_udp: VecDeque<Vec<u8>>,
    pending: VecDeque<TcpRecord>,
    pending_bytes: usize,
    pending_udp: VecDeque<Keepalive>,
    keepalive_exchange: Exchange,
    expected_local_lu: Option<Vec<u8>>,
    expected_remote_lu: Option<Vec<u8>>,
    identity: Option<SessionIdentity>,
    close_pending: bool,
}

impl AnyNetPort {
    pub(crate) fn open(local_ip: IpAddr, peer_ip: IpAddr) -> io::Result<Self> {
        Self::open_at(local_ip, peer_ip, anynet::MPTN_PORT)
    }

    pub(crate) fn open_with_lus(
        local_ip: IpAddr,
        peer_ip: IpAddr,
        local_lu: Option<String>,
        remote_lu: Option<String>,
    ) -> io::Result<Self> {
        let (local, remote) = match (local_lu, remote_lu) {
            (Some(local), Some(remote)) => (Some(encode_lu(&local)?), Some(encode_lu(&remote)?)),
            (None, None) => (None, None),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "both AnyNet LU names are required",
                ))
            }
        };
        let mut port = Self::open(local_ip, peer_ip)?;
        port.expected_local_lu = local;
        port.expected_remote_lu = remote;
        Ok(port)
    }

    fn open_at(local_ip: IpAddr, peer_ip: IpAddr, port: u16) -> io::Result<Self> {
        if local_ip == peer_ip || local_ip.is_ipv4() != peer_ip.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid AnyNet IP pair",
            ));
        }
        let address = SocketAddr::new(local_ip, port);
        let listener = anynet::listen_tcp(address)?;
        let udp = anynet::bind_udp(address)?;
        tracing::info!(%local_ip, %peer_ip, port, "AnyNet attachment opened");
        Ok(Self {
            local_ip,
            peer_ip,
            port,
            listener,
            udp,
            session: None,
            connecting: None,
            incoming: VecDeque::new(),
            incoming_udp: VecDeque::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            pending_udp: VecDeque::new(),
            keepalive_exchange: Exchange::default(),
            expected_local_lu: None,
            expected_remote_lu: None,
            identity: None,
            close_pending: false,
        })
    }

    fn accept_once(&mut self) -> io::Result<bool> {
        match self.listener.accept() {
            Ok((stream, address)) => {
                if address.ip() != self.peer_ip
                    || self.session.is_some()
                    || self.connecting.is_some()
                {
                    tracing::warn!(local_ip = %self.local_ip, source_ip = %address.ip(), configured_peer_ip = %self.peer_ip, "additional or unconfigured AnyNet TCP session rejected");
                    let _ = stream.shutdown(Shutdown::Both);
                    return Ok(true);
                }
                self.session = Some(TcpSession::new(stream)?);
                tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, source_port = address.port(), "AnyNet TCP session accepted");
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn start_dial(&mut self) -> io::Result<()> {
        let domain = if self.local_ip.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::new(self.local_ip, 0).into())?;
        let target = SocketAddr::new(self.peer_ip, self.port);
        match socket.connect(&target.into()) {
            Ok(()) => {}
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(115) => {}
            Err(error) => return Err(error),
        }
        self.connecting = Some(socket.into());
        tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, target_port = self.port, "AnyNet TCP connection started");
        Ok(())
    }

    fn finish_dial(&mut self) -> io::Result<bool> {
        let Some(stream) = self.connecting.as_ref() else {
            return Ok(false);
        };
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        match stream.peer_addr() {
            Ok(_) => {
                let stream = self.connecting.take().unwrap();
                self.session = Some(TcpSession::new(stream)?);
                tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, "AnyNet TCP connection established");
                self.drain()?;
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotConnected | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn drain(&mut self) -> io::Result<()> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        while session.has_capacity() {
            let Some(record) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes -= record.bytes.len();
            tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, kind = ?record.kind, bytes = record.bytes.len(), hex = %hex_dump(&record.bytes), "AnyNet TCP record queued for peer");
            session.queue(record)?;
        }
        session.flush()
    }

    fn check_udp(&mut self, can_forward: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if can_forward {
            if let Some(bytes) = self.incoming_udp.pop_front() {
                return Ok(Some(vec![RouterEvent::Unit(
                    RoutedUnit::AnyNetUdpDatagram(bytes),
                )]));
            }
        }
        let mut bytes = [0; anynet::MAX_RECORD];
        match self.udp.recv_from(&mut bytes) {
            Ok((size, source)) => {
                if source.ip() != self.peer_ip || source.port() != self.port {
                    tracing::warn!(local_ip = %self.local_ip, source_ip = %source.ip(), source_port = source.port(), "UDP/397 from unconfigured peer discarded");
                    return Ok(Some(Vec::new()));
                }
                let decoded = Keepalive::decode(&bytes[..size]).and_then(|keepalive| {
                    keepalive.validate_ingress(self.peer_ip, self.local_ip)?;
                    self.keepalive_exchange.received(keepalive.kind)?;
                    Ok(keepalive)
                });
                match decoded {
                    Ok(keepalive) => {
                        tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, kind = ?keepalive.kind, bytes = size, hex = %hex_dump(&bytes[..size]), "AnyNet node-pair keepalive received");
                        if self.incoming_udp.len() >= UDP_QUEUE_LIMIT {
                            tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, "AnyNet keepalive ingress queue full; node pair closed");
                            self.disconnect()?;
                            return Ok(Some(vec![RouterEvent::Closed]));
                        }
                        self.incoming_udp.push_back(bytes[..size].to_vec());
                        if can_forward {
                            Ok(Some(vec![RouterEvent::Unit(
                                RoutedUnit::AnyNetUdpDatagram(
                                    self.incoming_udp.pop_front().unwrap(),
                                ),
                            )]))
                        } else {
                            Ok(Some(Vec::new()))
                        }
                    }
                    Err(error) => {
                        tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, source_port = source.port(), error = %error, "unsupported AnyNet UDP/397 traffic; session closed");
                        tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, bytes = size, hex = %hex_dump(&bytes[..size]), "unsupported AnyNet UDP datagram");
                        self.disconnect()?;
                        Ok(Some(vec![RouterEvent::Closed]))
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn drain_udp(&mut self) -> io::Result<()> {
        while let Some(keepalive) = self.pending_udp.front().copied() {
            let bytes = keepalive.encode();
            match self
                .udp
                .send_to(&bytes, SocketAddr::new(self.peer_ip, self.port))
            {
                Ok(n) if n == bytes.len() => {
                    self.pending_udp.pop_front();
                    self.keepalive_exchange.sent(keepalive.kind);
                    tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, kind = ?keepalive.kind, bytes = n, hex = %hex_dump(&bytes), "AnyNet node-pair keepalive sent");
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short AnyNet UDP send",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn pop_incoming(&mut self) -> Option<Vec<RouterEvent>> {
        let record = self.incoming.pop_front()?;
        if let Err(error) = self.validate_record(&record, true) {
            tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, error = %error, "AnyNet session identity rejected");
            let _ = self.disconnect();
            return Some(vec![RouterEvent::Closed]);
        }
        tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, kind = ?record.kind, bytes = record.bytes.len(), hex = %hex_dump(&record.bytes), "AnyNet TCP record received");
        Some(vec![RouterEvent::Unit(RoutedUnit::AnyNetTcpRecord(
            record.bytes,
        ))])
    }

    fn validate_record(&mut self, record: &TcpRecord, from_peer: bool) -> io::Result<()> {
        if record.kind != TcpKind::Connect {
            return if self
                .identity
                .as_ref()
                .is_some_and(|identity| identity.accepted)
            {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AnyNet data before accepted Connect",
                ))
            };
        }
        let connect = Connect::decode(&record.bytes)?;
        match connect.direction {
            Direction::Request => {
                if self.identity.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate AnyNet Connect request",
                    ));
                }
                if let (Some(local), Some(remote)) =
                    (&self.expected_local_lu, &self.expected_remote_lu)
                {
                    let (source, destination) = if from_peer {
                        (local, remote)
                    } else {
                        (remote, local)
                    };
                    if connect.source.node != *source || connect.destination.node != *destination {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "AnyNet LU pair does not match route",
                        ));
                    }
                }
                self.identity = Some(SessionIdentity {
                    source: connect.source.node,
                    destination: connect.destination.node,
                    correlator: connect.correlator,
                    accepted: false,
                });
                Ok(())
            }
            Direction::PositiveResponse | Direction::NegativeResponse => {
                let identity = self.identity.as_mut().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AnyNet Connect response without request",
                    )
                })?;
                if identity.source != connect.source.node
                    || identity.destination != connect.destination.node
                    || identity.correlator != connect.correlator
                    || identity.accepted
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AnyNet Connect response identity mismatch",
                    ));
                }
                identity.accepted = connect.direction == Direction::PositiveResponse;
                Ok(())
            }
        }
    }
}

fn encode_lu(name: &str) -> io::Result<Vec<u8>> {
    let (netid, lu) = name
        .split_once('.')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "AnyNet LU must be NETID.LU"))?;
    if netid.is_empty() || lu.is_empty() || netid.len() > 8 || lu.len() > 8 || lu.contains('.') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid AnyNet LU name",
        ));
    }
    name.bytes()
        .map(|ch| match ch {
            b'A'..=b'I' => Ok(0xc1 + (ch - b'A')),
            b'J'..=b'R' => Ok(0xd1 + (ch - b'J')),
            b'S'..=b'Z' => Ok(0xe2 + (ch - b'S')),
            b'0'..=b'9' => Ok(0xf0 + (ch - b'0')),
            b'@' => Ok(0x7c),
            b'#' => Ok(0x7b),
            b'$' => Ok(0x5b),
            b'.' => Ok(0x4b),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid AnyNet LU character",
            )),
        })
        .collect()
}

impl RoutePort for AnyNetPort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if let Some(events) = self.check_udp(can_accept_information)? {
            return Ok(Some(events));
        }
        if self.accept_once()? {
            return Ok(Some(Vec::new()));
        }
        if !can_accept_information {
            return Ok(None);
        }
        if let Some(events) = self.pop_incoming() {
            return Ok(Some(events));
        }
        let Some(session) = self.session.as_mut() else {
            return Ok(None);
        };
        match session.receive_once() {
            Ok(None) => Ok(None),
            Ok(Some(records)) => {
                self.incoming.extend(records);
                Ok(Some(self.pop_incoming().unwrap_or_default()))
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, "AnyNet TCP session closed");
                self.disconnect()?;
                Ok(Some(vec![RouterEvent::Closed]))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, error = %error, "invalid AnyNet record; session closed");
                self.disconnect()?;
                Ok(Some(vec![RouterEvent::Closed]))
            }
            Err(error) => Err(error),
        }
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        if self.close_pending {
            self.disconnect()?;
            return Ok(vec![RouterEvent::Closed]);
        }
        if self.connecting.is_some() {
            if let Err(error) = self.finish_dial() {
                tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, error = %error, "AnyNet TCP connection failed");
                self.disconnect()?;
                return Ok(vec![RouterEvent::Closed]);
            }
        }
        self.drain()?;
        self.drain_udp()?;
        Ok(Vec::new())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        if let RoutedUnit::AnyNetUdpDatagram(bytes) = unit {
            let keepalive = match Keepalive::decode(&bytes)
                .and_then(|message| message.for_egress(self.local_ip, self.peer_ip))
            {
                Ok(message) => message,
                Err(error) => {
                    tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, error = %error, "invalid routed AnyNet keepalive; closing node pair");
                    self.close_pending = true;
                    return Ok(true);
                }
            };
            if self.pending_udp.len() >= UDP_QUEUE_LIMIT {
                return Ok(false);
            }
            self.pending_udp.push_back(keepalive);
            self.drain_udp()?;
            return Ok(true);
        }
        let RoutedUnit::AnyNetTcpRecord(bytes) = unit else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyNet port cannot receive another SNA profile",
            ));
        };
        let record = TcpRecord::decode(bytes)?;
        if let Err(error) = self.validate_record(&record, false) {
            tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, error = %error, "AnyNet routed session identity rejected");
            self.close_pending = true;
            return Ok(true);
        }
        if self.session.is_none() && self.connecting.is_none() {
            if record.kind != TcpKind::Connect {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AnyNet session must begin with MPTN Connect",
                ));
            }
            self.start_dial()?;
        }
        if self.pending_bytes + record.bytes.len() > PENDING_LIMIT {
            return Ok(false);
        }
        self.pending_bytes += record.bytes.len();
        self.pending.push_back(record);
        self.drain()?;
        Ok(true)
    }

    fn has_capacity(&self) -> bool {
        self.pending_bytes <= PENDING_LIMIT - anynet::MAX_RECORD
            && self.pending_udp.len() < UDP_QUEUE_LIMIT
    }
    fn available_receive_slots(&self) -> usize {
        usize::from(self.has_capacity())
    }
    fn set_ingress_busy(&mut self, _busy: bool) -> io::Result<()> {
        Ok(())
    }
    fn on_peer_ready(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn disconnect(&mut self) -> io::Result<()> {
        self.session = None;
        self.connecting = None;
        self.incoming.clear();
        self.incoming_udp.clear();
        self.pending.clear();
        self.pending_bytes = 0;
        self.pending_udp.clear();
        self.keepalive_exchange.clear();
        self.identity = None;
        self.close_pending = false;
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        self.drain_udp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener},
        thread,
        time::{Duration, Instant},
    };
    use transport_ip_sna::mptn_keepalive::Kind;

    // Synthetic TCP62 Connect from the IBM draft's fixed field layout.
    // The three-byte connection data is a marker, not a captured BIND.
    const CONNECT: &[u8] = &[
        0, 0, 0, 64, 0x80, 0x0a, 0, 60, 8, 0x0b, 1, 12, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b,
        0xe2, 0xd5, 0xc1, 0xc2, 1, 0x0b, 1, 12, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2,
        0xd5, 0xc1, 0xc1, 1, 3, 0x12, 0x34, 15, 0, 0, 0x10, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0x20, 0,
        0x0a, 0x02, 0, 7, 0x31, 0, 0x13,
    ];

    fn wait_until(mut step: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !step() {
            assert!(Instant::now() < deadline, "AnyNet loopback step timed out");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn next_unit(port: &mut AnyNetPort) -> Vec<u8> {
        let mut found = None;
        wait_until(|| {
            if let Some(events) = port.poll(true).unwrap() {
                for event in events {
                    if let RouterEvent::Unit(RoutedUnit::AnyNetTcpRecord(bytes)) = event {
                        found = Some(bytes);
                    }
                }
            }
            found.is_some()
        });
        found.unwrap()
    }

    fn next_udp_unit(port: &mut AnyNetPort) -> Vec<u8> {
        let mut found = None;
        wait_until(|| {
            if let Some(events) = port.poll(true).unwrap() {
                for event in events {
                    if let RouterEvent::Unit(RoutedUnit::AnyNetUdpDatagram(bytes)) = event {
                        found = Some(bytes);
                    }
                }
            }
            found.is_some()
        });
        found.unwrap()
    }

    fn read_exact_nonblocking(stream: &mut TcpStream, size: usize) -> Vec<u8> {
        let mut got = Vec::new();
        wait_until(|| {
            let mut scratch = [0; 256];
            match stream.read(&mut scratch) {
                Ok(n) => got.extend_from_slice(&scratch[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("AnyNet loopback read: {error}"),
            }
            got.len() == size
        });
        got
    }

    #[test]
    fn tcp62_connect_and_response_cross_two_route_ports() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(127, 83, 0, 1));
        let b_ip = IpAddr::V4(Ipv4Addr::new(127, 83, 0, 3));
        let b_peer = IpAddr::V4(Ipv4Addr::new(127, 83, 0, 4));
        let port = 18_397;
        let mut a = AnyNetPort::open_at(a_ip, IpAddr::V4(Ipv4Addr::LOCALHOST), port).unwrap();
        let mut b = AnyNetPort::open_at(b_ip, b_peer, port).unwrap();
        a.expected_local_lu = Some(encode_lu("SOLNET.SNAA").unwrap());
        a.expected_remote_lu = Some(encode_lu("SOLNET.SNAB").unwrap());
        b.expected_local_lu = Some(encode_lu("SOLNET.SNAB").unwrap());
        b.expected_remote_lu = Some(encode_lu("SOLNET.SNAA").unwrap());
        let server = TcpListener::bind(SocketAddr::new(b_peer, port)).unwrap();
        server.set_nonblocking(true).unwrap();
        let mut client = TcpStream::connect(SocketAddr::new(a_ip, port)).unwrap();
        client.set_nonblocking(true).unwrap();
        wait_until(|| {
            a.session.is_some() || {
                a.poll(true).unwrap();
                a.session.is_some()
            }
        });

        client.write_all(CONNECT).unwrap();
        let unit = next_unit(&mut a);
        assert_eq!(unit, CONNECT);
        assert!(b.send(RoutedUnit::AnyNetTcpRecord(unit)).unwrap());

        let mut accepted = None;
        wait_until(|| {
            b.tick().unwrap();
            if accepted.is_none() {
                if let Ok((stream, source)) = server.accept() {
                    assert_eq!(source.ip(), b_ip);
                    accepted = Some(stream);
                }
            }
            accepted.is_some() && b.session.is_some()
        });
        let mut server_stream = accepted.unwrap();
        server_stream.set_nonblocking(true).unwrap();
        assert_eq!(
            read_exact_nonblocking(&mut server_stream, CONNECT.len()),
            CONNECT
        );

        let mut response = CONNECT.to_vec();
        response[5] = 0x8a;
        server_stream.write_all(&response).unwrap();
        let unit = next_unit(&mut b);
        assert_eq!(unit, response);
        assert!(a.send(RoutedUnit::AnyNetTcpRecord(unit)).unwrap());
        assert_eq!(
            read_exact_nonblocking(&mut client, response.len()),
            response
        );

        let normal = [0, 0, 0, 6, 0, 0x5a];
        client.write_all(&[normal, normal].concat()).unwrap();
        assert_eq!(next_unit(&mut a), normal);
        assert_eq!(next_unit(&mut a), normal);

        let second = TcpStream::connect(SocketAddr::new(a_ip, port)).unwrap();
        assert!(a.poll(true).unwrap().unwrap().is_empty());
        assert!(a.session.is_some());
        drop(second);

        let udp = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
        udp.send_to(&[0, 0, 0, 8, 0x84, 0, 0, 4], SocketAddr::new(a_ip, port))
            .unwrap();
        assert!(matches!(
            a.poll(true).unwrap().unwrap().as_slice(),
            [RouterEvent::Closed]
        ));
        assert!(a.session.is_none());

        a.expected_local_lu = Some(encode_lu("SOLNET.SNAX").unwrap());
        let mut wrong = TcpStream::connect(SocketAddr::new(a_ip, port)).unwrap();
        wait_until(|| {
            a.session.is_some() || {
                a.poll(true).unwrap();
                a.session.is_some()
            }
        });
        wrong.write_all(CONNECT).unwrap();
        let mut rejected = false;
        wait_until(|| {
            if let Some(events) = a.poll(true).unwrap() {
                rejected = matches!(events.as_slice(), [RouterEvent::Closed]);
            }
            rejected
        });
        assert!(a.session.is_none());
    }

    #[test]
    fn ipv4_keepalive_rewrites_provider_addresses_on_each_leg() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(127, 84, 0, 1));
        let a_peer = IpAddr::V4(Ipv4Addr::new(127, 84, 0, 2));
        let b_ip = IpAddr::V4(Ipv4Addr::new(127, 84, 0, 3));
        let b_peer = IpAddr::V4(Ipv4Addr::new(127, 84, 0, 4));
        let port = 18_398;
        let mut a = AnyNetPort::open_at(a_ip, a_peer, port).unwrap();
        let mut b = AnyNetPort::open_at(b_ip, b_peer, port).unwrap();
        let guest_a = UdpSocket::bind(SocketAddr::new(a_peer, port)).unwrap();
        let guest_b = UdpSocket::bind(SocketAddr::new(b_peer, port)).unwrap();
        guest_a
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        guest_b
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let request = Keepalive {
            kind: Kind::Request,
            source: Ipv4Addr::new(127, 84, 0, 2),
            destination: Ipv4Addr::new(127, 84, 0, 1),
        }
        .encode();
        guest_a
            .send_to(&request, SocketAddr::new(a_ip, port))
            .unwrap();
        wait_until(|| a.poll(false).unwrap().is_some());
        assert_eq!(a.incoming_udp.len(), 1);
        assert!(b
            .send(RoutedUnit::AnyNetUdpDatagram(next_udp_unit(&mut a)))
            .unwrap());
        let mut bytes = [0; 64];
        let (n, source) = guest_b.recv_from(&mut bytes).unwrap();
        assert_eq!(source, SocketAddr::new(b_ip, port));
        let forwarded = Keepalive::decode(&bytes[..n]).unwrap();
        assert_eq!(forwarded.kind, Kind::Request);
        assert_eq!(forwarded.source, Ipv4Addr::new(127, 84, 0, 3));
        assert_eq!(forwarded.destination, Ipv4Addr::new(127, 84, 0, 4));

        let response = Keepalive {
            kind: Kind::Response,
            ..forwarded
        }
        .encode();
        guest_b
            .send_to(&response, SocketAddr::new(b_ip, port))
            .unwrap();
        assert!(a
            .send(RoutedUnit::AnyNetUdpDatagram(next_udp_unit(&mut b)))
            .unwrap());
        let (n, source) = guest_a.recv_from(&mut bytes).unwrap();
        assert_eq!(source, SocketAddr::new(a_ip, port));
        let returned = Keepalive::decode(&bytes[..n]).unwrap();
        assert_eq!(returned.kind, Kind::Response);
        assert_eq!(returned.source, Ipv4Addr::new(127, 84, 0, 2));
        assert_eq!(returned.destination, Ipv4Addr::new(127, 84, 0, 1));

        guest_b
            .send_to(&response, SocketAddr::new(b_ip, port))
            .unwrap();
        let mut closed = false;
        wait_until(|| {
            closed = b
                .poll(true)
                .unwrap()
                .is_some_and(|events| matches!(events.as_slice(), [RouterEvent::Closed]));
            closed
        });
    }
}
