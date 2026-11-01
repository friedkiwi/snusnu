//! One bounded TCP62/AnyNet session attachment.
//!
//! This relays complete TCP62 records between equivalent AnyNet peers. It
//! deliberately closes a session if UDP/397 traffic appears: node-pair
//! keepalives and expedited commands can carry provider IP addresses and
//! require a separate session-aware translation before proxying is safe.

use crate::routing::{RoutePort, RoutedUnit, RouterEvent};
use router_core::packet_log::hex_dump;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
};
use transport_ip_sna::anynet::{self, TcpKind, TcpRecord, TcpSession};

const PENDING_LIMIT: usize = anynet::MAX_RECORD * 4;

pub(crate) struct AnyNetPort {
    local_ip: IpAddr,
    peer_ip: IpAddr,
    port: u16,
    listener: TcpListener,
    udp: UdpSocket,
    session: Option<TcpSession>,
    connecting: Option<TcpStream>,
    incoming: VecDeque<TcpRecord>,
    pending: VecDeque<TcpRecord>,
    pending_bytes: usize,
}

impl AnyNetPort {
    pub(crate) fn open(local_ip: IpAddr, peer_ip: IpAddr) -> io::Result<Self> {
        Self::open_at(local_ip, peer_ip, anynet::MPTN_PORT)
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
            pending: VecDeque::new(),
            pending_bytes: 0,
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

    fn check_udp(&mut self) -> io::Result<Option<Vec<RouterEvent>>> {
        let mut bytes = [0; anynet::MAX_RECORD];
        match self.udp.recv_from(&mut bytes) {
            Ok((size, source)) => {
                if source.ip() != self.peer_ip {
                    tracing::warn!(local_ip = %self.local_ip, source_ip = %source.ip(), "UDP/397 from unconfigured peer discarded");
                    return Ok(Some(Vec::new()));
                }
                let decoded = anynet::UdpDatagram::decode(bytes[..size].to_vec());
                tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, source_port = source.port(), kind = ?decoded.as_ref().map(|message| message.kind), "AnyNet UDP/397 requires provider-address translation; session closed");
                tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, bytes = size, hex = %hex_dump(&bytes[..size]), "unsupported AnyNet UDP datagram");
                self.disconnect()?;
                Ok(Some(vec![RouterEvent::Closed]))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn pop_incoming(&mut self) -> Option<Vec<RouterEvent>> {
        let record = self.incoming.pop_front()?;
        tracing::debug!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, kind = ?record.kind, bytes = record.bytes.len(), hex = %hex_dump(&record.bytes), "AnyNet TCP record received");
        Some(vec![RouterEvent::Unit(RoutedUnit::AnyNetTcpRecord(
            record.bytes,
        ))])
    }
}

impl RoutePort for AnyNetPort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if let Some(events) = self.check_udp()? {
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
        if self.connecting.is_some() {
            if let Err(error) = self.finish_dial() {
                tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, error = %error, "AnyNet TCP connection failed");
                self.disconnect()?;
                return Ok(vec![RouterEvent::Closed]);
            }
        }
        self.drain()?;
        Ok(Vec::new())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        let RoutedUnit::AnyNetTcpRecord(bytes) = unit else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyNet port cannot receive another SNA profile",
            ));
        };
        let record = TcpRecord::decode(bytes)?;
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
        self.pending.clear();
        self.pending_bytes = 0;
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.drain()
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

        let udp = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        udp.send_to(&[0, 0, 0, 8, 0x84, 0, 0, 4], SocketAddr::new(a_ip, port))
            .unwrap();
        assert!(matches!(
            a.poll(true).unwrap().unwrap().as_slice(),
            [RouterEvent::Closed]
        ));
        assert!(a.session.is_none());
    }
}
