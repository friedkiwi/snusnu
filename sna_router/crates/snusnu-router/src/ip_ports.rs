//! Homogeneous IP-side SNA route attachments. These ports preserve native
//! protocol records; they do not translate AnyNet or HPR to LLC2 PIUs.

use crate::routing::{RoutePort, RoutedUnit, RouterEvent};
use std::{collections::VecDeque, io, net::IpAddr};
use transport_ip_sna::ee::{Datagram as EeDatagram, EeSockets, CONTROL_PORT};

const EE_QUEUE_LIMIT: usize = 64;

/// One EE adjacency. The five bound UDP sockets share one local IP and
/// address exactly one configured remote IP. The router pairs it with a
/// second EE port; source UDP port is deliberately not used as a selector.
pub(crate) struct EePort {
    sockets: EeSockets,
    local_ip: IpAddr,
    peer_ip: IpAddr,
    outgoing: VecDeque<EeDatagram>,
    completed: usize,
}

impl EePort {
    pub(crate) fn open(local_ip: IpAddr, peer_ip: IpAddr) -> io::Result<Self> {
        if local_ip == peer_ip {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EE local and peer IP must differ",
            ));
        }
        let sockets = EeSockets::bind(local_ip)?;
        tracing::info!(%local_ip, %peer_ip, "EE UDP attachment opened");
        Ok(Self {
            sockets,
            local_ip,
            peer_ip,
            outgoing: VecDeque::new(),
            completed: 0,
        })
    }

    fn drain(&mut self) -> io::Result<()> {
        while let Some(datagram) = self.outgoing.front() {
            match self.sockets.send(self.peer_ip, datagram) {
                Ok(()) => {
                    let sent = self.outgoing.pop_front().unwrap();
                    self.completed += 1;
                    tracing::debug!(
                        local_ip = %self.local_ip,
                        peer_ip = %self.peer_ip,
                        destination_port = sent.port,
                        dsap = sent.dsap,
                        ssap = sent.ssap,
                        kind = ?sent.kind,
                        hex = %hex(&sent.payload),
                        "EE datagram sent"
                    );
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

impl RoutePort for EePort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if !can_accept_information {
            return Ok(None);
        }
        let (source, datagram) = match self.sockets.receive() {
            Ok(Some(received)) => received,
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                tracing::warn!(local_ip = %self.local_ip, error = %error, "malformed EE datagram discarded");
                return Ok(Some(Vec::new()));
            }
            Err(error) => return Err(error),
        };
        if source.ip() != self.peer_ip {
            tracing::warn!(
                local_ip = %self.local_ip,
                source_ip = %source.ip(),
                configured_peer_ip = %self.peer_ip,
                "EE datagram from unconfigured peer discarded"
            );
            return Ok(Some(Vec::new()));
        }
        tracing::debug!(
            local_ip = %self.local_ip,
            peer_ip = %self.peer_ip,
            source_port = source.port(),
            destination_port = datagram.port,
            dsap = datagram.dsap,
            ssap = datagram.ssap,
            kind = ?datagram.kind,
            hex = %hex(&datagram.payload),
            "EE datagram received"
        );
        Ok(Some(vec![RouterEvent::Unit(RoutedUnit::EeDatagram {
            priority: (datagram.port - CONTROL_PORT) as u8,
            payload: datagram.payload,
        })]))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.drain()?;
        Ok(Vec::new())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        let RoutedUnit::EeDatagram { priority, payload } = unit else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EE route cannot receive another SNA profile",
            ));
        };
        let port = CONTROL_PORT
            .checked_add(priority as u16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid EE priority"))?;
        let datagram = EeDatagram::decode(port, payload)?;
        if self.outgoing.len() >= EE_QUEUE_LIMIT {
            return Ok(false);
        }
        self.outgoing.push_back(datagram);
        self.drain()?;
        Ok(true)
    }

    fn has_capacity(&self) -> bool {
        self.outgoing.len() < EE_QUEUE_LIMIT
    }

    fn available_receive_slots(&self) -> usize {
        EE_QUEUE_LIMIT - self.outgoing.len()
    }

    fn take_completed_information_count(&mut self) -> usize {
        std::mem::take(&mut self.completed)
    }

    fn set_ingress_busy(&mut self, _busy: bool) -> io::Result<()> {
        Ok(())
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.outgoing.clear();
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddr, UdpSocket},
        thread,
        time::{Duration, Instant},
    };

    fn wait_event(port: &mut EePort) -> io::Result<Vec<RouterEvent>> {
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            if let Some(events) = port.poll(true)? {
                return Ok(events);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "EE datagram missing",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn ee_port_preserves_priority_and_rejects_other_sources() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(127, 82, 0, 1));
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 82, 0, 2));
        let stranger_ip = IpAddr::V4(Ipv4Addr::new(127, 82, 0, 3));
        let mut port = EePort::open(local_ip, peer_ip).unwrap();
        let target = SocketAddr::new(local_ip, CONTROL_PORT);
        let stranger = UdpSocket::bind(SocketAddr::new(stranger_ip, 0)).unwrap();
        stranger.send_to(&[4, 4, 0xaf, 0x81], target).unwrap();
        assert!(wait_event(&mut port).unwrap().is_empty());

        let peer = UdpSocket::bind(SocketAddr::new(peer_ip, 0)).unwrap();
        peer.send_to(&[4, 4, 0xaf, 0x81], target).unwrap();
        let events = wait_event(&mut port).unwrap();
        assert!(matches!(
            events.as_slice(),
            [RouterEvent::Unit(RoutedUnit::EeDatagram {
                priority: 0,
                payload
            })] if payload == &[4, 4, 0xaf, 0x81]
        ));

        peer.send_to(&[4, 4, 0x00], target).unwrap();
        assert!(wait_event(&mut port).unwrap().is_empty());

        let capture = UdpSocket::bind(SocketAddr::new(peer_ip, CONTROL_PORT + 2)).unwrap();
        capture
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        assert!(port
            .send(RoutedUnit::EeDatagram {
                priority: 2,
                payload: vec![0x80, 0x80, 0x03, 0x12],
            })
            .unwrap());
        let mut buf = [0u8; 32];
        let (n, source) = capture.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x80, 0x80, 0x03, 0x12]);
        assert_eq!(source, SocketAddr::new(local_ip, CONTROL_PORT + 2));
    }
}
