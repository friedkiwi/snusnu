//! One outbound TCP62 circuit for a native-initiated LU6.2 session.
//!
//! The runtime chooses the peer and owns management/CNOS and UDP X'83'. This
//! connector owns only its TCP socket and the circuit-local conversion edge.

use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};
use transport_ip_sna::{
    anynet::{TcpSession, MAX_RECORD},
    mptn_connect::Connect,
    mptn_gateway_edge::{GatewayEdge, NativeLeg},
    mptn_keepalive::{Keepalive, Kind as KeepaliveKind},
    mptn_management_initiator::ManagementInitiator,
    mptn_native_bridge::Bridge,
    mptn_oob::{Compensation, Datagram as OobDatagram, Kind as OobKind},
};

const RECENT_OOB: usize = 64;

/// A UDP packet is handed to the matching circuit before this decision is
/// made. `Deliver` reserves one request until the native leg confirms it;
/// only then may the caller send the positive response.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum OutboundUdpAction {
    Reply(Vec<u8>),
    Deliver {
        sequence: u16,
        compensation: Compensation,
        reduced: Vec<u8>,
    },
    PendingDuplicate,
}

struct PendingOob {
    sequence: u16,
    packet: Vec<u8>,
    response: Vec<u8>,
    source: SocketAddr,
    compensation: Compensation,
    reduced: Vec<u8>,
    submitted: bool,
}

/// Session-local UDP/397 correlation for an outbound MPTN Connect. The
/// caller owns the shared socket and native delivery acknowledgement.
pub(crate) struct OutboundUdp {
    endpoint: OutboundEndpoint,
    connect: Connect,
    pending: Option<PendingOob>,
    completed: VecDeque<(u16, Vec<u8>, Vec<u8>)>,
}

impl OutboundUdp {
    pub(crate) fn new(endpoint: OutboundEndpoint, connect: Connect) -> io::Result<Self> {
        endpoint.validate()?;
        if connect.source.qualified_lu().is_err()
            || connect.destination.qualified_lu().is_err()
            || connect.correlator.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound UDP requires a qualified Connect identity",
            ));
        }
        Ok(Self {
            endpoint,
            connect,
            pending: None,
            completed: VecDeque::new(),
        })
    }

    pub(crate) fn receive(
        &mut self,
        packet: &[u8],
        source: SocketAddr,
    ) -> io::Result<OutboundUdpAction> {
        if source.ip() != self.endpoint.peer_ip {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP source differs from MPTN peer",
            ));
        }
        match packet.get(4).copied() {
            Some(0x84) => {
                let keepalive = Keepalive::decode(packet)?;
                keepalive.validate_ingress(source.ip(), self.endpoint.local_ip)?;
                if keepalive.kind != KeepaliveKind::Request {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsolicited MPTN keepalive response",
                    ));
                }
                Ok(OutboundUdpAction::Reply(
                    Keepalive {
                        kind: KeepaliveKind::Response,
                        ..keepalive
                    }
                    .encode()
                    .to_vec(),
                ))
            }
            Some(0x83) => {
                let oob = OobDatagram::decode(packet)?;
                if oob.kind != OobKind::Request
                    || !oob.options.is_empty()
                    || !oob.matches_connect(&self.connect)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP X'83' identity or profile differs from outbound Connect",
                    ));
                }
                if let Some(pending) = &self.pending {
                    if pending.sequence == oob.sequence && pending.packet == packet {
                        return if pending.submitted {
                            Ok(OutboundUdpAction::PendingDuplicate)
                        } else {
                            Ok(OutboundUdpAction::Deliver {
                                sequence: pending.sequence,
                                compensation: pending.compensation,
                                reduced: pending.reduced.clone(),
                            })
                        };
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "another UDP X'83' delivery is pending",
                    ));
                }
                if let Some((_, original, response)) = self
                    .completed
                    .iter()
                    .find(|(sequence, _, _)| *sequence == oob.sequence)
                {
                    if original != packet {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "UDP X'83' retransmission changed",
                        ));
                    }
                    return Ok(OutboundUdpAction::Reply(response.clone()));
                }
                let response = oob.positive_response()?;
                let action = OutboundUdpAction::Deliver {
                    sequence: oob.sequence,
                    compensation: oob.compensation.expect("validated X'83' request"),
                    reduced: oob.user_data.to_vec(),
                };
                self.pending = Some(PendingOob {
                    sequence: oob.sequence,
                    packet: packet.to_vec(),
                    response,
                    source,
                    compensation: oob.compensation.expect("validated X'83' request"),
                    reduced: oob.user_data.to_vec(),
                    submitted: false,
                });
                Ok(action)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported MPTN UDP command",
            )),
        }
    }

    pub(crate) fn complete_native_delivery(
        &mut self,
        sequence: u16,
    ) -> io::Result<(Vec<u8>, SocketAddr)> {
        if self
            .pending
            .as_ref()
            .is_none_or(|pending| pending.sequence != sequence || !pending.submitted)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP X'83' delivery is not pending",
            ));
        }
        let pending = self.pending.take().unwrap();
        let response = pending.response.clone();
        let source = pending.source;
        if self.completed.len() == RECENT_OOB {
            self.completed.pop_front();
        }
        self.completed
            .push_back((pending.sequence, pending.packet, pending.response));
        Ok((response, source))
    }

    pub(crate) fn pending_sequence(&self) -> Option<u16> {
        self.pending.as_ref().map(|pending| pending.sequence)
    }

    /// Re-offer a request when the native edge previously returned Busy.
    pub(crate) fn unsubmitted_delivery(&self) -> Option<OutboundUdpAction> {
        self.pending
            .as_ref()
            .filter(|pending| !pending.submitted)
            .map(|pending| OutboundUdpAction::Deliver {
                sequence: pending.sequence,
                compensation: pending.compensation,
                reduced: pending.reduced.clone(),
            })
    }

    pub(crate) fn mark_native_submitted(&mut self, sequence: u16) -> io::Result<()> {
        let pending = self
            .pending
            .as_mut()
            .filter(|pending| pending.sequence == sequence && !pending.submitted)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP X'83' native submission is not pending",
                )
            })?;
        pending.submitted = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutboundEndpoint {
    pub(crate) local_ip: IpAddr,
    pub(crate) peer_ip: IpAddr,
}

impl OutboundEndpoint {
    fn validate(self) -> io::Result<()> {
        if self.local_ip.is_unspecified()
            || self.peer_ip.is_unspecified()
            || self.local_ip == self.peer_ip
            || self.local_ip.is_ipv4() != self.peer_ip.is_ipv4()
            || self.local_ip.is_multicast()
            || self.peer_ip.is_multicast()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound TCP62 requires distinct unicast IP addresses of one family",
            ));
        }
        Ok(())
    }

    /// Connect one circuit from the configured local interface to peer
    /// TCP/397. Each call returns a separate credit and correlator domain.
    pub(crate) fn dial(self, timeout: Duration) -> io::Result<TcpSession> {
        Ok(TcpSession::new(self.dial_stream(397, timeout)?)?)
    }

    fn dial_port(self, port: u16, timeout: Duration) -> io::Result<TcpSession> {
        Ok(TcpSession::new(self.dial_stream(port, timeout)?)?)
    }

    fn dial_stream(self, port: u16, timeout: Duration) -> io::Result<TcpStream> {
        self.validate()?;
        if timeout.is_zero() || port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound TCP62 timeout and peer port must be nonzero",
            ));
        }
        let domain = if self.local_ip.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.bind(&SocketAddr::new(self.local_ip, 0).into())?;
        socket.connect_timeout(&SocketAddr::new(self.peer_ip, port).into(), timeout)?;
        let stream: TcpStream = socket.into();
        tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, peer_port = port, "outbound TCP62 circuit connected");
        Ok(stream)
    }

    /// Attach the independently validated native BIND conversion to this
    /// socket. The caller supplies a freshly allocated Connect correlator.
    pub(crate) fn open_edge<L: NativeLeg>(
        self,
        timeout: Duration,
        native: L,
        bridge: Bridge,
        connect: Connect,
    ) -> io::Result<GatewayEdge<L>> {
        if connect.source.qualified_lu().is_err()
            || connect.destination.qualified_lu().is_err()
            || connect.source == connect.destination
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound TCP62 Connect has invalid LU route",
            ));
        }
        Ok(GatewayEdge::new(
            native,
            self.dial(timeout)?,
            bridge,
            connect,
        ))
    }

    /// Complete the observed V5R4 SNASVCMG/CNOS exchange on its own TCP
    /// association. The caller must separately service UDP/397 and retain
    /// readiness only for the matching LU pair and peer address.
    pub(crate) fn establish_v5_management(
        self,
        timeout: Duration,
        local_lu: &str,
        remote_lu: &str,
    ) -> io::Result<()> {
        let mut entropy = [0u8; 20];
        File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        let local_name = encode_management_name(local_lu)?;
        let mut fqpcid = Vec::with_capacity(11 + local_name.len());
        fqpcid.extend_from_slice(&[0x60, (9 + local_name.len()) as u8]);
        fqpcid.extend_from_slice(&entropy[..8]);
        fqpcid.push(local_name.len() as u8);
        fqpcid.extend_from_slice(&local_name);
        let mut bind_token = [0x23, 0, 0, 0, 0, 0x80, 0];
        bind_token[1..5].copy_from_slice(&entropy[16..20]);
        let mut management = ManagementInitiator::new(
            local_lu,
            remote_lu,
            fqpcid,
            entropy[8..16].try_into().expect("eight random bytes"),
            bind_token,
            "",
            8,
        )?;
        let mut stream = self.dial_stream(397, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(management.connect_request())?;
        let cnos = management.accept_connect_response(&read_record(&mut stream)?)?;
        stream.write_all(&cnos)?;
        let bis = management.accept_cnos_reply(&read_record(&mut stream)?)?;
        stream.write_all(&bis)?;
        let unbind = management.accept_bis(&read_record(&mut stream)?)?;
        stream.write_all(&unbind)?;
        management.mark_unbind_sent(&unbind)?;
        let mut tail = [0u8; 1];
        if stream.read(&mut tail)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MPTN management peer sent data after UNBIND",
            ));
        }
        management.observe_peer_close()?;
        tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip, local_lu, remote_lu, "outbound TCP62 management ready");
        Ok(())
    }
}

fn encode_management_name(name: &str) -> io::Result<Vec<u8>> {
    let (netid, lu) = name.split_once('.').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "management LU must be NETID.LU",
        )
    })?;
    if netid.is_empty() || netid.len() > 8 || lu.is_empty() || lu.len() > 8 || lu.contains('.') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid management LU",
        ));
    }
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid management LU character",
                    ))
                }
            })
        })
        .collect()
}

fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if !(5..=MAX_RECORD).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP62 management record length outside bound",
        ));
    }
    let mut record = vec![0u8; length];
    record[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut record[4..])?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, TcpListener},
        thread,
    };
    use transport_ip_sna::{
        mptn_connect::{Address, Direction, TransportRequirements},
        mptn_oob::build_request,
    };

    fn udp_fixture() -> (OutboundEndpoint, Connect, SocketAddr) {
        let endpoint = OutboundEndpoint {
            local_ip: "10.99.4.10".parse().unwrap(),
            peer_ip: "10.99.4.3".parse().unwrap(),
        };
        let connect = Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            source: Address {
                node: vec![
                    0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc1,
                ],
            },
            destination: Address {
                node: vec![
                    0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2,
                ],
            },
            correlator: vec![1, 2, 3, 4, 5, 6, 7, 8],
            requirements: TransportRequirements {
                max_record: 0x8005,
                max_expedited: 0x76,
                max_termination: 0x76,
            },
            options: Vec::new(),
        };
        (endpoint, connect, "10.99.4.3:397".parse().unwrap())
    }

    #[test]
    fn rejects_ambiguous_or_unusable_endpoints_before_dial() {
        for endpoint in [
            OutboundEndpoint {
                local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            OutboundEndpoint {
                local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            OutboundEndpoint {
                local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                peer_ip: IpAddr::V6("::1".parse().unwrap()),
            },
        ] {
            assert_eq!(
                endpoint
                    .dial_port(397, Duration::from_millis(10))
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn dials_from_selected_local_ip_as_independent_session() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = OutboundEndpoint {
            local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        // Identical local and peer IP is invalid in real deployments; use
        // a second loopback address so this test exercises the socket path.
        let endpoint = OutboundEndpoint {
            local_ip: "127.0.0.2".parse().unwrap(),
            ..endpoint
        };
        let accepted = thread::spawn(move || {
            let (_, remote) = listener.accept().unwrap();
            remote.ip()
        });
        let session = endpoint.dial_port(port, Duration::from_secs(1)).unwrap();
        assert_eq!(session.peer_addr().unwrap().ip(), endpoint.peer_ip);
        assert_eq!(accepted.join().unwrap(), endpoint.local_ip);
    }

    #[test]
    fn management_name_is_strictly_network_qualified() {
        assert_eq!(encode_management_name("SOLNET.SNAA").unwrap().len(), 11);
        for bad in ["SNAA", "SOLNET.", "SOLNET.SNAA.EXTRA", "solnet.SNAA"] {
            assert!(encode_management_name(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn oversized_management_record_is_rejected_before_allocation() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(&((MAX_RECORD as u32) + 1).to_be_bytes())
                .unwrap();
        });
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        assert_eq!(
            read_record(&mut stream).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        writer.join().unwrap();
    }

    #[test]
    fn udp_oob_waits_for_native_delivery_and_replays_exact_ack() {
        let (endpoint, connect, source) = udp_fixture();
        let mut state = OutboundUdp::new(endpoint, connect.clone()).unwrap();
        let packet =
            build_request(&connect, 0, Compensation::Expedited, &[0, 0, 0, 0, 0, 0xc9]).unwrap();
        assert_eq!(
            state.receive(&packet, source).unwrap(),
            OutboundUdpAction::Deliver {
                sequence: 0,
                compensation: Compensation::Expedited,
                reduced: vec![0, 0, 0, 0, 0, 0xc9],
            }
        );
        assert!(matches!(
            state.receive(&packet, source).unwrap(),
            OutboundUdpAction::Deliver { sequence: 0, .. }
        ));
        assert!(state.unsubmitted_delivery().is_some());
        state.mark_native_submitted(0).unwrap();
        assert_eq!(
            state.receive(&packet, source).unwrap(),
            OutboundUdpAction::PendingDuplicate
        );
        let (ack, destination) = state.complete_native_delivery(0).unwrap();
        assert_eq!(destination, source);
        assert_eq!(
            OobDatagram::decode(&ack).unwrap().kind,
            OobKind::PositiveResponse
        );
        assert_eq!(
            state.receive(&packet, source).unwrap(),
            OutboundUdpAction::Reply(ack)
        );
        assert!(state.complete_native_delivery(0).is_err());
    }

    #[test]
    fn udp_oob_rejects_wrong_peer_correlator_and_changed_retry() {
        let (endpoint, connect, source) = udp_fixture();
        let mut state = OutboundUdp::new(endpoint, connect.clone()).unwrap();
        let packet = build_request(&connect, 4, Compensation::Abort, &[0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            state
                .receive(&packet, "10.99.4.4:397".parse().unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut wrong = connect.clone();
        wrong.correlator[0] ^= 0xff;
        let wrong_packet = build_request(&wrong, 4, Compensation::Abort, &[0, 0, 0, 0, 0]).unwrap();
        assert!(state.receive(&wrong_packet, source).is_err());
        assert!(matches!(
            state.receive(&packet, source).unwrap(),
            OutboundUdpAction::Deliver { .. }
        ));
        state.mark_native_submitted(4).unwrap();
        state.complete_native_delivery(4).unwrap();
        let changed = build_request(&connect, 4, Compensation::Abort, &[0, 0, 0, 0, 1]).unwrap();
        assert_eq!(
            state.receive(&changed, source).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn udp_keepalive_replies_to_valid_provider_pair() {
        let (endpoint, connect, source) = udp_fixture();
        let mut state = OutboundUdp::new(endpoint, connect).unwrap();
        let request = Keepalive {
            kind: KeepaliveKind::Request,
            source: "10.99.4.3".parse().unwrap(),
            destination: "10.99.4.10".parse().unwrap(),
        }
        .encode();
        let OutboundUdpAction::Reply(reply) = state.receive(&request, source).unwrap() else {
            panic!("no keepalive reply")
        };
        assert_eq!(
            Keepalive::decode(&reply).unwrap().kind,
            KeepaliveKind::Response
        );
    }
}
