//! One outbound TCP62 circuit for a native-initiated LU6.2 session.
//!
//! The runtime chooses the peer and owns management/CNOS and UDP X'83'. This
//! connector owns only its TCP socket and the circuit-local conversion edge.

use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};
use transport_ip_sna::{
    anynet::{TcpSession, MAX_RECORD},
    mptn_connect::Connect,
    mptn_gateway_edge::{GatewayEdge, NativeLeg},
    mptn_management_initiator::ManagementInitiator,
    mptn_native_bridge::Bridge,
};

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
}
