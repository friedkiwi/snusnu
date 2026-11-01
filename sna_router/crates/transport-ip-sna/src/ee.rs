//! Enterprise Extender / HPR IP DLC framing from RFC 2353, sections 2.1–2.3,
//! 2.6.1 and appendix 6: https://www.rfc-editor.org/rfc/rfc2353.html
//!
//! This validates and relays LDLC/HPR datagrams between equivalent peers.
//! HPR/APPN routing, XID3 negotiation and LLC2 conversion are outside this
//! wire adapter.

use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

pub const CONTROL_PORT: u16 = 12000;
pub const NETWORK_PORT: u16 = 12001;
pub const HIGH_PORT: u16 = 12002;
pub const MEDIUM_PORT: u16 = 12003;
pub const LOW_PORT: u16 = 12004;
pub const MAX_DATAGRAM: usize = 65_507;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LdlcKind {
    Xid,
    Test,
    Disc,
    Dm,
    UiNlp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub port: u16,
    pub dsap: u8,
    pub ssap: u8,
    pub kind: LdlcKind,
    /// Complete UDP payload: DSAP, SSAP, control byte, information.
    pub payload: Vec<u8>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

impl Datagram {
    pub fn decode(port: u16, payload: Vec<u8>) -> io::Result<Self> {
        if !(CONTROL_PORT..=LOW_PORT).contains(&port) {
            return Err(invalid("invalid EE UDP port"));
        }
        if payload.len() < 3 || payload.len() > MAX_DATAGRAM {
            return Err(invalid("invalid EE datagram length"));
        }
        let control = payload[2] & !0x10; // LLC U-frame P/F bit.
        let kind = match control {
            0xaf => LdlcKind::Xid,
            0xe3 => LdlcKind::Test,
            0x43 => LdlcKind::Disc,
            0x0f => LdlcKind::Dm,
            0x03 => LdlcKind::UiNlp,
            _ => return Err(invalid("unsupported EE LDLC control")),
        };
        if port != CONTROL_PORT && kind != LdlcKind::UiNlp {
            return Err(invalid("EE priority port carries non-UI frame"));
        }
        if kind == LdlcKind::UiNlp && payload.len() == 3 {
            return Err(invalid("EE UI has no HPR NLP"));
        }
        Ok(Self {
            port,
            dsap: payload[0],
            ssap: payload[1],
            kind,
            payload,
        })
    }

    pub fn destination(&self, peer_ip: std::net::IpAddr) -> SocketAddr {
        SocketAddr::new(peer_ip, self.port)
    }
}

/// Five UDP sockets, one per EE priority, bound to a single local IP.
/// Datagrams retain the actual destination priority port when relayed.
pub struct EeSockets {
    sockets: Vec<UdpSocket>,
    next_socket: usize,
}

impl EeSockets {
    pub fn bind(local_ip: std::net::IpAddr) -> io::Result<Self> {
        let mut sockets = Vec::with_capacity(5);
        for port in CONTROL_PORT..=LOW_PORT {
            let socket = UdpSocket::bind(SocketAddr::new(local_ip, port))?;
            socket.set_nonblocking(true)?;
            sockets.push(socket);
        }
        Ok(Self {
            sockets,
            next_socket: 0,
        })
    }

    pub fn receive(&mut self) -> io::Result<Option<(SocketAddr, Datagram)>> {
        let mut scratch = [0u8; MAX_DATAGRAM];
        for checked in 0..self.sockets.len() {
            let offset = (self.next_socket + checked) % self.sockets.len();
            let socket = &self.sockets[offset];
            match socket.recv_from(&mut scratch) {
                Ok((n, source)) => {
                    self.next_socket = (offset + 1) % self.sockets.len();
                    let port = CONTROL_PORT + offset as u16;
                    return Ok(Some((
                        source,
                        Datagram::decode(port, scratch[..n].to_vec())?,
                    )));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    pub fn send(&self, destination_ip: std::net::IpAddr, datagram: &Datagram) -> io::Result<()> {
        let index = usize::from(datagram.port - CONTROL_PORT);
        let sent =
            self.sockets[index].send_to(&datagram.payload, datagram.destination(destination_ip))?;
        if sent != datagram.payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short EE datagram send",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_and_priority_ui() {
        let xid = Datagram::decode(CONTROL_PORT, vec![4, 5, 0xbf, 0x81]).unwrap();
        assert_eq!(xid.kind, LdlcKind::Xid);
        assert_eq!(xid.ssap, 5);
        let nlp = Datagram::decode(HIGH_PORT, vec![0x80, 0x80, 3, 0x12]).unwrap();
        assert_eq!(nlp.kind, LdlcKind::UiNlp);
    }

    #[test]
    fn rejects_llc2_and_misplaced_controls() {
        assert!(Datagram::decode(CONTROL_PORT, vec![4, 4, 0x00, 0x11]).is_err());
        assert!(Datagram::decode(HIGH_PORT, vec![4, 4, 0xaf, 0x81]).is_err());
        assert!(Datagram::decode(12005, vec![4, 4, 3, 0x81]).is_err());
        assert!(Datagram::decode(HIGH_PORT, vec![4, 4, 3]).is_err());
    }
}
