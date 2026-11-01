//! Bounded TCP62/MPTN framing from the IBM-authored TCP62 draft, sections 3
//! and 5: https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00
//!
//! This module can relay complete records between equivalent AnyNet peers.
//! It does not translate native APPN control flows or LLC2 PIUs.

use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
};

pub const MPTN_PORT: u16 = 397;
pub const MAX_RECORD: usize = 65_536;
const MAX_QUEUED: usize = MAX_RECORD * 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpKind {
    Connect,
    Normal,
    Expedited,
    ExpeditedAck,
    Abort,
    Segmented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpKind {
    OutOfBand,
    Keepalive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpRecord {
    pub kind: TcpKind,
    /// Complete TCP record, including its four-byte, big-endian total length.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDatagram {
    pub kind: UdpKind,
    /// Complete UDP payload, including its four-byte, big-endian total length.
    pub bytes: Vec<u8>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn check_length(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() < 5 || bytes.len() > MAX_RECORD {
        return Err(invalid("MPTN record size is invalid"));
    }
    let declared = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if declared != bytes.len() {
        return Err(invalid("MPTN record length mismatch"));
    }
    Ok(())
}

impl TcpRecord {
    pub fn decode(bytes: Vec<u8>) -> io::Result<Self> {
        check_length(&bytes)?;
        let kind = match bytes[4] {
            0x80 => {
                crate::mptn_connect::Connect::decode(&bytes)?;
                TcpKind::Connect
            }
            0x00 => TcpKind::Normal,
            0x01 => TcpKind::Expedited,
            0x03 => TcpKind::ExpeditedAck,
            0x10 => TcpKind::Abort,
            0x20 => TcpKind::Segmented,
            _ => return Err(invalid("unsupported MPTN TCP compensation")),
        };
        Ok(Self { kind, bytes })
    }
}

impl UdpDatagram {
    pub fn decode(bytes: Vec<u8>) -> io::Result<Self> {
        check_length(&bytes)?;
        let kind = match bytes[4] {
            0x83 => {
                if bytes.len() < 10 {
                    return Err(invalid("short MPTN out-of-band command"));
                }
                let command_length = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
                if !(6..=bytes.len() - 4).contains(&command_length) {
                    return Err(invalid("MPTN out-of-band command length mismatch"));
                }
                UdpKind::OutOfBand
            }
            0x84 => {
                if bytes.len() < 8 {
                    return Err(invalid("short MPTN keepalive command"));
                }
                let command_length = u16::from_be_bytes(bytes[6..8].try_into().unwrap()) as usize;
                if command_length + 4 != bytes.len() {
                    return Err(invalid("MPTN keepalive command length mismatch"));
                }
                UdpKind::Keepalive
            }
            _ => return Err(invalid("unsupported MPTN UDP command")),
        };
        Ok(Self { kind, bytes })
    }
}

/// Incremental bounded TCP record reader. TCP boundaries are unrelated to
/// MPTN record boundaries.
#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<TcpRecord>> {
        if self.buffer.len() + bytes.len() > MAX_QUEUED {
            return Err(invalid("MPTN receive buffer full"));
        }
        self.buffer.extend_from_slice(bytes);
        let mut records = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
            if !(5..=MAX_RECORD).contains(&len) {
                return Err(invalid("MPTN record length outside configured bound"));
            }
            if self.buffer.len() < len {
                break;
            }
            let bytes: Vec<_> = self.buffer.drain(..len).collect();
            records.push(TcpRecord::decode(bytes)?);
        }
        Ok(records)
    }
}

/// Nonblocking, bounded single TCP62 session. A router must pair this with
/// UDP/397 handling and maintain MPTN session identity externally.
pub struct TcpSession {
    stream: TcpStream,
    decoder: Decoder,
    closed: bool,
    outbound: VecDeque<Vec<u8>>,
    outbound_bytes: usize,
    write_offset: usize,
}

impl TcpSession {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            decoder: Decoder::default(),
            closed: false,
            outbound: VecDeque::new(),
            outbound_bytes: 0,
            write_offset: 0,
        })
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn receive(&mut self) -> io::Result<Vec<TcpRecord>> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MPTN TCP closed",
            ));
        }
        let mut result = Vec::new();
        let mut scratch = [0; 8192];
        loop {
            match self.stream.read(&mut scratch) {
                Ok(0) => {
                    self.closed = true;
                    if result.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "MPTN TCP closed",
                        ));
                    }
                    return Ok(result);
                }
                Ok(n) => result.extend(self.decoder.push(&scratch[..n])?),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(result),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
    }

    pub fn queue(&mut self, record: TcpRecord) -> io::Result<()> {
        if self.outbound_bytes + record.bytes.len() > MAX_QUEUED {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "MPTN send queue full",
            ));
        }
        self.outbound_bytes += record.bytes.len();
        self.outbound.push_back(record.bytes);
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        while let Some(front) = self.outbound.front() {
            match self.stream.write(&front[self.write_offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "MPTN TCP write zero",
                    ))
                }
                Ok(n) => self.write_offset += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
            if self.write_offset == front.len() {
                let sent = self.outbound.pop_front().unwrap();
                self.outbound_bytes -= sent.len();
                self.write_offset = 0;
            }
        }
        Ok(())
    }

    pub fn has_capacity(&self) -> bool {
        self.outbound_bytes < MAX_QUEUED - MAX_RECORD
    }
}

pub fn listen_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn receive_udp(socket: &UdpSocket) -> io::Result<Option<(SocketAddr, UdpDatagram)>> {
    let mut scratch = [0u8; MAX_RECORD];
    match socket.recv_from(&mut scratch) {
        Ok((n, addr)) => Ok(Some((addr, UdpDatagram::decode(scratch[..n].to_vec())?))),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tcp_records_are_reassembled() {
        let mut decoder = Decoder::default();
        assert!(decoder.push(&[0, 0, 0]).unwrap().is_empty());
        let records = decoder.push(&[7, 0, 0xaa, 0xbb, 0, 0, 0, 5, 3]).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, TcpKind::Normal);
        assert_eq!(records[1].kind, TcpKind::ExpeditedAck);
    }

    #[test]
    fn rejects_malformed_or_unknown_records() {
        assert!(TcpRecord::decode(vec![0, 0, 0, 5, 0x80]).is_err());
        assert!(TcpRecord::decode(vec![0, 0, 0, 5, 0xff]).is_err());
        assert!(UdpDatagram::decode(vec![0, 0, 0, 5, 0x84]).is_err());
        assert!(Decoder::default().push(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn connect_record_uses_strict_mptn_validation() {
        // Lengths are consistent, but no addresses, correlator or BIND.
        assert!(TcpRecord::decode(vec![0, 0, 0, 11, 0x80, 0x0a, 0, 0, 0, 7, 8]).is_err());
    }
}
