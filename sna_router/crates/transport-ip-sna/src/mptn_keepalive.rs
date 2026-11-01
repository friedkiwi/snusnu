//! IPv4 node-pair keepalives on AnyNet UDP/397.
//!
//! IBM's TCP62 draft, sections 3.3.2 and 5.3.4, defines these as node-pair
//! commands, independent of one TCP session. This module implements only the
//! IPv4 provider-address shape observed with OS/400 V5R4. Other MPTN address
//! families and UDP/397 out-of-band commands require separate handling.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

const RECORD_BYTES: usize = 24;
const COMMAND_BYTES: u16 = 20;
const ADDRESS_PREFIX: [u8; 3] = [0x02, 0x01, 0x05];
const NULL_LOCAL_ADDRESS: u8 = 0x01;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Keepalive {
    pub kind: Kind,
    /// Provider address of the original request sender. The response retains
    /// this order even though its outer UDP source and destination reverse.
    pub source: Ipv4Addr,
    /// Provider address of the original request receiver.
    pub destination: Ipv4Addr,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn ipv4(address: IpAddr) -> io::Result<Ipv4Addr> {
    match address {
        IpAddr::V4(address) => Ok(address),
        IpAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 MPTN provider address unsupported",
        )),
    }
}

fn decode_address(bytes: &[u8]) -> io::Result<Ipv4Addr> {
    if bytes.len() != 8 || bytes[..3] != ADDRESS_PREFIX || bytes[7] != NULL_LOCAL_ADDRESS {
        return Err(invalid("unsupported MPTN keepalive provider address"));
    }
    Ok(Ipv4Addr::new(bytes[3], bytes[4], bytes[5], bytes[6]))
}

impl Keepalive {
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != RECORD_BYTES
            || u32::from_be_bytes(bytes[..4].try_into().unwrap()) != RECORD_BYTES as u32
            || bytes[4] != 0x84
            || u16::from_be_bytes(bytes[6..8].try_into().unwrap()) != COMMAND_BYTES
        {
            return Err(invalid("invalid MPTN keepalive length or command"));
        }
        let kind = match bytes[5] {
            0x02 => Kind::Request,
            0x82 => Kind::Response,
            _ => return Err(invalid("unsupported MPTN keepalive processing flags")),
        };
        Ok(Self {
            kind,
            source: decode_address(&bytes[8..16])?,
            destination: decode_address(&bytes[16..24])?,
        })
    }

    pub fn encode(self) -> [u8; RECORD_BYTES] {
        let mut result = [0u8; RECORD_BYTES];
        result[..4].copy_from_slice(&(RECORD_BYTES as u32).to_be_bytes());
        result[4] = 0x84;
        result[5] = match self.kind {
            Kind::Request => 0x02,
            Kind::Response => 0x82,
        };
        result[6..8].copy_from_slice(&COMMAND_BYTES.to_be_bytes());
        for (offset, address) in [(8, self.source), (16, self.destination)] {
            result[offset..offset + 3].copy_from_slice(&ADDRESS_PREFIX);
            result[offset + 3..offset + 7].copy_from_slice(&address.octets());
            result[offset + 7] = NULL_LOCAL_ADDRESS;
        }
        result
    }

    /// Check that this UDP packet belongs to the configured router-facing
    /// adjacency. The embedded provider pair remains in request order in a
    /// response; only the outer UDP source and destination switch.
    pub fn validate_ingress(self, peer: IpAddr, local: IpAddr) -> io::Result<()> {
        let peer = ipv4(peer)?;
        let local = ipv4(local)?;
        let expected = match self.kind {
            Kind::Request => (peer, local),
            Kind::Response => (local, peer),
        };
        if (self.source, self.destination) != expected {
            return Err(invalid(
                "MPTN keepalive provider pair does not match ingress",
            ));
        }
        Ok(())
    }

    /// Rewrite the provider pair for the destination router leg. This is
    /// required when each OS/400 peer addresses a different local router IP.
    pub fn for_egress(self, local: IpAddr, peer: IpAddr) -> io::Result<Self> {
        let local = ipv4(local)?;
        let peer = ipv4(peer)?;
        let (source, destination) = match self.kind {
            Kind::Request => (local, peer),
            Kind::Response => (peer, local),
        };
        Ok(Self {
            kind: self.kind,
            source,
            destination,
        })
    }
}

/// Node-pair response correlation. There is no request ID on the wire, so a
/// response is accepted only after a request was sent to this peer. Repeated
/// requests before a response are legitimate retransmissions.
#[derive(Default)]
pub struct Exchange {
    pending_response: bool,
}

impl Exchange {
    pub fn sent(&mut self, kind: Kind) {
        if kind == Kind::Request {
            self.pending_response = true;
        }
    }

    pub fn received(&mut self, kind: Kind) -> io::Result<()> {
        if kind == Kind::Response {
            if !self.pending_response {
                return Err(invalid("unsolicited MPTN keepalive response"));
            }
            self.pending_response = false;
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.pending_response = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized node-pair keepalive from the V5R4 capture. No SNA payload.
    const REQUEST: [u8; 24] = [
        0, 0, 0, 24, 0x84, 0x02, 0, 20, 0x02, 0x01, 0x05, 10, 99, 4, 3, 0x01, 0x02, 0x01, 0x05, 10,
        99, 4, 2, 0x01,
    ];

    #[test]
    fn decodes_captured_request_and_response_pair() {
        let request = Keepalive::decode(&REQUEST).unwrap();
        assert_eq!(request.kind, Kind::Request);
        assert_eq!(request.source, Ipv4Addr::new(10, 99, 4, 3));
        assert_eq!(request.destination, Ipv4Addr::new(10, 99, 4, 2));
        assert_eq!(request.encode(), REQUEST);
        let mut response = REQUEST;
        response[5] = 0x82;
        assert_eq!(Keepalive::decode(&response).unwrap().kind, Kind::Response);
        assert_eq!(Keepalive::decode(&response).unwrap().encode(), response);
    }

    #[test]
    fn rewrites_both_router_legs_and_correlates_response() {
        let b_peer = IpAddr::V4(Ipv4Addr::new(10, 99, 4, 3));
        let b_router = IpAddr::V4(Ipv4Addr::new(10, 99, 4, 11));
        let a_router = IpAddr::V4(Ipv4Addr::new(10, 99, 4, 10));
        let a_peer = IpAddr::V4(Ipv4Addr::new(10, 99, 4, 2));
        let ingress = Keepalive {
            kind: Kind::Request,
            source: Ipv4Addr::new(10, 99, 4, 3),
            destination: Ipv4Addr::new(10, 99, 4, 11),
        };
        ingress.validate_ingress(b_peer, b_router).unwrap();
        let egress = ingress.for_egress(a_router, a_peer).unwrap();
        assert_eq!(
            (egress.source, egress.destination),
            (Ipv4Addr::new(10, 99, 4, 10), Ipv4Addr::new(10, 99, 4, 2))
        );
        let mut a_exchange = Exchange::default();
        a_exchange.sent(egress.kind);
        let response = Keepalive {
            kind: Kind::Response,
            ..egress
        };
        response.validate_ingress(a_peer, a_router).unwrap();
        a_exchange.received(response.kind).unwrap();
        assert!(a_exchange.received(response.kind).is_err());
        let b_response = response.for_egress(b_router, b_peer).unwrap();
        assert_eq!(
            (b_response.source, b_response.destination),
            (ingress.source, ingress.destination)
        );
    }

    #[test]
    fn rejects_unknown_shapes_and_wrong_provider_pair() {
        let mut bad = REQUEST;
        bad[4] = 0x83;
        assert!(Keepalive::decode(&bad).is_err());
        bad = REQUEST;
        bad[10] = 4;
        assert!(Keepalive::decode(&bad).is_err());
        bad = REQUEST;
        bad[5] = 0x42;
        assert!(Keepalive::decode(&bad).is_err());
        bad = REQUEST;
        bad[0] = 1;
        assert!(Keepalive::decode(&bad).is_err());
        let request = Keepalive::decode(&REQUEST).unwrap();
        assert!(request
            .validate_ingress(
                IpAddr::V4(Ipv4Addr::new(10, 99, 4, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 99, 4, 3))
            )
            .is_err());
    }
}
