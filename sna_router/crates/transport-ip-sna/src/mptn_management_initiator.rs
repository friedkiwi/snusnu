//! Pure initiator for the isolated V5R4 TCP62 SNASVCMG/CNOS exchange.
//!
//! The profile is limited to the direct Solstice V5R4 trace. It does not
//! operate sockets or authorize normal runtime use: X'83' out-of-band,
//! SON/keepalive, and negotiated APPC capabilities need live handlers.

use std::io;

use router_core::cnos::{CnosGds, Service};

use crate::{
    anynet::{TcpKind, TcpRecord},
    mptn_bind_negotiation::validate_positive_response,
    mptn_compensations::required_from_connect,
    mptn_connect::{Address, Connect, Direction, OptionalField, TransportRequirements},
};

const MODE: [u8; 8] = [0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
const FIXED: [u8; 27] = [
    0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0, 0, 0, 0,
    0, 0x94, 0x43, 0, 0,
];
const RESPONSE_FIXED: [u8; 27] = [
    0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 7, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0, 0, 0, 0, 0,
    0x94, 0x43, 0, 0,
];
const TAIL: [u8; 12] = [
    0x2c, 0x0a, 4, 8, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
];
const REQUIRED: [u8; 6] = [0, 0x20, 1, 3, 0x10, 0x83];
const CNOS_PREFIX: [u8; 5] = [0, 1, 0x0b, 0x90, 0x20];
const REPLY_PREFIX: [u8; 5] = [0, 1, 3, 0x90, 1];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    AwaitConnect,
    AwaitCnosReply,
    AwaitBis,
    AwaitUnbindSent,
    AwaitPeerClose,
    Ready,
}

pub struct ManagementInitiator {
    request: Connect,
    connect_bytes: Vec<u8>,
    fqpcid: [u8; 22],
    cnos: CnosGds,
    phase: Phase,
    pending_unbind: Option<Vec<u8>>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn wrong_phase() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TCP62 management phase mismatch",
    )
}

fn name(name: &str) -> io::Result<Vec<u8>> {
    let mut parts = name.split('.');
    let (Some(netid), Some(cp), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid("management LU must be network-qualified"));
    };
    if netid.is_empty() || netid.len() > 8 || cp.is_empty() || cp.len() > 8 || name.len() != 11 {
        return Err(invalid("unsupported V5R4 management LU length"));
    }
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => return Err(invalid("unsupported V5R4 management LU character")),
            })
        })
        .collect()
}

fn record(kind: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    let len = 5 + body.len();
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(&(len as u32).to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(body);
    TcpRecord::decode(bytes.clone())?;
    Ok(bytes)
}

impl ManagementInitiator {
    /// IDs must be freshly minted by the caller for each attempt. `bind_token`
    /// is the seven-byte X'03'/X'13' instance from the captured V5 profile;
    /// it is independent of the transport correlator and FQPCID token.
    pub fn new(
        local_lu: &str,
        remote_lu: &str,
        fqpcid: [u8; 22],
        correlator: [u8; 8],
        bind_token: [u8; 7],
        mode: &str,
        session_limit: u16,
    ) -> io::Result<Self> {
        let local = name(local_lu)?;
        let remote = name(remote_lu)?;
        if local == remote
            || fqpcid[..2] != [0x60, 0x14]
            || fqpcid[10] != 11
            || fqpcid[11..] != local
            || fqpcid[2..10].iter().all(|&byte| byte == 0)
            || correlator.iter().all(|&byte| byte == 0)
            || bind_token[0] != 0x23
            || bind_token[1..5].iter().all(|&byte| byte == 0)
            || bind_token[5..] != [0x80, 0]
            || !(2..=8).contains(&session_limit)
            || session_limit % 2 != 0
        {
            return Err(invalid(
                "unsupported V5R4 management identity or session policy",
            ));
        }
        let cnos = CnosGds {
            service: Service::Request,
            modifier: 0,
            session_limit,
            source_winners: session_limit / 2,
            target_winners: session_limit / 2,
            mode: mode.to_owned(),
            mode_field_length: 8,
        };
        cnos.encode()
            .map_err(|_| invalid("invalid CNOS mode policy"))?;

        let mut user = vec![0, 9, 2];
        user.extend_from_slice(&MODE);
        user.extend_from_slice(&[9, 3, 1]);
        user.extend_from_slice(&bind_token);
        user.extend_from_slice(&[12, 4]);
        user.extend_from_slice(&local);
        user.extend_from_slice(&[10, 0x13, 0, 0xb0]);
        user.extend_from_slice(&bind_token);
        let mut data = vec![0, 0, 0x6b, 0x80, 0];
        data.extend_from_slice(&FIXED);
        data.push(local.len() as u8);
        data.extend_from_slice(&local);
        data.push(user.len() as u8);
        data.extend_from_slice(&user);
        data.push(0); // no URC
        data.push(remote.len() as u8);
        data.extend_from_slice(&remote);
        data.extend_from_slice(&fqpcid);
        data.extend_from_slice(&TAIL);
        if data.len() != 137 {
            return Err(invalid("V5R4 management BIND is not the captured profile"));
        }
        let request = Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            destination: Address { node: remote },
            source: Address { node: local },
            correlator: correlator.to_vec(),
            requirements: TransportRequirements {
                max_record: 0x0205,
                max_expedited: 0x76,
                max_termination: 0x76,
            },
            options: vec![
                OptionalField {
                    kind: 5,
                    processing: 8,
                    value: vec![1, 1],
                },
                OptionalField {
                    kind: 10,
                    processing: 2,
                    value: data,
                },
                OptionalField {
                    kind: 0x18,
                    processing: 0,
                    value: vec![1],
                },
                OptionalField {
                    kind: 0x19,
                    processing: 10,
                    value: REQUIRED.to_vec(),
                },
                OptionalField {
                    kind: 0x1a,
                    processing: 0,
                    value: vec![0x84],
                },
            ],
        };
        let connect_bytes = request.encode()?;
        if connect_bytes.len() != 230 {
            return Err(invalid(
                "V5R4 management Connect is not the captured profile",
            ));
        }
        Ok(Self {
            request,
            connect_bytes,
            fqpcid,
            cnos,
            phase: Phase::AwaitConnect,
            pending_unbind: None,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }
    pub fn connect_request(&self) -> &[u8] {
        &self.connect_bytes
    }

    pub fn accept_connect_response(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AwaitConnect {
            return Err(wrong_phase());
        }
        let response = Connect::decode(bytes)?;
        if !self.request.matches_response(&response)
            || response.direction != Direction::PositiveResponse
            || response.requirements != self.request.requirements
            || response.options.len() != 5
            || response.options.iter().map(|o| o.kind).collect::<Vec<_>>()
                != [5, 10, 0x18, 0x19, 0x1a]
            || response
                .options
                .iter()
                .map(|o| o.processing)
                .collect::<Vec<_>>()
                != [8, 2, 0, 10, 0]
            || response.options[0].value != [1, 1]
            || response.options[2].value != [1]
            || response.options[3].value != REQUIRED
            || response.options[4].value != [0x84]
            || response.connection_data().len() != 96
            || response.connection_data()[5..32] != RESPONSE_FIXED
            || response.connection_data()[61..65] != [10, 0x13, 0, 0xb0]
            || response.connection_data()[65] != 0x23
            || response.connection_data()[70..72] != [0x80, 0]
            || required_from_connect(&response).is_err()
            || validate_positive_response(
                self.request.connection_data(),
                response.connection_data(),
            )
            .is_err()
        {
            return Err(invalid(
                "V5R4 management BIND response is unsupported or stale",
            ));
        }
        let gds = self
            .cnos
            .encode()
            .map_err(|_| invalid("CNOS policy became invalid"))?;
        let mut body = Vec::with_capacity(5 + 12 + gds.len());
        body.extend_from_slice(&CNOS_PREFIX);
        body.extend_from_slice(&[12, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1]);
        body.extend_from_slice(&gds);
        let next = record(0, &body)?;
        self.phase = Phase::AwaitCnosReply;
        Ok(next)
    }

    pub fn accept_cnos_reply(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AwaitCnosReply {
            return Err(wrong_phase());
        }
        let checked = TcpRecord::decode(bytes.to_vec())?;
        if checked.kind != TcpKind::Normal || bytes.len() < 10 || bytes[5..10] != REPLY_PREFIX {
            return Err(invalid("unexpected V5R4 CNOS response envelope"));
        }
        let reply =
            CnosGds::decode(&bytes[10..]).map_err(|_| invalid("invalid V5R4 CNOS reply"))?;
        if reply.service != Service::AcceptedPending
            || reply.modifier != 0
            || reply.mode != self.cnos.mode
            || reply.mode_field_length != self.cnos.mode_field_length
            || reply.session_limit != self.cnos.session_limit
            || reply.source_winners != self.cnos.source_winners
            || reply.target_winners != self.cnos.target_winners
        {
            return Err(invalid("V5R4 CNOS limits were not accepted"));
        }
        self.phase = Phase::AwaitBis;
        record(0, &[0, 2, 0x4b, 0x90, 0, 0x70])
    }

    pub fn accept_bis(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AwaitBis {
            return Err(wrong_phase());
        }
        let checked = TcpRecord::decode(bytes.to_vec())?;
        if checked.kind != TcpKind::Normal || bytes != [0, 0, 0, 11, 0, 0, 2, 0x4b, 0xb0, 0, 0x70] {
            return Err(invalid("V5R4 management BIS is unsupported"));
        }
        // TCP62 §5.3.2: X'10' with user data carries UNBIND. SNA UNBIND
        // X'32 01' is normal session end; the FQPCID correlates this socket.
        let mut body = vec![0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0];
        body.extend_from_slice(&self.fqpcid);
        let unbind = record(0x10, &body)?;
        self.pending_unbind = Some(unbind.clone());
        self.phase = Phase::AwaitUnbindSent;
        Ok(unbind)
    }

    pub fn mark_unbind_sent(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.phase != Phase::AwaitUnbindSent || self.pending_unbind.as_deref() != Some(bytes) {
            return Err(wrong_phase());
        }
        self.pending_unbind = None;
        self.phase = Phase::AwaitPeerClose;
        Ok(())
    }

    /// Only clean TCP EOF after the exact UNBIND handoff permits user Connect.
    pub fn observe_peer_close(&mut self) -> io::Result<()> {
        if self.phase != Phase::AwaitPeerClose {
            return Err(wrong_phase());
        }
        self.phase = Phase::Ready;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ([u8; 22], [u8; 8], [u8; 7]) {
        let mut fqpcid = [0x22; 22];
        fqpcid[..2].copy_from_slice(&[0x60, 0x14]);
        fqpcid[10] = 11;
        fqpcid[11..].copy_from_slice(&name("SOLNET.SNAA").unwrap());
        (fqpcid, [0x11; 8], [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0])
    }

    fn session() -> ManagementInitiator {
        let (fqpcid, correlator, token) = ids();
        ManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            fqpcid,
            correlator,
            token,
            "",
            8,
        )
        .unwrap()
    }

    fn positive(request: &Connect) -> Vec<u8> {
        // Sanitized frame 62: same 96-byte reduced RSP(BIND), including its
        // X'13' user subfield, with the session IDs replaced by test values.
        let mut response = request.clone();
        response.direction = Direction::PositiveResponse;
        response.processing = 0x8a;
        let mut user = vec![0, 9, 2];
        user.extend_from_slice(&MODE);
        user.extend_from_slice(&[2, 3, 2, 12, 5]);
        user.extend_from_slice(&request.destination.node);
        user.extend_from_slice(&[10, 0x13, 0, 0xb0, 0x23, 0x33, 0x33, 0x33, 0x33, 0x80, 0]);
        assert_eq!(user.len(), 38);
        let mut data = vec![0, 0, 0xeb, 0x80, 0];
        data.extend_from_slice(&RESPONSE_FIXED);
        data.extend_from_slice(&[0, user.len() as u8]);
        data.extend_from_slice(&user);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&ids().0);
        assert_eq!(data.len(), 96);
        response.options[1].value = data;
        response.encode().unwrap()
    }

    fn reply() -> Vec<u8> {
        record(
            0,
            &[
                0, 1, 3, 0x90, 1, 0, 25, 0x12, 0x10, 0x0a, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
            ],
        )
        .unwrap()
    }

    #[test]
    fn direct_trace_shape_completes_only_after_correlated_unbind_and_eof() {
        let mut peer = session();
        let request = Connect::decode(peer.connect_request()).unwrap();
        assert_eq!(peer.connect_request().len(), 230);
        assert_eq!(request.destination.node, name("SOLNET.SNAB").unwrap());
        assert_eq!(request.source.node, name("SOLNET.SNAA").unwrap());
        assert_eq!(&request.connection_data()[5..32], &FIXED);
        assert_eq!(
            &request.connection_data()[33..44],
            name("SOLNET.SNAA").unwrap()
        );
        assert_eq!(
            &request.connection_data()[92..103],
            name("SOLNET.SNAB").unwrap()
        );
        assert_eq!(&request.connection_data()[103..125], &ids().0);
        let cnos = peer.accept_connect_response(&positive(&request)).unwrap();
        assert_eq!(peer.phase(), Phase::AwaitCnosReply);
        assert_eq!(cnos.len(), 47);
        assert_eq!(
            &cnos[..22],
            &[
                0, 0, 0, 47, 0, 0, 1, 0x0b, 0x90, 0x20, 12, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6,
                0xf1
            ]
        );
        assert_eq!(
            &cnos[22..],
            &CnosGds {
                service: Service::Request,
                modifier: 0,
                session_limit: 8,
                source_winners: 4,
                target_winners: 4,
                mode: String::new(),
                mode_field_length: 8
            }
            .encode()
            .unwrap()
        );
        let bis = peer.accept_cnos_reply(&reply()).unwrap();
        assert_eq!(bis, [0, 0, 0, 11, 0, 0, 2, 0x4b, 0x90, 0, 0x70]);
        let unbind = peer
            .accept_bis(&[0, 0, 0, 11, 0, 0, 2, 0x4b, 0xb0, 0, 0x70])
            .unwrap();
        assert_eq!(unbind.len(), 38);
        assert_eq!(
            &unbind[..16],
            &[0, 0, 0, 38, 0x10, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0]
        );
        assert_eq!(&unbind[16..], &ids().0);
        assert!(!peer.ready());
        peer.mark_unbind_sent(&unbind).unwrap();
        assert!(!peer.ready());
        peer.observe_peer_close().unwrap();
        assert!(peer.ready());
    }

    #[test]
    fn stale_and_malformed_connect_responses_do_not_advance() {
        let mut peer = session();
        let request = Connect::decode(peer.connect_request()).unwrap();
        let mut stale = Connect::decode(&positive(&request)).unwrap();
        stale.correlator[0] ^= 1;
        assert!(peer
            .accept_connect_response(&stale.encode().unwrap())
            .is_err());
        assert_eq!(peer.phase(), Phase::AwaitConnect);
        stale = Connect::decode(&positive(&request)).unwrap();
        *stale.options[1].value.last_mut().unwrap() ^= 1;
        assert!(peer
            .accept_connect_response(&stale.encode().unwrap())
            .is_err());
        stale = Connect::decode(&positive(&request)).unwrap();
        stale.options[1].value[5 + 24] = 0x03;
        assert!(peer
            .accept_connect_response(&stale.encode().unwrap())
            .is_err());
        stale = Connect::decode(&positive(&request)).unwrap();
        stale.options[4].value = vec![0];
        assert!(peer
            .accept_connect_response(&stale.encode().unwrap())
            .is_err());
        assert_eq!(peer.phase(), Phase::AwaitConnect);
    }

    #[test]
    fn cnos_bis_and_teardown_are_ordered_and_fail_closed() {
        let mut peer = session();
        assert!(peer.accept_cnos_reply(&reply()).is_err());
        assert!(peer.observe_peer_close().is_err());
        let request = Connect::decode(peer.connect_request()).unwrap();
        peer.accept_connect_response(&positive(&request)).unwrap();
        let mut wrong = reply();
        wrong[24] = 3; // target-winner count differs
        assert!(peer.accept_cnos_reply(&wrong).is_err());
        wrong = reply();
        wrong[14] = 8; // abnormal service
        assert!(peer.accept_cnos_reply(&wrong).is_err());
        assert_eq!(peer.phase(), Phase::AwaitCnosReply);
        peer.accept_cnos_reply(&reply()).unwrap();
        let mut bad_bis = [0, 0, 0, 11, 0, 0, 2, 0x4b, 0xb0, 0, 0x70];
        bad_bis[6] = 3;
        assert!(peer.accept_bis(&bad_bis).is_err());
        let unbind = peer
            .accept_bis(&[0, 0, 0, 11, 0, 0, 2, 0x4b, 0xb0, 0, 0x70])
            .unwrap();
        assert!(peer.observe_peer_close().is_err());
        let mut bad_unbind = unbind.clone();
        *bad_unbind.last_mut().unwrap() ^= 1;
        assert!(peer.mark_unbind_sent(&bad_unbind).is_err());
        peer.mark_unbind_sent(&unbind).unwrap();
        assert!(peer.accept_connect_response(&positive(&request)).is_err());
    }

    #[test]
    fn constructor_rejects_malformed_identity_token_and_limits() {
        let (fqpcid, correlator, token) = ids();
        let mut bad_fqpcid = fqpcid;
        bad_fqpcid[20] ^= 1;
        assert!(ManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            bad_fqpcid,
            correlator,
            token,
            "",
            8
        )
        .is_err());
        assert!(ManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAA",
            fqpcid,
            correlator,
            token,
            "",
            8
        )
        .is_err());
        assert!(
            ManagementInitiator::new("SNAA", "SOLNET.SNAB", fqpcid, correlator, token, "", 8)
                .is_err()
        );
        assert!(ManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            fqpcid,
            correlator,
            token,
            "",
            9
        )
        .is_err());
        assert!(ManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            fqpcid,
            correlator,
            [0; 7],
            "",
            8
        )
        .is_err());
    }
}
