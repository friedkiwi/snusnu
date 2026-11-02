//! Passive EE LDLC endpoint for one configured IP pair.
//!
//! This owns UDP/12000 control replies and TEST liveness. The caller must
//! provide local XID3s whose CV61 claims are backed by an APPN/RTP endpoint;
//! normal router startup does not construct this type yet. A link becoming
//! active here is not an RTP connection or an admitted LU route.

use router_core::{
    hpr_cv61::ControlFlowsTower,
    hpr_ip_activation::{HprIpActivation, Observation, Phase},
    hpr_lan::{HprMedium, DEFAULT_BASE_SAP},
    hpr_setmode::XidDone,
    hpr_xid_evidence::HprXidEvidence,
    hpr_xid_leg::Side,
    xid3::{ExchangeState, Role, Xid3},
};
use std::{
    io,
    net::IpAddr,
    time::{Duration, Instant},
};
use transport_ip_sna::ee::{Datagram, EeSockets, LdlcKind, CONTROL_PORT};

const LIVE_INTERVAL: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_secs(15);
const RETRY_LIMIT: u8 = 3;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[derive(Clone)]
pub(crate) struct LocalEeXids {
    prenegotiation: Vec<u8>,
    negotiation: Vec<u8>,
}

impl LocalEeXids {
    /// Accept only a consistent, locally secondary EE profile. Constructing
    /// this does not authorize starting it: the caller must implement every
    /// capability advertised in CV61 before binding the endpoint.
    pub(crate) fn new(prenegotiation: Vec<u8>, negotiation: Vec<u8>) -> io::Result<Self> {
        let pre = Xid3::decode(&prenegotiation)
            .map_err(|_| invalid("invalid local EE prenegotiation XID"))?;
        let np =
            Xid3::decode(&negotiation).map_err(|_| invalid("invalid local EE negotiation XID"))?;
        let evidence = HprXidEvidence::parse(&negotiation, HprMedium::EnterpriseExtender)
            .map_err(|_| invalid("invalid local EE HPR capabilities"))?;
        validate_tower(&negotiation)?;
        if pre.exchange_state() != ExchangeState::Prenegotiation
            || np.exchange_state() != ExchangeState::NegotiationProceeding
            || pre.cp_name().ok() != np.cp_name().ok()
            || pre.node_id() != np.node_id()
            || prenegotiation[16] != negotiation[16]
            || evidence.role != Role::Secondary
            || evidence.negotiation_byte & 0xc0 != 0xc0
        {
            return Err(invalid("inconsistent local EE XID profile"));
        }
        Ok(Self {
            prenegotiation,
            negotiation,
        })
    }
}

pub(crate) struct EeLdlcEndpoint {
    sockets: EeSockets,
    local_ip: IpAddr,
    peer_ip: IpAddr,
    xids: LocalEeXids,
    activation: HprIpActivation,
    next_live: Option<Instant>,
    retry_at: Option<Instant>,
    retries: u8,
}

impl EeLdlcEndpoint {
    pub(crate) fn bind(local_ip: IpAddr, peer_ip: IpAddr, xids: LocalEeXids) -> io::Result<Self> {
        if local_ip == peer_ip
            || local_ip.is_unspecified()
            || peer_ip.is_unspecified()
            || local_ip.is_ipv4() != peer_ip.is_ipv4()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid EE IP pair",
            ));
        }
        Ok(Self {
            sockets: EeSockets::bind(local_ip)?,
            local_ip,
            peer_ip,
            xids,
            activation: HprIpActivation::new(Side::Remote),
            next_live: None,
            retry_at: None,
            retries: 0,
        })
    }

    pub(crate) fn phase(&self) -> Phase {
        self.activation.phase()
    }

    /// Returns an NLP only after link/SAP validation. The caller must still
    /// validate the APPN route and RTP connection before using its contents.
    pub(crate) fn poll(&mut self, now: Instant) -> io::Result<Option<Datagram>> {
        let received = match self.sockets.receive() {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                tracing::warn!(local_ip=%self.local_ip, peer_ip=%self.peer_ip,
                    error=%error, "malformed EE datagram discarded");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let Some((source, packet)) = received else {
            return Ok(None);
        };
        if source.ip() != self.peer_ip {
            tracing::warn!(local_ip=%self.local_ip, peer_ip=%self.peer_ip,
                source_ip=%source.ip(), "EE control packet from wrong peer discarded");
            return Ok(None);
        }
        match self.process(packet, now) {
            Ok(result) => Ok(result),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                tracing::warn!(local_ip=%self.local_ip, peer_ip=%self.peer_ip,
                    error=%error, "invalid EE control or link state discarded");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn process(&mut self, packet: Datagram, now: Instant) -> io::Result<Option<Datagram>> {
        match packet.kind {
            LdlcKind::Xid => self.xid(packet),
            LdlcKind::Test => self.test(packet, now),
            LdlcKind::Disc => {
                self.base_command(&packet)?;
                self.send_control(
                    DEFAULT_BASE_SAP,
                    DEFAULT_BASE_SAP | 1,
                    0x0f | (packet.payload[2] & 0x10),
                    &[],
                )?;
                self.down();
                Ok(None)
            }
            LdlcKind::Dm => {
                self.down();
                Ok(None)
            }
            LdlcKind::UiNlp => self.nlp(packet, now),
        }
    }

    fn base_command(&self, packet: &Datagram) -> io::Result<()> {
        if packet.port != CONTROL_PORT
            || packet.dsap != DEFAULT_BASE_SAP
            || packet.ssap != DEFAULT_BASE_SAP
        {
            return Err(invalid("wrong EE base SAP or command port"));
        }
        Ok(())
    }

    fn xid(&mut self, packet: Datagram) -> io::Result<Option<Datagram>> {
        self.base_command(&packet)?;
        let information = &packet.payload[3..];
        let response = if information.is_empty() {
            &[][..]
        } else {
            let xid = Xid3::decode(information).map_err(|_| invalid("invalid remote EE XID3"))?;
            match xid.exchange_state() {
                ExchangeState::Prenegotiation => &self.xids.prenegotiation,
                ExchangeState::NegotiationProceeding => &self.xids.negotiation,
                _ => return Err(invalid("unsupported EE XID phase")),
            }
        };
        if !information.is_empty() && information[9] & 0x0c == 0x04 {
            validate_tower(information)?;
        }
        let previous = self.activation.clone();
        self.activation
            .observe_xid(Side::Remote, information)
            .map_err(|_| invalid("remote EE XID rejected"))?;
        if let Err(error) = self.send_control(
            DEFAULT_BASE_SAP,
            DEFAULT_BASE_SAP | 1,
            0xaf | (packet.payload[2] & 0x10),
            response,
        ) {
            self.activation = previous;
            return Err(error);
        }
        self.activation
            .observe_xid(Side::Local, response)
            .map_err(|_| invalid("local EE XID profile rejected"))?;
        Ok(None)
    }

    fn nlp(&mut self, packet: Datagram, now: Instant) -> io::Result<Option<Datagram>> {
        if packet.port == CONTROL_PORT {
            if let Ok(XidDone::Request) = XidDone::parse(&packet.payload[3..]) {
                let agreement = self
                    .activation
                    .agreement()
                    .ok_or_else(|| invalid("EE XID_DONE before agreement"))?;
                if packet.dsap != agreement.local.advertised_sap
                    || packet.ssap != agreement.remote.advertised_sap
                {
                    return Err(invalid("EE XID_DONE SAP mismatch"));
                }
                let previous = self.activation.clone();
                self.activation
                    .observe_xid_done(Side::Remote, &packet.payload[3..])
                    .map_err(|_| invalid("EE XID_DONE request rejected"))?;
                let reply = XidDone::Response.encode();
                if let Err(error) = self.send_control(
                    agreement.remote.advertised_sap,
                    agreement.local.advertised_sap,
                    0x03,
                    &reply,
                ) {
                    self.activation = previous;
                    return Err(error);
                }
                let observed = self
                    .activation
                    .observe_xid_done(Side::Local, &reply)
                    .map_err(|_| invalid("EE XID_DONE response rejected"))?;
                if observed == Observation::Activated {
                    self.next_live = Some(now + LIVE_INTERVAL);
                }
                return Ok(None);
            }
        }
        let agreement = self
            .activation
            .agreement()
            .ok_or_else(|| invalid("EE NLP before XID agreement"))?;
        if self.phase() != Phase::Active
            || packet.dsap != agreement.local.advertised_sap
            || packet.ssap != agreement.remote.advertised_sap
        {
            return Err(invalid("EE NLP before activation or wrong SAP"));
        }
        Ok(Some(packet))
    }

    fn test(&mut self, packet: Datagram, now: Instant) -> io::Result<Option<Datagram>> {
        if packet.port != CONTROL_PORT
            || packet.dsap != DEFAULT_BASE_SAP
            || packet.ssap & !1 != DEFAULT_BASE_SAP
            || self.phase() != Phase::Active
        {
            return Err(invalid("unexpected EE TEST"));
        }
        if packet.ssap & 1 != 0 {
            self.activation
                .observe_test(Side::Remote, true)
                .map_err(|_| invalid("unsolicited EE TEST response"))?;
            self.retry_at = None;
            self.retries = 0;
            self.next_live = Some(now + LIVE_INTERVAL);
        } else {
            self.activation
                .observe_test(Side::Remote, false)
                .map_err(|_| invalid("unexpected EE TEST command"))?;
            self.send_control(
                DEFAULT_BASE_SAP,
                DEFAULT_BASE_SAP | 1,
                0xe3 | (packet.payload[2] & 0x10),
                &packet.payload[3..],
            )?;
            self.activation
                .observe_test(Side::Local, true)
                .map_err(|_| invalid("local EE TEST reply rejected"))?;
        }
        Ok(None)
    }

    /// RFC 2353 defaults: 10-second successful liveness period, three
    /// retries separated by 15 seconds. No new liveness sequence starts
    /// until the previous one completes or fails.
    pub(crate) fn tick(&mut self, now: Instant) -> io::Result<()> {
        if self.phase() != Phase::Active {
            return Ok(());
        }
        let due = self.retry_at.is_some_and(|deadline| now >= deadline)
            || self.retry_at.is_none() && self.next_live.is_some_and(|deadline| now >= deadline);
        if !due {
            return Ok(());
        }
        if self.retry_at.is_some() && self.retries >= RETRY_LIMIT {
            self.down();
            return Ok(());
        }
        self.send_control(DEFAULT_BASE_SAP, DEFAULT_BASE_SAP, 0xf3, &[])?;
        self.activation
            .observe_test(Side::Local, false)
            .map_err(|_| invalid("local EE TEST request rejected"))?;
        self.retries += 1;
        self.retry_at = Some(now + RETRY_INTERVAL);
        self.next_live = None;
        Ok(())
    }

    fn send_control(&self, dsap: u8, ssap: u8, control: u8, information: &[u8]) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(3 + information.len());
        bytes.extend_from_slice(&[dsap, ssap, control]);
        bytes.extend_from_slice(information);
        let packet = Datagram::decode(CONTROL_PORT, bytes)?;
        self.sockets.send(self.peer_ip, &packet)
    }

    fn down(&mut self) {
        self.activation.observe_disconnect(Side::Remote);
        self.next_live = None;
        self.retry_at = None;
        self.retries = 0;
    }
}

/// CV61 on EE must contain one control-flows tower. XID3 syntax alone does
/// not validate it, and a missing X'81' causes peer rejection (sense 10160027).
fn validate_tower(xid: &[u8]) -> io::Result<()> {
    let mut offset = 29;
    let mut seen = false;
    while offset < xid.len() {
        let key = xid[offset];
        let length = usize::from(xid[offset + 1]);
        if key == 0x61 {
            if seen || length < 5 || xid[offset + 2] != 0xf8 {
                return Err(invalid("invalid or duplicate EE CV61"));
            }
            seen = true;
            let data = &xid[offset + 2..offset + 2 + length];
            let mut sub = 5;
            let mut tower = false;
            while sub < data.len() {
                if sub + 2 > data.len() {
                    return Err(invalid("truncated EE CV61 subfield"));
                }
                let sub_len = usize::from(data[sub]);
                if sub_len < 2 || sub + sub_len > data.len() {
                    return Err(invalid("invalid EE CV61 subfield length"));
                }
                if data[sub + 1] == 0x81 {
                    if tower || ControlFlowsTower::decode(&data[sub..sub + sub_len]).is_err() {
                        return Err(invalid("invalid or duplicate EE control-flows tower"));
                    }
                    tower = true;
                }
                sub += sub_len;
            }
            if !tower {
                return Err(invalid("missing EE control-flows tower"));
            }
        }
        offset += 2 + length;
    }
    if !seen {
        return Err(invalid("missing EE CV61"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::{
        hpr_xid_leg::local_ee_tg_descriptor,
        xid3::{ControlVector, Xid3},
    };
    use std::{net::UdpSocket, thread};

    fn xid(local: bool, negotiation: bool) -> Vec<u8> {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(if local {
            &[0xff, 0xf0, 0, 1]
        } else {
            &[0xff, 0xf0, 0, 2]
        });
        fixed[9] = if negotiation { 0x04 } else { 0x08 };
        fixed[12] = if local { 0xc0 } else { 0x80 };
        fixed[16] = 1;
        fixed[19] = if local { 0 } else { 0x10 };
        fixed[21..23].copy_from_slice(&1461u16.to_be_bytes());
        fixed[27] = 7;
        let mut vectors = vec![
            ControlVector {
                key: 0x0e,
                data: if local {
                    vec![
                        0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc1,
                    ]
                } else {
                    vec![
                        0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2,
                    ]
                },
            },
            local_ee_tg_descriptor(1),
        ];
        if negotiation {
            vectors.push(ControlVector {
                key: 0x61,
                data: [
                    vec![0xf8, 0, 2, 0x80, 2, 3, 0x80, 4],
                    vec![
                        0x17, 0x81, 0x05, 0xb5, 0, 0, 0xea, 0x60, 0x10, 0, 0, 0, 4, 0, 0, 0, 4, 2,
                        0xa4, 0, 2, 0xa4, 0,
                    ],
                ]
                .concat(),
            });
        }
        Xid3::from_parts(fixed, vectors).unwrap().encode().unwrap()
    }

    fn exchange(
        endpoint: &mut EeLdlcEndpoint,
        peer: &UdpSocket,
        information: &[u8],
        now: Instant,
    ) -> Vec<u8> {
        let mut request = vec![4, 4, 0xaf];
        request.extend_from_slice(information);
        peer.send_to(&request, (endpoint.local_ip, CONTROL_PORT))
            .unwrap();
        for _ in 0..100 {
            endpoint.poll(now).unwrap();
            let mut reply = [0u8; 512];
            match peer.recv_from(&mut reply) {
                Ok((size, _)) => return reply[..size].to_vec(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("EE reply receive failed: {error}"),
            }
        }
        panic!("EE endpoint did not answer XID");
    }

    #[test]
    fn passive_udp_link_answers_xid_done_and_test() {
        let pid = std::process::id();
        let local_ip = IpAddr::from([127, 93, (pid >> 8) as u8, pid as u8]);
        let peer_ip = IpAddr::from([127, 94, (pid >> 8) as u8, pid as u8]);
        let profile = LocalEeXids::new(xid(true, false), xid(true, true)).unwrap();
        let mut endpoint = EeLdlcEndpoint::bind(local_ip, peer_ip, profile).unwrap();
        let peer = UdpSocket::bind((peer_ip, CONTROL_PORT)).unwrap();
        peer.set_nonblocking(true).unwrap();
        let now = Instant::now();
        assert_eq!(exchange(&mut endpoint, &peer, &[], now), [4, 5, 0xaf]);
        assert_eq!(
            exchange(&mut endpoint, &peer, &xid(false, false), now),
            [vec![4, 5, 0xaf], xid(true, false)].concat()
        );
        assert_eq!(
            exchange(&mut endpoint, &peer, &xid(false, true), now),
            [vec![4, 5, 0xaf], xid(true, true)].concat()
        );
        assert_eq!(endpoint.phase(), Phase::Agreed);

        let request = [vec![4, 4, 3], XidDone::Request.encode().to_vec()].concat();
        peer.send_to(&request, (local_ip, CONTROL_PORT)).unwrap();
        let mut reply = [0u8; 512];
        let response = (0..100)
            .find_map(|_| {
                endpoint.poll(now).unwrap();
                match peer.recv_from(&mut reply) {
                    Ok((size, _)) => Some(reply[..size].to_vec()),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        None
                    }
                    Err(error) => panic!("EE reply receive failed: {error}"),
                }
            })
            .expect("XID_DONE response");
        assert_eq!(
            response,
            [vec![4, 4, 3], XidDone::Response.encode().to_vec()].concat()
        );
        assert_eq!(endpoint.phase(), Phase::Active);

        endpoint.tick(now + LIVE_INTERVAL).unwrap();
        let (size, _) = peer.recv_from(&mut reply).unwrap();
        assert_eq!(&reply[..size], &[4, 4, 0xf3]);
        peer.send_to(&[4, 5, 0xf3], (local_ip, CONTROL_PORT))
            .unwrap();
        endpoint.poll(now + LIVE_INTERVAL).unwrap();
        assert_eq!(endpoint.retries, 0);
        assert!(endpoint.retry_at.is_none());
    }
}
