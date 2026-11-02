//! Passive EE LDLC endpoint for one configured IP pair.
//!
//! This owns UDP/12000 control replies and TEST liveness. The caller must
//! provide local XID3s whose CV61 claims are backed by an APPN/RTP endpoint;
//! normal router startup does not construct this type yet. A link becoming
//! active here is not an RTP connection or an admitted LU route.

use router_core::{
    hpr_control_bootstrap::{ControlAdvertisement, HprControlBootstrap},
    hpr_cv61::{ArbMode, ControlFlowsTower},
    hpr_ip_activation::{HprIpActivation, Observation, Phase},
    hpr_lan::{HprMedium, DEFAULT_BASE_SAP},
    hpr_setmode::XidDone,
    hpr_xid_evidence::HprXidEvidence,
    hpr_xid_leg::{local_ee_tg_descriptor, Side},
    session::QualifiedName,
    xid3::{ControlVector, ExchangeState, Role, Xid3},
    ConnectionGeneration,
};
use std::{
    io,
    net::IpAddr,
    time::{Duration, Instant},
};
use transport_ip_sna::ee::{Datagram, EeSockets, LdlcKind, CONTROL_PORT, LOW_PORT, NETWORK_PORT};

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
    expected_peer_cp: Option<QualifiedName>,
}

impl LocalEeXids {
    /// Build the local secondary side of one regular EE TG. `local_cp` and
    /// `node_id` are stable identities supplied by configuration or persisted
    /// router state. For a guest served by the concentrator's APING endpoint,
    /// the server must authorize a proxy CP such as SNUSNU.SVC. The guest's
    /// NETID may differ, so only CP equality is rejected here.
    ///
    /// `tower` and `link_label` are allocated by the local APPN control
    /// bootstrap. Until path switching and Responsive ARB are implemented,
    /// the tower must advertise zero path-switch time and Base ARB. The
    /// caller must have a working RTP/CP tower before using this builder in
    /// production; it advertises those capabilities in CV61.
    pub(crate) fn build(
        local_cp: &QualifiedName,
        peer_cp: &QualifiedName,
        node_id: [u8; 4],
        tg_number: u8,
        link_label: [u8; 2],
        tower: &ControlFlowsTower,
        network_node: bool,
    ) -> io::Result<Self> {
        let id = u32::from_be_bytes(node_id);
        let block = id >> 20;
        if local_cp == peer_cp
            || !matches!(block, 0x000 | 0xfff)
            || id & 0x000f_ffff == 0
            || tg_number == 0
            || link_label[0] != 0x80
            || link_label[1] == 0xff
            || !(768..=1461).contains(&tower.max_send_packet_size)
            || tower.path_switch_time_ms != 0
            || tower.arb_mode != ArbMode::Base
            || tower.mobile
            || tower.multilink_tg
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid local EE identity, TG, label or packet size",
            ));
        }
        let mut cv61 = vec![0xf8, 0, 2, link_label[0], link_label[1], 3, 0x80, 4];
        cv61.extend_from_slice(
            &tower
                .encode()
                .map_err(|_| invalid("invalid EE control tower"))?,
        );
        let product = vec![
            0, 0x0b, 0x11, 0x0c, 0x08, 0x06, 0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4,
        ]; // Non-IBM SNUSNU product ID.
        let vectors = vec![
            ControlVector {
                key: 0x0e,
                data: vec![0xf4, 0xc1, 0x4b, 0xc1],
            },
            ControlVector {
                key: 0x10,
                data: product,
            },
            local_ee_tg_descriptor(tg_number),
        ];
        let mut pre_fixed = [0u8; 29];
        pre_fixed[2..6].copy_from_slice(&node_id);
        pre_fixed[9] = 0x88 | if network_node { 0x40 } else { 0 };
        pre_fixed[10] = 0xc0;
        pre_fixed[12] = 0x80;
        pre_fixed[15] = 0x80;
        pre_fixed[16] = tg_number;
        pre_fixed[17] = 0x01; // Native IP DLC in the V5R4 EE XID profile.
        pre_fixed[18] = 0x0b;
        pre_fixed[19] = 0x40; // ABM and local secondary station.
        pre_fixed[21..23].copy_from_slice(&tower.max_send_packet_size.to_be_bytes());
        pre_fixed[27] = 7;
        let mut pre = Xid3::from_parts(pre_fixed, vectors.clone())
            .map_err(|_| invalid("invalid local EE prenegotiation XID"))?;
        pre.set_cp_name(&local_cp.to_string())
            .map_err(|_| invalid("invalid local EE CP name"))?;
        let mut np_fixed = pre_fixed;
        np_fixed[9] = 0xb4 | if network_node { 0x40 } else { 0 };
        np_fixed[12] = 0xc0; // Secondary enhanced-XID negotiation complete.
        let mut np_vectors = vectors;
        np_vectors.push(ControlVector {
            key: 0x61,
            data: cv61,
        });
        let mut np = Xid3::from_parts(np_fixed, np_vectors)
            .map_err(|_| invalid("invalid local EE negotiation XID"))?;
        np.set_cp_name(&local_cp.to_string())
            .map_err(|_| invalid("invalid local EE CP name"))?;
        let mut result = Self::new(
            pre.encode()
                .map_err(|_| invalid("invalid local EE XID encoding"))?,
            np.encode()
                .map_err(|_| invalid("invalid local EE XID encoding"))?,
        )?;
        result.expected_peer_cp = Some(peer_cp.clone());
        Ok(result)
    }

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
            || (pre.node_id() != [0; 4] && pre.node_id() != np.node_id())
            || prenegotiation[16] != negotiation[16]
            || evidence.role != Role::Secondary
            || evidence.negotiation_byte & 0xc0 != 0xc0
        {
            return Err(invalid("inconsistent local EE XID profile"));
        }
        Ok(Self {
            prenegotiation,
            negotiation,
            expected_peer_cp: None,
        })
    }
}

pub(crate) struct EeLdlcEndpoint {
    sockets: EeSockets,
    local_ip: IpAddr,
    peer_ip: IpAddr,
    xids: Option<LocalEeXids>,
    resolve_xids: Option<XidResolver>,
    activation: HprIpActivation,
    peer_np: Option<Vec<u8>>,
    generation: u64,
    next_live: Option<Instant>,
    retry_at: Option<Instant>,
    retries: u8,
}

type XidResolver = Box<dyn Fn(&Xid3) -> io::Result<LocalEeXids> + Send + Sync>;

impl EeLdlcEndpoint {
    pub(crate) fn bind(local_ip: IpAddr, peer_ip: IpAddr, xids: LocalEeXids) -> io::Result<Self> {
        let mut endpoint = Self::bind_dynamic(local_ip, peer_ip, |_| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "static EE profile missing",
            ))
        })?;
        endpoint.xids = Some(xids);
        endpoint.resolve_xids = None;
        Ok(endpoint)
    }

    /// Bind before the peer CP is known. The callback is called only for a
    /// syntactically valid first prenegotiation XID3. It may return WouldBlock
    /// until an authorized local proxy CP is available; no XID3 is sent then.
    pub(crate) fn bind_dynamic(
        local_ip: IpAddr,
        peer_ip: IpAddr,
        resolver: impl Fn(&Xid3) -> io::Result<LocalEeXids> + Send + Sync + 'static,
    ) -> io::Result<Self> {
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
            xids: None,
            resolve_xids: Some(Box::new(resolver)),
            activation: HprIpActivation::new(Side::Remote),
            peer_np: None,
            generation: 1,
            next_live: None,
            retry_at: None,
            retries: 0,
        })
    }

    pub(crate) fn phase(&self) -> Phase {
        self.activation.phase()
    }

    pub(crate) fn generation(&self) -> ConnectionGeneration {
        ConnectionGeneration::new(self.generation).expect("EE generation starts nonzero")
    }

    pub(crate) fn peer_cp(&self) -> Option<String> {
        (self.phase() == Phase::Active)
            .then(|| self.activation.agreement())
            .flatten()
            .map(|agreement| agreement.remote.cp_name)
    }

    /// Return validated CP and Route Setup bootstrap labels only after the
    /// link has completed XID_DONE. The generation prevents a later link
    /// reactivation from reusing old RTP/APPN control state.
    pub(crate) fn control_bootstrap(&self) -> io::Result<Option<HprControlBootstrap>> {
        if self.phase() != Phase::Active {
            return Ok(None);
        }
        let local = self
            .xids
            .as_ref()
            .ok_or_else(|| invalid("EE local XID unavailable"))?;
        let peer = self
            .peer_np
            .as_ref()
            .ok_or_else(|| invalid("EE peer NP XID unavailable"))?;
        let local = ControlAdvertisement::from_xid3(&local.negotiation)
            .map_err(|_| invalid("invalid local EE control advertisement"))?;
        let peer = ControlAdvertisement::from_xid3(peer)
            .map_err(|_| invalid("invalid peer EE control advertisement"))?;
        HprControlBootstrap::new(self.generation(), local, peer)
            .map(Some)
            .map_err(|_| invalid("incompatible EE control bootstrap"))
    }

    /// Send one complete NLP on the requested EE priority port only after
    /// negotiated LDLC activation. RTP owns ANR routing and reliability.
    pub(crate) fn send_nlp(&self, priority_port: u16, nlp: &[u8]) -> io::Result<()> {
        if self.phase() != Phase::Active || !(NETWORK_PORT..=LOW_PORT).contains(&priority_port) {
            return Err(invalid("EE NLP send before activation or wrong priority"));
        }
        let agreement = self
            .activation
            .agreement()
            .ok_or_else(|| invalid("EE SAP agreement missing"))?;
        if nlp.is_empty() || nlp.len() > usize::from(agreement.max_btu) {
            return Err(invalid("EE NLP exceeds negotiated BTU"));
        }
        let mut bytes = Vec::with_capacity(3 + nlp.len());
        bytes.extend_from_slice(&[
            agreement.remote.advertised_sap,
            agreement.local.advertised_sap,
            0x03,
        ]);
        bytes.extend_from_slice(nlp);
        let datagram = Datagram::decode(priority_port, bytes)?;
        self.sockets.send(self.peer_ip, &datagram)
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
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
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
            if self.xids.is_none() {
                if xid.exchange_state() != ExchangeState::Prenegotiation {
                    return Err(invalid("EE negotiation XID before peer identity"));
                }
                let resolver = self
                    .resolve_xids
                    .as_ref()
                    .ok_or_else(|| invalid("EE local profile unavailable"))?;
                self.xids = Some(resolver(&xid)?);
            }
            let profile = self
                .xids
                .as_ref()
                .ok_or_else(|| invalid("EE local profile unavailable"))?;
            let observed: QualifiedName = xid
                .cp_name()
                .map_err(|_| invalid("invalid remote EE CP"))?
                .parse()
                .map_err(|_| invalid("invalid remote EE CP"))?;
            if let Some(expected) = &profile.expected_peer_cp {
                if observed != *expected {
                    tracing::warn!(local_ip=%self.local_ip, peer_ip=%self.peer_ip,
                        observed_cp=%observed, expected_cp=%expected,
                        "EE XID CP/NETID does not match configured peer");
                    return Err(invalid("unexpected EE peer CP or NETID"));
                }
            }
            match xid.exchange_state() {
                ExchangeState::Prenegotiation => &profile.prenegotiation,
                ExchangeState::NegotiationProceeding => &profile.negotiation,
                _ => return Err(invalid("unsupported EE XID phase")),
            }
        };
        if !information.is_empty() && information[9] & 0x0c == 0x04 {
            validate_tower(information)?;
        }
        let was_active = self.phase() == Phase::Active;
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
        if information.is_empty() || information[9] & 0x0c == 0x08 {
            self.peer_np = None;
            if was_active {
                self.generation = self.generation.saturating_add(1);
                self.next_live = None;
                self.retry_at = None;
                self.retries = 0;
            }
        } else {
            self.peer_np = Some(information.to_vec());
        }
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
        self.peer_np = None;
        self.generation = self.generation.saturating_add(1);
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
    use std::{
        net::UdpSocket,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
    };

    fn tower() -> ControlFlowsTower {
        let mut tower = ControlFlowsTower::decode(&[
            0x17, 0x81, 0x05, 0xb5, 0, 0, 0xea, 0x60, 0x10, 0, 0, 0, 4, 0, 0, 0, 4, 2, 0xa4, 0, 2,
            0xa5, 0,
        ])
        .unwrap();
        tower.path_switch_time_ms = 0;
        tower.arb_mode = ArbMode::Base;
        tower
    }

    #[test]
    fn builds_stable_local_nn_xids_for_foreign_netid_end_node() {
        let local: QualifiedName = "SNUSNU.SVC".parse().unwrap();
        let peer: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let xids = LocalEeXids::build(
            &local,
            &peer,
            [0xff, 0xf1, 0x23, 0x45],
            1,
            [0x80, 2],
            &tower(),
            true,
        )
        .unwrap();
        let pre = Xid3::decode(&xids.prenegotiation).unwrap();
        let np = Xid3::decode(&xids.negotiation).unwrap();
        assert_eq!(pre.cp_name().unwrap(), "SNUSNU.SVC");
        assert_eq!(np.cp_name().unwrap(), "SNUSNU.SVC");
        assert_eq!(pre.node_id(), [0xff, 0xf1, 0x23, 0x45]);
        assert_eq!(np.node_id(), pre.node_id());
        assert_eq!(pre.exchange_state(), ExchangeState::Prenegotiation);
        assert_eq!(np.exchange_state(), ExchangeState::NegotiationProceeding);
        assert_eq!(np.role(), Ok(Role::Secondary));
        assert_eq!(xids.prenegotiation[9] & 0x40, 0x40); // NN assertion.
        assert_eq!(xids.negotiation[9] & 0x40, 0x40);
        assert_eq!(
            HprXidEvidence::parse(&xids.negotiation, HprMedium::EnterpriseExtender)
                .unwrap()
                .advertised_sap,
            4
        );
        let again = LocalEeXids::build(
            &local,
            &peer,
            [0xff, 0xf1, 0x23, 0x45],
            1,
            [0x80, 2],
            &tower(),
            true,
        )
        .unwrap();
        assert_eq!(xids.prenegotiation, again.prenegotiation);
        assert_eq!(xids.negotiation, again.negotiation);
        assert!(LocalEeXids::build(
            &local,
            &local,
            [0xff, 0xf1, 0x23, 0x45],
            1,
            [0x80, 2],
            &tower(),
            true
        )
        .is_err());
        assert!(
            LocalEeXids::build(&local, &peer, [0, 0, 0, 0], 1, [0x80, 2], &tower(), true).is_err()
        );
        let mut unsupported = tower();
        unsupported.arb_mode = ArbMode::Responsive;
        assert!(LocalEeXids::build(
            &local,
            &peer,
            [0xff, 0xf1, 0x23, 0x45],
            1,
            [0x80, 2],
            &unsupported,
            true
        )
        .is_err());
        unsupported.arb_mode = ArbMode::Base;
        unsupported.path_switch_time_ms = 60_000;
        assert!(LocalEeXids::build(
            &local,
            &peer,
            [0xff, 0xf1, 0x23, 0x45],
            1,
            [0x80, 2],
            &unsupported,
            true
        )
        .is_err());
    }

    #[test]
    fn configured_peer_netid_is_checked_before_xid_response() {
        let local: QualifiedName = "SNUSNU.SVC".parse().unwrap();
        let expected: QualifiedName = "QAALICE.SNAB".parse().unwrap();
        let profile = LocalEeXids::build(
            &local,
            &expected,
            [0xff, 0xf1, 0x23, 0x45],
            1,
            [0x80, 2],
            &tower(),
            true,
        )
        .unwrap();
        let pid = std::process::id();
        let local_ip = IpAddr::from([127, 95, (pid >> 8) as u8, pid as u8]);
        let peer_ip = IpAddr::from([127, 96, (pid >> 8) as u8, pid as u8]);
        let mut endpoint = EeLdlcEndpoint::bind(local_ip, peer_ip, profile).unwrap();
        let wrong =
            Datagram::decode(CONTROL_PORT, [vec![4, 4, 0xaf], xid(false, false)].concat()).unwrap();
        assert_eq!(
            endpoint.process(wrong, Instant::now()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(endpoint.phase(), Phase::Down);
    }

    #[test]
    fn dynamic_profile_waits_for_authorized_local_cp() {
        let pid = std::process::id();
        let local_ip = IpAddr::from([127, 97, (pid >> 8) as u8, pid as u8]);
        let peer_ip = IpAddr::from([127, 98, (pid >> 8) as u8, pid as u8]);
        let ready = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&ready);
        let mut endpoint = EeLdlcEndpoint::bind_dynamic(local_ip, peer_ip, move |peer_xid| {
            if !shared.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "authorized proxy CP route not ready",
                ));
            }
            let local: QualifiedName = "SNUSNU.SVC".parse().unwrap();
            let peer: QualifiedName = peer_xid.cp_name().unwrap().parse().unwrap();
            LocalEeXids::build(
                &local,
                &peer,
                [0xff, 0xf1, 0x23, 0x45],
                1,
                [0x80, 2],
                &tower(),
                true,
            )
        })
        .unwrap();
        let peer = UdpSocket::bind((peer_ip, CONTROL_PORT)).unwrap();
        peer.set_nonblocking(true).unwrap();
        let now = Instant::now();
        assert_eq!(exchange(&mut endpoint, &peer, &[], now), [4, 5, 0xaf]);
        let mut request = vec![4, 4, 0xaf];
        request.extend_from_slice(&xid(false, false));
        peer.send_to(&request, (local_ip, CONTROL_PORT)).unwrap();
        endpoint.poll(now).unwrap();
        let mut scratch = [0u8; 512];
        assert_eq!(
            peer.recv_from(&mut scratch).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(endpoint.phase(), Phase::Down);
        ready.store(true, Ordering::Relaxed);
        assert_eq!(
            exchange(&mut endpoint, &peer, &xid(false, false), now)[..3],
            [4, 5, 0xaf]
        );
        assert_eq!(endpoint.phase(), Phase::Negotiating);
    }

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
        let mut remote_pre = xid(false, false);
        remote_pre[2..6].fill(0); // V5R4 assigns its node ID in a later NP XID.
        assert_eq!(
            exchange(&mut endpoint, &peer, &remote_pre, now),
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
        assert_eq!(endpoint.peer_cp().as_deref(), Some("SOLNET.SNAB"));
        let bootstrap = endpoint.control_bootstrap().unwrap().unwrap();
        assert_eq!(bootstrap.peer.cp.to_string(), "SOLNET.SNAB");
        assert_eq!(bootstrap.outbound_cp_label(), [0xa4, 0]);
        let priority = UdpSocket::bind((peer_ip, NETWORK_PORT)).unwrap();
        priority.set_nonblocking(true).unwrap();
        endpoint.send_nlp(NETWORK_PORT, &[0xc6, 0, 0xa4]).unwrap();
        let mut priority_reply = [0u8; 64];
        let (size, _) = priority.recv_from(&mut priority_reply).unwrap();
        assert_eq!(&priority_reply[..size], &[4, 4, 3, 0xc6, 0, 0xa4]);

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
