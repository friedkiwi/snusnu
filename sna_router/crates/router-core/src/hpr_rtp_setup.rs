//! Bounded receive-side evidence for one HPR RTP connection setup.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 2-11–2-20 defines the qualified
//! originator TCID, Connection Setup (X'0D'), Switching Information (X'14')
//! and Connection Identifier Exchange (X'10') segments. This state records a
//! locally addressed setup, a caller-confirmed transmitted CIE, and the
//! peer's subsequent use of that ID. It does not encode a reply, implement
//! STATUS/ARB/retransmission, or declare an RTP connection active.

use crate::{
    hpr_rtp::{RtpError, RtpOptionalSegment, RtpPacket},
    ConnectionGeneration,
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const MAX_NETWORK_ID: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpLocalTarget {
    /// Network ID in on-wire encoding, supplied by the local APPN identity.
    pub network_id: Vec<u8>,
    /// Unqualified CP name in on-wire encoding, not the four-byte fixed XID
    /// node identifier. The V5R4 capture's CV00 is EBCDIC `SNAA`.
    pub node_id: Vec<u8>,
    pub nce_instance: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupPhase {
    Idle,
    AwaitReplySent,
    AwaitPeerUse,
    PeerUsingAssignedId,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupError {
    StaleGeneration,
    WrongPhase,
    InvalidLocalTarget,
    InvalidRtp(RtpError),
    MissingQualifiedOrigin,
    InvalidSetup,
    InvalidSwitchingInformation,
    WrongTarget,
    WrongReplyTcid,
    MissingCie,
    WrongPeerTcid,
    InvalidTopic,
}

/// IBM SNA Formats GA27-3136-20 p. 9-39: CV X'28' identifies the traffic
/// carried by an RTP connection. User traffic contains a COS/TPF X'2C' CV.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtpSetupTopic {
    RouteSetup,
    CpSvcMg,
    User { cos_tpf: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpInboundSetup {
    generation: ConnectionGeneration,
    target: RtpLocalTarget,
    phase: SetupPhase,
    origin_tcid: Option<u64>,
    /// Complete source qualifier CV, including NCE-instance subfield. It is
    /// retained as evidence, not decoded into a routable peer identity.
    source_qualifier: Vec<u8>,
    assigned_tcid: Option<u64>,
    topic: Option<RtpSetupTopic>,
}

impl RtpInboundSetup {
    pub fn new(
        generation: ConnectionGeneration,
        target: RtpLocalTarget,
    ) -> Result<Self, SetupError> {
        if target.network_id.is_empty()
            || target.network_id.len() > MAX_NETWORK_ID
            || target.node_id.is_empty()
            || target.node_id.len() > 8
        {
            return Err(SetupError::InvalidLocalTarget);
        }
        Ok(Self {
            generation,
            target,
            phase: SetupPhase::Idle,
            origin_tcid: None,
            source_qualifier: Vec::new(),
            assigned_tcid: None,
            topic: None,
        })
    }

    pub fn phase(&self) -> SetupPhase {
        self.phase
    }

    pub fn source_qualifier(&self) -> Option<&[u8]> {
        (!self.source_qualifier.is_empty()).then_some(&self.source_qualifier)
    }

    pub fn topic(&self) -> Option<&RtpSetupTopic> {
        self.topic.as_ref()
    }

    fn check_generation(&self, generation: ConnectionGeneration) -> Result<(), SetupError> {
        if generation != self.generation {
            Err(SetupError::StaleGeneration)
        } else {
            Ok(())
        }
    }

    /// Observe one complete inbound qualified setup NLP after the caller has
    /// validated the EE peer, priority port, SAP, and link generation.
    pub fn observe_inbound_setup(
        &mut self,
        generation: ConnectionGeneration,
        packet: RtpPacket<'_>,
    ) -> Result<(), SetupError> {
        self.check_generation(generation)?;
        if self.phase != SetupPhase::Idle {
            return Err(SetupError::WrongPhase);
        }
        if packet.tcid & (ASSIGNOR | RESERVED) != ASSIGNOR || packet.thdr[8] & 0x40 == 0 {
            return Err(SetupError::MissingQualifiedOrigin);
        }
        packet
            .connection_qualifier()
            .map_err(SetupError::InvalidRtp)?
            .ok_or(SetupError::MissingQualifiedOrigin)?;
        let qualifier_len = usize::from(packet.thdr[20]).div_ceil(4) * 4;
        let source_qualifier = packet.thdr[20..20 + qualifier_len].to_vec();
        let segments = packet.optional_segments().map_err(SetupError::InvalidRtp)?;
        if segments.iter().filter(|s| s.key == 0x0d).count() != 1
            || segments.iter().filter(|s| s.key == 0x14).count() != 1
            || segments.iter().any(|s| s.key == 0x10)
        {
            return Err(SetupError::InvalidSetup);
        }
        let setup = segments.iter().find(|s| s.key == 0x0d).unwrap();
        let si = segments.iter().find(|s| s.key == 0x14).unwrap();
        let topic = validate_setup(*setup, &self.target)?;
        validate_switching_information(*si)?;
        self.origin_tcid = Some(packet.tcid);
        self.source_qualifier = source_qualifier;
        self.topic = Some(topic);
        self.phase = SetupPhase::AwaitReplySent;
        Ok(())
    }

    /// Record a reply only after the caller confirms its transmission. The
    /// packet must carry a valid CIE assigning the TCID for future peer sends.
    pub fn observe_outbound_reply_sent(
        &mut self,
        generation: ConnectionGeneration,
        packet: RtpPacket<'_>,
    ) -> Result<(), SetupError> {
        self.check_generation(generation)?;
        if self.phase != SetupPhase::AwaitReplySent {
            return Err(SetupError::WrongPhase);
        }
        let origin = self.origin_tcid.unwrap();
        if packet.tcid != origin & !ASSIGNOR || packet.thdr[8] & 0x40 != 0 {
            return Err(SetupError::WrongReplyTcid);
        }
        if packet
            .connection_qualifier()
            .map_err(SetupError::InvalidRtp)?
            .is_some()
        {
            return Err(SetupError::WrongReplyTcid);
        }
        let assigned = packet
            .connection_identifier_exchange()
            .map_err(SetupError::InvalidRtp)?
            .ok_or(SetupError::MissingCie)?;
        self.assigned_tcid = Some(assigned);
        self.phase = SetupPhase::AwaitPeerUse;
        Ok(())
    }

    /// Observe that the originator has switched to the CIE-assigned ID.
    /// This is not proof of STATUS, ARB or reliable RTP activation.
    pub fn observe_inbound_peer_use(
        &mut self,
        generation: ConnectionGeneration,
        packet: RtpPacket<'_>,
    ) -> Result<(), SetupError> {
        self.check_generation(generation)?;
        if self.phase != SetupPhase::AwaitPeerUse {
            return Err(SetupError::WrongPhase);
        }
        let assigned = self.assigned_tcid.unwrap();
        if packet.tcid != assigned & !ASSIGNOR || packet.thdr[8] & 0x40 != 0 {
            return Err(SetupError::WrongPeerTcid);
        }
        if packet
            .connection_qualifier()
            .map_err(SetupError::InvalidRtp)?
            .is_some()
        {
            return Err(SetupError::WrongPeerTcid);
        }
        if packet
            .optional_segments()
            .map_err(SetupError::InvalidRtp)?
            .iter()
            .any(|segment| matches!(segment.key, 0x0d | 0x10))
        {
            return Err(SetupError::WrongPeerTcid);
        }
        self.phase = SetupPhase::PeerUsingAssignedId;
        Ok(())
    }

    pub fn close(&mut self) {
        self.phase = SetupPhase::Closed;
        self.origin_tcid = None;
        self.assigned_tcid = None;
        self.source_qualifier.clear();
        self.topic = None;
    }

    pub fn reset(&mut self, generation: ConnectionGeneration) -> Result<(), SetupError> {
        if generation.get() <= self.generation.get() {
            return Err(SetupError::StaleGeneration);
        }
        self.generation = generation;
        self.phase = SetupPhase::Idle;
        self.origin_tcid = None;
        self.assigned_tcid = None;
        self.source_qualifier.clear();
        self.topic = None;
        Ok(())
    }
}

fn lt_vectors(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, SetupError> {
    let mut vectors = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(SetupError::InvalidSetup);
        }
        let len = usize::from(bytes[0]);
        let aligned = len.div_ceil(4) * 4;
        if len < 2 || aligned > bytes.len() || bytes[len..aligned].iter().any(|b| *b != 0) {
            return Err(SetupError::InvalidSetup);
        }
        vectors.push((bytes[1], &bytes[2..len]));
        bytes = &bytes[aligned..];
    }
    Ok(vectors)
}

fn validate_setup(
    segment: RtpOptionalSegment<'_>,
    local: &RtpLocalTarget,
) -> Result<RtpSetupTopic, SetupError> {
    let data = segment.data;
    if data.len() < 6 || data[..2] != [1, 1] || data[2] & !0x04 != 0x98 || data[3..6] != [0, 0, 0] {
        return Err(SetupError::InvalidSetup);
    }
    let vectors = lt_vectors(&data[6..])?;
    // CV28 is only framed here. Its topic and associated APPN control flow
    // are untrusted and cannot authorize a route or release packet data.
    if vectors.len() != 4
        || vectors.iter().map(|(key, _)| *key).collect::<Vec<_>>() != [0x28, 0x03, 0x00, 0x39]
    {
        return Err(SetupError::InvalidSetup);
    }
    let topic = parse_topic(vectors[0].1)?;
    if vectors[1].1 != local.network_id
        || vectors[2].1 != local.node_id
        || vectors[3].1 != local.nce_instance
    {
        return Err(SetupError::WrongTarget);
    }
    Ok(topic)
}

fn parse_topic(body: &[u8]) -> Result<RtpSetupTopic, SetupError> {
    const RSETUP: [u8; 6] = [0xd9, 0xe2, 0xc5, 0xe3, 0xe4, 0xd7];
    const CPSVCMG: [u8; 7] = [0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
    let (&indicator, value) = body.split_first().ok_or(SetupError::InvalidTopic)?;
    match indicator {
        0 if value == RSETUP => Ok(RtpSetupTopic::RouteSetup),
        0 if value == CPSVCMG => Ok(RtpSetupTopic::CpSvcMg),
        0x80 if value.len() >= 2 && usize::from(value[0]) == value.len() && value[1] == 0x2c => {
            Ok(RtpSetupTopic::User {
                cos_tpf: value.to_vec(),
            })
        }
        _ => Err(SetupError::InvalidTopic),
    }
}

/// Read CV X'28' to choose the control or user parser before constructing an
/// endpoint. This classification is untrusted until the caller validates the
/// EE adjacency and the endpoint checks CS target, peer qualifier and path.
pub fn classify_setup_topic(packet: RtpPacket<'_>) -> Result<RtpSetupTopic, SetupError> {
    let segments = packet.optional_segments().map_err(SetupError::InvalidRtp)?;
    let mut setups = segments.iter().filter(|segment| segment.key == 0x0d);
    let setup = setups.next().ok_or(SetupError::InvalidSetup)?;
    if setups.next().is_some() || setup.data.len() < 6 || setup.data[..2] != [1, 1] {
        return Err(SetupError::InvalidSetup);
    }
    let vectors = lt_vectors(&setup.data[6..])?;
    let (key, body) = vectors.first().ok_or(SetupError::InvalidTopic)?;
    if *key != 0x28 {
        return Err(SetupError::InvalidTopic);
    }
    parse_topic(body)
}

fn validate_switching_information(segment: RtpOptionalSegment<'_>) -> Result<(), SetupError> {
    let data = segment.data;
    if data.len() < 2 || data[..2] != [0, 0] {
        return Err(SetupError::InvalidSwitchingInformation);
    }
    let vectors = lt_vectors(&data[2..]).map_err(|_| SetupError::InvalidSwitchingInformation)?;
    if vectors.len() != 2 || vectors[0].0 != 0x83 || vectors[1].0 != 0x85 {
        return Err(SetupError::InvalidSwitchingInformation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: u64 = 0x8015_0001_0000_0040;
    const ASSIGNED: u64 = 0x8016_0002_0000_0040;

    fn generation(n: u64) -> ConnectionGeneration {
        ConnectionGeneration::new(n).unwrap()
    }

    fn target() -> RtpLocalTarget {
        RtpLocalTarget {
            network_id: b"NET001".to_vec(),
            node_id: b"NODE".to_vec(),
            nce_instance: [0, 0, 0, 4],
        }
    }

    fn lt(key: u8, body: &[u8]) -> Vec<u8> {
        let mut cv = vec![(body.len() + 2) as u8, key];
        cv.extend_from_slice(body);
        cv.resize(cv.len().div_ceil(4) * 4, 0);
        cv
    }

    fn segment(key: u8, body: &[u8]) -> Vec<u8> {
        let mut seg = vec![0, key];
        seg.extend_from_slice(body);
        seg.resize(seg.len().div_ceil(4) * 4, 0);
        seg[0] = (seg.len() / 4) as u8;
        seg
    }

    fn qualifier() -> Vec<u8> {
        // Sanitized 32-byte CV05 structure seen on V5R4 setup, including
        // CV03, CV00, CV26 and CV39. All identifiers are synthetic.
        [
            30, 5, 0x80, 0, 8, 3, b'S', b'R', b'C', b'0', b'0', b'1', 6, 0, b'O', b'R', b'I', b'G',
            0, 0, 4, 0x26, 0x12, 0x34, 6, 0x39, 0, 0, 0, 8, 0, 0,
        ]
        .to_vec()
    }

    fn setup_segments(local: &RtpLocalTarget) -> Vec<u8> {
        let mut cs = vec![1, 1, 0x98, 0, 0, 0];
        cs.extend_from_slice(&lt(0x28, &[0, 0xd9, 0xe2, 0xc5, 0xe3, 0xe4, 0xd7]));
        cs.extend_from_slice(&lt(0x03, &local.network_id));
        cs.extend_from_slice(&lt(0x00, &local.node_id));
        cs.extend_from_slice(&lt(0x39, &local.nce_instance));
        let mut si = vec![0, 0];
        si.extend_from_slice(&lt(0x83, &[0; 20]));
        si.extend_from_slice(&lt(0x85, &[0; 24]));
        let mut segments = segment(0x0d, &cs);
        segments.extend_from_slice(&segment(0x14, &si));
        segments.extend_from_slice(&segment(0x22, &[0; 18]));
        assert_eq!(segments.len(), 120);
        segments
    }

    fn nlp(tcid: u64, flags8: u8, qualifier: &[u8], segments: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xc2, 0x08, 0xa4, 0, 0xff, 0];
        let mut thdr = [0u8; 20];
        thdr[..8].copy_from_slice(&tcid.to_be_bytes());
        thdr[8] = flags8;
        thdr[9] = (if qualifier.is_empty() { 0 } else { 0x08 })
            | (if segments.is_empty() { 0 } else { 0x04 });
        thdr[10..12]
            .copy_from_slice(&((20 + qualifier.len() + segments.len()) as u16 / 4).to_be_bytes());
        bytes.extend_from_slice(&thdr);
        bytes.extend_from_slice(qualifier);
        bytes.extend_from_slice(segments);
        bytes
    }

    fn packet(bytes: &[u8]) -> RtpPacket<'_> {
        RtpPacket::parse(bytes).unwrap()
    }

    fn setup(local: &RtpLocalTarget) -> Vec<u8> {
        nlp(ORIGIN, 0x7c, &qualifier(), &setup_segments(local))
    }

    fn reply() -> Vec<u8> {
        let mut status = segment(0x0e, &[0; 18]);
        let mut cie = vec![0, 0];
        cie.extend_from_slice(&ASSIGNED.to_be_bytes());
        status.extend_from_slice(&segment(0x10, &cie));
        nlp(ORIGIN & !ASSIGNOR, 0, &[], &status)
    }

    #[test]
    fn observed_setup_reply_and_peer_use_advance_without_activation() {
        let local = target();
        let mut state = RtpInboundSetup::new(generation(1), local.clone()).unwrap();
        assert_eq!(state.phase(), SetupPhase::Idle);
        let setup = setup(&local);
        assert_eq!(packet(&setup).thdr.len(), 172); // V5R4 structural size.
        state
            .observe_inbound_setup(generation(1), packet(&setup))
            .unwrap();
        assert_eq!(state.phase(), SetupPhase::AwaitReplySent);
        assert_eq!(state.topic(), Some(&RtpSetupTopic::RouteSetup));
        assert_eq!(
            classify_setup_topic(packet(&setup)),
            Ok(RtpSetupTopic::RouteSetup)
        );
        assert!(state.source_qualifier().is_some());
        let reply = reply();
        state
            .observe_outbound_reply_sent(generation(1), packet(&reply))
            .unwrap();
        assert_eq!(state.phase(), SetupPhase::AwaitPeerUse);
        let peer = nlp(ASSIGNED & !ASSIGNOR, 0, &[], &[]);
        state
            .observe_inbound_peer_use(generation(1), packet(&peer))
            .unwrap();
        assert_eq!(state.phase(), SetupPhase::PeerUsingAssignedId);
    }

    #[test]
    fn topic_identifier_separates_control_and_user_rtp() {
        assert_eq!(
            parse_topic(&[0, 0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]),
            Ok(RtpSetupTopic::CpSvcMg)
        );
        let user = [
            0x80, 0x0c, 0x2c, 0x01, 0x08, 0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3,
        ];
        assert_eq!(
            parse_topic(&user),
            Ok(RtpSetupTopic::User {
                cos_tpf: user[1..].to_vec()
            })
        );
        assert_eq!(parse_topic(&[0, b'R']), Err(SetupError::InvalidTopic));
        assert_eq!(parse_topic(&[0x80, 3, 0x2c]), Err(SetupError::InvalidTopic));
        assert_eq!(parse_topic(&[0x40, 0]), Err(SetupError::InvalidTopic));
    }

    #[test]
    fn rejects_wrong_target_malformed_segments_and_unconfirmed_reply() {
        let local = target();
        let mut state = RtpInboundSetup::new(generation(1), local.clone()).unwrap();
        let setup_packet = setup(&local);
        let reply_packet = reply();
        assert_eq!(
            state.observe_outbound_reply_sent(generation(1), packet(&reply_packet)),
            Err(SetupError::WrongPhase)
        );
        let mut wrong = local.clone();
        wrong.nce_instance[3] ^= 1;
        assert_eq!(
            state.observe_inbound_setup(generation(1), packet(&setup(&wrong))),
            Err(SetupError::WrongTarget)
        );
        let mut malformed = setup_packet.clone();
        malformed[6 + 20 + 32 + 2 + 2] = 0; // Clear CS target-present bit.
        assert_eq!(
            state.observe_inbound_setup(generation(1), packet(&malformed)),
            Err(SetupError::InvalidSetup)
        );
        state
            .observe_inbound_setup(generation(1), packet(&setup_packet))
            .unwrap();
        let mut missing = nlp(ORIGIN & !ASSIGNOR, 0, &[], &segment(0x0e, &[0; 18]));
        assert_eq!(
            state.observe_outbound_reply_sent(generation(1), packet(&missing)),
            Err(SetupError::MissingCie)
        );
        missing = nlp((ORIGIN & !ASSIGNOR) + 1, 0, &[], &[]);
        assert_eq!(
            state.observe_outbound_reply_sent(generation(1), packet(&missing)),
            Err(SetupError::WrongReplyTcid)
        );
        let mut bad_cie = reply();
        let cie_tcid_start = bad_cie.len() - 8;
        bad_cie[cie_tcid_start] &= 0x7f; // CIE assignor bit must be one.
        assert_eq!(
            state.observe_outbound_reply_sent(generation(1), packet(&bad_cie)),
            Err(SetupError::InvalidRtp(
                RtpError::InvalidConnectionIdentifierExchange
            ))
        );
        state
            .observe_outbound_reply_sent(generation(1), packet(&reply_packet))
            .unwrap();
        let wrong_peer = nlp((ASSIGNED & !ASSIGNOR) + 1, 0, &[], &[]);
        assert_eq!(
            state.observe_inbound_peer_use(generation(1), packet(&wrong_peer)),
            Err(SetupError::WrongPeerTcid)
        );
        assert_eq!(state.phase(), SetupPhase::AwaitPeerUse);
    }

    #[test]
    fn stale_generation_and_close_clear_all_setup_evidence() {
        let local = target();
        let mut state = RtpInboundSetup::new(generation(1), local.clone()).unwrap();
        let setup = setup(&local);
        assert_eq!(
            state.observe_inbound_setup(generation(2), packet(&setup)),
            Err(SetupError::StaleGeneration)
        );
        state
            .observe_inbound_setup(generation(1), packet(&setup))
            .unwrap();
        state.close();
        assert_eq!(state.phase(), SetupPhase::Closed);
        assert!(state.source_qualifier().is_none());
        assert_eq!(state.reset(generation(1)), Err(SetupError::StaleGeneration));
        state.reset(generation(2)).unwrap();
        assert_eq!(state.phase(), SetupPhase::Idle);
        assert_eq!(
            state.observe_inbound_setup(generation(1), packet(&setup)),
            Err(SetupError::StaleGeneration)
        );
    }
}
