//! Initiate the reciprocal CP-CP contention-winner session over HPR RTP.
//!
//! Each APPN node originates one CPSVCMG BIND to its adjacent CP. The BIND
//! and subsequent CP Capabilities exchange are distinct from the peer's
//! contention-winner session handled by `hpr_cp_management`.

use crate::{
    fid2_bind::{BindClass, BindIdentity},
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_fid5::Fid5WholeBiu,
    hpr_session_address::{Direction, Fid5AddressAssociation, RtpAssociationScope, RtpObservation},
    session::QualifiedName,
    ConnectionGeneration,
};
use std::{error::Error, fmt};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const CPSVCMG: [u8; 7] = [0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
const REQUEST_FIXED: [u8; 27] = [
    0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0, 0, 0, 0,
    0, 0x94, 0x23, 0, 0,
];
const LOCAL_CAPABILITIES: [u8; 12] = [0, 12, 0x12, 0xc1, 0, 0, 0, 0, 0xe0, 0x80, 0, 0];
const CAP_ATTACH: [u8; 17] = [
    0x11, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 4, 0x22, 0xf0, 0xf0, 0xf1, 0, 0, 0,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpInitiatorError {
    InvalidNonce,
    InvalidName,
    WrongPhase,
    WrongScope,
    BindRejected { sense: u32 },
    InvalidResponse,
    InvalidCapabilities,
}

impl fmt::Display for CpInitiatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HPR reciprocal CP session: {self:?}")
    }
}

impl Error for CpInitiatorError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpInitiatorPhase {
    BindPrepared,
    AwaitBindResponse,
    CapabilitiesPrepared,
    AwaitCapabilitiesReply,
    Active,
}

#[derive(Clone, Debug)]
pub struct ReciprocalCpSession {
    local: QualifiedName,
    peer: QualifiedName,
    generation: ConnectionGeneration,
    phase: CpInitiatorPhase,
    bind: Vec<u8>,
    fqpcid: Vec<u8>,
    association: Option<Fid5AddressAssociation>,
    capabilities: Option<Vec<u8>>,
    pacing_grant: Option<Vec<u8>>,
}

impl ReciprocalCpSession {
    /// The caller supplies a fresh nonzero nonce for each link attempt. It is
    /// used for the PLU-assigned session address, FQPCID, and BIND instance.
    pub fn new(bootstrap: HprControlBootstrap, nonce: u64) -> Result<Self, CpInitiatorError> {
        Self::for_peers(
            bootstrap.local.cp,
            bootstrap.peer.cp,
            bootstrap.generation,
            nonce,
        )
    }

    fn for_peers(
        local: QualifiedName,
        peer: QualifiedName,
        generation: ConnectionGeneration,
        nonce: u64,
    ) -> Result<Self, CpInitiatorError> {
        if nonce == 0 || nonce & (ASSIGNOR | RESERVED) != 0 {
            return Err(CpInitiatorError::InvalidNonce);
        }
        let local_name = encode_name(&local)?;
        let peer_name = encode_name(&peer)?;
        let token = nonce.to_be_bytes();
        let mut fqpcid = vec![0x60, (9 + local_name.len()) as u8];
        fqpcid.extend_from_slice(&token);
        fqpcid.push(local_name.len() as u8);
        fqpcid.extend_from_slice(&local_name);
        let mut user = vec![0, 8, 2];
        user.extend_from_slice(&CPSVCMG);
        user.extend_from_slice(&[9, 3, 1]);
        user.extend_from_slice(&token[1..]);
        user.push((1 + local_name.len()) as u8);
        user.push(4);
        user.extend_from_slice(&local_name);
        user.extend_from_slice(&[10, 0x13, 0, 0xb0]);
        user.extend_from_slice(&token[1..]);
        let mut bind = vec![0x5d, 0, 0, 0];
        bind.extend_from_slice(&(ASSIGNOR | nonce).to_be_bytes());
        bind.extend_from_slice(&[0x6b, 0x80, 0]);
        bind.extend_from_slice(&REQUEST_FIXED);
        bind.push(local_name.len() as u8);
        bind.extend_from_slice(&local_name);
        bind.push(user.len() as u8);
        bind.extend_from_slice(&user);
        bind.push(0); // No URC.
        bind.push(peer_name.len() as u8);
        bind.extend_from_slice(&peer_name);
        bind.extend_from_slice(&fqpcid);
        // Adjacent APPN CP BINDs include the control-flow COS/TPF. Match the
        // peer's negotiated CPSVCMG class and medium RTP priority.
        bind.extend_from_slice(&[0x2c, 9, 4, 7]);
        bind.extend_from_slice(&CPSVCMG);
        let parsed =
            Fid5WholeBiu::parse_complete(&bind).map_err(|_| CpInitiatorError::WrongPhase)?;
        if parsed
            .classify_bind()
            .map_err(|_| CpInitiatorError::WrongPhase)?
            != Some(BindIdentity {
                class: BindClass::Management {
                    mode: "CPSVCMG".into(),
                },
                plu: local.to_string(),
                slu: peer.to_string(),
            })
        {
            return Err(CpInitiatorError::WrongPhase);
        }
        Ok(Self {
            local,
            peer,
            generation,
            phase: CpInitiatorPhase::BindPrepared,
            bind,
            fqpcid,
            association: None,
            capabilities: None,
            pacing_grant: None,
        })
    }

    pub fn phase(&self) -> CpInitiatorPhase {
        self.phase
    }

    pub fn prepare_bind(&self) -> Result<&[u8], CpInitiatorError> {
        (self.phase == CpInitiatorPhase::BindPrepared)
            .then_some(self.bind.as_slice())
            .ok_or(CpInitiatorError::WrongPhase)
    }

    /// Call after the qualified outbound RTP setup carrying BIND is accepted
    /// by the socket. Its control reply supplies the peer's directional TCID.
    pub fn mark_bind_sent(&mut self) -> Result<(), CpInitiatorError> {
        if self.phase != CpInitiatorPhase::BindPrepared {
            return Err(CpInitiatorError::WrongPhase);
        }
        self.phase = CpInitiatorPhase::AwaitBindResponse;
        Ok(())
    }

    /// Consume a complete FID5 BIU delivered by the authenticated outbound
    /// CP RTP connection. The returned BIU is the next CP capabilities Attach
    /// and must be queued before committing this candidate state.
    pub fn ingest(
        &mut self,
        scope: RtpAssociationScope,
        observation: RtpObservation,
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, CpInitiatorError> {
        if scope.generation != self.generation || observation.generation != self.generation {
            return Err(CpInitiatorError::WrongScope);
        }
        let fid5 =
            Fid5WholeBiu::parse_complete(bytes).map_err(|_| CpInitiatorError::InvalidResponse)?;
        match self.phase {
            CpInitiatorPhase::AwaitBindResponse => {
                // The peer can terminate a rejected BIND with UNBIND type
                // X'0F' and a four-byte sense. Report that sense and its
                // BIND displacement instead of treating it as a malformed
                // positive response.
                if observation.tcid == scope.slu_tcid
                    && fid5.expedited
                    && fid5.sequence_number == 0
                    && fid5.session_address
                        == (u64::from_be_bytes(self.bind[4..12].try_into().unwrap()) & !ASSIGNOR)
                            .to_be_bytes()
                    && fid5.rh == [0x6b, 0x80, 0]
                    && fid5.ru.len() >= 6
                    && fid5.ru[0..2] == [0x32, 0x0f]
                {
                    return Err(CpInitiatorError::BindRejected {
                        sense: u32::from_be_bytes(fid5.ru[2..6].try_into().unwrap()),
                    });
                }
                let mut association = Fid5AddressAssociation::new(scope);
                association
                    .observe_bind_request(
                        RtpObservation {
                            generation: self.generation,
                            tcid: scope.initial_plu_tcid,
                        },
                        Fid5WholeBiu::parse_complete(&self.bind).unwrap(),
                    )
                    .map_err(|_| CpInitiatorError::WrongScope)?;
                association
                    .observe_bind_response(observation, fid5)
                    .map_err(|_| CpInitiatorError::InvalidResponse)?;
                validate_bind_response(fid5.ru, &self.fqpcid)?;
                let target_sa = association
                    .data_address(Direction::PluToSlu)
                    .ok_or(CpInitiatorError::InvalidResponse)?;
                let mut capabilities = vec![0x5c, 0, 0, 1];
                capabilities.extend_from_slice(&target_sa);
                capabilities.extend_from_slice(&[0x0b, 0x91, 0x20]);
                capabilities.extend_from_slice(&CAP_ATTACH);
                capabilities.extend_from_slice(&LOCAL_CAPABILITIES);
                self.association = Some(association);
                self.capabilities = Some(capabilities.clone());
                self.phase = CpInitiatorPhase::CapabilitiesPrepared;
                Ok(vec![capabilities])
            }
            CpInitiatorPhase::AwaitCapabilitiesReply => {
                self.association
                    .as_ref()
                    .ok_or(CpInitiatorError::WrongPhase)?
                    .observe_data(Direction::SluToPlu, observation, fid5)
                    .map_err(|_| CpInitiatorError::WrongScope)?;
                // The SLU grants the adaptive pacing window with a solicited
                // expedited IPM after our CP Capabilities Attach. It is not
                // the X'12C1' capabilities reply and need not advance the
                // CP transaction. The V5R4 trace sends this before its GDS.
                if fid5.expedited && fid5.rh == [0x83, 0x01, 0] {
                    let window = if fid5.ru.len() == 3 && fid5.ru[0] == 0 {
                        u16::from_be_bytes([fid5.ru[1], fid5.ru[2]])
                    } else {
                        return Err(CpInitiatorError::InvalidCapabilities);
                    };
                    if !(1..=32767).contains(&window)
                        || self
                            .pacing_grant
                            .as_ref()
                            .is_some_and(|grant| grant != bytes)
                    {
                        return Err(CpInitiatorError::InvalidCapabilities);
                    }
                    self.pacing_grant = Some(bytes.to_vec());
                    return Ok(Vec::new());
                }
                if fid5.expedited
                    || fid5.rh != [0x03, 0x91, 1]
                    || fid5.ru.len() < 12
                    || fid5.ru.len() > 128
                    || fid5.ru[0..4] != [0, fid5.ru.len() as u8, 0x12, 0xc1]
                    || fid5.ru[8] & 0xe0 != 0x80
                {
                    return Err(CpInitiatorError::InvalidCapabilities);
                }
                self.phase = CpInitiatorPhase::Active;
                Ok(Vec::new())
            }
            _ => Err(CpInitiatorError::WrongPhase),
        }
    }

    pub fn prepare_capabilities(&self) -> Result<&[u8], CpInitiatorError> {
        (self.phase == CpInitiatorPhase::CapabilitiesPrepared)
            .then_some(self.capabilities.as_deref())
            .flatten()
            .ok_or(CpInitiatorError::WrongPhase)
    }

    pub fn mark_capabilities_sent(&mut self) -> Result<(), CpInitiatorError> {
        if self.phase != CpInitiatorPhase::CapabilitiesPrepared {
            return Err(CpInitiatorError::WrongPhase);
        }
        self.phase = CpInitiatorPhase::AwaitCapabilitiesReply;
        Ok(())
    }

    pub fn peers(&self) -> (&QualifiedName, &QualifiedName) {
        (&self.local, &self.peer)
    }
}

fn validate_bind_response(ru: &[u8], fqpcid: &[u8]) -> Result<(), CpInitiatorError> {
    if ru.len() < 31 || ru[0..4] != [0x31, 0, 0x13, 7] || ru[14..16] != [6, 2] || ru[27] != 0 {
        return Err(CpInitiatorError::InvalidResponse);
    }
    let user_start = 29usize;
    let user_end = user_start
        .checked_add(usize::from(ru[28]))
        .filter(|end| *end < ru.len())
        .ok_or(CpInitiatorError::InvalidResponse)?;
    let user = &ru[user_start..user_end];
    if user.len() < 10 || user[0..3] != [0, 8, 2] || user[3..10] != CPSVCMG {
        return Err(CpInitiatorError::InvalidResponse);
    }
    let retired = user_end
        .checked_add(1 + usize::from(ru[user_end]))
        .filter(|end| *end < ru.len())
        .ok_or(CpInitiatorError::InvalidResponse)?;
    if ru[retired] != 0 || !ru[retired + 1..].starts_with(fqpcid) {
        return Err(CpInitiatorError::InvalidResponse);
    }
    Ok(())
}

fn encode_name(name: &QualifiedName) -> Result<Vec<u8>, CpInitiatorError> {
    name.to_string()
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'I' => Ok(0xc1 + (byte - b'A')),
            b'J'..=b'R' => Ok(0xd1 + (byte - b'J')),
            b'S'..=b'Z' => Ok(0xe2 + (byte - b'S')),
            b'0'..=b'9' => Ok(0xf0 + (byte - b'0')),
            b'.' => Ok(0x4b),
            _ => Err(CpInitiatorError::InvalidName),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reciprocal_cp_bind_and_capabilities_use_distinct_directional_addresses() {
        let generation = ConnectionGeneration::new(3).unwrap();
        // Outbound CP nonce observed in the successful V5R4 BIND exchange
        // at 2026-11-02 17:21:20 UTC.
        let nonce = 0x18ca_5a3a_bb99_b979;
        let mut session = ReciprocalCpSession::for_peers(
            "SNUSNU.SVC".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
            generation,
            nonce,
        )
        .unwrap();
        let bind = session.prepare_bind().unwrap().to_vec();
        let parsed = Fid5WholeBiu::parse_complete(&bind).unwrap();
        assert_eq!(parsed.session_address, (ASSIGNOR | nonce).to_be_bytes());
        assert_eq!(parsed.ru[24], 0x23); // Confirm, parallel sessions, CNOS.
        assert_eq!(parsed.classify_bind().unwrap().unwrap().plu, "SNUSNU.SVC");
        assert_eq!(parsed.classify_bind().unwrap().unwrap().slu, "SOLNET.SNAB");
        assert!(parsed
            .ru
            .ends_with(&[0x2c, 9, 4, 7, 0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]));
        session.mark_bind_sent().unwrap();
        let scope = RtpAssociationScope {
            generation,
            initial_plu_tcid: 0x8000_0003_0000_0001,
            subsequent_plu_tcid: 0x0000_0004_0000_0001,
            slu_tcid: 0x0000_0003_0000_0001,
        };
        let mut response = vec![0x5d, 0, 0, 0];
        response.extend_from_slice(&nonce.to_be_bytes());
        response.extend_from_slice(&[0xeb, 0x80, 0]);
        let mut fixed = REQUEST_FIXED;
        fixed[8] = 0;
        fixed[9] = 0x80;
        fixed[12] = 0x80;
        fixed[13] = 0;
        fixed[23] = 0;
        fixed[24] = 0x23;
        fixed[25] = 0x40;
        response.extend_from_slice(&fixed);
        response.extend_from_slice(&[0, 13, 0, 8, 2]);
        response.extend_from_slice(&CPSVCMG);
        response.extend_from_slice(&[2, 3, 2, 0, 0]);
        response.extend_from_slice(&session.fqpcid);
        response.extend_from_slice(&[0x62, 8]);
        response.extend_from_slice(&0x8000_0000_0000_0007u64.to_be_bytes());
        let replies = session
            .ingest(
                scope,
                RtpObservation {
                    generation,
                    tcid: scope.slu_tcid,
                },
                &response,
            )
            .unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(session.phase(), CpInitiatorPhase::CapabilitiesPrepared);
        let caps = Fid5WholeBiu::parse_complete(&replies[0]).unwrap();
        assert_eq!(caps.session_address, 7u64.to_be_bytes());
        assert_eq!(caps.rh, [0x0b, 0x91, 0x20]);
        assert_eq!(&caps.ru[..CAP_ATTACH.len()], &CAP_ATTACH);
        assert_eq!(&caps.ru[CAP_ATTACH.len()..], &LOCAL_CAPABILITIES);
        session.mark_capabilities_sent().unwrap();
        let mut ipm = vec![0x5d, 0, 0, 0];
        ipm.extend_from_slice(&nonce.to_be_bytes());
        ipm.extend_from_slice(&[0x83, 0x01, 0, 0, 0, 1]);
        assert_eq!(
            ipm,
            [
                0x5d, 0, 0, 0, 0x18, 0xca, 0x5a, 0x3a, 0xbb, 0x99, 0xb9, 0x79, 0x83, 0x01, 0, 0, 0,
                1
            ]
        );
        for _ in 0..2 {
            assert!(session
                .ingest(
                    scope,
                    RtpObservation {
                        generation,
                        tcid: scope.slu_tcid,
                    },
                    &ipm,
                )
                .unwrap()
                .is_empty());
            assert_eq!(session.phase(), CpInitiatorPhase::AwaitCapabilitiesReply);
        }
        let mut peer_caps = vec![0x5c, 0, 0, 1];
        peer_caps.extend_from_slice(&nonce.to_be_bytes());
        peer_caps.extend_from_slice(&[3, 0x91, 1]);
        peer_caps.extend_from_slice(&[0, 12, 0x12, 0xc1, 0, 0, 0, 0, 0x82, 0x84, 0, 0]);
        assert!(session
            .ingest(
                scope,
                RtpObservation {
                    generation,
                    tcid: scope.slu_tcid,
                },
                &peer_caps
            )
            .unwrap()
            .is_empty());
        assert_eq!(session.phase(), CpInitiatorPhase::Active);
    }

    #[test]
    fn reports_live_v5r4_unbind_bind_sense_and_pointer() {
        let generation = ConnectionGeneration::new(1).unwrap();
        let nonce = 0x18ca_5a3a_bb99_b978;
        let mut session = ReciprocalCpSession::for_peers(
            "SNUSNU.SVC".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
            generation,
            nonce,
        )
        .unwrap();
        session.mark_bind_sent().unwrap();
        let scope = RtpAssociationScope {
            generation,
            initial_plu_tcid: 0x8000_0001_0000_0001,
            subsequent_plu_tcid: 0xe899_2ca2_0000_00b8,
            slu_tcid: 0x0000_0001_0000_0001,
        };
        // Complete FID5 BIU from the 2026-11-02 17:20:24 V5R4 trace.
        let unbind: Vec<u8> = concat!(
            "5d00000018ca5a3abb99b9786b8000320f08350018",
            "601318ca5a3abb99b9780ae2d5e4e2d5e44be2e5c3",
            "351408350018ec01310be2d6d3d5c5e34be2d5c1c200",
        )
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
        assert_eq!(
            session.ingest(
                scope,
                RtpObservation {
                    generation,
                    tcid: scope.slu_tcid,
                },
                &unbind,
            ),
            Err(CpInitiatorError::BindRejected { sense: 0x0835_0018 })
        );
        assert_eq!(session.phase(), CpInitiatorPhase::AwaitBindResponse);
    }
}
