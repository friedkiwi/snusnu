//! A bounded responder for the first CP-CP management BIND over HPR RTP.
//!
//! The V5R4 EE peer opens a CPSVCMG RTP connection before RouteSetup. Its
//! setup payload is a complete FID5 BIND. IBM SNA Formats GA27-3136-20
//! §6-163 and §9-112 require a positive FID5 RSP(BIND) with an SLU-assigned
//! session address (CV X'62'). This module owns that exchange and rejects
//! subsequent management traffic until it is understood and implemented.

use crate::{
    fid2_bind::BindClass, fid2_session_control::request_fqpcid,
    hpr_control_bootstrap::HprControlBootstrap, hpr_fid5::Fid5WholeBiu,
    hpr_session_address::RtpObservation, session::QualifiedName, ConnectionGeneration,
};
use std::{error::Error, fmt};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const CPSVCMG: [u8; 7] = [0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
const MAX_BIND: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpManagementError {
    StaleGeneration,
    WrongConnection,
    InvalidBiu,
    InvalidBind,
    WrongIdentity,
    UnsupportedBind,
    UnexpectedUnit,
}

impl fmt::Display for CpManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HPR CP management: {self:?}")
    }
}

impl Error for CpManagementError {}

#[derive(Clone, Debug)]
struct Bound {
    origin_tcid: u64,
    bind: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CpManagementResponder {
    local: QualifiedName,
    peer: QualifiedName,
    generation: ConnectionGeneration,
    bound: Option<Bound>,
}

impl CpManagementResponder {
    pub fn new(bootstrap: HprControlBootstrap) -> Self {
        Self::for_peers(bootstrap.local.cp, bootstrap.peer.cp, bootstrap.generation)
    }

    fn for_peers(
        local: QualifiedName,
        peer: QualifiedName,
        generation: ConnectionGeneration,
    ) -> Self {
        Self {
            local,
            peer,
            generation,
            bound: None,
        }
    }

    /// A replay of the exact BIND gets the same response. Other units are
    /// rejected until a CP-CP management parser can handle them safely.
    pub fn ingest(
        &mut self,
        observation: RtpObservation,
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, CpManagementError> {
        if observation.generation != self.generation {
            return Err(CpManagementError::StaleGeneration);
        }
        if let Some(bound) = &self.bound {
            if observation.tcid != bound.origin_tcid {
                return Err(CpManagementError::WrongConnection);
            }
            return if bytes == bound.bind {
                Ok(vec![bound.response.clone()])
            } else {
                Err(CpManagementError::UnexpectedUnit)
            };
        }
        let fid5 =
            Fid5WholeBiu::parse_complete(bytes).map_err(|_| CpManagementError::InvalidBiu)?;
        let identity = fid5
            .classify_bind()
            .map_err(|_| CpManagementError::InvalidBind)?
            .ok_or(CpManagementError::InvalidBind)?;
        if identity.class
            != (BindClass::Management {
                mode: "CPSVCMG".into(),
            })
        {
            return Err(CpManagementError::InvalidBind);
        }
        if identity.plu != self.peer.to_string() || identity.slu != self.local.to_string() {
            return Err(CpManagementError::WrongIdentity);
        }
        if fid5.rh != [0x6b, 0x80, 0]
            || u64::from_be_bytes(fid5.session_address) & (ASSIGNOR | RESERVED) != ASSIGNOR
        {
            return Err(CpManagementError::UnsupportedBind);
        }
        let response = self.positive_bind(fid5)?;
        self.bound = Some(Bound {
            origin_tcid: observation.tcid,
            bind: bytes.to_vec(),
            response: response.clone(),
        });
        Ok(vec![response])
    }

    fn positive_bind(&self, fid5: Fid5WholeBiu<'_>) -> Result<Vec<u8>, CpManagementError> {
        let ru = fid5.ru;
        if ru.len() > MAX_BIND || ru.len() < 31 || ru[1] != 0 || ru[26] != 0 {
            return Err(CpManagementError::UnsupportedBind);
        }
        // Require the captured LU 6.2 management profile and one-stage
        // windows before offering adaptive pacing. The request's fixed fields
        // beyond the pacing/security bits are copied only for this profile.
        if ru[..8] != [0x31, 0, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33]
            || ru[8..16] != [7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2]
            || ru[16..23] != [0; 7]
            || ru[25] & !0x40 != 0
        {
            return Err(CpManagementError::UnsupportedBind);
        }
        let fqpcid = request_fqpcid(ru).map_err(|_| CpManagementError::UnsupportedBind)?;
        let request_sa = u64::from_be_bytes(fid5.session_address) & !(ASSIGNOR | RESERVED);
        // One CP-CP session per RTP connection. The generation prevents a
        // restarted link from reusing an address on an active generation.
        let assigned_sa = ASSIGNOR | (self.generation.get() & !(ASSIGNOR | RESERVED));
        let mut response_ru = ru[..27].to_vec();
        response_ru[8] = 0;
        response_ru[9] = 0x80;
        response_ru[12] = 0x80;
        response_ru[13] = 0;
        response_ru[23] = 0;
        response_ru[24] = 0x23;
        response_ru[25] = 0x40;
        response_ru.extend_from_slice(&[0, 0x18, 0, 8, 2]);
        response_ru.extend_from_slice(&CPSVCMG);
        response_ru.extend_from_slice(&[2, 3, 2]);
        let local = encode_name(&self.local)?;
        response_ru.push((1 + local.len()) as u8);
        response_ru.push(5);
        response_ru.extend_from_slice(&local);
        response_ru.extend_from_slice(&[0, 0]); // URC and retired LU field.
        response_ru.extend_from_slice(&fqpcid);
        response_ru.extend_from_slice(&[0x62, 8]);
        response_ru.extend_from_slice(&assigned_sa.to_be_bytes());
        // Correct user-data length after the local name is encoded.
        response_ru[28] = (response_ru.len() - 29 - 2 - fqpcid.len() - 10) as u8;
        let mut response = Vec::with_capacity(15 + response_ru.len());
        response.extend_from_slice(&[0x5d, 0]);
        response.extend_from_slice(&fid5.th[2..4]);
        response.extend_from_slice(&request_sa.to_be_bytes());
        response.extend_from_slice(&[0xeb, 0x80, 0]);
        response.extend_from_slice(&response_ru);
        Ok(response)
    }
}

fn encode_name(name: &QualifiedName) -> Result<Vec<u8>, CpManagementError> {
    name.to_string()
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'I' => Ok(0xc1 + (byte - b'A')),
            b'J'..=b'R' => Ok(0xd1 + (byte - b'J')),
            b'S'..=b'Z' => Ok(0xe2 + (byte - b'S')),
            b'0'..=b'9' => Ok(0xf0 + (byte - b'0')),
            b'.' => Ok(0x4b),
            _ => Err(CpManagementError::WrongIdentity),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpr_session_address::{Fid5AddressAssociation, RtpAssociationScope};

    fn live_shape_bind() -> Vec<u8> {
        // Sanitized V5R4 CP-CP BIND. Instance IDs and PCID are synthetic;
        // mode, fixed profile, subfield layout, and CVs match the guest.
        let mut ru = vec![
            0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0,
            0, 0, 0, 0, 0x94, 0x43, 0, 0,
        ];
        let peer = "SOLNET.SNAB".parse().unwrap();
        let local = "SNUSNU.SVC".parse().unwrap();
        let mut user = vec![0, 8, 2];
        user.extend_from_slice(&CPSVCMG);
        user.extend_from_slice(&[9, 3, 1, 1, 2, 3, 4, 5, 6, 7]);
        user.push((1 + encode_name(&peer).unwrap().len()) as u8);
        user.push(4);
        user.extend_from_slice(&encode_name(&peer).unwrap());
        user.extend_from_slice(&[10, 0x13, 0, 0xb0, 1, 2, 3, 4, 5, 6, 7]);
        ru.push(11);
        ru.extend_from_slice(&encode_name(&peer).unwrap());
        ru.push(user.len() as u8);
        ru.extend_from_slice(&user);
        ru.push(0); // URC.
        ru.push(10);
        ru.extend_from_slice(&encode_name(&local).unwrap());
        ru.extend_from_slice(&[0x60, 20, 1, 2, 3, 4, 5, 6, 7, 8, 11]);
        ru.extend_from_slice(&encode_name(&peer).unwrap());
        ru.extend_from_slice(&[0x2c, 9, 4, 7]);
        ru.extend_from_slice(&CPSVCMG);
        let mut message = vec![0x5d, 0, 0, 0];
        message.extend_from_slice(&0x8002_0100_f0f1_0001u64.to_be_bytes());
        message.extend_from_slice(&[0x6b, 0x80, 0]);
        message.extend_from_slice(&ru);
        message
    }

    #[test]
    fn responds_to_v5r4_cp_management_bind_and_replays_exactly() {
        let generation = ConnectionGeneration::new(7).unwrap();
        let mut responder = CpManagementResponder::for_peers(
            "SNUSNU.SVC".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
            generation,
        );
        let observation = RtpObservation {
            generation,
            tcid: 0x80e8_992c_8f00_0020,
        };
        let bind = live_shape_bind();
        let response = responder.ingest(observation, &bind).unwrap().pop().unwrap();
        let parsed = Fid5WholeBiu::parse_complete(&response).unwrap();
        assert_eq!(parsed.rh, [0xeb, 0x80, 0]);
        assert_eq!(parsed.sequence_number, 0);
        assert_eq!(
            parsed.session_address,
            0x0002_0100_f0f1_0001u64.to_be_bytes()
        );
        assert_eq!(parsed.ru[0], 0x31);
        assert!(parsed
            .ru
            .windows(10)
            .any(|window| window == [0x62, 8, 0x80, 0, 0, 0, 0, 0, 0, 7]));
        let mut association = Fid5AddressAssociation::new(RtpAssociationScope {
            generation,
            initial_plu_tcid: observation.tcid,
            subsequent_plu_tcid: observation.tcid & !ASSIGNOR,
            slu_tcid: observation.tcid & !ASSIGNOR,
        });
        association
            .observe_bind_request(observation, Fid5WholeBiu::parse_complete(&bind).unwrap())
            .unwrap();
        association
            .observe_bind_response(
                RtpObservation {
                    tcid: observation.tcid & !ASSIGNOR,
                    ..observation
                },
                parsed,
            )
            .unwrap();
        assert_eq!(
            responder.ingest(observation, &bind).unwrap(),
            vec![response]
        );
        assert_eq!(
            responder.ingest(
                RtpObservation {
                    tcid: observation.tcid + 1,
                    ..observation
                },
                &bind
            ),
            Err(CpManagementError::WrongConnection)
        );
    }
}
