//! A bounded responder for the first CP-CP management BIND over HPR RTP.
//!
//! The V5R4 EE peer opens a CPSVCMG RTP connection before RouteSetup. Its
//! setup payload is a complete FID5 BIND. IBM SNA Formats GA27-3136-20
//! §6-163 and §9-112 require a positive FID5 RSP(BIND) with an SLU-assigned
//! session address (CV X'62'). This module owns that exchange and rejects
//! subsequent management traffic until it is understood and implemented.

use crate::{
    fid2_bind::BindClass,
    fid2_session_control::request_fqpcid,
    hpr_control_bootstrap::HprControlBootstrap,
    hpr_fid5::Fid5WholeBiu,
    hpr_session_address::{RtpAssociationScope, RtpObservation},
    session::QualifiedName,
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
    InvalidCapabilities,
    PeerUnbind { kind: u8, sense: u32 },
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
    bind: Vec<u8>,
    response: Vec<u8>,
    request_sa: u64,
    assigned_sa: u64,
    capabilities: Option<(Vec<u8>, Vec<u8>)>,
    pacing_grant: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct CpManagementResponder {
    local: QualifiedName,
    peer: QualifiedName,
    scope: RtpAssociationScope,
    bound: Option<Bound>,
}

impl CpManagementResponder {
    pub fn new(bootstrap: HprControlBootstrap, scope: RtpAssociationScope) -> Self {
        Self::for_peers(bootstrap.local.cp, bootstrap.peer.cp, scope)
    }

    fn for_peers(local: QualifiedName, peer: QualifiedName, scope: RtpAssociationScope) -> Self {
        Self {
            local,
            peer,
            scope,
            bound: None,
        }
    }

    /// The EN has activated its CP contention-winner session once its
    /// capabilities transaction and adaptive pacing grant have been
    /// validated. The runtime also waits until our replies are transmitted
    /// before originating the reciprocal NN contention-winner BIND.
    pub fn ready_for_reciprocal(&self) -> bool {
        self.bound
            .as_ref()
            .is_some_and(|bound| bound.capabilities.is_some() && bound.pacing_grant.is_some())
    }

    /// A replay of the exact BIND or CP Capabilities Attach gets the same
    /// response. Every other management command is rejected explicitly.
    pub fn ingest(
        &mut self,
        observation: RtpObservation,
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, CpManagementError> {
        if observation.generation != self.scope.generation {
            return Err(CpManagementError::StaleGeneration);
        }
        if let Some(bound) = &mut self.bound {
            if observation.tcid == self.scope.initial_plu_tcid && bytes == bound.bind {
                return Ok(vec![bound.response.clone()]);
            }
            if observation.tcid != self.scope.subsequent_plu_tcid {
                return Err(CpManagementError::WrongConnection);
            }
            let fid5 =
                Fid5WholeBiu::parse_complete(bytes).map_err(|_| CpManagementError::InvalidBiu)?;
            if u64::from_be_bytes(fid5.session_address) != bound.assigned_sa & !ASSIGNOR {
                return Err(CpManagementError::WrongConnection);
            }
            if fid5.expedited
                && fid5.rh == [0x6b, 0x80, 0]
                && fid5.ru.len() >= 6
                && fid5.ru[0] == 0x32
                && matches!(fid5.ru[1], 0x06 | 0x0f)
            {
                return Err(CpManagementError::PeerUnbind {
                    kind: fid5.ru[1],
                    sense: u32::from_be_bytes(fid5.ru[2..6].try_into().unwrap()),
                });
            }
            if let Some((request, response)) = &bound.capabilities {
                if bytes == request {
                    return Ok(vec![response.clone()]);
                }
                if let Some(grant) = &bound.pacing_grant {
                    return if bytes == grant {
                        Ok(Vec::new())
                    } else {
                        Err(CpManagementError::UnexpectedUnit)
                    };
                }
                // The peer grants our adaptive BIND pacing window after
                // receiving the CP capabilities reply, using an expedited
                // solicited IPM (IBM SNA Formats §5-14). It is carrier
                // control, not a CP service request to answer.
                let window = u16::from_be_bytes([
                    *fid5.ru.get(1).ok_or(CpManagementError::UnexpectedUnit)?,
                    *fid5.ru.get(2).ok_or(CpManagementError::UnexpectedUnit)?,
                ]);
                if !fid5.expedited
                    || fid5.rh != [0x83, 0x01, 0]
                    || fid5.ru.len() != 3
                    || fid5.ru[0] != 0
                    || !(1..=32767).contains(&window)
                {
                    return Err(CpManagementError::UnexpectedUnit);
                }
                bound.pacing_grant = Some(bytes.to_vec());
                return Ok(Vec::new());
            }
            let reply = Self::reply_capabilities(fid5, bound.request_sa)?;
            bound.capabilities = Some((bytes.to_vec(), reply.clone()));
            return Ok(vec![reply]);
        }
        if observation.tcid != self.scope.initial_plu_tcid {
            return Err(CpManagementError::WrongConnection);
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
            bind: bytes.to_vec(),
            response: response.clone(),
            request_sa: u64::from_be_bytes(fid5.session_address) & !(ASSIGNOR | RESERVED),
            assigned_sa: ASSIGNOR | (self.scope.generation.get() & !(ASSIGNOR | RESERVED)),
            capabilities: None,
            pacing_grant: None,
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
            || ru[24] != 0x43
            || ru[25] & !0x40 != 0
        {
            return Err(CpManagementError::UnsupportedBind);
        }
        let fqpcid = request_fqpcid(ru).map_err(|_| CpManagementError::UnsupportedBind)?;
        let request_sa = u64::from_be_bytes(fid5.session_address) & !(ASSIGNOR | RESERVED);
        // One CP-CP session per RTP connection. The generation prevents a
        // restarted link from reusing an address on an active generation.
        let assigned_sa = ASSIGNOR | (self.scope.generation.get() & !(ASSIGNOR | RESERVED));
        let mut response_ru = ru[..27].to_vec();
        response_ru[8] = 0;
        response_ru[9] = 0x80;
        response_ru[12] = 0x80;
        response_ru[13] = 0;
        // The V5R4 CP's positive reciprocal BIND response echoes its request
        // security and limited-resource flags, so use the same profile here.
        // The V5R4 CP PLU BIND requests syncpoint support (X'43'). Sending
        // X'23' here causes its UNBIND type X'06' with sense X'08350018':
        // invalid BIND negotiation at this byte. Retain the CP session's
        // requested profile; no application syncpoint traffic is handled here.
        response_ru[24] = ru[24];
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

    fn reply_capabilities(
        fid5: Fid5WholeBiu<'_>,
        request_sa: u64,
    ) -> Result<Vec<u8>, CpManagementError> {
        // V5R4 REQ_CP_CAP_TP X'22F0F0F1' carries an X'12C1' GDS
        // immediately after its 17-byte basic FMH-5 Attach. The PLU gives
        // change direction (CD); this reply closes the bracket (CEB).
        const ATTACH: [u8; 17] = [
            0x11, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 4, 0x22, 0xf0, 0xf0, 0xf1, 0, 0, 0,
        ];
        if fid5.expedited
            || fid5.rh != [0x0b, 0x91, 0x20]
            || fid5.sequence_number != 1
            || fid5.ru.len() < ATTACH.len() + 12
            || fid5.ru[..ATTACH.len()] != ATTACH
        {
            return Err(CpManagementError::UnexpectedUnit);
        }
        let gds = &fid5.ru[ATTACH.len()..];
        if gds.len() > 128
            || gds.len() != usize::from(u16::from_be_bytes([gds[0], gds[1]]))
            || gds[2..4] != [0x12, 0xc1]
            || gds[8] & 0xe0 != 0x80 // End-node CP.
            || gds[9] & 0x80 == 0
            || gds[11] != 0
        {
            return Err(CpManagementError::InvalidCapabilities);
        }
        let mut cursor = 12;
        while cursor < gds.len() {
            let length = usize::from(gds[cursor]);
            if length != 6 || gds.get(cursor + 1) != Some(&0x33) || cursor + length > gds.len() {
                return Err(CpManagementError::InvalidCapabilities);
            }
            cursor += length;
        }
        // NNCP retired indicator 111, retired bit in byte 9, no optional
        // services claimed. We do not assert topology, MS, or registration
        // support before those handlers exist.
        const LOCAL_CAPABILITIES: [u8; 12] = [0, 12, 0x12, 0xc1, 0, 0, 0, 0, 0xe0, 0x80, 0, 0];
        let mut reply = Vec::with_capacity(15 + LOCAL_CAPABILITIES.len());
        reply.extend_from_slice(&[0x5c, 0]);
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&request_sa.to_be_bytes());
        reply.extend_from_slice(&[0x03, 0x91, 0x01]);
        reply.extend_from_slice(&LOCAL_CAPABILITIES);
        Ok(reply)
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
    use crate::ConnectionGeneration;

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
        let scope = RtpAssociationScope {
            generation,
            initial_plu_tcid: 0x80e8_992c_8f00_0020,
            subsequent_plu_tcid: 0x0000_0001_0000_0001,
            slu_tcid: 0x00e8_992c_8f00_0020,
        };
        let mut responder = CpManagementResponder::for_peers(
            "SNUSNU.SVC".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
            scope,
        );
        let observation = RtpObservation {
            generation,
            tcid: scope.initial_plu_tcid,
        };
        let bind = live_shape_bind();
        assert!(!responder.ready_for_reciprocal());
        let response = responder.ingest(observation, &bind).unwrap().pop().unwrap();
        assert!(!responder.ready_for_reciprocal());
        let parsed = Fid5WholeBiu::parse_complete(&response).unwrap();
        assert_eq!(parsed.rh, [0xeb, 0x80, 0]);
        assert_eq!(parsed.sequence_number, 0);
        assert_eq!(
            parsed.session_address,
            0x0002_0100_f0f1_0001u64.to_be_bytes()
        );
        assert_eq!(parsed.ru[0], 0x31);
        assert_eq!(parsed.ru[24], 0x43);
        assert!(parsed
            .ru
            .windows(10)
            .any(|window| window == [0x62, 8, 0x80, 0, 0, 0, 0, 0, 0, 7]));
        let mut association = Fid5AddressAssociation::new(scope);
        association
            .observe_bind_request(observation, Fid5WholeBiu::parse_complete(&bind).unwrap())
            .unwrap();
        association
            .observe_bind_response(
                RtpObservation {
                    tcid: scope.slu_tcid,
                    ..observation
                },
                parsed,
            )
            .unwrap();
        assert_eq!(
            responder.ingest(observation, &bind).unwrap(),
            vec![response]
        );
        let mut capabilities = vec![0x5c, 0, 0, 1];
        capabilities.extend_from_slice(&generation.get().to_be_bytes());
        capabilities.extend_from_slice(&[0x0b, 0x91, 0x20]);
        capabilities.extend_from_slice(&[
            0x11, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 4, 0x22, 0xf0, 0xf0, 0xf1, 0, 0, 0, 0, 30, 0x12,
            0xc1, 0, 0, 0, 0, 0x82, 0x84, 0, 0, 6, 0x33, 0x80, 0, 0, 0xf3, 6, 0x33, 0x80, 0, 0,
            0xf4, 6, 0x33, 0x80, 0, 0, 0xf6,
        ]);
        let continued = RtpObservation {
            tcid: scope.subsequent_plu_tcid,
            ..observation
        };
        association
            .observe_data(
                crate::hpr_session_address::Direction::PluToSlu,
                continued,
                Fid5WholeBiu::parse_complete(&capabilities).unwrap(),
            )
            .unwrap();
        let capability_reply = responder
            .ingest(continued, &capabilities)
            .unwrap()
            .pop()
            .unwrap();
        assert!(!responder.ready_for_reciprocal());
        let parsed_reply = Fid5WholeBiu::parse_complete(&capability_reply).unwrap();
        assert_eq!(
            parsed_reply.session_address,
            0x0002_0100_f0f1_0001u64.to_be_bytes()
        );
        assert_eq!(parsed_reply.rh, [3, 0x91, 1]);
        assert_eq!(
            parsed_reply.ru,
            [0, 12, 0x12, 0xc1, 0, 0, 0, 0, 0xe0, 0x80, 0, 0]
        );
        assert_eq!(
            responder.ingest(continued, &capabilities).unwrap(),
            vec![capability_reply]
        );
        let mut ipm = vec![0x5d, 0, 0, 0];
        ipm.extend_from_slice(&generation.get().to_be_bytes());
        ipm.extend_from_slice(&[0x83, 1, 0, 0, 0, 1]);
        assert!(responder.ingest(continued, &ipm).unwrap().is_empty());
        assert!(responder.ready_for_reciprocal());
        assert!(responder.ingest(continued, &ipm).unwrap().is_empty());
        let mut wrong_window = ipm.clone();
        *wrong_window.last_mut().unwrap() = 0;
        assert_eq!(
            responder.ingest(continued, &wrong_window),
            Err(CpManagementError::UnexpectedUnit)
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

    #[test]
    fn reports_live_v5r4_failed_bind_negotiation_unbind() {
        let generation = ConnectionGeneration::new(1).unwrap();
        let scope = RtpAssociationScope {
            generation,
            initial_plu_tcid: 0x80e8_992c_a900_00f0,
            subsequent_plu_tcid: 0x0000_0001_0000_0002,
            slu_tcid: 0x00e8_992c_a900_00f0,
        };
        let mut responder = CpManagementResponder::for_peers(
            "SNUSNU.SVC".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
            scope,
        );
        responder
            .ingest(
                RtpObservation {
                    generation,
                    tcid: scope.initial_plu_tcid,
                },
                &live_shape_bind(),
            )
            .unwrap();
        // Complete FID5 BIU from V5R4 at 2026-11-02 17:26:05 UTC.
        let unbind: Vec<u8> = concat!(
            "5d00000000000000000000016b8000320608350018",
            "6014cec370e7b283a27b0be2d6d3d5c5e34be2d5c1c2",
            "3513083500180c000be2d6d3d5c5e34be2d5c1c200",
        )
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
        assert_eq!(
            responder.ingest(
                RtpObservation {
                    generation,
                    tcid: scope.subsequent_plu_tcid,
                },
                &unbind,
            ),
            Err(CpManagementError::PeerUnbind {
                kind: 0x06,
                sense: 0x0835_0018,
            })
        );
    }

    #[test]
    fn echoes_v5r4_cp_bind_security_and_resource_profile() {
        let generation = ConnectionGeneration::new(1).unwrap();
        let scope = RtpAssociationScope {
            generation,
            initial_plu_tcid: 0x80e8_992c_bb00_0188,
            subsequent_plu_tcid: 0x0000_0001_0000_0006,
            slu_tcid: 0x00e8_992c_bb00_0188,
        };
        let mut responder = CpManagementResponder::for_peers(
            "SNUSNU.SVC".parse().unwrap(),
            "SOLNET.SNAB".parse().unwrap(),
            scope,
        );
        // Complete guest BIND from 2026-11-02 17:37:00 UTC. The guest later
        // terminated this session with UNBIND X'06'/X'08350018'.
        let bind: Vec<u8> = concat!(
            "5d00000080020300f0f100016b800031001307b0b05133",
            "078786868707060200000000000000944300000be2d6d3d5",
            "c5e34be2d5c1c22c000802c3d7e2e5c3d4c709030124",
            "e3340b2780000c04e2d6d3d5c5e34be2d5c1c20a1300",
            "b024e3340b278000000ae2d5e4e2d5e44be2e5c36014",
            "cec370e7b283a2880be2d6d3d5c5e34be2d5c1c22c",
            "090407c3d7e2e5c3d4c7",
        )
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
        assert_eq!(bind.len(), 144);
        let request = Fid5WholeBiu::parse_complete(&bind).unwrap();
        assert_eq!(&request.ru[23..26], &[0x94, 0x43, 0x00]);
        let reply = responder
            .ingest(
                RtpObservation {
                    generation,
                    tcid: scope.initial_plu_tcid,
                },
                &bind,
            )
            .unwrap()
            .pop()
            .unwrap();
        let response = Fid5WholeBiu::parse_complete(&reply).unwrap();
        assert_eq!(&response.ru[23..26], &request.ru[23..26]);
    }
}
