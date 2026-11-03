//! Route-scoped SNASVCMG proxy for an EE end node reaching a verified local CP.
//!
//! This is separate from the CPSVCMG CP-CP RTP topic and from application
//! sessions. The caller proves the target CP through the live local carrier,
//! binds this state to one authorized user RTP scope, and commits a preview
//! only after every returned BIU has been accepted by that RTP egress.

use crate::{
    appn_control::ControlResponder,
    fid2_bind::BindClass,
    fid2_session_control::{ManagementBind, ManagementPacing},
    hpr_fid5::Fid5WholeBiu,
    hpr_session_address::{RtpAssociationScope, RtpObservation},
    session::QualifiedName,
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const MAX_BIU: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalManagementError {
    InvalidScope,
    WrongConnection,
    WrongIdentity,
    InvalidBind,
    InvalidControl,
    UnexpectedUnit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalManagementPhase {
    AwaitBind,
    AwaitCnos,
    CnosComplete,
    BisComplete,
}

#[derive(Clone, Debug)]
pub struct ExternalCpManagementResponder {
    scope: RtpAssociationScope,
    peer_cp: QualifiedName,
    target_cp: QualifiedName,
    assigned_sa: u64,
    request_sa: Option<u64>,
    phase: ExternalManagementPhase,
    bind_request: Option<Vec<u8>>,
    bind_response: Option<Vec<u8>>,
    cnos_request: Option<Vec<u8>>,
    cnos_replies: Option<Vec<Vec<u8>>>,
    bis_request: Option<Vec<u8>>,
    bis_replies: Option<Vec<Vec<u8>>>,
}

impl ExternalCpManagementResponder {
    pub fn new(
        scope: RtpAssociationScope,
        peer_cp: QualifiedName,
        target_cp: QualifiedName,
        assigned_sa: u64,
    ) -> Result<Self, ExternalManagementError> {
        if peer_cp == target_cp
            || assigned_sa & ASSIGNOR == 0
            || assigned_sa & RESERVED != 0
            || assigned_sa & !ASSIGNOR == 0
        {
            return Err(ExternalManagementError::InvalidScope);
        }
        Ok(Self {
            scope,
            peer_cp,
            target_cp,
            assigned_sa,
            request_sa: None,
            phase: ExternalManagementPhase::AwaitBind,
            bind_request: None,
            bind_response: None,
            cnos_request: None,
            cnos_replies: None,
            bis_request: None,
            bis_replies: None,
        })
    }

    pub fn phase(&self) -> ExternalManagementPhase {
        self.phase
    }

    pub fn ready(&self) -> bool {
        self.phase == ExternalManagementPhase::BisComplete
    }

    pub fn scope(&self) -> RtpAssociationScope {
        self.scope
    }

    /// Correlate a complete BIU with this route and directional session
    /// address before dispatch. An initial BIND uses the PLU-assigned SA;
    /// later BIUs use the SLU-assigned SA with its assignor bit cleared.
    pub fn owns(&self, observation: RtpObservation, bytes: &[u8]) -> bool {
        if observation.generation != self.scope.generation {
            return false;
        }
        let Ok(fid5) = Fid5WholeBiu::parse_complete(bytes) else {
            return false;
        };
        match self.phase {
            ExternalManagementPhase::AwaitBind => {
                observation.tcid == self.scope.initial_plu_tcid
                    && u64::from_be_bytes(fid5.session_address) & ASSIGNOR != 0
                    && fid5.classify_bind().ok().flatten().is_some_and(|identity| {
                        identity.class
                            == (BindClass::Management {
                                mode: "SNASVCMG".into(),
                            })
                            && identity.plu == self.peer_cp.to_string()
                            && identity.slu == self.target_cp.to_string()
                    })
            }
            ExternalManagementPhase::AwaitCnos
            | ExternalManagementPhase::CnosComplete
            | ExternalManagementPhase::BisComplete => {
                (observation.tcid == self.scope.subsequent_plu_tcid
                    && u64::from_be_bytes(fid5.session_address) == self.assigned_sa & !ASSIGNOR)
                    || (observation.tcid == self.scope.initial_plu_tcid
                        && self.bind_request.as_deref() == Some(bytes))
            }
        }
    }

    /// Preview an ingress and its exact responses. Commit the returned state
    /// only after the caller has queued every response for this RTP scope.
    pub fn preview_ingress(
        &self,
        observation: RtpObservation,
        bytes: &[u8],
    ) -> Result<(Self, Vec<Vec<u8>>), ExternalManagementError> {
        if bytes.len() > MAX_BIU || !self.owns(observation, bytes) {
            return Err(ExternalManagementError::WrongConnection);
        }
        let mut next = self.clone();
        if self.bind_request.as_deref() == Some(bytes) {
            return Ok((next, vec![self.bind_response.clone().unwrap()]));
        }
        if self.cnos_request.as_deref() == Some(bytes) {
            return Ok((next, self.cnos_replies.clone().unwrap()));
        }
        if self.bis_request.as_deref() == Some(bytes) {
            return Ok((next, self.bis_replies.clone().unwrap()));
        }
        let fid5 = Fid5WholeBiu::parse_complete(bytes)
            .map_err(|_| ExternalManagementError::InvalidControl)?;
        match self.phase {
            ExternalManagementPhase::AwaitBind => {
                let response = self.positive_bind(fid5)?;
                next.request_sa = Some(u64::from_be_bytes(fid5.session_address) & !ASSIGNOR);
                next.bind_request = Some(bytes.to_vec());
                next.bind_response = Some(response.clone());
                next.phase = ExternalManagementPhase::AwaitCnos;
                Ok((next, vec![response]))
            }
            ExternalManagementPhase::AwaitCnos => {
                if is_ipr(fid5) {
                    return Ok((next, Vec::new()));
                }
                let replies = self.reply_cnos(fid5)?;
                next.cnos_request = Some(bytes.to_vec());
                next.cnos_replies = Some(replies.clone());
                next.phase = ExternalManagementPhase::CnosComplete;
                Ok((next, replies))
            }
            ExternalManagementPhase::CnosComplete => {
                if is_ipr(fid5) {
                    return Ok((next, Vec::new()));
                }
                let replies = self.reply_bis(fid5)?;
                next.bis_request = Some(bytes.to_vec());
                next.bis_replies = Some(replies.clone());
                next.phase = ExternalManagementPhase::BisComplete;
                Ok((next, replies))
            }
            ExternalManagementPhase::BisComplete => {
                if is_ipr(fid5) || (fid5.rh[0] & 0xe0 == 0xc0 && fid5.ru == [0x70]) {
                    Ok((next, Vec::new()))
                } else {
                    Err(ExternalManagementError::UnexpectedUnit)
                }
            }
        }
    }

    fn positive_bind(&self, fid5: Fid5WholeBiu<'_>) -> Result<Vec<u8>, ExternalManagementError> {
        if !fid5.expedited
            || fid5.rh != [0x6b, 0x80, 0]
            || u64::from_be_bytes(fid5.session_address) & (ASSIGNOR | RESERVED) != ASSIGNOR
        {
            return Err(ExternalManagementError::InvalidBind);
        }
        // Reuse the narrow, live-tested SNASVCMG BIND profile. FID2's
        // addresses here are local parsing placeholders; neither is sent on
        // HPR. The complete FID5 SA is retained in the response envelope.
        let request = as_fid2(fid5, 1, 2);
        let bind = ManagementBind::from_request(
            &request,
            &self.peer_cp.to_string(),
            &self.target_cp.to_string(),
        )
        .map_err(|_| ExternalManagementError::InvalidBind)?;
        let response = bind
            .build_v4r4_positive_response(
                &request,
                ManagementPacing::FixedOneStage {
                    local_receive_window: 1,
                },
            )
            .map_err(|_| ExternalManagementError::InvalidBind)?;
        let mut reduced = response[6..].to_vec();
        reduced.extend_from_slice(&[0x62, 8]);
        reduced.extend_from_slice(&self.assigned_sa.to_be_bytes());
        encode_fid5(
            true,
            fid5.sequence_number,
            u64::from_be_bytes(fid5.session_address) & !ASSIGNOR,
            &reduced,
        )
    }

    fn reply_cnos(&self, fid5: Fid5WholeBiu<'_>) -> Result<Vec<Vec<u8>>, ExternalManagementError> {
        if fid5.expedited || fid5.rh != [0x0b, 0x91, 0x20] {
            return Err(ExternalManagementError::InvalidControl);
        }
        let request = as_fid2(fid5, 1, 2);
        let mut responder = ControlResponder::new(String::new(), 8)
            .map_err(|_| ExternalManagementError::InvalidControl)?;
        let response = responder
            .accept_attach(&request)
            .map_err(|_| ExternalManagementError::InvalidControl)?
            .to_vec();
        responder
            .mark_reply_transmitted(&response)
            .map_err(|_| ExternalManagementError::InvalidControl)?;
        let address = self
            .request_sa
            .ok_or(ExternalManagementError::InvalidScope)?;
        let ipr = encode_fid5(true, 0, address, &[0x83, 0x01, 0])?;
        let cnos = encode_fid5(false, 1, address, &response[6..])?;
        Ok(vec![ipr, cnos])
    }

    fn reply_bis(&self, fid5: Fid5WholeBiu<'_>) -> Result<Vec<Vec<u8>>, ExternalManagementError> {
        if fid5.expedited
            || fid5.rh[0] != 0x4b
            || fid5.rh[1] & !0x01 != 0x90
            || fid5.rh[2] != 0
            || fid5.ru != [0x70]
        {
            return Err(ExternalManagementError::InvalidControl);
        }
        let address = self
            .request_sa
            .ok_or(ExternalManagementError::InvalidScope)?;
        let ipr = encode_fid5(true, 0, address, &[0x83, 0x01, 0])?;
        let bis = encode_fid5(false, 2, address, &[0x4b, 0xb0, 0, 0x70])?;
        Ok(vec![ipr, bis])
    }
}

fn is_ipr(fid5: Fid5WholeBiu<'_>) -> bool {
    fid5.expedited && fid5.rh == [0x83, 0x01, 0] && fid5.ru.is_empty()
}

fn as_fid2(fid5: Fid5WholeBiu<'_>, daf: u8, oaf: u8) -> Vec<u8> {
    let mut piu = vec![0x2c, 0, daf, oaf];
    piu.extend_from_slice(&fid5.sequence_number.to_be_bytes());
    piu.extend_from_slice(&fid5.rh);
    piu.extend_from_slice(fid5.ru);
    piu
}

fn encode_fid5(
    expedited: bool,
    sequence: u16,
    address: u64,
    reduced: &[u8],
) -> Result<Vec<u8>, ExternalManagementError> {
    if reduced.len() < 3 || address & RESERVED != 0 {
        return Err(ExternalManagementError::InvalidControl);
    }
    let mut out = Vec::with_capacity(12 + reduced.len());
    out.extend_from_slice(&[0x5c | u8::from(expedited), 0]);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&address.to_be_bytes());
    out.extend_from_slice(reduced);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionGeneration;

    fn observed_bind() -> Vec<u8> {
        // V5R4 SOLNET.SNAB -> SOLNET.SNAA, 10:02:14.651 UTC, after the
        // live RouteSetup positive reply. The PCID and instance are guest
        // values; no fabricated LU identity is substituted.
        const HEX: &str = "
            5d 00 00 00 80 02 07 00 f0 f1 00 01 6b 80 00
            31 00 13 07 b0 b0 51 33 07 87 86 86 87 07 06 02
            00 00 00 00 00 00 00 94 43 40 00
            0b e2 d6 d3 d5 c5 e3 4b e2 d5 c1 c2
            2d 00 09 02 e2 d5 c1 e2 e5 c3 d4 c7
            09 03 01 25 bf 6c 0f 61 00 00
            0c 04 e2 d6 d3 d5 c5 e3 4b e2 d5 c1 c2
            0a 13 00 b0 25 bf 6c 0f 61 00 00
            00 0b e2 d6 d3 d5 c5 e3 4b e2 d5 c1 c1
            60 14 ce c3 70 e7 b2 83 a3 31
            0b e2 d6 d3 d5 c5 e3 4b e2 d5 c1 c2
            2c 0a 04 08 7b c3 d6 d5 d5 c5 c3 e3
        ";
        HEX.split_ascii_whitespace()
            .map(|pair| u8::from_str_radix(pair, 16).unwrap())
            .collect()
    }

    fn scope() -> RtpAssociationScope {
        RtpAssociationScope {
            generation: ConnectionGeneration::new(1).unwrap(),
            initial_plu_tcid: 0x80e8_992d_2a00_0178,
            subsequent_plu_tcid: 0x0000_0001_0000_0004,
            slu_tcid: 0x0000_e899_2d1b_00f8,
        }
    }

    #[test]
    fn captured_external_snasvcmg_bind_is_scoped_and_answered() {
        let scope = scope();
        let responder = ExternalCpManagementResponder::new(
            scope,
            "SOLNET.SNAB".parse().unwrap(),
            "SOLNET.SNAA".parse().unwrap(),
            0x8000_0000_0000_0006,
        )
        .unwrap();
        let bind = observed_bind();
        assert_eq!(bind.len(), 147);
        let observed = RtpObservation {
            generation: scope.generation,
            tcid: scope.initial_plu_tcid,
        };
        assert!(responder.owns(observed, &bind));
        let (bound, responses) = responder.preview_ingress(observed, &bind).unwrap();
        assert_eq!(bound.phase(), ExternalManagementPhase::AwaitCnos);
        assert!(!bound.ready());
        assert_eq!(responses.len(), 1);
        let response = Fid5WholeBiu::parse_complete(&responses[0]).unwrap();
        assert_eq!(response.rh, [0xeb, 0x80, 0]);
        assert_eq!(response.ru[0], 0x31);
        assert!(response
            .ru
            .windows(10)
            .any(|bytes| { bytes == [0x62, 8, 0x80, 0, 0, 0, 0, 0, 0, 6] }));
        assert_eq!(bound.preview_ingress(observed, &bind).unwrap().1, responses);
        let wrong_tcid = RtpObservation {
            tcid: scope.subsequent_plu_tcid,
            ..observed
        };
        assert!(!responder.owns(wrong_tcid, &bind));
        let mut wrong_lu = bind.clone();
        let position = wrong_lu
            .windows(11)
            .position(|part| {
                part == [
                    0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc1,
                ]
            })
            .unwrap();
        wrong_lu[position + 10] = 0xc2;
        assert!(!responder.owns(observed, &wrong_lu));
    }

    #[test]
    fn cnos_and_bis_need_the_bound_directional_address() {
        let scope = scope();
        let responder = ExternalCpManagementResponder::new(
            scope,
            "SOLNET.SNAB".parse().unwrap(),
            "SOLNET.SNAA".parse().unwrap(),
            0x8000_0000_0000_0006,
        )
        .unwrap();
        let observed = RtpObservation {
            generation: scope.generation,
            tcid: scope.initial_plu_tcid,
        };
        let (bound, _) = responder
            .preview_ingress(observed, &observed_bind())
            .unwrap();
        let subsequent = RtpObservation {
            tcid: scope.subsequent_plu_tcid,
            ..observed
        };
        // Reduced FID2 control-operator Attach from the V4R4 management
        // regression, wrapped as FID5 on the independently verified V5 RTP.
        let attach = encode_fid5(
            false,
            1,
            6,
            &[
                0x0b, 0x91, 0x20, 0x0c, 0x05, 0x02, 0xff, 0, 3, 0xd0, 0, 0, 2, 0x06, 0xf1, 0, 25,
                0x12, 0x10, 2, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40,
            ],
        )
        .unwrap();
        assert!(bound.owns(subsequent, &attach));
        let (cnos, replies) = bound.preview_ingress(subsequent, &attach).unwrap();
        assert_eq!(cnos.phase(), ExternalManagementPhase::CnosComplete);
        assert!(!cnos.ready());
        assert_eq!(replies.len(), 2);
        let ipr = Fid5WholeBiu::parse_complete(&replies[0]).unwrap();
        assert_eq!(ipr.rh, [0x83, 1, 0]);
        assert_eq!(
            u64::from_be_bytes(ipr.session_address),
            0x0002_0700_f0f1_0001
        );
        let reply = Fid5WholeBiu::parse_complete(&replies[1]).unwrap();
        assert_eq!(reply.rh, [0x03, 0x91, 0x01]);
        assert_eq!(reply.session_address, ipr.session_address);
        assert_eq!(&reply.ru[..4], &[0, 25, 0x12, 0x10]);
        assert_eq!(reply.ru[4], 0x0a);
        let mut wrong_address = attach.clone();
        wrong_address[11] = 7;
        assert!(!cnos.owns(subsequent, &wrong_address));
        let bis = encode_fid5(false, 2, 6, &[0x4b, 0x91, 0, 0x70]).unwrap();
        let (ready, replies) = cnos.preview_ingress(subsequent, &bis).unwrap();
        assert!(ready.ready());
        assert_eq!(replies.len(), 2);
        assert_eq!(
            Fid5WholeBiu::parse_complete(&replies[1]).unwrap().rh,
            [0x4b, 0xb0, 0]
        );
        assert_eq!(ready.preview_ingress(subsequent, &bis).unwrap().1, replies);
    }
}
