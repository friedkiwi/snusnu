//! FID5 carrier adapter for the SNASVCMG/CNOS/BIS management conversation.
//!
//! The management protocol remains in router-core. This adapter only maps its
//! reduced SNA units and directional addresses onto a verified HPR user RTP.

use std::io;

use router_core::{
    hpr_fid5::{encode_whole_biu, Fid5WholeBiu},
    native_management_initiator::{NativeManagementInitiator, Phase},
    session::{Flow, QualifiedName, SessionUnit},
};

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

pub(crate) struct HprManagementInitiator {
    protocol: NativeManagementInitiator,
    initial_sa: u64,
    peer_sa: Option<u64>,
}

impl HprManagementInitiator {
    pub(crate) fn new(
        source_cp: &QualifiedName,
        target_cp: &QualifiedName,
        initial_sa: u64,
        instance_id: [u8; 8],
        bind_token: [u8; 7],
        mode: &str,
    ) -> io::Result<Self> {
        if initial_sa & (3u64 << 62) != 1u64 << 63 || initial_sa & ((1u64 << 62) - 1) == 0 {
            return Err(invalid("HPR management initial session address invalid"));
        }
        let mut protocol = NativeManagementInitiator::new(
            &source_cp.to_string(),
            &target_cp.to_string(),
            0x2f,
            1,
            2,
            instance_id,
            bind_token,
            mode,
            8,
        )
        .map_err(|error| invalid(format!("HPR management policy: {error}")))?;
        protocol.accept_hpr_response_shape();
        protocol.allow_unilateral_bis();
        Ok(Self {
            protocol,
            initial_sa,
            peer_sa: None,
        })
    }

    pub(crate) fn phase(&self) -> Phase {
        self.protocol.phase()
    }

    pub(crate) fn complete(&self) -> bool {
        self.phase() == Phase::Complete
    }

    pub(crate) fn prepared(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(piu) = self.protocol.prepared() else {
            return Ok(None);
        };
        let sa = if self.phase() == Phase::BindPrepared {
            self.initial_sa
        } else {
            self.peer_sa
                .ok_or_else(|| invalid("HPR management peer SA missing"))?
        };
        let mut reduced = piu[4..].to_vec();
        if self.phase() == Phase::BindPrepared && reduced.get(2..5) == Some(&[0x6b, 0x85, 0]) {
            reduced[3] = 0x80;
        } else if reduced.get(2..5) == Some(&[0x83, 1, 0]) && reduced.get(5..) == Some(&[0, 0, 1]) {
            reduced.truncate(5);
        }
        let unit = SessionUnit::from_reduced(&reduced)
            .map_err(|error| invalid(format!("HPR management reduced unit: {error:?}")))?;
        let flow = if piu[0] & 1 != 0 {
            Flow::Expedited
        } else {
            Flow::Normal
        };
        encode_whole_biu(sa.to_be_bytes(), flow, &unit)
            .map(Some)
            .map_err(|error| invalid(format!("HPR management FID5 encoding: {error:?}")))
    }

    pub(crate) fn confirm_sent(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.prepared()?.as_deref() != Some(bytes) {
            return Err(invalid(
                "HPR management sent BIU differs from prepared unit",
            ));
        }
        let piu = self.protocol.prepared().unwrap().to_vec();
        self.protocol
            .mark_enqueued(&piu)
            .and_then(|_| self.protocol.acknowledge(1))
            .map_err(|error| invalid(format!("HPR management transmit: {error}")))
    }

    pub(crate) fn observe(&mut self, bytes: &[u8]) -> io::Result<()> {
        let phase = self.phase();
        let fid5 = Fid5WholeBiu::parse_complete(bytes)
            .map_err(|error| invalid(format!("HPR management peer BIU: {error:?}")))?;
        if fid5.session_address != (self.initial_sa & !(1u64 << 63)).to_be_bytes() {
            return Err(invalid("HPR management response has wrong session address"));
        }
        if phase == Phase::AwaitBindResponse && fid5.rh == [0x83, 1, 0] && fid5.ru.is_empty() {
            return Ok(());
        }
        if self.phase() == Phase::AwaitBindResponse {
            if fid5.ru.len() < 10 || fid5.ru[fid5.ru.len() - 10..fid5.ru.len() - 8] != [0x62, 8] {
                return Err(invalid("HPR management BIND response lacks assigned SA"));
            }
            let sa = u64::from_be_bytes(fid5.ru[fid5.ru.len() - 8..].try_into().unwrap());
            if sa & (3u64 << 62) != 1u64 << 63 || sa & ((1u64 << 62) - 1) == 0 {
                return Err(invalid("HPR management BIND assigned invalid SA"));
            }
            self.peer_sa = Some(sa & !(1u64 << 63));
        }
        // FID2 adaptive IPR includes a three-byte pacing RU. The HPR
        // equivalent has an empty RU; preserve the protocol transition.
        let mut piu = vec![if fid5.expedited { 0x2f } else { 0x2e }, 0, 2, 1];
        piu.extend_from_slice(&fid5.th[2..4]);
        piu.extend_from_slice(&fid5.rh);
        if matches!(phase, Phase::AwaitPeerBis | Phase::UnbindPrepared)
            && fid5.rh == [0x4b, 0xb0, 0]
        {
            piu[7] = 0xb1;
        }
        if phase == Phase::AwaitBindResponse {
            piu.extend_from_slice(&fid5.ru[..fid5.ru.len() - 10]);
        } else if fid5.rh == [0x83, 1, 0] && fid5.ru.is_empty() {
            piu.extend_from_slice(&[0, 0, 1]);
        } else {
            piu.extend_from_slice(fid5.ru);
        }
        self.protocol
            .observe(&piu)
            .map_err(|error| invalid(format!("HPR management peer unit in {phase:?}: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::{
        hpr_external_management::ExternalCpManagementResponder,
        hpr_session_address::{RtpAssociationScope, RtpObservation},
        ConnectionGeneration,
    };

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn captured_v5r4_ee_management_ipr_can_advance_to_unbind() {
        let mut initiator = HprManagementInitiator::new(
            &"QAALICE.SNAA".parse().unwrap(),
            &"QABOB.SNAB".parse().unwrap(),
            0xa000_0000_0000_0002,
            [0x18, 0xf1, 0xbe, 0xf9, 0xcd, 0x93, 0x43, 0x14],
            [0x23, 0, 0, 0, 0, 0, 2],
            "",
        )
        .unwrap();
        let bind = hex(concat!(
            "5d000000a0000000000000026b800031001307b0b0513307878686870706020000000000000094434000",
            "0cd8c1c1d3c9c3c54be2d5c1c12e000902e2d5c1e2e5c3d4c709030123000000000002",
            "0d04d8c1c1d3c9c3c54be2d5c1c10a1300b023000000000002000ad8c1c2d6c24be2d5c1c2",
            "601518f1bef9cd9343140cd8c1c1d3c9c3c54be2d5c1c12c0a04087bc3d6d5d5c5c3e3"
        ));
        assert_eq!(initiator.prepared().unwrap(), Some(bind.clone()));
        initiator.confirm_sent(&bind).unwrap();
        initiator
            .observe(&hex(concat!(
                "5d0000002000000000000002eb800031001307b0b0513300808686800006020000000000000094434000",
                "0025000902e2d5c1e2e5c3d4c70203020b05d8c1c2d6c24be2d5c1c20a1300b02627bf13fa80000000",
                "601518f1bef9cd9343140cd8c1c1d3c9c3c54be2d5c1c1620881010200f0f10001"
            )))
            .unwrap();
        let cnos = hex("5c00000101010200f0f100010b91200c0502ff0003d000000206f100191210020000000000080004000400084040404040404040");
        assert_eq!(initiator.prepared().unwrap(), Some(cnos.clone()));
        initiator.confirm_sent(&cnos).unwrap();
        let guest_ipr = hex("5d0000002000000000000002830100000001");
        initiator.observe(&guest_ipr).unwrap();
        initiator
            .observe(&hex(
                "5c0000012000000000000002039101001912100a0000000000080004000400084040404040404040",
            ))
            .unwrap();
        let cnos_ipr = hex("5d00000001010200f0f10001830100");
        assert_eq!(initiator.prepared().unwrap(), Some(cnos_ipr.clone()));
        initiator.confirm_sent(&cnos_ipr).unwrap();
        let bis = hex("5c00000201010200f0f100014b910070");
        assert_eq!(initiator.prepared().unwrap(), Some(bis.clone()));
        initiator.confirm_sent(&bis).unwrap();
        initiator.observe(&guest_ipr).unwrap();
        assert_eq!(initiator.phase(), Phase::UnbindPrepared);
        assert!(!initiator.complete());
        let unbind = initiator.prepared().unwrap().unwrap();
        assert_eq!(Fid5WholeBiu::parse_complete(&unbind).unwrap().ru[0], 0x32);
    }

    #[test]
    fn fid5_management_cnos_completes_against_hpr_responder() {
        complete_management_with_responder(false);
    }

    #[test]
    fn fid5_management_completes_when_ee_peer_omits_reciprocal_bis() {
        complete_management_with_responder(true);
    }

    fn complete_management_with_responder(omit_peer_bis: bool) {
        let generation = ConnectionGeneration::new(1).unwrap();
        let scope = RtpAssociationScope {
            generation,
            initial_plu_tcid: 1,
            subsequent_plu_tcid: 2,
            slu_tcid: 3,
        };
        let source_cp = "QAALICE.SNAA".parse().unwrap();
        let target_cp = "QABOB.SNAB".parse().unwrap();
        let mut initiator = HprManagementInitiator::new(
            &source_cp,
            &target_cp,
            0x8000_0000_0000_0001,
            [0xce, 0xc3, 0x74, 0x77, 0xb5, 0xdb, 0xed, 0x8c],
            [0x23, 0x50, 0x69, 0x47, 0xa1, 0, 0],
            "",
        )
        .unwrap();
        let mut responder =
            ExternalCpManagementResponder::new(scope, source_cp, target_cp, 0x8000_0000_0000_0002)
                .unwrap();
        for _ in 0..8 {
            let Some(request) = initiator.prepared().unwrap() else {
                break;
            };
            let observation = RtpObservation {
                generation,
                tcid: if initiator.phase() == Phase::BindPrepared {
                    scope.initial_plu_tcid
                } else {
                    scope.subsequent_plu_tcid
                },
            };
            let (next, replies) = responder.preview_ingress(observation, &request).unwrap();
            responder = next;
            initiator.confirm_sent(&request).unwrap();
            for reply in replies {
                if omit_peer_bis
                    && Fid5WholeBiu::parse_complete(&reply).unwrap().rh == [0x4b, 0xb0, 0]
                {
                    continue;
                }
                initiator.observe(&reply).unwrap();
            }
        }
        assert!(initiator.complete());
        assert!(!initiator.prepared().unwrap().is_some());
    }

    #[test]
    fn wrong_fid5_response_address_cannot_advance_management() {
        let mut initiator = HprManagementInitiator::new(
            &"QAALICE.SNAA".parse().unwrap(),
            &"QABOB.SNAB".parse().unwrap(),
            0x8000_0000_0000_0001,
            [1; 8],
            [0x23, 1, 1, 1, 1, 1, 1],
            "",
        )
        .unwrap();
        let bind = initiator.prepared().unwrap().unwrap();
        initiator.confirm_sent(&bind).unwrap();
        let mut wrong = vec![0x5d, 0, 0, 0];
        wrong.extend_from_slice(&2u64.to_be_bytes());
        wrong.extend_from_slice(&[0xeb, 0x80, 0, 0x31]);
        assert_eq!(
            initiator.observe(&wrong).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(initiator.phase(), Phase::AwaitBindResponse);
    }
}
