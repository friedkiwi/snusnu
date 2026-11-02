//! Evidence tracking for one HPR XID3 link leg.
//!
//! RFC 2353 §2.5.1 requires a regular EE TG initiator to identify its TG in
//! a prenegotiation CV46/CV80. Section 2.5.3 requires enhanced XID negotiation
//! for EE: fixed byte 12 bit 0 signals support, and a secondary sets bit 1
//! when it considers role and TG negotiation complete. This tracker enforces
//! only those observable facts and peer identity continuity. An agreed result
//! is not sufficient to arm SETMODE: LDLC, all CV61 capability bits, and APPN
//! topology remain outside this module. The router currently lacks RTP,
//! control flows over RTP, and APPN network-control-layer behavior, so it
//! cannot truthfully emit an EE CV61 sender profile or activate this route.

use crate::{
    hpr_lan::HprMedium,
    hpr_xid_evidence::{EvidenceError, HprXidEvidence},
    xid3::{ControlVector, ExchangeState, Role, Xid3, XidError},
};

const FIXED_BYTES: usize = 29;
const TG_DESCRIPTOR: u8 = 0x46;
const TG_IDENTIFIER: u8 = 0x80;
const ENHANCED_SUPPORTED: u8 = 0x80;
const NEGOTIATION_COMPLETE: u8 = 0x40;

/// Encode the CV46/CV80 TG Identifier for a locally configured regular EE
/// TG. GA27-3136 defines zero-length partner CP name and cleared link flags;
/// the direct V5R4 EE prenegotiation capture uses exactly this five-byte
/// subfield. The caller must insert this in its *own* prenegotiation XID3.
/// This does not claim HPR, RTP, control-flow, or LDLC support.
pub fn local_ee_tg_descriptor(tg_number: u8) -> ControlVector {
    ControlVector {
        key: TG_DESCRIPTOR,
        data: vec![5, TG_IDENTIFIER, tg_number, 0, 0],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegError {
    InvalidXid(XidError),
    WrongExchangeState,
    InvalidHprEvidence(EvidenceError),
    MissingPrenegotiation,
    MissingTgIdentifier,
    InvalidTgIdentifier,
    DuplicateTgIdentifier,
    TgMismatch,
    IdentityChanged,
    SameCp,
    RolesNotComplementary,
    EnhancedNegotiationUnsupported,
    SecondaryNotComplete,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Prenegotiation {
    cp_name: String,
    node_id: [u8; 4],
    tg_number: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegAgreement {
    pub local: HprXidEvidence,
    pub remote: HprXidEvidence,
    pub max_btu: u16,
}

/// One LAN or EE leg, never a bridge between the two.
#[derive(Clone, Debug)]
pub struct HprXidLeg {
    medium: HprMedium,
    initiator: Side,
    local_pre: Option<Prenegotiation>,
    remote_pre: Option<Prenegotiation>,
    local_np: Option<HprXidEvidence>,
    remote_np: Option<HprXidEvidence>,
}

impl HprXidLeg {
    pub fn new(medium: HprMedium, initiator: Side) -> Self {
        Self {
            medium,
            initiator,
            local_pre: None,
            remote_pre: None,
            local_np: None,
            remote_np: None,
        }
    }

    pub fn observe_prenegotiation(&mut self, side: Side, bytes: &[u8]) -> Result<(), LegError> {
        let xid = Xid3::decode(bytes).map_err(LegError::InvalidXid)?;
        if xid.exchange_state() != ExchangeState::Prenegotiation {
            return Err(LegError::WrongExchangeState);
        }
        let tg_number = bytes[16];
        let identifier = tg_identifier(bytes)?;
        if self.medium == HprMedium::EnterpriseExtender
            && side == self.initiator
            && identifier.is_none()
        {
            return Err(LegError::MissingTgIdentifier);
        }
        // OS/400 sends zero in the prenegotiation CV46 while its fixed TG
        // field already contains the proposed number. The CV46 number is
        // assigned during negotiation and must then agree with that field.
        if identifier.is_some_and(|number| number != 0 && number != tg_number) {
            return Err(LegError::TgMismatch);
        }
        let pre = Prenegotiation {
            cp_name: xid.cp_name().map_err(LegError::InvalidXid)?,
            node_id: xid.node_id(),
            tg_number,
        };
        let (slot, np) = match side {
            Side::Local => (&mut self.local_pre, &mut self.local_np),
            Side::Remote => (&mut self.remote_pre, &mut self.remote_np),
        };
        if let Some(previous) = slot {
            if *previous != pre {
                return Err(LegError::IdentityChanged);
            }
        }
        *slot = Some(pre);
        *np = None;
        Ok(())
    }

    pub fn observe_negotiation(&mut self, side: Side, bytes: &[u8]) -> Result<(), LegError> {
        let evidence =
            HprXidEvidence::parse(bytes, self.medium).map_err(LegError::InvalidHprEvidence)?;
        let (pre, slot) = match side {
            Side::Local => (&self.local_pre, &mut self.local_np),
            Side::Remote => (&self.remote_pre, &mut self.remote_np),
        };
        let pre = pre.as_ref().ok_or(LegError::MissingPrenegotiation)?;
        // An EE peer can leave the node-identification field zero during
        // prenegotiation and assign its FFF/000-block identifier in NP. The
        // direct V5R4 capture does this. Once NP has supplied an identifier,
        // later NP retries may not switch it to a different value.
        if evidence.cp_name != pre.cp_name
            || (pre.node_id != [0; 4] && evidence.node_id != pre.node_id)
            || slot.as_ref().is_some_and(|previous| {
                previous.node_id != [0; 4] && evidence.node_id != previous.node_id
            })
        {
            return Err(LegError::IdentityChanged);
        }
        if evidence.tg_number != pre.tg_number {
            return Err(LegError::TgMismatch);
        }
        if tg_identifier(bytes)?.is_some_and(|number| number != evidence.tg_number) {
            return Err(LegError::TgMismatch);
        }
        *slot = Some(evidence);
        Ok(())
    }

    /// Returns only XID-level agreement. The caller must not use this result
    /// to call `SetModeBridge::arm()` without separately validated link and
    /// APPN/HPR activation semantics.
    pub fn xid_agreement(&self) -> Result<LegAgreement, LegError> {
        let (Some(local), Some(remote)) = (&self.local_np, &self.remote_np) else {
            return Err(LegError::Incomplete);
        };
        if local.cp_name == remote.cp_name {
            return Err(LegError::SameCp);
        }
        if local.tg_number != remote.tg_number {
            return Err(LegError::TgMismatch);
        }
        if !matches!(
            (local.role, remote.role),
            (Role::Primary, Role::Secondary) | (Role::Secondary, Role::Primary)
        ) {
            return Err(LegError::RolesNotComplementary);
        }
        if self.medium == HprMedium::EnterpriseExtender {
            if local.negotiation_byte & ENHANCED_SUPPORTED == 0
                || remote.negotiation_byte & ENHANCED_SUPPORTED == 0
            {
                return Err(LegError::EnhancedNegotiationUnsupported);
            }
            let secondary = if local.role == Role::Secondary {
                local
            } else {
                remote
            };
            if secondary.negotiation_byte & NEGOTIATION_COMPLETE == 0 {
                return Err(LegError::SecondaryNotComplete);
            }
        }
        Ok(LegAgreement {
            local: local.clone(),
            remote: remote.clone(),
            max_btu: local.max_receive_btu.min(remote.max_receive_btu),
        })
    }
}

fn tg_identifier(bytes: &[u8]) -> Result<Option<u8>, LegError> {
    let mut cursor = FIXED_BYTES;
    let mut result = None;
    while cursor < bytes.len() {
        // Xid3::decode has already checked top-level vector bounds.
        let key = bytes[cursor];
        let len = bytes[cursor + 1] as usize;
        let data = &bytes[cursor + 2..cursor + 2 + len];
        if key == TG_DESCRIPTOR {
            let mut sub = 0;
            while sub < data.len() {
                let header = data
                    .get(sub..sub + 2)
                    .ok_or(LegError::InvalidTgIdentifier)?;
                let sub_len = header[0] as usize;
                let end = sub
                    .checked_add(sub_len)
                    .ok_or(LegError::InvalidTgIdentifier)?;
                if sub_len < 2 || end > data.len() {
                    return Err(LegError::InvalidTgIdentifier);
                }
                if header[1] == TG_IDENTIFIER {
                    // GA27-3136: length, key, TG number, partner CP-name
                    // length, partner CP-name, and final indicators byte.
                    if sub_len < 5 || sub_len != 5 + data[sub + 3] as usize {
                        return Err(LegError::InvalidTgIdentifier);
                    }
                    if result.replace(data[sub + 2]).is_some() {
                        return Err(LegError::DuplicateTgIdentifier);
                    }
                }
                sub = end;
            }
        }
        cursor += 2 + len;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xid3::ControlVector;

    fn fixture(medium: HprMedium, side: Side, np: bool, complete: bool) -> Vec<u8> {
        // The CV46 subfield and medium-specific CV61 prefixes/SAPs come from
        // direct V5R4 control captures. CP/node fields are synthetic.
        let mut fixed = [0u8; FIXED_BYTES];
        fixed[9] = if np { 0x04 } else { 0x08 };
        fixed[12] = if medium == HprMedium::EnterpriseExtender {
            0x80 | if complete { 0x40 } else { 0 }
        } else {
            0
        };
        fixed[16] = 1;
        fixed[19] = if side == Side::Local { 0x10 } else { 0 };
        fixed[21..23].copy_from_slice(
            &if medium == HprMedium::Lan {
                1496u16
            } else {
                1461u16
            }
            .to_be_bytes(),
        );
        fixed[27] = 7;
        fixed[2..6].copy_from_slice(&if side == Side::Local {
            [0xff, 0xf0, 0, 1]
        } else {
            [0xff, 0xf0, 0, 2]
        });
        let mut name = vec![
            0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1,
        ];
        name.push(if side == Side::Local { 0xc1 } else { 0xc2 });
        let mut vectors = vec![ControlVector {
            key: 0x0e,
            data: name,
        }];
        if medium == HprMedium::EnterpriseExtender {
            vectors.push(local_ee_tg_descriptor(1));
        }
        if np {
            vectors.push(ControlVector {
                key: 0x61,
                data: if medium == HprMedium::Lan {
                    vec![0xb8, 0, 2, 0x80, 4, 3, 0x80, 0xc8]
                } else {
                    vec![0xf8, 0, 2, 0x80, 2, 3, 0x80, 4]
                },
            });
        }
        Xid3::from_parts(fixed, vectors).unwrap().encode().unwrap()
    }

    #[test]
    fn ee_leg_requires_initiator_tg_and_secondary_completion() {
        let medium = HprMedium::EnterpriseExtender;
        let mut leg = HprXidLeg::new(medium, Side::Local);
        assert_eq!(leg.xid_agreement(), Err(LegError::Incomplete));
        for side in [Side::Local, Side::Remote] {
            leg.observe_prenegotiation(side, &fixture(medium, side, false, false))
                .unwrap();
            leg.observe_negotiation(side, &fixture(medium, side, true, false))
                .unwrap();
        }
        assert_eq!(leg.xid_agreement(), Err(LegError::SecondaryNotComplete));
        leg.observe_negotiation(Side::Remote, &fixture(medium, Side::Remote, true, true))
            .unwrap();
        let agreement = leg.xid_agreement().unwrap();
        assert_eq!(agreement.max_btu, 1461);
        assert_eq!(agreement.local.advertised_sap, 4);
    }

    #[test]
    fn lan_leg_accepts_legacy_completion_evidence_without_ee_bit() {
        let medium = HprMedium::Lan;
        let mut leg = HprXidLeg::new(medium, Side::Local);
        for side in [Side::Local, Side::Remote] {
            leg.observe_prenegotiation(side, &fixture(medium, side, false, false))
                .unwrap();
            leg.observe_negotiation(side, &fixture(medium, side, true, false))
                .unwrap();
        }
        assert_eq!(leg.xid_agreement().unwrap().max_btu, 1496);
    }

    #[test]
    fn rejects_missing_or_mismatched_ee_tg_identifier() {
        let medium = HprMedium::EnterpriseExtender;
        let mut leg = HprXidLeg::new(medium, Side::Local);
        let mut no_tg = fixture(medium, Side::Local, false, false);
        no_tg.truncate(no_tg.len() - 7);
        no_tg[1] = no_tg.len() as u8;
        assert_eq!(
            leg.observe_prenegotiation(Side::Local, &no_tg),
            Err(LegError::MissingTgIdentifier)
        );
        let mut mismatch = fixture(medium, Side::Local, false, false);
        mismatch[16] = 2;
        assert_eq!(
            leg.observe_prenegotiation(Side::Local, &mismatch),
            Err(LegError::TgMismatch)
        );
    }

    #[test]
    fn own_ee_tg_descriptor_matches_captured_regular_tg_encoding() {
        assert_eq!(local_ee_tg_descriptor(1).key, 0x46);
        assert_eq!(local_ee_tg_descriptor(1).data, [5, 0x80, 1, 0, 0]);
        let fixture = fixture(HprMedium::EnterpriseExtender, Side::Local, false, false);
        assert_eq!(tg_identifier(&fixture), Ok(Some(1)));
    }

    #[test]
    fn ee_zero_prenegotiation_id_can_be_assigned_once_in_np() {
        let medium = HprMedium::EnterpriseExtender;
        let mut leg = HprXidLeg::new(medium, Side::Local);
        leg.observe_prenegotiation(Side::Local, &fixture(medium, Side::Local, false, false))
            .unwrap();
        let mut remote_pre = fixture(medium, Side::Remote, false, false);
        remote_pre[2..6].fill(0);
        // Preserved V5R4 EE trace: CV46 proposes TG zero here, then sends
        // the assigned TG one in the negotiation-proceeding XID.
        let descriptor = remote_pre
            .windows(7)
            .position(|bytes| bytes == [0x46, 5, 5, 0x80, 1, 0, 0])
            .unwrap();
        remote_pre[descriptor + 4] = 0;
        leg.observe_prenegotiation(Side::Remote, &remote_pre)
            .unwrap();
        leg.observe_negotiation(Side::Local, &fixture(medium, Side::Local, true, false))
            .unwrap();
        let mut remote_np = fixture(medium, Side::Remote, true, true);
        remote_np[2..6].copy_from_slice(&[0xff, 0xf6, 0x01, 0x00]);
        leg.observe_negotiation(Side::Remote, &remote_np).unwrap();
        assert_eq!(
            leg.xid_agreement().unwrap().remote.node_id,
            [0xff, 0xf6, 1, 0]
        );

        let descriptor = remote_np
            .windows(7)
            .position(|bytes| bytes == [0x46, 5, 5, 0x80, 1, 0, 0])
            .unwrap();
        remote_np[descriptor + 4] = 0;
        assert_eq!(
            leg.observe_negotiation(Side::Remote, &remote_np),
            Err(LegError::TgMismatch)
        );
        remote_np[descriptor + 4] = 1;

        remote_np[2..6].copy_from_slice(&[0xff, 0xf6, 0x01, 0x01]);
        assert_eq!(
            leg.observe_negotiation(Side::Remote, &remote_np),
            Err(LegError::IdentityChanged)
        );
        assert_eq!(
            leg.xid_agreement().unwrap().remote.node_id,
            [0xff, 0xf6, 1, 0]
        );
    }
}
