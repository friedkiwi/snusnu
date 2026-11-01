//! Read-only evidence from an HPR negotiation-proceeding XID3.
//!
//! RFC 2353 §2.5 requires TG and HPR capability negotiation before EE
//! SETMODE. A LAN XID and an EE XID describe different local links; simply
//! relaying either XID across the other medium does not create a negotiated
//! TG. This module records selected, validated control fields for diagnostics.
//! It neither synthesizes XIDs nor authorizes link activation.

use crate::{
    hpr_lan::{advertised_hpr_sap, HprMedium, NegotiationError},
    xid3::{ExchangeState, Role, Xid3, XidError},
};

const FIXED_BYTES: usize = 29;
const TG_DESCRIPTOR: u8 = 0x46;
const HPR_CAPABILITIES: u8 = 0x61;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    InvalidXid(XidError),
    NotNegotiationProceeding,
    InvalidHprSap(NegotiationError),
    ShortBtu,
    MissingCapabilities,
    DuplicateTgDescriptor,
}

/// Metadata only. No user PIU or XID vector body is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HprXidEvidence {
    pub medium: HprMedium,
    pub cp_name: String,
    pub node_id: [u8; 4],
    pub role: Role,
    pub tg_number: u8,
    pub max_receive_btu: u16,
    pub advertised_sap: u8,
    /// Presence of CV46, whose TG Identifier subfield is required by RFC 2353
    /// for initiating an EE regular TG. Presence alone does not validate it.
    pub has_tg_descriptor: bool,
    /// The two-byte CV61 HPR capability prefix, kept opaque. The observed
    /// V5R4 LAN/EE profiles differ here; byte-level rewriting is unsupported.
    pub hpr_capability_prefix: [u8; 2],
    /// Fixed XID byte 12, kept opaque because activation-completion semantics
    /// require full peer negotiation, not an equality test on this byte.
    pub negotiation_byte: u8,
}

impl HprXidEvidence {
    pub fn parse(bytes: &[u8], medium: HprMedium) -> Result<Self, EvidenceError> {
        let xid = Xid3::decode(bytes).map_err(EvidenceError::InvalidXid)?;
        if xid.exchange_state() != ExchangeState::NegotiationProceeding {
            return Err(EvidenceError::NotNegotiationProceeding);
        }
        let cp_name = xid.cp_name().map_err(EvidenceError::InvalidXid)?;
        let role = xid.role().map_err(EvidenceError::InvalidXid)?;
        let max_receive_btu = xid.max_receive_btu();
        // IBM HPR XID negotiation rejects an adjacent HPR node advertising
        // a maximum BTU below 768 bytes (sense 10160022).
        if max_receive_btu < 768 {
            return Err(EvidenceError::ShortBtu);
        }
        let advertised_sap =
            advertised_hpr_sap(bytes, medium).map_err(EvidenceError::InvalidHprSap)?;
        let mut cursor = FIXED_BYTES;
        let mut tg_descriptor = false;
        let mut capability_prefix = None;
        while cursor < bytes.len() {
            // Xid3::decode has already checked complete CV bounds.
            let key = bytes[cursor];
            let len = bytes[cursor + 1] as usize;
            let data = &bytes[cursor + 2..cursor + 2 + len];
            if key == TG_DESCRIPTOR && std::mem::replace(&mut tg_descriptor, true) {
                return Err(EvidenceError::DuplicateTgDescriptor);
            }
            if key == HPR_CAPABILITIES {
                capability_prefix = data.get(..2).map(|pair| [pair[0], pair[1]]);
            }
            cursor += 2 + len;
        }
        let hpr_capability_prefix = capability_prefix.ok_or(EvidenceError::MissingCapabilities)?;
        Ok(Self {
            medium,
            cp_name,
            node_id: xid.node_id(),
            role,
            tg_number: bytes[16],
            max_receive_btu,
            advertised_sap,
            has_tg_descriptor: tg_descriptor,
            hpr_capability_prefix,
            negotiation_byte: bytes[12],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xid3::ControlVector;

    const LAN_CV61: [u8; 31] = [
        0xb8, 0x00, 0x02, 0x80, 0x04, 0x03, 0x80, 0xc8, 0x17, 0x81, 0x00, 0x00, 0x00, 0x00, 0xea,
        0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x02, 0xa4, 0x00, 0x02, 0xa4,
        0x00,
    ];
    const EE_CV61: [u8; 31] = [
        0xf8, 0x00, 0x02, 0x80, 0x02, 0x03, 0x80, 0x04, 0x17, 0x81, 0x05, 0xb5, 0x00, 0x00, 0xea,
        0x60, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x02, 0xa4, 0x00, 0x02, 0xa4,
        0x00,
    ];

    fn control_fixture(medium: HprMedium) -> Vec<u8> {
        // CV61 and CV46 are copied from direct V5R4 *control* captures. The
        // remaining XID fields/CP name are synthetic; no application data or
        // raw pcap is stored here.
        let (btu, cv61, byte12, cp_suffix) = match medium {
            HprMedium::Lan => (1496, LAN_CV61.to_vec(), 0, 0xc1),
            HprMedium::EnterpriseExtender => (1461, EE_CV61.to_vec(), 0x80, 0xc2),
        };
        let mut fixed = [0u8; FIXED_BYTES];
        fixed[9] = 0x04;
        fixed[12] = byte12;
        fixed[16] = 1;
        fixed[19] = 0x10;
        fixed[21..23].copy_from_slice(&(btu as u16).to_be_bytes());
        fixed[27] = 7;
        let mut cp = vec![
            0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1,
        ];
        cp.push(cp_suffix);
        let mut vectors = vec![
            ControlVector {
                key: 0x0e,
                data: cp,
            },
            ControlVector {
                key: HPR_CAPABILITIES,
                data: cv61,
            },
        ];
        if medium == HprMedium::EnterpriseExtender {
            vectors.push(ControlVector {
                key: TG_DESCRIPTOR,
                data: vec![0x05, 0x80, 0x01, 0x00, 0x00],
            });
        }
        let xid = Xid3::from_parts(fixed, vectors).unwrap();
        xid.encode().unwrap()
    }

    #[test]
    fn records_direct_v5r4_lan_and_ee_profile_differences() {
        let lan = HprXidEvidence::parse(&control_fixture(HprMedium::Lan), HprMedium::Lan).unwrap();
        let ee = HprXidEvidence::parse(
            &control_fixture(HprMedium::EnterpriseExtender),
            HprMedium::EnterpriseExtender,
        )
        .unwrap();
        assert_eq!((lan.tg_number, ee.tg_number), (1, 1));
        assert_eq!((lan.max_receive_btu, ee.max_receive_btu), (1496, 1461));
        assert_eq!((lan.advertised_sap, ee.advertised_sap), (0xc8, 0x04));
        assert_eq!((lan.has_tg_descriptor, ee.has_tg_descriptor), (false, true));
        assert_eq!(lan.hpr_capability_prefix, [0xb8, 0]);
        assert_eq!(ee.hpr_capability_prefix, [0xf8, 0]);
        assert_eq!((lan.negotiation_byte, ee.negotiation_byte), (0, 0x80));
    }

    #[test]
    fn rejects_incomplete_or_contradictory_control_evidence() {
        let mut short = control_fixture(HprMedium::Lan);
        short[21..23].copy_from_slice(&767u16.to_be_bytes());
        assert_eq!(
            HprXidEvidence::parse(&short, HprMedium::Lan),
            Err(EvidenceError::ShortBtu)
        );
        let mut preneg = control_fixture(HprMedium::Lan);
        preneg[9] = 0x08;
        assert_eq!(
            HprXidEvidence::parse(&preneg, HprMedium::Lan),
            Err(EvidenceError::NotNegotiationProceeding)
        );
        let mut duplicate = control_fixture(HprMedium::EnterpriseExtender);
        duplicate.extend_from_slice(&[TG_DESCRIPTOR, 0]);
        duplicate[1] = duplicate.len() as u8;
        assert_eq!(
            HprXidEvidence::parse(&duplicate, HprMedium::EnterpriseExtender),
            Err(EvidenceError::DuplicateTgDescriptor)
        );
    }
}
