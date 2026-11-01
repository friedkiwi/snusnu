//! Locally owned XID3 for a bounded native LLC2 FID2 link station.
//!
//! IBM SC30-3422-0 appendix B defines the fixed fields and F4/F7/X10
//! vectors; GA27-3136-10 defines the nested Product Identifier X'11'. The
//! profile advertises only FID2, one DLC transmission group and ABM. It does
//! not claim network-node, CP-CP, HPR, adaptive BIND pacing, or APPN CP
//! services before those behaviors exist in the local peer.

use crate::xid3::{ControlVector, ExchangeState, Role, Xid3, XidError};

const PRODUCT_SET_ID: [u8; 12] = [
    0x00, // retired
    0x0b, 0x11, 0x0c, // X11 non-IBM software identifier
    0x08, 0x06, // X06 software common name, eight bytes including header
    0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4, // SNUSNU
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalLlcProfile {
    pub cp_name: String,
    /// This node's unqualified adjacent link-station name, not the guest's.
    pub station_name: String,
    /// Locally assigned FFF/000-block role-negotiation value; never copy a peer.
    pub node_id: [u8; 4],
    /// Local transmission-group number; match the link configured at the peer.
    pub tg_number: u8,
    /// Must match the actual native receive buffer and 802.3 MTU.
    pub max_receive_btu: u16,
    /// Must match the local LLC2 receive/ack capacity.
    pub max_iframes_before_ack: u8,
    /// Native probe supports fixed Primary or Secondary. Negotiable is rejected.
    pub role: Role,
}

impl LocalLlcProfile {
    pub fn build(&self) -> Result<Xid3, XidError> {
        let block = u16::from_be_bytes([self.node_id[0], self.node_id[1]]) >> 4;
        if !matches!(block, 0x000 | 0xfff)
            || u32::from_be_bytes(self.node_id) & 0x000f_ffff == 0
            || !(265..=1496).contains(&self.max_receive_btu)
            || !(1..=127).contains(&self.max_iframes_before_ack)
            || self.role == Role::Negotiable
        {
            return Err(XidError::InvalidFormat);
        }
        let station = encode_station_name(&self.station_name)?;
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(&self.node_id);
        fixed[8] = 0xb0; // No INIT-SELF or BIND segmentation; standalone BIND.
        fixed[9] = 0x88; // No ACTPU, prenegotiation; no CP/NN claims.
        fixed[16] = self.tg_number;
        fixed[17] = 0x01; // Conventional LLC DLC type as in V4R4 XID3.
        fixed[18] = 0x0b; // Eleven DLC-dependent fixed bytes.
        fixed[19] = 0x40; // ABM-capable; role set below.
        fixed[21..23].copy_from_slice(&self.max_receive_btu.to_be_bytes());
        fixed[27] = self.max_iframes_before_ack;
        let mut xid = Xid3::from_parts(
            fixed,
            vec![
                ControlVector {
                    key: 0x0e,
                    data: vec![0xf4, 0xc1, 0x4b, 0xc1], // replaced immediately
                },
                ControlVector {
                    key: 0x0e,
                    data: [vec![0xf7], station].concat(),
                },
                ControlVector {
                    key: 0x10,
                    data: PRODUCT_SET_ID.to_vec(),
                },
            ],
        )?;
        xid.set_cp_name(&self.cp_name)?;
        xid.set_role(self.role);
        xid.set_exchange_state(ExchangeState::Prenegotiation);
        Ok(xid)
    }
}

fn encode_station_name(name: &str) -> Result<Vec<u8>, XidError> {
    if name.is_empty() || name.len() > 8 || !name.as_bytes()[0].is_ascii_uppercase() {
        return Err(XidError::InvalidCpName);
    }
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'@' => 0x7c,
                b'#' => 0x7b,
                b'$' => 0x5b,
                _ => return Err(XidError::InvalidCpName),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> LocalLlcProfile {
        LocalLlcProfile {
            cp_name: "SOLNET.ROUTER".into(),
            station_name: "ROUTER".into(),
            node_id: [0xff, 0xf1, 0x23, 0x45],
            tg_number: 1,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: Role::Primary,
        }
    }

    #[test]
    fn sends_own_identity_and_only_supported_link_capabilities() {
        let xid = profile().build().unwrap();
        let bytes = xid.encode().unwrap();
        assert_eq!(xid.cp_name().unwrap(), "SOLNET.ROUTER");
        assert_eq!(xid.node_id(), [0xff, 0xf1, 0x23, 0x45]);
        assert_eq!(xid.role(), Ok(Role::Primary));
        assert!(xid.abm_capable());
        assert_eq!(xid.max_receive_btu(), 1496);
        assert_eq!(xid.max_iframes_before_ack(), 1);
        assert_eq!(bytes[8..10], [0xb0, 0x88]);
        assert_eq!(bytes[16..19], [0x01, 0x01, 0x0b]);
        assert!(bytes
            .windows(9)
            .any(|part| part == [0x0e, 0x07, 0xf7, 0xd9, 0xd6, 0xe4, 0xe3, 0xc5, 0xd9]));
        assert!(bytes.windows(14).any(|part| part
            == [
                0x10, 0x0c, 0x00, 0x0b, 0x11, 0x0c, 0x08, 0x06, 0xe2, 0xd5, 0xe4, 0xe2, 0xd5, 0xe4
            ]));
    }

    #[test]
    fn rejects_peer_or_invalid_local_identifiers() {
        let mut local = profile();
        local.node_id = [0x05, 0x63, 0x39, 0x50]; // IBM product block.
        assert_eq!(local.build(), Err(XidError::InvalidFormat));
        local = profile();
        local.node_id = [0xff, 0xf0, 0, 0]; // No role-negotiation value.
        assert_eq!(local.build(), Err(XidError::InvalidFormat));
        local = profile();
        local.station_name = "lower".into();
        assert_eq!(local.build(), Err(XidError::InvalidCpName));
        local = profile();
        local.max_iframes_before_ack = 0;
        assert_eq!(local.build(), Err(XidError::InvalidFormat));
        local = profile();
        local.role = Role::Negotiable;
        assert_eq!(local.build(), Err(XidError::InvalidFormat));
    }
}
