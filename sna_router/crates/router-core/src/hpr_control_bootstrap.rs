//! Validated XID3 bootstrap information for the two APPN control RTP towers.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 9-108–9-112 defines the CV61 link
//! label and X'81' CP/Route Setup NCE labels. These values let an adjacent
//! HPR node address the control towers before route setup exists. Framing
//! them does not activate a CP-CP session or authorize an RTP connection.

use crate::{
    hpr_cv61::{ControlFlowsTower, Cv61TowerError},
    session::QualifiedName,
    xid3::{ExchangeState, Xid3, XidError},
    ConnectionGeneration,
};

const CV61: u8 = 0x61;
const SAP_SUBFIELD: u8 = 0x80;
const TOWER_SUBFIELD: u8 = 0x81;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    InvalidXid(XidError),
    WrongExchangeState,
    MissingCapabilities,
    DuplicateCapabilities,
    InvalidCapabilities,
    MissingSap,
    DuplicateSap,
    MissingTower,
    DuplicateTower,
    InvalidTower(Cv61TowerError),
    InvalidIdentity,
    SameNode,
}

/// One node's negotiation-proceeding XID3 HPR control bootstrap. The peer
/// owns all decoded labels; they must never be copied into our local XID3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlAdvertisement {
    pub cp: QualifiedName,
    pub node_id: [u8; 4],
    pub hpr_sap: u8,
    pub link_label: Vec<u8>,
    pub tower: ControlFlowsTower,
}

impl ControlAdvertisement {
    pub fn from_xid3(wire: &[u8]) -> Result<Self, BootstrapError> {
        let xid = Xid3::decode(wire).map_err(BootstrapError::InvalidXid)?;
        if xid.exchange_state() != ExchangeState::NegotiationProceeding {
            return Err(BootstrapError::WrongExchangeState);
        }
        let cp = xid
            .cp_name()
            .map_err(BootstrapError::InvalidXid)?
            .parse()
            .map_err(|_| BootstrapError::InvalidIdentity)?;
        let mut cursor = 29;
        let mut cv61 = None;
        while cursor < wire.len() {
            let header = wire
                .get(cursor..cursor + 2)
                .ok_or(BootstrapError::InvalidCapabilities)?;
            let end = cursor
                .checked_add(2 + usize::from(header[1]))
                .filter(|end| *end <= wire.len())
                .ok_or(BootstrapError::InvalidCapabilities)?;
            if header[0] == CV61 && cv61.replace(&wire[cursor + 2..end]).is_some() {
                return Err(BootstrapError::DuplicateCapabilities);
            }
            cursor = end;
        }
        let data = cv61.ok_or(BootstrapError::MissingCapabilities)?;
        // EE uses LDLC with no FID2 and requires all three HPR towers:
        // RTP (1401), Control Flows Over RTP (1402), and LDLC (2006).
        if data.len() < 4 || data[0] != 0xf8 || data[1] != 0 {
            return Err(BootstrapError::InvalidCapabilities);
        }
        let label_len = usize::from(data[2]);
        if !(1..=8).contains(&label_len) || data.len() < 3 + label_len {
            return Err(BootstrapError::InvalidCapabilities);
        }
        let link_label = data[3..3 + label_len].to_vec();
        if !valid_anr_label(&link_label) {
            return Err(BootstrapError::InvalidCapabilities);
        }
        let mut cursor = 3 + label_len;
        let mut sap = None;
        let mut tower = None;
        while cursor < data.len() {
            let header = data
                .get(cursor..cursor + 2)
                .ok_or(BootstrapError::InvalidCapabilities)?;
            let length = usize::from(header[0]);
            let end = cursor
                .checked_add(length)
                .filter(|end| length >= 2 && *end <= data.len())
                .ok_or(BootstrapError::InvalidCapabilities)?;
            match header[1] {
                SAP_SUBFIELD => {
                    if sap.is_some() {
                        return Err(BootstrapError::DuplicateSap);
                    }
                    if length != 3 || data[cursor + 2] == 0 || data[cursor + 2] & 1 != 0 {
                        return Err(BootstrapError::InvalidCapabilities);
                    }
                    sap = Some(data[cursor + 2]);
                }
                TOWER_SUBFIELD => {
                    if tower.is_some() {
                        return Err(BootstrapError::DuplicateTower);
                    }
                    tower = Some(
                        ControlFlowsTower::decode(&data[cursor..end])
                            .map_err(BootstrapError::InvalidTower)?,
                    );
                }
                _ => {}
            }
            cursor = end;
        }
        Ok(Self {
            cp,
            node_id: xid.node_id(),
            hpr_sap: sap.ok_or(BootstrapError::MissingSap)?,
            link_label,
            tower: {
                let tower = tower.ok_or(BootstrapError::MissingTower)?;
                if !valid_anr_label(&tower.cp_nce_label)
                    || !valid_anr_label(&tower.route_setup_nce_label)
                {
                    return Err(BootstrapError::InvalidCapabilities);
                }
                tower
            },
        })
    }
}

fn valid_anr_label(label: &[u8]) -> bool {
    (1..=8).contains(&label.len()) && label[0] & 0x80 != 0 && !label.contains(&0xff)
}

/// Directional control labels for one active adjacency. End nodes can use a
/// network-node server in a different NETID; the caller must separately
/// prove the node roles, XID/TG agreement, and XID_DONE/TEST.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HprControlBootstrap {
    pub generation: ConnectionGeneration,
    pub local: ControlAdvertisement,
    pub peer: ControlAdvertisement,
    pub max_packet_size: u16,
}

impl HprControlBootstrap {
    pub fn new(
        generation: ConnectionGeneration,
        local: ControlAdvertisement,
        peer: ControlAdvertisement,
    ) -> Result<Self, BootstrapError> {
        if local.cp == peer.cp || local.node_id == peer.node_id {
            return Err(BootstrapError::SameNode);
        }
        let max_packet_size = local
            .tower
            .max_send_packet_size
            .min(peer.tower.max_send_packet_size);
        Ok(Self {
            generation,
            local,
            peer,
            max_packet_size,
        })
    }

    /// The adjacent peer assigned these labels for NLPs sent to its CP and
    /// Route Setup components. They are distinct from the link label.
    pub fn outbound_cp_label(&self) -> &[u8] {
        &self.peer.tower.cp_nce_label
    }

    pub fn outbound_route_setup_label(&self) -> &[u8] {
        &self.peer.tower.route_setup_nce_label
    }

    pub fn inbound_cp_label(&self) -> &[u8] {
        &self.local.tower.cp_nce_label
    }

    pub fn inbound_route_setup_label(&self) -> &[u8] {
        &self.local.tower.route_setup_nce_label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_cv61::ArbMode,
        xid3::{ControlVector, Role},
    };

    fn xid(cp_name: &[u8], node_id: [u8; 4], label: &[u8], instance: u8) -> Vec<u8> {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(&node_id);
        fixed[9] = 0x04;
        fixed[16] = 1;
        fixed[19] = 0x10;
        fixed[21..23].copy_from_slice(&1461u16.to_be_bytes());
        fixed[27] = 7;
        let tower = ControlFlowsTower {
            max_send_packet_size: 1461,
            path_switch_time_ms: 60_000,
            mobile: false,
            multilink_tg: false,
            arb_mode: ArbMode::Responsive,
            cp_nce_instance: [0, 0, 0, instance],
            route_setup_nce_instance: [0, 0, 0, instance],
            cp_nce_label: label.to_vec(),
            route_setup_nce_label: label.to_vec(),
        };
        let mut cv61 = vec![0xf8, 0, 2, 0x80, 2, 3, 0x80, 4];
        cv61.extend_from_slice(&tower.encode().unwrap());
        let mut cp = vec![0xf4];
        cp.extend_from_slice(cp_name);
        let mut xid = Xid3::from_parts(
            fixed,
            vec![
                ControlVector {
                    key: 0x0e,
                    data: cp,
                },
                ControlVector {
                    key: 0x61,
                    data: cv61,
                },
            ],
        )
        .unwrap();
        xid.set_role(Role::Primary);
        xid.encode().unwrap()
    }

    #[test]
    fn extracts_directional_control_labels_from_validated_xids() {
        let local = xid(
            b"\xe2\xd6\xd3\xd5\xc5\xe3\x4b\xe2\xd5\xc1\xc1",
            [0xff, 0xf0, 0, 1],
            &[0xa4, 1],
            1,
        );
        let peer = xid(
            b"\xe2\xd6\xd3\xd5\xc5\xe3\x4b\xe2\xd5\xc1\xc2",
            [0xff, 0xf0, 0, 2],
            &[0xa4, 2],
            2,
        );
        let local = ControlAdvertisement::from_xid3(&local).unwrap();
        let peer = ControlAdvertisement::from_xid3(&peer).unwrap();
        let bootstrap =
            HprControlBootstrap::new(ConnectionGeneration::new(1).unwrap(), local, peer).unwrap();
        assert_eq!(bootstrap.local.cp.to_string(), "SOLNET.SNAA");
        assert_eq!(bootstrap.peer.cp.to_string(), "SOLNET.SNAB");
        assert_eq!(bootstrap.outbound_cp_label(), [0xa4, 2]);
        assert_eq!(bootstrap.inbound_route_setup_label(), [0xa4, 1]);
        assert_eq!(bootstrap.max_packet_size, 1461);
    }

    #[test]
    fn requires_truthful_towers_and_distinct_nodes() {
        let local = xid(
            b"\xe2\xd6\xd3\xd5\xc5\xe3\x4b\xe2\xd5\xc1\xc1",
            [0xff, 0xf0, 0, 1],
            &[0xa4, 1],
            1,
        );
        let mut lacking_tower = local.clone();
        let end = lacking_tower.len() - 23;
        lacking_tower.truncate(end);
        lacking_tower[1] = end as u8;
        lacking_tower[29 + 14 + 1] -= 23;
        assert_eq!(
            ControlAdvertisement::from_xid3(&lacking_tower),
            Err(BootstrapError::MissingTower)
        );
        let mut without_capability = local.clone();
        let cv61 = 29 + 14 + 2;
        without_capability[cv61] &= !0x10;
        assert_eq!(
            ControlAdvertisement::from_xid3(&without_capability),
            Err(BootstrapError::InvalidCapabilities)
        );
        let mut invalid_link_label = local.clone();
        invalid_link_label[29 + 14 + 2 + 3] = 0x7f;
        assert_eq!(
            ControlAdvertisement::from_xid3(&invalid_link_label),
            Err(BootstrapError::InvalidCapabilities)
        );
        let peer = xid(
            b"\xe2\xd6\xd3\xd5\xc5\xe3\x4b\xe2\xd5\xc1\xc2",
            [0xff, 0xf0, 0, 2],
            &[0xa4, 2],
            2,
        );
        let local_ad = ControlAdvertisement::from_xid3(&local).unwrap();
        let peer_ad = ControlAdvertisement::from_xid3(&peer).unwrap();
        assert_eq!(
            HprControlBootstrap::new(
                ConnectionGeneration::new(1).unwrap(),
                local_ad.clone(),
                local_ad,
            ),
            Err(BootstrapError::SameNode)
        );
        let mut other_netid = peer_ad;
        other_netid.cp.netid = "OTHER".to_string();
        assert!(HprControlBootstrap::new(
            ConnectionGeneration::new(1).unwrap(),
            local_advertisement(&local),
            other_netid,
        )
        .is_ok());
    }

    fn local_advertisement(xid: &[u8]) -> ControlAdvertisement {
        ControlAdvertisement::from_xid3(xid).unwrap()
    }
}
