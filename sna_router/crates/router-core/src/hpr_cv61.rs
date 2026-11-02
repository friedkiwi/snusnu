//! Control Flows Over RTP Tower (X'81') subfield of HPR Capabilities CV61.
//!
//! IBM *SNA Formats* GA27-3136-20, pp. 9-108–9-112, defines this subfield.
//! It carries the bootstrap NCE identifiers and ANR labels for CP-CP and
//! route-setup RTP connections. Framing it does not implement those towers or
//! authorize advertising the corresponding CV61 capability bits in an XID3.

const CONTROL_FLOWS_TOWER_KEY: u8 = 0x81;
const FIXED_LEN: usize = 18;
const MIN_PACKET_SIZE: u16 = 768;
const MAX_LABEL_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cv61TowerError {
    Truncated,
    WrongKey,
    LengthMismatch,
    InvalidPacketSize,
    InvalidArbMode,
    ReservedBits,
    InvalidLabelLength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArbMode {
    Base,
    Responsive,
}

/// The complete X'81' subfield, including values needed for bootstrap RTP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlFlowsTower {
    /// Packet size excludes the link header and must be at least 768 bytes.
    pub max_send_packet_size: u16,
    pub path_switch_time_ms: u32,
    pub mobile: bool,
    pub multilink_tg: bool,
    pub arb_mode: ArbMode,
    pub cp_nce_instance: [u8; 4],
    pub route_setup_nce_instance: [u8; 4],
    pub cp_nce_label: Vec<u8>,
    pub route_setup_nce_label: Vec<u8>,
}

impl ControlFlowsTower {
    /// Decode one length-key subfield, including its two-byte header. The
    /// caller must first locate a unique X'81' under CV61 and verify the CV61
    /// Control Flows Over RTP capability bit and XID3 identity/role.
    pub fn decode(subfield: &[u8]) -> Result<Self, Cv61TowerError> {
        if subfield.len() < FIXED_LEN + 2 {
            return Err(Cv61TowerError::Truncated);
        }
        if subfield[1] != CONTROL_FLOWS_TOWER_KEY {
            return Err(Cv61TowerError::WrongKey);
        }
        if usize::from(subfield[0]) != subfield.len() {
            return Err(Cv61TowerError::LengthMismatch);
        }
        let max_send_packet_size = u16::from_be_bytes([subfield[2], subfield[3]]);
        if max_send_packet_size < MIN_PACKET_SIZE {
            return Err(Cv61TowerError::InvalidPacketSize);
        }
        let flags = subfield[8];
        if flags & 0x0f != 0 {
            return Err(Cv61TowerError::ReservedBits);
        }
        let arb_mode = match flags & 0x30 {
            0 => ArbMode::Base,
            0x10 => ArbMode::Responsive,
            _ => return Err(Cv61TowerError::InvalidArbMode),
        };
        let cp_len = usize::from(subfield[17]);
        if !(1..=MAX_LABEL_LEN).contains(&cp_len) {
            return Err(Cv61TowerError::InvalidLabelLength);
        }
        let route_len_pos = FIXED_LEN + cp_len;
        let route_len = usize::from(
            *subfield
                .get(route_len_pos)
                .ok_or(Cv61TowerError::Truncated)?,
        );
        if !(1..=MAX_LABEL_LEN).contains(&route_len) {
            return Err(Cv61TowerError::InvalidLabelLength);
        }
        if subfield.len() != route_len_pos + 1 + route_len {
            return Err(Cv61TowerError::LengthMismatch);
        }
        Ok(Self {
            max_send_packet_size,
            path_switch_time_ms: u32::from_be_bytes(subfield[4..8].try_into().unwrap()),
            mobile: flags & 0x80 != 0,
            multilink_tg: flags & 0x40 != 0,
            arb_mode,
            cp_nce_instance: subfield[9..13].try_into().unwrap(),
            route_setup_nce_instance: subfield[13..17].try_into().unwrap(),
            cp_nce_label: subfield[18..route_len_pos].to_vec(),
            route_setup_nce_label: subfield[route_len_pos + 1..].to_vec(),
        })
    }

    /// Encode the X'81' subfield for a caller that has implemented the
    /// advertised HPR/RTP and APPN control towers. This method does not add
    /// the CV61 capability prefix or make a local XID3 sender profile.
    pub fn encode(&self) -> Result<Vec<u8>, Cv61TowerError> {
        if self.max_send_packet_size < MIN_PACKET_SIZE {
            return Err(Cv61TowerError::InvalidPacketSize);
        }
        if !(1..=MAX_LABEL_LEN).contains(&self.cp_nce_label.len())
            || !(1..=MAX_LABEL_LEN).contains(&self.route_setup_nce_label.len())
        {
            return Err(Cv61TowerError::InvalidLabelLength);
        }
        let length = FIXED_LEN + 1 + self.cp_nce_label.len() + self.route_setup_nce_label.len();
        let mut result = Vec::with_capacity(length);
        result.push(length as u8);
        result.push(CONTROL_FLOWS_TOWER_KEY);
        result.extend_from_slice(&self.max_send_packet_size.to_be_bytes());
        result.extend_from_slice(&self.path_switch_time_ms.to_be_bytes());
        let flags = (u8::from(self.mobile) << 7)
            | (u8::from(self.multilink_tg) << 6)
            | match self.arb_mode {
                ArbMode::Base => 0,
                ArbMode::Responsive => 0x10,
            };
        result.push(flags);
        result.extend_from_slice(&self.cp_nce_instance);
        result.extend_from_slice(&self.route_setup_nce_instance);
        result.push(self.cp_nce_label.len() as u8);
        result.extend_from_slice(&self.cp_nce_label);
        result.push(self.route_setup_nce_label.len() as u8);
        result.extend_from_slice(&self.route_setup_nce_label);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V5R4_EE_TOWER: [u8; 23] = [
        0x17, 0x81, 0x05, 0xb5, 0x00, 0x00, 0xea, 0x60, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x04, 0x02, 0xa4, 0x00, 0x02, 0xa4, 0x00,
    ];

    #[test]
    fn decodes_preserved_v5r4_ee_tower_and_roundtrips() {
        let tower = ControlFlowsTower::decode(&V5R4_EE_TOWER).unwrap();
        assert_eq!(tower.max_send_packet_size, 1461);
        assert_eq!(tower.path_switch_time_ms, 60_000);
        assert_eq!(tower.arb_mode, ArbMode::Responsive);
        assert!(!tower.mobile && !tower.multilink_tg);
        assert_eq!(tower.cp_nce_instance, [0, 0, 0, 4]);
        assert_eq!(tower.route_setup_nce_instance, [0, 0, 0, 4]);
        assert_eq!(tower.cp_nce_label, [0xa4, 0]);
        assert_eq!(tower.route_setup_nce_label, [0xa4, 0]);
        assert_eq!(tower.encode().unwrap(), V5R4_EE_TOWER);
    }

    #[test]
    fn handles_one_and_eight_byte_labels_and_base_mode() {
        let mut tower = ControlFlowsTower::decode(&V5R4_EE_TOWER).unwrap();
        tower.cp_nce_label = vec![1];
        tower.route_setup_nce_label = vec![2; 8];
        tower.arb_mode = ArbMode::Base;
        tower.mobile = true;
        let encoded = tower.encode().unwrap();
        assert_eq!(encoded[0], 28);
        assert_eq!(ControlFlowsTower::decode(&encoded), Ok(tower));
    }

    #[test]
    fn rejects_length_key_flags_labels_and_packet_size() {
        let mut value = V5R4_EE_TOWER;
        value[0] = 22;
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::LengthMismatch)
        );
        value = V5R4_EE_TOWER;
        value[1] = 0x80;
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::WrongKey)
        );
        value = V5R4_EE_TOWER;
        value[2..4].copy_from_slice(&767u16.to_be_bytes());
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::InvalidPacketSize)
        );
        value = V5R4_EE_TOWER;
        value[8] |= 1;
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::ReservedBits)
        );
        value = V5R4_EE_TOWER;
        value[8] = 0x20;
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::InvalidArbMode)
        );
        value = V5R4_EE_TOWER;
        value[17] = 0;
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::InvalidLabelLength)
        );
        value = V5R4_EE_TOWER;
        value[20] = 9;
        assert_eq!(
            ControlFlowsTower::decode(&value),
            Err(Cv61TowerError::InvalidLabelLength)
        );
        assert_eq!(
            ControlFlowsTower::decode(&V5R4_EE_TOWER[..19]),
            Err(Cv61TowerError::Truncated)
        );
    }
}
