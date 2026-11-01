//! Bounded SNA format-3 XID information fields for a Type 2.1 APPN node.
//!
//! IBM SC30-3422-0, chapter 2 and appendix B, defines the fixed fields and
//! control vectors. An XID3 carries a node-specific role negotiation value,
//! capabilities, and a CP name. A peer must supply its own values; copying a
//! captured peer's XID is not a valid way to create an APPN link station.

use std::{error::Error, fmt};

const FIXED_BYTES: usize = 29;
const MAX_BYTES: usize = 255;
const CV_NETWORK_NAME: u8 = 0x0e;
const CV_PRODUCT_SET_ID: u8 = 0x10;
const NAME_CP: u8 = 0xf4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XidError {
    Truncated,
    InvalidFormat,
    InvalidLength,
    InvalidControlVector,
    InvalidCpName,
    DuplicateCpName,
    UnsupportedRole,
}

impl fmt::Display for XidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid SNA XID3: {self:?}")
    }
}

impl Error for XidError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Secondary,
    Primary,
    Negotiable,
}

impl Role {
    fn bits(self) -> u8 {
        match self {
            Self::Secondary => 0x00,
            Self::Primary => 0x10,
            Self::Negotiable => 0x30,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeState {
    Unsupported,
    NegotiationProceeding,
    Prenegotiation,
    Nonactivation,
}

impl ExchangeState {
    fn bits(self) -> u8 {
        match self {
            Self::Unsupported => 0,
            Self::NegotiationProceeding => 0x04,
            Self::Prenegotiation => 0x08,
            Self::Nonactivation => 0x0c,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlVector {
    pub key: u8,
    /// Contents following the key and one-byte content length.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Xid3 {
    /// The 29-byte format-3 fixed area, including node-specific capability
    /// fields. Callers creating a peer must supply a locally defined area.
    fixed: [u8; FIXED_BYTES],
    vectors: Vec<ControlVector>,
}

impl Xid3 {
    /// Parse one complete XID3 I-field, excluding the LLC XID header.
    pub fn decode(bytes: &[u8]) -> Result<Self, XidError> {
        if bytes.len() < FIXED_BYTES {
            return Err(XidError::Truncated);
        }
        if bytes.len() > MAX_BYTES || bytes[1] as usize != bytes.len() {
            return Err(XidError::InvalidLength);
        }
        if bytes[0] != 0x32 {
            return Err(XidError::InvalidFormat);
        }
        let fixed: [u8; FIXED_BYTES] = bytes[..FIXED_BYTES].try_into().unwrap();
        let vectors = decode_vectors(&bytes[FIXED_BYTES..])?;
        let result = Self { fixed, vectors };
        result.validate()?;
        Ok(result)
    }

    /// Construct from an explicitly supplied local capability area and
    /// control vectors. This validates the wire shape and CP identity but
    /// does not perform role negotiation or assert that the capability area
    /// truthfully describes a local implementation.
    pub fn from_parts(
        mut fixed: [u8; FIXED_BYTES],
        vectors: Vec<ControlVector>,
    ) -> Result<Self, XidError> {
        fixed[0] = 0x32;
        let mut result = Self { fixed, vectors };
        result.fixed[1] = result
            .encoded_len()?
            .try_into()
            .map_err(|_| XidError::InvalidLength)?;
        result.validate()?;
        result.cp_name()?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>, XidError> {
        self.validate()?;
        let mut result = Vec::with_capacity(self.encoded_len()?);
        result.extend_from_slice(&self.fixed);
        result[1] = self
            .encoded_len()?
            .try_into()
            .map_err(|_| XidError::InvalidLength)?;
        for vector in &self.vectors {
            result.push(vector.key);
            result.push(
                vector
                    .data
                    .len()
                    .try_into()
                    .map_err(|_| XidError::InvalidLength)?,
            );
            result.extend_from_slice(&vector.data);
        }
        Ok(result)
    }

    pub fn node_id(&self) -> [u8; 4] {
        self.fixed[2..6].try_into().unwrap()
    }

    /// Set this node's own role-negotiation value. The peer's node ID must
    /// never be copied into an outgoing XID3.
    pub fn set_node_id(&mut self, id: [u8; 4]) {
        self.fixed[2..6].copy_from_slice(&id);
    }

    pub fn role(&self) -> Result<Role, XidError> {
        match self.fixed[19] & 0x30 {
            0x00 => Ok(Role::Secondary),
            0x10 => Ok(Role::Primary),
            0x30 => Ok(Role::Negotiable),
            _ => Err(XidError::UnsupportedRole),
        }
    }

    pub fn set_role(&mut self, role: Role) {
        self.fixed[19] = self.fixed[19] & !0x30 | role.bits();
    }

    pub fn abm_capable(&self) -> bool {
        self.fixed[19] & 0x40 != 0
    }

    pub fn exchange_state(&self) -> ExchangeState {
        match self.fixed[9] & 0x0c {
            0x00 => ExchangeState::Unsupported,
            0x04 => ExchangeState::NegotiationProceeding,
            0x08 => ExchangeState::Prenegotiation,
            _ => ExchangeState::Nonactivation,
        }
    }

    pub fn set_exchange_state(&mut self, state: ExchangeState) {
        self.fixed[9] = self.fixed[9] & !0x0c | state.bits();
    }

    pub fn max_receive_btu(&self) -> u16 {
        u16::from_be_bytes([self.fixed[21], self.fixed[22]])
    }

    pub fn max_iframes_before_ack(&self) -> u8 {
        self.fixed[27] & 0x7f
    }

    pub fn cp_name(&self) -> Result<String, XidError> {
        let mut found = None;
        for vector in &self.vectors {
            if vector.key == CV_NETWORK_NAME && vector.data.first() == Some(&NAME_CP) {
                if found.is_some() {
                    return Err(XidError::DuplicateCpName);
                }
                found = Some(decode_cp_name(&vector.data[1..])?);
            }
        }
        found.ok_or(XidError::InvalidCpName)
    }

    pub fn set_cp_name(&mut self, name: &str) -> Result<(), XidError> {
        let mut data = vec![NAME_CP];
        data.extend_from_slice(&encode_cp_name(name)?);
        let mut replacement = self.clone();
        let mut found = false;
        for vector in &mut replacement.vectors {
            if vector.key == CV_NETWORK_NAME && vector.data.first() == Some(&NAME_CP) {
                if found {
                    return Err(XidError::DuplicateCpName);
                }
                vector.data = data.clone();
                found = true;
            }
        }
        if !found {
            replacement.vectors.push(ControlVector {
                key: CV_NETWORK_NAME,
                data,
            });
        }
        replacement.fixed[1] = replacement
            .encoded_len()?
            .try_into()
            .map_err(|_| XidError::InvalidLength)?;
        replacement.validate()?;
        *self = replacement;
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, XidError> {
        let mut result = FIXED_BYTES;
        for vector in &self.vectors {
            if vector.data.len() > u8::MAX as usize {
                return Err(XidError::InvalidLength);
            }
            result = result
                .checked_add(2 + vector.data.len())
                .ok_or(XidError::InvalidLength)?;
        }
        if result > MAX_BYTES {
            return Err(XidError::InvalidLength);
        }
        Ok(result)
    }

    fn validate(&self) -> Result<(), XidError> {
        if self.fixed[0] != 0x32 || self.fixed[1] as usize != self.encoded_len()? {
            return Err(XidError::InvalidFormat);
        }
        self.role()?;
        if self.max_receive_btu() == 0 || self.max_iframes_before_ack() == 0 {
            return Err(XidError::InvalidFormat);
        }
        // Older adjacent nodes may omit the CP-name vector. IBM SC30-3422-0
        // requires current senders to supply it but explicitly says a
        // receiver must not treat its absence as a protocol error.
        let mut cp_names = self.vectors.iter().filter(|vector| {
            vector.key == CV_NETWORK_NAME && vector.data.first() == Some(&NAME_CP)
        });
        if let Some(vector) = cp_names.next() {
            decode_cp_name(&vector.data[1..])?;
            if cp_names.next().is_some() {
                return Err(XidError::DuplicateCpName);
            }
        }
        for vector in &self.vectors {
            if vector.key == CV_PRODUCT_SET_ID && vector.data.len() > 60 {
                return Err(XidError::InvalidControlVector);
            }
        }
        Ok(())
    }
}

fn decode_vectors(bytes: &[u8]) -> Result<Vec<ControlVector>, XidError> {
    let mut cursor = 0;
    let mut result = Vec::new();
    while cursor < bytes.len() {
        let header = bytes.get(cursor..cursor + 2).ok_or(XidError::Truncated)?;
        let length = header[1] as usize;
        let end = cursor
            .checked_add(2 + length)
            .filter(|end| *end <= bytes.len())
            .ok_or(XidError::Truncated)?;
        result.push(ControlVector {
            key: header[0],
            data: bytes[cursor + 2..end].to_vec(),
        });
        cursor = end;
    }
    Ok(result)
}

fn decode_cp_name(bytes: &[u8]) -> Result<String, XidError> {
    let mut result = String::new();
    for &byte in bytes {
        let ascii = match byte {
            0xc1..=0xc9 => b'A' + (byte - 0xc1),
            0xd1..=0xd9 => b'J' + (byte - 0xd1),
            0xe2..=0xe9 => b'S' + (byte - 0xe2),
            0xf0..=0xf9 => b'0' + (byte - 0xf0),
            0x4b => b'.',
            0x7c => b'@',
            0x7b => b'#',
            0x5b => b'$',
            _ => return Err(XidError::InvalidCpName),
        };
        result.push(ascii as char);
    }
    validate_cp_name(&result)?;
    Ok(result)
}

fn encode_cp_name(name: &str) -> Result<Vec<u8>, XidError> {
    validate_cp_name(name)?;
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                b'@' => 0x7c,
                b'#' => 0x7b,
                b'$' => 0x5b,
                _ => return Err(XidError::InvalidCpName),
            })
        })
        .collect()
}

fn validate_cp_name(name: &str) -> Result<(), XidError> {
    let Some((netid, cp)) = name.split_once('.') else {
        return Err(XidError::InvalidCpName);
    };
    if cp.contains('.')
        || netid.is_empty()
        || netid.len() > 8
        || cp.is_empty()
        || cp.len() > 8
        || !name.bytes().all(|byte| {
            byte == b'.'
                || byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'@' | b'#' | b'$')
        })
    {
        return Err(XidError::InvalidCpName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized V4R4 XID3: fixed area and CP-name vector retain wire shape;
    // product ID is a synthetic short vector, not a copied product identity.
    fn sample() -> Xid3 {
        let mut fixed = [0u8; FIXED_BYTES];
        fixed[2..6].copy_from_slice(&[0x05, 0x63, 0x39, 0x50]);
        fixed[9] = 0x08;
        fixed[19] = 0x70;
        fixed[21..23].copy_from_slice(&1496u16.to_be_bytes());
        fixed[27] = 7;
        Xid3::from_parts(
            fixed,
            vec![
                ControlVector {
                    key: CV_NETWORK_NAME,
                    data: [vec![NAME_CP], encode_cp_name("SOLNET.SNAB").unwrap()].concat(),
                },
                ControlVector {
                    key: CV_PRODUCT_SET_ID,
                    data: vec![0x11, 0x01],
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_and_extracts_peer_identity_and_role() {
        let sample = sample();
        let decoded = Xid3::decode(&sample.encode().unwrap()).unwrap();
        assert_eq!(decoded.cp_name().unwrap(), "SOLNET.SNAB");
        assert_eq!(decoded.node_id(), [0x05, 0x63, 0x39, 0x50]);
        assert_eq!(decoded.role(), Ok(Role::Negotiable));
        assert!(decoded.abm_capable());
        assert_eq!(decoded.exchange_state(), ExchangeState::Prenegotiation);
        assert_eq!(decoded.max_receive_btu(), 1496);
        assert_eq!(decoded.max_iframes_before_ack(), 7);
    }

    #[test]
    fn local_identity_mutation_changes_only_owned_fields() {
        let mut xid = sample();
        xid.set_node_id([0xff, 0xf1, 0x23, 0x45]);
        xid.set_cp_name("SOLNET.ROUTER").unwrap();
        xid.set_role(Role::Secondary);
        xid.set_exchange_state(ExchangeState::NegotiationProceeding);
        let wire = xid.encode().unwrap();
        let decoded = Xid3::decode(&wire).unwrap();
        assert_eq!(decoded.node_id(), [0xff, 0xf1, 0x23, 0x45]);
        assert_eq!(decoded.cp_name().unwrap(), "SOLNET.ROUTER");
        assert_eq!(decoded.role(), Ok(Role::Secondary));
        assert_eq!(
            decoded.exchange_state(),
            ExchangeState::NegotiationProceeding
        );
        assert_eq!(decoded.max_receive_btu(), 1496);
    }

    #[test]
    fn malformed_length_vectors_and_names_fail_closed() {
        let mut wire = sample().encode().unwrap();
        wire[1] -= 1;
        assert_eq!(Xid3::decode(&wire), Err(XidError::InvalidLength));
        let mut wire = sample().encode().unwrap();
        wire.pop();
        assert_eq!(Xid3::decode(&wire), Err(XidError::InvalidLength));
        let mut wire = sample().encode().unwrap();
        wire[FIXED_BYTES + 1] = 0xff;
        assert_eq!(Xid3::decode(&wire), Err(XidError::Truncated));
        let mut xid = sample();
        xid.vectors.push(xid.vectors[0].clone());
        xid.fixed[1] = xid.encoded_len().unwrap() as u8;
        assert_eq!(xid.encode(), Err(XidError::DuplicateCpName));
        assert!(xid.set_cp_name("lower.case").is_err());
    }

    #[test]
    fn reserved_role_is_rejected() {
        let mut wire = sample().encode().unwrap();
        wire[19] = wire[19] & !0x30 | 0x20;
        assert_eq!(Xid3::decode(&wire), Err(XidError::UnsupportedRole));
    }

    #[test]
    fn older_peer_may_omit_cp_name_but_local_sender_may_not() {
        let mut wire = sample().encode().unwrap();
        wire.drain(FIXED_BYTES..FIXED_BYTES + 14);
        wire[1] = wire.len() as u8;
        assert!(Xid3::decode(&wire).is_ok());
        assert_eq!(
            Xid3::decode(&wire).unwrap().cp_name(),
            Err(XidError::InvalidCpName)
        );
        let fixed = wire[..FIXED_BYTES].try_into().unwrap();
        assert_eq!(
            Xid3::from_parts(
                fixed,
                vec![ControlVector {
                    key: CV_PRODUCT_SET_ID,
                    data: vec![0x11, 0x01]
                }]
            ),
            Err(XidError::InvalidCpName)
        );
    }
}
