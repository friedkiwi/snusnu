//! Receive-side framing and identities for the APPN Route Setup X'12CE' GDS.
//!
//! IBM *SNA Formats* GA27-3136-20, pp. 13-67–13-71 and 9-5, specifies the
//! 16-byte fixed area and LT-encoded control vectors. A complete GDS may be
//! carried in an RTP NLP data portion or a FID2 ROUTE SETUP NC request RU.
//! The caller must isolate and, when necessary, reassemble that GDS first.
//! Parsing it does not accept a route, interpret the RSCV/ANR paths, or
//! authorize a Route Setup reply or an RTP connection.

const MAX_GDS_BYTES: usize = 4096;
const MAX_VECTORS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSetupError {
    Truncated,
    TooLarge,
    WrongKey,
    LengthMismatch,
    InvalidVector,
    TooManyVectors,
    MissingFqPcid,
    DuplicateFqPcid,
    InvalidFqPcid,
    InvalidCpName,
    MissingRequiredVector,
    InvalidReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSetupKind {
    Request,
    PositiveReply,
    NegativeReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSetupVector<'a> {
    pub key: u8,
    /// The complete LT vector, including its length and key bytes.
    pub wire: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSetupGds<'a> {
    pub kind: RouteSetupKind,
    pub path_switch: bool,
    pub destination_hop_index: u8,
    pub arb_mode: Option<u8>,
    /// Eight opaque PCID bytes and the origin CP name in the X'60' CV.
    pub pcid: [u8; 8],
    pub origin_cp_name: String,
    /// Network-qualified destination LU from X'0E' type F3 on a request.
    /// A BF-link route may omit this vector.
    pub destination_lu_name: Option<String>,
    /// Network-qualified destination CP name from X'0E' type F4 on a
    /// positive reply. The destination LU name on a request is type F3.
    pub destination_cp_name: Option<String>,
    pub vectors: Vec<RouteSetupVector<'a>>,
}

impl<'a> RouteSetupGds<'a> {
    /// Parse exactly one complete GDS, beginning with its two-byte length.
    /// This deliberately does not scan arbitrary RTP bytes for X'12CE'.
    pub fn parse(wire: &'a [u8]) -> Result<Self, RouteSetupError> {
        if wire.len() > MAX_GDS_BYTES {
            return Err(RouteSetupError::TooLarge);
        }
        if wire.len() < 16 {
            return Err(RouteSetupError::Truncated);
        }
        if wire[2..4] != [0x12, 0xce] {
            return Err(RouteSetupError::WrongKey);
        }
        if usize::from(u16::from_be_bytes([wire[0], wire[1]])) != wire.len() {
            return Err(RouteSetupError::LengthMismatch);
        }
        let reply = wire[4] & 0x80 != 0;
        let path_switch = !reply && wire[4] & 0x40 != 0;
        let mut vectors = Vec::new();
        let mut cursor = 16;
        let mut fqpcid = None;
        let mut destination_lu_name = None;
        let mut destination_cp_name = None;
        let mut has_sense = false;
        let mut route_information = 0usize;
        let mut has_route_selection = false;
        let mut has_cos = false;
        while cursor < wire.len() {
            if wire.len() - cursor < 2 {
                return Err(RouteSetupError::InvalidVector);
            }
            let length = usize::from(wire[cursor]);
            if length < 2 || length > wire.len() - cursor {
                return Err(RouteSetupError::InvalidVector);
            }
            if vectors.len() == MAX_VECTORS {
                return Err(RouteSetupError::TooManyVectors);
            }
            let vector = &wire[cursor..cursor + length];
            let key = vector[1];
            match key {
                0x60 => {
                    if fqpcid.is_some() {
                        return Err(RouteSetupError::DuplicateFqPcid);
                    }
                    fqpcid = Some(parse_fqpcid(vector)?);
                }
                0x0e if !reply && vector.get(2) == Some(&0xf3) => {
                    if destination_lu_name.is_some() {
                        return Err(RouteSetupError::InvalidVector);
                    }
                    destination_lu_name = Some(decode_qualified_name(&vector[3..])?);
                }
                0x0e if reply && vector.get(2) == Some(&0xf4) => {
                    if destination_cp_name.is_some() {
                        return Err(RouteSetupError::InvalidReply);
                    }
                    destination_cp_name = Some(decode_qualified_name(&vector[3..])?);
                }
                0x35 => has_sense = true,
                0x80 => route_information += 1,
                0x2b => has_route_selection = true,
                0x2c => has_cos = true,
                _ => {}
            }
            vectors.push(RouteSetupVector { key, wire: vector });
            cursor += length;
        }
        let (pcid, origin_cp_name) = fqpcid.ok_or(RouteSetupError::MissingFqPcid)?;
        let kind = if !reply {
            if route_information != 1
                || vectors.last().map(|cv| cv.key) != Some(0x80)
                || !has_route_selection
                || !has_cos
                || has_sense
            {
                return Err(RouteSetupError::MissingRequiredVector);
            }
            RouteSetupKind::Request
        } else if has_sense {
            RouteSetupKind::NegativeReply
        } else {
            if route_information != 2
                || vectors.last().map(|cv| cv.key) != Some(0x80)
                || !has_route_selection
                || !has_cos
                || destination_cp_name.is_none()
            {
                return Err(RouteSetupError::MissingRequiredVector);
            }
            RouteSetupKind::PositiveReply
        };
        Ok(Self {
            kind,
            path_switch,
            destination_hop_index: wire[5],
            arb_mode: (kind == RouteSetupKind::PositiveReply).then_some((wire[4] >> 4) & 0x03),
            pcid,
            origin_cp_name,
            destination_lu_name,
            destination_cp_name,
            vectors,
        })
    }
}

fn parse_fqpcid(vector: &[u8]) -> Result<([u8; 8], String), RouteSetupError> {
    if vector.len() < 14 || vector.len() > 28 {
        return Err(RouteSetupError::InvalidFqPcid);
    }
    let name_len = usize::from(vector[10]);
    if !(3..=17).contains(&name_len) || 11 + name_len != vector.len() {
        return Err(RouteSetupError::InvalidFqPcid);
    }
    let pcid = vector[2..10].try_into().unwrap();
    Ok((pcid, decode_qualified_name(&vector[11..])?))
}

fn decode_qualified_name(wire: &[u8]) -> Result<String, RouteSetupError> {
    let mut name = String::with_capacity(wire.len());
    for &byte in wire {
        let character = match byte {
            0xc1..=0xc9 => b'A' + (byte - 0xc1),
            0xd1..=0xd9 => b'J' + (byte - 0xd1),
            0xe2..=0xe9 => b'S' + (byte - 0xe2),
            0xf0..=0xf9 => b'0' + (byte - 0xf0),
            0x4b => b'.',
            0x7c => b'@',
            0x7b => b'#',
            0x5b => b'$',
            _ => return Err(RouteSetupError::InvalidCpName),
        };
        name.push(char::from(character));
    }
    let Some((netid, cp)) = name.split_once('.') else {
        return Err(RouteSetupError::InvalidCpName);
    };
    if netid.is_empty()
        || netid.len() > 8
        || cp.is_empty()
        || cp.len() > 8
        || cp.contains('.')
        || !netid.as_bytes()[0].is_ascii_uppercase()
        || !cp.as_bytes()[0].is_ascii_uppercase()
    {
        return Err(RouteSetupError::InvalidCpName);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Complete X'12CE' GDS slices from preserved direct V5R4 EE capture,
    // packets 70 and 72 on UDP/12001. Product and IP headers are excluded.
    const REQUEST: &str = "007012ce0001000000000000000000000e0ef3e2d6d3d5c5e34be2d5c1c2162b010112461080010be2d6d3d5c5e34be2d5c1c2211660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e31a800000000005b500000114000010cc00000000066704008002";
    const REPLY: &str = "009412ce8001a0000003a980000000001a800000000005b500000114000010cc000000000667040080021660cec37477b5dc29970be2d6d3d5c5e34be2d5c1c10c2c01087bc3d6d5d5c5c3e30e0ef4e2d6d3d5c5e34be2d5c1c20426a400063900000004162b010012461080010be2d6d3d5c5e34be2d5c1c1211a808000000005b500000114000010cc00000000066704008002";

    fn unhex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn preserved_v5r4_request_and_reply_correlate_by_fqpcid() {
        let request = unhex(REQUEST);
        let reply = unhex(REPLY);
        let request = RouteSetupGds::parse(&request).unwrap();
        let reply = RouteSetupGds::parse(&reply).unwrap();
        assert_eq!(request.kind, RouteSetupKind::Request);
        assert_eq!(reply.kind, RouteSetupKind::PositiveReply);
        assert_eq!(request.origin_cp_name, "SOLNET.SNAA");
        assert_eq!(request.destination_lu_name.as_deref(), Some("SOLNET.SNAB"));
        assert_eq!(reply.origin_cp_name, request.origin_cp_name);
        assert_eq!(reply.destination_cp_name.as_deref(), Some("SOLNET.SNAB"));
        assert_eq!(request.pcid, reply.pcid);
        assert_eq!(request.vectors.len(), 5);
        assert_eq!(reply.vectors.len(), 8);
    }

    #[test]
    fn rejects_length_cv_and_identity_corruption() {
        let mut wire = unhex(REQUEST);
        wire[1] = 0;
        assert_eq!(
            RouteSetupGds::parse(&wire),
            Err(RouteSetupError::LengthMismatch)
        );
        let mut wire = unhex(REQUEST);
        wire[16] = 0;
        assert_eq!(
            RouteSetupGds::parse(&wire),
            Err(RouteSetupError::InvalidVector)
        );
        let mut wire = unhex(REQUEST);
        wire[52 + 10] = 18;
        assert_eq!(
            RouteSetupGds::parse(&wire),
            Err(RouteSetupError::InvalidFqPcid)
        );
    }
}
