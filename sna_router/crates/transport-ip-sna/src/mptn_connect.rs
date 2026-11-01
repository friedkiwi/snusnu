//! TCP62 MPTN_Connect framing from the IBM-authored TCP62 draft, sections
//! 5.2.1–5.2.3 and 5.3.1:
//! https://datatracker.ietf.org/doc/html/draft-ietf-tn3270e-tcp62-00
//!
//! Address names remain EBCDIC wire bytes. This codec does not establish an
//! LU6.2 session or interpret the BIND/BIND_RSP carried in connection data.

use std::io;

use crate::anynet::MAX_RECORD;

const CONNECT: u8 = 0x80;
const REQUIRE_GATEWAY_AND_DESTINATION: u8 = 0x0a;
const CONNECTION_DATA: u8 = 0x0a;
const TRANSPORT_REQUIREMENTS_LEN: u8 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Request,
    PositiveResponse,
    NegativeResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    /// Network-qualified LU name, still in the EBCDIC bytes used on the wire.
    pub node: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportRequirements {
    pub max_record: u32,
    pub max_expedited: u32,
    pub max_termination: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionalField {
    pub kind: u8,
    pub processing: u8,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connect {
    pub direction: Direction,
    /// Full processing byte. Bits 4 and 6 (IBM bit numbering) must be set.
    pub processing: u8,
    pub ttl: u8,
    pub destination: Address,
    pub source: Address,
    /// One to eight bytes; the wire length byte includes itself.
    pub correlator: Vec<u8>,
    pub requirements: TransportRequirements,
    pub options: Vec<OptionalField>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, len: usize) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| invalid("MPTN Connect offset overflow"))?;
    let slice = input
        .get(*cursor..end)
        .ok_or_else(|| invalid("truncated MPTN Connect"))?;
    *cursor = end;
    Ok(slice)
}

fn address(input: &[u8], cursor: &mut usize) -> io::Result<Address> {
    let prefix = take(input, cursor, 3)?;
    if prefix[0] != 0x0b || prefix[1] != 0x01 {
        return Err(invalid("unsupported MPTN address family or mode"));
    }
    let size = prefix[2] as usize;
    if !(4..=18).contains(&size) {
        return Err(invalid("MPTN LU node address length is invalid"));
    }
    let node = take(input, cursor, size - 1)?.to_vec();
    if take(input, cursor, 1)?[0] != 0x01 {
        return Err(invalid("MPTN LU local address must be null"));
    }
    Ok(Address { node })
}

fn validate_processing(processing: u8) -> io::Result<Direction> {
    // The draft numbers bits from the high bit. Bit 3 is reserved; bits 4
    // and 6 are mandatory for Connect. Request-only reserved bits must clear.
    if processing & 0x10 != 0
        || processing & REQUIRE_GATEWAY_AND_DESTINATION != REQUIRE_GATEWAY_AND_DESTINATION
    {
        return Err(invalid("invalid MPTN Connect processing flags"));
    }
    if processing & 0x80 == 0 {
        if processing != REQUIRE_GATEWAY_AND_DESTINATION {
            return Err(invalid("reserved MPTN Connect request flags"));
        }
        return Ok(Direction::Request);
    }
    if processing & 0x40 == 0 {
        if processing != 0x8a {
            return Err(invalid("invalid positive MPTN Connect response flags"));
        }
        return Ok(Direction::PositiveResponse);
    }
    // A negative response may indicate destination rejection or that a
    // gateway/destination did not understand the command. Preserve those
    // reason bits, but require a consistent negative response marker.
    if processing & !(0x80 | 0x40 | 0x20 | 0x08 | 0x04 | 0x02 | 0x01) != 0 {
        return Err(invalid("invalid negative MPTN Connect response flags"));
    }
    Ok(Direction::NegativeResponse)
}

fn validate_optional(field: &OptionalField, direction: Direction) -> io::Result<()> {
    if field.processing & 0xf0 != 0 {
        return Err(invalid("reserved MPTN optional processing bits"));
    }
    if direction == Direction::Request && field.processing & 0x05 != 0 {
        return Err(invalid("response flags in MPTN optional request field"));
    }
    let required_bits = match field.kind {
        0x05 => 0x08,
        0x0a => 0x02,
        0x18 | 0x1a | 0x1c => 0,
        0x19 => 0x0a,
        0xf0 if direction == Direction::NegativeResponse => field.processing & 0x0a,
        _ => return Err(invalid("unsupported or malformed MPTN optional field")),
    };
    if field.processing & 0x0a != required_bits {
        return Err(invalid("incorrect MPTN optional processing requirement"));
    }
    match field.kind {
        0x05 if field.value.len() >= 2
            && field.value[0] <= 5
            && field.value[1] as usize == field.value.len() - 1 => {}
        0x0a if !field.value.is_empty() => {}
        0x18 if !field.value.is_empty()
            && field
                .value
                .iter()
                .all(|byte| *byte == 1 || (direction != Direction::Request && *byte == 0)) => {}
        0x19 if !field.value.is_empty()
            && field
                .value
                .iter()
                .all(|byte| matches!(byte, 0x00 | 0x01 | 0x03 | 0x10 | 0x20 | 0x83)) => {}
        0x1a if !field.value.is_empty()
            && field
                .value
                .iter()
                .all(|byte| *byte == 0x84 || (direction != Direction::Request && *byte == 0)) => {}
        0x1c if (2..=8).contains(&field.value.len()) => {}
        0xf0 if !field.value.is_empty() => {}
        _ => return Err(invalid("unsupported or malformed MPTN optional field")),
    }
    Ok(())
}

impl Connect {
    pub fn decode(record: &[u8]) -> io::Result<Self> {
        if record.len() < 39 || record.len() > MAX_RECORD {
            return Err(invalid("MPTN Connect record size is invalid"));
        }
        let declared = u32::from_be_bytes(record[..4].try_into().unwrap()) as usize;
        if declared != record.len() || record[4] != CONNECT {
            return Err(invalid("MPTN Connect record length or type is invalid"));
        }
        let direction = validate_processing(record[5])?;
        let command_length = u32::from_be_bytes(record[6..10].try_into().unwrap()) as usize;
        if command_length + 4 != record.len() {
            return Err(invalid("MPTN Connect command length mismatch"));
        }
        let ttl = record[10];
        if ttl == 0 {
            return Err(invalid("MPTN Connect TTL exhausted"));
        }
        let mut cursor = 11;
        let destination = address(record, &mut cursor)?;
        let source = address(record, &mut cursor)?;
        let suffix_len = take(record, &mut cursor, 1)?[0] as usize;
        if !(2..=9).contains(&suffix_len) {
            return Err(invalid("MPTN correlator length is invalid"));
        }
        let correlator = take(record, &mut cursor, suffix_len - 1)?.to_vec();
        if take(record, &mut cursor, 1)?[0] != TRANSPORT_REQUIREMENTS_LEN {
            return Err(invalid("unsupported MPTN transport requirements length"));
        }
        let requirements = TransportRequirements {
            max_record: u32::from_be_bytes(take(record, &mut cursor, 4)?.try_into().unwrap()),
            max_expedited: u32::from_be_bytes(take(record, &mut cursor, 4)?.try_into().unwrap()),
            max_termination: u32::from_be_bytes(take(record, &mut cursor, 4)?.try_into().unwrap()),
        };
        if requirements.max_record == 0
            || requirements.max_record as usize > MAX_RECORD
            || requirements.max_expedited as usize > MAX_RECORD
            || requirements.max_termination as usize > MAX_RECORD
        {
            return Err(invalid("unsupported MPTN transport size limit"));
        }
        if take(record, &mut cursor, 2)? != [0x20, 0x00] {
            return Err(invalid("unsupported MPTN termination or expedited marking"));
        }
        let mut options = Vec::new();
        let mut last_kind = 0;
        let mut connection_data_count = 0;
        while cursor < record.len() {
            let prefix = take(record, &mut cursor, 4)?;
            let kind = prefix[0];
            let length = u16::from_be_bytes(prefix[2..4].try_into().unwrap()) as usize;
            if length < 4 {
                return Err(invalid("MPTN optional field length is invalid"));
            }
            if kind < last_kind || (kind == last_kind && kind != 0xf0) {
                return Err(invalid("MPTN optional fields out of order or duplicated"));
            }
            let field = OptionalField {
                kind,
                processing: prefix[1],
                value: take(record, &mut cursor, length - 4)?.to_vec(),
            };
            validate_optional(&field, direction)?;
            connection_data_count += usize::from(kind == CONNECTION_DATA);
            last_kind = kind;
            options.push(field);
        }
        if connection_data_count != 1 {
            return Err(invalid(
                "MPTN Connect requires one BIND connection-data field",
            ));
        }
        Ok(Self {
            direction,
            processing: record[5],
            ttl,
            destination,
            source,
            correlator,
            requirements,
            options,
        })
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if validate_processing(self.processing)? != self.direction
            || self.ttl == 0
            || !(3..=17).contains(&self.destination.node.len())
            || !(3..=17).contains(&self.source.node.len())
            || !(1..=8).contains(&self.correlator.len())
            || self.requirements.max_record == 0
            || self.requirements.max_record as usize > MAX_RECORD
            || self.requirements.max_expedited as usize > MAX_RECORD
            || self.requirements.max_termination as usize > MAX_RECORD
        {
            return Err(invalid("invalid MPTN Connect fields"));
        }
        let mut record = vec![0; 4];
        record.extend_from_slice(&[CONNECT, self.processing, 0, 0, 0, 0, self.ttl]);
        for address in [&self.destination, &self.source] {
            record.extend_from_slice(&[0x0b, 0x01, (address.node.len() + 1) as u8]);
            record.extend_from_slice(&address.node);
            record.push(0x01);
        }
        record.push((self.correlator.len() + 1) as u8);
        record.extend_from_slice(&self.correlator);
        record.push(TRANSPORT_REQUIREMENTS_LEN);
        record.extend_from_slice(&self.requirements.max_record.to_be_bytes());
        record.extend_from_slice(&self.requirements.max_expedited.to_be_bytes());
        record.extend_from_slice(&self.requirements.max_termination.to_be_bytes());
        record.extend_from_slice(&[0x20, 0x00]);
        let mut last_kind = 0;
        let mut connection_data_count = 0;
        for option in &self.options {
            validate_optional(option, self.direction)?;
            if option.kind < last_kind || (option.kind == last_kind && option.kind != 0xf0) {
                return Err(invalid("MPTN optional fields out of order or duplicated"));
            }
            let length = option
                .value
                .len()
                .checked_add(4)
                .and_then(|len| u16::try_from(len).ok())
                .ok_or_else(|| invalid("MPTN optional field too large"))?;
            record.extend_from_slice(&[option.kind, option.processing]);
            record.extend_from_slice(&length.to_be_bytes());
            record.extend_from_slice(&option.value);
            connection_data_count += usize::from(option.kind == CONNECTION_DATA);
            last_kind = option.kind;
        }
        if connection_data_count != 1 || record.len() > MAX_RECORD {
            return Err(invalid("invalid MPTN Connect option set or size"));
        }
        let total = u32::try_from(record.len()).map_err(|_| invalid("MPTN record too large"))?;
        record[..4].copy_from_slice(&total.to_be_bytes());
        record[6..10].copy_from_slice(&(total - 4).to_be_bytes());
        Ok(record)
    }

    /// A response echoes the request's address pair and source correlator.
    pub fn matches_response(&self, response: &Self) -> bool {
        self.direction == Direction::Request
            && response.direction != Direction::Request
            && self.destination == response.destination
            && self.source == response.source
            && self.correlator == response.correlator
    }

    pub fn connection_data(&self) -> &[u8] {
        self.options
            .iter()
            .find(|field| field.kind == CONNECTION_DATA)
            .map_or(&[], |field| field.value.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-built from TCP62 draft 5.3.1: SOLNET.SNAB -> SOLNET.SNAA
    // EBCDIC LU addresses, correlator 12 34, fixed requirements, BIND RU.
    const REQUEST: &[u8] = &[
        0, 0, 0, 66, 0x80, 0x0a, 0, 0, 0, 62, 8, 0x0b, 1, 12, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3,
        0x4b, 0xe2, 0xd5, 0xc1, 0xc2, 1, 0x0b, 1, 12, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b,
        0xe2, 0xd5, 0xc1, 0xc1, 1, 3, 0x12, 0x34, 15, 0, 0, 0x10, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0x20,
        0, 0x0a, 0x02, 0, 7, 0x31, 0x00, 0x13,
    ];

    #[test]
    fn decodes_and_reencodes_connect_request() {
        let request = Connect::decode(REQUEST).unwrap();
        assert_eq!(request.direction, Direction::Request);
        assert_eq!(request.correlator, [0x12, 0x34]);
        assert_eq!(request.connection_data(), [0x31, 0x00, 0x13]);
        assert_eq!(request.encode().unwrap(), REQUEST);
    }

    #[test]
    fn response_matches_only_original_request() {
        let request = Connect::decode(REQUEST).unwrap();
        let mut response = request.clone();
        response.direction = Direction::PositiveResponse;
        response.processing = 0x8a;
        response.options[0].value = vec![0x31, 0x00];
        let encoded = response.encode().unwrap();
        assert_eq!(Connect::decode(&encoded).unwrap(), response);
        assert!(request.matches_response(&response));
        response.correlator[0] ^= 1;
        assert!(!request.matches_response(&response));
    }

    #[test]
    fn negative_response_can_carry_diagnostics() {
        let request = Connect::decode(REQUEST).unwrap();
        let mut response = request.clone();
        response.direction = Direction::NegativeResponse;
        response.processing = 0xca;
        response.options.push(OptionalField {
            kind: 0xf0,
            processing: 0,
            value: vec![0, 0x80, 0, 7],
        });
        let encoded = response.encode().unwrap();
        assert_eq!(Connect::decode(&encoded).unwrap(), response);
        assert!(request.matches_response(&response));
    }

    #[test]
    fn rejects_length_address_flag_and_option_errors() {
        let mut bytes = REQUEST.to_vec();
        bytes[5] = 0x4a; // Negative marker without response bit.
        assert!(Connect::decode(&bytes).is_err());
        bytes = REQUEST.to_vec();
        bytes[13] = 0x00; // Wrong address family.
        assert!(Connect::decode(&bytes).is_err());
        bytes = REQUEST.to_vec();
        bytes[6..10].copy_from_slice(&1u32.to_be_bytes());
        assert!(Connect::decode(&bytes).is_err());
        bytes = REQUEST.to_vec();
        bytes[59] = 0x99; // Unknown optional field.
        assert!(Connect::decode(&bytes).is_err());
        bytes = REQUEST.to_vec();
        bytes[41] = 1; // Correlator must contain at least one value byte.
        assert!(Connect::decode(&bytes).is_err());
        bytes = REQUEST.to_vec();
        bytes[10] = 0; // TTL exhausted.
        assert!(Connect::decode(&bytes).is_err());
        bytes = REQUEST.to_vec();
        bytes[59] = 0x19; // Wrong processing flags for required compensations.
        assert!(Connect::decode(&bytes).is_err());
    }
}
