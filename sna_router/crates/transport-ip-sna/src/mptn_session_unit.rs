//! Complete post-BIND TCP62 normal record / carrier-neutral session unit.
//!
//! This is the lossless reduced SNF/RH/RU boundary. It leaves segmentation,
//! expedited acknowledgement, BIND/UNBIND, and native pacing with the carrier
//! adapter. TCP62 must not carry a native RH pacing indication.

use std::io;

use router_core::session::SessionUnit;

use crate::{
    anynet::{TcpKind, TcpRecord, MAX_RECORD},
    mptn_gateway::{mptn_normal_to_native, NativeSessionAddress},
};

// The validation path only uses the resulting FID2 TH to locate the reduced
// unit; these addresses are never sent and do not become session identity.
const VALIDATION_ADDRESS: NativeSessionAddress = NativeSessionAddress {
    daf: 1,
    oaf: 2,
    odai: false,
};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Decode one already reassembled normal record. The established session
/// must be selected by the caller before it accepts this user unit.
pub fn normal_record_to_unit(record: &TcpRecord) -> io::Result<SessionUnit> {
    // TcpRecord has public fields, so revalidate the envelope as well as the
    // category and RH restrictions in the existing native converter.
    let checked = TcpRecord::decode(record.bytes.clone())?;
    if checked.kind != TcpKind::Normal || record.kind != TcpKind::Normal {
        return Err(invalid(
            "TCP62 session unit requires a complete normal record",
        ));
    }
    let piu = mptn_normal_to_native(&checked, VALIDATION_ADDRESS)?;
    SessionUnit::from_reduced(&piu[4..]).map_err(io::Error::other)
}

/// Encode a normalized session unit for a TCP62 normal record. The unit's
/// SNF is preserved exactly. The caller must handle carrier credit and exact
/// socket queue confirmation before releasing its ingress slot.
pub fn unit_to_normal_record(unit: &SessionUnit) -> io::Result<TcpRecord> {
    let length = 5 + unit.as_reduced().len();
    if length > MAX_RECORD {
        return Err(invalid("TCP62 session unit exceeds record bound"));
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&(length as u32).to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(unit.as_reduced());
    let record = TcpRecord::decode(bytes)?;
    mptn_normal_to_native(&record, VALIDATION_ADDRESS)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_gateway::native_normal_to_mptn;

    fn record(bytes: &[u8]) -> TcpRecord {
        TcpRecord::decode(bytes.to_vec()).unwrap()
    }

    #[test]
    fn captured_normal_request_and_implied_response_preserve_snf() {
        // V5R4 525-byte TCP/397 request prefix and captured positive response
        // from tests/user_bind_attach.rs. Application payload is redacted.
        let mut request = vec![
            0, 0, 2, 0x0d, 0, 0, 2, 0x03, 0x90, 0x20, 0x02, 0x03, 0x12, 0xa0, 0, 0, 0x04, 0x10,
            0x80, 0x03,
        ];
        request.resize(525, 0);
        let response = [0, 0, 0, 10, 0, 0x80, 0, 0x83, 0xa0, 0];
        for bytes in [&request[..], &response[..]] {
            let original = record(bytes);
            let unit = normal_record_to_unit(&original).unwrap();
            assert_eq!(unit.as_reduced(), &bytes[5..]);
            assert_eq!(unit_to_normal_record(&unit).unwrap(), original);
        }
    }

    #[test]
    fn native_pacing_is_consumed_by_existing_converter_and_never_reintroduced() {
        let native = [
            0x2c, 0, 0x11, 0x22, 0x12, 0x34, 0x03, 0x01, 0x20, 0xaa, 0xbb,
        ];
        let converted = native_normal_to_mptn(&native).unwrap();
        assert!(converted.native_pacing_requested);
        let record = record(&converted.bytes);
        let unit = normal_record_to_unit(&record).unwrap();
        assert_eq!(unit.snf(), &[0x12, 0x34]);
        assert_eq!(unit.rh(), &[0x03, 0, 0x20]);
        assert_eq!(unit_to_normal_record(&unit).unwrap(), record);
    }

    #[test]
    fn excludes_carrier_control_pacing_and_incomplete_records() {
        let paced = record(&[0, 0, 0, 10, 0, 0, 1, 3, 1, 0]);
        assert!(normal_record_to_unit(&paced).is_err());
        let bind = record(&[0, 0, 0, 11, 0, 0, 0, 0x6b, 0x80, 0, 0x31]);
        assert!(normal_record_to_unit(&bind).is_err());
        let ipr = record(&[0, 0, 0, 10, 0, 0, 0, 0x83, 1, 0]);
        assert!(normal_record_to_unit(&ipr).is_err());
        let mut segmented = record(&[0, 0, 0, 10, 0, 0, 1, 3, 0, 0]);
        segmented.bytes[4] = 0x20;
        segmented.kind = TcpKind::Segmented;
        assert!(normal_record_to_unit(&segmented).is_err());
    }
}
