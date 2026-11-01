//! Read-only correlation of the first V4R4 5250 application record.
//!
//! The 82-byte p90/p55 PIU after the user FMH-5 Attach is an application GDS
//! X'12A0' startup record, not an architected APPC Attach acknowledgment.
//! IBM-authored RFC 2877 §9 documents this 73-byte 5250 pass-through record
//! shape and its fixed 12-byte prefix. Its response code, system/object names,
//! and diagnostic bytes are application-owned. In particular the observed
//! X'C9F9F0F3' (`I903`) is not assigned a meaning by that RFC. A router must
//! forward real application data from its destination LU, never synthesize a
//! startup status from the SNA session handshake.

use crate::{user_bind::UserBindOffer, user_pacing::FirstAttachRoute};
use std::{error::Error, fmt};

const STARTUP_PREFIX: [u8; 12] = [
    0x90, 0x00, 0x05, 0x60, 0x06, 0x00, 0x20, 0xc0, 0x00, 0x3d, 0x00, 0x00,
];
const OBSERVED_TP: [u8; 4] = [0x30, 0xf0, 0xf0, 0xf5];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupRecordError {
    WrongSession,
    WrongRoute,
    UnsupportedRecord,
    InvalidName,
}

impl fmt::Display for StartupRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native 5250 startup record: {self:?}")
    }
}

impl Error for StartupRecordError {}

/// Parsed application metadata only. A code is kept as raw EBCDIC because
/// the observed `I903` is not one of RFC 2877's listed printer outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupRecord {
    pub response_code: [u8; 4],
    pub system_name: String,
    pub object_name: String,
    pub diagnostic_bytes: usize,
}

/// Correlate one 5250 startup record to a previously accepted user Attach.
/// This parser does not charge pacing or create a response. The sender side
/// must separately use the user session's PI/IPR state and an actual LU/TP.
pub fn correlate_v4r4_startup_record(
    piu: &[u8],
    offer: &UserBindOffer,
    attach_route: &FirstAttachRoute,
) -> Result<StartupRecord, StartupRecordError> {
    if attach_route.remote_lu != offer.plu
        || attach_route.local_lu != offer.slu
        || attach_route.mode != offer.mode
        || attach_route.transaction_program != OBSERVED_TP
    {
        return Err(StartupRecordError::WrongRoute);
    }
    if piu.len() != 82
        || piu[0] != offer.request()[0] & !0x01
        || piu[1] != 0
        || piu[2] != offer.oaf
        || piu[3] != offer.daf
        || piu[4..9] != [0, 1, 0x03, 0xa1, 0]
    {
        return Err(StartupRecordError::WrongSession);
    }
    let ru = &piu[9..];
    if ru[0..4] != [0, 73, 0x12, 0xa0] || ru[4..16] != STARTUP_PREFIX {
        return Err(StartupRecordError::UnsupportedRecord);
    }
    let system_name = decode_name(&ru[20..28])?;
    let object_name = decode_name(&ru[28..38])?;
    Ok(StartupRecord {
        response_code: ru[16..20].try_into().unwrap(),
        system_name,
        object_name,
        diagnostic_bytes: ru.len() - 38,
    })
}

fn decode_name(bytes: &[u8]) -> Result<String, StartupRecordError> {
    let mut name = String::with_capacity(bytes.len());
    let mut padding = false;
    for &byte in bytes {
        if byte == 0x40 {
            padding = true;
            continue;
        }
        if padding {
            return Err(StartupRecordError::InvalidName);
        }
        let value = match byte {
            0xc1..=0xc9 => b'A' + (byte - 0xc1),
            0xd1..=0xd9 => b'J' + (byte - 0xd1),
            0xe2..=0xe9 => b'S' + (byte - 0xe2),
            0xf0..=0xf9 => b'0' + (byte - 0xf0),
            _ => return Err(StartupRecordError::InvalidName),
        };
        name.push(char::from(value));
    }
    if name.is_empty() {
        return Err(StartupRecordError::InvalidName);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fid2_session_control::ManagementBind, user_pacing::UserPacingSession};

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn route_and_offer() -> (FirstAttachRoute, UserBindOffer) {
        let management = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let management =
            ManagementBind::from_request(&management, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let user = hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260142222222222222222222222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        let offer = UserBindOffer::from_request(&user, &management, "").unwrap();
        let mut pacing = UserPacingSession::new(&offer, &management, 1).unwrap();
        let response = pacing.prepared_bind_response().to_vec();
        pacing.mark_bind_enqueued(&response).unwrap();
        pacing.acknowledge_bind(1).unwrap();
        let mut attach = hex(concat!(
            "2c00020200010b9120",
            "240502ff0803d000400430f0f0f500140b",
            "e2d6d3d5c5e34be2d5c1c1",
            "0102030405060001",
            "00c512f500c112e2"
        ));
        attach.extend_from_slice(&[0; 189]);
        let route = pacing
            .observe_first_attach(&offer, &OBSERVED_TP, &attach)
            .unwrap();
        (route, offer)
    }

    fn sanitized_record() -> Vec<u8> {
        // Independent p90/p55 profile: application identifiers replaced by
        // TARGET/PCPRINTER. Fixed bytes, I903 code and diagnostic size match
        // the V4R4 capture; the diagnostic body is deliberately synthetic.
        let mut piu = hex(concat!(
            "2c000202000103a100",
            "004912a090000560060020c0003d0000",
            "c9f9f0f3",
            "e3c1d9c7c5e34040",
            "d7c3d7d9c9d5e3c5d940"
        ));
        piu.extend_from_slice(&[0; 34]);
        piu.push(2);
        assert_eq!(piu.len(), 82);
        piu
    }

    #[test]
    fn recognizes_application_record_without_inventing_status() {
        let (route, offer) = route_and_offer();
        let record = correlate_v4r4_startup_record(&sanitized_record(), &offer, &route).unwrap();
        assert_eq!(record.response_code, [0xc9, 0xf9, 0xf0, 0xf3]);
        assert_eq!(record.system_name, "TARGET");
        assert_eq!(record.object_name, "PCPRINTER");
        assert_eq!(record.diagnostic_bytes, 35);
    }

    #[test]
    fn rejects_wrong_session_route_and_record_shape() {
        let (route, offer) = route_and_offer();
        let mut record = sanitized_record();
        record[2] = 1;
        assert_eq!(
            correlate_v4r4_startup_record(&record, &offer, &route),
            Err(StartupRecordError::WrongSession)
        );
        let mut wrong_route = route.clone();
        wrong_route.transaction_program[3] ^= 1;
        assert_eq!(
            correlate_v4r4_startup_record(&sanitized_record(), &offer, &wrong_route),
            Err(StartupRecordError::WrongRoute)
        );
        let mut record = sanitized_record();
        record[9 + 3] ^= 1;
        assert_eq!(
            correlate_v4r4_startup_record(&record, &offer, &route),
            Err(StartupRecordError::UnsupportedRecord)
        );
        let mut record = sanitized_record();
        record[9 + 20] = 0x40;
        assert_eq!(
            correlate_v4r4_startup_record(&record, &offer, &route),
            Err(StartupRecordError::InvalidName)
        );
    }
}
