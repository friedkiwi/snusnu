//! Read-only correlation of the second, user LU 6.2 BIND response.
//!
//! The independent V4R4 two-peer capture returned an adaptive, SYNCPT-capable
//! user-session response after the SNASVCMG exchange. Matching that response
//! says nothing about whether this router can activate or gateway the session.

use crate::user_bind::UserBindOffer;
use std::{error::Error, fmt};

// Sanitized two-peer V4R4 p78 fixed response. The window bytes are the
// negotiated adaptive value (zero), not the offered p71 fixed windows.
const OBSERVED_RESPONSE_FIXED: [u8; 27] = [
    0x31, 0x00, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33, 0x00, 0x80, 0xc7, 0xc7, 0x80, 0x00, 0x06, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0x43, 0x40, 0x00,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserResponseError {
    UnsupportedMode,
    WrongSession,
    UnsupportedResponse,
}

impl fmt::Display for UserResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native user LU6.2 response: {self:?}")
    }
}

impl Error for UserResponseError {}

/// A correlated V4R4 response profile, retained only for diagnostics and
/// future negotiation work. `0x94` claims conversation security/password
/// substitution and `0x43` claims SYNCPT/backout; neither may be inferred as
/// a capability of this router from observing an OS/400-to-OS/400 exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedUserBindResponse {
    pub security_flags: u8,
    pub sync_flags: u8,
    pub adaptive_pacing: bool,
}

/// Match the captured positive user RSP(BIND) against a separately validated
/// user BIND offer. The unknown X'13' user subfield is length-checked and
/// ignored. This accepts no generic negotiated response and grants no route.
pub fn correlate_observed_v4r4_user_response(
    offer: &UserBindOffer,
    piu: &[u8],
) -> Result<ObservedUserBindResponse, UserResponseError> {
    if !offer.mode.is_empty() {
        return Err(UserResponseError::UnsupportedMode);
    }
    let request = offer.request();
    if piu.len() < 9
        || piu[0] != request[0]
        || piu[1] != 0
        || piu[2] != offer.oaf
        || piu[3] != offer.daf
        || piu[4..6] != [0, 0]
    {
        return Err(UserResponseError::WrongSession);
    }
    if piu.len() < 36 || piu[6..9] != [0xeb, 0x80, 0] || piu[9..36] != OBSERVED_RESPONSE_FIXED {
        return Err(UserResponseError::UnsupportedResponse);
    }
    let ru = &piu[9..];
    // Response outer PLU/SLU names are absent, as in the management reply.
    // User subfields are mode, session-instance, responder SLU, and opaque
    // X'13' in that order. Each length includes the one-byte subfield key.
    let slu = encode_lu_name(&offer.slu)?;
    let user_len = 27 + slu.len();
    if ru.get(27..32) != Some(&[0, user_len as u8, 0, 9, 2])
        || ru.get(32..40) != Some(&[0x40; 8])
        || ru.get(40..43) != Some(&[2, 3, 2])
    {
        return Err(UserResponseError::UnsupportedResponse);
    }
    if slu.len() > 17
        || ru.get(43) != Some(&((1 + slu.len()) as u8))
        || ru.get(44) != Some(&5)
        || ru.get(45..45 + slu.len()) != Some(slu.as_slice())
    {
        return Err(UserResponseError::WrongSession);
    }
    let unknown = 45 + slu.len();
    if ru.get(unknown..unknown + 2) != Some(&[10, 0x13])
        || ru.get(unknown + 11..unknown + 13) != Some(&[0, 0])
        || ru.get(unknown + 13..unknown + 13 + offer.fqpcid.len()) != Some(offer.fqpcid.as_slice())
        || unknown + 13 + offer.fqpcid.len() != ru.len()
    {
        return Err(UserResponseError::WrongSession);
    }
    Ok(ObservedUserBindResponse {
        security_flags: ru[23],
        sync_flags: ru[24],
        adaptive_pacing: ru[9] & 0x80 != 0,
    })
}

fn encode_lu_name(name: &str) -> Result<Vec<u8>, UserResponseError> {
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => return Err(UserResponseError::WrongSession),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fid2_session_control::ManagementBind, user_bind::UserBindOffer};

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn offer() -> UserBindOffer {
        let management = hex(concat!(
            "2f00010200006b850031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601411111111111111110b1111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let bind = ManagementBind::from_request(&management, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let user = hex(concat!(
            "2f00020200006b850031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601422222222222222220b2222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        UserBindOffer::from_request(&user, &bind, "").unwrap()
    }

    fn captured_response() -> Vec<u8> {
        // Independent sanitized V4R4 two-peer p78 positive RSP(BIND).
        // Session-instance, X'13', and FQPCID tokens are synthetic.
        hex(concat!(
            "2f0002020000eb800031001307b0b051330080c7c7800006020000000000000094434000",
            "002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c2",
            "0a130000000000000000000000601422222222222222220b2222222222222222222222"
        ))
    }

    #[test]
    fn correlates_observed_user_response_without_activating_route() {
        let matched =
            correlate_observed_v4r4_user_response(&offer(), &captured_response()).unwrap();
        assert_eq!(
            matched,
            ObservedUserBindResponse {
                security_flags: 0x94,
                sync_flags: 0x43,
                adaptive_pacing: true,
            }
        );
    }

    #[test]
    fn rejects_wrong_session_and_unsupported_negotiation() {
        let offer = offer();
        let mut response = captured_response();
        response[0] ^= 0x02;
        assert_eq!(
            correlate_observed_v4r4_user_response(&offer, &response),
            Err(UserResponseError::WrongSession)
        );
        let mut response = captured_response();
        *response.last_mut().unwrap() ^= 1;
        assert_eq!(
            correlate_observed_v4r4_user_response(&offer, &response),
            Err(UserResponseError::WrongSession)
        );
        let mut response = captured_response();
        response[9 + 9] &= !0x80;
        assert_eq!(
            correlate_observed_v4r4_user_response(&offer, &response),
            Err(UserResponseError::UnsupportedResponse)
        );
        let mut response = captured_response();
        response[9 + 24] = 0x23;
        assert_eq!(
            correlate_observed_v4r4_user_response(&offer, &response),
            Err(UserResponseError::UnsupportedResponse)
        );
    }
}
