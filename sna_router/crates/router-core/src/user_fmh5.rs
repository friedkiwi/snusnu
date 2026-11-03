//! Read-only first user-session FMH-5 boundary after user BIND.
//!
//! Two independent V4R4 peer traces start the default-mode APPC conversation
//! with a length-qualified FMH-5 Attach in a 242-byte FID2 PIU. The following bytes
//! carry application/conversation data and are deliberately left opaque.
//! Parsing this header does not authorize a positive reply or a route.

use crate::user_bind::UserBindOffer;
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserFmh5Error {
    Truncated,
    WrongSession,
    UnsupportedPiu,
}

impl fmt::Display for UserFmh5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native user FMH-5: {self:?}")
    }
}

impl Error for UserFmh5Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstUserAttach {
    pub daf: u8,
    pub oaf: u8,
    pub sequence: u16,
    pub fmh5_bytes: usize,
    pub opaque_tail_bytes: usize,
}

/// Recognize only the observed first normal-flow Attach header. The caller
/// must separately implement pacing, APPC allocation and the chosen gateway.
pub fn parse_first_user_attach(
    piu: &[u8],
    offer: &UserBindOffer,
) -> Result<FirstUserAttach, UserFmh5Error> {
    if offer.mode == "QRMTWSC" {
        if piu.len() < 9 + 17 + 8 {
            return Err(UserFmh5Error::Truncated);
        }
        if piu.len() > 1496
            || piu[0] != offer.request()[0] & !0x01
            || piu[1] != 0
            || piu[2] != offer.daf
            || piu[3] != offer.oaf
            || piu[4..9] != [0, 1, 0x0b, 0x91, 0x20]
        {
            return Err(UserFmh5Error::WrongSession);
        }
        if piu[9..19] != [0x11, 5, 2, 0xff, 8, 3, 0xd0, 0, 0, 4] || piu[23..26] != [0, 0, 0] {
            return Err(UserFmh5Error::UnsupportedPiu);
        }
        return Ok(FirstUserAttach {
            daf: piu[2],
            oaf: piu[3],
            sequence: 1,
            fmh5_bytes: 17,
            opaque_tail_bytes: piu.len() - 9 - 17,
        });
    }
    let fmh5_bytes = 25 + offer.plu.len();
    if piu.len() < 9 + fmh5_bytes {
        return Err(UserFmh5Error::Truncated);
    }
    if piu.len() > 1496
        || !matches!(piu[0], 0x2c | 0x2e)
        || piu[1] != 0
        || piu[2] != offer.daf
        || piu[3] != offer.oaf
        || piu[0] & 0x02 != offer.request()[0] & 0x02
    {
        return Err(UserFmh5Error::WrongSession);
    }
    if piu[4..9] != [0, 1, 0x0b, 0x91, 0x20]
        || piu[9] as usize != fmh5_bytes
        || piu[10..16] != [0x05, 0x02, 0xff, 0x08, 0x03, 0xd0]
        || piu.len() == 9 + fmh5_bytes
    {
        return Err(UserFmh5Error::UnsupportedPiu);
    }
    Ok(FirstUserAttach {
        daf: piu[2],
        oaf: piu[3],
        sequence: 1,
        fmh5_bytes,
        opaque_tail_bytes: piu.len() - 9 - fmh5_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fid2_session_control::ManagementBind;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn offer() -> UserBindOffer {
        let mgmt = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601411111111111111110b1111111111111111111111",
            "2c0a00000000000000000000"
        ));
        let management = ManagementBind::from_request(&mgmt, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let user = hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601422222222222222220b2222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        UserBindOffer::from_request(&user, &management, "").unwrap()
    }

    #[test]
    fn recognizes_captured_first_attach_without_parsing_app_data() {
        let offer = offer();
        let mut piu = vec![0x2c, 0, 2, 2, 0, 1, 0x0b, 0x91, 0x20];
        piu.extend_from_slice(&[0x24, 0x05, 0x02, 0xff, 0x08, 0x03, 0xd0]);
        piu.resize(9 + 36 + 197, 0);
        let attach = parse_first_user_attach(&piu, &offer).unwrap();
        assert_eq!(attach.fmh5_bytes, 36);
        assert_eq!(attach.opaque_tail_bytes, 197);
        piu[0] = 0x2e;
        assert_eq!(
            parse_first_user_attach(&piu, &offer),
            Err(UserFmh5Error::WrongSession)
        );
        piu[0] = 0x2c;
        piu[2] = 1;
        assert_eq!(
            parse_first_user_attach(&piu, &offer),
            Err(UserFmh5Error::WrongSession)
        );
    }
}
