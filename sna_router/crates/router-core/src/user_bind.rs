//! Correlation gate for a second, user LU 6.2 session after SNASVCMG CNOS.
//!
//! This only records an offer. It does not negotiate a positive BIND or
//! activate a route. A user session needs its own pacing, APPC conversation,
//! and AnyNet gateway state before any +RSP(BIND) can be transmitted.

use crate::{
    fid2_bind::{classify_bind, BindClass, BindError},
    fid2_session_control::{request_fqpcid, ManagementBind, SessionControlError},
};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserBindError {
    Invalid(BindError),
    Unsupported(SessionControlError),
    WrongMode,
    WrongLuPair,
    WrongSession,
}

impl fmt::Display for UserBindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native user LU 6.2 BIND: {self:?}")
    }
}

impl Error for UserBindError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserBindOffer {
    pub daf: u8,
    pub oaf: u8,
    pub plu: String,
    pub slu: String,
    pub mode: String,
    pub fqpcid: [u8; 22],
    request: Vec<u8>,
}

impl UserBindOffer {
    /// `expected_mode = ""` selects only the observed blank/default mode.
    /// Named modes require exact policy. The PLU and SLU are the configured
    /// peer and local LU identities, not inferred from session addresses.
    pub fn from_request(
        piu: &[u8],
        management: &ManagementBind,
        expected_mode: &str,
    ) -> Result<Self, UserBindError> {
        let info = classify_bind(piu)
            .map_err(UserBindError::Invalid)?
            .ok_or(UserBindError::WrongMode)?;
        let mode = match info.class {
            BindClass::Undetermined if expected_mode.is_empty() => String::new(),
            BindClass::NamedLu62 { mode } if mode == expected_mode => mode,
            _ => return Err(UserBindError::WrongMode),
        };
        if info.plu != management.plu() || info.slu != management.slu() {
            return Err(UserBindError::WrongLuPair);
        }
        if piu.len() < 9
            || !matches!(piu[0], 0x2d | 0x2f)
            || piu[1] != 0
            || !matches!(&piu[6..9], [0x6b, 0x80, 0] | [0x6b, 0x85, 0])
            || info.daf == 0
            || info.oaf == 0
            || (info.daf, info.oaf) == management.request_addresses()
        {
            return Err(UserBindError::WrongSession);
        }
        let fqpcid = request_fqpcid(&piu[9..]).map_err(UserBindError::Unsupported)?;
        if &fqpcid == management.fqpcid() {
            return Err(UserBindError::WrongSession);
        }
        Ok(Self {
            daf: info.daf,
            oaf: info.oaf,
            plu: info.plu,
            slu: info.slu,
            mode,
            fqpcid,
            request: piu.to_vec(),
        })
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn management() -> ManagementBind {
        // Sanitized live V4R4 SNASVCMG BIND, separate session instance.
        let piu = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
            "2c0a00000000000000000000"
        ));
        ManagementBind::from_request(&piu, "SOLNET.SNAA", "SOLNET.SNAB").unwrap()
    }

    fn user() -> Vec<u8> {
        // Sanitized third live probe p35: blank/default mode, DAF2/OAF2.
        hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260142222222222222222222222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ))
    }

    #[test]
    fn records_distinct_default_mode_user_session_without_activating_it() {
        let mgmt = management();
        let piu = user();
        assert_eq!(piu.len(), 141);
        let offer = UserBindOffer::from_request(&piu, &mgmt, "").unwrap();
        assert_eq!((offer.daf, offer.oaf), (2, 2));
        assert_eq!(
            (offer.plu.as_str(), offer.slu.as_str()),
            ("SOLNET.SNAA", "SOLNET.SNAB")
        );
        assert_eq!(offer.mode, "");
        assert_eq!(offer.request(), piu);
        assert_ne!(&offer.fqpcid, mgmt.fqpcid());
    }

    #[test]
    fn rejects_mode_and_session_aliases() {
        let mgmt = management();
        let piu = user();
        assert_eq!(
            UserBindOffer::from_request(&piu, &mgmt, "SNASVCMG"),
            Err(UserBindError::WrongMode)
        );
        let mut same_address = piu.clone();
        same_address[2] = 1;
        assert_eq!(
            UserBindOffer::from_request(&same_address, &mgmt, ""),
            Err(UserBindError::WrongSession)
        );
        let mut same_instance = piu;
        let offset = same_instance
            .windows(2)
            .position(|part| part == [0x60, 0x14])
            .unwrap();
        same_instance[offset..offset + 22].copy_from_slice(mgmt.fqpcid());
        assert_eq!(
            UserBindOffer::from_request(&same_instance, &mgmt, ""),
            Err(UserBindError::WrongSession)
        );
    }
}
