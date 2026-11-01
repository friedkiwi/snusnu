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
    UnsupportedProfile,
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
    pub fqpcid: Vec<u8>,
    request: Vec<u8>,
}

/// The application LU pair and mode must be selected by configuration.
/// Empty mode selects only the observed SNA default-mode BIND.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBindPolicy<'a> {
    pub plu: &'a str,
    pub slu: &'a str,
    pub mode: &'a str,
}

const V4R4_USER_REQUEST_FIXED: [u8; 27] = [
    0x31, 0x00, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33, 0x03, 0x83, 0xc7, 0xc7, 0x83, 0x03, 0x06, 0x02,
    0, 0, 0, 0, 0, 0, 0, 0x94, 0x43, 0x40, 0,
];

fn ebcdic_lu(name: &str) -> Result<Vec<u8>, UserBindError> {
    name.bytes()
        .map(|b| match b {
            b'A'..=b'I' => Ok(0xc1 + (b - b'A')),
            b'J'..=b'R' => Ok(0xd1 + (b - b'J')),
            b'S'..=b'Z' => Ok(0xe2 + (b - b'S')),
            b'0'..=b'9' => Ok(0xf0 + (b - b'0')),
            b'.' => Ok(0x4b),
            _ => Err(UserBindError::WrongLuPair),
        })
        .collect()
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
        Self::from_request_with_policy(
            piu,
            management,
            UserBindPolicy {
                plu: management.plu(),
                slu: management.slu(),
                mode: expected_mode,
            },
        )
    }

    pub fn from_request_with_policy(
        piu: &[u8],
        management: &ManagementBind,
        policy: UserBindPolicy<'_>,
    ) -> Result<Self, UserBindError> {
        Self::from_request_with_policy_internal(piu, management, policy, false)
    }

    /// A completed management session may release its local address pair.
    /// The caller must have observed its UNBIND before using this constructor.
    pub fn from_request_after_management(
        piu: &[u8],
        management: &ManagementBind,
        policy: UserBindPolicy<'_>,
    ) -> Result<Self, UserBindError> {
        Self::from_request_with_policy_internal(piu, management, policy, true)
    }

    fn from_request_with_policy_internal(
        piu: &[u8],
        management: &ManagementBind,
        policy: UserBindPolicy<'_>,
        management_closed: bool,
    ) -> Result<Self, UserBindError> {
        let info = classify_bind(piu)
            .map_err(UserBindError::Invalid)?
            .ok_or(UserBindError::WrongMode)?;
        let mode = match info.class {
            BindClass::Undetermined if policy.mode.is_empty() => String::new(),
            BindClass::NamedLu62 { mode } if mode == policy.mode => mode,
            _ => return Err(UserBindError::WrongMode),
        };
        if info.plu != policy.plu || info.slu != policy.slu {
            return Err(UserBindError::WrongLuPair);
        }
        if piu.len() < 9
            || !matches!(piu[0], 0x2d | 0x2f)
            || piu[1] != 0
            || !matches!(&piu[6..9], [0x6b, 0x80, 0] | [0x6b, 0x85, 0])
            || info.daf == 0
            || info.oaf == 0
            || (!management_closed && (info.daf, info.oaf) == management.request_addresses())
        {
            return Err(UserBindError::WrongSession);
        }
        let fqpcid = request_fqpcid(&piu[9..]).map_err(UserBindError::Unsupported)?;
        if fqpcid == management.fqpcid() {
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

    /// Candidate fixed one-stage response for the exact captured V4R4
    /// default-mode user BIND profile. It is not authorization to transmit:
    /// the caller must first provide session pacing, APPC, and all AnyNet
    /// compensations. The local receive window is bounded by that runtime.
    pub fn build_fixed_response(&self, local_receive_window: u8) -> Result<Vec<u8>, UserBindError> {
        if !(1..=3).contains(&local_receive_window) {
            return Err(UserBindError::UnsupportedProfile);
        }
        let ru = &self.request[9..];
        if ru.len() < 27 || ru[..27] != V4R4_USER_REQUEST_FIXED {
            return Err(UserBindError::UnsupportedProfile);
        }
        let plu = ebcdic_lu(&self.plu)?;
        let slu = ebcdic_lu(&self.slu)?;
        let plu_len = *ru.get(27).ok_or(UserBindError::UnsupportedProfile)? as usize;
        if plu_len != plu.len() || ru.get(28..28 + plu_len) != Some(plu.as_slice()) {
            return Err(UserBindError::UnsupportedProfile);
        }
        let user_len_offset = 28 + plu_len;
        let user_len = *ru
            .get(user_len_offset)
            .ok_or(UserBindError::UnsupportedProfile)? as usize;
        let user_start = user_len_offset + 1;
        let user_end = user_start + user_len;
        let user = ru
            .get(user_start..user_end)
            .ok_or(UserBindError::UnsupportedProfile)?;
        // Preserve the observed V4 default-mode subfield profile while the
        // PLU subfield follows its own network-qualified name length.
        if user_len != 34 + plu_len
            || user.get(..11) != Some(&[0, 9, 2, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40])
            || user.get(11..14) != Some(&[9, 3, 1])
            || user.get(21..23) != Some(&[(1 + plu_len) as u8, 4])
            || user.get(23..23 + plu_len) != Some(plu.as_slice())
            || user.get(23 + plu_len..25 + plu_len) != Some(&[10, 0x13])
        {
            return Err(UserBindError::UnsupportedProfile);
        }
        let slu_len_offset = user_end + 1;
        if ru.get(user_end) != Some(&0)
            || ru.get(slu_len_offset) != Some(&(slu.len() as u8))
            || ru.get(slu_len_offset + 1..slu_len_offset + 1 + slu.len()) != Some(slu.as_slice())
        {
            return Err(UserBindError::UnsupportedProfile);
        }
        let fqpcid_offset = slu_len_offset + 1 + slu.len();
        let cos_offset = fqpcid_offset + self.fqpcid.len();
        if ru.get(fqpcid_offset..cos_offset) != Some(self.fqpcid.as_slice())
            || ru.get(cos_offset..cos_offset + 2) != Some(&[0x2c, 0x0a])
            || cos_offset + 12 != ru.len()
        {
            return Err(UserBindError::UnsupportedProfile);
        }
        let mut user = vec![0, 9, 2];
        user.extend_from_slice(&[0x40; 8]); // SNA default/blank mode.
        user.extend_from_slice(&[2, 3, 2]); // FQPCID session instance.
        user.push((1 + slu.len()) as u8);
        user.push(5);
        user.extend_from_slice(&slu);
        let mut response = vec![self.request[0], 0, self.oaf, self.daf, 0, 0, 0xeb, 0x80, 0];
        let mut fixed = V4R4_USER_REQUEST_FIXED;
        // IBM SC31-6808 §4-25: secondary send/primary receive stay at the
        // offered three; secondary receive/primary send use the local limit.
        // Clear adaptive pacing, security and SYNCPT claims: this candidate
        // supports only fixed pacing and CONFIRM-level APPC.
        fixed[8] = 3;
        fixed[9] = local_receive_window;
        fixed[12] = 0x80 | local_receive_window;
        fixed[13] = 3;
        fixed[23] = 0;
        fixed[24] = 0x23;
        response.extend_from_slice(&fixed);
        response.extend_from_slice(&[0, user.len() as u8]);
        response.extend_from_slice(&user);
        response.extend_from_slice(&[0, 0]);
        response.extend_from_slice(&self.fqpcid);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fid2_session_control::ManagementPacing;
    use crate::user_pacing::UserPacingSession;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn management_piu() -> Vec<u8> {
        // Sanitized live V4R4 SNASVCMG BIND, separate session instance.
        hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601411111111111111110b1111111111111111111111",
            "2c0a00000000000000000000"
        ))
    }

    fn management() -> ManagementBind {
        ManagementBind::from_request(&management_piu(), "SOLNET.SNAA", "SOLNET.SNAB").unwrap()
    }

    fn user() -> Vec<u8> {
        // Sanitized third live probe p35: blank/default mode, DAF2/OAF2.
        hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902404040404040404009030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c2601422222222222222220b2222222222222222222222",
            "2c0a01087bc3d6d5d5c5c3e3"
        ))
    }

    fn with_qa_names(piu: &[u8], plu: &str, slu: &str) -> Vec<u8> {
        // Rebuild the captured V4 request using its length-qualified fields;
        // only identities and the FQPCID CP name change.
        let ru = &piu[9..];
        let old_plu_len = ru[27] as usize;
        let user_len_offset = 28 + old_plu_len;
        let user_start = user_len_offset + 1;
        let user_end = user_start + ru[user_len_offset] as usize;
        let old_slu_len_offset = user_end + 1;
        let old_fqpcid_offset = old_slu_len_offset + 1 + ru[old_slu_len_offset] as usize;
        let old_fqpcid = request_fqpcid(ru).unwrap();
        let plu = ebcdic_lu(plu).unwrap();
        let slu = ebcdic_lu(slu).unwrap();
        let mut user = vec![0];
        let mut cursor = user_start + 1;
        while cursor < user_end {
            let len = ru[cursor] as usize;
            if ru[cursor + 1] == 4 {
                user.extend_from_slice(&[(1 + plu.len()) as u8, 4]);
                user.extend_from_slice(&plu);
            } else {
                user.extend_from_slice(&ru[cursor..cursor + len + 1]);
            }
            cursor += len + 1;
        }
        let mut rebuilt = piu[..9 + 27].to_vec();
        rebuilt.push(plu.len() as u8);
        rebuilt.extend_from_slice(&plu);
        rebuilt.push(user.len() as u8);
        rebuilt.extend_from_slice(&user);
        rebuilt.extend_from_slice(&[0, slu.len() as u8]);
        rebuilt.extend_from_slice(&slu);
        rebuilt.extend_from_slice(&[0x60, (9 + plu.len()) as u8]);
        rebuilt.extend_from_slice(&old_fqpcid[2..10]);
        rebuilt.push(plu.len() as u8);
        rebuilt.extend_from_slice(&plu);
        rebuilt.extend_from_slice(&ru[old_fqpcid_offset + old_fqpcid.len()..]);
        rebuilt
    }

    #[test]
    fn cross_netid_qa_management_and_user_binds_keep_variable_lengths() {
        let mgmt = with_qa_names(&management_piu(), "QABOB.SNAB", "QAALICE.SNAA");
        let management = ManagementBind::from_request(&mgmt, "QABOB.SNAB", "QAALICE.SNAA").unwrap();
        assert_eq!(management.fqpcid().len(), 21);
        let management_response = management
            .build_v4r4_positive_response(
                &mgmt,
                ManagementPacing::FixedOneStage {
                    local_receive_window: 1,
                },
            )
            .unwrap();
        management
            .correlate_positive_response(&management_response)
            .unwrap();
        let user = with_qa_names(&user(), "QABOB.SNAB", "QAALICE.SNAA");
        let offer = UserBindOffer::from_request(&user, &management, "").unwrap();
        assert_eq!(offer.fqpcid.len(), 21);
        let response = offer.build_fixed_response(1).unwrap();
        assert_eq!(response.len(), 89);
        assert_eq!(&response[response.len() - 21..], offer.fqpcid.as_slice());
        let mut pacing = UserPacingSession::new(&offer, &management, 1).unwrap();
        pacing.mark_bind_enqueued(&response).unwrap();
        pacing.acknowledge_bind(1).unwrap();
        let mut attach = hex(concat!(
            "2c00020200010b9120",
            "230502ff0803d000400430f0f0f500130a",
            "d8c1c2d6c24be2d5c1c2",
            "0102030405060001",
            "00c512f500c112e2"
        ));
        attach.extend_from_slice(&[0; 189]);
        let route = pacing
            .observe_first_attach(&offer, &[0x30, 0xf0, 0xf0, 0xf5], &attach)
            .unwrap();
        assert_eq!(
            (route.remote_lu.as_str(), route.local_lu.as_str()),
            ("QABOB.SNAB", "QAALICE.SNAA")
        );
        let mut malformed = user;
        let cv = malformed
            .windows(2)
            .position(|pair| pair == [0x60, 0x13])
            .unwrap();
        malformed[cv + 10] = 11; // Inconsistent inner CP-name length.
        assert!(UserBindOffer::from_request(&malformed, &management, "").is_err());

        let outbound = with_qa_names(&management_piu(), "QAALICE.SNAA", "QABOB.SNAB");
        let opposite =
            ManagementBind::from_request(&outbound, "QAALICE.SNAA", "QABOB.SNAB").unwrap();
        assert_eq!(opposite.fqpcid().len(), 23);
        opposite
            .build_v4r4_positive_response(
                &outbound,
                ManagementPacing::FixedOneStage {
                    local_receive_window: 1,
                },
            )
            .unwrap();
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
        let candidate = offer.build_fixed_response(1).unwrap();
        assert_eq!(candidate.len(), 89);
        assert_eq!(&candidate[..9], &[0x2d, 0, 2, 2, 0, 0, 0xeb, 0x80, 0]);
        assert_eq!(&candidate[17..23], &[3, 1, 0xc7, 0xc7, 0x81, 3]);
        assert_eq!(&candidate[candidate.len() - 22..], &offer.fqpcid);
        assert_eq!(candidate[9 + 23], 0); // no security/password substitution
        assert_eq!(candidate[9 + 24], 0x23); // CONFIRM; no SYNCPT claim
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
        let reused = UserBindOffer::from_request_after_management(
            &same_address,
            &mgmt,
            UserBindPolicy {
                plu: "SOLNET.SNAA",
                slu: "SOLNET.SNAB",
                mode: "",
            },
        )
        .unwrap();
        assert_eq!((reused.daf, reused.oaf), mgmt.request_addresses());
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
        let mut unsupported = user();
        unsupported[9 + 10] ^= 1; // unvalidated request fixed profile
        let offer = UserBindOffer::from_request(&unsupported, &mgmt, "").unwrap();
        assert_eq!(
            offer.build_fixed_response(1),
            Err(UserBindError::UnsupportedProfile)
        );
    }

    #[test]
    fn explicit_policy_can_select_distinct_application_lus() {
        let mgmt = management();
        let mut piu = user();
        for (old, new) in [
            ("SOLNET.SNAA", "SOLNET.APPA"),
            ("SOLNET.SNAB", "SOLNET.APPB"),
        ] {
            let old = ebcdic_lu(old).unwrap();
            let new = ebcdic_lu(new).unwrap();
            for index in 0..=piu.len() - old.len() {
                if piu[index..index + old.len()] == old {
                    piu[index..index + new.len()].copy_from_slice(&new);
                }
            }
        }
        assert_eq!(
            UserBindOffer::from_request(&piu, &mgmt, ""),
            Err(UserBindError::WrongLuPair)
        );
        let offer = UserBindOffer::from_request_with_policy(
            &piu,
            &mgmt,
            UserBindPolicy {
                plu: "SOLNET.APPA",
                slu: "SOLNET.APPB",
                mode: "",
            },
        )
        .unwrap();
        assert_eq!(offer.plu, "SOLNET.APPA");
        assert_eq!(offer.slu, "SOLNET.APPB");
        assert_eq!(offer.build_fixed_response(1).unwrap().len(), 89);
    }
}
