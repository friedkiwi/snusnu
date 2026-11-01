//! Conservative classification of a complete FID2 LU 6.2 BIND request.
//!
//! Layout: IBM *SNA Formats*, GA27-3136, chapters 3, 4, 5.1 (BIND), and 7
//! (structured User Data). In particular the mode is subfield X'02', not a
//! fixed offset or a property of the FID2 session addresses. CP-CP and SNA
//! management sessions also use LU 6.2; an unknown mode is never assumed to
//! be an application session.

use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindClass {
    /// IBM-reserved management mode; never forward to an AnyNet LU session.
    Management { mode: String },
    /// A named non-management mode. Policy must still check both LU names.
    NamedLu62 { mode: String },
    /// No usable mode was present. Policy must reject until identity is known.
    Undetermined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindInfo {
    pub class: BindClass,
    pub daf: u8,
    pub oaf: u8,
    /// Network-qualified when the BIND supplies a network ID.
    pub plu: String,
    pub slu: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindError {
    Truncated,
    UnsupportedPiu,
    UnsupportedBind,
    InvalidStructure,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid FID2 LU6.2 BIND: {self:?}")
    }
}

impl Error for BindError {}

/// Returns `None` for a complete FID2 PIU that is not a BIND request.
/// Returns an error for a truncated, segmented, or unsupported candidate.
pub fn classify_bind(piu: &[u8]) -> Result<Option<BindInfo>, BindError> {
    if piu.len() < 6 {
        return Err(BindError::Truncated);
    }
    if piu[0] >> 4 != 2 || ((piu[0] >> 2) & 3) != 3 || piu[0] & 0x08 == 0 {
        return Err(BindError::UnsupportedPiu);
    }
    if piu.len() < 9 {
        return Err(BindError::Truncated);
    }
    // Session Control request with a complete, unsegmented RU.
    if piu[6] & 0xe0 != 0x60 || piu.len() == 9 || piu[9] != 0x31 {
        return Ok(None);
    }
    if piu.len() < 9 + 28 {
        return Err(BindError::Truncated);
    }
    let ru = &piu[9..];
    if ru.len() > 256 {
        return Err(BindError::UnsupportedBind);
    }
    // LU 6.2 requires FM profile 19, TS profile 7, and PS type 6 level 2.
    if ru[2] != 0x13 || ru[3] != 0x07 || ru[14] != 0x06 || ru[15] != 0x02 {
        return Err(BindError::UnsupportedBind);
    }
    // Cryptographic option fields make the following field offsets variable.
    // This parser intentionally handles only the no-cryptography layout.
    if ru[26] != 0 {
        return Err(BindError::UnsupportedBind);
    }
    let mut offset = 27;
    let plu_len = usize::from(ru[offset]);
    if !(1..=17).contains(&plu_len) {
        return Err(BindError::InvalidStructure);
    }
    let plu_start = offset + 1;
    offset = offset
        .checked_add(1 + plu_len)
        .filter(|&end| end < ru.len())
        .ok_or(BindError::Truncated)?;
    let plu = decode_lu_name(&ru[plu_start..offset])?;
    let user_len = usize::from(ru[offset]);
    offset += 1;
    let end = offset
        .checked_add(user_len)
        .filter(|&end| end <= ru.len())
        .ok_or(BindError::Truncated)?;
    let mut mode = None;
    let mut previous_key = None;
    if user_len > 0 {
        if ru[offset] != 0 {
            return Err(BindError::UnsupportedBind);
        }
        offset += 1;
    }
    while offset < end {
        let length = usize::from(ru[offset]);
        if length < 1 || offset + 1 + length > end {
            return Err(BindError::InvalidStructure);
        }
        let key = ru[offset + 1];
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(BindError::InvalidStructure);
        }
        previous_key = Some(key);
        if key == 2 {
            if length > 9 {
                return Err(BindError::InvalidStructure);
            }
            mode = Some(decode_mode(&ru[offset + 2..offset + 1 + length])?);
        }
        offset += 1 + length;
    }
    // A negotiable BIND carries URC length followed by secondary LU name.
    // This parser requires both identities before allowing route selection.
    if end >= ru.len() {
        return Err(BindError::Truncated);
    }
    let urc_len = usize::from(ru[end]);
    if urc_len > 12 {
        return Err(BindError::InvalidStructure);
    }
    let slu_len_offset = end
        .checked_add(1 + urc_len)
        .filter(|&offset| offset < ru.len())
        .ok_or(BindError::Truncated)?;
    let slu_len = usize::from(ru[slu_len_offset]);
    if !(1..=17).contains(&slu_len) {
        return Err(BindError::InvalidStructure);
    }
    let slu_start = slu_len_offset + 1;
    let slu_end = slu_start
        .checked_add(slu_len)
        .filter(|&end| end <= ru.len())
        .ok_or(BindError::Truncated)?;
    let slu = decode_lu_name(&ru[slu_start..slu_end])?;
    let class = match mode.filter(|name| !name.is_empty()) {
        Some(mode) if matches!(mode.as_str(), "SNASVCMG" | "CPSVCMG" | "CPSVCMGR") => {
            BindClass::Management { mode }
        }
        Some(mode) => BindClass::NamedLu62 { mode },
        None => BindClass::Undetermined,
    };
    Ok(Some(BindInfo {
        class,
        daf: piu[2],
        oaf: piu[3],
        plu,
        slu,
    }))
}

fn decode_mode(bytes: &[u8]) -> Result<String, BindError> {
    let mut name = String::new();
    let mut padding = false;
    for &byte in bytes {
        if byte == 0x40 {
            padding = true;
            continue;
        }
        if padding {
            return Err(BindError::InvalidStructure);
        }
        let c = match byte {
            0xc1..=0xc9 => (b'A' + (byte - 0xc1)) as char,
            0xd1..=0xd9 => (b'J' + (byte - 0xd1)) as char,
            0xe2..=0xe9 => (b'S' + (byte - 0xe2)) as char,
            0xf0..=0xf9 => (b'0' + (byte - 0xf0)) as char,
            0x7c => '@',
            0x7b => '#',
            0x5b => '$',
            _ => return Err(BindError::InvalidStructure),
        };
        name.push(c);
    }
    Ok(name)
}

fn decode_lu_name(bytes: &[u8]) -> Result<String, BindError> {
    let mut name = String::new();
    let mut padding = false;
    for &byte in bytes {
        if byte == 0x40 {
            padding = true;
            continue;
        }
        if padding {
            return Err(BindError::InvalidStructure);
        }
        if byte == 0x4b {
            name.push('.');
        } else {
            name.push(decode_mode(&[byte])?.chars().next().unwrap());
        }
    }
    let mut parts = name.split('.');
    let first = parts.next().unwrap_or("");
    let second = parts.next();
    if first.is_empty()
        || first.len() > 8
        || second.is_some_and(|part| part.is_empty() || part.len() > 8)
        || parts.next().is_some()
    {
        return Err(BindError::InvalidStructure);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind_with_mode(subfield: &[u8]) -> Vec<u8> {
        // Sanitized form of the V4R4 LU6.2 BIND shape: synthetic PLU `ABC`,
        // SLU `DEF`, with only the mode subfield retained from User Data.
        let mut piu = vec![0x2d, 0, 1, 2, 0, 0, 0x6b, 0x85, 0];
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14] = 6;
        ru[15] = 2;
        ru.extend_from_slice(&[3, 0xc1, 0xc2, 0xc3]);
        ru.push((1 + subfield.len()) as u8);
        ru.push(0); // structured User Data key
        ru.extend_from_slice(subfield);
        ru.extend_from_slice(&[0, 3, 0xc4, 0xc5, 0xc6]); // URC, SLU `DEF`
        piu.extend(ru);
        piu
    }

    #[test]
    fn classifies_captured_management_mode_shape() {
        let piu = bind_with_mode(&[9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]);
        assert_eq!(
            classify_bind(&piu),
            Ok(Some(BindInfo {
                class: BindClass::Management {
                    mode: "SNASVCMG".into(),
                },
                daf: 1,
                oaf: 2,
                plu: "ABC".into(),
                slu: "DEF".into(),
            }))
        );
    }

    #[test]
    fn blank_or_missing_mode_is_undetermined() {
        let blank = bind_with_mode(&[1, 2]);
        assert_eq!(
            classify_bind(&blank),
            Ok(Some(BindInfo {
                class: BindClass::Undetermined,
                daf: 1,
                oaf: 2,
                plu: "ABC".into(),
                slu: "DEF".into(),
            }))
        );
        let missing = bind_with_mode(&[]);
        assert_eq!(
            classify_bind(&missing),
            Ok(Some(BindInfo {
                class: BindClass::Undetermined,
                daf: 1,
                oaf: 2,
                plu: "ABC".into(),
                slu: "DEF".into(),
            }))
        );
    }

    #[test]
    fn named_application_mode_requires_lu_policy() {
        let piu = bind_with_mode(&[8, 2, 0xc1, 0xd7, 0xd7, 0xe3, 0xc5, 0xe2, 0xe3]);
        assert_eq!(
            classify_bind(&piu),
            Ok(Some(BindInfo {
                class: BindClass::NamedLu62 {
                    mode: "APPTEST".into(),
                },
                daf: 1,
                oaf: 2,
                plu: "ABC".into(),
                slu: "DEF".into(),
            }))
        );
    }

    #[test]
    fn rejects_truncated_and_malformed_mode() {
        let piu = bind_with_mode(&[9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]);
        assert_eq!(
            classify_bind(&piu[..piu.len() - 1]),
            Err(BindError::Truncated)
        );
        let mut bad = piu.clone();
        bad[9 + 33] = 0xff;
        assert_eq!(classify_bind(&bad), Err(BindError::InvalidStructure));
        let mut segmented = piu;
        segmented[0] = 0x28;
        assert_eq!(classify_bind(&segmented), Err(BindError::UnsupportedPiu));
    }

    #[test]
    fn response_and_other_session_units_are_not_bind_requests() {
        let mut response = bind_with_mode(&[1, 2]);
        response[6] = 0xeb;
        assert_eq!(classify_bind(&response), Ok(None));
        let mut unbind = bind_with_mode(&[1, 2]);
        unbind[9] = 0x32;
        assert_eq!(classify_bind(&unbind), Ok(None));
    }

    #[test]
    fn rejects_missing_or_invalid_lu_identity() {
        let piu = bind_with_mode(&[1, 2]);
        let mut missing_slu = piu.clone();
        let slu_length_offset = missing_slu.len() - 4;
        missing_slu[slu_length_offset] = 0;
        assert_eq!(
            classify_bind(&missing_slu),
            Err(BindError::InvalidStructure)
        );
        let mut invalid_plu = piu;
        invalid_plu[9 + 28] = 0xff;
        assert_eq!(
            classify_bind(&invalid_plu),
            Err(BindError::InvalidStructure)
        );
    }
}
