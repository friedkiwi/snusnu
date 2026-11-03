//! Bounded validation of the reduced BIND/BIND_RSP images in TCP62 Connect.
//!
//! IBM's TCP62 draft §5.3.1.1.2 carries BIND connection data; V5R4 AnyNet
//! includes SNF and RH before the RU. IBM SNA Formats GA27-3136, chapters
//! 5.1 and 7, defines the LU 6.2 fixed fields and structured user data.

use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindNegotiationError {
    Truncated,
    Unsupported,
    WrongSession,
    WrongMode,
    InvalidCapabilities,
}

impl fmt::Display for BindNegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid TCP62 BIND negotiation: {self:?}")
    }
}

impl Error for BindNegotiationError {}

struct BindFields<'a> {
    fixed: &'a [u8],
    mode: Vec<u8>,
    slu: &'a [u8],
    user_slu: Option<Vec<u8>>,
    fqpcid: &'a [u8],
}

fn take_len<'a>(ru: &'a [u8], offset: &mut usize) -> Result<&'a [u8], BindNegotiationError> {
    let length = *ru.get(*offset).ok_or(BindNegotiationError::Truncated)? as usize;
    let start = *offset + 1;
    let end = start
        .checked_add(length)
        .ok_or(BindNegotiationError::Truncated)?;
    let field = ru.get(start..end).ok_or(BindNegotiationError::Truncated)?;
    *offset = end;
    Ok(field)
}

/// X'60' FQPCID has an eight-byte PCID followed by a variable length
/// network-qualified CP name (IBM SNA Formats GA27-3136, chapter 8).
pub(crate) fn fqpcid_at(data: &[u8], offset: usize) -> Result<&[u8], BindNegotiationError> {
    let header = data
        .get(offset..offset + 11)
        .ok_or(BindNegotiationError::Truncated)?;
    let cp_len = header[10] as usize;
    if header[0] != 0x60 || !(3..=17).contains(&cp_len) || header[1] as usize != 9 + cp_len {
        return Err(BindNegotiationError::Unsupported);
    }
    data.get(offset..offset + 11 + cp_len)
        .ok_or(BindNegotiationError::Truncated)
}

fn user_identity(user: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), BindNegotiationError> {
    if user.first() != Some(&0) {
        return Err(BindNegotiationError::Unsupported);
    }
    let mut cursor = 1;
    let mut found = None;
    let mut user_slu = None;
    while cursor < user.len() {
        let size = user[cursor] as usize;
        let end = cursor + 1 + size;
        if size == 0 || end > user.len() {
            return Err(BindNegotiationError::Unsupported);
        }
        if user[cursor + 1] == 2 {
            if found.is_some() || size > 9 {
                return Err(BindNegotiationError::Unsupported);
            }
            let name = &user[cursor + 2..end];
            let trimmed = name
                .iter()
                .rposition(|&byte| byte != 0x40)
                .map_or(0, |i| i + 1);
            found = Some(name[..trimmed].to_vec());
        } else if user[cursor + 1] == 5 {
            if user_slu.is_some() || size < 2 {
                return Err(BindNegotiationError::Unsupported);
            }
            user_slu = Some(user[cursor + 2..end].to_vec());
        }
        cursor = end;
    }
    Ok((found.unwrap_or_default(), user_slu))
}

fn fields(data: &[u8], response: bool) -> Result<BindFields<'_>, BindNegotiationError> {
    if data.len() < 5 + 27 + 4 || data[5] != 0x31 {
        return Err(BindNegotiationError::Truncated);
    }
    if (response && data[2..5] != [0xeb, 0x80, 0])
        || (!response && (data[2] & 0xe0 != 0x60 || data[3] & 0x01 != 0))
    {
        return Err(BindNegotiationError::Unsupported);
    }
    let ru = &data[5..];
    if ru[2..4] != [0x13, 0x07] || ru[14..16] != [0x06, 0x02] || ru[26] != 0 {
        return Err(BindNegotiationError::Unsupported);
    }
    let mut cursor = 27;
    let plu = take_len(ru, &mut cursor)?;
    let user = take_len(ru, &mut cursor)?;
    let urc = take_len(ru, &mut cursor)?;
    let slu = take_len(ru, &mut cursor)?;
    if (response && (!plu.is_empty() || !slu.is_empty())) || !urc.is_empty() {
        return Err(BindNegotiationError::Unsupported);
    }
    let fqpcid = fqpcid_at(ru, cursor)?;
    let (mode, user_slu) = user_identity(user)?;
    Ok(BindFields {
        fixed: &ru[..27],
        mode,
        slu,
        user_slu,
        fqpcid,
    })
}

/// Validate the native BIND correlation that TCP62 itself does not provide:
/// the mode, FQPCID, LU 6.2 profile, and negotiated capabilities.
pub fn validate_positive_response(
    request: &[u8],
    response: &[u8],
) -> Result<(), BindNegotiationError> {
    let request = fields(request, false)?;
    let response = fields(response, true)?;
    if request.fqpcid != response.fqpcid {
        return Err(BindNegotiationError::WrongSession);
    }
    if request.mode != response.mode {
        return Err(BindNegotiationError::WrongMode);
    }
    if response.user_slu.as_deref() != Some(request.slu) {
        return Err(BindNegotiationError::WrongSession);
    }
    if request.mode == [0xd8, 0xd9, 0xd4, 0xe3, 0xe6, 0xe2, 0xc3] {
        // V5R4's 5494 controller response negotiates seven pacing slots and
        // changes FM usage/characteristics while retaining LU6.2 identity.
        if request.fixed[..6] != response.fixed[..6]
            || request.fixed[6] != 0xd0
            || response.fixed[6] != 0x50
            || request.fixed[7] != response.fixed[7]
            || response.fixed[8..10] != [0, 7]
            || request.fixed[10..12] != response.fixed[10..12]
            || response.fixed[12..14] != [0x87, 0]
            || request.fixed[14..23] != response.fixed[14..23]
            || response.fixed[23] != 0x90
            || request.fixed[24..27] != response.fixed[24..27]
        {
            return Err(BindNegotiationError::Unsupported);
        }
    } else if request.fixed[..8] != response.fixed[..8]
        || request.fixed[14..23] != response.fixed[14..23]
        || request.fixed[25..27] != response.fixed[25..27]
    {
        return Err(BindNegotiationError::Unsupported);
    }
    let requested = request.fixed[24];
    let accepted = response.fixed[24];
    let sync = accepted & 0x60;
    if (sync != 0x20 && sync != 0x40)
        || (requested & 0x60 == 0x20 && sync != 0x20)
        || accepted & 0x03 != requested & 0x03
        || accepted & 0x9c != 0
        || (request.mode != [0xd8, 0xd9, 0xd4, 0xe3, 0xe6, 0xe2, 0xc3]
            && response.fixed[23] & !request.fixed[23] != 0)
    {
        return Err(BindNegotiationError::InvalidCapabilities);
    }
    if request.slu.is_empty() {
        return Err(BindNegotiationError::Unsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // Reduced SNF/RH/RU images from V5R4 direct AnyNet p7/p9. No app payload.
    const REQUEST: &str = "00006b800031001307b0b0513303838c8c8303060200000000000000944300000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301238ff2ee2700000c04e2d6d3d5c5e34be2d5c1c10a1300b0238ff2ee270000000be2d6d3d5c5e34be2d5c1c26014cec37477b5dc299a0be2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e3";
    const RESPONSE: &str = "0000eb800031001307b0b0513303038c8c830306020000000000000094430000002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20a1300b0238ff4f5c3000000006014cec37477b5dc299a0be2d6d3d5c5e34be2d5c1c1";
    const V4R4_REQUEST: &str = "00006b840031001307b0b051330383c7c78303060200000000000000944340000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301235069de6780000c04e2d6d3d5c5e34be2d5c1c10a1300b0235069de678000000be2d6d3d5c5e34be2d5c1c26014cec37477b5dbed8d0be2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e3";
    const V4R4_RESPONSE: &str = "0000eb800031001307b0b051330080c7c7800006020000000000000094434000002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20a1300b023506a33da800000006014cec37477b5dbed8d0be2d6d3d5c5e34be2d5c1c1";

    #[test]
    fn accepts_observed_v5r4_5494_controller_bind_response() {
        let request = hex(concat!(
            "00006b800031001307b0b0d0b300008686800006020000000000000000230000",
            "0ee2d5e4e2d5e44bd7d9c9d5e3c5d91a000802d8d9d4e3e6e2c30f04",
            "e2d5e4e2d5e44bd7d9c9d5e3c5d9000fe2d6d3d5c5e34be2f1f0f5f4f5f0f4",
            "6013b35f896bd26878d10ae2d5e4e2d5e44be2e5c3"
        ));
        let response = hex(concat!(
            "0000eb800031001307b0b050b30007868687000602000000000000009023000000",
            "1b000802d8d9d4e3e6e2c31005e2d6d3d5c5e34be2f1f0f5f4f5f0f40000",
            "6013b35f896bd26878d10ae2d5e4e2d5e44be2e5c3"
        ));
        assert_eq!(validate_positive_response(&request, &response), Ok(()));
    }

    #[test]
    fn accepts_captured_anynet_bind_negotiation_and_confirm_downgrade() {
        let request = hex(REQUEST);
        let response = hex(RESPONSE);
        assert_eq!(validate_positive_response(&request, &response), Ok(()));
        let mut confirm_only = response;
        confirm_only[5 + 24] = 0x23;
        assert_eq!(validate_positive_response(&request, &confirm_only), Ok(()));
        assert_eq!(
            validate_positive_response(&hex(V4R4_REQUEST), &hex(V4R4_RESPONSE)),
            Ok(())
        );
    }

    #[test]
    fn rejects_wrong_session_mode_and_undefined_sync_level() {
        let request = hex(REQUEST);
        let response = hex(RESPONSE);
        let mut wrong = response.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert_eq!(
            validate_positive_response(&request, &wrong),
            Err(BindNegotiationError::WrongSession)
        );
        wrong = response.clone();
        wrong[5 + 24] = 0x03;
        assert_eq!(
            validate_positive_response(&request, &wrong),
            Err(BindNegotiationError::InvalidCapabilities)
        );
        wrong = response;
        let mode_pos = wrong.windows(8).position(|part| part == [0x40; 8]).unwrap();
        wrong[mode_pos] = 0xc1;
        assert_eq!(
            validate_positive_response(&request, &wrong),
            Err(BindNegotiationError::WrongMode)
        );
        let mut wrong_lu = hex(RESPONSE);
        let slu_pos = wrong_lu
            .windows(12)
            .position(|part| {
                part == [
                    0x0c, 0x05, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1,
                ]
            })
            .unwrap();
        wrong_lu[slu_pos + 11] ^= 1;
        assert_eq!(
            validate_positive_response(&request, &wrong_lu),
            Err(BindNegotiationError::WrongSession)
        );
    }
}
