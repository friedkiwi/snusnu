//! Narrow FID2 session-control checks for a native LU 6.2 management peer.
//!
//! IBM *SNA Formats* GA27-3136 describes BIND responses and adaptive isolated
//! pacing messages (IPMs); *LU 6.2 Reference: Peer Protocols* SC31-6808-0 §4
//! requires an SLU to negotiate a positive BIND response before using the
//! session. This module correlates headers and identities. It does not derive
//! the negotiated BIND parameters or declare a session active.

use crate::fid2_bind::{classify_bind, BindClass, BindError};
use std::{error::Error, fmt};

const V4R4_MANAGEMENT_REQUEST_FIXED: [u8; 27] = [
    0x31, 0x00, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33, 0x07, 0x87, 0x86, 0x86, 0x87, 0x07, 0x06, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0x43, 0x40, 0x00,
];
// IBM SC31-6808-0 §4-24/25: when both halves support adaptive pacing the
// negotiated send/receive windows become zero. Preserve the staging and
// adaptive-pacing indicators; all remaining supported fixed fields agree.
const V4R4_MANAGEMENT_RESPONSE_FIXED: [u8; 27] = [
    0x31, 0x00, 0x13, 0x07, 0xb0, 0xb0, 0x51, 0x33, 0x00, 0x80, 0x86, 0x86, 0x80, 0x00, 0x06, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x40, 0x00,
];
const SNASVCMG: [u8; 8] = [0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];

/// Session-level pacing selected by the local SLU for +RSP(BIND).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementPacing {
    /// Both sides use adaptive session-level pacing; requires IPM handling.
    Adaptive,
    /// One-stage fixed pacing. `local_receive_window` limits normal-flow
    /// requests arriving from the PLU and requires IPR/window accounting.
    FixedOneStage { local_receive_window: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionControlError {
    InvalidRequest(BindError),
    WrongMode,
    WrongLuPair,
    UnsupportedRequest,
    TruncatedResponse,
    WrongResponse,
    WrongSession,
    UnsupportedResponse,
}

impl fmt::Display for SessionControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native LU6.2 session control: {self:?}")
    }
}

impl Error for SessionControlError {}

/// The identities and FID2 addresses associated with one SNASVCMG BIND.
/// This is only a correlation gate. A separate session manager must negotiate
/// every BIND parameter and its control vectors before sending +RSP(BIND).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementBind {
    plu: String,
    slu: String,
    request_daf: u8,
    request_oaf: u8,
    odai: u8,
    fqpcid: [u8; 22],
}

impl ManagementBind {
    /// Accept only an inbound, complete SNASVCMG BIND for the configured LU
    /// pair. `remote_plu` is the peer's LU; `local_slu` belongs to this node.
    pub fn from_request(
        piu: &[u8],
        remote_plu: &str,
        local_slu: &str,
    ) -> Result<Self, SessionControlError> {
        let bind = classify_bind(piu)
            .map_err(SessionControlError::InvalidRequest)?
            .ok_or(SessionControlError::WrongMode)?;
        if bind.class
            != (BindClass::Management {
                mode: "SNASVCMG".into(),
            })
        {
            return Err(SessionControlError::WrongMode);
        }
        if bind.plu != remote_plu || bind.slu != local_slu {
            return Err(SessionControlError::WrongLuPair);
        }
        let fqpcid = request_fqpcid(&piu[9..])?;
        Ok(Self {
            plu: bind.plu,
            slu: bind.slu,
            request_daf: bind.daf,
            request_oaf: bind.oaf,
            odai: piu[0] & 0x02,
            fqpcid,
        })
    }

    pub fn plu(&self) -> &str {
        &self.plu
    }

    pub fn slu(&self) -> &str {
        &self.slu
    }

    pub fn request_addresses(&self) -> (u8, u8) {
        (self.request_daf, self.request_oaf)
    }

    pub fn fqpcid(&self) -> &[u8; 22] {
        &self.fqpcid
    }

    /// Check a candidate positive response's session-control envelope. The
    /// result means only that its FID2 addresses and LU 6.2 fixed profile
    /// correlate with this request. The captured V4R4 response omits both LU
    /// names; the FQPCID and reversed FID2 addresses tie it to the request.
    /// Remaining negotiable fields need validation before transmission.
    pub fn correlate_positive_response(&self, piu: &[u8]) -> Result<(), SessionControlError> {
        if piu.len() < 9 + 28 {
            return Err(SessionControlError::TruncatedResponse);
        }
        if piu.len() > 9 + 256
            || piu[0] >> 4 != 2
            || ((piu[0] >> 2) & 3) != 3
            || piu[0] & 0x02 != self.odai
        {
            return Err(SessionControlError::UnsupportedResponse);
        }
        if piu[2] != self.request_oaf || piu[3] != self.request_daf {
            return Err(SessionControlError::WrongSession);
        }
        // Positive response, category Session Control. The V4R4 negotiated
        // BIND carries RH EB 80 00; tolerate the FID2 TH's variable flags.
        if piu[6..9] != [0xeb, 0x80, 0x00] || piu[9] != 0x31 {
            return Err(SessionControlError::WrongResponse);
        }
        let ru = &piu[9..];
        if ru[2] != 0x13 || ru[3] != 0x07 || ru[14] != 0x06 || ru[15] != 0x02 {
            return Err(SessionControlError::UnsupportedResponse);
        }
        let (mode, fqpcid) = response_mode_and_fqpcid(ru)?;
        if !mode {
            return Err(SessionControlError::WrongMode);
        }
        if fqpcid != self.fqpcid {
            return Err(SessionControlError::WrongSession);
        }
        Ok(())
    }

    /// Construct one positive RSP(BIND) for the observed V4R4 SNASVCMG
    /// profile. This is intentionally narrower than generic LU 6.2 BIND
    /// negotiation: other fixed parameter sets, cryptography, and unrecognized
    /// control vectors are rejected. Structured user subfield X'13' is ignored
    /// as required for an unrecognized subfield. The caller must implement
    /// the selected adaptive IPM or fixed IPR pacing, CNOS, parallel-session
    /// behavior, and CONFIRM before transmitting. Unlike the captured OS/400
    /// response, byte 23 is zero because this peer provides no conversation
    /// security or password substitution; byte 24 negotiates CONFIRM rather
    /// than claiming SYNCPT/backout support.
    pub fn build_v4r4_positive_response(
        &self,
        request_piu: &[u8],
        pacing: ManagementPacing,
    ) -> Result<Vec<u8>, SessionControlError> {
        if ManagementBind::from_request(request_piu, &self.plu, &self.slu)? != *self {
            return Err(SessionControlError::WrongSession);
        }
        // GA27-3136-12 RH byte 1: X'80' requests DR1; X'85' additionally
        // sets the pacing and larger-window indicators. Both occur on the
        // same V4R4 management BIND profile. The response does not echo PI.
        if request_piu[1] != 0
            || request_piu[4..6] != [0, 0]
            || request_piu[6] != 0x6b
            || !matches!(request_piu[7], 0x80 | 0x85)
            || request_piu[8] != 0
        {
            return Err(SessionControlError::UnsupportedRequest);
        }
        let ru = &request_piu[9..];
        if ru.get(..27) != Some(&V4R4_MANAGEMENT_REQUEST_FIXED) {
            return Err(SessionControlError::UnsupportedRequest);
        }
        validate_v4r4_request_tail(ru, &self.plu, &self.fqpcid)?;
        let slu = encode_lu_name(&self.slu)?;
        let mut user = vec![0x00, 0x09, 0x02];
        user.extend_from_slice(&SNASVCMG);
        // X'03': both sides use the FQPCID as the session-instance ID.
        user.extend_from_slice(&[0x02, 0x03, 0x02]);
        user.push((1 + slu.len()) as u8);
        user.push(0x05);
        user.extend_from_slice(&slu);
        let mut response = vec![
            request_piu[0],
            0,
            self.request_oaf,
            self.request_daf,
            0,
            0,
            0xeb,
            0x80,
            0,
        ];
        let mut fixed = V4R4_MANAGEMENT_RESPONSE_FIXED;
        if let ManagementPacing::FixedOneStage {
            local_receive_window,
        } = pacing
        {
            if !(1..=7).contains(&local_receive_window) {
                return Err(SessionControlError::UnsupportedResponse);
            }
            // GA27-3136-19 §6-29 permits the SLU to clear the adaptive bit.
            // SC31-6808-0 §4-25: with one-stage pacing, secondary send is
            // taken from primary receive (7); secondary receive is bounded
            // by the local installation limit; primary send equals that
            // negotiated secondary receive; primary receive stays 7.
            fixed[8] = 7;
            fixed[9] = local_receive_window;
            fixed[12] = 0x80 | local_receive_window;
            fixed[13] = 7;
        }
        response.extend_from_slice(&fixed);
        response.extend_from_slice(&[0, user.len() as u8]); // No outer PLU name.
        response.extend_from_slice(&user);
        response.extend_from_slice(&[0, 0]); // No URC or outer SLU name.
        response.extend_from_slice(&self.fqpcid);
        self.correlate_positive_response(&response)?;
        Ok(response)
    }
}

fn validate_v4r4_request_tail(
    ru: &[u8],
    plu: &str,
    fqpcid: &[u8; 22],
) -> Result<(), SessionControlError> {
    let plu_len = ru[27] as usize;
    let user_len_offset = 28 + plu_len;
    let user_len = *ru
        .get(user_len_offset)
        .ok_or(SessionControlError::UnsupportedRequest)? as usize;
    let user_start = user_len_offset + 1;
    let user_end = user_start + user_len;
    let user = ru
        .get(user_start..user_end)
        .ok_or(SessionControlError::UnsupportedRequest)?;
    if user.first() != Some(&0)
        || ru.get(28..user_len_offset) != Some(encode_lu_name(plu)?.as_slice())
    {
        return Err(SessionControlError::UnsupportedRequest);
    }
    let mut cursor = 1;
    let mut found_instance = false;
    let mut found_plu = false;
    while cursor < user.len() {
        let length = user[cursor] as usize;
        let end = cursor + 1 + length;
        let subfield = user
            .get(cursor + 1..end)
            .ok_or(SessionControlError::UnsupportedRequest)?;
        match subfield.first() {
            Some(2) if length == 9 && subfield[1..] == SNASVCMG => {}
            Some(3) if length == 9 && subfield[1] == 1 => found_instance = true,
            Some(4) if subfield[1..] == encode_lu_name(plu)? => found_plu = true,
            Some(0x13) if length == 10 => {} // Unknown V4R4 extension: do not echo.
            _ => return Err(SessionControlError::UnsupportedRequest),
        }
        cursor = end;
    }
    if !found_instance || !found_plu {
        return Err(SessionControlError::UnsupportedRequest);
    }
    let urc_len = *ru
        .get(user_end)
        .ok_or(SessionControlError::UnsupportedRequest)? as usize;
    if urc_len != 0 {
        return Err(SessionControlError::UnsupportedRequest);
    }
    let slu_len_offset = user_end + 1;
    let slu_len = *ru
        .get(slu_len_offset)
        .ok_or(SessionControlError::UnsupportedRequest)? as usize;
    let fqpcid_offset = slu_len_offset + 1 + slu_len;
    if ru.get(fqpcid_offset..fqpcid_offset + 22) != Some(fqpcid.as_slice()) {
        return Err(SessionControlError::WrongSession);
    }
    let trailing = &ru[fqpcid_offset + 22..];
    if !trailing.is_empty() && (trailing.len() != 12 || trailing[..2] != [0x2c, 0x0a]) {
        return Err(SessionControlError::UnsupportedRequest);
    }
    Ok(())
}

fn encode_lu_name(name: &str) -> Result<Vec<u8>, SessionControlError> {
    if name.len() > 17 || name.is_empty() {
        return Err(SessionControlError::WrongLuPair);
    }
    name.bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => return Err(SessionControlError::WrongLuPair),
            })
        })
        .collect()
}

pub(crate) fn request_fqpcid(ru: &[u8]) -> Result<[u8; 22], SessionControlError> {
    let mut offset = 27;
    for _ in 0..4 {
        let length = *ru
            .get(offset)
            .ok_or(SessionControlError::UnsupportedRequest)? as usize;
        offset = offset
            .checked_add(1 + length)
            .filter(|&end| end <= ru.len())
            .ok_or(SessionControlError::UnsupportedRequest)?;
    }
    let vector = ru
        .get(offset..offset + 22)
        .ok_or(SessionControlError::UnsupportedRequest)?;
    if vector[..2] != [0x60, 0x14] {
        return Err(SessionControlError::UnsupportedRequest);
    }
    Ok(vector.try_into().unwrap())
}

fn response_mode_and_fqpcid(ru: &[u8]) -> Result<(bool, [u8; 22]), SessionControlError> {
    // V4R4 negotiable response: fixed 27 bytes, PLU length/name, structured
    // user data, URC length/data, SLU length/name, then the FQPCID vector.
    let plu_len = *ru.get(27).ok_or(SessionControlError::TruncatedResponse)? as usize;
    if plu_len != 0 {
        return Err(SessionControlError::UnsupportedResponse);
    }
    let user_len_offset = 28 + plu_len;
    let user_len = *ru
        .get(user_len_offset)
        .ok_or(SessionControlError::TruncatedResponse)? as usize;
    let user_start = user_len_offset + 1;
    let user_end = user_start
        .checked_add(user_len)
        .filter(|&end| end < ru.len())
        .ok_or(SessionControlError::TruncatedResponse)?;
    let user = &ru[user_start..user_end];
    if user.first() != Some(&0) {
        return Err(SessionControlError::UnsupportedResponse);
    }
    let mut cursor = 1;
    let mut mode = false;
    while cursor < user.len() {
        let length = user[cursor] as usize;
        let end = cursor + 1 + length;
        if length == 0 || end > user.len() {
            return Err(SessionControlError::UnsupportedResponse);
        }
        if user[cursor + 1] == 2 {
            mode = length == 9
                && user[cursor + 2..end] == [0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
        }
        cursor = end;
    }
    let urc_len = ru[user_end] as usize;
    let slu_len_offset = user_end + 1 + urc_len;
    let slu_len = *ru
        .get(slu_len_offset)
        .ok_or(SessionControlError::TruncatedResponse)? as usize;
    if slu_len != 0 {
        return Err(SessionControlError::UnsupportedResponse);
    }
    let fqpcid_offset = slu_len_offset + 1 + slu_len;
    let vector = ru
        .get(fqpcid_offset..fqpcid_offset + 22)
        .ok_or(SessionControlError::TruncatedResponse)?;
    if vector[..2] != [0x60, 0x14] {
        return Err(SessionControlError::UnsupportedResponse);
    }
    Ok((mode, vector.try_into().unwrap()))
}

/// A solicited adaptive pacing message (IPM) observed on native V4R4.
/// IBM GA27-3136-12 §4-13 defines its three-byte extension after the RH.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolicitedIpm {
    pub daf: u8,
    pub oaf: u8,
    /// Source TH ODAI bit. Adaptive BIND pacing uses zero; an LU session may
    /// use either value, so callers must correlate the addresses as well.
    pub odai: bool,
    pub next_window: u16,
}

pub fn solicited_ipm(piu: &[u8]) -> Option<SolicitedIpm> {
    if piu.len() != 12 || piu[0] >> 4 != 2 || ((piu[0] >> 2) & 3) != 3 {
        return None;
    }
    let next_window = u16::from_be_bytes([piu[10], piu[11]]);
    // Type 00=solicited. Reset and reserved bits are zero; next-window is
    // nonzero 15-bit. Other IPM types need explicit reset/withdrawal state.
    (piu[6..9] == [0x83, 0x01, 0x00] && piu[9] == 0 && (1..=32767).contains(&next_window))
        .then_some(SolicitedIpm {
            daf: piu[2],
            oaf: piu[3],
            odai: piu[0] & 0x02 != 0,
            next_window,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn builds_bounded_response_from_sanitized_v4r4_request() {
        // Independent p54 request: guest session instance, FQPCID, and COS
        // tokens replaced with synthetic bytes; configured lab LU names stay.
        let request = hex_bytes(concat!(
            "2f00010200006b850031001307b0b0513307878686870706020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d000902e2d5c1e2e5c3d4c709030100000000000000",
            "0c04e2d6d3d5c5e34be2d5c1c10a1300000000000000000000",
            "0be2d6d3d5c5e34be2d5c1c260141111111111111111111111111111111111111111",
            "2c0a00000000000000000000"
        ));
        assert_eq!(request.len(), 141);
        let bind = ManagementBind::from_request(&request, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let response = bind
            .build_v4r4_positive_response(&request, ManagementPacing::Adaptive)
            .unwrap();
        // SC31-6808-0 permits the unrecognized X'13' user subfield to be
        // discarded. The 89-byte expectation negotiates adaptive pacing,
        // advertises no security features or SYNCPT/backout, and carries our
        // SLU name/FQPCID.
        let expected = hex_bytes(concat!(
            "2f0002010000eb800031001307b0b0513300808686800006020000000000000000234000",
            "001b000902e2d5c1e2e5c3d4c70203020c05e2d6d3d5c5e34be2d5c1c2",
            "000060141111111111111111111111111111111111111111"
        ));
        assert_eq!(response, expected);
        assert_eq!(bind.correlate_positive_response(&response), Ok(()));

        // Independent one-guest emulator probe (native-probe-sol5.pcap):
        // identical 132-byte BIND RU, but ODAI is clear and RH requests DR1
        // without link BIND pacing. Tokens are sanitized above. Preserve ODAI
        // in the reply and do not invent a pacing indicator on +RSP(BIND).
        let mut live = request.clone();
        live[0] = 0x2d;
        live[7] = 0x80;
        let live_bind = ManagementBind::from_request(&live, "SOLNET.SNAA", "SOLNET.SNAB").unwrap();
        let live_response = live_bind
            .build_v4r4_positive_response(
                &live,
                ManagementPacing::FixedOneStage {
                    local_receive_window: 1,
                },
            )
            .unwrap();
        assert_eq!(&live_response[..9], &[0x2d, 0, 2, 1, 0, 0, 0xeb, 0x80, 0]);
        assert_eq!(&live_response[9 + 8..9 + 14], &[7, 1, 0x86, 0x86, 0x81, 7]);
        assert_eq!(
            live_bind.correlate_positive_response(&live_response),
            Ok(())
        );

        let fixed = bind
            .build_v4r4_positive_response(
                &request,
                ManagementPacing::FixedOneStage {
                    local_receive_window: 1,
                },
            )
            .unwrap();
        assert_eq!(&fixed[9 + 8..9 + 14], &[7, 1, 0x86, 0x86, 0x81, 7]);
        assert_eq!(fixed[9 + 23], 0); // No local conversation security.
        assert_eq!(fixed[9 + 24], 0x23); // CONFIRM, parallel sessions, CNOS.
        assert_eq!(bind.correlate_positive_response(&fixed), Ok(()));
        assert_eq!(
            bind.build_v4r4_positive_response(
                &request,
                ManagementPacing::FixedOneStage {
                    local_receive_window: 0,
                },
            ),
            Err(SessionControlError::UnsupportedResponse)
        );

        let mut unsupported = request.clone();
        unsupported[9 + 9] &= !0x80; // No adaptive pacing in request.
        assert_eq!(
            bind.build_v4r4_positive_response(&unsupported, ManagementPacing::Adaptive),
            Err(SessionControlError::UnsupportedRequest)
        );
        unsupported = request.clone();
        unsupported[7] = 0x81; // PI without the observed larger-window request.
        assert_eq!(
            bind.build_v4r4_positive_response(&unsupported, ManagementPacing::Adaptive),
            Err(SessionControlError::UnsupportedRequest)
        );
        unsupported = request.clone();
        unsupported[7] = 0x84;
        assert_eq!(
            bind.build_v4r4_positive_response(&unsupported, ManagementPacing::Adaptive),
            Err(SessionControlError::UnsupportedRequest)
        );
    }

    fn management_request() -> Vec<u8> {
        // Synthetic names ABC/DEF; SNASVCMG and the fixed profile match the
        // native V4R4 management BIND. No recorded guest/application bytes.
        let mut piu = vec![0x2f, 0, 1, 2, 0, 0, 0x6b, 0x85, 0];
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        ru.extend_from_slice(&[3, 0xc1, 0xc2, 0xc3]);
        ru.extend_from_slice(&[11, 0, 9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]);
        ru.extend_from_slice(&[0, 3, 0xc4, 0xc5, 0xc6]);
        ru.extend_from_slice(&[0x60, 0x14]);
        ru.extend_from_slice(&[0x11; 20]); // Synthetic FQPCID token.
        piu.extend(ru);
        piu
    }

    fn response() -> Vec<u8> {
        // Independent 100-byte V4R4 RSP(BIND) shape. Session-instance and
        // FQPCID token bytes are synthetic; identities here are lab names.
        let hex = concat!(
            "2f0002010000eb800031001307b0b05133008086868000060200000000000000944340000026",
            "000902e2d5c1e2e5c3d4c70203020c05e2d6d3d5c5e34be2d5c1c20a1300",
            "0000000000000000000060141111111111111111111111111111111111111111"
        );
        let piu = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(piu.len(), 100);
        piu
    }

    #[test]
    fn correlates_management_bind_envelope_without_claiming_negotiation() {
        let gate = ManagementBind::from_request(&management_request(), "ABC", "DEF").unwrap();
        assert_eq!(gate.request_addresses(), (1, 2));
        assert_eq!(gate.correlate_positive_response(&response()), Ok(()));
        let mut wrong = response();
        wrong[2] = 3;
        assert_eq!(
            gate.correlate_positive_response(&wrong),
            Err(SessionControlError::WrongSession)
        );
        wrong = response();
        wrong[6] = 0x6b;
        assert_eq!(
            gate.correlate_positive_response(&wrong),
            Err(SessionControlError::WrongResponse)
        );
        wrong = response();
        wrong[0] = 0x2d;
        assert_eq!(
            gate.correlate_positive_response(&wrong),
            Err(SessionControlError::UnsupportedResponse)
        );
        wrong = response();
        wrong[9 + 27] = 1; // V4R4 +RSP omits the PLU name.
        assert_eq!(
            gate.correlate_positive_response(&wrong),
            Err(SessionControlError::UnsupportedResponse)
        );
        wrong = response();
        wrong[9 + 68] = 1; // V4R4 +RSP omits the SLU name.
        assert_eq!(
            gate.correlate_positive_response(&wrong),
            Err(SessionControlError::UnsupportedResponse)
        );
    }

    #[test]
    fn rejects_other_modes_and_lu_pairs() {
        assert_eq!(
            ManagementBind::from_request(&management_request(), "ABC", "OTHER"),
            Err(SessionControlError::WrongLuPair)
        );
        let mut request = management_request();
        request[9 + 31 + 4] = 0x40;
        assert!(ManagementBind::from_request(&request, "ABC", "DEF").is_err());
    }

    #[test]
    fn recognizes_solicited_adaptive_pacing_window_grants() {
        let piu = [0x2d, 0, 1, 0, 0, 0, 0x83, 0x01, 0, 0, 0x7f, 0xff];
        assert_eq!(
            solicited_ipm(&piu),
            Some(SolicitedIpm {
                daf: 1,
                oaf: 0,
                odai: false,
                next_window: 32767
            })
        );
        assert_eq!(solicited_ipm(&piu[..9]), None);
        let mut not_pacing = piu;
        not_pacing[7] = 0;
        assert_eq!(solicited_ipm(&not_pacing), None);
        not_pacing = piu;
        not_pacing[9] = 0x40; // Unsolicited needs reset handling.
        assert_eq!(solicited_ipm(&not_pacing), None);
    }
}
