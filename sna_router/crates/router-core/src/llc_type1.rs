//! Local LLC Type 1 TEST/XID responses for one configured MAC/SAP.
//!
//! XID information is supplied by the caller. In particular, an SNA XID3
//! contains endpoint identity and capabilities that this module cannot infer.
//! An absent XID response payload leaves the command unanswered.

use crate::llc::{Control, LlcFrame};

const XID: u8 = 0xaf;
const TEST: u8 = 0xe3;
const POLL_FINAL: u8 = 0x10;
const MAX_8023_DATA_LEN: usize = 1500;
const MIN_FRAME_LEN_WITHOUT_FCS: usize = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Type1Command {
    Test,
    Xid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    InvalidLocalSap,
    InformationTooLong,
}

/// Recognize a command for exactly this local MAC/SAP. Responses, unrelated
/// frames, and commands addressed to other MACs or SAPs are ignored.
pub fn command_for(
    request: &LlcFrame<'_>,
    local_mac: [u8; 6],
    local_sap: u8,
) -> Option<Type1Command> {
    if local_sap & 1 != 0
        || request.destination != local_mac
        || request.dsap != local_sap
        || request.is_response()
    {
        return None;
    }
    match request.control {
        Control::Unnumbered { byte } if byte & !POLL_FINAL == TEST => Some(Type1Command::Test),
        Control::Unnumbered { byte } if byte & !POLL_FINAL == XID => Some(Type1Command::Xid),
        _ => None,
    }
}

/// Construct an untagged 802.3 response without FCS. TEST echoes the exact
/// information field. XID uses caller-supplied identity/capability bytes; if
/// absent, it yields no response. The 802.3 length excludes Ethernet padding.
pub fn response_for(
    request: &LlcFrame<'_>,
    local_mac: [u8; 6],
    local_sap: u8,
    xid_information: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, ResponseError> {
    if local_sap & 1 != 0 {
        return Err(ResponseError::InvalidLocalSap);
    }
    let Some(command) = command_for(request, local_mac, local_sap) else {
        return Ok(None);
    };
    let information = match command {
        Type1Command::Test => request.information,
        Type1Command::Xid => match xid_information {
            Some(info) => info,
            None => return Ok(None),
        },
    };
    let data_len = 3 + information.len();
    if data_len > MAX_8023_DATA_LEN {
        return Err(ResponseError::InformationTooLong);
    }
    let poll_final = match request.control {
        Control::Unnumbered { byte } => byte & POLL_FINAL,
        _ => unreachable!("command_for accepts only unnumbered commands"),
    };
    let control = match command {
        Type1Command::Test => TEST,
        Type1Command::Xid => XID,
    } | poll_final;
    let mut response = Vec::with_capacity((14 + data_len).max(MIN_FRAME_LEN_WITHOUT_FCS));
    response.extend_from_slice(&request.source);
    response.extend_from_slice(&local_mac);
    response.extend_from_slice(&(data_len as u16).to_be_bytes());
    response.extend_from_slice(&[request.ssap, local_sap | 1, control]);
    response.extend_from_slice(information);
    response.resize(MIN_FRAME_LEN_WITHOUT_FCS.max(response.len()), 0);
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llc::parse_8023;

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn make_request(dsap: u8, ssap: u8, control: u8, info: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&LOCAL);
        frame.extend_from_slice(&PEER);
        frame.extend_from_slice(&(3 + info.len() as u16).to_be_bytes());
        frame.extend_from_slice(&[dsap, ssap, control]);
        frame.extend_from_slice(info);
        frame
    }

    #[test]
    fn test_echoes_information_and_poll_bit() {
        let request_bytes = make_request(4, 4, 0xf3, &[0x10, 0x20]);
        let request = parse_8023(&request_bytes).unwrap();
        let response = response_for(&request, LOCAL, 4, None).unwrap().unwrap();
        assert_eq!(response.len(), 60);
        assert_eq!(&response[..14], &[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0, 5]);
        assert_eq!(&response[14..19], &[4, 5, 0xf3, 0x10, 0x20]);
        assert!(response[19..].iter().all(|byte| *byte == 0));
        let parsed = parse_8023(&response).unwrap();
        assert!(parsed.is_response());
        assert_eq!(parsed.information, &[0x10, 0x20]);
    }

    #[test]
    fn xid_requires_supplied_identity_and_keeps_final_bit() {
        let request_bytes = make_request(4, 4, 0xaf, &[0x81, 0x01, 0x00]);
        let request = parse_8023(&request_bytes).unwrap();
        assert_eq!(command_for(&request, LOCAL, 4), Some(Type1Command::Xid));
        assert_eq!(response_for(&request, LOCAL, 4, None), Ok(None));
        let response = response_for(&request, LOCAL, 4, Some(&[0x81, 0x01, 0x00]))
            .unwrap()
            .unwrap();
        assert_eq!(&response[14..20], &[4, 5, 0xaf, 0x81, 0x01, 0x00]);
    }

    #[test]
    fn ignores_other_addresses_and_responses() {
        let request_bytes = make_request(6, 4, 0xe3, &[]);
        let request = parse_8023(&request_bytes).unwrap();
        assert_eq!(response_for(&request, LOCAL, 4, None), Ok(None));
        let response_bytes = make_request(4, 5, 0xe3, &[]);
        let response = parse_8023(&response_bytes).unwrap();
        assert_eq!(response_for(&response, LOCAL, 4, None), Ok(None));
        let request_bytes = make_request(4, 4, 0xe3, &[]);
        let request = parse_8023(&request_bytes).unwrap();
        assert_eq!(response_for(&request, PEER, 4, None), Ok(None));
    }

    #[test]
    fn bounds_payload_and_rejects_odd_local_sap() {
        let request_bytes = make_request(4, 4, 0xaf, &[]);
        let request = parse_8023(&request_bytes).unwrap();
        assert_eq!(
            response_for(&request, LOCAL, 5, None),
            Err(ResponseError::InvalidLocalSap)
        );
        assert_eq!(
            response_for(&request, LOCAL, 4, Some(&[0; 1498])),
            Err(ResponseError::InformationTooLong)
        );
    }
}
