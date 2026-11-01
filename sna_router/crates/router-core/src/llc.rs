//! Borrowed IEEE 802.3/802.2 frame views for capture and replay.
//!
//! Input starts at the destination MAC, excludes the Ethernet FCS, and is
//! untagged. VLAN handling belongs at the link adapter boundary. Parsing does
//! not imply that the frame is valid for any particular LLC state.

pub const SNA_SAP: u8 = 0x04;
const ETHERNET_HEADER_LEN: usize = 14;
const LLC_HEADER_LEN: usize = 3;
const MAX_8023_DATA_LEN: usize = 1500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedEthernetHeader,
    Not8023,
    InvalidLength,
    TruncatedPayload,
    TruncatedLlcControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Information {
        send_sequence: u8,
        receive_sequence: u8,
        poll_final: bool,
    },
    Supervisory {
        function: u8,
        receive_sequence: u8,
        poll_final: bool,
    },
    Unnumbered {
        byte: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LlcFrame<'a> {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub dsap: u8,
    pub ssap: u8,
    pub control: Control,
    pub information: &'a [u8],
}

impl LlcFrame<'_> {
    /// The SSAP low bit distinguishes a response from a command.
    pub fn is_response(&self) -> bool {
        self.ssap & 1 != 0
    }

    /// Match the SNA path-control SAP, ignoring the SSAP response bit.
    pub fn is_sna(&self) -> bool {
        self.dsap == SNA_SAP && self.ssap & !1 == SNA_SAP
    }
}

/// Parse one untagged 802.3 frame. Trailing Ethernet padding is ignored using
/// the declared 802.3 length; it never becomes LLC information.
pub fn parse_8023(frame: &[u8]) -> Result<LlcFrame<'_>, ParseError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TruncatedEthernetHeader);
    }
    let length = u16::from_be_bytes([frame[12], frame[13]]) as usize;
    if length > MAX_8023_DATA_LEN {
        return Err(ParseError::Not8023);
    }
    if length < LLC_HEADER_LEN {
        return Err(ParseError::InvalidLength);
    }
    if frame.len() < ETHERNET_HEADER_LEN + length {
        return Err(ParseError::TruncatedPayload);
    }
    let payload = &frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + length];
    let first = payload[2];
    let (control, header_len) = if first & 1 == 0 {
        let second = *payload.get(3).ok_or(ParseError::TruncatedLlcControl)?;
        (
            Control::Information {
                send_sequence: first >> 1,
                receive_sequence: second >> 1,
                poll_final: second & 1 != 0,
            },
            4,
        )
    } else if first & 3 == 1 {
        let second = *payload.get(3).ok_or(ParseError::TruncatedLlcControl)?;
        (
            Control::Supervisory {
                function: (first >> 2) & 3,
                receive_sequence: second >> 1,
                poll_final: second & 1 != 0,
            },
            4,
        )
    } else {
        (Control::Unnumbered { byte: first }, 3)
    };
    let mut destination = [0; 6];
    destination.copy_from_slice(&frame[..6]);
    let mut source = [0; 6];
    source.copy_from_slice(&frame[6..12]);
    Ok(LlcFrame {
        destination,
        source,
        dsap: payload[0],
        ssap: payload[1],
        control,
        information: &payload[header_len..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(length: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn xid_excludes_ethernet_padding() {
        let bytes = frame(5, &[4, 5, 0xaf, 0x81, 0x01, 0, 0, 0]);
        let llc = parse_8023(&bytes).unwrap();
        assert_eq!(llc.destination, [0, 1, 2, 3, 4, 5]);
        assert_eq!(llc.source, [6, 7, 8, 9, 10, 11]);
        assert!(llc.is_sna());
        assert!(llc.is_response());
        assert_eq!(llc.control, Control::Unnumbered { byte: 0xaf });
        assert_eq!(llc.information, [0x81, 0x01]);
    }

    #[test]
    fn numbered_controls_use_two_bytes() {
        let information_bytes = frame(6, &[4, 4, 0x0a, 0x0f, 0xaa, 0xbb]);
        let information = parse_8023(&information_bytes).unwrap();
        assert_eq!(
            information.control,
            Control::Information {
                send_sequence: 5,
                receive_sequence: 7,
                poll_final: true,
            }
        );
        assert_eq!(information.information, [0xaa, 0xbb]);
        let supervisory_bytes = frame(4, &[4, 4, 0x05, 0x0e]);
        let supervisory = parse_8023(&supervisory_bytes).unwrap();
        assert_eq!(
            supervisory.control,
            Control::Supervisory {
                function: 1,
                receive_sequence: 7,
                poll_final: false,
            }
        );
        assert!(supervisory.information.is_empty());
    }

    #[test]
    fn rejects_wrong_or_incomplete_lengths() {
        assert_eq!(
            parse_8023(&[0; 13]),
            Err(ParseError::TruncatedEthernetHeader)
        );
        assert_eq!(parse_8023(&frame(0x0800, &[])), Err(ParseError::Not8023));
        assert_eq!(
            parse_8023(&frame(2, &[4, 4])),
            Err(ParseError::InvalidLength)
        );
        assert_eq!(
            parse_8023(&frame(5, &[4, 4, 0xaf])),
            Err(ParseError::TruncatedPayload)
        );
        assert_eq!(
            parse_8023(&frame(3, &[4, 4, 0x00])),
            Err(ParseError::TruncatedLlcControl)
        );
        assert_eq!(
            parse_8023(&frame(3, &[4, 4, 0x01])),
            Err(ParseError::TruncatedLlcControl)
        );
    }
}
