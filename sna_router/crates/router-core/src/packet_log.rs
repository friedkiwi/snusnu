//! Lazy, bounded-by-input packet descriptions for diagnostic logging.
//!
//! The SNA information field can contain a segment rather than a complete
//! PIU. FID2 fields are decoded only where the bytes are present; unsupported
//! formats remain labeled as such. These helpers do not log on their own.
//! FID2 TH and RH offsets follow IBM SNA Formats GA27-3136, chapters 3-4.

use crate::llc::{parse_8023, Control};
use std::fmt::{self, Display, Formatter, Write};

pub struct HexDump<'a>(&'a [u8]);
pub struct EthernetDescription<'a>(&'a [u8]);
pub struct LlcDescription<'a>(&'a [u8]);
pub struct SnaDescription<'a>(&'a [u8]);

/// Complete offset, hex and ASCII dump. Semicolons separate 16-byte rows so
/// a text log still has one timestamped line per packet.
pub fn hex_dump(bytes: &[u8]) -> HexDump<'_> {
    HexDump(bytes)
}

pub fn decode_ethernet(bytes: &[u8]) -> EthernetDescription<'_> {
    EthernetDescription(bytes)
}

/// Describe an LLC PDU beginning with DSAP, without an Ethernet header.
pub fn decode_llc_pdu(bytes: &[u8]) -> LlcDescription<'_> {
    LlcDescription(bytes)
}

/// Best-effort SNA information field description. FID2 TH/RH decoding is
/// deliberately conservative because a field can be segmented or opaque.
pub fn decode_sna_information(bytes: &[u8]) -> SnaDescription<'_> {
    SnaDescription(bytes)
}

impl Display for HexDump<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("0000: <empty>");
        }
        for (row, chunk) in self.0.chunks(16).enumerate() {
            if row != 0 {
                f.write_str("; ")?;
            }
            write!(f, "{:04x}: ", row * 16)?;
            for &byte in chunk {
                write!(f, "{byte:02x} ")?;
            }
            for _ in chunk.len()..16 {
                f.write_str("   ")?;
            }
            f.write_char('|')?;
            for &byte in chunk {
                f.write_char(if byte.is_ascii_graphic() || byte == b' ' {
                    char::from(byte)
                } else {
                    '.'
                })?;
            }
            f.write_char('|')?;
        }
        Ok(())
    }
}

impl Display for EthernetDescription<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(f, "ethernet_bytes={}", bytes.len())?;
        if bytes.len() >= 12 {
            f.write_str(" src=")?;
            write_mac(f, &bytes[6..12])?;
            f.write_str(" dst=")?;
            write_mac(f, &bytes[..6])?;
        }
        if bytes.len() >= 14 {
            let declared = u16::from_be_bytes([bytes[12], bytes[13]]);
            write!(f, " length_or_type=0x{declared:04x}")?;
        }
        match parse_8023(bytes) {
            Ok(frame) => {
                let declared = u16::from_be_bytes([bytes[12], bytes[13]]) as usize;
                write!(
                    f,
                    " declared_len={declared} padding={}",
                    bytes.len() - 14 - declared
                )?;
                write_llc(f, frame.dsap, frame.ssap, frame.control, frame.information)?;
            }
            Err(error) => write!(f, " decode_error={error:?}")?,
        }
        Ok(())
    }
}

impl Display for LlcDescription<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(f, "llc_bytes={}", bytes.len())?;
        if bytes.len() < 3 {
            return f.write_str(" decode_error=truncated_header");
        }
        let first = bytes[2];
        let (control, offset) = if first & 1 == 0 {
            if bytes.len() < 4 {
                return f.write_str(" decode_error=truncated_information_control");
            }
            (
                Control::Information {
                    send_sequence: first >> 1,
                    receive_sequence: bytes[3] >> 1,
                    poll_final: bytes[3] & 1 != 0,
                },
                4,
            )
        } else if first & 3 == 1 {
            if bytes.len() < 4 {
                return f.write_str(" decode_error=truncated_supervisory_control");
            }
            (
                Control::Supervisory {
                    function: (first >> 2) & 3,
                    receive_sequence: bytes[3] >> 1,
                    poll_final: bytes[3] & 1 != 0,
                },
                4,
            )
        } else {
            (Control::Unnumbered { byte: first }, 3)
        };
        write_llc(f, bytes[0], bytes[1], control, &bytes[offset..])
    }
}

fn write_llc(
    f: &mut Formatter<'_>,
    dsap: u8,
    ssap: u8,
    control: Control,
    information: &[u8],
) -> fmt::Result {
    write!(
        f,
        " dsap=0x{dsap:02x} ssap=0x{ssap:02x} response={} ",
        ssap & 1 != 0
    )?;
    match control {
        Control::Information {
            send_sequence,
            receive_sequence,
            poll_final,
        } => {
            write!(
                f,
                "llc=I ns={send_sequence} nr={receive_sequence} pf={poll_final}"
            )?;
        }
        Control::Supervisory {
            function,
            receive_sequence,
            poll_final,
        } => {
            let name = match function {
                0 => "RR",
                1 => "RNR",
                2 => "REJ",
                _ => "SREJ",
            };
            write!(f, "llc={name} nr={receive_sequence} pf={poll_final}")?;
        }
        Control::Unnumbered { byte } => {
            let name = match byte & !0x10 {
                0xaf => "XID",
                0xe3 => "TEST",
                0x6f => "SABME",
                0x63 => "UA",
                0x43 => "DISC",
                0x0f => "DM",
                0x03 => "UI",
                _ => "U",
            };
            write!(f, "llc={name} control=0x{byte:02x} pf={}", byte & 0x10 != 0)?;
        }
    }
    write!(f, " info_len={}", information.len())?;
    if matches!(control, Control::Information { .. }) && dsap == 4 && ssap & !1 == 4 {
        write!(f, " sna=({})", decode_sna_information(information))?;
    } else if matches!(control, Control::Unnumbered { byte } if byte & !0x10 == 0xaf) {
        if let Some(first) = information.first() {
            write!(f, " xid_first=0x{first:02x}")?;
        }
    }
    Ok(())
}

impl Display for SnaDescription<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(f, "bytes={}", bytes.len())?;
        let Some(&first) = bytes.first() else {
            return f.write_str(" empty");
        };
        let fid = first >> 4;
        write!(f, " fid={fid}")?;
        if fid != 2 {
            return f.write_str(" th=unsupported_or_fragment");
        }
        if bytes.len() < 6 {
            return f.write_str(" th=truncated");
        }
        let mpf = match (first >> 2) & 3 {
            0 => "middle",
            1 => "last",
            2 => "first",
            _ => "whole",
        };
        let seq = u16::from_be_bytes([bytes[4], bytes[5]]);
        write!(
            f,
            " mpf={mpf} odai={} expedited={} daf=0x{:02x} oaf=0x{:02x} seq=0x{seq:04x}",
            first & 2 != 0,
            first & 1 != 0,
            bytes[2],
            bytes[3]
        )?;
        if first & 0x08 == 0 {
            return f.write_str(" rh=continuation");
        }
        if bytes.len() < 9 {
            return f.write_str(" rh=truncated");
        }
        let rh = &bytes[6..9];
        let category = match (rh[0] >> 5) & 3 {
            0 => "FM",
            1 => "NC",
            2 => "DFC",
            _ => "SC",
        };
        write!(
            f,
            " rh={:02x}{:02x}{:02x} direction={} category={category} ru_len={}",
            rh[0],
            rh[1],
            rh[2],
            if rh[0] & 0x80 != 0 {
                "response"
            } else {
                "request"
            },
            bytes.len() - 9
        )
    }
}

fn write_mac(f: &mut Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            f.write_char(':')?;
        }
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4r4_xid_describes_addresses_control_and_ignores_padding() {
        let bytes = [
            0x02, 0x00, 0x35, 0x27, 0x23, 0x01, 0x02, 0x00, 0x35, 0x27, 0x23, 0x99, 0x00, 0x06,
            0x04, 0x04, 0xaf, 0x81, 0x01, 0x00, 0, 0,
        ];
        let decoded = decode_ethernet(&bytes).to_string();
        assert!(decoded.contains("src=02:00:35:27:23:99 dst=02:00:35:27:23:01"));
        assert!(decoded.contains("declared_len=6 padding=2"));
        assert!(decoded.contains("llc=XID control=0xaf pf=false info_len=3 xid_first=0x81"));
    }

    #[test]
    fn fid2_information_decodes_th_and_rh_when_present() {
        let bytes = [0x2c, 0, 1, 2, 0x12, 0x34, 0x80, 0, 0, 0x31];
        let decoded = decode_sna_information(&bytes).to_string();
        assert!(decoded.contains("fid=2 mpf=whole odai=false expedited=false"));
        assert!(decoded.contains("daf=0x01 oaf=0x02 seq=0x1234"));
        assert!(decoded.contains("direction=response category=FM ru_len=1"));
        assert!(decode_sna_information(&bytes[..5])
            .to_string()
            .contains("th=truncated"));
        assert!(decode_sna_information(&[0x00, 1])
            .to_string()
            .contains("unsupported_or_fragment"));
    }

    #[test]
    fn hex_dump_shows_full_bytes_with_offsets_and_ascii() {
        let bytes = (0..18).collect::<Vec<u8>>();
        let dump = hex_dump(&bytes).to_string();
        assert!(dump.contains("0000: 00 01 02"));
        assert!(dump.contains("; 0010: 10 11"));
        assert!(dump.contains("|................|"));
    }
}
