//! Ethernet IEEE 802.3/802.2 framing for HPR over LAN without link-level
//! error recovery. IBM *SNA Formats* GA27-3136-19, chapter 1, pp. 1-15–1-16
//! defines a base APPN SAP for XID/TEST/DISC/DM and a separately negotiated
//! HPR UI SAP (default X'C8') carrying opaque HPR NLPs.
//!
//! This is only a frame codec. XID3 HPR capability negotiation, LDLC timers,
//! and APPN/HPR route state belong to a media adapter validated against
//! paired peer captures. The NHDR classifier here only selects an EE port;
//! it does not activate or route an HPR transmission group.

use crate::llc::{parse_8023, Control};

const MAX_8023_PAYLOAD: usize = 1500;
const LLC_HEADER: usize = 3;

pub const DEFAULT_BASE_SAP: u8 = 0x04;
pub const DEFAULT_HPR_SAP: u8 = 0xc8;
const XID3_FIXED_BYTES: usize = 29;
const HPR_CAPABILITIES_KEY: u8 = 0x61;
const LLC_SAP_SUBFIELD_KEY: u8 = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Saps {
    pub local_base: u8,
    pub remote_base: u8,
    pub local_hpr: u8,
    pub remote_hpr: u8,
}

impl Default for Saps {
    fn default() -> Self {
        Self {
            local_base: DEFAULT_BASE_SAP,
            remote_base: DEFAULT_BASE_SAP,
            local_hpr: DEFAULT_HPR_SAP,
            remote_hpr: DEFAULT_HPR_SAP,
        }
    }
}

impl Saps {
    pub fn new(
        local_base: u8,
        remote_base: u8,
        local_hpr: u8,
        remote_hpr: u8,
    ) -> Result<Self, FrameError> {
        if [local_base, remote_base, local_hpr, remote_hpr]
            .iter()
            .any(|sap| *sap == 0 || sap & 1 != 0)
        {
            return Err(FrameError::InvalidSapPair);
        }
        Ok(Self {
            local_base,
            remote_base,
            local_hpr,
            remote_hpr,
        })
    }
}

/// The LAN default is permitted by IBM *SNA Formats*, whereas RFC 2353
/// requires an explicit LLC SAP subfield on an EE IP link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HprMedium {
    Lan,
    EnterpriseExtender,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationError {
    InvalidXid3,
    WrongExchangeState,
    MissingHprCapabilities,
    DuplicateHprCapabilities,
    InvalidCapabilities,
    MissingSap,
    DuplicateSap,
    InvalidSap,
    Incomplete,
}

/// SAP advertised by one node in a negotiation-proceeding XID3. This only
/// extracts the DLC SAP; it does not decide whether the HPR TG can activate.
pub fn advertised_hpr_sap(xid: &[u8], medium: HprMedium) -> Result<u8, NegotiationError> {
    if xid.len() < XID3_FIXED_BYTES
        || xid.len() > u8::MAX as usize
        || xid[0] != 0x32
        || xid[1] as usize != xid.len()
    {
        return Err(NegotiationError::InvalidXid3);
    }
    if xid[9] & 0x0c != 0x04 {
        return Err(NegotiationError::WrongExchangeState);
    }
    let mut cursor = XID3_FIXED_BYTES;
    let mut capabilities = None;
    while cursor < xid.len() {
        let header = xid
            .get(cursor..cursor + 2)
            .ok_or(NegotiationError::InvalidXid3)?;
        let end = cursor
            .checked_add(2 + header[1] as usize)
            .filter(|end| *end <= xid.len())
            .ok_or(NegotiationError::InvalidXid3)?;
        if header[0] == HPR_CAPABILITIES_KEY {
            if capabilities.replace(&xid[cursor + 2..end]).is_some() {
                return Err(NegotiationError::DuplicateHprCapabilities);
            }
        }
        cursor = end;
    }
    let data = capabilities.ok_or(NegotiationError::MissingHprCapabilities)?;
    // The original IBM HPR architecture has a two-byte CV61 fixed prefix.
    // Observed V5R4 EE and LAN XID3s have a five-byte prefix beginning
    // with 02 80 at offset two. Its final byte differs by medium (EE 02,
    // LAN 04), so it must not be treated as part of the SAP subfield.
    // Select only that explicit observed extension; guessing a subfield
    // boundary could accept a false SAP from arbitrary capability bytes.
    if data.len() < 2 {
        return Err(NegotiationError::InvalidCapabilities);
    }
    let prefix = if data.len() >= 5 && data[2..4] == [0x02, 0x80] {
        5
    } else {
        2
    };
    let sap = parse_sap_subfields(&data[prefix..])?;
    match (sap, medium) {
        (Some(sap), _) => Ok(sap),
        (None, HprMedium::Lan) => Ok(DEFAULT_HPR_SAP),
        (None, HprMedium::EnterpriseExtender) => Err(NegotiationError::MissingSap),
    }
}

fn parse_sap_subfields(data: &[u8]) -> Result<Option<u8>, NegotiationError> {
    let mut cursor = 0;
    let mut sap = None;
    while cursor < data.len() {
        let header = data
            .get(cursor..cursor + 2)
            .ok_or(NegotiationError::InvalidCapabilities)?;
        let length = header[0] as usize;
        if length < 2 {
            return Err(NegotiationError::InvalidCapabilities);
        }
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or(NegotiationError::InvalidCapabilities)?;
        if header[1] == LLC_SAP_SUBFIELD_KEY {
            if length != 3 {
                return Err(NegotiationError::InvalidCapabilities);
            }
            let value = data[cursor + 2];
            if value == 0 || value & 1 != 0 {
                return Err(NegotiationError::InvalidSap);
            }
            if sap.replace(value).is_some() {
                return Err(NegotiationError::DuplicateSap);
            }
        }
        cursor = end;
    }
    Ok(sap)
}

/// The directional pair becomes usable only after both XID3 advertisements
/// have been observed. A new exchange should start with a fresh value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HprSapNegotiation {
    local_base: u8,
    remote_base: u8,
    local_hpr: Option<u8>,
    remote_hpr: Option<u8>,
}

impl HprSapNegotiation {
    pub fn new(local_base: u8, remote_base: u8) -> Result<Self, NegotiationError> {
        if local_base == 0 || remote_base == 0 || local_base & 1 != 0 || remote_base & 1 != 0 {
            return Err(NegotiationError::InvalidSap);
        }
        Ok(Self {
            local_base,
            remote_base,
            local_hpr: None,
            remote_hpr: None,
        })
    }

    pub fn observe_sent(&mut self, xid: &[u8], medium: HprMedium) -> Result<(), NegotiationError> {
        self.local_hpr = Some(advertised_hpr_sap(xid, medium)?);
        Ok(())
    }

    pub fn observe_received(
        &mut self,
        xid: &[u8],
        medium: HprMedium,
    ) -> Result<(), NegotiationError> {
        self.remote_hpr = Some(advertised_hpr_sap(xid, medium)?);
        Ok(())
    }

    pub fn saps(self) -> Result<Saps, NegotiationError> {
        let (Some(local_hpr), Some(remote_hpr)) = (self.local_hpr, self.remote_hpr) else {
            return Err(NegotiationError::Incomplete);
        };
        Saps::new(self.local_base, self.remote_base, local_hpr, remote_hpr)
            .map_err(|_| NegotiationError::InvalidSap)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Xid,
    Test,
    Disc,
    Dm,
    /// UI with P/F clear, carrying an opaque HPR network-layer packet.
    UiNlp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub dsap: u8,
    pub ssap: u8,
    pub control: u8,
    pub kind: Kind,
    pub information: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidSapPair,
    MalformedEthernet,
    WrongSap,
    UnsupportedControl,
    UnexpectedInformation,
    MissingNlp,
    InvalidNlp,
    FrameTooLarge,
}

/// NHDR switching mode and transmission priority in the first NLP byte.
/// IBM *SNA Formats* GA27-3136-19, chapter 2, pp. 2-5–2-7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NlpRoute {
    /// LDLC and other function-routed NLPs use EE UDP port 12000.
    Function,
    Anr(Priority),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Priority {
    Low,
    Medium,
    High,
    Network,
}

impl NlpRoute {
    /// RFC 2353 §2.6.1 maps function traffic and the four ANR priorities
    /// to EE destination UDP ports 12000–12004.
    pub fn ee_destination_port(self) -> u16 {
        match self {
            Self::Function => 12000,
            Self::Anr(Priority::Network) => 12001,
            Self::Anr(Priority::High) => 12002,
            Self::Anr(Priority::Medium) => 12003,
            Self::Anr(Priority::Low) => 12004,
        }
    }
}

pub fn classify_nlp(information: &[u8]) -> Result<NlpRoute, FrameError> {
    let first = *information.first().ok_or(FrameError::MissingNlp)?;
    match first >> 5 {
        0b101 => Ok(NlpRoute::Function),
        0b110 => {
            let priority = match (first >> 1) & 0b11 {
                0 => Priority::Low,
                1 => Priority::Medium,
                2 => Priority::High,
                _ => Priority::Network,
            };
            Ok(NlpRoute::Anr(priority))
        }
        _ => Err(FrameError::InvalidNlp),
    }
}

/// Parse only unnumbered LDLC controls at the base APPN SAP and HPR NLP UI
/// frames at the negotiated HPR SAP. 802.3 declared length removes padding.
pub fn parse_frame(bytes: &[u8], saps: Saps) -> Result<Frame<'_>, FrameError> {
    let llc = parse_8023(bytes).map_err(|_| FrameError::MalformedEthernet)?;
    let Control::Unnumbered { byte: control } = llc.control else {
        return Err(FrameError::UnsupportedControl);
    };
    let kind = if control & !0x10 == 0x03 {
        if control != 0x03 {
            return Err(FrameError::UnsupportedControl);
        }
        if llc.dsap != saps.local_hpr || llc.ssap != saps.remote_hpr {
            return Err(FrameError::WrongSap);
        }
        if llc.information.is_empty() {
            return Err(FrameError::MissingNlp);
        }
        Kind::UiNlp
    } else {
        if llc.dsap != saps.local_base || llc.ssap & !1 != saps.remote_base {
            return Err(FrameError::WrongSap);
        }
        let kind = match control & !0x10 {
            0xaf => Kind::Xid,
            0xe3 => Kind::Test,
            0x43 => Kind::Disc,
            0x0f => Kind::Dm,
            _ => return Err(FrameError::UnsupportedControl),
        };
        if matches!(kind, Kind::Disc | Kind::Dm) && !llc.information.is_empty() {
            return Err(FrameError::UnexpectedInformation);
        }
        kind
    };
    Ok(Frame {
        destination: llc.destination,
        source: llc.source,
        dsap: llc.dsap,
        ssap: llc.ssap,
        control,
        kind,
        information: llc.information,
    })
}

/// Construct one untagged 802.3 frame without FCS or Ethernet padding. The
/// packet-socket adapter adds minimum-size padding when transmitting.
pub fn encode_frame(
    destination: [u8; 6],
    source: [u8; 6],
    kind: Kind,
    response: bool,
    poll_final: bool,
    information: &[u8],
    saps: Saps,
) -> Result<Vec<u8>, FrameError> {
    if destination[0] & 1 != 0 || source[0] & 1 != 0 || destination == source {
        return Err(FrameError::MalformedEthernet);
    }
    if information.len() + LLC_HEADER > MAX_8023_PAYLOAD {
        return Err(FrameError::FrameTooLarge);
    }
    if matches!(kind, Kind::Disc | Kind::Dm) && !information.is_empty() {
        return Err(FrameError::UnexpectedInformation);
    }
    if kind == Kind::UiNlp && information.is_empty() {
        return Err(FrameError::MissingNlp);
    }
    if kind == Kind::UiNlp && (response || poll_final) {
        return Err(FrameError::UnsupportedControl);
    }
    let (dsap, ssap, control) = match kind {
        Kind::UiNlp => (saps.remote_hpr, saps.local_hpr, 0x03),
        Kind::Xid => (saps.remote_base, saps.local_base | u8::from(response), 0xaf),
        Kind::Test => (saps.remote_base, saps.local_base | u8::from(response), 0xe3),
        Kind::Disc => (saps.remote_base, saps.local_base | u8::from(response), 0x43),
        Kind::Dm => (saps.remote_base, saps.local_base | u8::from(response), 0x0f),
    };
    let mut frame = Vec::with_capacity(14 + LLC_HEADER + information.len());
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&((LLC_HEADER + information.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[dsap, ssap, control | (u8::from(poll_final) << 4)]);
    frame.extend_from_slice(information);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

    fn saps() -> Saps {
        Saps::default()
    }

    fn xid3_with_capabilities(data: &[u8]) -> Vec<u8> {
        let mut xid = vec![0; XID3_FIXED_BYTES];
        xid[0] = 0x32;
        xid[9] = 0x04;
        xid.extend_from_slice(&[HPR_CAPABILITIES_KEY, data.len() as u8]);
        xid.extend_from_slice(data);
        xid[1] = xid.len() as u8;
        xid
    }

    #[test]
    fn parses_negotiated_hpr_ui_and_ignores_ethernet_padding() {
        let mut bytes = vec![
            0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0, 5, 0xc8, 0xc8, 3, 0x12, 0x34,
        ];
        bytes.resize(60, 0);
        let frame = parse_frame(&bytes, saps()).unwrap();
        assert_eq!(frame.kind, Kind::UiNlp);
        assert_eq!(frame.information, [0x12, 0x34]);
        assert_eq!(frame.destination, B);
        assert_eq!(frame.source, A);
        assert_eq!(
            encode_frame(B, A, Kind::UiNlp, false, false, &[0x12, 0x34], saps()).unwrap(),
            bytes[..19]
        );
    }

    #[test]
    fn base_sap_carries_xid_but_hpr_sap_carries_nlp() {
        let xid = encode_frame(B, A, Kind::Xid, true, true, &[0x81, 0x01], saps()).unwrap();
        assert_eq!(&xid[14..17], &[0x04, 0x05, 0xbf]);
        let parsed = parse_frame(&xid, saps()).unwrap();
        assert_eq!(parsed.kind, Kind::Xid);
        assert_eq!(parsed.information, [0x81, 0x01]);
        assert!(parse_frame(
            &encode_frame(B, A, Kind::UiNlp, false, false, &[1], saps()).unwrap(),
            Saps::new(4, 4, 0xca, 0xc8).unwrap()
        )
        .is_err());
    }

    #[test]
    fn directional_negotiated_saps_are_not_assumed_equal() {
        let a = Saps::new(0x04, 0x08, 0xc8, 0xca).unwrap();
        let b = Saps::new(0x08, 0x04, 0xca, 0xc8).unwrap();
        let sent = encode_frame(B, A, Kind::UiNlp, false, false, &[0x12], a).unwrap();
        assert_eq!(&sent[14..17], &[0xca, 0xc8, 0x03]);
        assert_eq!(parse_frame(&sent, b).unwrap().kind, Kind::UiNlp);
        let xid = encode_frame(B, A, Kind::Xid, false, false, &[0x81], a).unwrap();
        assert_eq!(&xid[14..17], &[0x08, 0x04, 0xaf]);
        assert_eq!(parse_frame(&xid, b).unwrap().kind, Kind::Xid);
    }

    #[test]
    fn nlp_header_maps_to_the_five_ee_ports() {
        for (first, route, port) in [
            (0xa0, NlpRoute::Function, 12000),
            (0xc0, NlpRoute::Anr(Priority::Low), 12004),
            (0xc2, NlpRoute::Anr(Priority::Medium), 12003),
            (0xc4, NlpRoute::Anr(Priority::High), 12002),
            (0xc6, NlpRoute::Anr(Priority::Network), 12001),
        ] {
            let classified = classify_nlp(&[first]).unwrap();
            assert_eq!(classified, route);
            assert_eq!(classified.ee_destination_port(), port);
        }
        assert_eq!(classify_nlp(&[]), Err(FrameError::MissingNlp));
        assert_eq!(classify_nlp(&[0x20]), Err(FrameError::InvalidNlp));
    }

    #[test]
    fn v5r4_ee_cv61_advertises_sap_and_keeps_directional_state() {
        // CV61 from a V5R4 EE negotiation-proceeding XID3 control capture.
        // Only the capability vector is retained; no application data is used.
        let captured = xid3_with_capabilities(&[
            0xf8, 0x00, 0x02, 0x80, 0x02, 0x03, 0x80, 0x04, 0x17, 0x81, 0x05, 0xb5, 0x00, 0x00,
            0xea, 0x60, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x02, 0xa4, 0x00,
            0x02, 0xa4, 0x00,
        ]);
        assert_eq!(
            advertised_hpr_sap(&captured, HprMedium::EnterpriseExtender),
            Ok(4)
        );
        let mut state = HprSapNegotiation::new(4, 4).unwrap();
        assert_eq!(state.saps(), Err(NegotiationError::Incomplete));
        state
            .observe_sent(&captured, HprMedium::EnterpriseExtender)
            .unwrap();
        assert_eq!(state.saps(), Err(NegotiationError::Incomplete));
        let remote = xid3_with_capabilities(&[0x80, 0x00, 0x03, 0x80, 0xca]);
        state.observe_received(&remote, HprMedium::Lan).unwrap();
        assert_eq!(state.saps().unwrap().local_hpr, 4);
        assert_eq!(state.saps().unwrap().remote_hpr, 0xca);
    }

    #[test]
    fn v5r4_lan_cv61_advertises_c8_sap() {
        // Direct V5R4 HPR LAN XID3 capability vector, excluding all PIUs.
        let captured = xid3_with_capabilities(&[
            0xb8, 0x00, 0x02, 0x80, 0x04, 0x03, 0x80, 0xc8, 0x17, 0x81, 0x00, 0x00, 0x00, 0x00,
            0xea, 0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x02, 0xa4, 0x00,
            0x02, 0xa4, 0x00,
        ]);
        assert_eq!(advertised_hpr_sap(&captured, HprMedium::Lan), Ok(0xc8));
    }

    #[test]
    fn cv61_requires_complete_unique_sap_and_correct_exchange_phase() {
        let absent = xid3_with_capabilities(&[0x80, 0x00]);
        assert_eq!(advertised_hpr_sap(&absent, HprMedium::Lan), Ok(0xc8));
        assert_eq!(
            advertised_hpr_sap(&absent, HprMedium::EnterpriseExtender),
            Err(NegotiationError::MissingSap)
        );
        let malformed = xid3_with_capabilities(&[0xf8, 0, 2, 0x80, 2, 4, 0x80, 4]);
        assert_eq!(
            advertised_hpr_sap(&malformed, HprMedium::EnterpriseExtender),
            Err(NegotiationError::InvalidCapabilities)
        );
        let repeated_sap = xid3_with_capabilities(&[0x80, 0, 3, 0x80, 0xc8, 3, 0x80, 0xca]);
        assert_eq!(
            advertised_hpr_sap(&repeated_sap, HprMedium::Lan),
            Err(NegotiationError::DuplicateSap)
        );
        let odd_sap = xid3_with_capabilities(&[0x80, 0, 3, 0x80, 0xc9]);
        assert_eq!(
            advertised_hpr_sap(&odd_sap, HprMedium::Lan),
            Err(NegotiationError::InvalidSap)
        );
        let mut wrong_state = absent.clone();
        wrong_state[9] = 0x08;
        assert_eq!(
            advertised_hpr_sap(&wrong_state, HprMedium::Lan),
            Err(NegotiationError::WrongExchangeState)
        );
        let mut wrong_length = absent.clone();
        wrong_length[1] += 1;
        assert_eq!(
            advertised_hpr_sap(&wrong_length, HprMedium::Lan),
            Err(NegotiationError::InvalidXid3)
        );
        let mut duplicate = absent.clone();
        duplicate.extend_from_slice(&[HPR_CAPABILITIES_KEY, 2, 0x80, 0]);
        duplicate[1] = duplicate.len() as u8;
        assert_eq!(
            advertised_hpr_sap(&duplicate, HprMedium::Lan),
            Err(NegotiationError::DuplicateHprCapabilities)
        );
    }

    #[test]
    fn rejects_llc2_and_invalid_ldlc_frames() {
        assert_eq!(Saps::new(4, 4, 5, 0xc8), Err(FrameError::InvalidSapPair));
        assert!(parse_frame(&[0; 13], saps()).is_err());
        let mut ui = encode_frame(B, A, Kind::UiNlp, false, false, &[1], saps()).unwrap();
        ui[16] = 0x13;
        assert_eq!(
            parse_frame(&ui, saps()),
            Err(FrameError::UnsupportedControl)
        );
        let mut i_frame = encode_frame(B, A, Kind::Xid, false, false, &[1], saps()).unwrap();
        i_frame[16] = 0;
        i_frame[12..14].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(
            parse_frame(&i_frame, saps()),
            Err(FrameError::MalformedEthernet)
        );
        assert_eq!(
            encode_frame(B, A, Kind::UiNlp, true, false, &[1], saps()),
            Err(FrameError::UnsupportedControl)
        );
        assert_eq!(
            encode_frame(B, A, Kind::Disc, false, false, &[1], saps()),
            Err(FrameError::UnexpectedInformation)
        );
    }
}
