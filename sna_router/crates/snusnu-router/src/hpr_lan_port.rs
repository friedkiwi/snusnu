//! Prototype one-adjacency HPR LAN media port. It translates only 802.3 LLC
//! framing and EE UDP priority selection; it is deliberately not wired into
//! configuration until a paired LAN/EE link-activation capture validates it.

use crate::routing::{RoutePort, RoutedUnit, RouterEvent};
use link_linux::packet::{PacketPort, MAX_FRAME_LEN};
use router_core::{
    hpr_lan::{self, HprMedium, HprSapNegotiation, Kind, NegotiationError, Saps, DEFAULT_HPR_SAP},
    hpr_setmode::{Phase, SetModeBridge, XidDone},
    llc::{parse_8023, Control},
    llc2::{Effect, Llc2},
    packet_log::hex_dump,
};
use std::{collections::VecDeque, io};
use transport_ip_sna::ee::{Datagram, LdlcKind, CONTROL_PORT};

const QUEUE_LIMIT: usize = 64;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn negotiation_error(error: NegotiationError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("HPR SAP negotiation: {error:?}"),
    )
}

/// A configured MAC pair identifies exactly one LAN guest adjacency.
/// `local_mac` is the router's virtual peer MAC on that TAP.
struct HprLanCodec {
    local_mac: [u8; 6],
    guest_mac: [u8; 6],
    saps: HprSapNegotiation,
    local_base: u8,
    remote_base: u8,
    llc2: Llc2,
    setmode: SetModeBridge,
    pending_sabme: Option<Vec<u8>>,
    local_frames: VecDeque<Vec<u8>>,
}

impl HprLanCodec {
    fn new(
        local_mac: [u8; 6],
        guest_mac: [u8; 6],
        local_base: u8,
        remote_base: u8,
    ) -> io::Result<Self> {
        if local_mac == guest_mac
            || [local_mac, guest_mac]
                .iter()
                .any(|mac| *mac == [0; 6] || mac[0] & 1 != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid HPR LAN MAC pair",
            ));
        }
        let saps = HprSapNegotiation::new(local_base, remote_base).map_err(negotiation_error)?;
        Ok(Self {
            local_mac,
            guest_mac,
            saps,
            local_base,
            remote_base,
            llc2: Llc2::new(local_base, remote_base),
            setmode: SetModeBridge::default(),
            pending_sabme: None,
            local_frames: VecDeque::new(),
        })
    }

    /// The caller must validate XID3 roles, HPR capabilities and TG agreement
    /// on both media before enabling SETMODE. SAP observation alone is not enough.
    #[cfg(test)]
    fn arm_after_validated_xid(&mut self) -> io::Result<()> {
        self.saps.saps().map_err(negotiation_error)?;
        self.setmode
            .arm()
            .map_err(|_| invalid("HPR SETMODE already armed"))
    }

    fn local_llc(&mut self, pdu: Vec<u8>) -> io::Result<()> {
        if pdu.len() > 1500 {
            return Err(invalid("HPR LAN LLC control exceeds 802.3 MTU"));
        }
        let mut frame = Vec::with_capacity(14 + pdu.len());
        frame.extend_from_slice(&self.guest_mac);
        frame.extend_from_slice(&self.local_mac);
        frame.extend_from_slice(&(pdu.len() as u16).to_be_bytes());
        frame.extend_from_slice(&pdu);
        self.local_frames.push_back(frame);
        Ok(())
    }

    fn ee_xid_done(&self, kind: XidDone) -> RoutedUnit {
        let mut payload = vec![self.local_base, self.remote_base, 0x03];
        payload.extend_from_slice(&kind.encode());
        RoutedUnit::EeDatagram {
            priority: 0,
            payload,
        }
    }

    fn local_effects(&mut self, effects: Vec<Effect<'_>>) -> io::Result<()> {
        for effect in effects {
            match effect {
                Effect::Send(pdu) => self.local_llc(pdu)?,
                Effect::Deliver(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "LLC2 information on HPR LAN",
                    ))
                }
                Effect::Disconnected | Effect::TimedOut => self.setmode.reset(),
                Effect::Connected => {}
            }
        }
        Ok(())
    }

    fn provisional_saps(&self) -> Saps {
        Saps::new(
            self.local_base,
            self.remote_base,
            DEFAULT_HPR_SAP,
            DEFAULT_HPR_SAP,
        )
        .unwrap()
    }

    fn receive(&mut self, bytes: &[u8]) -> io::Result<Option<RoutedUnit>> {
        let llc = match parse_8023(bytes) {
            Ok(frame) => frame,
            Err(_) => return Ok(None),
        };
        if llc.destination != self.local_mac || llc.source != self.guest_mac {
            return Ok(None);
        }
        if llc.dsap == self.local_base && llc.ssap & !1 == self.remote_base {
            match llc.control {
                Control::Information { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "SAP04 LLC2 I-frame cannot cross HPR media",
                    ))
                }
                Control::Supervisory { .. } => {
                    if self.setmode.phase() != Phase::Active {
                        return Err(invalid("LLC2 supervisory frame before HPR SETMODE"));
                    }
                    let effects = self
                        .llc2
                        .receive(&llc)
                        .map_err(|_| invalid("invalid HPR LAN LLC2 supervision"))?;
                    self.local_effects(effects)?;
                    return Ok(None);
                }
                Control::Unnumbered { byte } if byte & !0x10 == 0x6f && !llc.is_response() => {
                    self.setmode
                        .on_lan_sabme(byte & 0x10 != 0)
                        .map_err(|_| invalid("LAN SABME before validated XID or during SETMODE"))?;
                    self.pending_sabme = Some(
                        bytes[..14 + u16::from_be_bytes([bytes[12], bytes[13]]) as usize].to_vec(),
                    );
                    return Ok(Some(self.ee_xid_done(XidDone::Request)));
                }
                Control::Unnumbered { byte } if byte & !0x10 == 0x63 && llc.is_response() => {
                    let effects = self
                        .llc2
                        .receive(&llc)
                        .map_err(|_| invalid("unexpected LAN UA"))?;
                    self.local_effects(effects)?;
                    self.setmode
                        .on_lan_ua()
                        .map_err(|_| invalid("LAN UA outside EE SETMODE"))?;
                    return Ok(Some(self.ee_xid_done(XidDone::Response)));
                }
                _ => {}
            }
        }
        let Control::Unnumbered { byte: control } = llc.control else {
            return Ok(None);
        };
        let saps = if control == 0x03 {
            self.saps.saps().map_err(negotiation_error)?
        } else {
            self.provisional_saps()
        };
        let frame =
            hpr_lan::parse_frame(bytes, saps).map_err(|_| invalid("invalid HPR LAN LLC frame"))?;
        let mut next_saps = self.saps;
        if frame.kind == Kind::Xid && is_proceeding_xid(frame.information) {
            next_saps
                .observe_received(frame.information, HprMedium::Lan)
                .map_err(negotiation_error)?;
        }
        let port = if frame.kind == Kind::UiNlp {
            match hpr_lan::classify_nlp(frame.information)
                .map_err(|_| invalid("invalid HPR NLP header"))?
            {
                hpr_lan::NlpRoute::Anr(priority) if self.setmode.phase() == Phase::Active => {
                    hpr_lan::NlpRoute::Anr(priority).ee_destination_port()
                }
                hpr_lan::NlpRoute::Function => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "unsupported LAN function NLP",
                    ))
                }
                _ => return Err(invalid("HPR LAN data before SETMODE")),
            }
        } else {
            CONTROL_PORT
        };
        let payload = bytes[14..14 + 3 + frame.information.len()].to_vec();
        Datagram::decode(port, payload.clone())?;
        self.saps = next_saps;
        Ok(Some(RoutedUnit::EeDatagram {
            priority: (port - CONTROL_PORT) as u8,
            payload,
        }))
    }

    fn send(&mut self, priority: u8, payload: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        let port = CONTROL_PORT
            .checked_add(priority as u16)
            .ok_or_else(|| invalid("invalid EE priority"))?;
        let datagram = Datagram::decode(port, payload)?;
        if datagram.kind == LdlcKind::UiNlp {
            match hpr_lan::classify_nlp(&datagram.payload[3..])
                .map_err(|_| invalid("invalid HPR NLP header"))?
            {
                hpr_lan::NlpRoute::Function => {
                    match XidDone::parse(&datagram.payload[3..])
                        .map_err(|_| invalid("unsupported EE function NLP"))?
                    {
                        XidDone::Request => {
                            self.setmode.on_ee_request().map_err(|_| {
                                invalid("EE SETMODE before validated XID or during SETMODE")
                            })?;
                            let pdu = self
                                .llc2
                                .begin_connect()
                                .map_err(|_| invalid("LAN LLC2 already connecting"))?;
                            self.local_llc(pdu)?;
                        }
                        XidDone::Response => {
                            self.setmode
                                .on_ee_response()
                                .map_err(|_| invalid("unexpected EE SETMODE response"))?;
                            let saved = self
                                .pending_sabme
                                .take()
                                .ok_or_else(|| invalid("missing LAN SABME"))?;
                            let llc = parse_8023(&saved)
                                .map_err(|_| invalid("invalid saved LAN SABME"))?;
                            let effects = self
                                .llc2
                                .receive(&llc)
                                .map_err(|_| invalid("invalid LAN SABME"))?;
                            self.local_effects(effects)?;
                        }
                    }
                    return Ok(None);
                }
                hpr_lan::NlpRoute::Anr(_) if self.setmode.phase() != Phase::Active => {
                    return Err(invalid("EE HPR data before SETMODE"))
                }
                _ => {}
            }
        }
        let mut next_saps = self.saps;
        if datagram.kind == LdlcKind::Xid && is_proceeding_xid(&datagram.payload[3..]) {
            next_saps
                .observe_sent(&datagram.payload[3..], HprMedium::EnterpriseExtender)
                .map_err(negotiation_error)?;
        }
        let saps = if datagram.kind == LdlcKind::UiNlp {
            next_saps.saps().map_err(negotiation_error)?
        } else {
            self.provisional_saps()
        };
        let kind = match datagram.kind {
            LdlcKind::Xid => Kind::Xid,
            LdlcKind::Test => Kind::Test,
            LdlcKind::Disc => Kind::Disc,
            LdlcKind::Dm => Kind::Dm,
            LdlcKind::UiNlp => Kind::UiNlp,
        };
        if kind == Kind::UiNlp {
            let expected_port = hpr_lan::classify_nlp(&datagram.payload[3..])
                .map_err(|_| invalid("invalid HPR NLP header"))?
                .ee_destination_port();
            if port != expected_port {
                return Err(invalid("EE priority port disagrees with HPR NLP header"));
            }
        }
        let frame = hpr_lan::encode_frame(
            self.guest_mac,
            self.local_mac,
            kind,
            datagram.ssap & 1 != 0,
            datagram.payload[2] & 0x10 != 0,
            &datagram.payload[3..],
            saps,
        )
        .map_err(|_| invalid("invalid HPR LAN outbound frame"))?;
        if frame[14..] != datagram.payload {
            return Err(invalid("EE LLC SAPs disagree with negotiated HPR LAN SAPs"));
        }
        self.saps = next_saps;
        Ok(Some(frame))
    }
}

fn is_proceeding_xid(information: &[u8]) -> bool {
    information.len() >= 29 && information[0] == 0x32 && information[9] & 0x0c == 0x04
}

/// AF_PACKET attachment for one HPR-capable LAN guest. No APPN or HPR TG is
/// terminated here; XID3 and NLP bytes are relayed within a single adjacency.
pub(crate) struct HprLanPort {
    packet: PacketPort,
    interface: String,
    codec: HprLanCodec,
    outgoing: VecDeque<Vec<u8>>,
    completed: usize,
}

impl HprLanPort {
    pub(crate) fn open(
        interface: &str,
        local_mac: [u8; 6],
        guest_mac: [u8; 6],
        local_base: u8,
        remote_base: u8,
    ) -> io::Result<Self> {
        let codec = HprLanCodec::new(local_mac, guest_mac, local_base, remote_base)?;
        let packet = PacketPort::open(interface)?;
        Ok(Self {
            packet,
            interface: interface.to_owned(),
            codec,
            outgoing: VecDeque::new(),
            completed: 0,
        })
    }

    fn drain(&mut self) -> io::Result<()> {
        while let Some(frame) = self.outgoing.front() {
            match self.packet.send_frame(frame) {
                Ok(()) => {
                    self.outgoing.pop_front();
                    self.completed += 1;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl RoutePort for HprLanPort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if !can_accept_information {
            return Ok(None);
        }
        let mut buffer = [0; MAX_FRAME_LEN];
        let length = match self.packet.receive_frame(&mut buffer) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        let received = self.codec.receive(&buffer[..length]);
        while let Some(frame) = self.codec.local_frames.pop_front() {
            self.outgoing.push_back(frame);
        }
        match received {
            Ok(Some(unit)) => {
                if let RoutedUnit::EeDatagram {
                    priority,
                    ref payload,
                } = unit
                {
                    tracing::debug!(
                        interface = %self.interface,
                        local_mac = ?self.codec.local_mac,
                        guest_mac = ?self.codec.guest_mac,
                        priority,
                        dsap = payload[0],
                        ssap = payload[1],
                        control = payload[2],
                        decoded = ?hpr_lan::parse_frame(&buffer[..length], self.codec.saps.saps().unwrap_or_else(|_| self.codec.provisional_saps())),
                        hex = %hex_dump(&buffer[..length]),
                        "HPR LAN frame received"
                    );
                }
                Ok(Some(vec![RouterEvent::Unit(unit)]))
            }
            Ok(None) => Ok(Some(Vec::new())),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => Err(error),
            Err(error) => {
                tracing::warn!(interface = %self.interface, error = %error, "HPR LAN frame discarded");
                Ok(Some(Vec::new()))
            }
        }
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.drain()?;
        Ok(Vec::new())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        let RoutedUnit::EeDatagram { priority, payload } = unit else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HPR LAN port requires EE datagram unit",
            ));
        };
        if self.outgoing.len() >= QUEUE_LIMIT {
            return Ok(false);
        }
        let frame = self.codec.send(priority, payload)?;
        while let Some(frame) = self.codec.local_frames.pop_front() {
            self.outgoing.push_back(frame);
        }
        if let Some(frame) = frame {
            tracing::debug!(
                interface = %self.interface,
                local_mac = ?self.codec.local_mac,
                guest_mac = ?self.codec.guest_mac,
                priority,
                decoded = ?parse_8023(&frame),
                hex = %hex_dump(&frame),
                "HPR LAN frame queued"
            );
            self.outgoing.push_back(frame);
        }
        self.drain()?;
        Ok(true)
    }

    fn has_capacity(&self) -> bool {
        self.outgoing.len() < QUEUE_LIMIT
    }
    fn available_receive_slots(&self) -> usize {
        QUEUE_LIMIT - self.outgoing.len()
    }
    fn take_completed_information_count(&mut self) -> usize {
        std::mem::take(&mut self.completed)
    }
    fn set_ingress_busy(&mut self, _busy: bool) -> io::Result<()> {
        Ok(())
    }
    fn on_peer_ready(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn disconnect(&mut self) -> io::Result<()> {
        self.outgoing.clear();
        self.codec.saps = HprSapNegotiation::new(self.codec.local_base, self.codec.remote_base)
            .map_err(negotiation_error)?;
        self.codec.setmode.reset();
        self.codec.llc2 = Llc2::new(self.codec.local_base, self.codec.remote_base);
        self.codec.pending_sabme = None;
        self.codec.local_frames.clear();
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.drain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const GUEST: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn xid(sap: u8) -> Vec<u8> {
        let mut bytes = vec![0; 29];
        bytes[0] = 0x32;
        bytes[9] = 0x04;
        bytes.extend_from_slice(&[0x61, 5, 0x80, 0, 3, 0x80, sap]);
        bytes[1] = bytes.len() as u8;
        bytes
    }

    fn negotiated() -> HprLanCodec {
        let mut codec = HprLanCodec::new(LOCAL, GUEST, 4, 4).unwrap();
        let guest_xid = hpr_lan::encode_frame(
            LOCAL,
            GUEST,
            Kind::Xid,
            false,
            false,
            &xid(0xc8),
            Saps::default(),
        )
        .unwrap();
        codec.receive(&guest_xid).unwrap();
        codec.send(0, [vec![4, 4, 0xaf], xid(4)].concat()).unwrap();
        codec.arm_after_validated_xid().unwrap();
        codec
    }

    fn lan_llc(pdu: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + pdu.len());
        frame.extend_from_slice(&LOCAL);
        frame.extend_from_slice(&GUEST);
        frame.extend_from_slice(&(pdu.len() as u16).to_be_bytes());
        frame.extend_from_slice(pdu);
        frame
    }

    #[test]
    fn lan_primary_waits_for_ee_setmode_then_answers_sabme_and_rr_locally() {
        let mut codec = negotiated();
        let request = codec.receive(&lan_llc(&[4, 4, 0x7f])).unwrap().unwrap();
        let RoutedUnit::EeDatagram { priority, payload } = request else {
            panic!("EE request expected")
        };
        assert_eq!(priority, 0);
        assert_eq!(
            payload,
            [vec![4, 4, 3], XidDone::Request.encode().to_vec()].concat()
        );
        assert!(codec.local_frames.is_empty());
        assert!(codec
            .send(
                0,
                [vec![4, 4, 3], XidDone::Response.encode().to_vec()].concat()
            )
            .unwrap()
            .is_none());
        assert_eq!(
            &codec.local_frames.pop_front().unwrap()[14..],
            &[4, 5, 0x73]
        );
        assert_eq!(codec.setmode.phase(), Phase::Active);
        assert!(codec.receive(&lan_llc(&[4, 4, 1, 1])).unwrap().is_none());
        assert_eq!(
            &codec.local_frames.pop_front().unwrap()[14..],
            &[4, 5, 1, 1]
        );
        assert!(
            matches!(codec.receive(&lan_llc(&[4, 4, 0, 0])), Err(ref error) if error.kind() == io::ErrorKind::Unsupported)
        );
    }

    #[test]
    fn ee_primary_waits_for_lan_ua_before_xid_done_response() {
        let mut codec = negotiated();
        assert!(codec
            .send(
                0,
                [vec![4, 4, 3], XidDone::Request.encode().to_vec()].concat()
            )
            .unwrap()
            .is_none());
        assert_eq!(
            &codec.local_frames.pop_front().unwrap()[14..],
            &[4, 4, 0x7f]
        );
        assert_eq!(codec.setmode.phase(), Phase::WaitingForLanUa);
        let response = codec.receive(&lan_llc(&[4, 5, 0x73])).unwrap().unwrap();
        let RoutedUnit::EeDatagram { priority, payload } = response else {
            panic!("EE response expected")
        };
        assert_eq!(priority, 0);
        assert_eq!(
            payload,
            [vec![4, 4, 3], XidDone::Response.encode().to_vec()].concat()
        );
        assert_eq!(codec.setmode.phase(), Phase::Active);
    }

    #[test]
    fn relays_xid_and_priority_ui_after_directional_sap_exchange() {
        let mut codec = HprLanCodec::new(LOCAL, GUEST, 4, 4).unwrap();
        let guest_xid = xid(0xc8);
        let lan = hpr_lan::encode_frame(
            LOCAL,
            GUEST,
            Kind::Xid,
            false,
            true,
            &guest_xid,
            Saps::default(),
        )
        .unwrap();
        let RoutedUnit::EeDatagram { priority, payload } = codec.receive(&lan).unwrap().unwrap()
        else {
            panic!("expected EE datagram")
        };
        assert_eq!(priority, 0);
        assert_eq!(payload, lan[14..]);
        let peer_xid = xid(4);
        let ee_xid = [vec![4, 4, 0xbf], peer_xid].concat();
        let emitted = codec.send(0, ee_xid.clone()).unwrap().unwrap();
        assert_eq!(&emitted[14..], ee_xid);
        let lan_ui = hpr_lan::encode_frame(
            LOCAL,
            GUEST,
            Kind::UiNlp,
            false,
            false,
            &[0xc2, 0],
            Saps::new(4, 4, 0xc8, 4).unwrap(),
        )
        .unwrap();
        assert!(codec.receive(&lan_ui).is_err());
        codec.arm_after_validated_xid().unwrap();
        codec.setmode.on_lan_sabme(true).unwrap();
        codec.setmode.on_ee_response().unwrap();
        let RoutedUnit::EeDatagram { priority, payload } = codec.receive(&lan_ui).unwrap().unwrap()
        else {
            panic!("expected EE datagram")
        };
        assert_eq!(priority, 3);
        assert_eq!(&payload[..3], &[4, 0xc8, 3]);
        let outbound = codec.send(3, vec![0xc8, 4, 3, 0xc2, 0]).unwrap().unwrap();
        assert_eq!(&outbound[14..], &[0xc8, 4, 3, 0xc2, 0]);
    }

    #[test]
    fn rejects_legacy_llc2_and_wrong_ee_priority() {
        let mut codec = HprLanCodec::new(LOCAL, GUEST, 4, 4).unwrap();
        let mut frame =
            hpr_lan::encode_frame(LOCAL, GUEST, Kind::Xid, false, false, &[], Saps::default())
                .unwrap();
        frame[16] = 0;
        frame[12..14].copy_from_slice(&4u16.to_be_bytes());
        frame.push(0);
        assert!(
            matches!(codec.receive(&frame), Err(ref error) if error.kind() == io::ErrorKind::Unsupported)
        );
        assert!(codec.send(2, vec![4, 4, 0xaf]).is_err());
        assert!(codec.send(3, vec![0xc8, 4, 3, 0xc2]).is_err());
    }
}

/// Opt-in, ignored diagnostic. It is deliberately outside router configuration
/// and forwards only EE/LAN LDLC U-controls. SETMODE remains unarmed, so no
/// HPR UI or LLC2 traffic crosses this experiment.
#[cfg(all(test, target_os = "linux"))]
mod diagnostic_test {
    use super::*;
    use crate::ip_ports::EePort;
    use router_core::xid3::Xid3;
    use std::{
        env,
        net::IpAddr,
        thread,
        time::{Duration, Instant},
    };

    fn setting(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
    }

    fn mac(name: &str) -> [u8; 6] {
        let value = setting(name);
        let octets: Vec<_> = value
            .split(':')
            .map(|part| u8::from_str_radix(part, 16).expect("invalid MAC octet"))
            .collect();
        octets.try_into().expect("MAC must have six octets")
    }

    fn allow_empty_xid(payload: &[u8], now: Instant, last: &mut Option<Instant>) -> bool {
        if !matches!(payload, [4, 4 | 5, 0xaf | 0xbf]) {
            return false;
        }
        if last.is_some_and(|previous| now.duration_since(previous) < Duration::from_secs(2)) {
            return false;
        }
        *last = Some(now);
        true
    }

    fn forward_control(
        unit: RoutedUnit,
        destination: &mut dyn RoutePort,
        direction: &str,
        last_empty_xid: &mut Option<Instant>,
    ) -> io::Result<()> {
        let RoutedUnit::EeDatagram {
            priority,
            ref payload,
        } = unit
        else {
            return Ok(());
        };
        if priority != 0 {
            return Ok(());
        }
        let datagram = Datagram::decode(CONTROL_PORT, payload.clone())?;
        if datagram.kind == LdlcKind::UiNlp {
            return Ok(());
        }
        if datagram.kind == LdlcKind::Xid {
            if payload.len() == 3 {
                if !allow_empty_xid(payload, Instant::now(), last_empty_xid) {
                    return Ok(());
                }
                eprintln!("{direction}: bounded empty XID probe");
            } else {
                let xid = Xid3::decode(&payload[3..]);
                match xid {
                Ok(xid) => eprintln!("{direction}: XID3 length={} node_id={:02x?} role={:?} exchange={:?} abm={} btu={} cv61_sap={:?}", payload.len()-3, xid.node_id(), xid.role(), xid.exchange_state(), xid.abm_capable(), xid.max_receive_btu(), hpr_lan::advertised_hpr_sap(&payload[3..], if direction == "LAN to EE" { HprMedium::Lan } else { HprMedium::EnterpriseExtender })),
                Err(error) => {
                    eprintln!("{direction}: XID control length={} XID3 rejected={error:?}", payload.len()-3);
                    return Ok(());
                }
                }
            }
        } else {
            eprintln!("{direction}: {:?} control", datagram.kind);
        }
        if !destination.send(unit)? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "diagnostic destination queue full",
            ));
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires explicit SNA_DIAG_* environment, CAP_NET_RAW, and an isolated lab TAP"]
    fn mixed_media_xid_only() -> io::Result<()> {
        let mut lan = HprLanPort::open(
            &setting("SNA_DIAG_TAP"),
            mac("SNA_DIAG_PROXY_MAC"),
            mac("SNA_DIAG_GUEST_MAC"),
            4,
            4,
        )?;
        let local_ip: IpAddr = setting("SNA_DIAG_LOCAL_IP")
            .parse()
            .expect("invalid local IP");
        let peer_ip: IpAddr = setting("SNA_DIAG_PEER_IP")
            .parse()
            .expect("invalid peer IP");
        let mut ee = EePort::open(local_ip, peer_ip)?;
        let seconds: u64 = setting("SNA_DIAG_SECONDS")
            .parse()
            .expect("invalid seconds");
        if !(1..=300).contains(&seconds) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "diagnostic duration outside 1..300 seconds",
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut lan_last_empty_xid = None;
        let mut ee_last_empty_xid = None;
        while Instant::now() < deadline {
            for event in lan.poll(true)?.unwrap_or_default() {
                if let RouterEvent::Unit(unit) = event {
                    forward_control(unit, &mut ee, "LAN to EE", &mut lan_last_empty_xid)?;
                }
            }
            for event in ee.poll(true)?.unwrap_or_default() {
                if let RouterEvent::Unit(unit) = event {
                    forward_control(unit, &mut lan, "EE to LAN", &mut ee_last_empty_xid)?;
                }
            }
            lan.tick()?;
            ee.tick()?;
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }

    #[test]
    fn empty_xid_bootstrap_is_exact_and_rate_bounded() {
        let start = Instant::now();
        let mut last = None;
        assert!(!allow_empty_xid(&[4, 4, 3], start, &mut last));
        assert!(!allow_empty_xid(&[4, 6, 0xaf], start, &mut last));
        assert!(allow_empty_xid(&[4, 4, 0xbf], start, &mut last));
        assert!(!allow_empty_xid(
            &[4, 5, 0xaf],
            start + Duration::from_secs(1),
            &mut last
        ));
        assert!(allow_empty_xid(
            &[4, 5, 0xaf],
            start + Duration::from_secs(2),
            &mut last
        ));
    }
}
