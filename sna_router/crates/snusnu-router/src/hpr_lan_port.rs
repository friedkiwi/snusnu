//! Prototype one-adjacency HPR LAN media port. It translates only 802.3 LLC
//! framing and EE UDP priority selection; it is deliberately not wired into
//! configuration until a paired LAN/EE link-activation capture validates it.

use crate::routing::{RoutePort, RoutedUnit, RouterEvent};
use link_linux::packet::{PacketPort, MAX_FRAME_LEN};
use router_core::{
    hpr_lan::{self, HprMedium, HprSapNegotiation, Kind, NegotiationError, Saps, DEFAULT_HPR_SAP},
    llc::{parse_8023, Control},
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
        })
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
        let Control::Unnumbered { byte: control } = llc.control else {
            // FID2 I-frames and LLC2 supervision are outside this HPR media port.
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
            hpr_lan::classify_nlp(frame.information)
                .map_err(|_| invalid("invalid HPR NLP header"))?
                .ee_destination_port()
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

    fn send(&mut self, priority: u8, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        let port = CONTROL_PORT
            .checked_add(priority as u16)
            .ok_or_else(|| invalid("invalid EE priority"))?;
        let datagram = Datagram::decode(port, payload)?;
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
        Ok(frame)
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
        match self.codec.receive(&buffer[..length]) {
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
        let emitted = codec.send(0, ee_xid.clone()).unwrap();
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
        let RoutedUnit::EeDatagram { priority, payload } = codec.receive(&lan_ui).unwrap().unwrap()
        else {
            panic!("expected EE datagram")
        };
        assert_eq!(priority, 3);
        assert_eq!(&payload[..3], &[4, 0xc8, 3]);
        let outbound = codec.send(3, vec![0xc8, 4, 3, 0xc2, 0]).unwrap();
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
        assert!(codec.receive(&frame).unwrap().is_none());
        assert!(codec.send(2, vec![4, 4, 0xaf]).is_err());
        assert!(codec.send(3, vec![0xc8, 4, 3, 0xc2]).is_err());
    }
}
