//! LLC attachment listener for automatic, destination-based routing.
//!
//! One packet socket discovers the guest's chosen proxy MAC. Once the fabric
//! resolves that MAC, a separate endpoint owns the link and its LLC2 credit.

use crate::{
    endpoint::{format_mac, validate_mac_pair, Endpoint, Event},
    routing::{RoutePort, RoutedUnit, RouterEvent},
};
use link_linux::packet::{PacketPort, MAX_FRAME_LEN};
use router_core::{
    llc::{parse_8023, Control},
    llc2::State,
    xid3::Xid3,
};
use std::{
    collections::{HashSet, VecDeque},
    io,
    time::Duration,
};

const CONNECT_BARRIER: Duration = Duration::from_millis(200);

pub(crate) struct LlcAutoListener {
    port: PacketPort,
    interface: String,
    guest_mac: [u8; 6],
    allowed_proxy_macs: HashSet<[u8; 6]>,
    active_proxy_macs: HashSet<[u8; 6]>,
}

pub(crate) struct LlcIngressOffer {
    pub(crate) interface: String,
    pub(crate) guest_mac: [u8; 6],
    pub(crate) proxy_mac: [u8; 6],
    pub(crate) peer_cp: Option<String>,
    first_frame: Vec<u8>,
}

impl LlcAutoListener {
    pub(crate) fn open(interface: &str, guest_mac: [u8; 6]) -> io::Result<Self> {
        if guest_mac == [0; 6] || guest_mac[0] & 1 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid LLC guest MAC",
            ));
        }
        Ok(Self {
            port: PacketPort::open(interface)?,
            interface: interface.to_owned(),
            guest_mac,
            allowed_proxy_macs: HashSet::new(),
            active_proxy_macs: HashSet::new(),
        })
    }

    pub(crate) fn allow_proxy_mac(&mut self, mac: [u8; 6]) -> io::Result<()> {
        validate_mac_pair(self.guest_mac, mac)?;
        self.allowed_proxy_macs.insert(mac);
        Ok(())
    }

    pub(crate) fn withdraw_proxy_mac(&mut self, mac: [u8; 6]) {
        self.allowed_proxy_macs.remove(&mac);
    }

    pub(crate) fn release(&mut self, mac: [u8; 6]) {
        self.active_proxy_macs.remove(&mac);
    }

    /// Reserve a destination before an upstream-initiated circuit opens its
    /// LLC endpoint. This prevents the listener from offering the same link.
    pub(crate) fn reserve(&mut self, mac: [u8; 6]) -> io::Result<bool> {
        if !self.allowed_proxy_macs.contains(&mac) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LLC proxy MAC is not registered for this attachment",
            ));
        }
        Ok(self.active_proxy_macs.insert(mac))
    }

    /// Poll one frame and offer its destination at most once while its
    /// association is active. A private endpoint receives subsequent frames.
    pub(crate) fn poll_offer(&mut self) -> io::Result<Option<LlcIngressOffer>> {
        let mut bytes = [0u8; MAX_FRAME_LEN];
        let length = match self.port.receive_frame(&mut bytes) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some((proxy_mac, peer_cp)) = classify_offer(
            &bytes[..length],
            self.guest_mac,
            &self.allowed_proxy_macs,
            &self.active_proxy_macs,
        )?
        else {
            return Ok(None);
        };
        self.active_proxy_macs.insert(proxy_mac);
        tracing::info!(interface = %self.interface, guest_mac = %format_mac(self.guest_mac), proxy_mac = %format_mac(proxy_mac), peer_cp = ?peer_cp, "LLC automatic session offered");
        Ok(Some(LlcIngressOffer {
            interface: self.interface.clone(),
            guest_mac: self.guest_mac,
            proxy_mac,
            peer_cp,
            first_frame: bytes[..length].to_vec(),
        }))
    }
}

fn classify_offer(
    bytes: &[u8],
    guest_mac: [u8; 6],
    allowed_proxy_macs: &HashSet<[u8; 6]>,
    active_proxy_macs: &HashSet<[u8; 6]>,
) -> io::Result<Option<([u8; 6], Option<String>)>> {
    let Ok(frame) = parse_8023(bytes) else {
        return Ok(None);
    };
    if frame.source != guest_mac
        || !frame.is_sna()
        || !allowed_proxy_macs.contains(&frame.destination)
        || active_proxy_macs.contains(&frame.destination)
    {
        return Ok(None);
    }
    let peer_cp = match frame.control {
        Control::Unnumbered { byte }
            if byte & !0x10 == 0xaf && frame.information.first() == Some(&0x32) =>
        {
            Xid3::decode(frame.information)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid LLC XID3: {error}"),
                    )
                })?
                .cp_name()
                .ok()
        }
        _ => None,
    };
    Ok(Some((frame.destination, peer_cp)))
}

impl LlcIngressOffer {
    /// Pass an owned endpoint and its first events to the native APPN
    /// converter. The opening frame cannot be lost between sockets.
    pub(crate) fn into_endpoint(self) -> io::Result<(Endpoint, Vec<Event>, Option<String>)> {
        self.into_endpoint_with_gate(false)
    }

    fn into_endpoint_with_gate(
        self,
        connect_allowed: bool,
    ) -> io::Result<(Endpoint, Vec<Event>, Option<String>)> {
        let mut endpoint = Endpoint::open(&self.interface, self.guest_mac, self.proxy_mac)?;
        if !connect_allowed {
            endpoint.set_connect_allowed(false)?;
        }
        let first_events = endpoint.inject_frame(&self.first_frame, true)?;
        Ok((endpoint, first_events, self.peer_cp))
    }

    /// Open a private LLC2 association and replay the offered first frame.
    pub(crate) fn open_port(self) -> io::Result<AutoLlcPort> {
        let (endpoint, first_events, _) = self.into_endpoint_with_gate(true)?;
        Ok(AutoLlcPort {
            endpoint,
            first_events: first_events.into(),
        })
    }
}

pub(crate) struct AutoLlcPort {
    endpoint: Endpoint,
    first_events: VecDeque<Event>,
}

impl AutoLlcPort {
    /// A remote circuit can select a known local LLC attachment before that
    /// attachment sends its first frame. The caller reserves the MAC in the
    /// listener first and releases it when the circuit closes.
    pub(crate) fn open_outbound(
        interface: &str,
        guest_mac: [u8; 6],
        proxy_mac: [u8; 6],
    ) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::open(interface, guest_mac, proxy_mac)?,
            first_events: VecDeque::new(),
        })
    }
}

impl RoutePort for AutoLlcPort {
    fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        if !self.first_events.is_empty() {
            return Ok(Some(self.first_events.drain(..).map(map_event).collect()));
        }
        Ok(self
            .endpoint
            .poll(can_accept_information)?
            .map(|events| events.into_iter().map(map_event).collect()))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        Ok(self.endpoint.tick()?.into_iter().map(map_event).collect())
    }

    fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
        match unit {
            RoutedUnit::DlcType1(pdu) => {
                self.endpoint.send_type1(&pdu)?;
                Ok(true)
            }
            RoutedUnit::SnaInformation(data) => self.endpoint.queue_information(data),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encapsulation requires an LLC converter",
            )),
        }
    }

    fn has_capacity(&self) -> bool {
        self.endpoint.has_capacity()
    }
    fn available_receive_slots(&self) -> usize {
        self.endpoint.available_receive_slots()
    }
    fn take_completed_information_count(&mut self) -> usize {
        self.endpoint.take_completed_information_count()
    }
    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.endpoint.set_local_busy(busy)
    }
    fn on_peer_ready(&mut self) -> io::Result<()> {
        if self.endpoint.state() == State::Disconnected {
            self.endpoint.begin_connect_after(CONNECT_BARRIER);
        }
        Ok(())
    }
    fn disconnect(&mut self) -> io::Result<()> {
        self.endpoint.disconnect()
    }
    fn flush(&mut self) -> io::Result<()> {
        self.endpoint.flush()
    }
}

fn map_event(event: Event) -> RouterEvent {
    match event {
        Event::Type1(pdu) => RouterEvent::Unit(RoutedUnit::DlcType1(pdu)),
        Event::Information(data) => RouterEvent::Unit(RoutedUnit::SnaInformation(data)),
        Event::Connected => RouterEvent::Ready,
        Event::Disconnected => RouterEvent::Closed,
        Event::TimedOut => RouterEvent::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(destination: [u8; 6], source: [u8; 6], pdu: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend(destination);
        frame.extend(source);
        frame.extend(u16::try_from(pdu.len()).unwrap().to_be_bytes());
        frame.extend(pdu);
        frame
    }

    #[test]
    fn only_allowed_unclaimed_proxy_macs_offer_a_session() {
        let guest = [0x02, 0, 0, 0, 0, 1];
        let proxy = [0x02, 0x53, 0x4e, 0, 0, 1];
        let pdu = [4, 4, 0xaf];
        let bytes = frame(proxy, guest, &pdu);
        let allowed = HashSet::from([proxy]);
        assert_eq!(
            classify_offer(&bytes, guest, &allowed, &HashSet::new()).unwrap(),
            Some((proxy, None))
        );
        assert_eq!(
            classify_offer(&bytes, guest, &allowed, &HashSet::from([proxy])).unwrap(),
            None
        );
        assert_eq!(
            classify_offer(&bytes, guest, &HashSet::new(), &HashSet::new()).unwrap(),
            None
        );
        let wrong_guest = [0x02, 0, 0, 0, 0, 2];
        assert_eq!(
            classify_offer(&bytes, wrong_guest, &allowed, &HashSet::new()).unwrap(),
            None
        );
    }

    #[test]
    fn xid3_offer_reports_observed_cp() {
        let guest = [0x02, 0, 0, 0, 0, 1];
        let proxy = [0x02, 0x53, 0x4e, 0, 0, 1];
        let xid = [
            0x32, 0x2f, 0xff, 0xf1, 0x23, 0x45, 0x00, 0x00, 0x00, 0xb4, 0xc0, 0x00, 0x00, 0x00,
            0x00, 0x80, 0x01, 0x01, 0x0b, 0x50, 0x00, 0x05, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x00, 0x0e, 0x0c, 0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1,
            0xc2, 0x10, 0x02, 0x11, 0x01,
        ];
        let mut pdu = vec![4, 4, 0xaf];
        pdu.extend(xid);
        assert_eq!(
            classify_offer(
                &frame(proxy, guest, &pdu),
                guest,
                &HashSet::from([proxy]),
                &HashSet::new(),
            )
            .unwrap(),
            Some((proxy, Some("SOLNET.SNAB".into())))
        );
    }
}
