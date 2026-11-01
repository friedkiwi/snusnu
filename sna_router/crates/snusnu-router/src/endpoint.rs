//! One SNA LLC2 association on a Linux Ethernet interface.
//!
//! The endpoint owns the local LLC2 link. Its caller routes XID/TEST PDUs
//! and delivered SNA information to another endpoint or encapsulation.

use link_linux::packet::{PacketPort, MAX_FRAME_LEN};
use router_core::{
    llc::{parse_8023, Control, LlcFrame, SNA_SAP},
    llc2::{Effect, Error as LlcError, Llc2, State},
    packet_log::{decode_ethernet, hex_dump},
};
use std::{
    collections::VecDeque,
    io,
    time::{Duration, Instant},
};

const QUEUE_LIMIT: usize = 32;
const RETRY_INTERVAL: Duration = Duration::from_secs(4);

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Event {
    Type1(Vec<u8>),
    Information(Vec<u8>),
    Connected,
    Disconnected,
    TimedOut,
}

pub(crate) struct Endpoint {
    port: PacketPort,
    interface: String,
    guest_mac: [u8; 6],
    proxy_mac: [u8; 6],
    llc: Llc2,
    queued: VecDeque<Vec<u8>>,
    deadline: Option<Instant>,
    connect_after: Option<Instant>,
    completed_information: usize,
}

impl Endpoint {
    pub(crate) fn open(
        interface: &str,
        guest_mac: [u8; 6],
        proxy_mac: [u8; 6],
    ) -> io::Result<Self> {
        let port = PacketPort::open(interface).map_err(|error| {
            tracing::error!(interface, error = %error, "failed to open AF_PACKET interface");
            error
        })?;
        tracing::info!(interface, guest_mac = %format_mac(guest_mac), proxy_mac = %format_mac(proxy_mac), sap = SNA_SAP, "LLC endpoint opened");
        Ok(Self {
            port,
            interface: interface.to_owned(),
            guest_mac,
            proxy_mac,
            llc: Llc2::new(SNA_SAP, SNA_SAP),
            queued: VecDeque::new(),
            deadline: None,
            connect_after: None,
            completed_information: 0,
        })
    }

    pub(crate) fn state(&self) -> State {
        self.llc.state()
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.available_receive_slots() > 0
    }

    /// Free complete information frames, including the local LLC send window
    /// in the occupied count. Routers can charge one slot per routed PIU.
    pub(crate) fn available_receive_slots(&self) -> usize {
        QUEUE_LIMIT.saturating_sub(self.buffered_information_count())
    }

    /// Include the sent I-frame retained for LLC retransmission. A routed
    /// transport can use this count when granting downstream capacity.
    pub(crate) fn buffered_information_count(&self) -> usize {
        self.queued.len() + usize::from(self.llc.has_pending_information())
    }

    pub(crate) fn take_completed_information_count(&mut self) -> usize {
        std::mem::take(&mut self.completed_information)
    }

    /// Poll one frame. `can_accept_information` is the capacity of the next
    /// hop, checked before acknowledging a numbered LLC information frame.
    pub(crate) fn poll(&mut self, can_accept_information: bool) -> io::Result<Option<Vec<Event>>> {
        let mut buffer = [0u8; MAX_FRAME_LEN];
        match self.port.receive_frame(&mut buffer) {
            Ok(length) => Ok(Some(
                self.receive_frame(&buffer[..length], can_accept_information)?,
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => {
                tracing::error!(interface = %self.interface, error = %error, "failed to receive Ethernet frame");
                Err(error)
            }
        }
    }

    fn receive_frame(
        &mut self,
        bytes: &[u8],
        can_accept_information: bool,
    ) -> io::Result<Vec<Event>> {
        let frame = match parse_8023(bytes) {
            Ok(frame) => frame,
            Err(error) => {
                tracing::trace!(interface = %self.interface, bytes = bytes.len(), reason = ?error, "ignored non-LLC Ethernet frame");
                return Ok(Vec::new());
            }
        };
        if frame.source != self.guest_mac || frame.destination != self.proxy_mac || !frame.is_sna()
        {
            tracing::trace!(interface = %self.interface, source_mac = %format_mac(frame.source), destination_mac = %format_mac(frame.destination), dsap = frame.dsap, ssap = frame.ssap, "ignored LLC frame outside configured peer");
            return Ok(Vec::new());
        }
        tracing::debug!(interface = %self.interface, source_mac = %format_mac(frame.source), destination_mac = %format_mac(frame.destination), dsap = frame.dsap, ssap = frame.ssap, control = ?frame.control, information_bytes = frame.information.len(), decoded = %decode_ethernet(bytes), hex = %hex_dump(bytes), "ethernet frame received");
        if is_type1(&frame) {
            // The declared 802.3 length excludes any Ethernet padding. The
            // LLC PDU remains unchanged across the router.
            return Ok(vec![Event::Type1(
                bytes[14..17 + frame.information.len()].to_vec(),
            )]);
        }
        let pending_before = self.llc.has_pending_information();
        let effects = self
            .llc
            .receive_with_capacity(&frame, can_accept_information)
            .map_err(llc_error)?;
        if pending_before
            && !self.llc.has_pending_information()
            && self.llc.state() == State::Connected
        {
            self.completed_information += 1;
            tracing::trace!(interface = %self.interface, completed = self.completed_information, "LLC information acknowledged by peer");
        }
        let events = self.apply(effects)?;
        self.flush()?;
        self.sync_deadline();
        Ok(events)
    }

    pub(crate) fn send_type1(&self, pdu: &[u8]) -> io::Result<()> {
        if pdu.len() < 3
            || pdu[0] != SNA_SAP
            || pdu[1] & !1 != SNA_SAP
            || !matches!(pdu[2] & !0x10, 0xaf | 0xe3)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SNA XID/TEST PDU",
            ));
        }
        self.send_llc(pdu)
    }

    /// Queue information for the local LLC2 peer. A full queue does not drop
    /// or acknowledge the payload; callers must apply upstream backpressure.
    pub(crate) fn queue_information(&mut self, information: Vec<u8>) -> io::Result<bool> {
        if !self.has_capacity() {
            tracing::warn!(interface = %self.interface, queued = self.buffered_information_count(), limit = QUEUE_LIMIT, "LLC egress queue full");
            return Ok(false);
        }
        tracing::trace!(interface = %self.interface, bytes = information.len(), queued = self.buffered_information_count() + 1, "SNA information queued for LLC peer");
        self.queued.push_back(information);
        self.flush()?;
        self.sync_deadline();
        Ok(true)
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        while self.llc.state() == State::Connected {
            let Some(information) = self.queued.front() else {
                break;
            };
            match self.llc.send_information(information) {
                Ok(pdu) => {
                    self.send_llc(&pdu)?;
                    self.queued.pop_front();
                }
                Err(LlcError::WindowFull | LlcError::RemoteBusy) => break,
                Err(error) => return Err(llc_error(error)),
            }
        }
        Ok(())
    }

    pub(crate) fn set_local_busy(&mut self, busy: bool) -> io::Result<()> {
        if let Some(pdu) = self.llc.set_local_busy(busy) {
            tracing::debug!(interface = %self.interface, busy, signal = if busy { "RNR" } else { "RR" }, "LLC receive flow state changed");
            self.send_llc(&pdu)?;
        }
        Ok(())
    }

    pub(crate) fn begin_connect_after(&mut self, delay: Duration) {
        self.connect_after = Some(Instant::now() + delay);
        tracing::debug!(interface = %self.interface, delay_ms = delay.as_millis(), "LLC active connect scheduled");
    }

    pub(crate) fn cancel_connect(&mut self) {
        self.connect_after = None;
    }

    pub(crate) fn disconnect(&mut self) -> io::Result<()> {
        tracing::info!(interface = %self.interface, state = ?self.llc.state(), "LLC endpoint disconnecting");
        self.queued.clear();
        self.connect_after = None;
        if let Some(pdu) = self.llc.disconnect() {
            self.send_llc(&pdu)?;
        }
        self.sync_deadline();
        Ok(())
    }

    pub(crate) fn tick(&mut self) -> io::Result<Vec<Event>> {
        let now = Instant::now();
        if self.connect_after.is_some_and(|deadline| now >= deadline) {
            self.connect_after = None;
            if self.llc.state() == State::Disconnected {
                tracing::info!(interface = %self.interface, "LLC active connect starting");
                let pdu = self.llc.begin_connect().map_err(llc_error)?;
                self.send_llc(&pdu)?;
                self.sync_deadline();
            }
        }
        if !self.deadline.is_some_and(|deadline| now >= deadline) {
            return Ok(Vec::new());
        }
        self.deadline = None;
        tracing::warn!(interface = %self.interface, state = ?self.llc.state(), "LLC acknowledgement timer expired");
        let effects = self.llc.on_ack_timeout();
        let events = self.apply(effects)?;
        self.sync_deadline();
        Ok(events)
    }

    fn apply(&mut self, effects: Vec<Effect>) -> io::Result<Vec<Event>> {
        let mut events = Vec::new();
        for effect in effects {
            match effect {
                Effect::Send(pdu) => self.send_llc(&pdu)?,
                Effect::Deliver(information) => {
                    tracing::trace!(interface = %self.interface, bytes = information.len(), "SNA information accepted from LLC peer");
                    events.push(Event::Information(information.to_vec()))
                }
                Effect::Connected => {
                    self.connect_after = None;
                    tracing::info!(interface = %self.interface, guest_mac = %format_mac(self.guest_mac), proxy_mac = %format_mac(self.proxy_mac), "LLC2 connected");
                    events.push(Event::Connected);
                }
                Effect::Disconnected => {
                    tracing::info!(interface = %self.interface, "LLC2 disconnected");
                    events.push(Event::Disconnected)
                }
                Effect::TimedOut => {
                    tracing::warn!(interface = %self.interface, "LLC2 timed out");
                    events.push(Event::TimedOut)
                }
            }
        }
        Ok(events)
    }

    fn send_llc(&self, pdu: &[u8]) -> io::Result<()> {
        if pdu.len() > 1500 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LLC PDU too large",
            ));
        }
        let mut frame = Vec::with_capacity(14 + pdu.len());
        frame.extend_from_slice(&self.guest_mac);
        frame.extend_from_slice(&self.proxy_mac);
        frame.extend_from_slice(&(pdu.len() as u16).to_be_bytes());
        frame.extend_from_slice(pdu);
        self.port.send_frame(&frame).map_err(|error| {
            tracing::error!(interface = %self.interface, destination_mac = %format_mac(self.guest_mac), error = %error, "failed to send Ethernet frame");
            error
        })?;
        tracing::debug!(interface = %self.interface, source_mac = %format_mac(self.proxy_mac), destination_mac = %format_mac(self.guest_mac), decoded = %decode_ethernet(&frame), hex = %hex_dump(&frame), "ethernet frame sent");
        Ok(())
    }

    fn sync_deadline(&mut self) {
        if self.llc.state() == State::Connecting || self.llc.has_pending_information() {
            self.deadline
                .get_or_insert_with(|| Instant::now() + RETRY_INTERVAL);
        } else {
            self.deadline = None;
        }
    }
}

pub(crate) fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn is_type1(frame: &LlcFrame<'_>) -> bool {
    matches!(frame.control, Control::Unnumbered { byte } if matches!(byte & !0x10, 0xaf | 0xe3))
}

fn llc_error(error: LlcError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("LLC2: {error:?}"))
}
