//! Two isolated TAPs with local LLC2 termination on each side.
//!
//! The guest systems own XID3, PIUs and APPN. We relay XID/TEST unchanged;
//! numbered LLC traffic is acknowledged locally and only its information
//! field crosses to the other local LLC2 association.

use super::STOP;
use link_linux::packet::{PacketPort, MAX_FRAME_LEN};
use router_core::{
    llc::{parse_8023, Control, LlcFrame, SNA_SAP},
    llc2::{Effect, Error as LlcError, Llc2, State},
};
use std::{
    collections::VecDeque,
    io,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const QUEUE_LIMIT: usize = 32;
const RETRY_INTERVAL: Duration = Duration::from_secs(4);
const CONNECT_BARRIER: Duration = Duration::from_millis(200);

struct Leg {
    port: PacketPort,
    guest_mac: [u8; 6],
    proxy_mac: [u8; 6],
    llc: Llc2,
    queued: VecDeque<Vec<u8>>,
    deadline: Option<Instant>,
    connect_after: Option<Instant>,
    delivered: u64,
}

impl Leg {
    fn new(port: PacketPort, guest_mac: [u8; 6], proxy_mac: [u8; 6]) -> Self {
        Self {
            port,
            guest_mac,
            proxy_mac,
            llc: Llc2::new(SNA_SAP, SNA_SAP),
            queued: VecDeque::new(),
            deadline: None,
            connect_after: None,
            delivered: 0,
        }
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
        self.port.send_frame(&frame)
    }

    fn flush(&mut self) -> io::Result<()> {
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

    fn clear(&mut self) {
        self.queued.clear();
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

pub(super) fn run(
    interface_a: &str,
    interface_b: &str,
    mac_a: [u8; 6],
    mac_b: [u8; 6],
) -> io::Result<()> {
    let a = PacketPort::open(interface_a)?;
    let b = PacketPort::open(interface_b)?;
    let mut legs = [Leg::new(a, mac_a, mac_b), Leg::new(b, mac_b, mac_a)];
    eprintln!("lab link: {interface_a} <-> {interface_b}; SNA SAP 04");
    let mut buffer = [0u8; MAX_FRAME_LEN];
    while !STOP.load(Ordering::Relaxed) {
        let mut received = false;
        for side in 0..2 {
            loop {
                match legs[side].port.receive_frame(&mut buffer) {
                    Ok(length) => {
                        received = true;
                        receive(&mut legs, side, &buffer[..length])?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }
        timer(&mut legs)?;
        if !received {
            thread::sleep(Duration::from_micros(200));
        }
    }
    Ok(())
}

fn timer(legs: &mut [Leg; 2]) -> io::Result<()> {
    for side in 0..2 {
        if legs[side]
            .connect_after
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            legs[side].connect_after = None;
            if legs[side].llc.state() == State::Disconnected
                && legs[1 - side].llc.state() == State::Connected
            {
                let pdu = legs[side].llc.begin_connect().map_err(llc_error)?;
                legs[side].send_llc(&pdu)?;
                legs[side].sync_deadline();
            }
        }
    }
    for side in 0..2 {
        if !legs[side]
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            continue;
        }
        legs[side].deadline = None;
        let effects = legs[side].llc.on_ack_timeout();
        for effect in effects {
            match effect {
                Effect::Send(pdu) => legs[side].send_llc(&pdu)?,
                Effect::TimedOut => eprintln!("lab link: leg {side} timed out"),
                Effect::Disconnected => disconnect_opposite(legs, side)?,
                Effect::Connected | Effect::Deliver(_) => {}
            }
        }
        legs[side].sync_deadline();
    }
    Ok(())
}

fn receive(legs: &mut [Leg; 2], side: usize, bytes: &[u8]) -> io::Result<()> {
    let Ok(frame) = parse_8023(bytes) else {
        return Ok(());
    };
    let (local, remote) = split(legs, side);
    if frame.source != local.guest_mac || frame.destination != local.proxy_mac || !frame.is_sna() {
        return Ok(());
    }
    if is_type1(&frame) {
        // The packet socket on the other TAP adds minimum Ethernet padding.
        // The declared 802.3 length excludes any incoming padding.
        remote
            .port
            .send_frame(&bytes[..14 + 3 + frame.information.len()])?;
        eprintln!("lab link: relayed XID/TEST from leg {side}");
        return Ok(());
    }
    let effects = local.llc.receive(&frame).map_err(llc_error)?;
    for effect in effects {
        match effect {
            Effect::Send(pdu) => local.send_llc(&pdu)?,
            Effect::Deliver(information) => {
                if remote.queued.len() == QUEUE_LIMIT {
                    eprintln!("lab link: relay queue full; resetting both legs");
                    disconnect_pair(local, remote)?;
                    return Ok(());
                }
                remote.queued.push_back(information.to_vec());
                local.delivered += 1;
                if local.delivered == 1 || local.delivered % 10 == 0 {
                    eprintln!(
                        "lab link: leg {side} delivered {} SNA fields",
                        local.delivered
                    );
                }
            }
            Effect::Connected => {
                eprintln!("lab link: leg {side} connected");
                local.connect_after = None;
                if remote.llc.state() == State::Disconnected {
                    // Give the answering SNA endpoint time to finish its
                    // outstanding XID exchange. It may initiate SABME itself.
                    remote.connect_after = Some(Instant::now() + CONNECT_BARRIER);
                }
            }
            Effect::Disconnected => {
                eprintln!("lab link: leg {side} disconnected");
                disconnect_pair(local, remote)?;
            }
            Effect::TimedOut => eprintln!("lab link: leg {side} timed out"),
        }
    }
    local.flush()?;
    remote.flush()?;
    local.sync_deadline();
    remote.sync_deadline();
    Ok(())
}

fn disconnect_opposite(legs: &mut [Leg; 2], side: usize) -> io::Result<()> {
    let (local, remote) = split(legs, side);
    disconnect_pair(local, remote)
}

fn disconnect_pair(local: &mut Leg, remote: &mut Leg) -> io::Result<()> {
    local.clear();
    remote.clear();
    local.connect_after = None;
    remote.connect_after = None;
    if let Some(pdu) = local.llc.disconnect() {
        local.send_llc(&pdu)?;
    }
    if let Some(pdu) = remote.llc.disconnect() {
        remote.send_llc(&pdu)?;
    }
    local.sync_deadline();
    remote.sync_deadline();
    Ok(())
}

fn split(legs: &mut [Leg; 2], side: usize) -> (&mut Leg, &mut Leg) {
    if side == 0 {
        let (local, remote) = legs.split_at_mut(1);
        (&mut local[0], &mut remote[0])
    } else {
        let (remote, local) = legs.split_at_mut(1);
        (&mut local[0], &mut remote[0])
    }
}

fn is_type1(frame: &LlcFrame<'_>) -> bool {
    matches!(frame.control, Control::Unnumbered { byte } if matches!(byte & !0x10, 0xaf | 0xe3))
}

fn llc_error(error: LlcError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("LLC2: {error:?}"))
}
