//! Small, deterministic LLC Type 2 endpoint for one MAC/SAP association.
//!
//! This starts as a passive, one-frame-window endpoint. It handles connection
//! setup and local acknowledgement without interpreting SNA information. The
//! caller owns MAC filtering, transmission, and the acknowledgement timer;
//! `on_ack_timeout` is called only when that timer expires. A single pending
//! information frame bounds retransmission storage.

use crate::llc::{Control, LlcFrame};

const SABME: u8 = 0x6f;
const UA: u8 = 0x63;
const DISC: u8 = 0x43;
const DM: u8 = 0x0f;
const POLL_FINAL: u8 = 0x10;
const RR: u8 = 0;
const RNR: u8 = 1;
const REJ: u8 = 2;
const MAX_INFORMATION: usize = 1496; // 1500-byte 802.3 field minus 4-byte LLC2 header
const MAX_RETRIES: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSap,
    NotConnected,
    AlreadyConnecting,
    RemoteBusy,
    WindowFull,
    InformationTooLarge,
    InvalidAcknowledgement,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Effect<'a> {
    /// Complete LLC PDU, from DSAP onward; caller supplies Ethernet addresses.
    Send(Vec<u8>),
    /// One accepted, in-order SNA information field. It borrows the input frame.
    Deliver(&'a [u8]),
    Connected,
    Disconnected,
    TimedOut,
}

#[derive(Debug)]
struct Pending {
    sequence: u8,
    information: Vec<u8>,
    retries: u8,
}

#[derive(Debug)]
pub struct Llc2 {
    local_sap: u8,
    remote_sap: u8,
    state: State,
    send_next: u8,
    receive_next: u8,
    remote_busy: bool,
    pending: Option<Pending>,
    connect_retries: u8,
}

impl Llc2 {
    pub fn new(local_sap: u8, remote_sap: u8) -> Self {
        Self {
            local_sap: local_sap & !1,
            remote_sap: remote_sap & !1,
            state: State::Disconnected,
            send_next: 0,
            receive_next: 0,
            remote_busy: false,
            pending: None,
            connect_retries: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn has_pending_information(&self) -> bool {
        self.pending.is_some()
    }

    /// Tear down this local leg after its circuit target is lost. A connected
    /// peer receives DISC; a connection still being established is cancelled.
    pub fn disconnect(&mut self) -> Option<Vec<u8>> {
        let frame = (self.state == State::Connected).then(|| self.unnumbered(DISC, false, true));
        self.reset_disconnected();
        frame
    }

    pub fn receive<'a>(&mut self, frame: &LlcFrame<'a>) -> Result<Vec<Effect<'a>>, Error> {
        if frame.dsap != self.local_sap || frame.ssap & !1 != self.remote_sap {
            return Err(Error::WrongSap);
        }
        let response = frame.is_response();
        let effects = match frame.control {
            Control::Unnumbered { byte } if byte & !POLL_FINAL == SABME && !response => {
                self.reset_connected();
                vec![
                    Effect::Send(self.unnumbered(UA, true, byte & POLL_FINAL != 0)),
                    Effect::Connected,
                ]
            }
            Control::Unnumbered { byte } if byte & !POLL_FINAL == DISC && !response => {
                let was_connected = self.state == State::Connected;
                self.reset_disconnected();
                let reply = if was_connected { UA } else { DM };
                vec![
                    Effect::Send(self.unnumbered(reply, true, byte & POLL_FINAL != 0)),
                    Effect::Disconnected,
                ]
            }
            Control::Unnumbered { byte } if byte & !POLL_FINAL == DM && response => {
                self.reset_disconnected();
                vec![Effect::Disconnected]
            }
            Control::Unnumbered { byte }
                if byte & !POLL_FINAL == UA && response && self.state == State::Connecting =>
            {
                self.reset_connected();
                vec![Effect::Connected]
            }
            Control::Information {
                send_sequence,
                receive_sequence,
                poll_final,
            } if self.state == State::Connected => {
                self.acknowledge(receive_sequence)?;
                let mut effects = Vec::with_capacity(2);
                if send_sequence == self.receive_next {
                    self.receive_next = self.receive_next.wrapping_add(1) & 0x7f;
                    effects.push(Effect::Deliver(frame.information));
                    effects.push(Effect::Send(self.supervisory(
                        RR,
                        !response,
                        poll_final && !response,
                    )));
                } else if send_sequence == self.receive_next.wrapping_sub(1) & 0x7f {
                    // Repeated frame: acknowledge, but never deliver twice.
                    effects.push(Effect::Send(self.supervisory(
                        RR,
                        !response,
                        poll_final && !response,
                    )));
                } else {
                    effects.push(Effect::Send(self.supervisory(
                        REJ,
                        !response,
                        poll_final && !response,
                    )));
                }
                effects
            }
            Control::Supervisory {
                function,
                receive_sequence,
                poll_final,
            } if self.state == State::Connected => {
                self.acknowledge(receive_sequence)?;
                match function {
                    RR => self.remote_busy = false,
                    RNR => self.remote_busy = true,
                    REJ => self.remote_busy = false,
                    _ => return Ok(Vec::new()), // SREJ is outside this initial window.
                }
                let mut effects = Vec::with_capacity(2);
                if function == REJ {
                    if let Some(pending) = &self.pending {
                        effects.push(Effect::Send(self.information(
                            pending.sequence,
                            &pending.information,
                            false,
                        )));
                    }
                }
                if poll_final && !response {
                    effects.push(Effect::Send(self.supervisory(RR, true, true)));
                }
                effects
            }
            Control::Information { poll_final, .. } | Control::Supervisory { poll_final, .. }
                if self.state == State::Disconnected && !response =>
            {
                vec![Effect::Send(self.unnumbered(DM, true, poll_final))]
            }
            _ => Vec::new(),
        };
        Ok(effects)
    }

    /// Initiate the LLC2 association. The caller sends the returned LLC PDU
    /// and schedules a connection timer; UA completes the handshake.
    pub fn begin_connect(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != State::Disconnected {
            return Err(Error::AlreadyConnecting);
        }
        self.state = State::Connecting;
        self.connect_retries = 0;
        Ok(self.unnumbered(SABME, false, true))
    }

    /// Send one information field. A second send waits until the first is
    /// acknowledged. The caller starts or restarts its acknowledgement timer.
    pub fn send_information(&mut self, information: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state != State::Connected {
            return Err(Error::NotConnected);
        }
        if self.remote_busy {
            return Err(Error::RemoteBusy);
        }
        if self.pending.is_some() {
            return Err(Error::WindowFull);
        }
        if information.len() > MAX_INFORMATION {
            return Err(Error::InformationTooLarge);
        }
        let sequence = self.send_next;
        let frame = self.information(sequence, information, false);
        self.pending = Some(Pending {
            sequence,
            information: information.to_vec(),
            retries: 0,
        });
        self.send_next = self.send_next.wrapping_add(1) & 0x7f;
        Ok(frame)
    }

    /// A timer event is explicit so trace replay and tests need no wall clock.
    pub fn on_ack_timeout(&mut self) -> Vec<Effect<'static>> {
        if self.state == State::Connecting {
            if self.connect_retries >= MAX_RETRIES {
                self.reset_disconnected();
                return vec![Effect::TimedOut, Effect::Disconnected];
            }
            self.connect_retries += 1;
            return vec![Effect::Send(self.unnumbered(SABME, false, true))];
        }
        if self.state != State::Connected {
            return Vec::new();
        }
        let Some(pending) = &mut self.pending else {
            return Vec::new();
        };
        if pending.retries >= MAX_RETRIES {
            self.reset_disconnected();
            return vec![Effect::TimedOut, Effect::Disconnected];
        }
        pending.retries += 1;
        let sequence = pending.sequence;
        let information = pending.information.clone();
        vec![Effect::Send(self.information(sequence, &information, true))]
    }

    fn acknowledge(&mut self, receive_sequence: u8) -> Result<(), Error> {
        match &self.pending {
            Some(pending) if receive_sequence == pending.sequence => Ok(()),
            Some(pending) if receive_sequence == pending.sequence.wrapping_add(1) & 0x7f => {
                self.pending = None;
                Ok(())
            }
            None if receive_sequence == self.send_next => Ok(()),
            _ => Err(Error::InvalidAcknowledgement),
        }
    }

    fn reset_connected(&mut self) {
        self.state = State::Connected;
        self.send_next = 0;
        self.receive_next = 0;
        self.remote_busy = false;
        self.pending = None;
        self.connect_retries = 0;
    }

    fn reset_disconnected(&mut self) {
        self.state = State::Disconnected;
        self.pending = None;
        self.remote_busy = false;
        self.connect_retries = 0;
    }

    fn unnumbered(&self, byte: u8, response: bool, poll_final: bool) -> Vec<u8> {
        vec![
            self.remote_sap,
            self.local_sap | u8::from(response),
            byte | if poll_final { POLL_FINAL } else { 0 },
        ]
    }

    fn supervisory(&self, function: u8, response: bool, poll_final: bool) -> Vec<u8> {
        vec![
            self.remote_sap,
            self.local_sap | u8::from(response),
            0x01 | (function << 2),
            (self.receive_next << 1) | u8::from(poll_final),
        ]
    }

    fn information(&self, sequence: u8, information: &[u8], poll: bool) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + information.len());
        frame.extend_from_slice(&[
            self.remote_sap,
            self.local_sap,
            sequence << 1,
            (self.receive_next << 1) | u8::from(poll),
        ]);
        frame.extend_from_slice(information);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llc::parse_8023;

    fn receive<'a>(link: &mut Llc2, payload: &'a [u8]) -> Vec<Effect<'a>> {
        let mut frame = vec![0; 14];
        frame[12..14].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        // Hold the frame alive for `Effect::Deliver` by leaking this test-only buffer.
        let frame = Box::leak(frame.into_boxed_slice());
        link.receive(&parse_8023(frame).unwrap()).unwrap()
    }

    #[test]
    fn passive_open_data_duplicate_and_close() {
        let mut link = Llc2::new(4, 4);
        assert_eq!(link.state(), State::Disconnected);
        assert_eq!(
            receive(&mut link, &[4, 4, 0x7f]),
            vec![Effect::Send(vec![4, 5, 0x73]), Effect::Connected,]
        );
        assert_eq!(link.state(), State::Connected);
        assert_eq!(
            receive(&mut link, &[4, 4, 0, 0, 0xaa]),
            vec![Effect::Deliver(&[0xaa]), Effect::Send(vec![4, 5, 1, 2]),]
        );
        assert_eq!(
            receive(&mut link, &[4, 4, 0, 0, 0xaa]),
            vec![Effect::Send(vec![4, 5, 1, 2]),]
        );
        assert_eq!(
            receive(&mut link, &[4, 4, 0x53]),
            vec![Effect::Send(vec![4, 5, 0x73]), Effect::Disconnected,]
        );
        assert_eq!(link.state(), State::Disconnected);
    }

    #[test]
    fn one_outstanding_frame_and_acknowledgement() {
        let mut link = Llc2::new(4, 4);
        receive(&mut link, &[4, 4, 0x7f]);
        assert_eq!(
            link.send_information(&[0x11, 0x22]).unwrap(),
            vec![4, 4, 0, 0, 0x11, 0x22]
        );
        assert_eq!(link.send_information(&[0x33]), Err(Error::WindowFull));
        assert_eq!(receive(&mut link, &[4, 5, 1, 2]), Vec::new());
        assert_eq!(
            link.send_information(&[0x33]).unwrap(),
            vec![4, 4, 2, 0, 0x33]
        );
    }

    #[test]
    fn remote_busy_reject_and_explicit_retry_limit() {
        let mut link = Llc2::new(4, 4);
        receive(&mut link, &[4, 4, 0x7f]);
        assert_eq!(
            receive(&mut link, &[4, 4, 5, 1]),
            vec![Effect::Send(vec![4, 5, 1, 1])]
        );
        assert_eq!(link.send_information(&[1]), Err(Error::RemoteBusy));
        receive(&mut link, &[4, 4, 1, 0]);
        link.send_information(&[1]).unwrap();
        assert_eq!(
            receive(&mut link, &[4, 4, 9, 0]),
            vec![Effect::Send(vec![4, 4, 0, 0, 1])]
        );
        for _ in 0..MAX_RETRIES {
            assert_eq!(
                link.on_ack_timeout(),
                vec![Effect::Send(vec![4, 4, 0, 1, 1])]
            );
        }
        assert_eq!(
            link.on_ack_timeout(),
            vec![Effect::TimedOut, Effect::Disconnected]
        );
    }

    #[test]
    fn invalid_ack_does_not_consume_pending_frame() {
        let mut link = Llc2::new(4, 4);
        receive(&mut link, &[4, 4, 0x7f]);
        link.send_information(&[1]).unwrap();
        let frame = parse_8023(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 1, 8]).unwrap();
        assert_eq!(link.receive(&frame), Err(Error::InvalidAcknowledgement));
        assert_eq!(link.send_information(&[2]), Err(Error::WindowFull));
    }

    #[test]
    fn active_connect_retries_and_accepts_ua() {
        let mut link = Llc2::new(4, 4);
        assert_eq!(link.begin_connect().unwrap(), vec![4, 4, 0x7f]);
        assert_eq!(link.state(), State::Connecting);
        assert_eq!(link.begin_connect(), Err(Error::AlreadyConnecting));
        assert_eq!(link.on_ack_timeout(), vec![Effect::Send(vec![4, 4, 0x7f])]);
        assert_eq!(receive(&mut link, &[4, 5, 0x73]), vec![Effect::Connected]);
        assert_eq!(link.state(), State::Connected);
        assert_eq!(
            link.send_information(&[0x55]).unwrap(),
            vec![4, 4, 0, 0, 0x55]
        );
    }

    #[test]
    fn active_connect_times_out_without_peer() {
        let mut link = Llc2::new(4, 4);
        link.begin_connect().unwrap();
        for _ in 0..MAX_RETRIES {
            assert_eq!(link.on_ack_timeout(), vec![Effect::Send(vec![4, 4, 0x7f])]);
        }
        assert_eq!(
            link.on_ack_timeout(),
            vec![Effect::TimedOut, Effect::Disconnected]
        );
        assert_eq!(link.state(), State::Disconnected);
    }

    #[test]
    fn local_disconnect_clears_pending_and_notifies_peer() {
        let mut link = Llc2::new(4, 4);
        receive(&mut link, &[4, 4, 0x7f]);
        link.send_information(&[0x55]).unwrap();
        assert!(link.has_pending_information());
        assert_eq!(link.disconnect(), Some(vec![4, 4, 0x53]));
        assert_eq!(link.state(), State::Disconnected);
        assert!(!link.has_pending_information());
        assert_eq!(link.disconnect(), None);
    }
}
