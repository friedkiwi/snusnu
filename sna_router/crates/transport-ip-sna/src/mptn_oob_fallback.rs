//! Pure retry state for TCP62 UDP/397 out-of-band expedited and abort flows.
//!
//! IBM's TCP62 draft sections 3.2.2.1 and 3.4 prescribe a TCP expedited
//! acknowledgement deadline, an OOB fallback, OOB replies, five retries,
//! and immediate OOB abort. The caller supplies time and must validate each
//! datagram against its original MPTN Connect before passing it here. This
//! state does not encode X'83', deduplicate TCP/UDP payload copies, or enable
//! the X'83' required compensation. V5R4 has not emitted X'83' in our lab.

use std::{
    io,
    time::{Duration, Instant},
};

use crate::{
    mptn_connect::Connect,
    mptn_oob::{Datagram, Kind},
};

pub const TCP_ACK_WAIT: Duration = Duration::from_secs(3);
pub const OOB_REPLY_WAIT: Duration = Duration::from_secs(10);
pub const MAX_OOB_RETRANSMISSIONS: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Expedited,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Build and send an X'83' request with the original Connect identity,
    /// this sequence and the same payload on each retransmission.
    SendOob { purpose: Purpose, sequence: u16 },
    /// Neither TCP nor UDP acknowledged the expedited data. Retire the LU
    /// session and its transport instead of continuing without SON.
    CloseUnresponsive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    ExpeditedAcknowledged,
    AbortAcknowledged,
    Rejected,
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    AwaitTcpAck,
    AwaitOobReply { retransmissions: u8 },
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    purpose: Purpose,
    sequence: u16,
    stage: Stage,
    since: Instant,
}

#[derive(Default)]
pub struct Fallback {
    pending: Option<Pending>,
    closed: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Fallback {
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// An abort drops queued normal data and disables further inbound data.
    /// The caller must enforce this on the actual TCP/native queues.
    pub fn normal_may_pass(&self) -> bool {
        !self.closed && !self.pending.is_some_and(|p| p.purpose == Purpose::Abort)
    }

    /// Call immediately after queueing one TCP X'01' record. The sequence is
    /// owned by the sender's per-connection expedited sequence counter.
    pub fn sent_tcp_expedited(&mut self, sequence: u16, now: Instant) -> io::Result<()> {
        if self.closed || self.pending.is_some() {
            return Err(invalid("TCP62 OOB fallback already pending or closed"));
        }
        self.pending = Some(Pending {
            purpose: Purpose::Expedited,
            sequence,
            stage: Stage::AwaitTcpAck,
            since: now,
        });
        Ok(())
    }

    /// An UNBIND/abort uses OOB immediately, without a TCP X'01' attempt.
    /// It preempts any pending expedited fallback; callers must discard
    /// queued normal/expedited TCP data and stop accepting session traffic.
    pub fn begin_abort(&mut self, sequence: u16, now: Instant) -> io::Result<Action> {
        if self.closed {
            return Err(invalid("TCP62 OOB session is closed"));
        }
        self.pending = Some(Pending {
            purpose: Purpose::Abort,
            sequence,
            stage: Stage::AwaitOobReply { retransmissions: 0 },
            since: now,
        });
        Ok(Action::SendOob {
            purpose: Purpose::Abort,
            sequence,
        })
    }

    /// A late TCP acknowledgement still completes an expedited transfer
    /// after OOB fallback began; it cancels pending OOB retries.
    pub fn received_tcp_ack(&mut self) -> io::Result<Completion> {
        let pending = self
            .pending
            .ok_or_else(|| invalid("unsolicited TCP62 expedited ACK"))?;
        if pending.purpose != Purpose::Expedited || self.closed {
            return Err(invalid("TCP62 ACK cannot complete OOB abort"));
        }
        self.pending = None;
        Ok(Completion::ExpeditedAcknowledged)
    }

    /// Handle only an X'83' response that belongs to the original Connect
    /// and exact pending sequence. Request/response payloads remain opaque.
    pub fn received_oob_response(
        &mut self,
        datagram: &Datagram<'_>,
        original_connect: &Connect,
    ) -> io::Result<Completion> {
        let pending = self
            .pending
            .ok_or_else(|| invalid("unsolicited TCP62 OOB response"))?;
        if self.closed
            || !matches!(pending.stage, Stage::AwaitOobReply { .. })
            || !datagram.matches_connect(original_connect)
            || datagram.sequence != pending.sequence
        {
            return Err(invalid("TCP62 OOB response identity or sequence mismatch"));
        }
        match datagram.kind {
            Kind::Request => Err(invalid("TCP62 OOB request is not an acknowledgement")),
            Kind::PositiveResponse => {
                self.pending = None;
                if pending.purpose == Purpose::Abort {
                    self.closed = true;
                    Ok(Completion::AbortAcknowledged)
                } else {
                    Ok(Completion::ExpeditedAcknowledged)
                }
            }
            Kind::NegativeResponse => {
                self.pending = None;
                self.closed = true;
                Ok(Completion::Rejected)
            }
        }
    }

    /// Check deadlines after every poll. The initial OOB send happens after
    /// the TCP ACK wait. There are at most five further sends; the next
    /// expired reply deadline closes the session.
    pub fn poll(&mut self, now: Instant) -> Option<Action> {
        let pending = self.pending.as_mut()?;
        let wait = match pending.stage {
            Stage::AwaitTcpAck => TCP_ACK_WAIT,
            Stage::AwaitOobReply { .. } => OOB_REPLY_WAIT,
        };
        if now.saturating_duration_since(pending.since) < wait {
            return None;
        }
        pending.since = now;
        match &mut pending.stage {
            Stage::AwaitTcpAck => {
                pending.stage = Stage::AwaitOobReply { retransmissions: 0 };
                Some(Action::SendOob {
                    purpose: pending.purpose,
                    sequence: pending.sequence,
                })
            }
            Stage::AwaitOobReply { retransmissions }
                if *retransmissions < MAX_OOB_RETRANSMISSIONS =>
            {
                *retransmissions += 1;
                Some(Action::SendOob {
                    purpose: pending.purpose,
                    sequence: pending.sequence,
                })
            }
            Stage::AwaitOobReply { .. } => {
                self.pending = None;
                self.closed = true;
                Some(Action::CloseUnresponsive)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{Address, Direction, TransportRequirements};

    fn connect() -> Connect {
        Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 1,
            source: Address {
                node: vec![0xc1, 0x4b, 0xc2],
            },
            destination: Address {
                node: vec![0xc3, 0x4b, 0xc4],
            },
            correlator: vec![0x44],
            requirements: TransportRequirements {
                max_record: 1024,
                max_expedited: 100,
                max_termination: 100,
            },
            options: Vec::new(),
        }
    }

    fn response<'a>(
        sequence: u16,
        source_node: &'a [u8],
        suffix: &'a [u8],
        kind: Kind,
    ) -> Datagram<'a> {
        Datagram {
            kind,
            sequence,
            correlator_node: source_node,
            correlator_suffix: suffix,
            options: Vec::new(),
            compensation: None,
            user_data: &[],
        }
    }

    #[test]
    fn tcp_ack_then_fallback_and_late_ack_cancel_retries() {
        let start = Instant::now();
        let mut flow = Fallback::default();
        flow.sent_tcp_expedited(0, start).unwrap();
        assert_eq!(
            flow.poll(start + TCP_ACK_WAIT - Duration::from_millis(1)),
            None
        );
        assert_eq!(
            flow.poll(start + TCP_ACK_WAIT),
            Some(Action::SendOob {
                purpose: Purpose::Expedited,
                sequence: 0
            })
        );
        assert!(flow.normal_may_pass());
        assert_eq!(
            flow.received_tcp_ack().unwrap(),
            Completion::ExpeditedAcknowledged
        );
        assert_eq!(flow.poll(start + Duration::from_secs(100)), None);
    }

    #[test]
    fn five_retries_then_close_without_response() {
        let start = Instant::now();
        let mut flow = Fallback::default();
        flow.sent_tcp_expedited(u16::MAX, start).unwrap();
        let first = start + TCP_ACK_WAIT;
        assert!(matches!(
            flow.poll(first),
            Some(Action::SendOob {
                sequence: u16::MAX,
                ..
            })
        ));
        for attempt in 1..=MAX_OOB_RETRANSMISSIONS {
            assert_eq!(
                flow.poll(first + OOB_REPLY_WAIT * u32::from(attempt)),
                Some(Action::SendOob {
                    purpose: Purpose::Expedited,
                    sequence: u16::MAX
                })
            );
        }
        assert_eq!(
            flow.poll(first + OOB_REPLY_WAIT * u32::from(MAX_OOB_RETRANSMISSIONS + 1)),
            Some(Action::CloseUnresponsive)
        );
        assert!(flow.is_closed());
        assert!(!flow.normal_may_pass());
    }

    #[test]
    fn response_must_match_original_connect_and_pending_sequence() {
        let start = Instant::now();
        let c = connect();
        let mut flow = Fallback::default();
        flow.sent_tcp_expedited(9, start).unwrap();
        flow.poll(start + TCP_ACK_WAIT);
        let wrong = response(8, &c.source.node, &c.correlator, Kind::PositiveResponse);
        assert!(flow.received_oob_response(&wrong, &c).is_err());
        let wrong_node = response(
            9,
            &c.destination.node,
            &c.correlator,
            Kind::PositiveResponse,
        );
        assert!(flow.received_oob_response(&wrong_node, &c).is_err());
        let good = response(9, &c.source.node, &c.correlator, Kind::PositiveResponse);
        assert_eq!(
            flow.received_oob_response(&good, &c).unwrap(),
            Completion::ExpeditedAcknowledged
        );
        assert!(!flow.is_pending());
    }

    #[test]
    fn abort_is_immediate_and_stops_normal_flow() {
        let start = Instant::now();
        let c = connect();
        let mut flow = Fallback::default();
        flow.sent_tcp_expedited(1, start).unwrap();
        assert_eq!(
            flow.begin_abort(2, start).unwrap(),
            Action::SendOob {
                purpose: Purpose::Abort,
                sequence: 2
            }
        );
        assert!(!flow.normal_may_pass());
        assert!(flow.received_tcp_ack().is_err());
        let ack = response(2, &c.source.node, &c.correlator, Kind::PositiveResponse);
        assert_eq!(
            flow.received_oob_response(&ack, &c).unwrap(),
            Completion::AbortAcknowledged
        );
        assert!(flow.is_closed());
    }
}
