//! Session-local TCP62 expedited flow control.
//!
//! IBM's TCP62 draft, sections 3.2.2, 3.4 and 5.3.2, requires an immediate
//! five-byte acknowledgement for a TCP expedited record. Expedited data must
//! be delivered before later normal data. An abort discards pending data.
//! This helper does not implement the UDP/397 out-of-band fallback; callers
//! must close the session if an acknowledgement times out.

use std::io;

use crate::anynet::{TcpKind, TcpRecord, MAX_RECORD};

const ACK: [u8; 5] = [0, 0, 0, 5, 0x03];
const REDUCED_TH_AND_RH: usize = 5;

#[derive(Debug, Eq, PartialEq)]
pub enum Inbound {
    /// The expedited payload remains in the input record at `bytes[5..]`.
    /// Deliver it to the native session before any later normal record, and
    /// send this ACK on the same TCP connection promptly.
    Expedited {
        ack: TcpRecord,
    },
    Acked,
    /// Session is closed. Optional termination data begins after the header.
    Aborted {
        has_termination_data: bool,
    },
}

#[derive(Debug)]
pub struct Flow {
    max_pending: usize,
    pending_native: usize,
    unacked_tcp: Option<usize>,
    closed: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Flow {
    pub fn new(max_pending: usize) -> io::Result<Self> {
        if !(MAX_RECORD..=MAX_RECORD * 4).contains(&max_pending) {
            return Err(invalid("invalid TCP62 expedited credit limit"));
        }
        Ok(Self {
            max_pending,
            pending_native: 0,
            unacked_tcp: None,
            closed: false,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn pending_native(&self) -> usize {
        self.pending_native
    }

    pub fn pending_tcp(&self) -> usize {
        self.unacked_tcp.unwrap_or(0)
    }

    /// A later normal record may be delivered only after earlier expedited
    /// bytes have been accepted by the native endpoint.
    pub fn inbound_normal_may_pass(&self) -> bool {
        !self.closed && self.pending_native == 0
    }

    /// Later outbound normal records may follow an expedited record on the
    /// same TCP stream before its ACK arrives. TCP preserves their order;
    /// callers must enqueue them on that same stream in that order.
    pub fn outbound_normal_may_pass(&self) -> bool {
        !self.closed
    }

    /// One unacknowledged TCP expedited record at a time keeps the unnumbered
    /// TCP ACK unambiguous and bounds retained data while OOB is unavailable.
    pub fn send_expedited(&mut self, reduced_piu: &[u8]) -> io::Result<TcpRecord> {
        if self.closed {
            return Err(invalid("TCP62 session is closed"));
        }
        if self.unacked_tcp.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP62 expedited acknowledgement pending",
            ));
        }
        if reduced_piu.len() < REDUCED_TH_AND_RH
            || reduced_piu.len() > MAX_RECORD - 5
            || reduced_piu.len() + 5 > self.max_pending
        {
            return Err(invalid(
                "TCP62 expedited data outside credit or header bound",
            ));
        }
        let len = reduced_piu.len() + 5;
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(reduced_piu);
        let record = TcpRecord::decode(bytes)?;
        self.unacked_tcp = Some(len);
        Ok(record)
    }

    /// Process one expedited, ACK or abort record. The caller owns normal
    /// traffic and must preserve TCP record order while using this helper.
    pub fn receive(&mut self, record: &TcpRecord) -> io::Result<Inbound> {
        if self.closed {
            return Err(invalid("TCP62 session is closed"));
        }
        let checked = TcpRecord::decode(record.bytes.clone())?;
        match checked.kind {
            TcpKind::Expedited => {
                let data_len = checked.bytes.len() - 5;
                if data_len < REDUCED_TH_AND_RH {
                    return Err(invalid("TCP62 expedited SNA header is truncated"));
                }
                let next = self
                    .pending_native
                    .checked_add(data_len)
                    .ok_or_else(|| invalid("TCP62 native credit overflow"))?;
                if next > self.max_pending {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "TCP62 native expedited delivery credit exhausted",
                    ));
                }
                self.pending_native = next;
                Ok(Inbound::Expedited {
                    ack: TcpRecord::decode(ACK.to_vec()).unwrap(),
                })
            }
            TcpKind::ExpeditedAck => {
                if self.unacked_tcp.take().is_none() {
                    return Err(invalid("unsolicited TCP62 expedited acknowledgement"));
                }
                Ok(Inbound::Acked)
            }
            TcpKind::Abort => {
                let data_len = checked.bytes.len() - 5;
                if data_len != 0 && data_len < REDUCED_TH_AND_RH {
                    return Err(invalid("TCP62 abort SNA header is truncated"));
                }
                self.closed = true;
                self.pending_native = 0;
                self.unacked_tcp = None;
                Ok(Inbound::Aborted {
                    has_termination_data: data_len != 0,
                })
            }
            _ => Err(invalid("TCP62 record is not an expedited compensation")),
        }
    }

    pub fn complete_native_delivery(&mut self, bytes: usize) -> io::Result<()> {
        if self.closed || bytes > self.pending_native {
            return Err(invalid("TCP62 expedited delivery exceeds reserved credit"));
        }
        self.pending_native -= bytes;
        Ok(())
    }

    /// The UDP OOB fallback is unavailable; do not leave an expedited
    /// session running after its TCP acknowledgement deadline expires.
    pub fn ack_timed_out(&mut self) -> io::Result<()> {
        if self.unacked_tcp.is_none() {
            return Err(invalid("no TCP62 expedited acknowledgement pending"));
        }
        self.closed = true;
        self.pending_native = 0;
        self.unacked_tcp = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, len: usize) -> TcpRecord {
        let mut bytes = vec![0; len];
        bytes[..4].copy_from_slice(&(len as u32).to_be_bytes());
        bytes[4] = kind;
        TcpRecord::decode(bytes).unwrap()
    }

    #[test]
    fn captured_expedited_shapes_ack_and_hold_later_normal_data() {
        // Both V5R4 sessions had 15- and 11-byte expedited records followed
        // by an exact five-byte ACK. No SNA application data is copied here.
        let mut flow = Flow::new(MAX_RECORD).unwrap();
        let action = flow.receive(&record(0x01, 15)).unwrap();
        assert_eq!(
            action,
            Inbound::Expedited {
                ack: record(0x03, 5)
            }
        );
        assert_eq!(flow.pending_native(), 10);
        assert!(!flow.inbound_normal_may_pass());
        flow.complete_native_delivery(10).unwrap();
        assert!(flow.inbound_normal_may_pass());
        assert!(matches!(
            flow.receive(&record(0x01, 11)),
            Ok(Inbound::Expedited { .. })
        ));
        assert_eq!(flow.pending_native(), 6);
    }

    #[test]
    fn outbound_ack_is_correlated_and_timeout_closes() {
        let mut flow = Flow::new(MAX_RECORD).unwrap();
        assert_eq!(flow.send_expedited(&[0; 10]).unwrap().bytes.len(), 15);
        assert_eq!(flow.pending_tcp(), 15);
        assert!(flow.outbound_normal_may_pass());
        assert_eq!(
            flow.send_expedited(&[0; 6]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(flow.receive(&record(0x03, 5)).unwrap(), Inbound::Acked);
        assert_eq!(flow.pending_tcp(), 0);
        assert!(flow.receive(&record(0x03, 5)).is_err());
        flow.send_expedited(&[0; 6]).unwrap();
        flow.ack_timed_out().unwrap();
        assert!(flow.is_closed());
    }

    #[test]
    fn captured_abort_retires_credit_and_rejects_short_header() {
        let mut flow = Flow::new(MAX_RECORD).unwrap();
        flow.receive(&record(0x01, 11)).unwrap();
        flow.send_expedited(&[0; 6]).unwrap();
        assert!(flow.receive(&record(0x10, 9)).is_err());
        assert_eq!(
            flow.receive(&record(0x10, 59)).unwrap(),
            Inbound::Aborted {
                has_termination_data: true
            }
        );
        assert!(flow.is_closed());
        assert_eq!(flow.pending_native(), 0);
        assert!(!flow.inbound_normal_may_pass());
        assert!(!flow.outbound_normal_may_pass());
    }
}
