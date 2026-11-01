//! Bounded reverse TCP62/native normal-flow adapter after user BIND.
//!
//! The caller owns one established TCP62 stream and one native LU6.2 session.
//! Both outgoing directions require an exact queue confirmation before pacing
//! state advances. This adapter does not carry expedited data or UNBIND.

use std::io;

use router_core::fixed_pacing::{is_canonical_ipr, FixedPacing};

use crate::{
    anynet::{TcpKind, TcpRecord},
    mptn_gateway::{mptn_normal_to_native, native_normal_to_mptn, NativeSessionAddress},
    mptn_reverse_user_bind::NativeAddress,
    mptn_segments::Reassembler,
};

pub enum NativeInput<'a> {
    PacingGrant,
    TcpRecord(&'a TcpRecord),
}

struct PendingNative {
    piu: Vec<u8>,
    pacing_after: FixedPacing,
}

struct PendingTcp {
    record: TcpRecord,
    pacing_after: FixedPacing,
    requested_grant: bool,
}

pub struct ReverseUserFlow {
    address: NativeAddress,
    receive_window: u8,
    pacing: FixedPacing,
    segments: Reassembler,
    pending_native: Option<PendingNative>,
    pending_tcp: Option<PendingTcp>,
    grant_pending: bool,
    grant: Option<(Vec<u8>, FixedPacing)>,
    closed: bool,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn blocked() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "reverse user flow egress is pending",
    )
}

impl ReverseUserFlow {
    /// Windows must be negotiated from the native positive RSP(BIND).
    pub fn new(address: NativeAddress, send_window: u8, receive_window: u8) -> io::Result<Self> {
        if address.daf == 0 || address.oaf == 0 {
            return Err(invalid("native user address must be nonzero"));
        }
        let pacing = FixedPacing::new(send_window, receive_window)
            .map_err(|_| invalid("native user pacing window is invalid"))?;
        Ok(Self {
            address,
            receive_window,
            pacing,
            segments: Reassembler::default(),
            pending_native: None,
            pending_tcp: None,
            grant_pending: false,
            grant: None,
            closed: false,
        })
    }

    /// A segmented X'20' record returns `None` until its final X'00'. A
    /// complete FM request gets the native first-window PI locally; TCP62
    /// must not supply PI. Native queue failure leaves pacing unchanged.
    pub fn prepare_tcp_normal(&mut self, record: &TcpRecord) -> io::Result<Option<&[u8]>> {
        if self.closed || self.pending_native.is_some() || self.grant.is_some() {
            return Err(blocked());
        }
        if !matches!(record.kind, TcpKind::Normal | TcpKind::Segmented) {
            return Err(invalid("reverse user flow needs TCP62 normal data"));
        }
        let Some(complete) = self.segments.push(record)? else {
            return Ok(None);
        };
        let mut piu = mptn_normal_to_native(
            &complete,
            NativeSessionAddress {
                daf: self.address.daf,
                oaf: self.address.oaf,
                odai: self.address.odai,
            },
        )?;
        let mut next = self.pacing.clone();
        if piu[6] & 0x80 == 0 {
            if next.send_request().map_err(|_| blocked())? {
                piu[7] |= 1;
            }
        }
        self.pending_native = Some(PendingNative {
            piu,
            pacing_after: next,
        });
        Ok(Some(&self.pending_native.as_ref().unwrap().piu))
    }

    pub fn mark_native_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        let Some(pending) = self.pending_native.take() else {
            return Err(blocked());
        };
        if pending.piu != piu {
            self.pending_native = Some(pending);
            return Err(invalid("native user egress differs from prepared PIU"));
        }
        self.pacing = pending.pacing_after;
        Ok(())
    }

    /// A native IPR is consumed here. Other complete native normal PIUs are
    /// staged as TCP62 records; caller must confirm TCP enqueue before the
    /// receive window advances or any native IPR becomes eligible.
    pub fn prepare_native_input(&mut self, piu: &[u8]) -> io::Result<NativeInput<'_>> {
        if self.closed || self.pending_tcp.is_some() {
            return Err(blocked());
        }
        if piu.len() < 9
            || piu[0] & !1 != (0x2c | (u8::from(self.address.odai) << 1))
            || piu[1] != 0
            || piu[2..4] != [self.address.oaf, self.address.daf]
        {
            return Err(invalid("native user PIU belongs to another session"));
        }
        if piu.len() == 9 && is_canonical_ipr(&piu[6..9], &piu[9..]) {
            if piu[4..6] != [0, 0] {
                return Err(invalid("native IPR has nonzero sequence"));
            }
            self.pacing
                .receive_pacing_response()
                .map_err(|_| invalid("unexpected native user IPR"))?;
            return Ok(NativeInput::PacingGrant);
        }
        let converted = native_normal_to_mptn(piu)?;
        let record = TcpRecord::decode(converted.bytes)?;
        let mut next = self.pacing.clone();
        if piu[6] & 0x80 == 0 {
            next.receive_request(converted.native_pacing_requested)
                .map_err(|_| invalid("native user request pacing violated"))?;
        }
        self.pending_tcp = Some(PendingTcp {
            record,
            pacing_after: next,
            requested_grant: converted.native_pacing_requested,
        });
        Ok(NativeInput::TcpRecord(
            &self.pending_tcp.as_ref().unwrap().record,
        ))
    }

    pub fn mark_tcp_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        let Some(pending) = self.pending_tcp.take() else {
            return Err(blocked());
        };
        if &pending.record != record {
            self.pending_tcp = Some(pending);
            return Err(invalid("TCP62 egress differs from prepared record"));
        }
        self.pacing = pending.pacing_after;
        self.grant_pending |= pending.requested_grant;
        Ok(())
    }

    /// Reserve a native receive window only when the downstream TCP queue and
    /// native egress have capacity. The IPR is committed after exact enqueue.
    pub fn prepare_native_grant(&mut self, available_slots: usize) -> io::Result<Option<&[u8]>> {
        if self.closed || self.pending_tcp.is_some() || self.pending_native.is_some() {
            return Err(blocked());
        }
        if !self.grant_pending {
            return Ok(None);
        }
        if available_slots < self.receive_window as usize {
            return Err(blocked());
        }
        if self.grant.is_none() {
            let mut next = self.pacing.clone();
            next.grant_receive_window()
                .map_err(|_| invalid("native receive pacing grant is not pending"))?;
            self.grant = Some((
                vec![
                    0x2d | (u8::from(self.address.odai) << 1),
                    0,
                    self.address.daf,
                    self.address.oaf,
                    0,
                    0,
                    0x83,
                    1,
                    0,
                ],
                next,
            ));
        }
        Ok(self.grant.as_ref().map(|(piu, _)| piu.as_slice()))
    }

    pub fn mark_native_grant_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        let Some((prepared, next)) = self.grant.take() else {
            return Err(blocked());
        };
        if prepared != piu {
            self.grant = Some((prepared, next));
            return Err(invalid("native user IPR differs from prepared grant"));
        }
        self.pacing = next;
        self.grant_pending = false;
        Ok(())
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.segments.clear();
        self.pending_native = None;
        self.pending_tcp = None;
        self.grant = None;
        self.grant_pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> NativeAddress {
        NativeAddress {
            daf: 2,
            oaf: 1,
            odai: false,
        }
    }

    fn normal(snf: u16, rh: [u8; 3], ru: &[u8]) -> TcpRecord {
        let len = 10 + ru.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&snf.to_be_bytes());
        bytes.extend_from_slice(&rh);
        bytes.extend_from_slice(ru);
        TcpRecord::decode(bytes).unwrap()
    }

    #[test]
    fn tcp_attach_gets_local_pacing_and_waits_for_native_ipr() {
        let mut flow = ReverseUserFlow::new(address(), 1, 1).unwrap();
        let first = normal(1, [3, 0, 0], &[0xaa]);
        let piu = flow.prepare_tcp_normal(&first).unwrap().unwrap().to_vec();
        assert_eq!(piu, [0x2c, 0, 2, 1, 0, 1, 3, 1, 0, 0xaa]);
        assert!(flow.mark_native_enqueued(&[0]).is_err());
        flow.mark_native_enqueued(&piu).unwrap();
        assert_eq!(
            flow.prepare_tcp_normal(&first).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(matches!(
            flow.prepare_native_input(&[0x2d, 0, 1, 2, 0, 0, 0x83, 1, 0])
                .unwrap(),
            NativeInput::PacingGrant
        ));
        let second = normal(2, [3, 0, 0], &[0xbb]);
        let next = flow.prepare_tcp_normal(&second).unwrap().unwrap().to_vec();
        assert_eq!(&next[6..9], &[3, 1, 0]);
    }

    #[test]
    fn native_response_and_request_preserve_order_and_local_grant() {
        let mut flow = ReverseUserFlow::new(address(), 1, 2).unwrap();
        let response = [0x2c, 0, 1, 2, 0, 1, 0x83, 0xa0, 0];
        let NativeInput::TcpRecord(record) = flow.prepare_native_input(&response).unwrap() else {
            panic!("expected TCP response")
        };
        let record = record.clone();
        assert_eq!(record.bytes, normal(1, [0x83, 0xa0, 0], &[]).bytes);
        assert!(flow.prepare_native_grant(2).is_err());
        flow.mark_tcp_enqueued(&record).unwrap();
        assert!(flow.prepare_native_grant(2).unwrap().is_none());

        let request = [0x2c, 0, 1, 2, 0, 2, 3, 1, 0, 0xbb];
        let NativeInput::TcpRecord(record) = flow.prepare_native_input(&request).unwrap() else {
            panic!("expected TCP request")
        };
        let record = record.clone();
        assert_eq!(record.bytes, normal(2, [3, 0, 0], &[0xbb]).bytes);
        flow.mark_tcp_enqueued(&record).unwrap();
        assert_eq!(
            flow.prepare_native_grant(1).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let grant = flow.prepare_native_grant(2).unwrap().unwrap().to_vec();
        assert_eq!(grant, [0x2d, 0, 2, 1, 0, 0, 0x83, 1, 0]);
        flow.mark_native_grant_enqueued(&grant).unwrap();
        assert!(flow.prepare_native_grant(2).unwrap().is_none());
    }
}
