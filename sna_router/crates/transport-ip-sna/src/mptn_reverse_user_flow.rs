//! Bounded reverse TCP62/native normal-flow adapter after user BIND.
//!
//! The caller owns one established TCP62 stream and one native LU6.2 session.
//! Both outgoing directions require an exact queue confirmation before pacing
//! state advances. This adapter does not carry expedited data or UNBIND.

use std::io;

use router_core::fixed_pacing::{is_canonical_ipr, FixedPacing};

use crate::{
    anynet::{TcpKind, TcpRecord, MAX_RECORD},
    mptn_expedited::{Flow as ExpeditedFlow, Inbound as ExpeditedInbound},
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
    deferred_normal: Option<TcpRecord>,
    pending_native: Option<PendingNative>,
    pending_tcp: Option<PendingTcp>,
    grant_pending: bool,
    grant: Option<(Vec<u8>, FixedPacing)>,
    expedited: ExpeditedFlow,
    pending_expedited_native: Option<(Vec<u8>, usize)>,
    pending_udp_native: Option<Vec<u8>>,
    pending_expedited_tcp: Option<TcpRecord>,
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
            deferred_normal: None,
            pending_native: None,
            pending_tcp: None,
            grant_pending: false,
            grant: None,
            expedited: ExpeditedFlow::new(MAX_RECORD * 2)?,
            pending_expedited_native: None,
            pending_udp_native: None,
            pending_expedited_tcp: None,
            closed: false,
        })
    }

    /// A segmented X'20' record returns `None` until its final X'00'. A
    /// complete FM request gets the native first-window PI locally; TCP62
    /// must not supply PI. Native queue failure leaves pacing unchanged.
    pub fn prepare_tcp_normal(&mut self, record: &TcpRecord) -> io::Result<Option<&[u8]>> {
        if self.closed
            || self.pending_native.is_some()
            || self.grant.is_some()
            || self.deferred_normal.is_some()
            || self.pending_udp_native.is_some()
            || !self.expedited.inbound_normal_may_pass()
        {
            return Err(blocked());
        }
        if !matches!(record.kind, TcpKind::Normal | TcpKind::Segmented) {
            return Err(invalid("reverse user flow needs TCP62 normal data"));
        }
        let Some(complete) = self.segments.push(record)? else {
            return Ok(None);
        };
        self.prepare_complete_normal(complete).map(Some)
    }

    /// A final TCP62 segment may complete while native send pacing is
    /// exhausted. Keep that complete record and retry after a native IPR;
    /// never ask the caller to replay the final fragment without its header.
    pub fn retry_deferred_normal(&mut self) -> io::Result<Option<&[u8]>> {
        if self.closed
            || self.pending_native.is_some()
            || self.pending_udp_native.is_some()
            || !self.expedited.inbound_normal_may_pass()
        {
            return Err(blocked());
        }
        let Some(record) = self.deferred_normal.take() else {
            return Ok(None);
        };
        self.prepare_complete_normal(record).map(Some)
    }

    fn prepare_complete_normal(&mut self, complete: TcpRecord) -> io::Result<&[u8]> {
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
            match next.send_request() {
                Ok(pi) => {
                    if pi {
                        piu[7] |= 1;
                    }
                }
                Err(_) => {
                    self.deferred_normal = Some(complete);
                    return Err(blocked());
                }
            }
        }
        self.pending_native = Some(PendingNative {
            piu,
            pacing_after: next,
        });
        Ok(&self.pending_native.as_ref().unwrap().piu)
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

    /// TCP62 expedited data has an immediate five-byte ACK. The returned
    /// native PIU must still enter its own bounded queue before later normal
    /// data can pass. The ACK belongs on the same TCP stream.
    pub fn prepare_tcp_expedited(&mut self, record: &TcpRecord) -> io::Result<(&[u8], TcpRecord)> {
        if self.closed
            || self.pending_expedited_native.is_some()
            || self.pending_udp_native.is_some()
        {
            return Err(blocked());
        }
        let ExpeditedInbound::Expedited { ack } = self.expedited.receive(record)? else {
            return Err(invalid("expected TCP62 expedited data"));
        };
        let mut normal = record.clone();
        normal.kind = TcpKind::Normal;
        normal.bytes[4] = 0;
        let mut piu = match mptn_normal_to_native(
            &normal,
            NativeSessionAddress {
                daf: self.address.daf,
                oaf: self.address.oaf,
                odai: self.address.odai,
            },
        ) {
            Ok(piu) => piu,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        piu[0] |= 1; // expedited FID2 flow, never normal pacing
        self.pending_expedited_native = Some((piu, record.bytes.len() - 5));
        Ok((&self.pending_expedited_native.as_ref().unwrap().0, ack))
    }

    pub fn mark_expedited_native_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        let Some((prepared, bytes)) = self.pending_expedited_native.take() else {
            return Err(blocked());
        };
        if prepared != piu {
            self.pending_expedited_native = Some((prepared, bytes));
            return Err(invalid("native expedited egress differs from prepared PIU"));
        }
        self.expedited.complete_native_delivery(bytes)
    }

    /// The gateway validates UDP X'83' source, Connect correlator, sequence
    /// and duplicate suppression before calling this method. `reduced` is
    /// only its SNF/RH/RU image. UDP delivery has no TCP X'03' ACK; the
    /// gateway owns the X'83' UDP acknowledgement and retry window.
    pub fn prepare_udp_expedited(&mut self, reduced: &[u8]) -> io::Result<&[u8]> {
        if self.closed
            || self.pending_udp_native.is_some()
            || self.pending_expedited_native.is_some()
        {
            return Err(blocked());
        }
        let len = 5 + reduced.len();
        if reduced.len() < 5 || len > MAX_RECORD {
            return Err(invalid("UDP expedited SNA image length is invalid"));
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(reduced);
        let record = TcpRecord::decode(bytes)?;
        let mut piu = mptn_normal_to_native(
            &record,
            NativeSessionAddress {
                daf: self.address.daf,
                oaf: self.address.oaf,
                odai: self.address.odai,
            },
        )?;
        piu[0] |= 1;
        self.pending_udp_native = Some(piu);
        Ok(self.pending_udp_native.as_deref().unwrap())
    }

    pub fn mark_udp_native_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.pending_udp_native.as_deref() != Some(piu) {
            return Err(invalid(
                "UDP expedited native egress differs from prepared PIU",
            ));
        }
        self.pending_udp_native = None;
        Ok(())
    }

    /// Queue one native expedited PIU on TCP and wait for its exact X'03'
    /// acknowledgement. Duplicate outbound expedited data is backpressured.
    pub fn prepare_native_expedited(&mut self, piu: &[u8]) -> io::Result<&TcpRecord> {
        if self.closed
            || self.pending_expedited_tcp.is_some()
            || piu.len() < 9
            || piu[0] != (0x2d | (u8::from(self.address.odai) << 1))
            || piu[1] != 0
            || piu[2..4] != [self.address.oaf, self.address.daf]
        {
            return Err(blocked());
        }
        let mut normalized = piu.to_vec();
        normalized[0] &= !1;
        let translated = native_normal_to_mptn(&normalized)?;
        if translated.native_pacing_requested {
            return Err(invalid("native expedited PIU requests normal pacing"));
        }
        let record = self.expedited.send_expedited(&translated.bytes[5..])?;
        self.pending_expedited_tcp = Some(record);
        Ok(self.pending_expedited_tcp.as_ref().unwrap())
    }

    pub fn mark_expedited_tcp_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.pending_expedited_tcp.as_ref() != Some(record) {
            return Err(invalid(
                "TCP62 expedited egress differs from prepared record",
            ));
        }
        self.pending_expedited_tcp = None;
        Ok(())
    }

    pub fn accept_tcp_expedited_ack(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.closed
            || self.pending_expedited_tcp.is_some()
            || self.expedited.receive(record)? != ExpeditedInbound::Acked
        {
            return Err(invalid("unexpected TCP62 expedited ACK"));
        }
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
        self.deferred_normal = None;
        self.pending_native = None;
        self.pending_tcp = None;
        self.grant = None;
        self.grant_pending = false;
        self.pending_expedited_native = None;
        self.pending_udp_native = None;
        self.pending_expedited_tcp = None;
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
        let second = normal(2, [3, 0, 0], &[0xbb]);
        assert_eq!(
            flow.prepare_tcp_normal(&second).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(matches!(
            flow.prepare_native_input(&[0x2d, 0, 1, 2, 0, 0, 0x83, 1, 0])
                .unwrap(),
            NativeInput::PacingGrant
        ));
        let next = flow.retry_deferred_normal().unwrap().unwrap().to_vec();
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

    #[test]
    fn captured_expedited_shapes_hold_normal_until_native_queue_accepts() {
        let mut flow = ReverseUserFlow::new(address(), 1, 1).unwrap();
        let inbound = TcpRecord::decode(vec![
            0, 0, 0, 15, 1, 0x80, 0, 0x4b, 0x80, 0, 0xc9, 0, 1, 0, 1,
        ])
        .unwrap();
        let (piu, ack) = flow.prepare_tcp_expedited(&inbound).unwrap();
        let piu = piu.to_vec();
        assert_eq!(
            piu,
            [0x2d, 0, 2, 1, 0x80, 0, 0x4b, 0x80, 0, 0xc9, 0, 1, 0, 1]
        );
        assert_eq!(ack.bytes, [0, 0, 0, 5, 3]);
        assert_eq!(
            flow.prepare_tcp_normal(&normal(1, [3, 0, 0], &[0xaa]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        flow.mark_expedited_native_enqueued(&piu).unwrap();
        assert!(flow
            .prepare_tcp_normal(&normal(1, [3, 0, 0], &[0xaa]))
            .unwrap()
            .is_some());
    }

    #[test]
    fn native_expedited_waits_for_exact_tcp_ack() {
        let mut flow = ReverseUserFlow::new(address(), 1, 1).unwrap();
        let native = [0x2d, 0, 1, 2, 0x80, 0, 0xcb, 0x80, 0, 0xc9];
        let record = flow.prepare_native_expedited(&native).unwrap().clone();
        assert_eq!(record.bytes, [0, 0, 0, 11, 1, 0x80, 0, 0xcb, 0x80, 0, 0xc9]);
        assert!(flow
            .accept_tcp_expedited_ack(&TcpRecord::decode(vec![0, 0, 0, 5, 3]).unwrap())
            .is_err());
        flow.mark_expedited_tcp_enqueued(&record).unwrap();
        flow.accept_tcp_expedited_ack(&TcpRecord::decode(vec![0, 0, 0, 5, 3]).unwrap())
            .unwrap();
        assert!(flow
            .accept_tcp_expedited_ack(&TcpRecord::decode(vec![0, 0, 0, 5, 3]).unwrap())
            .is_err());
    }

    #[test]
    fn final_segment_survives_exhausted_native_send_window() {
        let mut flow = ReverseUserFlow::new(address(), 1, 1).unwrap();
        let first = normal(1, [3, 0, 0], &[0xaa]);
        let piu = flow.prepare_tcp_normal(&first).unwrap().unwrap().to_vec();
        flow.mark_native_enqueued(&piu).unwrap();
        let start = TcpRecord::decode(vec![0, 0, 0, 11, 0x20, 0, 2, 3, 0, 0, 0xbb]).unwrap();
        let finish = TcpRecord::decode(vec![0, 0, 0, 6, 0, 0xcc]).unwrap();
        assert!(flow.prepare_tcp_normal(&start).unwrap().is_none());
        assert_eq!(
            flow.prepare_tcp_normal(&finish).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            flow.prepare_tcp_normal(&finish).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(matches!(
            flow.prepare_native_input(&[0x2d, 0, 1, 2, 0, 0, 0x83, 1, 0])
                .unwrap(),
            NativeInput::PacingGrant
        ));
        let piu = flow.retry_deferred_normal().unwrap().unwrap().to_vec();
        assert_eq!(piu, [0x2c, 0, 2, 1, 0, 2, 3, 1, 0, 0xbb, 0xcc]);
        flow.mark_native_enqueued(&piu).unwrap();
        assert!(flow.retry_deferred_normal().unwrap().is_none());
    }

    #[test]
    fn validated_udp_expedited_reaches_native_without_tcp_ack() {
        let mut flow = ReverseUserFlow::new(address(), 1, 1).unwrap();
        let reduced = [0x80, 0, 0x4b, 0x80, 0, 0xc9, 0, 1, 0, 1];
        let piu = flow.prepare_udp_expedited(&reduced).unwrap().to_vec();
        assert_eq!(
            piu,
            [0x2d, 0, 2, 1, 0x80, 0, 0x4b, 0x80, 0, 0xc9, 0, 1, 0, 1]
        );
        assert_eq!(
            flow.prepare_udp_expedited(&reduced).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            flow.prepare_tcp_normal(&normal(1, [3, 0, 0], &[0xaa]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(flow.mark_udp_native_enqueued(&[0]).is_err());
        flow.mark_udp_native_enqueued(&piu).unwrap();
        assert!(flow
            .prepare_tcp_normal(&normal(1, [3, 0, 0], &[0xaa]))
            .unwrap()
            .is_some());
    }
}
