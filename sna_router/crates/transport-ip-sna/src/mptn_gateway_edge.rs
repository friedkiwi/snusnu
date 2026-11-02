//! Unregistered LLC↔TCP62 converter edge prototype. The runtime route loader
//! still rejects this converter. UDP X'83' and APPC session control are absent.

use std::{collections::VecDeque, io};

use crate::{
    anynet::{TcpKind, TcpRecord, TcpSession, MAX_RECORD},
    mptn_connect::Connect,
    mptn_native_bridge::{Bridge, Phase},
};

pub enum NativeEvent {
    UserBind(Vec<u8>),
    BindResponseAck(usize),
    FirstAttach(Vec<u8>),
    UserInformation(Vec<u8>),
    EgressAck(usize),
    Closed,
}

/// The native adapter owns XID, LLC2 and SNASVCMG. `Bridge` owns the user
/// session. Successful enqueue means the exact PIU entered a bounded queue.
pub trait NativeLeg {
    /// The edge must reserve converter capacity before the native leg may
    /// acknowledge another LLC information frame.
    fn receive_once(&mut self, can_accept_information: bool) -> io::Result<Option<NativeEvent>>;
    fn enqueue(&mut self, piu: &[u8]) -> io::Result<bool>;
    fn available_slots(&self) -> usize;
    fn management_closed(&self) -> bool {
        false
    }
    fn close(&mut self) -> io::Result<()>;
}

enum NativeReply {
    Bind,
    Ipr,
    UserNormal,
    UdpExpedited,
}

#[derive(Clone, Copy)]
enum NativeNormalKind {
    Request,
    PositiveResponse,
}

const MAX_INCOMING_BYTES: usize = MAX_RECORD * 2;

pub struct GatewayEdge<L: NativeLeg> {
    native: L,
    tcp: Option<TcpSession>,
    bridge: Bridge,
    template: Option<Connect>,
    native_reply: Option<(NativeReply, Vec<u8>)>,
    connect: Option<TcpRecord>,
    attach: Option<(TcpRecord, bool)>,
    normal: Option<(TcpRecord, bool, NativeNormalKind)>,
    incoming: VecDeque<TcpRecord>,
    incoming_bytes: usize,
    /// TCP queue order and whether GatewaySession charged this record.
    writes: VecDeque<(usize, bool)>,
    connect_fully_sent: bool,
    ipr_ack_outstanding: bool,
    ipr_ack_received: bool,
    attach_fully_sent: bool,
    udp_expedited_pending: Option<usize>,
    udp_expedited_completed: bool,
    closed: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl<L: NativeLeg> GatewayEdge<L> {
    pub fn new(native: L, tcp: TcpSession, bridge: Bridge, template: Connect) -> Self {
        Self {
            native,
            tcp: Some(tcp),
            bridge,
            template: Some(template),
            native_reply: None,
            connect: None,
            attach: None,
            normal: None,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            writes: VecDeque::new(),
            connect_fully_sent: false,
            ipr_ack_outstanding: false,
            ipr_ack_received: false,
            attach_fully_sent: false,
            udp_expedited_pending: None,
            udp_expedited_completed: false,
            closed: false,
        }
    }

    pub fn native_mut(&mut self) -> &mut L {
        &mut self.native
    }
    pub fn phase(&self) -> Phase {
        self.bridge.phase()
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// True after the native IPR entered the LLC egress queue and before its
    /// one exact LLC completion arrives. The lab harness uses this as a
    /// read-only final gate for the first Attach exchange.
    pub fn ipr_ack_outstanding(&self) -> bool {
        self.ipr_ack_outstanding
    }
    /// True only after the first Attach record was written to TCP and the
    /// native IPR for that Attach received its exact LLC completion.
    pub fn first_attach_delivery_complete(&self) -> bool {
        !self.closed && self.attach_fully_sent && self.ipr_ack_received
    }
    pub fn pending_gateway_bytes(&self) -> (usize, usize) {
        self.bridge.pending_bytes()
    }

    /// Accept one UDP X'83' expedited PIU for this circuit. The caller keeps
    /// its UDP response pending until `take_completed_udp_expedited` is true.
    pub fn submit_udp_expedited(&mut self, reduced: &[u8]) -> io::Result<()> {
        if self.closed
            || !self.first_attach_delivery_complete()
            || self.bridge.phase() != Phase::Active
            || self.native_reply.is_some()
            || self.udp_expedited_pending.is_some()
            || self.udp_expedited_completed
            || self.ipr_ack_outstanding
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native UDP expedited delivery is busy",
            ));
        }
        let piu = self.bridge.next_mptn_udp_expedited(reduced)?;
        self.native_reply = Some((NativeReply::UdpExpedited, piu));
        self.drive_queues()
    }

    pub fn take_completed_udp_expedited(&mut self) -> bool {
        std::mem::take(&mut self.udp_expedited_completed)
    }

    pub fn poll_native_once(&mut self) -> io::Result<()> {
        let result = self.poll_native_inner();
        if result.is_err() {
            let _ = self.close();
        }
        result
    }

    fn poll_native_inner(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(invalid("gateway edge is closed"));
        }
        // After Attach, consume at most one native I-frame per TCP delivery
        // and local pacing grant. The LLC receive window supplies backpressure
        // while any converted record or IPR is outstanding.
        let charged_write = self.writes.iter().any(|(_, charged)| *charged);
        let can_accept_information = if self.attach_fully_sent {
            self.first_attach_delivery_complete()
                && self.bridge.phase() == Phase::Active
                && self.normal.is_none()
                && self.native_reply.is_none()
                && !self.ipr_ack_outstanding
                && self.udp_expedited_pending.is_none()
                && !self.udp_expedited_completed
                && !charged_write
        } else {
            self.attach.is_none() && !charged_write
        };
        if let Some(event) = self.native.receive_once(can_accept_information)? {
            match event {
                NativeEvent::UserBind(piu) => {
                    let template = self
                        .template
                        .take()
                        .ok_or_else(|| invalid("duplicate user BIND"))?;
                    self.connect = Some(if self.native.management_closed() {
                        self.bridge
                            .begin_native_bind_after_management(&piu, template)?
                    } else {
                        self.bridge.begin_native_bind(&piu, template)?
                    });
                }
                NativeEvent::BindResponseAck(n) => self.bridge.acknowledge_native_bind(n)?,
                NativeEvent::FirstAttach(piu) => {
                    if self.attach.is_some() {
                        return Err(invalid("duplicate first Attach"));
                    }
                    let (record, _) = self.bridge.first_attach(&piu)?;
                    self.attach = Some((record, false));
                }
                NativeEvent::UserInformation(piu) => {
                    if !can_accept_information || !self.first_attach_delivery_complete() {
                        return Err(invalid("native user data before gateway credit"));
                    }
                    if piu.len() == 9 && piu[6..9] == [0x83, 0x01, 0] {
                        self.bridge.observe_native_ipr(&piu)?;
                    } else if piu.len() == 9 && piu[6..9] == [0x83, 0xa0, 0] {
                        let record = self.bridge.next_native_positive_response(&piu)?;
                        self.normal = Some((record, false, NativeNormalKind::PositiveResponse));
                    } else {
                        let (record, _) = self.bridge.next_native_normal(&piu)?;
                        self.normal = Some((record, false, NativeNormalKind::Request));
                    }
                }
                NativeEvent::EgressAck(n) => {
                    if n != 1 {
                        return Err(invalid("unexpected native user egress ACK count"));
                    }
                    if self.ipr_ack_outstanding {
                        self.ipr_ack_outstanding = false;
                        self.ipr_ack_received = true;
                    } else if let Some(bytes) = self.udp_expedited_pending.take() {
                        self.bridge.complete_mptn_udp_expedited(bytes)?;
                        self.udp_expedited_completed = true;
                    } else if self.bridge.phase() == Phase::AwaitNativeNormalAck {
                        self.bridge.acknowledge_native_normal(n)?;
                    } else {
                        return Err(invalid("unexpected native user egress ACK"));
                    }
                }
                NativeEvent::Closed => return self.close(),
            }
        }
        self.drive_queues()?;
        self.drive_incoming()
    }

    pub fn poll_tcp_once(&mut self) -> io::Result<()> {
        let result = self.poll_tcp_inner();
        if result.is_err() {
            let _ = self.close();
        }
        result
    }

    fn poll_tcp_inner(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(invalid("gateway edge is closed"));
        }
        self.drive_incoming()?;
        // Keep reading one bounded chunk per poll even when native egress is
        // blocked: a later TCP62 Abort must be able to preempt queued normal
        // records rather than waiting for their LLC completion forever.
        for record in self
            .tcp
            .as_mut()
            .unwrap()
            .receive_once()?
            .unwrap_or_default()
        {
            let next = self
                .incoming_bytes
                .checked_add(record.bytes.len())
                .ok_or_else(|| invalid("TCP62 incoming queue overflow"))?;
            if next > MAX_INCOMING_BYTES {
                return Err(invalid("TCP62 incoming queue full"));
            }
            self.incoming_bytes = next;
            self.incoming.push_back(record);
        }
        self.drive_incoming()
    }

    fn drive_incoming(&mut self) -> io::Result<()> {
        if let Some(abort) = self
            .incoming
            .iter()
            .find(|record| record.kind == TcpKind::Abort)
        {
            if abort.bytes.len() != 5 && abort.bytes.len() < 10 {
                return Err(invalid("TCP62 Abort termination header is truncated"));
            }
            // TCP62 Abort discards pending normal and expedited data. The
            // native LLC association is closed because the UDP UNBIND
            // compensation is unavailable to this gateway.
            self.close()?;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TCP62 peer aborted user session",
            ));
        }
        while let Some(record) = self.incoming.front() {
            match record.kind {
                TcpKind::Connect => {
                    if self.bridge.phase() != Phase::AwaitConnect || !self.connect_fully_sent {
                        return Err(invalid("TCP62 Connect response before completed request"));
                    }
                    let record = self.incoming.pop_front().unwrap();
                    self.incoming_bytes -= record.bytes.len();
                    let response = self.bridge.accept_connect_response(&record)?;
                    self.native_reply = Some((NativeReply::Bind, response));
                    self.drive_queues()?;
                }
                TcpKind::Normal | TcpKind::Segmented => {
                    if self.bridge.phase() == Phase::AwaitConnect {
                        return Err(invalid("TCP62 application data before Connect response"));
                    }
                    // A remote application may send soon after Connect.
                    // Retain its bounded records until the native user BIND,
                    // first Attach, and native IPR are all completed.
                    if !self.first_attach_delivery_complete()
                        || self.bridge.phase() != Phase::Active
                        || self.native_reply.is_some()
                        || self.udp_expedited_pending.is_some()
                        || self.udp_expedited_completed
                    {
                        return Ok(());
                    }
                    let record = self.incoming.pop_front().unwrap();
                    self.incoming_bytes -= record.bytes.len();
                    if let Some(piu) = self.bridge.next_mptn_normal(&record)? {
                        self.native_reply = Some((NativeReply::UserNormal, piu));
                        self.drive_queues()?;
                        return Ok(()); // one LLC I-frame is outstanding
                    }
                }
                _ => return Err(invalid("unsupported TCP62 record on native gateway")),
            }
        }
        Ok(())
    }

    /// Release gateway byte credit only after the socket accepted the final
    /// byte of each charged record. Connect completions are uncharged.
    pub fn flush_tcp(&mut self) -> io::Result<()> {
        let result = self.flush_tcp_inner().and_then(|()| self.drive_incoming());
        if result.is_err() {
            let _ = self.close();
        }
        result
    }

    fn flush_tcp_inner(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(invalid("gateway edge is closed"));
        }
        self.drive_queues()?;
        let mut completed = Vec::new();
        let result = self
            .tcp
            .as_mut()
            .unwrap()
            .flush_with_completion(|len| completed.push(len));
        for len in completed {
            let Some((expected, charged)) = self.writes.pop_front() else {
                self.close()?;
                return Err(invalid("untracked TCP62 write completion"));
            };
            if expected != len {
                self.close()?;
                return Err(invalid("TCP62 completion length mismatch"));
            }
            if charged {
                self.bridge.complete_tcp_delivery(len)?;
                self.attach_fully_sent = true;
            } else if self.connect_fully_sent {
                self.close()?;
                return Err(invalid("duplicate TCP62 Connect write completion"));
            } else {
                self.connect_fully_sent = true;
            }
        }
        result
    }

    fn drive_queues(&mut self) -> io::Result<()> {
        if let Some((kind, piu)) = self.native_reply.take() {
            if !self.native.enqueue(&piu)? {
                self.native_reply = Some((kind, piu));
                return Ok(());
            }
            match kind {
                NativeReply::Bind => self.bridge.mark_native_bind_enqueued(&piu)?,
                NativeReply::Ipr => {
                    self.bridge.mark_ipr_enqueued(&piu)?;
                    self.ipr_ack_outstanding = true;
                }
                NativeReply::UserNormal => self.bridge.mark_native_normal_enqueued(&piu)?,
                NativeReply::UdpExpedited => self.udp_expedited_pending = Some(piu.len()),
            }
        }
        if let Some(record) = self.connect.take() {
            match self.tcp.as_mut().unwrap().queue(record.clone()) {
                Ok(()) => self.writes.push_back((record.bytes.len(), false)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.connect = Some(record);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        if let Some((record, queued)) = self.attach.take() {
            if !queued {
                match self.tcp.as_mut().unwrap().queue(record.clone()) {
                    Ok(()) => self.writes.push_back((record.bytes.len(), true)),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.attach = Some((record, false));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            match self
                .bridge
                .mark_attach_enqueued(&record, self.native.available_slots())
            {
                Ok(ipr) => self.native_reply = Some((NativeReply::Ipr, ipr)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.attach = Some((record, true));
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            // Try the prepared IPR now; if native queue is full it remains
            // pending and no pacing credit is granted.
            self.drive_queues()?;
        }
        if let Some((record, queued, kind)) = self.normal.take() {
            if !queued {
                match self.tcp.as_mut().unwrap().queue(record.clone()) {
                    Ok(()) => self.writes.push_back((record.bytes.len(), true)),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.normal = Some((record, false, kind));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            let accepted = match kind {
                NativeNormalKind::Request => self
                    .bridge
                    .mark_normal_enqueued(&record, self.native.available_slots()),
                NativeNormalKind::PositiveResponse => self
                    .bridge
                    .mark_native_positive_response_enqueued(&record)
                    .map(|()| None),
            };
            match accepted {
                Ok(Some(ipr)) => self.native_reply = Some((NativeReply::Ipr, ipr)),
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.normal = Some((record, true, kind));
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            self.drive_queues()?;
        }
        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            self.closed = true;
            self.tcp.take();
            self.native_reply = None;
            self.connect = None;
            self.attach = None;
            self.normal = None;
            self.incoming.clear();
            self.incoming_bytes = 0;
            self.writes.clear();
            self.connect_fully_sent = false;
            self.ipr_ack_outstanding = false;
            self.ipr_ack_received = false;
            self.attach_fully_sent = false;
            self.udp_expedited_pending = None;
            self.udp_expedited_completed = false;
            self.native.close()?;
        }
        Ok(())
    }
}
