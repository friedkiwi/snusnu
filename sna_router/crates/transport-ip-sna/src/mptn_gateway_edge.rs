//! Unregistered LLC↔TCP62 converter edge prototype. The runtime route loader
//! still rejects this converter. UDP X'83' and later APPC flows are absent.

use std::{collections::VecDeque, io};

use crate::{
    anynet::{TcpKind, TcpRecord, TcpSession},
    mptn_connect::Connect,
    mptn_native_bridge::{Bridge, Phase},
};

pub enum NativeEvent {
    UserBind(Vec<u8>),
    BindResponseAck(usize),
    FirstAttach(Vec<u8>),
    EgressAck(usize),
    Closed,
}

/// The native adapter owns XID, LLC2 and SNASVCMG. `Bridge` owns the user
/// session. Successful enqueue means the exact PIU entered a bounded queue.
pub trait NativeLeg {
    fn receive_once(&mut self) -> io::Result<Option<NativeEvent>>;
    fn enqueue(&mut self, piu: &[u8]) -> io::Result<bool>;
    fn available_slots(&self) -> usize;
    fn close(&mut self) -> io::Result<()>;
}

enum NativeReply {
    Bind,
    Ipr,
}

pub struct GatewayEdge<L: NativeLeg> {
    native: L,
    tcp: Option<TcpSession>,
    bridge: Bridge,
    template: Option<Connect>,
    native_reply: Option<(NativeReply, Vec<u8>)>,
    connect: Option<TcpRecord>,
    attach: Option<(TcpRecord, bool)>,
    /// TCP queue order and whether GatewaySession charged this record.
    writes: VecDeque<(usize, bool)>,
    connect_fully_sent: bool,
    ipr_ack_outstanding: bool,
    ipr_ack_received: bool,
    attach_fully_sent: bool,
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
            writes: VecDeque::new(),
            connect_fully_sent: false,
            ipr_ack_outstanding: false,
            ipr_ack_received: false,
            attach_fully_sent: false,
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
        if let Some(event) = self.native.receive_once()? {
            match event {
                NativeEvent::UserBind(piu) => {
                    let template = self
                        .template
                        .take()
                        .ok_or_else(|| invalid("duplicate user BIND"))?;
                    self.connect = Some(self.bridge.begin_native_bind(&piu, template)?);
                }
                NativeEvent::BindResponseAck(n) => self.bridge.acknowledge_native_bind(n)?,
                NativeEvent::FirstAttach(piu) => {
                    if self.attach.is_some() {
                        return Err(invalid("duplicate first Attach"));
                    }
                    let (record, _) = self.bridge.first_attach(&piu)?;
                    self.attach = Some((record, false));
                }
                NativeEvent::EgressAck(n) => {
                    if n != 1 || !self.ipr_ack_outstanding {
                        return Err(invalid("unexpected native user egress ACK"));
                    }
                    self.ipr_ack_outstanding = false;
                    self.ipr_ack_received = true;
                }
                NativeEvent::Closed => return self.close(),
            }
        }
        self.drive_queues()
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
        for record in self
            .tcp
            .as_mut()
            .unwrap()
            .receive_once()?
            .unwrap_or_default()
        {
            if record.kind != TcpKind::Connect || self.bridge.phase() != Phase::AwaitConnect {
                self.close()?;
                return Err(invalid("TCP62 record outside supported BIND phase"));
            }
            if !self.connect_fully_sent {
                return Err(invalid(
                    "TCP62 Connect response before request write completed",
                ));
            }
            let response = self.bridge.accept_connect_response(&record)?;
            self.native_reply = Some((NativeReply::Bind, response));
        }
        self.drive_queues()
    }

    /// Release gateway byte credit only after the socket accepted the final
    /// byte of each charged record. Connect completions are uncharged.
    pub fn flush_tcp(&mut self) -> io::Result<()> {
        let result = self.flush_tcp_inner();
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
        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            self.closed = true;
            self.tcp.take();
            self.native_reply = None;
            self.connect = None;
            self.attach = None;
            self.writes.clear();
            self.connect_fully_sent = false;
            self.ipr_ack_outstanding = false;
            self.ipr_ack_received = false;
            self.attach_fully_sent = false;
            self.native.close()?;
        }
        Ok(())
    }
}
