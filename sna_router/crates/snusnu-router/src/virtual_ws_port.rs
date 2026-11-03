//! A virtual native Type1 peer over one WebSocket circuit.
//!
//! The wrapped port owns circuit open, credit and transport retry. This
//! adapter starts XID without a local Ethernet interface, then waits for the
//! remote LLC endpoint's LinkReady. Management follows the native V4 sequence,
//! then a single admitted TCP62 user BIND may start on the managed link.

use crate::{
    routing::{FailureScope, RoutePort, RoutedUnit, RouterEvent},
    virtual_native_cp::VirtualNativeCp,
};
use router_core::{
    native_management::{ManagementSession, Phase as ResponderPhase},
    native_management_initiator::{NativeManagementInitiator, Phase as ManagementPhase},
    xid3::Xid3,
};
use std::{collections::VecDeque, io};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord},
    mptn_ingress::IngressOffer,
    mptn_reverse_user_bind::{NativeAddress, Phase as UserBindPhase, ReverseUserBind},
    mptn_reverse_user_flow::{NativeInput, ReverseUserFlow},
    mptn_reverse_user_native_close::NativeUserClose,
    mptn_reverse_user_teardown::{
        AbortAction, AbortBearer, Phase as TeardownPhase, ReverseUserTeardown,
    },
};

#[derive(Clone, Copy)]
enum NativeUserOutputKind {
    Normal,
    Grant,
    Expedited,
    TeardownUnbind,
    NativeCloseResponse,
    UdpExpedited(u16),
}

#[derive(Clone, Copy)]
enum TcpUserOutputKind {
    Normal,
    Expedited,
    ExpeditedAck,
}

#[derive(Clone, Copy)]
enum ManagementEgress {
    Initiator,
    ResponderBind,
    ResponderAttach,
    ResponderBis,
    ResponderUnbind,
}

pub(crate) struct VirtualWsPort<P: RoutePort> {
    inner: P,
    cp: VirtualNativeCp,
    local_xid: Xid3,
    local_cp: String,
    peer_cp: String,
    initial_xid_sent: bool,
    management: Option<NativeManagementInitiator>,
    reciprocal_management: Option<ManagementSession>,
    management_egress: VecDeque<ManagementEgress>,
    management_invalidated: bool,
    early_management_information: Option<Vec<u8>>,
    user_bind: Option<ReverseUserBind>,
    user_bind_native_completed: bool,
    early_user_response: Option<Vec<u8>>,
    tcp_bind_response: Option<Vec<u8>>,
    user_address: Option<NativeAddress>,
    user_flow: Option<ReverseUserFlow>,
    tcp_user_input: Option<TcpRecord>,
    deferred_user_normal: bool,
    native_user_output: Option<Vec<u8>>,
    native_user_output_kind: Option<NativeUserOutputKind>,
    native_user_output_queued: bool,
    native_user_input: Option<Vec<u8>>,
    tcp_user_output: Option<TcpRecord>,
    tcp_user_output_kind: Option<TcpUserOutputKind>,
    tcp_user_output_queued: bool,
    udp_abort_output: Option<TcpRecord>,
    udp_abort_output_queued: bool,
    expedited_ack: Option<TcpRecord>,
    expedited_native_completed: bool,
    user_teardown: Option<ReverseUserTeardown>,
    native_user_close: Option<NativeUserClose>,
    tcp_user_writes: VecDeque<TcpUserOutputKind>,
    user_closed: bool,
    udp_user_input: Option<(u16, Vec<u8>)>,
    udp_user_completion: Option<u16>,
    udp_abort_input: Option<(u16, Vec<u8>)>,
    udp_abort_pending: Option<u16>,
    udp_abort_completion: Option<u16>,
}

impl<P: RoutePort> VirtualWsPort<P> {
    /// Preserve identities observed by a private native egress so the
    /// automatic directory can learn an LLC peer reached through TCP62.
    pub(crate) fn take_inner_identity_observations(
        &mut self,
    ) -> Vec<crate::routing::IdentityObservation> {
        self.inner.take_identity_observations()
    }

    pub(crate) fn new(
        inner: P,
        local_xid: Xid3,
        local_cp: &str,
        peer_cp: &str,
    ) -> io::Result<Self> {
        let cp = VirtualNativeCp::new(local_xid.clone(), local_cp, peer_cp)?;
        Ok(Self {
            inner,
            cp,
            local_xid,
            local_cp: local_cp.to_owned(),
            peer_cp: peer_cp.to_owned(),
            initial_xid_sent: false,
            management: None,
            reciprocal_management: None,
            management_egress: VecDeque::new(),
            management_invalidated: false,
            early_management_information: None,
            user_bind: None,
            user_bind_native_completed: false,
            early_user_response: None,
            tcp_bind_response: None,
            user_address: None,
            user_flow: None,
            tcp_user_input: None,
            deferred_user_normal: false,
            native_user_output: None,
            native_user_output_kind: None,
            native_user_output_queued: false,
            native_user_input: None,
            tcp_user_output: None,
            tcp_user_output_kind: None,
            tcp_user_output_queued: false,
            udp_abort_output: None,
            udp_abort_output_queued: false,
            expedited_ack: None,
            expedited_native_completed: false,
            user_teardown: None,
            native_user_close: None,
            tcp_user_writes: VecDeque::new(),
            user_closed: false,
            udp_user_input: None,
            udp_user_completion: None,
            udp_abort_input: None,
            udp_abort_pending: None,
            udp_abort_completion: None,
        })
    }

    pub(crate) fn ready(&self) -> bool {
        self.cp.ready()
    }

    pub(crate) fn attach_management(
        &mut self,
        initiator: NativeManagementInitiator,
    ) -> io::Result<()> {
        if self.initial_xid_sent
            || self.management.is_some()
            || self.management_invalidated
            || initiator.remote_cp() != self.peer_cp
        {
            return Err(protocol(
                "virtual management identity or attachment phase mismatch",
            ));
        }
        self.management = Some(initiator);
        Ok(())
    }

    /// Start another native management exchange on the same WebSocket route
    /// port after the previous user session has closed. The caller must mint
    /// a new FQPCID and BIND token for `initiator`.
    pub(crate) fn rearm_management(
        &mut self,
        initiator: NativeManagementInitiator,
    ) -> io::Result<()> {
        if initiator.remote_cp() != self.peer_cp {
            return Err(protocol("virtual management identity mismatch"));
        }
        if self.user_closed {
            if !self.management_egress.is_empty()
                || !self.tcp_user_writes.is_empty()
                || self.tcp_bind_response.is_some()
                || self.tcp_user_input.is_some()
                || self.tcp_user_output.is_some()
                || self.tcp_user_output_queued
                || self.native_user_input.is_some()
                || self.native_user_output.is_some()
                || self.native_user_output_queued
                || self.udp_abort_output.is_some()
                || self.udp_abort_output_queued
                || self.deferred_user_normal
                || self.udp_user_input.is_some()
                || self.udp_user_completion.is_some()
                || self.udp_abort_input.is_some()
                || self.udp_abort_pending.is_some()
                || self.udp_abort_completion.is_some()
                || self.expedited_ack.is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "virtual user close still has pending delivery",
                ));
            }
            self.inner.disconnect()?;
            self.reset_cp()?;
        }
        if !self.management_invalidated
            || self.initial_xid_sent
            || self.management.is_some()
            || self.user_bind.is_some()
            || self.user_flow.is_some()
        {
            return Err(protocol("virtual management is still active"));
        }
        self.management = Some(initiator);
        self.management_invalidated = false;
        Ok(())
    }

    pub(crate) fn management_complete(&self) -> bool {
        self.management
            .as_ref()
            .is_some_and(|management| management.phase() == ManagementPhase::Complete)
            && self
                .reciprocal_management
                .as_ref()
                .is_none_or(|management| management.phase() == ResponderPhase::Closed)
    }

    pub(crate) fn management_phases(&self) -> (Option<ManagementPhase>, Option<ResponderPhase>) {
        (
            self.management
                .as_ref()
                .map(NativeManagementInitiator::phase),
            self.reciprocal_management
                .as_ref()
                .map(ManagementSession::phase),
        )
    }

    /// Allocate the first user address on this private native association
    /// from the active management BIND address pair. The observed V4R4
    /// profile accepts the next remote address with the same local address;
    /// this method refuses reuse before management has completed.
    pub(crate) fn first_user_address(&self) -> io::Result<NativeAddress> {
        if !self.management_complete() || self.user_bind.is_some() || self.user_address.is_some() {
            return Err(protocol("native user address requires idle managed link"));
        }
        let (management_daf, management_oaf) = self
            .management
            .as_ref()
            .ok_or_else(|| protocol("native management BIND unavailable"))?
            .address_pair();
        let daf = management_daf
            .checked_add(1)
            .ok_or_else(|| protocol("native user address space exhausted"))?;
        Ok(NativeAddress {
            daf,
            oaf: management_oaf,
            odai: true,
        })
    }

    pub(crate) fn begin_user_bind(
        &mut self,
        offer: &IngressOffer,
        address: NativeAddress,
    ) -> io::Result<()> {
        if !self.ready() || !self.management_complete() || self.user_bind.is_some() {
            return Err(protocol("virtual user BIND needs an idle managed link"));
        }
        self.user_bind = Some(ReverseUserBind::after_management(offer, address)?);
        self.user_address = Some(address);
        self.user_teardown = Some(ReverseUserTeardown::from_user_offer(offer, address)?);
        self.native_user_close = Some(NativeUserClose::from_user_offer(offer, address)?);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn user_bind_response_ready(&self) -> bool {
        self.tcp_bind_response.is_some()
    }

    pub(crate) fn tcp_bind_response(&self) -> Option<&[u8]> {
        self.tcp_bind_response.as_deref()
    }

    pub(crate) fn mark_tcp_bind_response_enqueued(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.tcp_bind_response.as_deref() != Some(bytes) {
            return Err(protocol(
                "virtual TCP62 BIND response changed before enqueue",
            ));
        }
        self.user_bind
            .as_mut()
            .ok_or_else(|| protocol("virtual user BIND is absent"))?
            .mark_tcp_response_enqueued(bytes)?;
        let (send_window, receive_window) = self
            .user_bind
            .as_ref()
            .unwrap()
            .native_flow_windows()
            .ok_or_else(|| protocol("native BIND did not negotiate pacing windows"))?;
        self.user_flow = Some(ReverseUserFlow::new(
            self.user_address.unwrap(),
            send_window,
            receive_window,
        )?);
        self.tcp_bind_response = None;
        Ok(())
    }

    /// Retain one TCP62 record before releasing the gateway's ingress slot.
    /// The native PIU is prepared and sent by subsequent poll/tick calls.
    pub(crate) fn submit_tcp_user_record(&mut self, record: &TcpRecord) -> io::Result<bool> {
        if self.user_flow.is_none()
            || self.user_closed
            || self.tcp_user_input.is_some()
            || self.native_user_output.is_some()
            || self.deferred_user_normal
            || self.udp_abort_input.is_some()
            || self.udp_abort_pending.is_some()
            || self
                .user_teardown
                .as_ref()
                .is_some_and(|teardown| teardown.phase() != TeardownPhase::Active)
            || self.expedited_ack.is_some()
            || self.udp_user_input.is_some()
        {
            return Ok(false);
        }
        if !matches!(
            record.kind,
            TcpKind::Normal
                | TcpKind::Segmented
                | TcpKind::Expedited
                | TcpKind::ExpeditedAck
                | TcpKind::Abort
        ) {
            return Err(protocol(
                "virtual user flow does not accept this TCP62 record kind",
            ));
        }
        self.tcp_user_input = Some(record.clone());
        Ok(true)
    }

    pub(crate) fn tcp_user_record(&self) -> Option<&TcpRecord> {
        (!self.tcp_user_output_queued)
            .then_some(self.tcp_user_output.as_ref())
            .flatten()
    }

    /// A native-initiated UNBIND yields a validated X'10' Abort image whose
    /// bytes after the TCP62 header become the outbound UDP X'83' payload.
    pub(crate) fn udp_abort_record(&self) -> Option<&TcpRecord> {
        (!self.udp_abort_output_queued)
            .then_some(self.udp_abort_output.as_ref())
            .flatten()
    }

    pub(crate) fn mark_udp_abort_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.udp_abort_output.as_ref() != Some(record) || self.udp_abort_output_queued {
            return Err(protocol("UDP Abort differs from prepared native close"));
        }
        self.native_user_close
            .as_mut()
            .ok_or_else(|| protocol("native user close absent"))?
            .mark_udp_abort_enqueued(record)?;
        self.udp_abort_output_queued = true;
        Ok(())
    }

    /// Call only after the gateway verified a positive X'83' UDP response
    /// for this Abort's sequence and Connect identity.
    pub(crate) fn complete_udp_abort_response(&mut self) -> io::Result<()> {
        if !self.udp_abort_output_queued || self.native_user_output.is_some() {
            return Err(protocol("native close has no acknowledged UDP Abort"));
        }
        let response = self
            .native_user_close
            .as_mut()
            .ok_or_else(|| protocol("native user close absent"))?
            .accept_udp_abort_response()?
            .to_vec();
        self.udp_abort_output = None;
        self.native_user_output = Some(response);
        self.native_user_output_kind = Some(NativeUserOutputKind::NativeCloseResponse);
        Ok(())
    }

    pub(crate) fn user_closed(&self) -> bool {
        self.user_closed
    }

    /// The gateway has already validated X'83' source, association and
    /// sequence. This retains one reduced SNA image until native completion.
    pub(crate) fn submit_udp_expedited(
        &mut self,
        sequence: u16,
        reduced: &[u8],
    ) -> io::Result<bool> {
        if self.user_flow.is_none()
            || self.user_closed
            || self.udp_user_input.is_some()
            || self.udp_user_completion.is_some()
            || self.tcp_user_input.is_some()
            || self.native_user_output.is_some()
            || self.deferred_user_normal
            || self.udp_abort_input.is_some()
            || self.udp_abort_pending.is_some()
            || self
                .user_teardown
                .as_ref()
                .is_some_and(|teardown| teardown.phase() != TeardownPhase::Active)
        {
            return Ok(false);
        }
        if reduced.len() < 5 || reduced.len() > 1491 {
            return Err(protocol("UDP X83 SNA image length invalid"));
        }
        self.udp_user_input = Some((sequence, reduced.to_vec()));
        Ok(true)
    }

    pub(crate) fn take_completed_udp_expedited(&mut self) -> Option<u16> {
        self.udp_user_completion.take()
    }

    /// The gateway validates association, sequence and reduced X'83' body.
    /// The positive UDP response is held until native +RSP(UNBIND) arrives.
    pub(crate) fn submit_udp_abort(&mut self, sequence: u16, reduced: &[u8]) -> io::Result<bool> {
        if self.user_flow.is_none()
            || self.user_closed
            || self.udp_abort_input.is_some()
            || self.udp_abort_pending.is_some()
            || self.udp_abort_completion.is_some()
            || self.tcp_user_input.is_some()
            || self.native_user_output.is_some()
            || self.native_user_input.is_some()
            || self.tcp_user_output.is_some()
            || self.deferred_user_normal
            || self.expedited_ack.is_some()
            || self.udp_user_input.is_some()
            || self.udp_user_completion.is_some()
            || self
                .user_teardown
                .as_ref()
                .is_none_or(|teardown| teardown.phase() != TeardownPhase::Active)
        {
            return Ok(false);
        }
        self.udp_abort_input = Some((sequence, reduced.to_vec()));
        Ok(true)
    }

    pub(crate) fn take_completed_udp_abort(&mut self) -> Option<u16> {
        self.udp_abort_completion.take()
    }

    pub(crate) fn take_expedited_native_completed(&mut self) -> bool {
        std::mem::take(&mut self.expedited_native_completed)
    }

    /// The gateway calls this only after the final byte of each queued user
    /// TCP record was written, in queue order.
    pub(crate) fn complete_tcp_user_records(&mut self, completed: usize) -> io::Result<()> {
        for _ in 0..completed {
            self.tcp_user_writes
                .pop_front()
                .ok_or_else(|| protocol("untracked TCP62 user write completion"))?;
        }
        Ok(())
    }

    pub(crate) fn mark_tcp_user_record_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.tcp_user_output.as_ref() != Some(record) {
            return Err(protocol("TCP62 user output differs from prepared record"));
        }
        let flow = self
            .user_flow
            .as_mut()
            .ok_or_else(|| protocol("virtual user flow absent"))?;
        let kind = self
            .tcp_user_output_kind
            .take()
            .ok_or_else(|| protocol("TCP62 user output kind missing"))?;
        match kind {
            TcpUserOutputKind::Normal => flow.mark_tcp_enqueued(record)?,
            TcpUserOutputKind::Expedited => flow.mark_expedited_tcp_enqueued(record)?,
            TcpUserOutputKind::ExpeditedAck => {}
        }
        self.tcp_user_writes.push_back(kind);
        self.tcp_user_output = None;
        self.tcp_user_output_queued = false;
        Ok(())
    }

    fn reset_cp(&mut self) -> io::Result<()> {
        self.cp = VirtualNativeCp::new(self.local_xid.clone(), &self.local_cp, &self.peer_cp)?;
        self.initial_xid_sent = false;
        self.early_management_information = None;
        self.reciprocal_management = None;
        self.management_egress.clear();
        if let Some(user_bind) = self.user_bind.as_mut() {
            user_bind.close();
        }
        self.user_bind = None;
        self.user_bind_native_completed = false;
        self.early_user_response = None;
        self.tcp_bind_response = None;
        self.user_address = None;
        if let Some(flow) = self.user_flow.as_mut() {
            flow.close();
        }
        self.user_flow = None;
        self.tcp_user_input = None;
        self.deferred_user_normal = false;
        self.native_user_output = None;
        self.native_user_output_kind = None;
        self.native_user_output_queued = false;
        self.native_user_input = None;
        self.tcp_user_output = None;
        self.tcp_user_output_queued = false;
        self.udp_abort_output = None;
        self.udp_abort_output_queued = false;
        self.tcp_user_output_kind = None;
        self.expedited_ack = None;
        self.expedited_native_completed = false;
        self.user_teardown = None;
        self.native_user_close = None;
        self.tcp_user_writes.clear();
        self.user_closed = false;
        self.udp_user_input = None;
        self.udp_user_completion = None;
        self.udp_abort_input = None;
        self.udp_abort_pending = None;
        self.udp_abort_completion = None;
        if self.management.take().is_some() {
            // FQPCID and BIND token must be freshly minted on the next
            // circuit. A caller must construct a new virtual session.
            self.management_invalidated = true;
        }
        Ok(())
    }

    fn start_if_needed(&mut self) -> io::Result<()> {
        if self.management_invalidated {
            return Err(protocol(
                "virtual management needs a fresh session instance",
            ));
        }
        if self.initial_xid_sent {
            return Ok(());
        }
        let pdu = self.cp.prepare_active_null_xid()?;
        if !self.inner.send(RoutedUnit::DlcType1(pdu.clone()))? {
            return Err(protocol("WebSocket refused initial virtual null XID"));
        }
        self.cp.confirm_sent(&pdu)?;
        self.initial_xid_sent = true;
        Ok(())
    }

    fn waiting_management_ack(phase: ManagementPhase) -> bool {
        matches!(
            phase,
            ManagementPhase::AwaitBindAck
                | ManagementPhase::AwaitCnosAck
                | ManagementPhase::AwaitCnosIprAck
                | ManagementPhase::AwaitBisAck
                | ManagementPhase::AwaitBisIprAck
                | ManagementPhase::AwaitUnbindAck
        )
    }

    fn complete_management_egress(&mut self) -> io::Result<()> {
        let completed = self.inner.take_completed_information_count();
        if completed == 0 {
            return Ok(());
        }
        let mut remaining = completed;
        while let Some(tag) = self.management_egress.pop_front() {
            if remaining == 0 {
                self.management_egress.push_front(tag);
                break;
            }
            remaining -= 1;
            match tag {
                ManagementEgress::Initiator => {
                    let management = self
                        .management
                        .as_mut()
                        .ok_or_else(|| protocol("virtual management absent"))?;
                    management
                        .acknowledge(1)
                        .map_err(|_| protocol("virtual management LLC acknowledgement mismatch"))?;
                    if let Some(piu) = self.early_management_information.take() {
                        management
                            .observe(&piu)
                            .map_err(|_| protocol("early virtual management PIU is invalid"))?;
                        self.inner.on_downstream_completed(1)?;
                    }
                }
                ManagementEgress::ResponderBind => {
                    let responder = self
                        .reciprocal_management
                        .as_mut()
                        .ok_or_else(|| protocol("reciprocal management absent"))?;
                    responder.acknowledge_bind(1).map_err(|_| {
                        protocol("reciprocal management BIND acknowledgement mismatch")
                    })?;
                    if let Some(piu) = responder.take_early_attach() {
                        self.receive_reciprocal_management(&piu)?;
                        self.inner.on_downstream_completed(1)?;
                    }
                }
                ManagementEgress::ResponderAttach => self
                    .reciprocal_management
                    .as_mut()
                    .ok_or_else(|| protocol("reciprocal management absent"))?
                    .acknowledge_attach_replies(1)
                    .map_err(|_| protocol("reciprocal management CNOS acknowledgement mismatch"))?,
                ManagementEgress::ResponderBis => self
                    .reciprocal_management
                    .as_mut()
                    .ok_or_else(|| protocol("reciprocal management absent"))?
                    .acknowledge_bis(1)
                    .map_err(|_| protocol("reciprocal management BIS acknowledgement mismatch"))?,
                ManagementEgress::ResponderUnbind => self
                    .reciprocal_management
                    .as_mut()
                    .ok_or_else(|| protocol("reciprocal management absent"))?
                    .acknowledge_unbind(1)
                    .map_err(|_| {
                        protocol("reciprocal management UNBIND acknowledgement mismatch")
                    })?,
            }
        }
        if remaining == 0 {
            return Ok(());
        }
        if remaining == 1
            && self
                .user_bind
                .as_ref()
                .is_some_and(|bind| bind.phase() == UserBindPhase::AwaitNativeBind)
            && !self.user_bind_native_completed
        {
            self.user_bind_native_completed = true;
            if let Some(piu) = self.early_user_response.take() {
                self.accept_user_response(&piu)?;
                self.inner.on_downstream_completed(1)?;
            }
        } else if remaining == 1 && self.native_user_output_queued {
            let piu = self
                .native_user_output
                .take()
                .ok_or_else(|| protocol("native user output missing"))?;
            let kind = self
                .native_user_output_kind
                .take()
                .ok_or_else(|| protocol("native user output kind missing"))?;
            let flow = self
                .user_flow
                .as_mut()
                .ok_or_else(|| protocol("virtual user flow absent"))?;
            match kind {
                NativeUserOutputKind::Normal => flow.mark_native_enqueued(&piu)?,
                NativeUserOutputKind::Grant => flow.mark_native_grant_enqueued(&piu)?,
                NativeUserOutputKind::Expedited => {
                    flow.mark_expedited_native_enqueued(&piu)?;
                    if self.expedited_native_completed {
                        return Err(protocol("unclaimed TCP62 expedited native completion"));
                    }
                    self.expedited_native_completed = true;
                    self.tcp_user_output = self.expedited_ack.take();
                    self.tcp_user_output_kind = Some(TcpUserOutputKind::ExpeditedAck);
                }
                NativeUserOutputKind::TeardownUnbind => self
                    .user_teardown
                    .as_mut()
                    .ok_or_else(|| protocol("TCP62 user teardown absent"))?
                    .mark_native_unbind_enqueued(&piu)?,
                NativeUserOutputKind::NativeCloseResponse => {
                    self.native_user_close
                        .as_mut()
                        .ok_or_else(|| protocol("native user close absent"))?
                        .mark_native_response_enqueued(&piu)?;
                    self.user_closed = true;
                    flow.close();
                }
                NativeUserOutputKind::UdpExpedited(sequence) => {
                    flow.mark_udp_native_enqueued(&piu)?;
                    if self.udp_user_completion.replace(sequence).is_some() {
                        return Err(protocol("unclaimed UDP X83 native completion"));
                    }
                }
            }
            self.native_user_output_queued = false;
        } else {
            return Err(protocol(
                "virtual information completion has no outstanding PIU",
            ));
        }
        Ok(())
    }

    fn accept_user_response(&mut self, piu: &[u8]) -> io::Result<()> {
        let response = self
            .user_bind
            .as_mut()
            .ok_or_else(|| protocol("virtual user BIND is absent"))?
            .accept_native_response(piu)?;
        self.tcp_bind_response = Some(response.encode()?);
        Ok(())
    }

    fn drive_management(&mut self) -> io::Result<()> {
        if !self.cp.ready() || !self.inner.has_capacity() {
            return Ok(());
        }
        let Some(management) = self.management.as_mut() else {
            return Ok(());
        };
        let Some(piu) = management.prepared().map(<[u8]>::to_vec) else {
            if management.phase() == ManagementPhase::Complete {
                if let Some(user_bind) = self.user_bind.as_mut() {
                    if user_bind.phase() == UserBindPhase::NativeBindPrepared {
                        let piu = user_bind.native_bind().to_vec();
                        if self.inner.send(RoutedUnit::SnaInformation(piu.clone()))? {
                            user_bind.mark_native_bind_enqueued(&piu)?;
                        }
                    }
                }
            }
            return Ok(());
        };
        if self.inner.send(RoutedUnit::SnaInformation(piu.clone()))? {
            management.mark_enqueued(&piu).map_err(|_| {
                protocol("virtual management egress changed after queue acceptance")
            })?;
            self.management_egress
                .push_back(ManagementEgress::Initiator);
        }
        Ok(())
    }

    fn send_reciprocal(&mut self, piu: Vec<u8>, tag: ManagementEgress) -> io::Result<()> {
        if !self.inner.send(RoutedUnit::SnaInformation(piu))? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "reciprocal management egress has no WebSocket credit",
            ));
        }
        self.management_egress.push_back(tag);
        Ok(())
    }

    fn receive_reciprocal_management(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.reciprocal_management.is_none() {
            let management_cp = self
                .management
                .as_ref()
                .map(NativeManagementInitiator::local_cp)
                .unwrap_or(&self.local_cp);
            self.reciprocal_management = Some(ManagementSession::new(
                self.peer_cp.clone(),
                management_cp.to_owned(),
            ));
        }
        let responder = self.reciprocal_management.as_mut().unwrap();
        if piu.len() == 9 && piu[6..9] == [0x83, 1, 0] {
            responder
                .observe_ipr(piu)
                .map_err(|_| protocol("reciprocal management IPR invalid"))?;
            return Ok(());
        }
        match responder.phase() {
            ResponderPhase::AwaitBind => {
                responder
                    .observe_bind(piu)
                    .map_err(|_| protocol("reciprocal management BIND invalid"))?;
                let response = responder
                    .prepare_bind_response()
                    .map_err(|_| protocol("reciprocal management BIND response unavailable"))?
                    .to_vec();
                self.send_reciprocal(response.clone(), ManagementEgress::ResponderBind)?;
                self.reciprocal_management
                    .as_mut()
                    .unwrap()
                    .mark_bind_enqueued(&response)
                    .map_err(|_| protocol("reciprocal management BIND egress mismatch"))?;
            }
            ResponderPhase::AwaitBindAck => responder
                .buffer_early_attach(piu)
                .map_err(|_| protocol("reciprocal early CNOS invalid"))?,
            ResponderPhase::AwaitAttach => {
                let (ipr, cnos) = responder
                    .observe_attach(piu)
                    .map_err(|_| protocol("reciprocal CNOS invalid"))?;
                let (ipr, cnos) = (ipr.to_vec(), cnos.to_vec());
                self.send_reciprocal(ipr.clone(), ManagementEgress::ResponderAttach)?;
                self.send_reciprocal(cnos.clone(), ManagementEgress::ResponderAttach)?;
                self.reciprocal_management
                    .as_mut()
                    .unwrap()
                    .mark_attach_replies_enqueued(&ipr, &cnos)
                    .map_err(|_| protocol("reciprocal CNOS egress mismatch"))?;
            }
            ResponderPhase::CnosComplete => {
                let ipr = responder
                    .observe_remote_bis(piu)
                    .map_err(|_| protocol("reciprocal BIS invalid"))?
                    .to_vec();
                self.send_reciprocal(ipr.clone(), ManagementEgress::ResponderBis)?;
                let responder = self.reciprocal_management.as_mut().unwrap();
                responder
                    .mark_bis_ipr_enqueued(&ipr)
                    .map_err(|_| protocol("reciprocal BIS IPR egress mismatch"))?;
                let bis = responder
                    .prepare_local_bis(true)
                    .map_err(|_| protocol("reciprocal local BIS unavailable"))?
                    .to_vec();
                self.send_reciprocal(bis.clone(), ManagementEgress::ResponderBis)?;
                self.reciprocal_management
                    .as_mut()
                    .unwrap()
                    .mark_local_bis_enqueued(&bis)
                    .map_err(|_| protocol("reciprocal BIS egress mismatch"))?;
            }
            ResponderPhase::BisComplete => {
                let response = responder
                    .prepare_unbind_response(piu)
                    .map_err(|_| protocol("reciprocal UNBIND invalid"))?
                    .to_vec();
                self.send_reciprocal(response.clone(), ManagementEgress::ResponderUnbind)?;
                self.reciprocal_management
                    .as_mut()
                    .unwrap()
                    .mark_unbind_enqueued(&response)
                    .map_err(|_| protocol("reciprocal UNBIND egress mismatch"))?;
            }
            _ => return Err(protocol("reciprocal management PIU in wrong phase")),
        }
        Ok(())
    }

    fn drive_user_flow(&mut self) -> io::Result<()> {
        let Some(flow) = self.user_flow.as_mut() else {
            return Ok(());
        };
        if self.tcp_user_output.is_none() && self.native_user_output.is_none() {
            if let Some(piu) = self.native_user_input.take() {
                if self
                    .user_teardown
                    .as_ref()
                    .is_some_and(|teardown| teardown.phase() == TeardownPhase::AwaitNativeResponse)
                {
                    let bearer = self
                        .user_teardown
                        .as_mut()
                        .unwrap()
                        .accept_native_response(&piu)?;
                    if bearer == AbortBearer::Udp {
                        let sequence = self.udp_abort_pending.take().ok_or_else(|| {
                            protocol("UDP X83 Abort native response lacks pending sequence")
                        })?;
                        if self.udp_abort_completion.replace(sequence).is_some() {
                            return Err(protocol("unclaimed UDP X83 Abort completion"));
                        }
                    }
                    flow.close();
                    self.user_closed = true;
                } else if piu.len() >= 10 && piu[6..9] == [0x6b, 0x80, 0] && piu[9] == 0x32 {
                    self.udp_abort_output = Some(
                        self.native_user_close
                            .as_mut()
                            .ok_or_else(|| protocol("native user close absent"))?
                            .accept_native_unbind(&piu)?
                            .clone(),
                    );
                    flow.close();
                } else if piu.len() >= 9 && piu[0] & 1 != 0 && piu[6..9] != [0x83, 1, 0] {
                    self.tcp_user_output = Some(flow.prepare_native_expedited(&piu)?.clone());
                    self.tcp_user_output_kind = Some(TcpUserOutputKind::Expedited);
                } else {
                    match flow.prepare_native_input(&piu)? {
                        NativeInput::PacingGrant => {}
                        NativeInput::TcpRecord(record) => {
                            self.tcp_user_output = Some(record.clone());
                            self.tcp_user_output_kind = Some(TcpUserOutputKind::Normal);
                        }
                    }
                }
                self.inner.on_downstream_completed(1)?;
            }
        }
        if self.native_user_output.is_none() {
            if let Some((sequence, reduced)) = self.udp_abort_input.take() {
                let piu = self
                    .user_teardown
                    .as_mut()
                    .ok_or_else(|| protocol("UDP X83 user teardown absent"))?
                    .prepare_udp_abort(&reduced)?
                    .to_vec();
                self.native_user_output = Some(piu);
                self.native_user_output_kind = Some(NativeUserOutputKind::TeardownUnbind);
                self.udp_abort_pending = Some(sequence);
                flow.close();
            } else if let Some((sequence, reduced)) = self.udp_user_input.take() {
                let piu = flow.prepare_udp_expedited(&reduced)?.to_vec();
                self.native_user_output = Some(piu);
                self.native_user_output_kind = Some(NativeUserOutputKind::UdpExpedited(sequence));
            } else if self.deferred_user_normal {
                match flow.retry_deferred_normal() {
                    Ok(Some(piu)) => {
                        self.native_user_output = Some(piu.to_vec());
                        self.native_user_output_kind = Some(NativeUserOutputKind::Normal);
                        self.deferred_user_normal = false;
                    }
                    Ok(None) => self.deferred_user_normal = false,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            } else if let Some(record) = self.tcp_user_input.take() {
                match record.kind {
                    TcpKind::Expedited => {
                        let (piu, ack) = flow.prepare_tcp_expedited(&record)?;
                        self.native_user_output = Some(piu.to_vec());
                        self.native_user_output_kind = Some(NativeUserOutputKind::Expedited);
                        self.expedited_ack = Some(ack);
                    }
                    TcpKind::ExpeditedAck => flow.accept_tcp_expedited_ack(&record)?,
                    TcpKind::Abort => {
                        let teardown = self
                            .user_teardown
                            .as_mut()
                            .ok_or_else(|| protocol("TCP62 user teardown absent"))?;
                        match teardown.accept_abort(&record)? {
                            AbortAction::HardClose => {
                                flow.close();
                                self.user_closed = true;
                                self.inner.disconnect()?;
                            }
                            AbortAction::NativeUnbind(piu) => {
                                self.native_user_output = Some(piu.to_vec());
                                self.native_user_output_kind =
                                    Some(NativeUserOutputKind::TeardownUnbind);
                                flow.close();
                            }
                        }
                    }
                    TcpKind::Normal | TcpKind::Segmented => {
                        match flow.prepare_tcp_normal(&record) {
                            Ok(Some(piu)) => {
                                self.native_user_output = Some(piu.to_vec());
                                self.native_user_output_kind = Some(NativeUserOutputKind::Normal);
                            }
                            Ok(None) => {} // One segmented fragment was retained.
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                // The final segment is retained by ReverseUserFlow
                                // when the native send window is exhausted.
                                self.deferred_user_normal = true;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    _ => return Err(protocol("unsupported TCP62 user record kind")),
                }
            } else if self.tcp_user_output.is_none() {
                match flow.prepare_native_grant(1) {
                    Ok(Some(piu)) => {
                        self.native_user_output = Some(piu.to_vec());
                        self.native_user_output_kind = Some(NativeUserOutputKind::Grant);
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if let Some(piu) = self.native_user_output.as_ref() {
            if !self.native_user_output_queued
                && self.inner.has_capacity()
                && self.inner.send(RoutedUnit::SnaInformation(piu.clone()))?
            {
                self.native_user_output_queued = true;
            }
        }
        Ok(())
    }

    fn handle(&mut self, events: Vec<RouterEvent>) -> io::Result<Vec<RouterEvent>> {
        let mut output = Vec::with_capacity(events.len());
        for event in events {
            match event {
                RouterEvent::Unit(RoutedUnit::DlcType1(pdu)) => {
                    if let Some(reply) = self.cp.receive_type1(&pdu)? {
                        if !self.inner.send(RoutedUnit::DlcType1(reply.clone()))? {
                            return Err(protocol("WebSocket refused virtual Type1 response"));
                        }
                        self.cp.confirm_sent(&reply)?;
                    }
                }
                RouterEvent::Ready => {
                    self.cp.receive_link_ready()?;
                    self.inner.on_peer_ready()?;
                    output.push(RouterEvent::Ready);
                }
                RouterEvent::Unit(RoutedUnit::SnaInformation(piu)) => {
                    let mut observed = false;
                    if self.user_bind.is_none()
                        && !self.management_complete()
                        && piu.len() >= 9
                        && piu[0] & 0x02 == 0
                        && !(piu.len() == 12 && piu[6..9] == [0x83, 1, 0])
                    {
                        self.receive_reciprocal_management(&piu)?;
                        self.inner.on_downstream_completed(1)?;
                        continue;
                    }
                    let management = self.management.as_mut().ok_or_else(|| {
                        protocol("virtual native session handler is not installed")
                    })?;
                    if self.user_flow.is_some() {
                        if self.native_user_input.replace(piu).is_some() {
                            return Err(protocol("virtual native user ingress queue full"));
                        }
                    } else if management.phase() == ManagementPhase::Complete {
                        if self
                            .user_bind
                            .as_ref()
                            .is_none_or(|bind| bind.phase() != UserBindPhase::AwaitNativeBind)
                        {
                            return Err(protocol("virtual user BIND response without request"));
                        }
                        if self.user_bind_native_completed {
                            self.accept_user_response(&piu)?;
                            observed = true;
                        } else if self.early_user_response.replace(piu).is_some() {
                            return Err(protocol("multiple early virtual user BIND responses"));
                        }
                    } else if Self::waiting_management_ack(management.phase()) {
                        if self.early_management_information.replace(piu).is_some() {
                            return Err(protocol("multiple early virtual management PIUs"));
                        }
                    } else {
                        management
                            .observe(&piu)
                            .map_err(|_| protocol("virtual management peer PIU is invalid"))?;
                        observed = true;
                    }
                    if observed {
                        self.inner.on_downstream_completed(1)?;
                    }
                }
                RouterEvent::Unit(_) => {
                    return Err(protocol("unsupported virtual native encapsulation"));
                }
                RouterEvent::Closed | RouterEvent::TimedOut => {
                    self.reset_cp()?;
                    output.push(event);
                }
                // The concentrator publishes managed CP bindings on the
                // WebSocket control plane. A virtual native session has no
                // local LLC MAC to update, so this metadata is harmless.
                RouterEvent::ManagedMac(_) => {}
            }
        }
        Ok(output)
    }
}

impl<P: RoutePort> RoutePort for VirtualWsPort<P> {
    fn poll(&mut self, _can_accept_information: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        self.start_if_needed()?;
        // Keep the next native user PIU at the circuit boundary while the
        // prior one still awaits TCP queue acceptance.
        let can_receive = self.user_flow.is_none()
            || (self.native_user_input.is_none() && self.tcp_user_output.is_none());
        let events = self.inner.poll(can_receive)?;
        self.complete_management_egress()?;
        let output = events.map(|events| self.handle(events)).transpose()?;
        self.drive_management()?;
        self.drive_user_flow()?;
        Ok(output)
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.start_if_needed()?;
        let events = self.inner.tick()?;
        self.complete_management_egress()?;
        let output = self.handle(events)?;
        self.drive_management()?;
        self.drive_user_flow()?;
        Ok(output)
    }

    fn send(&mut self, _unit: RoutedUnit) -> io::Result<bool> {
        Err(protocol("virtual native session handler is not installed"))
    }

    fn has_capacity(&self) -> bool {
        false
    }

    fn available_receive_slots(&self) -> usize {
        0
    }

    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.inner.set_ingress_busy(busy)
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        if !self.ready() {
            return Err(protocol("virtual native link is not ready"));
        }
        Ok(())
    }

    fn failure_scope(&self, error: &io::Error) -> FailureScope {
        self.inner.failure_scope(error)
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.inner.disconnect()?;
        self.reset_cp()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_type1::NativeType1;
    use router_core::xid3::{ControlVector, ExchangeState, Role};
    use router_core::xid3_activation::Phase;
    use std::collections::VecDeque;
    use transport_ip_sna::{
        mptn_compensations::CompensationSet,
        mptn_connect::{Address, Connect, Direction, OptionalField, TransportRequirements},
        mptn_ingress::{IngressPolicy, IngressSession},
    };

    struct MockWs {
        incoming: VecDeque<RouterEvent>,
        sent: Vec<Vec<u8>>,
        information: Vec<Vec<u8>>,
        completed: usize,
        inbound_completed: usize,
        ready_sent: usize,
    }

    impl RoutePort for MockWs {
        fn poll(&mut self, _: bool) -> io::Result<Option<Vec<RouterEvent>>> {
            Ok(self.incoming.pop_front().map(|event| vec![event]))
        }
        fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
            Ok(vec![])
        }
        fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
            match unit {
                RoutedUnit::DlcType1(pdu) => self.sent.push(pdu),
                RoutedUnit::SnaInformation(piu) => self.information.push(piu),
                _ => panic!("unsupported mock virtual unit"),
            }
            Ok(true)
        }
        fn has_capacity(&self) -> bool {
            true
        }
        fn take_completed_information_count(&mut self) -> usize {
            std::mem::take(&mut self.completed)
        }
        fn on_downstream_completed(&mut self, count: usize) -> io::Result<()> {
            self.inbound_completed += count;
            Ok(())
        }
        fn set_ingress_busy(&mut self, _: bool) -> io::Result<()> {
            Ok(())
        }
        fn on_peer_ready(&mut self) -> io::Result<()> {
            self.ready_sent += 1;
            Ok(())
        }
        fn disconnect(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn xid(name: &str, role: Role) -> Xid3 {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(&[0xff, 0xf1, 0x12, 0x34]);
        fixed[9] = 0x08;
        fixed[19] = 0x40;
        fixed[21..23].copy_from_slice(&1496u16.to_be_bytes());
        fixed[27] = 7;
        let mut xid = Xid3::from_parts(
            fixed,
            vec![ControlVector {
                key: 0x0e,
                data: vec![
                    0xf4, 0xd8, 0xc1, 0xc2, 0xd6, 0xc2, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2,
                ],
            }],
        )
        .unwrap();
        xid.set_cp_name(name).unwrap();
        xid.set_role(role);
        xid.set_exchange_state(ExchangeState::Prenegotiation);
        xid
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn user_offer() -> IngressOffer {
        let source = hex("e2d6d3d5c5e34be2d5c1c1");
        let destination = hex("e2d6d3d5c5e34be2d5c1c2");
        let connect = Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            source: Address { node: source },
            destination: Address { node: destination },
            correlator: vec![0x35; 8],
            requirements: TransportRequirements {
                max_record: 0x8005,
                max_expedited: 0x76,
                max_termination: 0x76,
            },
            options: vec![
                OptionalField {
                    kind: 5,
                    processing: 8,
                    value: vec![1, 1],
                },
                OptionalField {
                    kind: 10,
                    processing: 2,
                    value: hex(concat!(
                        "00006b800031001307b0b0513303838c8c8303060200000000000000944300000b",
                        "e2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301238ff2ee27",
                        "00000c04e2d6d3d5c5e34be2d5c1c10a1300b0238ff2ee270000000be2d6",
                        "d3d5c5e34be2d5c1c26014cec37477b5dc299a0be2d6d3d5c5e34be2d5c1c1",
                        "2c0a01087bc3d6d5d5c5c3e3"
                    )),
                },
                OptionalField {
                    kind: 0x18,
                    processing: 0,
                    value: vec![1],
                },
                OptionalField {
                    kind: 0x19,
                    processing: 10,
                    value: vec![0, 0x20, 1, 3, 0x10, 0x83],
                },
                OptionalField {
                    kind: 0x1a,
                    processing: 0,
                    value: vec![0x84],
                },
            ],
        };
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "SOLNET.SNAA".into(),
            destination_lu: "SOLNET.SNAB".into(),
            user_mode: None,
            allow_blank_user_mode: true,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        ingress.receive(&connect.encode().unwrap()).unwrap().clone()
    }

    fn fresh_management(marker: u8) -> NativeManagementInitiator {
        NativeManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            0x2f,
            1,
            2,
            [marker; 8],
            [0x23, marker, marker, marker, marker, 0, 0],
            "",
            8,
        )
        .unwrap()
    }

    #[test]
    fn routed_management_cp_may_differ_from_adjacent_xid_cp() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("SOLNET.SNAB", Role::Secondary),
            "SOLNET.SNAB",
            "SOLNET.SNAA",
        )
        .unwrap();
        let management = NativeManagementInitiator::new(
            "QABOB.SNAB",
            "SOLNET.SNAA",
            0x2f,
            1,
            2,
            [1; 8],
            [0x23, 1, 1, 1, 1, 0, 0],
            "",
            8,
        )
        .unwrap();
        port.attach_management(management).unwrap();
        assert_eq!(port.management.as_ref().unwrap().local_cp(), "QABOB.SNAB");
        assert_eq!(port.local_cp, "SOLNET.SNAB");
    }

    #[test]
    fn rearm_requires_closed_and_drained_session_and_keeps_inner_port() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("SOLNET.SNAA", Role::Secondary),
            "SOLNET.SNAA",
            "SOLNET.SNAB",
        )
        .unwrap();
        port.attach_management(fresh_management(1)).unwrap();
        assert!(port.rearm_management(fresh_management(2)).is_err());
        port.user_closed = true;
        port.tcp_user_writes.push_back(TcpUserOutputKind::Normal);
        assert_eq!(
            port.rearm_management(fresh_management(2))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        port.tcp_user_writes.clear();
        port.rearm_management(fresh_management(2)).unwrap();
        assert!(!port.management_invalidated);
        assert!(!port.user_closed);
        port.tick().unwrap();
        assert_eq!(port.inner.sent.len(), 1);
        port.handle(vec![RouterEvent::Closed]).unwrap();
        assert!(port.management_invalidated);
        port.rearm_management(fresh_management(3)).unwrap();
        port.tick().unwrap();
        assert_eq!(port.inner.sent.len(), 2);
    }

    #[test]
    fn reciprocal_qa_management_bind_keeps_independent_session_and_exact_credit() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("QABOB.SNAB", Role::Secondary),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        let initiator = NativeManagementInitiator::new(
            "QABOB.SNAB",
            "QAALICE.SNAA",
            0x2f,
            1,
            2,
            [0xce, 0xc3, 0x74, 0x77, 0xb5, 0xdb, 0xed, 0x8c],
            [0x23, 0x50, 0x69, 0x47, 0xa1, 0, 0],
            "",
            8,
        )
        .unwrap();
        port.attach_management(initiator).unwrap();
        let reciprocal_bind = hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0cd8c1c1d3c9c3c54be2d5c1c12e000902e2d5c1e2e5c3d4c7",
            "09030123f4fd39d800000d04d8c1c1d3c9c3c54be2d5c1c1",
            "0a1300b023f4fd39d80000000ad8c1c2d6c24be2d5c1c2",
            "6015d8e7221f0a531d820cd8c1c1d3c9c3c54be2d5c1c1",
            "2c0a04087bc3d6d5d5c5c3e3"
        ));
        port.handle(vec![RouterEvent::Unit(RoutedUnit::SnaInformation(
            reciprocal_bind,
        ))])
        .unwrap();
        assert_eq!(port.inner.inbound_completed, 1);
        assert_eq!(&port.inner.information[0][..9], &hex("2d0002010000eb8000"));
        assert_eq!(
            port.reciprocal_management.as_ref().unwrap().phase(),
            ResponderPhase::AwaitBindAck
        );
        assert_eq!(
            port.management.as_ref().unwrap().phase(),
            ManagementPhase::BindPrepared
        );
        port.inner.completed = 1;
        port.complete_management_egress().unwrap();
        assert_eq!(
            port.reciprocal_management.as_ref().unwrap().phase(),
            ResponderPhase::AwaitAttach
        );
    }

    #[test]
    fn qa_user_pacing_grant_uses_one_slot_adaptive_ipm() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("QABOB.SNAB", Role::Secondary),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        let address = NativeAddress {
            daf: 2,
            oaf: 2,
            odai: true,
        };
        port.user_flow = Some(ReverseUserFlow::new(address, 3, 1).unwrap());
        port.native_user_input = Some(hex("2e0002020001030100bb"));
        port.drive_user_flow().unwrap();
        let record = port.tcp_user_record().unwrap().clone();
        assert_eq!(record.bytes, hex("0000000b000001030000bb"));
        port.mark_tcp_user_record_enqueued(&record).unwrap();
        port.drive_user_flow().unwrap();
        assert_eq!(
            port.inner.information,
            vec![hex("2f0002020000830100000001")]
        );
        assert_eq!(port.inner.inbound_completed, 1);
        port.inner.completed = 1;
        port.complete_management_egress().unwrap();
    }

    #[test]
    fn native_expedited_accepts_one_logical_ack_after_tcp_or_udp_delivery() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("QABOB.SNAB", Role::Secondary),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        port.user_flow = Some(
            ReverseUserFlow::new(
                NativeAddress {
                    daf: 2,
                    oaf: 2,
                    odai: true,
                },
                3,
                1,
            )
            .unwrap(),
        );
        let native = hex("2f00020280004b8000c900010001");
        port.native_user_input = Some(native.clone());
        port.drive_user_flow().unwrap();
        let first = port.tcp_user_record().unwrap().clone();
        assert_eq!(first.bytes, hex("0000000f0180004b8000c900010001"));
        port.mark_tcp_user_record_enqueued(&first).unwrap();
        assert_eq!(port.inner.inbound_completed, 1);

        // A correlated UDP X'83' positive is presented by the gateway as
        // this same logical X'03'. A later TCP X'03' must not clear another
        // expedited record; the gateway suppresses it before this API.
        let ack = TcpRecord::decode(hex("0000000503")).unwrap();
        assert!(port.submit_tcp_user_record(&ack).unwrap());
        port.drive_user_flow().unwrap();
        assert!(port.tcp_user_record().is_none());
        assert_eq!(port.inner.inbound_completed, 1);

        port.native_user_input = Some(native);
        port.drive_user_flow().unwrap();
        let second = port.tcp_user_record().unwrap().clone();
        port.mark_tcp_user_record_enqueued(&second).unwrap();
        assert!(port.submit_tcp_user_record(&ack).unwrap());
        port.drive_user_flow().unwrap();
        assert!(port.submit_tcp_user_record(&ack).unwrap());
        assert!(port.drive_user_flow().is_err());
    }

    #[test]
    fn udp_abort_completes_only_after_native_unbind_and_correlated_response() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("QABOB.SNAB", Role::Secondary),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        let address = NativeAddress {
            daf: 2,
            oaf: 2,
            odai: true,
        };
        let offer = user_offer();
        port.user_flow = Some(ReverseUserFlow::new(address, 3, 1).unwrap());
        port.user_teardown = Some(ReverseUserTeardown::from_user_offer(&offer, address).unwrap());
        let mut reduced = hex("00006b8000320f08010000");
        reduced.extend_from_slice(offer.fqpcid());
        let destination = &offer.connect().destination.node;
        reduced.extend_from_slice(&[
            0x35,
            0x13,
            0x08,
            1,
            0,
            0,
            (destination.len() + 1) as u8,
            0,
            destination.len() as u8,
        ]);
        reduced.extend_from_slice(destination);
        reduced.push(0);
        assert!(port.submit_udp_abort(9, &reduced).unwrap());
        assert!(!port.submit_udp_abort(9, &reduced).unwrap());
        port.drive_user_flow().unwrap();
        let unbind = port.inner.information.last().unwrap();
        assert_eq!(&unbind[..15], &hex("2f00020200006b8000320f08010000"));
        assert_eq!(port.take_completed_udp_abort(), None);

        port.inner.completed = 1;
        port.complete_management_egress().unwrap();
        assert_eq!(port.take_completed_udp_abort(), None);
        assert!(!port
            .submit_udp_expedited(10, &hex("80004b8000c900010001"))
            .unwrap());
        assert!(!port
            .submit_tcp_user_record(&TcpRecord::decode(hex("0000000503")).unwrap())
            .unwrap());
        port.native_user_input = Some(hex("2f0002020000eb800032"));
        port.drive_user_flow().unwrap();
        assert_eq!(port.inner.inbound_completed, 1);
        assert_eq!(port.take_completed_udp_abort(), Some(9));
        assert_eq!(port.take_completed_udp_abort(), None);
        assert!(port.user_closed());
    }

    #[test]
    fn native_management_starts_after_link_and_waits_for_exact_remote_llc_credit() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("SOLNET.SNAA", Role::Secondary),
            "SOLNET.SNAA",
            "SOLNET.SNAB",
        )
        .unwrap();
        let management = NativeManagementInitiator::new(
            "SOLNET.SNAA",
            "SOLNET.SNAB",
            0x2f,
            1,
            2,
            [0xce, 0xc3, 0x74, 0x77, 0xb5, 0xdb, 0xed, 0x8c],
            [0x23, 0x50, 0x69, 0x47, 0xa1, 0, 0],
            "",
            8,
        )
        .unwrap();
        port.attach_management(management).unwrap();
        let mut peer = NativeType1::new(xid("SOLNET.SNAB", Role::Primary)).unwrap();
        port.tick().unwrap();
        for _ in 0..8 {
            let next = port.inner.sent.pop().unwrap();
            let reply = peer.on_pdu(&next).unwrap().unwrap();
            peer.confirm_sent(&reply).unwrap();
            port.inner
                .incoming
                .push_back(RouterEvent::Unit(RoutedUnit::DlcType1(reply.pdu)));
            port.poll(false).unwrap();
            if peer.phase() == Phase::ReadyForSabme && port.cp.xid_ready() {
                break;
            }
        }
        assert!(port.inner.information.is_empty());
        port.inner.incoming.push_back(RouterEvent::Ready);
        assert_eq!(port.poll(false).unwrap().unwrap().len(), 1);
        assert_eq!(port.inner.ready_sent, 1); // LinkReady is immediate.
        assert_eq!(port.inner.information.len(), 1);
        assert_eq!(&port.inner.information[0][..9], &hex("2f00010200006b8500"));
        assert!(!port.management_complete());
        assert!(port
            .begin_user_bind(
                &user_offer(),
                NativeAddress {
                    daf: 2,
                    oaf: 1,
                    odai: false
                }
            )
            .is_err());

        // The passive peer may send an adaptive IPR before the BIND's LLC
        // acknowledgement reaches us. Buffer it without advancing session.
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(
                "2d0000010000830100007fff",
            ))));
        port.poll(false).unwrap();
        assert_eq!(port.inner.inbound_completed, 0);
        assert_eq!(
            port.management.as_ref().unwrap().phase(),
            ManagementPhase::AwaitBindAck
        );
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert_eq!(port.inner.inbound_completed, 1);

        assert_eq!(
            port.management.as_ref().unwrap().phase(),
            ManagementPhase::AwaitBindResponse
        );

        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(concat!(
                "2f0002010000eb800031001307b0b0513300808686800006020000000000000094434000",
                "0026000902e2d5c1e2e5c3d4c70203020c05e2d6d3d5c5e34be2d5c1c20a13",
                "00b023506a1207800000006014cec37477b5dbed8c0be2d6d3d5c5e34be2d5c1c1"
            )))));
        port.poll(false).unwrap();
        assert_eq!(port.inner.information.len(), 2);
        assert_eq!(&port.inner.information[1][..9], &hex("2e00010200010b9120"));
        assert!(!port.management_complete());

        port.inner.completed = 1;
        port.poll(false).unwrap();
        for peer_piu in [
            "2f0002010000830100000001",
            "2e0002010001039101001912100a0000000000080004000400084040404040404040",
        ] {
            port.inner
                .incoming
                .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(peer_piu))));
            port.poll(false).unwrap();
        }
        assert_eq!(&port.inner.information[2], &hex("2f0001020000830100000001"));
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert_eq!(&port.inner.information[3], &hex("2e00010200024b910070"));
        port.inner.completed = 1;
        port.poll(false).unwrap();
        for peer_piu in ["2f0002010000830100000001", "2e00020100024bb10070"] {
            port.inner
                .incoming
                .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(peer_piu))));
            port.poll(false).unwrap();
        }
        assert_eq!(&port.inner.information[4], &hex("2f0001020000830100000001"));
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert_eq!(&port.inner.information[5][..9], &hex("2f00010200006b8000"));
        port.inner.completed = 1;
        port.poll(false).unwrap();
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(
                "2f0002010000eb800032",
            ))));
        port.poll(false).unwrap();
        assert!(port.management_complete());
        assert_eq!(
            port.first_user_address().unwrap(),
            NativeAddress {
                daf: 2,
                oaf: 2,
                odai: true,
            }
        );

        port.begin_user_bind(
            &user_offer(),
            NativeAddress {
                daf: 2,
                oaf: 1,
                odai: false,
            },
        )
        .unwrap();
        port.poll(false).unwrap();
        assert_eq!(&port.inner.information[6][..9], &hex("2d00020100006b8500"));
        let mut native_response = hex(concat!(
            "0000eb800031001307b0b0513303038c8c83030602000000000000009443000000",
            "2600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20a1300b0",
            "238ff4f5c3000000006014cec37477b5dc299a0be2d6d3d5c5e34be2d5c1c1"
        ));
        native_response[5 + 8..5 + 14].copy_from_slice(&[0, 0x80, 0xc7, 0xc7, 0x80, 0]);
        native_response[5 + 25] = 0x40;
        native_response.splice(0..0, [0x2d, 0, 1, 2]);
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(
                native_response,
            )));
        port.poll(false).unwrap();
        assert!(!port.user_bind_response_ready());
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert!(port.user_bind_response_ready());
        let response = port.tcp_bind_response().unwrap().to_vec();
        port.mark_tcp_bind_response_enqueued(&response).unwrap();
        assert!(!port.user_bind_response_ready());

        let attach = TcpRecord::decode(hex("0000000b000001030000aa")).unwrap();
        assert!(port.submit_tcp_user_record(&attach).unwrap());
        port.poll(false).unwrap();
        assert_eq!(&port.inner.information[7], &hex("2c0002010001030100aa"));
        assert!(!port.submit_tcp_user_record(&attach).unwrap());
        port.inner.completed = 1;
        port.poll(false).unwrap();
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(
                "2d0001020000830100000003",
            ))));
        port.poll(false).unwrap();
        assert!(port.tcp_user_record().is_none()); // Adaptive IPR is local pacing.
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(
                "2c000102800083a000",
            ))));
        port.poll(false).unwrap();
        let native_reply = port.tcp_user_record().unwrap().clone();
        assert_eq!(native_reply.bytes, hex("0000000a00800083a000"));
        port.mark_tcp_user_record_enqueued(&native_reply).unwrap();
        assert!(port.tcp_user_record().is_none());
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(hex(
                "2c0001020001030100bb",
            ))));
        port.poll(false).unwrap();
        let native_request = port.tcp_user_record().unwrap().clone();
        assert_eq!(native_request.bytes, hex("0000000b000001030000bb"));
        port.mark_tcp_user_record_enqueued(&native_request).unwrap();
        port.poll(false).unwrap();
        assert_eq!(
            port.inner.information.last().unwrap(),
            &hex("2d0002010000830100")
        );
        port.inner.completed = 1;
        port.poll(false).unwrap();
        let expedited = TcpRecord::decode(hex("0000000b010002030000cc")).unwrap();
        assert!(port.submit_tcp_user_record(&expedited).unwrap());
        port.poll(false).unwrap();
        assert_eq!(
            port.inner.information.last().unwrap(),
            &hex("2d0002010002030000cc")
        );
        assert!(port.tcp_user_record().is_none());
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert!(port.take_expedited_native_completed());
        assert!(!port.take_expedited_native_completed());
        let expedited_ack = port.tcp_user_record().unwrap().clone();
        assert_eq!(expedited_ack.bytes, hex("0000000503"));
        port.mark_tcp_user_record_enqueued(&expedited_ack).unwrap();

        let udp_reduced = hex("80004b8000c900010001");
        assert!(port.submit_udp_expedited(7, &udp_reduced).unwrap());
        assert!(!port.submit_udp_expedited(7, &udp_reduced).unwrap());
        port.poll(false).unwrap();
        assert_eq!(
            port.inner.information.last().unwrap(),
            &hex("2d00020180004b8000c900010001")
        );
        assert_eq!(port.take_completed_udp_expedited(), None);
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert_eq!(port.take_completed_udp_expedited(), Some(7));
        assert_eq!(port.take_completed_udp_expedited(), None);

        let mut native_unbind = hex("2d00010200006b8000320100000000");
        native_unbind.extend_from_slice(user_offer().fqpcid());
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(native_unbind)));
        port.poll(false).unwrap();
        assert!(port.tcp_user_record().is_none());
        let abort = port.udp_abort_record().unwrap().clone();
        assert_eq!(abort.kind, TcpKind::Abort);
        assert!(port.complete_udp_abort_response().is_err());
        port.mark_udp_abort_enqueued(&abort).unwrap();
        assert!(port.udp_abort_record().is_none());
        assert!(!port.user_closed());
        port.complete_tcp_user_records(1).unwrap(); // Prior normal reply.
        port.complete_tcp_user_records(1).unwrap(); // Prior native request.
        port.complete_tcp_user_records(1).unwrap(); // Expedited ACK.
        assert_eq!(
            port.inner.information.last().unwrap(),
            &hex("2d00020180004b8000c900010001")
        );
        port.complete_udp_abort_response().unwrap(); // Correlated UDP positive.
        assert!(port.complete_udp_abort_response().is_err());
        port.poll(false).unwrap();
        assert_eq!(
            port.inner.information.last().unwrap(),
            &hex("2d0002010000eb800032")
        );
        assert!(!port.user_closed());
        port.inner.completed = 1;
        port.poll(false).unwrap();
        assert!(port.user_closed());
    }

    #[test]
    fn starts_type1_then_link_ready_and_rejects_unhandled_piu() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("QABOB.SNAB", Role::Secondary),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        let mut llc = NativeType1::new(xid("QAALICE.SNAA", Role::Primary)).unwrap();
        port.tick().unwrap();
        assert_eq!(port.inner.sent, vec![vec![4, 4, 0xbf]]);
        for _ in 0..8 {
            let next = port.inner.sent.pop().unwrap();
            let reply = llc.on_pdu(&next).unwrap().unwrap();
            llc.confirm_sent(&reply).unwrap();
            port.inner
                .incoming
                .push_back(RouterEvent::Unit(RoutedUnit::DlcType1(reply.pdu)));
            assert!(port.poll(false).unwrap().unwrap().is_empty());
            if llc.phase() == Phase::ReadyForSabme && port.cp.xid_ready() {
                break;
            }
        }
        assert_eq!(llc.phase(), Phase::ReadyForSabme);
        assert!(!port.ready());
        port.inner.incoming.push_back(RouterEvent::Ready);
        assert_eq!(port.poll(false).unwrap().unwrap().len(), 1);
        assert!(port.ready());
        assert_eq!(port.inner.ready_sent, 1);
        port.inner
            .incoming
            .push_back(RouterEvent::Unit(RoutedUnit::SnaInformation(vec![
                0x2d, 0, 1,
            ])));
        assert!(port.poll(false).is_err());
    }

    #[test]
    fn rejects_link_ready_before_xid() {
        let inner = MockWs {
            incoming: VecDeque::from([RouterEvent::Ready]),
            sent: vec![],
            information: vec![],
            completed: 0,
            inbound_completed: 0,
            ready_sent: 0,
        };
        let mut port = VirtualWsPort::new(
            inner,
            xid("QABOB.SNAB", Role::Secondary),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        assert!(port.poll(false).is_err());
        assert_eq!(port.inner.ready_sent, 0);
    }
}
