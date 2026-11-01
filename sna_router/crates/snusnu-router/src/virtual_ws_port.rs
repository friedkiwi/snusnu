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
    native_management_initiator::{NativeManagementInitiator, Phase as ManagementPhase},
    xid3::Xid3,
};
use std::io;
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord},
    mptn_ingress::IngressOffer,
    mptn_reverse_user_bind::{NativeAddress, Phase as UserBindPhase, ReverseUserBind},
    mptn_reverse_user_flow::{NativeInput, ReverseUserFlow},
};

#[derive(Clone, Copy)]
enum NativeUserOutputKind {
    Normal,
    Grant,
}

pub(crate) struct VirtualWsPort<P: RoutePort> {
    inner: P,
    cp: VirtualNativeCp,
    local_xid: Xid3,
    local_cp: String,
    peer_cp: String,
    initial_xid_sent: bool,
    management: Option<NativeManagementInitiator>,
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
}

impl<P: RoutePort> VirtualWsPort<P> {
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
            || initiator.local_cp() != self.local_cp
            || initiator.remote_cp() != self.peer_cp
        {
            return Err(protocol(
                "virtual management identity or attachment phase mismatch",
            ));
        }
        self.management = Some(initiator);
        Ok(())
    }

    pub(crate) fn management_complete(&self) -> bool {
        self.management
            .as_ref()
            .is_some_and(|management| management.phase() == ManagementPhase::Complete)
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
        Ok(())
    }

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
            || self.tcp_user_input.is_some()
            || self.native_user_output.is_some()
            || self.deferred_user_normal
        {
            return Ok(false);
        }
        if !matches!(record.kind, TcpKind::Normal | TcpKind::Segmented) {
            return Err(protocol(
                "virtual user flow does not accept this TCP62 record kind",
            ));
        }
        self.tcp_user_input = Some(record.clone());
        Ok(true)
    }

    pub(crate) fn tcp_user_record(&self) -> Option<&TcpRecord> {
        self.tcp_user_output.as_ref()
    }

    pub(crate) fn mark_tcp_user_record_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.tcp_user_output.as_ref() != Some(record) {
            return Err(protocol("TCP62 user output differs from prepared record"));
        }
        self.user_flow
            .as_mut()
            .ok_or_else(|| protocol("virtual user flow absent"))?
            .mark_tcp_enqueued(record)?;
        self.tcp_user_output = None;
        Ok(())
    }

    fn reset_cp(&mut self) -> io::Result<()> {
        self.cp = VirtualNativeCp::new(self.local_xid.clone(), &self.local_cp, &self.peer_cp)?;
        self.initial_xid_sent = false;
        self.early_management_information = None;
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
        let management = self
            .management
            .as_mut()
            .ok_or_else(|| protocol("virtual information completion without management"))?;
        if Self::waiting_management_ack(management.phase()) {
            management
                .acknowledge(completed)
                .map_err(|_| protocol("virtual management LLC acknowledgement mismatch"))?;
            if let Some(piu) = self.early_management_information.take() {
                management
                    .observe(&piu)
                    .map_err(|_| protocol("early virtual management PIU is invalid"))?;
            }
        } else if completed == 1
            && self
                .user_bind
                .as_ref()
                .is_some_and(|bind| bind.phase() == UserBindPhase::AwaitNativeBind)
            && !self.user_bind_native_completed
        {
            self.user_bind_native_completed = true;
            if let Some(piu) = self.early_user_response.take() {
                self.accept_user_response(&piu)?;
            }
        } else if completed == 1 && self.native_user_output_queued {
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
        }
        Ok(())
    }

    fn drive_user_flow(&mut self) -> io::Result<()> {
        let Some(flow) = self.user_flow.as_mut() else {
            return Ok(());
        };
        if self.tcp_user_output.is_none() && self.native_user_output.is_none() {
            if let Some(piu) = self.native_user_input.take() {
                match flow.prepare_native_input(&piu)? {
                    NativeInput::PacingGrant => {}
                    NativeInput::TcpRecord(record) => self.tcp_user_output = Some(record.clone()),
                }
            }
        }
        if self.native_user_output.is_none() {
            if self.deferred_user_normal {
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
                    }
                }
                RouterEvent::Unit(_) => {
                    return Err(protocol("unsupported virtual native encapsulation"));
                }
                RouterEvent::Closed | RouterEvent::TimedOut => {
                    self.reset_cp()?;
                    output.push(event);
                }
                RouterEvent::ManagedMac(_) => {
                    return Err(protocol("virtual native peer has no local LLC MAC"));
                }
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

    #[test]
    fn native_management_starts_after_link_and_waits_for_exact_remote_llc_credit() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
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
        assert_eq!(
            port.management.as_ref().unwrap().phase(),
            ManagementPhase::AwaitBindAck
        );
        port.inner.completed = 1;
        port.poll(false).unwrap();
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
    }

    #[test]
    fn starts_type1_then_link_ready_and_rejects_unhandled_piu() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
            information: vec![],
            completed: 0,
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
