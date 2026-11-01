//! A virtual native Type1 peer over one WebSocket circuit.
//!
//! The wrapped port owns circuit open, credit and transport retry. This
//! adapter starts XID without a local Ethernet interface, then waits for the
//! remote LLC endpoint's LinkReady. User and management PIUs remain disabled
//! until a session gateway is attached.

use crate::{
    routing::{FailureScope, RoutePort, RoutedUnit, RouterEvent},
    virtual_native_cp::VirtualNativeCp,
};
use router_core::{
    native_management_initiator::{NativeManagementInitiator, Phase as ManagementPhase},
    xid3::Xid3,
};
use std::io;

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

    fn reset_cp(&mut self) -> io::Result<()> {
        self.cp = VirtualNativeCp::new(self.local_xid.clone(), &self.local_cp, &self.peer_cp)?;
        self.initial_xid_sent = false;
        self.early_management_information = None;
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
        management
            .acknowledge(completed)
            .map_err(|_| protocol("virtual management LLC acknowledgement mismatch"))?;
        if let Some(piu) = self.early_management_information.take() {
            management
                .observe(&piu)
                .map_err(|_| protocol("early virtual management PIU is invalid"))?;
        }
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
            return Ok(());
        };
        if self.inner.send(RoutedUnit::SnaInformation(piu.clone()))? {
            management.mark_enqueued(&piu).map_err(|_| {
                protocol("virtual management egress changed after queue acceptance")
            })?;
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
                    if Self::waiting_management_ack(management.phase()) {
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
        // Pull pending information so an unsupported PIU causes an immediate
        // reset instead of being left indefinitely in the WebSocket queue.
        let events = self.inner.poll(true)?;
        self.complete_management_egress()?;
        let output = events.map(|events| self.handle(events)).transpose()?;
        self.drive_management()?;
        Ok(output)
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.start_if_needed()?;
        let events = self.inner.tick()?;
        self.complete_management_egress()?;
        let output = self.handle(events)?;
        self.drive_management()?;
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
