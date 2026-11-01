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
use router_core::xid3::Xid3;
use std::io;

pub(crate) struct VirtualWsPort<P: RoutePort> {
    inner: P,
    cp: VirtualNativeCp,
    local_xid: Xid3,
    local_cp: String,
    peer_cp: String,
    initial_xid_sent: bool,
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
        })
    }

    pub(crate) fn ready(&self) -> bool {
        self.cp.ready()
    }

    fn reset_cp(&mut self) -> io::Result<()> {
        self.cp = VirtualNativeCp::new(self.local_xid.clone(), &self.local_cp, &self.peer_cp)?;
        self.initial_xid_sent = false;
        Ok(())
    }

    fn start_if_needed(&mut self) -> io::Result<()> {
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
                RouterEvent::Unit(RoutedUnit::SnaInformation(_)) => {
                    return Err(protocol("virtual native session handler is not installed"));
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
        let Some(events) = self.inner.poll(true)? else {
            return Ok(None);
        };
        Ok(Some(self.handle(events)?))
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        self.start_if_needed()?;
        let events = self.inner.tick()?;
        self.handle(events)
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
            let RoutedUnit::DlcType1(pdu) = unit else {
                panic!("only Type1 is supported")
            };
            self.sent.push(pdu);
            Ok(true)
        }
        fn has_capacity(&self) -> bool {
            true
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

    #[test]
    fn starts_type1_then_link_ready_and_rejects_unhandled_piu() {
        let inner = MockWs {
            incoming: VecDeque::new(),
            sent: vec![],
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
