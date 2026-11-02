//! Native responder leg for a concentrator-initiated circuit.
//!
//! The WebSocket port owns the circuit and byte credit. This adapter owns
//! XID3, SNASVCMG/CNOS, and the native user BIND boundary. One instance is
//! used for one incoming circuit and one MPTN user session.

use crate::{
    config::parse_cp,
    remote::{InboundOpen, WsRoutePort},
    routing::{RoutePort, RoutedUnit, RouterEvent},
    virtual_native_cp::VirtualNativeCp,
};
use router_core::{
    native_management::{ManagementSession, Phase as ManagementPhase},
    user_bind::{UserBindOffer, UserBindPolicy},
    user_fmh5::parse_first_user_attach,
    xid3::Xid3,
};
use std::{collections::VecDeque, io};
use transport_ip_sna::mptn_gateway_edge::{NativeEvent, NativeLeg};

#[derive(Clone, Copy)]
enum Egress {
    ManagementBind,
    ManagementAttach,
    ManagementBis,
    ManagementUnbind,
    UserBind,
    UserData,
}

pub(crate) struct WsNativeResponder<P: RoutePort> {
    inner: P,
    cp: VirtualNativeCp,
    management: ManagementSession,
    source_lu: String,
    destination_lu: String,
    armed: bool,
    closed: bool,
    user_offer: Option<UserBindOffer>,
    user_bind_emitted: bool,
    user_bind_pending: bool,
    user_bind_acked: bool,
    first_attach_seen: bool,
    events: VecDeque<NativeEvent>,
    egress: VecDeque<Egress>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn protocol(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

impl<P: RoutePort> WsNativeResponder<P> {
    pub(crate) fn new(
        inner: P,
        local_xid: Xid3,
        local_cp: &str,
        peer_cp: &str,
        source_lu: &str,
        destination_lu: &str,
    ) -> io::Result<Self> {
        let source = parse_cp(source_lu)?;
        let destination = parse_cp(destination_lu)?;
        let local = parse_cp(local_cp)?;
        let peer = parse_cp(peer_cp)?;
        if source == destination || source.netid != peer.netid || destination.netid != local.netid {
            return Err(invalid("native user LU pair disagrees with CP policy"));
        }
        Ok(Self {
            inner,
            cp: VirtualNativeCp::new(local_xid, local_cp, peer_cp)?,
            management: ManagementSession::new(peer_cp.to_owned(), local_cp.to_owned()),
            source_lu: source_lu.to_owned(),
            destination_lu: destination_lu.to_owned(),
            armed: false,
            closed: false,
            user_offer: None,
            user_bind_emitted: false,
            user_bind_pending: false,
            user_bind_acked: false,
            first_attach_seen: false,
            events: VecDeque::new(),
            egress: VecDeque::new(),
        })
    }

    /// Call only after the WebSocket port has accepted and authorized an
    /// incoming Open. Sending Type1 before that would start an outgoing Open.
    pub(crate) fn arm_inbound(&mut self) -> io::Result<()> {
        if self.armed || self.closed {
            return Err(invalid("native responder already armed or closed"));
        }
        let pdu = self.cp.prepare_active_null_xid()?;
        if !self.inner.send(RoutedUnit::DlcType1(pdu.clone()))? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no Type1 circuit credit",
            ));
        }
        self.cp.confirm_sent(&pdu)?;
        self.armed = true;
        Ok(())
    }

    pub(crate) fn management_bind(
        &self,
    ) -> Option<&router_core::fid2_session_control::ManagementBind> {
        self.management.bind()
    }

    /// The management address and FQPCID can now seed a user-session Bridge.
    /// An early user BIND stays queued until the Bridge takes ownership.
    pub(crate) fn management_ready(&self) -> bool {
        matches!(
            self.management.phase(),
            ManagementPhase::BisComplete | ManagementPhase::Closed
        )
    }

    fn send_information(&mut self, piu: Vec<u8>, tag: Egress) -> io::Result<()> {
        if !self.inner.send(RoutedUnit::SnaInformation(piu))? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native WebSocket egress full",
            ));
        }
        self.egress.push_back(tag);
        Ok(())
    }

    /// WebSocket circuit credit is counted in bytes. A RoutePort exposes at
    /// most one `available_receive_slots()` even when its allowance can carry
    /// both short management replies. Require a full 1500-byte allowance and
    /// bound the pair before enqueueing either reply.
    fn send_management_pair(
        &mut self,
        first: Vec<u8>,
        second: Vec<u8>,
        tag: Egress,
    ) -> io::Result<()> {
        if !self.inner.has_capacity() || first.len() + second.len() > 1500 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native management reply pair has insufficient byte credit",
            ));
        }
        self.send_information(first, tag)?;
        self.send_information(second, tag)
    }

    fn complete_egress(&mut self) -> io::Result<()> {
        let completed = self.inner.take_completed_information_count();
        for _ in 0..completed {
            let tag = self
                .egress
                .pop_front()
                .ok_or_else(|| invalid("unmatched native completion"))?;
            match tag {
                Egress::ManagementBind => self.management.acknowledge_bind(1).map_err(protocol)?,
                Egress::ManagementAttach => self
                    .management
                    .acknowledge_attach_replies(1)
                    .map_err(protocol)?,
                Egress::ManagementBis => self.management.acknowledge_bis(1).map_err(protocol)?,
                Egress::ManagementUnbind => {
                    self.management.acknowledge_unbind(1).map_err(protocol)?
                }
                Egress::UserBind => {
                    if !self.user_bind_pending || self.user_bind_acked {
                        return Err(invalid("unexpected user BIND completion"));
                    }
                    self.user_bind_pending = false;
                    self.user_bind_acked = true;
                    self.events.push_back(NativeEvent::BindResponseAck(1));
                }
                Egress::UserData => self.events.push_back(NativeEvent::EgressAck(1)),
            }
        }
        if let Some(piu) = self.management.take_early_attach() {
            self.process_information(piu)?;
        }
        if self.management.phase() == ManagementPhase::BisComplete {
            if let Some(offer) = self.user_offer.as_ref().filter(|_| !self.user_bind_emitted) {
                self.events
                    .push_back(NativeEvent::UserBind(offer.request().to_vec()));
                self.user_bind_emitted = true;
            }
        }
        Ok(())
    }

    fn validate_user_bind(&self, piu: &[u8]) -> io::Result<UserBindOffer> {
        let management = self
            .management
            .bind()
            .ok_or_else(|| invalid("management BIND absent"))?;
        let policy = UserBindPolicy {
            plu: &self.source_lu,
            slu: &self.destination_lu,
            mode: "",
        };
        let offer = if self.management.phase() == ManagementPhase::Closed {
            UserBindOffer::from_request_after_management(piu, management, policy)
        } else {
            UserBindOffer::from_request_with_policy(piu, management, policy)
        }
        .map_err(protocol)?;
        offer.build_fixed_response(1).map_err(protocol)?;
        Ok(offer)
    }

    fn process_information(&mut self, piu: Vec<u8>) -> io::Result<()> {
        if !self.cp.ready() {
            return Err(invalid(
                "native information before verified XID3 and LinkReady",
            ));
        }
        // SNASVCMG can release its own session after the user BIND has been
        // accepted. Its SC UNBIND still belongs to management, even when the
        // user session is waiting for its first FMH-5 Attach.
        if piu.len() >= 10 && piu[6..9] == [0x6b, 0x80, 0] && piu[9] == 0x32 {
            if self.management.phase() != ManagementPhase::BisComplete {
                return Err(invalid("native management UNBIND outside BIS boundary"));
            }
            let response = self
                .management
                .prepare_unbind_response(&piu)
                .map_err(protocol)?
                .to_vec();
            self.send_information(response.clone(), Egress::ManagementUnbind)?;
            self.management
                .mark_unbind_enqueued(&response)
                .map_err(protocol)?;
            return Ok(());
        }
        if let Some(offer) = self.user_offer.as_ref().filter(|_| self.user_bind_acked) {
            if !self.first_attach_seen {
                parse_first_user_attach(&piu, offer).map_err(protocol)?;
                self.first_attach_seen = true;
                self.events.push_back(NativeEvent::FirstAttach(piu));
            } else {
                self.events.push_back(NativeEvent::UserInformation(piu));
            }
            return Ok(());
        }
        if self.management.phase() == ManagementPhase::Closed {
            if self.user_offer.is_some() {
                return Err(invalid("native user BIND response not acknowledged"));
            }
            let offer = self.validate_user_bind(&piu)?;
            self.events.push_back(NativeEvent::UserBind(piu));
            self.user_offer = Some(offer);
            self.user_bind_emitted = true;
            return Ok(());
        }
        if piu.len() >= 9 && piu[6] == 0x83 {
            self.management.observe_ipr(&piu).map_err(protocol)?;
            return Ok(());
        }
        match self.management.phase() {
            ManagementPhase::AwaitBind => {
                self.management.observe_bind(&piu).map_err(protocol)?;
                let response = self
                    .management
                    .prepare_bind_response()
                    .map_err(protocol)?
                    .to_vec();
                self.send_information(response.clone(), Egress::ManagementBind)?;
                self.management
                    .mark_bind_enqueued(&response)
                    .map_err(protocol)?;
            }
            ManagementPhase::AwaitBindAck => self
                .management
                .buffer_early_attach(&piu)
                .map_err(protocol)?,
            ManagementPhase::AwaitAttach => {
                let (ipr, cnos) = self.management.observe_attach(&piu).map_err(protocol)?;
                let (ipr, cnos) = (ipr.to_vec(), cnos.to_vec());
                self.send_management_pair(ipr.clone(), cnos.clone(), Egress::ManagementAttach)?;
                self.management
                    .mark_attach_replies_enqueued(&ipr, &cnos)
                    .map_err(protocol)?;
            }
            ManagementPhase::CnosComplete => {
                if !self.inner.has_capacity() {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIS has insufficient byte credit",
                    ));
                }
                let ipr = self
                    .management
                    .observe_remote_bis(&piu)
                    .map_err(protocol)?
                    .to_vec();
                self.send_information(ipr.clone(), Egress::ManagementBis)?;
                self.management
                    .mark_bis_ipr_enqueued(&ipr)
                    .map_err(protocol)?;
                let local_bis = self
                    .management
                    .prepare_local_bis(true)
                    .map_err(protocol)?
                    .to_vec();
                if ipr.len() + local_bis.len() > 1500 {
                    return Err(invalid("native BIS reply pair exceeds byte allowance"));
                }
                self.send_information(local_bis.clone(), Egress::ManagementBis)?;
                self.management
                    .mark_local_bis_enqueued(&local_bis)
                    .map_err(protocol)?;
            }
            ManagementPhase::AwaitBisAck => {
                if self.user_offer.is_some() {
                    return Err(invalid("duplicate native user BIND"));
                }
                self.user_offer = Some(self.validate_user_bind(&piu)?);
            }
            ManagementPhase::BisComplete => {
                let candidate = self
                    .user_offer
                    .is_none()
                    .then(|| self.validate_user_bind(&piu));
                if let Some(Ok(offer)) = candidate {
                    self.user_offer = Some(offer);
                    self.events.push_back(NativeEvent::UserBind(piu));
                    self.user_bind_emitted = true;
                    return Ok(());
                }
                let response = self
                    .management
                    .prepare_unbind_response(&piu)
                    .map_err(protocol)?
                    .to_vec();
                self.send_information(response.clone(), Egress::ManagementUnbind)?;
                self.management
                    .mark_unbind_enqueued(&response)
                    .map_err(protocol)?;
            }
            _ => return Err(invalid("unexpected native management PIU")),
        }
        Ok(())
    }

    fn process_event(&mut self, event: RouterEvent) -> io::Result<()> {
        match event {
            RouterEvent::Unit(RoutedUnit::DlcType1(pdu)) => {
                if let Some(response) = self.cp.receive_type1(&pdu)? {
                    if !self.inner.send(RoutedUnit::DlcType1(response.clone()))? {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "native Type1 egress full",
                        ));
                    }
                    self.cp.confirm_sent(&response)?;
                }
            }
            RouterEvent::Ready => self.cp.receive_link_ready()?,
            RouterEvent::Unit(RoutedUnit::SnaInformation(piu)) => {
                self.process_information(piu)?;
                self.inner.on_downstream_completed(1)?;
            }
            RouterEvent::Closed | RouterEvent::TimedOut => {
                self.closed = true;
                self.events.push_back(NativeEvent::Closed);
            }
            _ => return Err(invalid("unsupported native WebSocket route event")),
        }
        Ok(())
    }

    /// Advance XID and management while retaining any early user BIND for
    /// the GatewayEdge that will take ownership after management is ready.
    pub(crate) fn poll_management_once(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "native circuit closed during management",
            ));
        }
        if self.management_ready() {
            return Ok(());
        }
        self.drive_once(false)
    }

    fn drive_once(&mut self, can_accept_information: bool) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        if !self.armed {
            return Err(invalid(
                "native responder has no authorized inbound circuit",
            ));
        }
        self.complete_egress()?;
        if !self.events.is_empty() {
            return self.inner.flush();
        }
        let receive_credit = self.user_offer.is_none() || can_accept_information;
        if let Some(events) = self.inner.poll(receive_credit)? {
            for event in events {
                self.process_event(event)?;
            }
        }
        for event in self.inner.tick()? {
            self.process_event(event)?;
        }
        self.complete_egress()?;
        self.inner.flush()
    }
}

impl WsNativeResponder<WsRoutePort> {
    /// Poll an authenticated WebSocket route until a native circuit opens,
    /// then start XID3 on that circuit. The caller receives the server-owned
    /// source identity for its route decision and audit log.
    pub(crate) fn poll_inbound_open_once(&mut self) -> io::Result<Option<InboundOpen>> {
        if self.armed || self.closed {
            return Err(invalid("native responder is already armed or closed"));
        }
        if let Some(events) = self.inner.poll(false)? {
            if !events.is_empty() {
                return Err(invalid("native circuit data arrived before inbound Open"));
            }
        }
        let Some(open) = self.inner.take_inbound_open() else {
            return Ok(None);
        };
        self.arm_inbound()?;
        self.inner.flush()?;
        Ok(Some(open))
    }
}

impl<P: RoutePort> NativeLeg for WsNativeResponder<P> {
    fn receive_once(&mut self, can_accept_information: bool) -> io::Result<Option<NativeEvent>> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        self.drive_once(can_accept_information)?;
        Ok(self.events.pop_front())
    }

    fn enqueue(&mut self, piu: &[u8]) -> io::Result<bool> {
        if self.closed || self.user_offer.is_none() {
            return Err(invalid("native user session is absent"));
        }
        let tag = if !self.user_bind_acked && !self.user_bind_pending {
            let expected = self
                .user_offer
                .as_ref()
                .unwrap()
                .build_fixed_response(1)
                .map_err(protocol)?;
            if piu != expected {
                return Err(invalid(
                    "native user BIND reply differs from validated profile",
                ));
            }
            Egress::UserBind
        } else if self.user_bind_acked {
            Egress::UserData
        } else {
            return Ok(false);
        };
        if !self.inner.send(RoutedUnit::SnaInformation(piu.to_vec()))? {
            return Ok(false);
        }
        if matches!(tag, Egress::UserBind) {
            self.user_bind_pending = true;
        }
        self.egress.push_back(tag);
        Ok(true)
    }

    fn available_slots(&self) -> usize {
        self.inner.available_receive_slots()
    }

    fn management_closed(&self) -> bool {
        self.management.phase() == ManagementPhase::Closed
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        self.inner.disconnect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_type1::NativeType1;
    use router_core::{
        xid3::{Role, Xid3},
        xid3_activation::Phase,
        xid3_local::LocalLlcProfile,
    };
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct State {
        type1: Vec<Vec<u8>>,
        information: Vec<Vec<u8>>,
        completed: usize,
        disconnected: bool,
    }

    struct FakePort(Rc<RefCell<State>>);

    impl RoutePort for FakePort {
        fn poll(&mut self, _: bool) -> io::Result<Option<Vec<RouterEvent>>> {
            Ok(None)
        }
        fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
            Ok(Vec::new())
        }
        fn send(&mut self, unit: RoutedUnit) -> io::Result<bool> {
            match unit {
                RoutedUnit::DlcType1(pdu) => self.0.borrow_mut().type1.push(pdu),
                RoutedUnit::SnaInformation(piu) => self.0.borrow_mut().information.push(piu),
                _ => return Err(invalid("unexpected fake route unit")),
            }
            Ok(true)
        }
        fn has_capacity(&self) -> bool {
            true
        }
        fn set_ingress_busy(&mut self, _: bool) -> io::Result<()> {
            Ok(())
        }
        fn on_peer_ready(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn take_completed_information_count(&mut self) -> usize {
            std::mem::take(&mut self.0.borrow_mut().completed)
        }
        fn disconnect(&mut self) -> io::Result<()> {
            self.0.borrow_mut().disconnected = true;
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn xid() -> Xid3 {
        LocalLlcProfile {
            cp_name: "QABOB.SNAB".into(),
            station_name: "BOB".into(),
            node_id: [0xff, 0xf1, 0x23, 0x45],
            tg_number: 1,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: Role::Secondary,
        }
        .build()
        .unwrap()
    }

    fn responder(state: Rc<RefCell<State>>) -> WsNativeResponder<FakePort> {
        WsNativeResponder::new(
            FakePort(state),
            xid(),
            "QABOB.SNAB",
            "QAALICE.SNAA",
            "QAALICE.SNAA",
            "QABOB.SNAB",
        )
        .unwrap()
    }

    fn decoded_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn make_ready(leg: &mut WsNativeResponder<FakePort>) {
        let peer_xid = LocalLlcProfile {
            cp_name: "QAALICE.SNAA".into(),
            station_name: "ALICE".into(),
            node_id: [0, 0, 0, 1],
            tg_number: 1,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: Role::Primary,
        }
        .build()
        .unwrap();
        let mut peer = NativeType1::new(peer_xid).unwrap();
        leg.arm_inbound().unwrap();
        let mut next = leg.inner.0.borrow().type1.last().unwrap().clone();
        for _ in 0..8 {
            let reply = peer.on_pdu(&next).unwrap().unwrap();
            peer.confirm_sent(&reply).unwrap();
            let response = leg.cp.receive_type1(&reply.pdu).unwrap().unwrap();
            leg.cp.confirm_sent(&response).unwrap();
            next = response;
            if peer.phase() == Phase::ReadyForSabme && leg.cp.xid_ready() {
                break;
            }
        }
        assert_eq!(peer.phase(), Phase::ReadyForSabme);
        leg.cp.receive_link_ready().unwrap();
        assert!(leg.cp.ready());
    }

    #[test]
    fn inbound_circuit_must_be_armed_before_type1_or_user_data() {
        let state = Rc::new(RefCell::new(State::default()));
        let mut leg = responder(state.clone());
        assert!(leg.receive_once(true).is_err());
        assert!(leg.enqueue(&[0x2d, 0]).is_err());
        assert!(state.borrow().type1.is_empty());
        leg.arm_inbound().unwrap();
        assert_eq!(state.borrow().type1, vec![vec![4, 4, 0xbf]]);
        assert!(leg.arm_inbound().is_err());
        assert!(leg.receive_once(true).unwrap().is_none());
        leg.close().unwrap();
        assert!(state.borrow().disconnected);
    }

    #[test]
    fn identical_user_lus_are_rejected() {
        let state = Rc::new(RefCell::new(State::default()));
        assert!(WsNativeResponder::new(
            FakePort(state),
            xid(),
            "QABOB.SNAB",
            "QAALICE.SNAA",
            "QABOB.SNAB",
            "QABOB.SNAB",
        )
        .is_err());
        let state = Rc::new(RefCell::new(State::default()));
        assert!(WsNativeResponder::new(
            FakePort(state),
            xid(),
            "QABOB.SNAB",
            "QAALICE.SNAA",
            "WRONGNET.SNAA",
            "QABOB.SNAB",
        )
        .is_err());
    }

    #[test]
    fn management_bind_response_requires_exact_websocket_completion() {
        let state = Rc::new(RefCell::new(State::default()));
        let mut leg = responder(state.clone());
        make_ready(&mut leg);
        // Sanitized QAALICE to QABOB SNASVCMG BIND from the native lab.
        let bind = decoded_hex(concat!(
            "2d00010200006b800031001307b0b0513307878686870706020000000000000094434000",
            "0cd8c1c1d3c9c3c54be2d5c1c12e000902e2d5c1e2e5c3d4c7",
            "09030123f4fd39d800000d04d8c1c1d3c9c3c54be2d5c1c1",
            "0a1300b023f4fd39d80000000ad8c1c2d6c24be2d5c1c2",
            "6015d8e7221f0a531d820cd8c1c1d3c9c3c54be2d5c1c1",
            "2c0a04087bc3d6d5d5c5c3e3"
        ));
        leg.process_information(bind).unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::AwaitBindAck);
        assert_eq!(state.borrow().information.len(), 1);
        assert_eq!(
            &state.borrow().information[0][..9],
            &[0x2d, 0, 2, 1, 0, 0, 0xeb, 0x80, 0]
        );
        leg.complete_egress().unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::AwaitBindAck);
        state.borrow_mut().completed = 1;
        leg.complete_egress().unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::AwaitAttach);
        // RoutePort's default slot API reports one boolean slot, while the
        // WebSocket byte allowance carries both short CNOS replies.
        assert_eq!(leg.inner.available_receive_slots(), 1);
        let attach = vec![
            0x2c, 0, 1, 2, 0, 1, 0x0b, 0x91, 0x20, 0x0c, 0x05, 0x02, 0xff, 0, 3, 0xd0, 0, 0, 2,
            0x06, 0xf1, 0, 25, 0x12, 0x10, 2, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 8, 0x40, 0x40, 0x40,
            0x40, 0x40, 0x40, 0x40, 0x40,
        ];
        leg.process_information(attach).unwrap();
        assert_eq!(state.borrow().information.len(), 3);
        assert_eq!(leg.management.phase(), ManagementPhase::AwaitCnosAck);
        state.borrow_mut().completed = 2;
        leg.complete_egress().unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::CnosComplete);
        leg.process_information(vec![0x2c, 0, 1, 2, 0, 0, 0x83, 1, 0])
            .unwrap();
        leg.process_information(vec![0x2c, 0, 1, 2, 0, 2, 0x4b, 0x91, 0, 0x70])
            .unwrap();
        assert_eq!(state.borrow().information.len(), 5);
        assert_eq!(leg.management.phase(), ManagementPhase::AwaitBisAck);
        state.borrow_mut().completed = 2;
        leg.complete_egress().unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::BisComplete);
        // The live Alice→Bob run accepted this user BIND, then received a
        // management UNBIND before the first user FMH-5 Attach.
        let user_bind = decoded_hex(concat!(
            "2d00020200006b800031001307b0b051330383c7c7830306020000000000000094434000",
            "0cd8c1c1d3c9c3c54be2d5c1c12e0009024040404040404040090301247e7f02818000",
            "0d04d8c1c1d3c9c3c54be2d5c1c10a1300b0247e7f02818000000ad8c1c2d6c24be2d5c1c2",
            "6015d8e7221f0a531d860cd8c1c1d3c9c3c54be2d5c1c12c0a01087bc3d6d5d5c5c3e3"
        ));
        leg.process_information(user_bind).unwrap();
        assert!(leg.user_offer.is_some());
        leg.user_bind_acked = true;
        let mut unbind = vec![0x2d, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0];
        unbind.extend_from_slice(leg.management_bind().unwrap().fqpcid());
        leg.process_information(unbind).unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::AwaitUnbindAck);
        assert_eq!(
            state.borrow().information.last().unwrap(),
            &[0x2d, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x32]
        );
        assert!(leg.user_offer.is_some());
        assert!(!leg.first_attach_seen);
        state.borrow_mut().completed = 1;
        leg.complete_egress().unwrap();
        assert_eq!(leg.management.phase(), ManagementPhase::Closed);
    }
}
