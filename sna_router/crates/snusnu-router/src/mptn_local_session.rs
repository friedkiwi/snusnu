//! A local TCP62 to TCP62 circuit on the shared LU session event pipeline.
//! Each attachment owns its own TCP association and exclusive UDP/397 lease.

use std::{io, net::UdpSocket, time::Duration};

use router_core::session::{SessionEvent, SessionIdentity, SessionUnit};

use crate::{
    hpr_local_mptn::HprToMptnSession,
    hpr_mptn_session_source::MptnToHprSession,
    hpr_session_source::{SessionSource, SourceUpdate},
    mptn_outbound_port::OutboundEndpoint,
};

pub(crate) struct MptnLocalSession {
    source: MptnToHprSession,
    target: Option<HprToMptnSession>,
    target_udp: Option<UdpSocket>,
    target_endpoint: OutboundEndpoint,
    identity: SessionIdentity,
    source_gateway: String,
    target_gateway: String,
}

trait SessionTarget {
    fn send(&mut self, event: &SessionEvent) -> io::Result<bool>;
    fn poll(&mut self) -> io::Result<Option<SessionEvent>>;
    fn confirm_polled(&mut self) -> io::Result<()>;
}

impl SessionTarget for HprToMptnSession {
    fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        HprToMptnSession::send(self, event)
    }

    fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
        HprToMptnSession::poll(self)
    }

    fn confirm_polled(&mut self) -> io::Result<()> {
        HprToMptnSession::confirm_polled(self)
    }
}

/// Retain each carrier event until the other carrier accepts it. The target
/// is opened only after the first BIND, so a rejected setup cannot consume a
/// TCP62 destination association.
fn relay_once<S, T, F>(source: &mut S, target: &mut Option<T>, open_target: F) -> io::Result<bool>
where
    S: SessionSource,
    T: SessionTarget,
    F: FnOnce(&SessionUnit) -> io::Result<T>,
{
    if let Some(update) = source.poll()? {
        match update {
            SourceUpdate::Closed => {
                source.complete_received(false)?;
                return Ok(false);
            }
            SourceUpdate::Event(event) => {
                if target.is_none() {
                    let SessionEvent::BindRequest(bind) = &event else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "local MPTN circuit did not start with BIND",
                        ));
                    };
                    *target = Some(open_target(bind)?);
                }
                if target.as_mut().unwrap().send(&event)? {
                    source.complete_received(!matches!(event, SessionEvent::Credit { .. }))?;
                }
            }
        }
    }
    if let Some(target) = target.as_mut() {
        if let Some(event) = target.poll()? {
            if source.send(&event)? {
                target.confirm_polled()?;
            }
        }
    }
    Ok(true)
}

impl MptnLocalSession {
    pub(crate) fn new(
        source: MptnToHprSession,
        target_udp: UdpSocket,
        target_endpoint: OutboundEndpoint,
        identity: SessionIdentity,
        source_gateway: String,
        target_gateway: String,
    ) -> Self {
        Self {
            source,
            target: None,
            target_udp: Some(target_udp),
            target_endpoint,
            identity,
            source_gateway,
            target_gateway,
        }
    }

    pub(crate) fn gateways(&self) -> (&str, &str) {
        (&self.source_gateway, &self.target_gateway)
    }

    /// An event stays leased to its carrier until the other carrier accepts it.
    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        let live = relay_once(&mut self.source, &mut self.target, |bind| {
            let udp = self.target_udp.take().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "local MPTN target UDP lease missing",
                )
            })?;
            HprToMptnSession::new(
                self.target_endpoint,
                udp,
                &self.identity,
                bind,
                Duration::from_secs(600),
            )
        })?;
        if !live {
            self.close()?;
        }
        Ok(live)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.source.close()?;
        if let Some(target) = self.target.as_mut() {
            target.close();
        }
        self.target_udp.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use crate::session_switch::ee_bridge::{self as ee_session_bridge, EeBridgeIngress};
    use router_core::session::Flow;

    impl SessionTarget for EeBridgeIngress {
        fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
            EeBridgeIngress::send(self, event)
        }

        fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
            EeBridgeIngress::poll(self)
        }

        fn confirm_polled(&mut self) -> io::Result<()> {
            EeBridgeIngress::confirm_polled(self)
        }
    }

    #[derive(Default)]
    struct Source {
        incoming: VecDeque<SourceUpdate>,
        sent: Vec<SessionEvent>,
        confirmations: Vec<bool>,
        blocked: bool,
    }

    impl SessionSource for Source {
        fn poll(&mut self) -> io::Result<Option<SourceUpdate>> {
            Ok(self.incoming.front().cloned())
        }

        fn complete_received(&mut self, charge: bool) -> io::Result<()> {
            self.incoming.pop_front().expect("leased source event");
            self.confirmations.push(charge);
            Ok(())
        }

        fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
            if self.blocked {
                return Ok(false);
            }
            self.sent.push(event.clone());
            Ok(true)
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Target {
        incoming: VecDeque<SessionEvent>,
        sent: Vec<SessionEvent>,
        confirmations: usize,
        blocked: bool,
    }

    impl SessionTarget for Target {
        fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
            if self.blocked {
                return Ok(false);
            }
            self.sent.push(event.clone());
            Ok(true)
        }

        fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
            Ok(self.incoming.front().cloned())
        }

        fn confirm_polled(&mut self) -> io::Result<()> {
            self.incoming.pop_front().expect("leased target event");
            self.confirmations += 1;
            Ok(())
        }
    }

    fn unit(ru: u8) -> SessionUnit {
        SessionUnit::from_reduced(&[0, 7, 0x6b, 0x80, 0, ru]).unwrap()
    }

    #[test]
    fn mptn_bridge_preserves_bind_information_credit_unbind_and_close_leases() {
        let bind = SessionEvent::BindRequest(unit(0x31));
        let bind_result = SessionEvent::BindResult {
            accepted: true,
            unit: unit(0xb1),
        };
        let from_source = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(0xc9),
        };
        let from_target = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(0xca),
        };
        let credit = SessionEvent::Credit {
            normal: 4,
            expedited: 1,
        };
        let unbind = SessionEvent::Unbind(unit(0x32));
        let mut source = Source::default();
        let mut target = None;

        source.incoming.push_back(SourceUpdate::Event(bind.clone()));
        assert!(relay_once(&mut source, &mut target, |_| Ok(Target::default())).unwrap());
        assert_eq!(target.as_ref().unwrap().sent, [bind]);
        assert_eq!(source.confirmations, [true]);

        target
            .as_mut()
            .unwrap()
            .incoming
            .push_back(bind_result.clone());
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(source.sent, [bind_result]);
        assert_eq!(target.as_ref().unwrap().confirmations, 1);

        source
            .incoming
            .push_back(SourceUpdate::Event(from_source.clone()));
        target.as_mut().unwrap().blocked = true;
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(
            source.incoming.front(),
            Some(&SourceUpdate::Event(from_source.clone()))
        );
        assert_eq!(source.confirmations, [true]);
        target.as_mut().unwrap().blocked = false;
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(target.as_ref().unwrap().sent.last(), Some(&from_source));
        assert_eq!(source.confirmations, [true, true]);

        target
            .as_mut()
            .unwrap()
            .incoming
            .push_back(from_target.clone());
        source.blocked = true;
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(target.as_ref().unwrap().confirmations, 1);
        source.blocked = false;
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(source.sent.last(), Some(&from_target));
        assert_eq!(target.as_ref().unwrap().confirmations, 2);

        source
            .incoming
            .push_back(SourceUpdate::Event(credit.clone()));
        target.as_mut().unwrap().incoming.push_back(credit.clone());
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(target.as_ref().unwrap().sent.last(), Some(&credit));
        assert_eq!(source.sent.last(), Some(&credit));
        assert_eq!(source.confirmations.last(), Some(&false));

        source
            .incoming
            .push_back(SourceUpdate::Event(unbind.clone()));
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(target.as_ref().unwrap().sent.last(), Some(&unbind));
        target.as_mut().unwrap().incoming.push_back(unbind.clone());
        relay_once(&mut source, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(source.sent.last(), Some(&unbind));

        source.incoming.push_back(SourceUpdate::Closed);
        assert!(!relay_once(&mut source, &mut target, |_| unreachable!()).unwrap());
        assert!(source.incoming.is_empty());
        assert_eq!(source.confirmations.last(), Some(&false));
    }

    #[test]
    fn mptn_source_to_ee_session_pair_preserves_two_way_events_and_close() {
        let mut mptn = Source::default();
        let (ee_ingress, mut ee_source) = ee_session_bridge::pair();
        let mut target = None;
        let bind = SessionEvent::BindRequest(unit(0x31));
        mptn.incoming.push_back(SourceUpdate::Event(bind.clone()));
        let mut ee_ingress = Some(ee_ingress);
        relay_once(&mut mptn, &mut target, |_| Ok(ee_ingress.take().unwrap())).unwrap();
        assert_eq!(ee_source.poll().unwrap(), Some(SourceUpdate::Event(bind)));
        ee_source.complete_received(true).unwrap();

        let accepted = SessionEvent::BindResult {
            accepted: true,
            unit: unit(0xb1),
        };
        assert!(ee_source.send(&accepted).unwrap());
        relay_once(&mut mptn, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(mptn.sent.last(), Some(&accepted));

        let outbound = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(0xc9),
        };
        mptn.incoming
            .push_back(SourceUpdate::Event(outbound.clone()));
        relay_once(&mut mptn, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(
            ee_source.poll().unwrap(),
            Some(SourceUpdate::Event(outbound))
        );
        ee_source.complete_received(true).unwrap();

        let inbound = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(0xca),
        };
        assert!(ee_source.send(&inbound).unwrap());
        relay_once(&mut mptn, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(mptn.sent.last(), Some(&inbound));

        let credit = SessionEvent::Credit {
            normal: 2,
            expedited: 0,
        };
        mptn.incoming.push_back(SourceUpdate::Event(credit.clone()));
        relay_once(&mut mptn, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(ee_source.poll().unwrap(), Some(SourceUpdate::Event(credit)));
        assert_eq!(mptn.confirmations.last(), Some(&false));
        ee_source.complete_received(false).unwrap();

        let unbind = SessionEvent::Unbind(unit(0x32));
        mptn.incoming.push_back(SourceUpdate::Event(unbind.clone()));
        relay_once(&mut mptn, &mut target, |_| unreachable!()).unwrap();
        assert_eq!(ee_source.poll().unwrap(), Some(SourceUpdate::Event(unbind)));
        ee_source.complete_received(true).unwrap();
        ee_source.close().unwrap();
        assert_eq!(
            target.as_mut().unwrap().poll().unwrap(),
            Some(SessionEvent::Reset)
        );
        target.as_mut().unwrap().confirm_polled().unwrap();
        assert_eq!(target.as_mut().unwrap().poll().unwrap(), None);
    }
}
