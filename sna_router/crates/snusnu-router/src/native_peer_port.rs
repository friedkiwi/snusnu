//! Experimental native APPN LLC port, currently bounded to link activation.
//!
//! It answers TEST/XID with a caller-provided local XID3 profile and permits
//! SABME only after the XID role exchange completes. It deliberately closes
//! on the first SNA information PIU: a positive management BIND response
//! needs session parameter negotiation that is not yet implemented. This
//! port never emits `RouterEvent::Ready` and cannot carry routed user data.

use crate::{
    endpoint::{Endpoint, Event},
    native_type1::NativeType1,
    routing::{RoutePort, RoutedUnit, RouterEvent},
    runtime::LlcPeer,
};
use router_core::{
    llc2::State,
    xid3::{Role, Xid3},
    xid3_activation::Phase,
};
use std::{io, time::Duration};

pub(crate) struct NativePeerPort {
    endpoint: Endpoint,
    type1: NativeType1,
    local_xid: Xid3,
    activation_announced: bool,
    reached_information: bool,
}

impl NativePeerPort {
    pub(crate) fn open(peer: LlcPeer<'_>, local_xid: Xid3) -> io::Result<Self> {
        let type1 = NativeType1::new(local_xid.clone())?;
        let mut endpoint = Endpoint::open(peer.interface, peer.guest_mac, peer.proxy_mac)?;
        endpoint.set_connect_allowed(false)?;
        tracing::info!(
            interface = peer.interface,
            local_cp = %local_xid.cp_name().map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            "native APPN XID-only port opened"
        );
        Ok(Self {
            endpoint,
            type1,
            local_xid,
            activation_announced: false,
            reached_information: false,
        })
    }

    pub(crate) fn reached_information(&self) -> bool {
        self.reached_information
    }

    fn process(&mut self, events: Vec<Event>) -> io::Result<Vec<RouterEvent>> {
        for event in events {
            match event {
                Event::Type1(pdu) => {
                    if let Some(outbound) = self.type1.on_pdu(&pdu)? {
                        self.endpoint.send_type1(&outbound.pdu)?;
                        if self.type1.confirm_sent(&outbound)? == Phase::ReadyForSabme
                            && !self.activation_announced
                        {
                            self.endpoint.set_connect_allowed(true)?;
                            if self.type1.local_role() == Role::Primary {
                                // Let any crossed final XID command/response
                                // settle before the primary sets LLC2 mode.
                                self.endpoint.begin_connect_after(Duration::from_millis(50));
                            }
                            self.activation_announced = true;
                            tracing::info!(peer_cp = ?self.type1.peer_name(), local_role = ?self.type1.local_role(), "APPN XID3 negotiation complete; SABME permitted");
                        }
                    }
                }
                Event::Connected => {
                    if self.type1.phase() != Phase::ReadyForSabme {
                        self.endpoint.disconnect()?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "LLC2 contact before APPN XID3 completion",
                        ));
                    }
                    tracing::info!(peer_cp = ?self.type1.peer_name(), "native APPN LLC2 contact established; awaiting management BIND");
                }
                Event::Information(piu) => {
                    self.reached_information = true;
                    let ru = piu.get(9).copied();
                    tracing::warn!(bytes = piu.len(), ru_code = ?ru, "native APPN PIU reached XID-only port; management BIND responder unavailable, disconnecting");
                    self.endpoint.disconnect()?;
                }
                Event::Disconnected | Event::TimedOut => {
                    if self.endpoint.state() == State::Disconnected {
                        self.endpoint.set_connect_allowed(false)?;
                        self.type1 = NativeType1::new(self.local_xid.clone())?;
                        self.activation_announced = false;
                    }
                }
            }
        }
        // The native port is not ready for user traffic until management
        // BIND/CNOS and a gateway session are implemented.
        Ok(Vec::new())
    }
}

impl RoutePort for NativePeerPort {
    fn poll(&mut self, _: bool) -> io::Result<Option<Vec<RouterEvent>>> {
        self.endpoint
            .poll(true)?
            .map(|events| self.process(events))
            .transpose()
    }

    fn tick(&mut self) -> io::Result<Vec<RouterEvent>> {
        let events = self.endpoint.tick()?;
        self.process(events)
    }

    fn send(&mut self, _: RoutedUnit) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native APPN session gateway is not implemented",
        ))
    }

    fn has_capacity(&self) -> bool {
        !self.reached_information
    }

    fn set_ingress_busy(&mut self, busy: bool) -> io::Result<()> {
        self.endpoint.set_local_busy(busy)
    }

    fn on_peer_ready(&mut self) -> io::Result<()> {
        // The remote route has no bearing on the local XID exchange.
        Ok(())
    }

    fn disconnect(&mut self) -> io::Result<()> {
        self.endpoint.disconnect()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.endpoint.flush()
    }
}
