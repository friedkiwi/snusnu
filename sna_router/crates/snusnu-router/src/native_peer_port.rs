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
    fid2_bind::{classify_bind, BindClass},
    llc2::State,
    native_management::{ManagementSession, Phase as ManagementPhase},
    xid3::{Role, Xid3},
    xid3_activation::Phase,
};
use std::{io, time::Duration};

pub(crate) struct NativePeerPort {
    endpoint: Endpoint,
    type1: NativeType1,
    local_xid: Xid3,
    activation_announced: bool,
    reached_management_bind: bool,
    management: Option<ManagementSession>,
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
            reached_management_bind: false,
            management: None,
        })
    }

    pub(crate) fn open_management(
        peer: LlcPeer<'_>,
        local_xid: Xid3,
        remote_plu: String,
        local_slu: String,
    ) -> io::Result<Self> {
        let mut port = Self::open(peer, local_xid)?;
        port.management = Some(ManagementSession::new(remote_plu, local_slu));
        Ok(port)
    }

    pub(crate) fn management_complete(&self) -> bool {
        matches!(
            self.management.as_ref().map(ManagementSession::phase),
            Some(ManagementPhase::Closed)
        )
    }

    pub(crate) fn reached_management_bind(&self) -> bool {
        self.reached_management_bind
    }

    fn process(&mut self, events: Vec<Event>) -> io::Result<Vec<RouterEvent>> {
        if let Some(management) = self.management.as_mut() {
            let completed = self.endpoint.take_completed_information_count();
            match management.phase() {
                ManagementPhase::AwaitBindAck if completed != 0 => management
                    .acknowledge_bind(completed)
                    .map_err(management_error)?,
                ManagementPhase::AwaitCnosAck if completed != 0 => management
                    .acknowledge_attach_replies(completed)
                    .map_err(management_error)?,
                ManagementPhase::AwaitBisAck if completed != 0 => management
                    .acknowledge_bis(completed)
                    .map_err(management_error)?,
                ManagementPhase::AwaitUnbindAck if completed != 0 => management
                    .acknowledge_unbind(completed)
                    .map_err(management_error)?,
                _ if completed != 0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected native LLC completion",
                    ))
                }
                _ => {}
            }
            if let Some(attach) = management.take_early_attach() {
                if let Err(error) = self.process_management_piu(attach) {
                    self.endpoint.disconnect()?;
                    return Err(error);
                }
            }
        }
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
                    if self.management.is_some() {
                        if let Err(error) = self.process_management_piu(piu) {
                            self.endpoint.disconnect()?;
                            return Err(error);
                        }
                        continue;
                    }
                    let bind = match classify_bind(&piu) {
                        Ok(bind) => bind,
                        Err(error) => {
                            self.endpoint.disconnect()?;
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unsupported native BIND: {error}"),
                            ));
                        }
                    };
                    let Some(bind) = bind else {
                        self.endpoint.disconnect()?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "first native PIU is not a BIND",
                        ));
                    };
                    if !matches!(&bind.class, BindClass::Management { mode } if mode == "SNASVCMG")
                    {
                        self.endpoint.disconnect()?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "first native BIND is not SNASVCMG",
                        ));
                    }
                    self.reached_management_bind = true;
                    tracing::warn!(plu = %bind.plu, slu = %bind.slu, daf = bind.daf, oaf = bind.oaf, bytes = piu.len(), "native APPN SNASVCMG BIND reached XID-only port; responder unavailable, disconnecting");
                    self.endpoint.disconnect()?;
                }
                Event::Disconnected | Event::TimedOut => {
                    if self.management.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "native management probe lost LLC association",
                        ));
                    }
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

    fn process_management_piu(&mut self, piu: Vec<u8>) -> io::Result<()> {
        let management = self.management.as_mut().expect("management mode");
        if piu.len() >= 9 && piu[6] == 0x83 {
            management.observe_ipr(&piu).map_err(management_error)?;
            tracing::debug!("native management fixed pacing IPR accepted");
            return Ok(());
        }
        match management.phase() {
            ManagementPhase::AwaitBind => {
                let bind = management.observe_bind(&piu).map_err(management_error)?;
                let (daf, oaf) = bind.request_addresses();
                tracing::info!(
                    daf,
                    oaf,
                    bytes = piu.len(),
                    "native SNASVCMG BIND validated"
                );
                let response = management
                    .prepare_bind_response()
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(response.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIND response queue full",
                    ));
                }
                management
                    .mark_bind_enqueued(&response)
                    .map_err(management_error)?;
                self.reached_management_bind = true;
            }
            ManagementPhase::AwaitBindAck => management
                .buffer_early_attach(&piu)
                .map_err(management_error)?,
            ManagementPhase::AwaitAttach => {
                // Both responses must fit before pacing is consumed. If an
                // I/O error occurs after enqueue, this one-shot probe exits
                // and the entire LLC association is discarded.
                if self.endpoint.available_receive_slots() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native CNOS needs two LLC egress slots",
                    ));
                }
                let (ipr, cnos) = management.observe_attach(&piu).map_err(management_error)?;
                let (ipr, cnos) = (ipr.to_vec(), cnos.to_vec());
                for reply in [&ipr, &cnos] {
                    if !self.endpoint.queue_information(reply.clone())? {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "native CNOS response queue full",
                        ));
                    }
                }
                management
                    .mark_attach_replies_enqueued(&ipr, &cnos)
                    .map_err(management_error)?;
                tracing::info!(
                    "native CNOS accepted-pending response queued; no user route active"
                );
            }
            ManagementPhase::CnosComplete => {
                management
                    .observe_remote_bis(&piu)
                    .map_err(management_error)?;
                let local_bis = management
                    .prepare_local_bis(true)
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(local_bis.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native BIS egress queue full",
                    ));
                }
                management
                    .mark_local_bis_enqueued(&local_bis)
                    .map_err(management_error)?;
                tracing::info!(
                    "native bilateral BIS exchange queued; awaiting LLC acknowledgement"
                );
            }
            ManagementPhase::BisComplete => {
                if matches!(classify_bind(&piu), Ok(Some(_))) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "native user BIND gateway is not implemented",
                    ));
                }
                let response = management
                    .prepare_unbind_response(&piu)
                    .map_err(management_error)?
                    .to_vec();
                if !self.endpoint.queue_information(response.clone())? {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "native UNBIND response queue full",
                    ));
                }
                management
                    .mark_unbind_enqueued(&response)
                    .map_err(management_error)?;
                tracing::info!("native management UNBIND response queued; no user route active");
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported native management PIU",
                ))
            }
        }
        Ok(())
    }
}

fn management_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
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
        !self.reached_management_bind
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
