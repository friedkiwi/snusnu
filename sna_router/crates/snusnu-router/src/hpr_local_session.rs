//! One selected local carrier destination for an HPR user session.
//!
//! The caller retains ownership of the MPTN gateway's exclusive UDP lease.
//! It must call `release_udp` on the named gateway whenever this session is
//! removed, including after an error or reset.

use crate::{
    hpr_local_llc::HprToLlcSession, hpr_local_mptn::HprToMptnSession,
    session_switch::ee_bridge::EeBridgeIngress,
};
use router_core::session::SessionEvent;
use std::io;

pub(crate) enum HprLocalSession {
    Llc(Box<HprToLlcSession>),
    Ee(EeBridgeIngress),
    Mptn {
        session: Box<HprToMptnSession>,
        gateway_id: String,
    },
}

impl HprLocalSession {
    pub(crate) fn mptn_gateway_id(&self) -> Option<&str> {
        match self {
            Self::Llc(_) | Self::Ee(_) => None,
            Self::Mptn { gateway_id, .. } => Some(gateway_id),
        }
    }

    pub(crate) fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        match self {
            Self::Llc(session) => session.send(event),
            Self::Ee(session) => session.send(event),
            Self::Mptn { session, .. } => session.send(event),
        }
    }

    pub(crate) fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
        match self {
            Self::Llc(session) => session.poll(),
            Self::Ee(session) => session.poll(),
            Self::Mptn { session, .. } => session.poll(),
        }
    }

    pub(crate) fn confirm_polled(&mut self) -> io::Result<()> {
        match self {
            Self::Llc(session) => session.confirm_polled(),
            Self::Ee(session) => session.confirm_polled(),
            Self::Mptn { session, .. } => session.confirm_polled(),
        }
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        match self {
            Self::Llc(session) => session.close(),
            Self::Ee(session) => session.close(),
            Self::Mptn { session, .. } => {
                session.close();
                Ok(())
            }
        }
    }
}
