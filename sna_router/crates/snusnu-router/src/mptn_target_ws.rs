//! An incoming SessionV1 circuit terminating at a local TCP62 peer.
//!
//! The gateway lends UDP/397 exclusively for the circuit. The first BIND
//! starts an independent outbound TCP62 Connect; the owner releases the UDP
//! lease after this bridge is dropped on close or error.

use std::{
    io,
    net::UdpSocket,
    time::{Duration, Instant},
};

use router_core::session::{SessionEvent, SessionIdentity};

use crate::{
    auto_hpr_runtime::{from_session_wire, to_session_wire},
    hpr_local_mptn::HprToMptnSession,
    mptn_outbound_port::OutboundEndpoint,
    remote::{SessionWsPort, SessionWsUpdate},
};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn validate_identity(identity: &SessionIdentity, gateway_id: &str) -> io::Result<()> {
    if gateway_id.is_empty()
        || identity
            .source_cp
            .as_ref()
            .is_none_or(|cp| cp.netid != identity.source_lu.netid)
        || identity
            .target_cp
            .as_ref()
            .is_none_or(|cp| cp.netid != identity.target_lu.netid)
        || identity.source_lu == identity.target_lu
    {
        return Err(invalid("MPTN target SessionV1 identity is incomplete"));
    }
    Ok(())
}

pub(crate) struct MptnTargetWs {
    identity: SessionIdentity,
    ws: SessionWsPort,
    udp: Option<UdpSocket>,
    endpoint: OutboundEndpoint,
    session: Option<HprToMptnSession>,
    pending_ws: Option<(SessionEvent, bool)>,
    gateway_id: String,
    created_at: Instant,
}

impl MptnTargetWs {
    pub(crate) fn new(
        identity: SessionIdentity,
        ws: SessionWsPort,
        udp: UdpSocket,
        endpoint: OutboundEndpoint,
        gateway_id: String,
    ) -> io::Result<Self> {
        validate_identity(&identity, &gateway_id)?;
        Ok(Self {
            identity,
            ws,
            udp: Some(udp),
            endpoint,
            session: None,
            pending_ws: None,
            gateway_id,
            created_at: Instant::now(),
        })
    }

    pub(crate) fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// True while the circuit remains active. The caller removes the bridge
    /// and releases the selected gateway's UDP lease after false or error.
    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if self.session.is_none() && self.created_at.elapsed() > Duration::from_secs(120) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "incoming MPTN SessionV1 BIND timed out",
            ));
        }
        if self.pending_ws.is_none() {
            match self.ws.poll()? {
                Some(SessionWsUpdate::Event(wire)) => {
                    let event = from_session_wire(wire)?;
                    let charged = !matches!(event, SessionEvent::Credit { .. });
                    self.pending_ws = Some((event, charged));
                }
                Some(SessionWsUpdate::Closed) => {
                    self.close()?;
                    return Ok(false);
                }
                Some(SessionWsUpdate::Opened) | None => {}
            }
        }
        if self.session.is_none() {
            if let Some((SessionEvent::BindRequest(bind), _)) = self.pending_ws.as_ref() {
                let udp = self
                    .udp
                    .take()
                    .ok_or_else(|| invalid("MPTN target UDP lease is absent"))?;
                self.session = Some(HprToMptnSession::new(
                    self.endpoint,
                    udp,
                    &self.identity,
                    bind,
                    Duration::from_secs(600),
                )?);
            } else if self.pending_ws.is_some() {
                return Err(invalid("MPTN target SessionV1 did not start with BIND"));
            }
        }
        if let (Some(session), Some((event, charged))) =
            (self.session.as_mut(), self.pending_ws.as_ref())
        {
            if session.send(event)? {
                if *charged {
                    self.ws.complete_received(1)?;
                }
                self.pending_ws = None;
            }
        }
        if let Some(session) = self.session.as_mut() {
            if let Some(event) = session.poll()? {
                let Some(wire) = to_session_wire(&event) else {
                    self.close()?;
                    return Ok(false);
                };
                if self.ws.send(wire)? {
                    session.confirm_polled()?;
                }
            }
        }
        let _ = self.ws.take_completed_send_count();
        Ok(true)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        if let Some(session) = self.session.as_mut() {
            session.close();
        }
        self.udp.take();
        self.ws.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::session::QualifiedName;

    #[test]
    fn target_requires_distinct_lus_and_matching_hosting_cp_netids() {
        let source_lu = QualifiedName::new("BOBNET", "CLIENT").unwrap();
        let target_lu = QualifiedName::new("ALICENET", "SERVER").unwrap();
        let source_cp = QualifiedName::new("BOBNET", "BOBCP").unwrap();
        let target_cp = QualifiedName::new("ALICENET", "ALICECP").unwrap();
        let identity = SessionIdentity::new(source_lu, target_lu)
            .with_control_points(Some(source_cp), Some(target_cp))
            .unwrap();
        assert!(validate_identity(&identity, "gateway").is_ok());
        assert!(validate_identity(&identity, "").is_err());
        let wrong_target = SessionIdentity::new(
            QualifiedName::new("BOBNET", "CLIENT").unwrap(),
            QualifiedName::new("BOBNET", "CLIENT").unwrap(),
        )
        .with_control_points(
            Some(QualifiedName::new("BOBNET", "BOBCP").unwrap()),
            Some(QualifiedName::new("BOBNET", "BOBCP").unwrap()),
        )
        .unwrap();
        assert!(validate_identity(&wrong_target, "gateway").is_err());
    }
}
