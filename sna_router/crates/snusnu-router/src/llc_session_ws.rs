//! One authenticated SessionV1 circuit terminating at a local LLC peer.
//!
//! The owner must lease the attachment exclusively before constructing this
//! bridge. A fresh XID and management exchange uses the source CP published
//! for this circuit; no previous EE adjacency proof is borrowed.

use std::{
    io,
    time::{Duration, Instant},
};

use router_core::session::{QualifiedName, SessionEvent, SessionIdentity};
use router_core::{
    native_management::Phase as ResponderPhase,
    native_management_initiator::Phase as ManagementPhase,
};

use crate::{
    auto_hpr_runtime::{from_session_wire, to_session_wire},
    hpr_local_llc::{HprToLlcProbe, HprToLlcSession},
    native_peer_port::NativePeerPort,
    remote::{AutoWsHub, SessionWsPort, SessionWsUpdate},
    routing::RoutePort,
    runtime::LlcPeer,
};
use transport_ws::wire::{self, route_export::Resource};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const PENDING_EVENT_TIMEOUT: Duration = Duration::from_secs(60);

fn expired(now: Instant, opened_at: Instant, bound: bool, pending_since: Option<Instant>) -> bool {
    (!bound && now.duration_since(opened_at) >= SETUP_TIMEOUT)
        || pending_since.is_some_and(|since| now.duration_since(since) >= PENDING_EVENT_TIMEOUT)
}

fn control_points(identity: &SessionIdentity) -> io::Result<(&QualifiedName, &QualifiedName)> {
    let source = identity
        .source_cp
        .as_ref()
        .ok_or_else(|| invalid("SessionV1 source CP is unavailable"))?;
    let target = identity
        .target_cp
        .as_ref()
        .ok_or_else(|| invalid("SessionV1 target CP is unavailable"))?;
    if source.netid != identity.source_lu.netid || target.netid != identity.target_lu.netid {
        return Err(invalid("SessionV1 LU and hosting CP NETIDs disagree"));
    }
    Ok((source, target))
}

/// Admit only a current LU 6.2 route whose published hosting CP is the CP
/// verified on this LLC attachment. The source reference is resolved from the
/// authenticated concentrator directory, not from fields in a BIND payload.
pub(crate) fn admit(
    hub: &mut AutoWsHub,
    open: wire::IncomingOpen,
    target_lu: &QualifiedName,
    verified_target_cp: &QualifiedName,
) -> io::Result<Option<(SessionIdentity, SessionWsPort)>> {
    let local = open.target.as_ref().and_then(|r| hub.local_route(r));
    let remote = open.source_route.as_ref().and_then(|r| hub.remote_route(r));
    let identity = match validate_open(&open, local, remote.as_ref(), target_lu, verified_target_cp)
    {
        Ok(identity) => identity,
        Err(reason) => {
            hub.reject_incoming(&open, reason)?;
            return Ok(None);
        }
    };
    let Some(port) = hub.accept_session_incoming(open)? else {
        return Ok(None);
    };
    Ok(Some((identity, port)))
}

fn validate_open(
    open: &wire::IncomingOpen,
    local: Option<&wire::RouteExport>,
    remote: Option<&wire::RouteExport>,
    target_lu: &QualifiedName,
    verified_target_cp: &QualifiedName,
) -> Result<SessionIdentity, wire::OpenFailure> {
    if open.profile != wire::CircuitProfile::SessionV1 as i32 {
        return Err(wire::OpenFailure::Unsupported);
    }
    if open.circuit_id.len() != 16
        || open.source_router_id.len() != 16
        || open
            .source_route
            .as_ref()
            .is_none_or(|route| route.router_id != open.source_router_id)
    {
        return Err(wire::OpenFailure::Protocol);
    }
    let Some(Resource::LogicalUnit(target)) = local.and_then(|route| route.resource.as_ref())
    else {
        return Err(wire::OpenFailure::RouteGone);
    };
    if target.lu.as_ref().and_then(qualified).as_ref() != Some(target_lu)
        || target.hosting_cp.as_ref().and_then(qualified).as_ref() != Some(verified_target_cp)
    {
        return Err(wire::OpenFailure::RouteGone);
    }
    if !target
        .supported_types
        .contains(&(wire::LuType::LuType62 as i32))
    {
        return Err(wire::OpenFailure::Unsupported);
    }
    let Some(Resource::LogicalUnit(source)) = remote.and_then(|route| route.resource.as_ref())
    else {
        return Err(wire::OpenFailure::RouteGone);
    };
    if !source
        .supported_types
        .contains(&(wire::LuType::LuType62 as i32))
    {
        return Err(wire::OpenFailure::Unsupported);
    }
    let source_lu = source
        .lu
        .as_ref()
        .and_then(qualified)
        .ok_or(wire::OpenFailure::Protocol)?;
    let source_cp = source
        .hosting_cp
        .as_ref()
        .and_then(qualified)
        .ok_or(wire::OpenFailure::Protocol)?;
    SessionIdentity::new(source_lu, target_lu.clone())
        .with_control_points(Some(source_cp), Some(verified_target_cp.clone()))
        .map_err(|_| wire::OpenFailure::Protocol)
}

fn qualified(value: &wire::SnaName) -> Option<QualifiedName> {
    QualifiedName::new(&value.netid, &value.name).ok()
}

/// An incoming concentrator LU circuit and its private LLC association.
/// `pump` returns false after circuit closure; the owner then releases its
/// exclusive attachment lease and may restart its ordinary discovery probe.
pub(crate) struct LlcSessionWs {
    identity: SessionIdentity,
    attachment_id: String,
    ws: SessionWsPort,
    probe: Option<HprToLlcProbe>,
    session: Option<HprToLlcSession>,
    verified_native: Option<NativePeerPort>,
    reverse_session: Option<HprToLlcSession<NativePeerPort>>,
    pending_ws: Option<(SessionEvent, bool)>,
    pending_since: Option<Instant>,
    opened_at: Instant,
    bound: bool,
    verified: bool,
    log_session: Option<u64>,
    log_carrier: Option<u64>,
    last_management: Option<(Option<ManagementPhase>, Option<ResponderPhase>)>,
}

impl LlcSessionWs {
    pub(crate) fn new(
        identity: SessionIdentity,
        ws: SessionWsPort,
        attachment_id: String,
        peer: LlcPeer<'_>,
        adjacent_cp: &QualifiedName,
        seed: &[u8],
    ) -> io::Result<Self> {
        let (source_cp, target_cp) = control_points(&identity)?;
        let probe =
            HprToLlcProbe::new_with_management(peer, adjacent_cp, target_cp, source_cp, seed)?;
        Ok(Self {
            identity,
            attachment_id,
            ws,
            probe: Some(probe),
            session: None,
            verified_native: None,
            reverse_session: None,
            pending_ws: None,
            pending_since: None,
            opened_at: Instant::now(),
            bound: false,
            verified: false,
            log_session: None,
            log_carrier: None,
            last_management: None,
        })
    }

    pub(crate) fn new_from_verified(
        identity: SessionIdentity,
        ws: SessionWsPort,
        attachment_id: String,
        native: NativePeerPort,
    ) -> Self {
        Self {
            identity,
            attachment_id,
            ws,
            probe: None,
            session: None,
            verified_native: Some(native),
            reverse_session: None,
            pending_ws: None,
            pending_since: None,
            opened_at: Instant::now(),
            bound: false,
            verified: true,
            log_session: None,
            log_carrier: None,
            last_management: None,
        }
    }

    pub(crate) fn with_log_context(mut self, session: u64, carrier: Option<u64>) -> Self {
        self.log_session = Some(session);
        self.log_carrier = carrier;
        self
    }

    pub(crate) fn attachment_id(&self) -> &str {
        &self.attachment_id
    }

    pub(crate) fn verified_target_cp(&self) -> Option<&QualifiedName> {
        self.verified
            .then_some(self.identity.target_cp.as_ref())
            .flatten()
    }

    pub(crate) fn uses_live_adjacency(&self) -> bool {
        self.verified_native.is_some() || self.reverse_session.is_some()
    }

    /// Advance at most one received and one transmitted session event. The
    /// incoming unit remains leased until native LLC accepts it; native output
    /// remains leased until the WebSocket queues it.
    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if expired(
            Instant::now(),
            self.opened_at,
            self.bound,
            self.pending_since,
        ) {
            tracing::warn!(attachment = %self.attachment_id,
                source_lu = %self.identity.source_lu,
                target_lu = %self.identity.target_lu,
                bound = self.bound, pending = self.pending_ws.is_some(),
                "SessionV1 LLC setup or pending event timed out");
            if !self.uses_live_adjacency() {
                self.close()?;
            }
            return Ok(false);
        }
        if self.pending_ws.is_none() {
            match self.ws.poll()? {
                Some(SessionWsUpdate::Event(wire)) => {
                    let event = from_session_wire(wire)?;
                    if matches!(event, SessionEvent::BindRequest(_)) {
                        tracing::info!(attachment = %self.attachment_id,
                            session = ?self.log_session, carrier = ?self.log_carrier,
                            source_lu = %self.identity.source_lu,
                            target_lu = %self.identity.target_lu,
                            "incoming LLC SessionV1 BIND received");
                    }
                    let charged = !matches!(event, SessionEvent::Credit { .. });
                    self.pending_ws = Some((event, charged));
                    self.pending_since = Some(Instant::now());
                }
                Some(SessionWsUpdate::Closed) => {
                    if !self.uses_live_adjacency() {
                        self.close()?;
                    }
                    return Ok(false);
                }
                Some(SessionWsUpdate::Opened) | None => {}
            }
        } else if self.ws.poll_control()? {
            if !self.uses_live_adjacency() {
                self.close()?;
            }
            return Ok(false);
        }

        if let Some(probe) = self.probe.as_mut() {
            probe.pump()?;
            self.verified = probe.verified_target_cp().is_some();
        }
        if self.session.is_none() && self.reverse_session.is_none() {
            if let Some((SessionEvent::BindRequest(bind), _)) = self.pending_ws.as_ref() {
                if let Some(native) = self.verified_native.take() {
                    self.reverse_session = Some(HprToLlcSession::from_verified_port(
                        native,
                        self.identity
                            .source_cp
                            .as_ref()
                            .ok_or_else(|| invalid("verified LLC source CP missing"))?,
                        self.identity
                            .target_cp
                            .as_ref()
                            .ok_or_else(|| invalid("verified LLC target CP missing"))?,
                        &self.identity.source_lu,
                        &self.identity.target_lu,
                        bind,
                    )?);
                    tracing::info!(attachment = %self.attachment_id,
                        session = ?self.log_session, carrier = ?self.log_carrier,
                        "reverse LLC session attached to verified adjacency");
                } else if self
                    .probe
                    .as_ref()
                    .and_then(HprToLlcProbe::verified_target_cp)
                    .is_some()
                {
                    let session = self.probe.take().unwrap().into_session(
                        &self.identity.source_lu,
                        &self.identity.target_lu,
                        bind,
                    )?;
                    self.session = Some(session);
                }
            } else if self.pending_ws.is_some() {
                return Err(invalid("SessionV1 LLC circuit did not start with BIND"));
            }
        }

        if let Some((event, charged)) = self.pending_ws.as_ref() {
            let accepted = if let Some(session) = self.reverse_session.as_mut() {
                session.send(event)?
            } else if let Some(session) = self.session.as_mut() {
                session.send(event)?
            } else {
                false
            };
            if accepted {
                if matches!(event, SessionEvent::BindRequest(_)) {
                    tracing::info!(attachment = %self.attachment_id,
                        session = ?self.log_session, carrier = ?self.log_carrier,
                        "reverse LLC user BIND queued after management exchange");
                }
                if *charged {
                    self.ws.complete_received(1)?;
                }
                self.pending_ws = None;
                self.pending_since = None;
            }
        }

        if self.session.is_some() || self.reverse_session.is_some() {
            let event = if let Some(session) = self.reverse_session.as_mut() {
                session.poll()?
            } else {
                self.session.as_mut().unwrap().poll()?
            };
            if let Some(session) = self.reverse_session.as_ref() {
                let phases = session.management_phases();
                if self.last_management != Some(phases) {
                    tracing::info!(attachment = %self.attachment_id,
                        session = ?self.log_session, carrier = ?self.log_carrier,
                        initiator = ?phases.0, reciprocal = ?phases.1,
                        "reverse LLC management state changed");
                    self.last_management = Some(phases);
                }
            }
            if let Some(event) = event {
                let Some(wire) = to_session_wire(&event) else {
                    if !self.uses_live_adjacency() {
                        self.close()?;
                    }
                    return Ok(false);
                };
                if self.ws.send(wire)? {
                    if let Some(session) = self.reverse_session.as_mut() {
                        session.confirm_polled()?;
                    } else {
                        self.session.as_mut().unwrap().confirm_polled()?;
                    }
                    if let SessionEvent::BindResult { accepted, .. } = event {
                        tracing::info!(attachment = %self.attachment_id,
                            session = ?self.log_session, carrier = ?self.log_carrier,
                            accepted, "reverse LLC user BIND result sent upstream");
                        if accepted {
                            self.bound = true;
                        } else {
                            if !self.uses_live_adjacency() {
                                self.close()?;
                            }
                            return Ok(false);
                        }
                    }
                }
            }
        }
        let _ = self.ws.take_completed_send_count();
        if self
            .reverse_session
            .as_ref()
            .is_some_and(HprToLlcSession::verified_user_closed)
            && self.pending_ws.is_none()
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn into_live_adjacency(mut self) -> io::Result<NativePeerPort> {
        let native = if let Some(native) = self.verified_native.take() {
            native
        } else {
            self.reverse_session
                .take()
                .ok_or_else(|| invalid("LLC circuit has no live native association"))?
                .into_verified_port()?
        };
        self.ws.close()?;
        Ok(native)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        if let Some(session) = self.session.as_mut() {
            session.close()?;
        }
        if let Some(session) = self.reverse_session.as_mut() {
            session.close()?;
        }
        if let Some(native) = self.verified_native.as_mut() {
            native.disconnect()?;
        }
        if let Some(probe) = self.probe.as_mut() {
            probe.close()?;
        }
        self.ws.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport_ws::wire::route_export::Resource;

    fn q(name: &str) -> QualifiedName {
        name.parse().unwrap()
    }

    #[test]
    fn requires_authenticated_hosting_cp_for_each_lu() {
        let mut identity = SessionIdentity::new(q("BOBNET.BOB"), q("SOLNET.SNAA"));
        assert!(control_points(&identity).is_err());
        identity.source_cp = Some(q("BOBNET.CP"));
        identity.target_cp = Some(q("SOLNET.SNAA"));
        assert!(control_points(&identity).is_ok());
        identity.source_cp = Some(q("OTHER.CP"));
        assert!(control_points(&identity).is_err());
    }

    fn name(value: &str) -> wire::SnaName {
        let (netid, name) = value.split_once('.').unwrap();
        wire::SnaName {
            netid: netid.into(),
            name: name.into(),
        }
    }

    fn route(lu: &str, cp: &str) -> wire::RouteExport {
        wire::RouteExport {
            id: 1,
            generation: 1,
            resource: Some(Resource::LogicalUnit(wire::LuReachability {
                lu: Some(name(lu)),
                hosting_cp: Some(name(cp)),
                supported_types: vec![wire::LuType::LuType62 as i32],
            })),
        }
    }

    fn open() -> wire::IncomingOpen {
        wire::IncomingOpen {
            circuit_id: vec![1; 16],
            source_router_id: vec![2; 16],
            target: None,
            source_receive_allowance_bytes: 1024,
            source_route: Some(wire::RouteReference {
                router_id: vec![2; 16],
                epoch: vec![3; 16],
                route_id: 1,
                route_generation: 1,
            }),
            profile: wire::CircuitProfile::SessionV1 as i32,
        }
    }

    #[test]
    fn admits_cross_netid_source_only_for_verified_local_lu_and_cp() {
        let target = route("SOLNET.SNAA", "SOLNET.SNAA");
        let source = route("BOBNET.BOB", "BOBNET.CP");
        let identity = validate_open(
            &open(),
            Some(&target),
            Some(&source),
            &q("SOLNET.SNAA"),
            &q("SOLNET.SNAA"),
        )
        .unwrap();
        assert_eq!(identity.source_lu, q("BOBNET.BOB"));
        assert_eq!(control_points(&identity).unwrap().0, &q("BOBNET.CP"));
        assert_eq!(identity.target_cp, Some(q("SOLNET.SNAA")));
        assert!(matches!(
            validate_open(
                &open(),
                Some(&target),
                Some(&source),
                &q("SOLNET.SNAA"),
                &q("SOLNET.OTHER"),
            ),
            Err(wire::OpenFailure::RouteGone)
        ));
    }

    #[test]
    fn setup_and_pending_leases_have_bounded_lifetimes() {
        let opened = Instant::now();
        assert!(!expired(
            opened + SETUP_TIMEOUT - Duration::from_millis(1),
            opened,
            false,
            None
        ));
        assert!(expired(opened + SETUP_TIMEOUT, opened, false, None));
        assert!(!expired(opened + SETUP_TIMEOUT * 2, opened, true, None));
        let pending = opened + Duration::from_secs(5);
        assert!(!expired(
            pending + PENDING_EVENT_TIMEOUT - Duration::from_millis(1),
            opened,
            true,
            Some(pending)
        ));
        assert!(expired(
            pending + PENDING_EVENT_TIMEOUT,
            opened,
            true,
            Some(pending)
        ));
    }
}
