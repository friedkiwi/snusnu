//! One authenticated SessionV1 circuit terminating at a local LLC peer.
//!
//! The owner must lease the attachment exclusively before constructing this
//! bridge. A fresh XID and management exchange uses the source CP published
//! for this circuit; no previous EE adjacency proof is borrowed.

use std::io;

use router_core::session::{QualifiedName, SessionEvent, SessionIdentity};

use crate::{
    auto_hpr_runtime::{from_session_wire, to_session_wire},
    hpr_local_llc::{HprToLlcProbe, HprToLlcSession},
    remote::{AutoWsHub, SessionWsPort, SessionWsUpdate},
    runtime::LlcPeer,
};
use transport_ws::wire::{self, route_export::Resource};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
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
    pending_ws: Option<(SessionEvent, bool)>,
    verified: bool,
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
            pending_ws: None,
            verified: false,
        })
    }

    pub(crate) fn attachment_id(&self) -> &str {
        &self.attachment_id
    }

    pub(crate) fn verified_target_cp(&self) -> Option<&QualifiedName> {
        self.verified
            .then_some(self.identity.target_cp.as_ref())
            .flatten()
    }

    /// Advance at most one received and one transmitted session event. The
    /// incoming unit remains leased until native LLC accepts it; native output
    /// remains leased until the WebSocket queues it.
    pub(crate) fn pump(&mut self) -> io::Result<bool> {
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

        if let Some(probe) = self.probe.as_mut() {
            probe.pump()?;
            self.verified = probe.verified_target_cp().is_some();
        }
        if self.session.is_none() {
            if let Some((SessionEvent::BindRequest(bind), _)) = self.pending_ws.as_ref() {
                if self
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
            session.close()?;
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
}
