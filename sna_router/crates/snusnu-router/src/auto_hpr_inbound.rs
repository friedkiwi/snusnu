//! Admission of an upstream LU session onto a live EE adjacency.
//!
//! The concentrator authenticates the source route. We still bind the open to
//! the current local LU export and the peer CP observed on this EE link before
//! handing the circuit to the HPR session switch.

use std::io;

use router_core::session::{QualifiedName, SessionIdentity};
use transport_ws::wire::{self, route_export::Resource};

use crate::remote::{AutoWsHub, SessionWsPort};

pub(crate) fn admit(
    hub: &mut AutoWsHub,
    open: wire::IncomingOpen,
    peer_cp: &QualifiedName,
) -> io::Result<Option<(SessionIdentity, SessionWsPort)>> {
    let local_route = open
        .target
        .as_ref()
        .and_then(|reference| hub.local_route(reference));
    let source_route = open
        .source_route
        .as_ref()
        .and_then(|reference| hub.remote_route(reference));
    let identity = match validate(
        &open,
        local_route,
        source_route.as_ref(),
        peer_cp,
        hub.allowed_netid(),
    ) {
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

fn validate(
    open: &wire::IncomingOpen,
    local_route: Option<&wire::RouteExport>,
    source_route: Option<&wire::RouteExport>,
    peer_cp: &QualifiedName,
    allowed_netid: &str,
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
    let local = match local_route.and_then(|route| route.resource.as_ref()) {
        Some(Resource::LogicalUnit(local)) => local,
        _ => return Err(wire::OpenFailure::RouteGone),
    };
    let target = local
        .lu
        .as_ref()
        .and_then(qualified)
        .filter(|lu| lu.netid == allowed_netid)
        .ok_or(wire::OpenFailure::RouteGone)?;
    if local.hosting_cp.as_ref().and_then(qualified).as_ref() != Some(peer_cp) {
        return Err(wire::OpenFailure::RouteGone);
    }
    if !local
        .supported_types
        .contains(&(wire::LuType::LuType62 as i32))
    {
        return Err(wire::OpenFailure::Unsupported);
    }
    let source = match source_route.and_then(|route| route.resource.as_ref()) {
        Some(Resource::LogicalUnit(source)) => source,
        _ => return Err(wire::OpenFailure::RouteGone),
    };
    let source_lu = source
        .lu
        .as_ref()
        .and_then(qualified)
        .ok_or(wire::OpenFailure::Protocol)?;
    if !source
        .supported_types
        .contains(&(wire::LuType::LuType62 as i32))
    {
        return Err(wire::OpenFailure::Unsupported);
    }
    let source_cp = source
        .hosting_cp
        .as_ref()
        .and_then(qualified)
        .ok_or(wire::OpenFailure::Protocol)?;
    SessionIdentity::new(source_lu, target)
        .with_control_points(Some(source_cp), Some(peer_cp.clone()))
        .map_err(|_| wire::OpenFailure::Protocol)
}

fn qualified(value: &wire::SnaName) -> Option<QualifiedName> {
    QualifiedName::new(&value.netid, &value.name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(netid: &str, name: &str) -> wire::SnaName {
        wire::SnaName {
            netid: netid.into(),
            name: name.into(),
        }
    }

    fn lu_route(lu: wire::SnaName, cp: wire::SnaName) -> wire::RouteExport {
        wire::RouteExport {
            id: 1,
            generation: 1,
            resource: Some(Resource::LogicalUnit(wire::LuReachability {
                lu: Some(lu),
                hosting_cp: Some(cp),
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
    fn binds_authenticated_source_to_current_ee_guest_lu() {
        let local_cp = QualifiedName::new("SOLNET", "SNAB").unwrap();
        let target = lu_route(name("SOLNET", "SNAB"), name("SOLNET", "SNAB"));
        let source = lu_route(name("OTHERNET", "CLIENT"), name("OTHERNET", "CP"));
        let identity =
            validate(&open(), Some(&target), Some(&source), &local_cp, "SOLNET").unwrap();
        assert_eq!(identity.source_lu.to_string(), "OTHERNET.CLIENT");
        assert_eq!(identity.target_lu.to_string(), "SOLNET.SNAB");
        assert_eq!(identity.target_cp, Some(local_cp));
    }

    #[test]
    fn rejects_stale_or_wrong_profile_and_peer_identity() {
        let local_cp = QualifiedName::new("SOLNET", "SNAB").unwrap();
        let target = lu_route(name("SOLNET", "SNAB"), name("SOLNET", "SNAB"));
        let source = lu_route(name("OTHERNET", "CLIENT"), name("OTHERNET", "CP"));
        let mut request = open();
        assert!(matches!(
            validate(&request, None, Some(&source), &local_cp, "SOLNET"),
            Err(wire::OpenFailure::RouteGone)
        ));
        request.profile = wire::CircuitProfile::NativeDlc as i32;
        assert!(matches!(
            validate(&request, Some(&target), Some(&source), &local_cp, "SOLNET"),
            Err(wire::OpenFailure::Unsupported)
        ));
        request.profile = wire::CircuitProfile::SessionV1 as i32;
        request.source_router_id = vec![4; 16];
        assert!(matches!(
            validate(&request, Some(&target), Some(&source), &local_cp, "SOLNET"),
            Err(wire::OpenFailure::Protocol)
        ));
        request.source_router_id = vec![2; 16];
        let wrong_cp = QualifiedName::new("SOLNET", "OTHER").unwrap();
        assert!(matches!(
            validate(&request, Some(&target), Some(&source), &wrong_cp, "SOLNET"),
            Err(wire::OpenFailure::RouteGone)
        ));
    }
}
