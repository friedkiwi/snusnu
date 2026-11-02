//! Verified local LLC identities for the automatic LLC/WebSocket bridge.
//!
//! The listener knows a guest MAC before it knows an SNA identity. An XID3
//! supplied by that guest establishes the CP; a later native session parser
//! establishes each LU. Only those observations can be announced upstream.

use crate::{
    config::parse_cp,
    remote::{AutoWsHub, WsRoutePort},
    routing::PortId,
};
use router_core::xid3::Xid3;
use std::{
    collections::{HashMap, HashSet},
    io,
};
use transport_ws::wire;

#[derive(Clone)]
struct LocalLlcIdentity {
    interface: String,
    guest_mac: [u8; 6],
    cp: Option<wire::SnaName>,
    lus: HashSet<(String, String)>,
}

/// The local side of automatic LLC-to-WebSocket routing. The upstream
/// directory remains owned by the WebSocket adapter and is never copied into
/// local exports.
#[derive(Default)]
pub(crate) struct AutoLlcWsBridge {
    local: HashMap<PortId, LocalLlcIdentity>,
}

#[derive(Clone, Debug)]
pub(crate) struct IncomingLlcSelection {
    pub(crate) attachment: PortId,
    pub(crate) interface: String,
    pub(crate) guest_mac: [u8; 6],
    pub(crate) proxy_mac: [u8; 6],
}

impl AutoLlcWsBridge {
    pub(crate) fn register(
        &mut self,
        id: PortId,
        interface: String,
        guest_mac: [u8; 6],
    ) -> io::Result<()> {
        if self.local.contains_key(&id)
            || self
                .local
                .values()
                .any(|entry| entry.interface == interface && entry.guest_mac == guest_mac)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "duplicate local LLC attachment",
            ));
        }
        self.local.insert(
            id,
            LocalLlcIdentity {
                interface,
                guest_mac,
                cp: None,
                lus: HashSet::new(),
            },
        );
        Ok(())
    }

    pub(crate) fn withdraw(&mut self, id: &PortId) {
        self.local.remove(id);
    }

    /// Call only for Type1 units received through the private LLC endpoint
    /// for this attachment. It has already checked the guest MAC and proxy.
    pub(crate) fn observe_type1(&mut self, id: &PortId, pdu: &[u8]) -> io::Result<bool> {
        if pdu.len() < 4 || pdu[2] & !0x10 != 0xaf || pdu[3] != 0x32 {
            return Ok(false);
        }
        let xid = Xid3::decode(&pdu[3..]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid guest XID3: {error}"),
            )
        })?;
        let cp = xid.cp_name().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guest XID3 has no valid CP: {error}"),
            )
        })?;
        self.observe_cp(id, &cp)
    }

    /// An observed CP is accepted only from the registered local attachment.
    /// A changed CP withdraws all LUs learned under the old CP.
    pub(crate) fn observe_cp(&mut self, id: &PortId, name: &str) -> io::Result<bool> {
        let cp = parse_cp(name)?;
        let local = self
            .local
            .get_mut(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LLC attachment is absent"))?;
        if local.cp.as_ref() == Some(&cp) {
            return Ok(false);
        }
        if let Some(previous) = &local.cp {
            tracing::warn!(attachment = %id.0,
                old_cp = %format_name(previous), new_cp = %format_name(&cp),
                "guest LLC CP changed; withdrawing previously observed LUs");
        }
        local.cp = Some(cp);
        local.lus.clear();
        Ok(true)
    }

    /// Call only after a native BIND has established the LU on this guest's
    /// private association. A CP name alone never implies an LU export.
    pub(crate) fn observe_bound_lu(&mut self, id: &PortId, name: &str) -> io::Result<bool> {
        let lu = parse_cp(name)?;
        let local = self
            .local
            .get_mut(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LLC attachment is absent"))?;
        let cp = local.cp.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LLC CP has not been observed",
            )
        })?;
        if lu.netid != cp.netid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "LU {} is outside observed CP NETID {}",
                    format_name(&lu),
                    cp.netid
                ),
            ));
        }
        Ok(local.lus.insert((lu.netid, lu.name)))
    }

    pub(crate) fn advertisements(
        &self,
        allowed_netid: &str,
    ) -> io::Result<(Vec<wire::SnaName>, Vec<wire::LuReachability>)> {
        let mut cps = Vec::new();
        let mut lus = Vec::new();
        let mut cp_names = HashSet::new();
        let mut lu_names = HashSet::new();
        for (id, local) in &self.local {
            let Some(cp) = &local.cp else { continue };
            if cp.netid != allowed_netid {
                tracing::warn!(attachment = %id.0, observed_cp = %format_name(cp),
                    assigned_netid = allowed_netid,
                    "local LLC identity excluded from upstream announcement: NETID mismatch");
                continue;
            }
            if !cp_names.insert((cp.netid.clone(), cp.name.clone())) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "local CP {} is observed on multiple LLC attachments",
                        format_name(cp)
                    ),
                ));
            }
            cps.push(cp.clone());
            for (netid, name) in &local.lus {
                if !lu_names.insert((netid.clone(), name.clone())) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("local LU {netid}.{name} is observed on multiple LLC attachments"),
                    ));
                }
                lus.push(wire::LuReachability {
                    lu: Some(wire::SnaName {
                        netid: netid.clone(),
                        name: name.clone(),
                    }),
                    hosting_cp: Some(cp.clone()),
                    supported_types: Vec::new(),
                });
            }
        }
        cps.sort_by(|a, b| (&a.netid, &a.name).cmp(&(&b.netid, &b.name)));
        lus.sort_by(|a, b| {
            let a = a.lu.as_ref().expect("constructed LU");
            let b = b.lu.as_ref().expect("constructed LU");
            (&a.netid, &a.name).cmp(&(&b.netid, &b.name))
        });
        Ok((cps, lus))
    }

    /// Publish only identities actually observed on local LLC attachments.
    /// The hub applies the server-assigned NETID boundary as a second check.
    pub(crate) fn publish_verified(&self, hub: &mut AutoWsHub) -> io::Result<()> {
        let (cps, lus) = self.advertisements(hub.allowed_netid())?;
        hub.publish_local(&cps, &lus)
    }

    /// Select one current upstream CP for the managed proxy MAC contacted by
    /// this LLC guest. The guest CP must have been seen in a valid XID3 and
    /// published in this concentrator epoch before a circuit can be opened.
    pub(crate) fn open_managed_cp(
        &self,
        hub: &mut AutoWsHub,
        attachment: &PortId,
        proxy_mac: [u8; 6],
    ) -> io::Result<WsRoutePort> {
        let local_cp = self
            .local
            .get(attachment)
            .and_then(|entry| entry.cp.as_ref())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "LLC guest CP has not been observed",
                )
            })?
            .clone();
        let source = hub.local_reference_cp(&local_cp).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "observed LLC CP {} is not published",
                    format_name(&local_cp)
                ),
            )
        })?;
        let (target, target_cp) = hub.resolve_mac(&proxy_mac)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "managed proxy MAC {} has no live upstream route",
                    format_mac(proxy_mac)
                ),
            )
        })?;
        hub.open_ref(target, target_cp, None, Some(source), local_cp)
    }

    /// Resolve a concentrator-initiated CP/LU circuit to one local LLC guest
    /// and the managed source MAC that guest recognizes as its remote peer.
    /// The caller reserves that proxy MAC on the listener before opening the
    /// private outbound LLC endpoint and accepting the incoming circuit.
    pub(crate) fn incoming_selection(
        &self,
        hub: &AutoWsHub,
        open: &wire::IncomingOpen,
    ) -> io::Result<IncomingLlcSelection> {
        let target_ref = open.target.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "incoming circuit has no target")
        })?;
        let target = hub.local_route(target_ref).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "incoming target is not published locally",
            )
        })?;
        let attachment =
            self.select_local_resource(target.resource.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incoming target has no SNA resource",
                )
            })?)?;
        let source_ref = open.source_route.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "incoming circuit has no source")
        })?;
        if source_ref.router_id != open.source_router_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incoming source router ID differs from source route",
            ));
        }
        let source = hub.remote_route(source_ref).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "incoming source route is not current",
            )
        })?;
        let source_cp = match source.resource.as_ref() {
            Some(wire::route_export::Resource::ControlPoint(cp)) => cp,
            Some(wire::route_export::Resource::LogicalUnit(lu)) => {
                lu.hosting_cp.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "incoming LU source has no hosting CP",
                    )
                })?
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incoming source route has no SNA resource",
                ))
            }
        };
        let proxy_mac = hub.managed_mac_for_cp(source_cp)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "incoming source CP {} has no managed proxy MAC",
                    format_name(source_cp)
                ),
            )
        })?;
        let local = self
            .local
            .get(&attachment)
            .expect("selected registered attachment");
        Ok(IncomingLlcSelection {
            attachment,
            interface: local.interface.clone(),
            guest_mac: local.guest_mac,
            proxy_mac,
        })
    }

    pub(crate) fn select_local_resource(
        &self,
        resource: &wire::route_export::Resource,
    ) -> io::Result<PortId> {
        match resource {
            wire::route_export::Resource::ControlPoint(cp) => self.select_cp(cp),
            wire::route_export::Resource::LogicalUnit(lu) => {
                let name = lu.lu.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "LU target has no name")
                })?;
                let attachment = self.select_lu(name)?;
                if let Some(host) = &lu.hosting_cp {
                    if self.select_cp(host)? != attachment {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "LU target hosting CP belongs to another local attachment",
                        ));
                    }
                }
                Ok(attachment)
            }
        }
    }

    pub(crate) fn select_cp(&self, cp: &wire::SnaName) -> io::Result<PortId> {
        self.select(|local| local.cp.as_ref() == Some(cp), &format_name(cp))
    }

    pub(crate) fn select_lu(&self, lu: &wire::SnaName) -> io::Result<PortId> {
        self.select(
            |local| local.lus.contains(&(lu.netid.clone(), lu.name.clone())),
            &format_name(lu),
        )
    }

    fn select(
        &self,
        matches: impl Fn(&LocalLlcIdentity) -> bool,
        identity: &str,
    ) -> io::Result<PortId> {
        let mut found = self
            .local
            .iter()
            .filter_map(|(id, local)| matches(local).then_some(id));
        let first = found.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("local LLC identity {identity} is not observed"),
            )
        })?;
        if found.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("local LLC identity {identity} is ambiguous"),
            ));
        }
        Ok(first.clone())
    }
}

fn format_name(name: &wire::SnaName) -> String {
    format!("{}.{}", name.netid, name.name)
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_only_observed_local_names_in_assigned_netid() {
        let mut bridge = AutoLlcWsBridge::default();
        let alice = PortId::new("alice");
        let bob = PortId::new("bob");
        bridge
            .register(alice.clone(), "tap0".into(), [2, 0, 0, 0, 0, 1])
            .unwrap();
        bridge
            .register(bob.clone(), "tap1".into(), [2, 0, 0, 0, 0, 2])
            .unwrap();
        assert_eq!(bridge.advertisements("NETA").unwrap().0.len(), 0);
        assert_eq!(
            bridge
                .observe_bound_lu(&alice, "NETA.LUA")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        bridge.observe_cp(&alice, "NETA.CPA").unwrap();
        bridge.observe_bound_lu(&alice, "NETA.LUA").unwrap();
        bridge.observe_cp(&bob, "NETB.CPB").unwrap();
        bridge.observe_bound_lu(&bob, "NETB.LUB").unwrap();
        let (cps, lus) = bridge.advertisements("NETA").unwrap();
        assert_eq!(cps, vec![parse_cp("NETA.CPA").unwrap()]);
        assert_eq!(lus.len(), 1);
        assert_eq!(lus[0].lu, Some(parse_cp("NETA.LUA").unwrap()));
        assert_eq!(lus[0].hosting_cp, Some(parse_cp("NETA.CPA").unwrap()));
        assert_eq!(
            bridge.select_cp(&parse_cp("NETB.CPB").unwrap()).unwrap(),
            bob
        );
        assert_eq!(
            bridge.select_lu(&parse_cp("NETA.LUA").unwrap()).unwrap(),
            alice
        );
    }

    #[test]
    fn changing_cp_withdraws_old_lu_and_duplicate_names_are_rejected() {
        let mut bridge = AutoLlcWsBridge::default();
        let a = PortId::new("a");
        let b = PortId::new("b");
        bridge
            .register(a.clone(), "tap0".into(), [2, 0, 0, 0, 0, 1])
            .unwrap();
        bridge
            .register(b.clone(), "tap0".into(), [2, 0, 0, 0, 0, 2])
            .unwrap();
        bridge.observe_cp(&a, "NETA.CPA").unwrap();
        bridge.observe_bound_lu(&a, "NETA.LUA").unwrap();
        assert_eq!(
            bridge.observe_bound_lu(&a, "NETB.LUB").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        bridge.observe_cp(&a, "NETA.CPX").unwrap();
        assert_eq!(
            bridge
                .select_lu(&parse_cp("NETA.LUA").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        bridge.observe_cp(&b, "NETA.CPX").unwrap();
        assert_eq!(
            bridge.advertisements("NETA").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            bridge
                .select_cp(&parse_cp("NETA.CPX").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn incoming_lu_must_belong_to_its_observed_hosting_cp() {
        let mut bridge = AutoLlcWsBridge::default();
        let alice = PortId::new("alice");
        let bob = PortId::new("bob");
        bridge
            .register(alice.clone(), "tap0".into(), [2, 0, 0, 0, 0, 1])
            .unwrap();
        bridge
            .register(bob.clone(), "tap1".into(), [2, 0, 0, 0, 0, 2])
            .unwrap();
        bridge.observe_cp(&alice, "NETA.CPA").unwrap();
        bridge.observe_bound_lu(&alice, "NETA.LUA").unwrap();
        bridge.observe_cp(&bob, "NETA.CPB").unwrap();
        let resource = wire::route_export::Resource::LogicalUnit(wire::LuReachability {
            lu: Some(parse_cp("NETA.LUA").unwrap()),
            hosting_cp: Some(parse_cp("NETA.CPA").unwrap()),
            supported_types: Vec::new(),
        });
        assert_eq!(bridge.select_local_resource(&resource).unwrap(), alice);
        let wrong_host = wire::route_export::Resource::LogicalUnit(wire::LuReachability {
            lu: Some(parse_cp("NETA.LUA").unwrap()),
            hosting_cp: Some(parse_cp("NETA.CPB").unwrap()),
            supported_types: Vec::new(),
        });
        assert_eq!(
            bridge
                .select_local_resource(&wrong_host)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
