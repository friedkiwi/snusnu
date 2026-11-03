//! LU ownership shared by HPR, WebSocket, LLC and MPTN session adapters.
//!
//! Each attachment replaces its own snapshot. Removing a disconnected
//! attachment withdraws its learned LUs without disturbing other carriers.
//! An LU exported by more than one owner is ambiguous and cannot be routed.

use std::{
    collections::{HashMap, HashSet},
    io,
};

use router_core::{
    route_registry::{AttachmentId, OwnerId, OwnerVersion, RouteKey, RouteOrigin, RouteRegistry},
    session::QualifiedName,
};

use crate::config::RouterConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateCarrier {
    Llc,
    Mptn,
    Ee,
}

/// A configured name is a hint, not an active route. The carrier adapter must
/// verify its adjacent CP before inserting it into the live directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfiguredCandidate {
    pub(crate) lu: QualifiedName,
    pub(crate) cp_hint: Option<QualifiedName>,
    pub(crate) attachment_id: String,
    pub(crate) carrier: CandidateCarrier,
}

impl ConfiguredCandidate {
    /// The name hint becomes reachable only after this attachment has proved
    /// its CP in XID or the corresponding MPTN management exchange.
    pub(crate) fn verify_cp(
        &self,
        observed_cp: &QualifiedName,
    ) -> Option<(QualifiedName, Destination)> {
        if self.lu.netid != observed_cp.netid
            || self
                .cp_hint
                .as_ref()
                .is_some_and(|expected| expected != observed_cp)
        {
            return None;
        }
        let hosting_cp = observed_cp.clone();
        let attachment_id = self.attachment_id.clone();
        let destination = match self.carrier {
            CandidateCarrier::Llc => Destination::Llc {
                hosting_cp,
                attachment_id,
            },
            CandidateCarrier::Mptn => Destination::Mptn {
                hosting_cp,
                attachment_id,
            },
            CandidateCarrier::Ee => Destination::Ee {
                hosting_cp,
                attachment_id,
            },
        };
        Some((self.lu.clone(), destination))
    }
}

pub(crate) fn configured_candidates(config: &RouterConfig) -> io::Result<Vec<ConfiguredCandidate>> {
    let mut candidates = Vec::new();
    for attachment in &config.llc {
        let cp_hint = attachment.local_cp.as_deref().map(parse_name).transpose()?;
        for lu in &attachment.lus {
            candidates.push(ConfiguredCandidate {
                lu: parse_name(lu)?,
                cp_hint: cp_hint.clone(),
                attachment_id: attachment.id.clone(),
                carrier: CandidateCarrier::Llc,
            });
        }
    }
    for attachment in &config.mptn_gateway {
        if !attachment.destination_lu.is_empty() {
            candidates.push(ConfiguredCandidate {
                lu: parse_name(&attachment.destination_lu)?,
                cp_hint: (!attachment.peer_cp.is_empty())
                    .then(|| parse_name(&attachment.peer_cp))
                    .transpose()?,
                attachment_id: attachment.id.clone(),
                carrier: CandidateCarrier::Mptn,
            });
        }
    }
    for attachment in &config.ee {
        for lu in &attachment.peer_lus {
            candidates.push(ConfiguredCandidate {
                lu: parse_name(lu)?,
                cp_hint: None,
                attachment_id: attachment.id.clone(),
                carrier: CandidateCarrier::Ee,
            });
        }
    }
    Ok(candidates)
}

fn parse_name(name: &str) -> io::Result<QualifiedName> {
    name.parse()
        .map_err(|_| invalid("invalid configured SNA name"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Destination {
    Ws {
        hosting_cp: QualifiedName,
        attachment_id: String,
    },
    Llc {
        hosting_cp: QualifiedName,
        attachment_id: String,
    },
    Mptn {
        hosting_cp: QualifiedName,
        attachment_id: String,
    },
    Ee {
        hosting_cp: QualifiedName,
        attachment_id: String,
    },
}

impl Destination {
    pub(crate) fn hosting_cp(&self) -> &QualifiedName {
        match self {
            Self::Ws { hosting_cp, .. }
            | Self::Llc { hosting_cp, .. }
            | Self::Mptn { hosting_cp, .. }
            | Self::Ee { hosting_cp, .. } => hosting_cp,
        }
    }

    pub(crate) fn attachment_id(&self) -> &str {
        match self {
            Self::Ws { attachment_id, .. }
            | Self::Llc { attachment_id, .. }
            | Self::Mptn { attachment_id, .. }
            | Self::Ee { attachment_id, .. } => attachment_id,
        }
    }
}

#[derive(Default)]
pub(crate) struct HprDestinationDirectory {
    registry: RouteRegistry,
    members: HashMap<String, HashSet<OwnerId>>,
    destinations: HashMap<OwnerId, HashMap<QualifiedName, Destination>>,
    revisions: HashMap<OwnerId, u64>,
}

impl HprDestinationDirectory {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Validate a complete replacement before mutating the existing owner.
    /// Refreshes can therefore never leave a partially applied route list.
    pub(crate) fn replace_owner(
        &mut self,
        owner: &str,
        routes: impl IntoIterator<Item = (QualifiedName, Destination)>,
    ) -> io::Result<()> {
        if owner.is_empty() {
            return Err(invalid("empty route owner"));
        }
        let mut snapshot = HashMap::new();
        for (lu, destination) in routes {
            if destination.attachment_id().is_empty() {
                return Err(invalid("empty destination attachment ID"));
            }
            if snapshot.insert(lu, destination).is_some() {
                return Err(invalid("duplicate LU in one attachment snapshot"));
            }
        }
        let mut grouped = HashMap::<OwnerId, HashMap<QualifiedName, Destination>>::new();
        for (lu, destination) in snapshot {
            let scoped = scoped_owner(owner, destination.attachment_id())?;
            grouped.entry(scoped).or_default().insert(lu, destination);
        }
        let old_members = self.members.get(owner).cloned().unwrap_or_default();
        let new_members = grouped.keys().cloned().collect::<HashSet<_>>();
        let mut next_registry = self.registry.clone();
        let mut next_revisions = self.revisions.clone();
        for member in old_members.difference(&new_members) {
            let revision = next_revision(&mut next_revisions, member)?;
            let old = self
                .destinations
                .get(member)
                .ok_or_else(|| invalid("missing HPR route owner"))?;
            let origin = old
                .values()
                .next()
                .map(route_origin)
                .ok_or_else(|| invalid("empty HPR route owner"))?;
            next_registry
                .withdraw_owner(
                    member,
                    origin,
                    OwnerVersion::new(1, revision).map_err(registry_error)?,
                )
                .map_err(registry_error)?;
        }
        for (member, destinations) in &grouped {
            let first = destinations
                .values()
                .next()
                .ok_or_else(|| invalid("empty HPR route owner"))?;
            let origin = route_origin(first);
            if destinations.values().any(|destination| {
                route_origin(destination) != origin
                    || destination.attachment_id() != first.attachment_id()
            }) {
                return Err(invalid("mixed HPR route owner"));
            }
            let keys = destinations
                .iter()
                .map(|(lu, destination)| RouteKey::LogicalUnit {
                    lu: lu.clone(),
                    hosting_cp: destination.hosting_cp().clone(),
                })
                .collect();
            let revision = next_revision(&mut next_revisions, member)?;
            next_registry
                .replace_owner(
                    member.clone(),
                    AttachmentId::new(first.attachment_id()).map_err(registry_error)?,
                    origin,
                    OwnerVersion::new(1, revision).map_err(registry_error)?,
                    keys,
                )
                .map_err(registry_error)?;
        }
        self.registry = next_registry;
        self.revisions = next_revisions;
        for member in old_members {
            self.destinations.remove(&member);
        }
        for (member, destinations) in grouped {
            self.destinations.insert(member, destinations);
        }
        if new_members.is_empty() {
            self.members.remove(owner);
        } else {
            self.members.insert(owner.to_owned(), new_members);
        }
        Ok(())
    }

    pub(crate) fn withdraw_owner(&mut self, owner: &str) -> io::Result<()> {
        self.replace_owner(owner, [])
    }

    /// Return one unambiguous route. Two owners advertising the same LU fail
    /// closed even when their CP names happen to match.
    pub(crate) fn resolve_lu(&self, lu: &QualifiedName) -> Option<Destination> {
        let selected = self.registry.resolve_lu(lu, None, None).ok()?;
        self.destinations.get(&selected.owner)?.get(lu).cloned()
    }

    /// Only unambiguous, verified routes are eligible for publication. A
    /// duplicate LU is omitted until one owner withdraws it.
    pub(crate) fn routes(&self) -> Vec<(QualifiedName, Destination)> {
        let mut seen = HashSet::new();
        let mut routes = self
            .registry
            .entries()
            .into_iter()
            .filter_map(|entry| {
                let RouteKey::LogicalUnit { lu, .. } = entry.key else {
                    return None;
                };
                seen.insert(lu.clone())
                    .then(|| self.resolve_lu(&lu).map(|destination| (lu, destination)))
                    .flatten()
            })
            .collect::<Vec<_>>();
        routes.sort_by(|(a, _), (b, _)| (&a.netid, &a.name).cmp(&(&b.netid, &b.name)));
        routes
    }
}

fn scoped_owner(owner: &str, attachment: &str) -> io::Result<OwnerId> {
    OwnerId::new(format!("hpr:{}:{owner}:{attachment}", owner.len())).map_err(registry_error)
}

fn next_revision(revisions: &mut HashMap<OwnerId, u64>, owner: &OwnerId) -> io::Result<u64> {
    let revision = revisions
        .get(owner)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| invalid("HPR route revision exhausted"))?;
    revisions.insert(owner.clone(), revision);
    Ok(revision)
}

fn route_origin(destination: &Destination) -> RouteOrigin {
    match destination {
        Destination::Ws { .. } => RouteOrigin::Upstream,
        Destination::Llc { .. } | Destination::Mptn { .. } | Destination::Ee { .. } => {
            RouteOrigin::Local
        }
    }
}

fn registry_error(error: router_core::route_registry::RegistryError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn llc(id: &str) -> Destination {
        Destination::Llc {
            hosting_cp: name("SOLNET.SNAA"),
            attachment_id: id.to_owned(),
        }
    }

    #[test]
    fn replaces_and_withdraws_only_one_attachments_routes() {
        let mut directory = HprDestinationDirectory::new();
        let ping = name("SOLNET.PING");
        let printer = name("SOLNET.PRINTER");
        directory
            .replace_owner("llc-a", [(ping.clone(), llc("llc-a"))])
            .unwrap();
        directory
            .replace_owner("llc-b", [(printer.clone(), llc("llc-b"))])
            .unwrap();
        assert_eq!(directory.resolve_lu(&ping), Some(llc("llc-a")));
        directory.replace_owner("llc-a", []).unwrap();
        assert!(directory.resolve_lu(&ping).is_none());
        assert_eq!(directory.resolve_lu(&printer), Some(llc("llc-b")));
    }

    #[test]
    fn one_carrier_snapshot_preserves_other_attachment_and_retires_old_lease() {
        let mut directory = HprDestinationDirectory::new();
        let a = name("SOLNET.PING");
        let b = name("SOLNET.PRINTER");
        directory
            .replace_owner(
                "llc",
                [(a.clone(), llc("lan-a")), (b.clone(), llc("lan-b"))],
            )
            .unwrap();
        let lease = directory.registry.resolve_lu(&b, None, None).unwrap().lease;
        directory
            .replace_owner("llc", [(a.clone(), llc("lan-a"))])
            .unwrap();
        assert_eq!(directory.resolve_lu(&a), Some(llc("lan-a")));
        assert!(directory.resolve_lu(&b).is_none());
        assert!(!directory.registry.validate_lease(&lease));
        directory
            .replace_owner("llc", [(a, llc("lan-a")), (b.clone(), llc("lan-b"))])
            .unwrap();
        assert_eq!(directory.resolve_lu(&b), Some(llc("lan-b")));
        assert!(!directory.registry.validate_lease(&lease));
    }

    #[test]
    fn ambiguous_lu_fails_closed_and_recovers_when_owner_withdraws() {
        let mut directory = HprDestinationDirectory::new();
        let lu = name("SOLNET.SNAA");
        directory
            .replace_owner("llc-a", [(lu.clone(), llc("llc-a"))])
            .unwrap();
        directory
            .replace_owner("llc-b", [(lu.clone(), llc("llc-b"))])
            .unwrap();
        assert!(directory.resolve_lu(&lu).is_none());
        assert!(directory.routes().is_empty());
        directory.withdraw_owner("llc-b").unwrap();
        assert_eq!(directory.resolve_lu(&lu), Some(llc("llc-a")));
        assert_eq!(directory.routes(), vec![(lu, llc("llc-a"))]);
    }

    #[test]
    fn invalid_refresh_keeps_previous_snapshot() {
        let mut directory = HprDestinationDirectory::new();
        let lu = name("SOLNET.SNAA");
        directory
            .replace_owner("llc-a", [(lu.clone(), llc("llc-a"))])
            .unwrap();
        assert!(directory
            .replace_owner(
                "llc-a",
                [(lu.clone(), llc("llc-a")), (lu.clone(), llc("llc-a"))],
            )
            .is_err());
        assert_eq!(directory.resolve_lu(&lu), Some(llc("llc-a")));
    }

    #[test]
    fn static_hints_do_not_become_routes_without_peer_proof() {
        let config: RouterConfig = toml::from_str(
            "[[llc]]\nid='lan'\ninterface='eth0'\nguest_mac='02:00:00:00:00:01'\nlocal_cp='SOLNET.SNAA'\nlus=['SOLNET.SNAA']\n[[hpr_ip]]\nid='ee'\nlocal_ip='192.0.2.1'\npeer_ip='192.0.2.2'\npeer_lus=['QAALICE.APP1']\n",
        )
        .unwrap();
        let hints = configured_candidates(&config).unwrap();
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].carrier, CandidateCarrier::Llc);
        assert_eq!(hints[0].cp_hint, Some(name("SOLNET.SNAA")));
        assert_eq!(hints[1].carrier, CandidateCarrier::Ee);
        assert_eq!(hints[1].cp_hint, None);
        let directory = HprDestinationDirectory::new();
        assert!(directory.resolve_lu(&name("SOLNET.SNAA")).is_none());
        assert!(directory.resolve_lu(&name("QAALICE.APP1")).is_none());
        assert_eq!(
            hints[0].verify_cp(&name("SOLNET.SNAA")),
            Some((name("SOLNET.SNAA"), llc("lan")))
        );
        assert!(hints[0].verify_cp(&name("SOLNET.OTHER")).is_none());
        assert!(hints[1].verify_cp(&name("SOLNET.SNAB")).is_none());
        assert!(matches!(
            hints[1].verify_cp(&name("QAALICE.SNAB")),
            Some((lu, Destination::Ee { .. })) if lu == name("QAALICE.APP1")
        ));
    }
}
