//! Carrier-independent reachability learned by attachment adapters.
//!
//! Adapters validate their own wire protocols and publish complete snapshots.
//! The registry selects a next hop; a selected adapter still owns its wire
//! route reference, session setup, and transport lifetime.

use std::collections::{HashMap, HashSet};

use crate::session::QualifiedName;

const DEFAULT_MAX_OWNERS: usize = 4096;
const MAX_ROUTES_PER_OWNER: usize = 4096;

/// A stable discovery-proof slot, reused with an increasing generation.
/// Callers must not create a fresh owner ID for every short-lived circuit.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OwnerId(String);

impl OwnerId {
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(RegistryError::InvalidOwner);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An attachment is the next hop selected for a new session. Several live
/// discovery proofs may name the same attachment and must not revoke each
/// other when one association ends.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AttachmentId(String);

impl AttachmentId {
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(RegistryError::InvalidAttachment);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An adapter generation changes when its peer association is replaced.
/// Revision increases for every snapshot or withdrawal within that generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OwnerVersion {
    pub generation: u64,
    pub revision: u64,
}

impl OwnerVersion {
    pub fn new(generation: u64, revision: u64) -> Result<Self, RegistryError> {
        if generation == 0 || revision == 0 {
            return Err(RegistryError::InvalidVersion);
        }
        Ok(Self {
            generation,
            revision,
        })
    }

    fn validate(self) -> Result<(), RegistryError> {
        Self::new(self.generation, self.revision).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOrigin {
    Local,
    Upstream,
}

/// SNA identities and LLC address aliases are kept distinct. A MAC alias
/// selects an attachment, but never becomes a CP or LU advertisement.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RouteKey {
    ControlPoint(QualifiedName),
    LogicalUnit {
        lu: QualifiedName,
        hosting_cp: QualifiedName,
    },
    ProxyMac([u8; 6]),
}

/// SNA LU session protocols. The WebSocket adapter maps these to its wire
/// enum; the registry does not depend on a particular concentrator protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LuType {
    Lu0,
    Lu1,
    Lu2,
    Lu3,
    Lu4,
    Lu61,
    Lu62,
    Lu7,
}

/// Reachability metadata belongs to a proof, not to the route identity key.
/// An empty LU type list means that no session capability has been verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRecord {
    pub key: RouteKey,
    pub supported_types: Vec<LuType>,
}

impl From<RouteKey> for RouteRecord {
    fn from(key: RouteKey) -> Self {
        Self {
            key,
            supported_types: Vec::new(),
        }
    }
}

impl RouteRecord {
    fn validate(&self) -> Result<(), RegistryError> {
        self.key.validate()?;
        if !matches!(&self.key, RouteKey::LogicalUnit { .. }) && !self.supported_types.is_empty() {
            return Err(RegistryError::InvalidRoute);
        }
        Ok(())
    }

    fn canonicalize(&mut self) {
        self.supported_types.sort_unstable();
        self.supported_types.dedup();
    }
}

impl RouteKey {
    fn validate(&self) -> Result<(), RegistryError> {
        match self {
            Self::ControlPoint(cp) => validate_name(cp),
            Self::LogicalUnit { lu, hosting_cp } => {
                validate_name(lu)?;
                validate_name(hosting_cp)?;
                if lu.netid != hosting_cp.netid {
                    return Err(RegistryError::InvalidRoute);
                }
                Ok(())
            }
            Self::ProxyMac(mac) if mac == &[0; 6] || mac[0] & 1 != 0 => {
                Err(RegistryError::InvalidRoute)
            }
            Self::ProxyMac(_) => Ok(()),
        }
    }
}

fn validate_name(name: &QualifiedName) -> Result<(), RegistryError> {
    QualifiedName::new(name.netid.clone(), name.name.clone())
        .map(|_| ())
        .map_err(|_| RegistryError::InvalidRoute)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    InvalidOwner,
    InvalidAttachment,
    InvalidVersion,
    InvalidRoute,
    DuplicateRoute,
    StaleUpdate,
    OriginChanged,
    NoRoute,
    AmbiguousRoute,
    Capacity,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RegistryError {}

/// A route incarnation survives an unchanged snapshot refresh. Withdrawal,
/// replacement, or a new peer generation invalidates it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteLease {
    pub owner: OwnerId,
    pub key: RouteKey,
    pub incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSelection {
    pub owner: OwnerId,
    pub attachment: AttachmentId,
    pub origin: RouteOrigin,
    pub key: RouteKey,
    pub supported_types: Vec<LuType>,
    pub owner_version: OwnerVersion,
    pub lease: RouteLease,
}

#[derive(Clone, Debug)]
struct OwnedRoute {
    key: RouteKey,
    supported_types: Vec<LuType>,
    incarnation: u64,
}

#[derive(Clone, Debug)]
struct OwnerState {
    attachment: AttachmentId,
    origin: RouteOrigin,
    version: OwnerVersion,
    routes: Vec<OwnedRoute>,
}

/// The sole authority for attachment reachability and new-session next hops.
/// Closed sessions and carrier protocol state remain with their adapters.
pub struct RouteRegistry {
    owners: HashMap<OwnerId, OwnerState>,
    // Tombstones must outlive withdrawal so delayed adapter events cannot
    // recreate routes with an old attachment generation or revision.
    last_versions: HashMap<OwnerId, (RouteOrigin, OwnerVersion)>,
    next_incarnation: u64,
    max_owners: usize,
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteRegistry {
    pub fn new() -> Self {
        Self::with_max_owners(DEFAULT_MAX_OWNERS).expect("default registry capacity is nonzero")
    }

    pub fn with_max_owners(max_owners: usize) -> Result<Self, RegistryError> {
        if max_owners == 0 {
            return Err(RegistryError::Capacity);
        }
        Ok(Self {
            owners: HashMap::new(),
            last_versions: HashMap::new(),
            next_incarnation: 1,
            max_owners,
        })
    }

    /// Validate an entire replacement before changing any live route.
    pub fn replace_owner(
        &mut self,
        owner: OwnerId,
        attachment: AttachmentId,
        origin: RouteOrigin,
        version: OwnerVersion,
        routes: Vec<RouteKey>,
    ) -> Result<(), RegistryError> {
        self.replace_records(
            owner,
            attachment,
            origin,
            version,
            routes.into_iter().map(RouteRecord::from).collect(),
        )
    }

    /// Replace reachability with LU capability metadata. A metadata change
    /// retires the old route lease even if its CP/LU key is unchanged.
    pub fn replace_records(
        &mut self,
        owner: OwnerId,
        attachment: AttachmentId,
        origin: RouteOrigin,
        version: OwnerVersion,
        mut routes: Vec<RouteRecord>,
    ) -> Result<(), RegistryError> {
        self.check_update(&owner, origin, version)?;
        if routes.len() > MAX_ROUTES_PER_OWNER {
            return Err(RegistryError::Capacity);
        }
        let mut distinct = HashSet::new();
        for route in &mut routes {
            route.validate()?;
            route.canonicalize();
            if !distinct.insert(route.key.clone()) {
                return Err(RegistryError::DuplicateRoute);
            }
        }

        let previous = self.owners.get(&owner);
        let same_generation = previous.is_some_and(|state| {
            state.version.generation == version.generation && state.origin == origin
        });
        let mut next_incarnation = self.next_incarnation;
        let mut snapshot = Vec::with_capacity(routes.len());
        for record in routes {
            let RouteRecord {
                key,
                supported_types,
            } = record;
            let incarnation = if same_generation {
                previous
                    .and_then(|state| {
                        state.routes.iter().find(|route| {
                            route.key == key && route.supported_types == supported_types
                        })
                    })
                    .map(|route| route.incarnation)
            } else {
                None
            };
            let incarnation = match incarnation {
                Some(value) => value,
                None => {
                    let value = next_incarnation;
                    next_incarnation = next_incarnation
                        .checked_add(1)
                        .ok_or(RegistryError::Capacity)?;
                    value
                }
            };
            snapshot.push(OwnedRoute {
                key,
                supported_types,
                incarnation,
            });
        }
        self.owners.insert(
            owner.clone(),
            OwnerState {
                attachment,
                origin,
                version,
                routes: snapshot,
            },
        );
        self.last_versions.insert(owner, (origin, version));
        self.next_incarnation = next_incarnation;
        Ok(())
    }

    /// A withdrawal records a tombstone even when no snapshot is currently
    /// installed. Reappearance requires a newer version.
    pub fn withdraw_owner(
        &mut self,
        owner: &OwnerId,
        origin: RouteOrigin,
        version: OwnerVersion,
    ) -> Result<(), RegistryError> {
        self.check_update(owner, origin, version)?;
        self.owners.remove(owner);
        self.last_versions.insert(owner.clone(), (origin, version));
        Ok(())
    }

    fn check_update(
        &self,
        owner: &OwnerId,
        origin: RouteOrigin,
        version: OwnerVersion,
    ) -> Result<(), RegistryError> {
        version.validate()?;
        if !self.last_versions.contains_key(owner) && self.last_versions.len() >= self.max_owners {
            return Err(RegistryError::Capacity);
        }
        if let Some((previous_origin, previous_version)) = self.last_versions.get(owner) {
            if *previous_origin != origin {
                return Err(RegistryError::OriginChanged);
            }
            if version <= *previous_version {
                return Err(RegistryError::StaleUpdate);
            }
        }
        Ok(())
    }

    pub fn resolve_lu(
        &self,
        lu: &QualifiedName,
        target_cp: Option<&QualifiedName>,
        ingress: Option<&AttachmentId>,
    ) -> Result<RouteSelection, RegistryError> {
        let exact = self.select(ingress, |key| {
            matches!(key, RouteKey::LogicalUnit { lu: route_lu, hosting_cp }
                if route_lu == lu && target_cp.is_none_or(|cp| cp == hosting_cp))
        });
        if !matches!(exact, Err(RegistryError::NoRoute)) {
            return exact;
        }
        let Some(target_cp) = target_cp else {
            return Err(RegistryError::NoRoute);
        };
        self.resolve_cp(target_cp, ingress)
    }

    pub fn resolve_cp(
        &self,
        cp: &QualifiedName,
        ingress: Option<&AttachmentId>,
    ) -> Result<RouteSelection, RegistryError> {
        self.select(
            ingress,
            |key| matches!(key, RouteKey::ControlPoint(route_cp) if route_cp == cp),
        )
    }

    pub fn resolve_mac(
        &self,
        mac: [u8; 6],
        ingress: Option<&AttachmentId>,
    ) -> Result<RouteSelection, RegistryError> {
        self.select(
            ingress,
            |key| matches!(key, RouteKey::ProxyMac(route_mac) if route_mac == &mac),
        )
    }

    fn select(
        &self,
        ingress: Option<&AttachmentId>,
        matches: impl Fn(&RouteKey) -> bool,
    ) -> Result<RouteSelection, RegistryError> {
        let mut selected: Option<RouteSelection> = None;
        for (owner, state) in &self.owners {
            if ingress == Some(&state.attachment) {
                continue;
            }
            for route in &state.routes {
                if !matches(&route.key) {
                    continue;
                }
                if let Some(first) = &selected {
                    if first.attachment != state.attachment
                        || first.origin != state.origin
                        || first.key != route.key
                        || first.supported_types != route.supported_types
                    {
                        return Err(RegistryError::AmbiguousRoute);
                    }
                    if first.owner.as_str() <= owner.as_str() {
                        continue;
                    }
                }
                selected = Some(selection(owner, state, route));
            }
        }
        selected.ok_or(RegistryError::NoRoute)
    }

    pub fn validate_lease(&self, lease: &RouteLease) -> bool {
        self.owners.get(&lease.owner).is_some_and(|state| {
            state
                .routes
                .iter()
                .any(|route| route.key == lease.key && route.incarnation == lease.incarnation)
        })
    }

    /// A locally owned CP or LU may be advertised only in the assigned NETID.
    /// Collisions with any other owner are omitted rather than published.
    pub fn local_exports(&self, netid: &str) -> Vec<RouteSelection> {
        let mut identities = HashMap::<
            PublicationIdentity,
            Option<(AttachmentId, RouteKey, RouteOrigin, Vec<LuType>)>,
        >::new();
        for state in self.owners.values() {
            for route in &state.routes {
                if let Some(identity) = PublicationIdentity::from_key(&route.key) {
                    let signature = (
                        state.attachment.clone(),
                        route.key.clone(),
                        state.origin,
                        route.supported_types.clone(),
                    );
                    identities
                        .entry(identity)
                        .and_modify(|current| {
                            if current.as_ref() != Some(&signature) {
                                *current = None;
                            }
                        })
                        .or_insert(Some(signature));
                }
            }
        }
        let mut exports = Vec::new();
        for (owner, state) in &self.owners {
            if state.origin != RouteOrigin::Local {
                continue;
            }
            for route in &state.routes {
                let Some(identity) = PublicationIdentity::from_key(&route.key) else {
                    continue;
                };
                let signature = (
                    state.attachment.clone(),
                    route.key.clone(),
                    state.origin,
                    route.supported_types.clone(),
                );
                if identity.netid() != netid || identities.get(&identity) != Some(&Some(signature))
                {
                    continue;
                }
                exports.push(selection(owner, state, route));
            }
        }
        exports.sort_by_key(|entry| format!("{}:{:?}", entry.owner.as_str(), entry.key));
        let mut exported = HashSet::new();
        exports.retain(|entry| {
            PublicationIdentity::from_key(&entry.key)
                .is_some_and(|identity| exported.insert(identity))
        });
        exports
    }

    /// Inspect all current advertisements without turning cached hints into
    /// live routes. Adapter status/candidates belong outside this registry.
    pub fn entries(&self) -> Vec<RouteSelection> {
        let mut entries = self
            .owners
            .iter()
            .flat_map(|(owner, state)| {
                state
                    .routes
                    .iter()
                    .map(move |route| selection(owner, state, route))
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| format!("{}:{:?}", entry.owner.as_str(), entry.key));
        entries
    }
}

fn selection(owner: &OwnerId, state: &OwnerState, route: &OwnedRoute) -> RouteSelection {
    RouteSelection {
        owner: owner.clone(),
        attachment: state.attachment.clone(),
        origin: state.origin,
        key: route.key.clone(),
        supported_types: route.supported_types.clone(),
        owner_version: state.version,
        lease: RouteLease {
            owner: owner.clone(),
            key: route.key.clone(),
            incarnation: route.incarnation,
        },
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum PublicationIdentity {
    Cp(QualifiedName),
    Lu(QualifiedName),
}

impl PublicationIdentity {
    fn from_key(key: &RouteKey) -> Option<Self> {
        match key {
            RouteKey::ControlPoint(cp) => Some(Self::Cp(cp.clone())),
            RouteKey::LogicalUnit { lu, .. } => Some(Self::Lu(lu.clone())),
            RouteKey::ProxyMac(_) => None,
        }
    }

    fn netid(&self) -> &str {
        match self {
            Self::Cp(cp) | Self::Lu(cp) => &cp.netid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn owner(value: &str) -> OwnerId {
        OwnerId::new(value).unwrap()
    }

    fn attachment(value: &str) -> AttachmentId {
        AttachmentId::new(value).unwrap()
    }

    fn version(generation: u64, revision: u64) -> OwnerVersion {
        OwnerVersion::new(generation, revision).unwrap()
    }

    fn lu(value: &str, host: &str) -> RouteKey {
        RouteKey::LogicalUnit {
            lu: name(value),
            hosting_cp: name(host),
        }
    }

    #[test]
    fn exact_lu_beats_cp_fallback_and_excludes_ingress() {
        let mut registry = RouteRegistry::new();
        let cp = name("SOLNET.SNAA");
        registry
            .replace_owner(
                owner("llc-a"),
                attachment("llc-a"),
                RouteOrigin::Local,
                version(1, 1),
                vec![RouteKey::ControlPoint(cp.clone())],
            )
            .unwrap();
        registry
            .replace_owner(
                owner("ee-b"),
                attachment("ee-b"),
                RouteOrigin::Local,
                version(1, 1),
                vec![lu("SOLNET.APP1", "SOLNET.SNAA")],
            )
            .unwrap();
        assert_eq!(
            registry
                .resolve_lu(&name("SOLNET.APP1"), Some(&cp), None)
                .unwrap()
                .owner,
            owner("ee-b")
        );
        assert_eq!(
            registry
                .resolve_lu(&name("SOLNET.APP2"), Some(&cp), None)
                .unwrap()
                .owner,
            owner("llc-a")
        );
        assert_eq!(
            registry.resolve_lu(&name("SOLNET.APP2"), Some(&cp), Some(&attachment("llc-a"))),
            Err(RegistryError::NoRoute)
        );
        assert_eq!(
            registry.resolve_lu(&name("SOLNET.APP2"), None, None),
            Err(RegistryError::NoRoute)
        );
    }

    #[test]
    fn withdrawal_is_a_tombstone_and_reappearance_invalidates_lease() {
        let mut registry = RouteRegistry::new();
        let key = lu("SOLNET.APP1", "SOLNET.SNAA");
        registry
            .replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 1),
                vec![key.clone()],
            )
            .unwrap();
        let first = registry
            .resolve_lu(&name("SOLNET.APP1"), None, None)
            .unwrap();
        registry
            .replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 2),
                vec![key.clone()],
            )
            .unwrap();
        assert!(registry.validate_lease(&first.lease));
        registry
            .withdraw_owner(&owner("llc"), RouteOrigin::Local, version(1, 3))
            .unwrap();
        assert!(!registry.validate_lease(&first.lease));
        assert_eq!(
            registry.replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 3),
                vec![key.clone()]
            ),
            Err(RegistryError::StaleUpdate)
        );
        registry
            .replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 4),
                vec![key],
            )
            .unwrap();
        let second = registry
            .resolve_lu(&name("SOLNET.APP1"), None, None)
            .unwrap();
        assert_ne!(first.lease.incarnation, second.lease.incarnation);
        assert!(!registry.validate_lease(&first.lease));
    }

    #[test]
    fn invalid_replacement_is_atomic_and_generation_retires_old_lease() {
        let mut registry = RouteRegistry::new();
        let cp = RouteKey::ControlPoint(name("SOLNET.SNAA"));
        registry
            .replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 1),
                vec![cp.clone()],
            )
            .unwrap();
        let first = registry.resolve_cp(&name("SOLNET.SNAA"), None).unwrap();
        assert_eq!(
            registry.replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 2),
                vec![cp.clone(), cp.clone()],
            ),
            Err(RegistryError::DuplicateRoute)
        );
        assert!(registry.validate_lease(&first.lease));
        registry
            .replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(2, 1),
                vec![cp],
            )
            .unwrap();
        assert!(!registry.validate_lease(&first.lease));
    }

    #[test]
    fn ambiguity_fails_closed_and_local_export_excludes_upstream_and_wrong_netid() {
        let mut registry = RouteRegistry::new();
        let shared = lu("SOLNET.APP1", "SOLNET.SNAA");
        registry
            .replace_owner(
                owner("llc"),
                attachment("llc"),
                RouteOrigin::Local,
                version(1, 1),
                vec![RouteKey::ControlPoint(name("SOLNET.SNAA")), shared.clone()],
            )
            .unwrap();
        registry
            .replace_owner(
                owner("ee"),
                attachment("ee"),
                RouteOrigin::Local,
                version(1, 1),
                vec![lu("QABOB.SNAB", "QABOB.SNAB")],
            )
            .unwrap();
        registry
            .replace_owner(
                owner("ws-alice"),
                attachment("ws-alice"),
                RouteOrigin::Upstream,
                version(1, 1),
                vec![shared],
            )
            .unwrap();
        assert_eq!(
            registry.resolve_lu(&name("SOLNET.APP1"), None, None),
            Err(RegistryError::AmbiguousRoute)
        );
        let exports = registry.local_exports("SOLNET");
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].key, RouteKey::ControlPoint(name("SOLNET.SNAA")));
        assert!(registry
            .local_exports("QABOB")
            .iter()
            .all(|e| e.origin == RouteOrigin::Local));
    }

    #[test]
    fn mac_alias_selects_owner_but_is_not_exported_as_sna_identity() {
        let mut registry = RouteRegistry::new();
        let mac = [0x02, 0, 0, 1, 2, 3];
        registry
            .replace_owner(
                owner("ws"),
                attachment("ws"),
                RouteOrigin::Upstream,
                version(1, 1),
                vec![RouteKey::ProxyMac(mac)],
            )
            .unwrap();
        assert_eq!(registry.resolve_mac(mac, None).unwrap().owner, owner("ws"));
        assert!(registry.local_exports("SOLNET").is_empty());
    }

    #[test]
    fn independent_proofs_on_one_attachment_coalesce_until_last_withdraws() {
        let mut registry = RouteRegistry::new();
        let key = lu("SOLNET.APP1", "SOLNET.SNAA");
        for proof in ["llc-link-1", "llc-link-2"] {
            registry
                .replace_owner(
                    owner(proof),
                    attachment("llc-a"),
                    RouteOrigin::Local,
                    version(1, 1),
                    vec![key.clone()],
                )
                .unwrap();
        }
        let first = registry
            .resolve_lu(&name("SOLNET.APP1"), None, None)
            .unwrap();
        assert_eq!(first.attachment, attachment("llc-a"));
        assert_eq!(registry.local_exports("SOLNET").len(), 1);
        registry
            .withdraw_owner(&owner("llc-link-1"), RouteOrigin::Local, version(1, 2))
            .unwrap();
        assert_eq!(
            registry
                .resolve_lu(&name("SOLNET.APP1"), None, None)
                .unwrap()
                .owner,
            owner("llc-link-2")
        );
        assert_eq!(registry.local_exports("SOLNET").len(), 1);
        registry
            .replace_owner(
                owner("llc-link-3"),
                attachment("llc-b"),
                RouteOrigin::Local,
                version(1, 1),
                vec![key],
            )
            .unwrap();
        assert_eq!(
            registry.resolve_lu(&name("SOLNET.APP1"), None, None),
            Err(RegistryError::AmbiguousRoute)
        );
        assert!(registry.local_exports("SOLNET").is_empty());
    }

    #[test]
    fn stable_proof_slots_bound_tombstones_and_can_advance_generation() {
        let mut registry = RouteRegistry::with_max_owners(2).unwrap();
        registry
            .replace_owner(
                owner("llc-a/slot-0"),
                attachment("llc-a"),
                RouteOrigin::Local,
                version(1, 1),
                vec![RouteKey::ControlPoint(name("SOLNET.SNAA"))],
            )
            .unwrap();
        registry
            .withdraw_owner(&owner("llc-a/slot-0"), RouteOrigin::Local, version(1, 2))
            .unwrap();
        registry
            .withdraw_owner(&owner("llc-b/slot-0"), RouteOrigin::Local, version(1, 1))
            .unwrap();
        assert_eq!(
            registry.withdraw_owner(&owner("llc-c/slot-0"), RouteOrigin::Local, version(1, 1)),
            Err(RegistryError::Capacity)
        );
        registry
            .replace_owner(
                owner("llc-a/slot-0"),
                attachment("llc-a"),
                RouteOrigin::Local,
                version(2, 1),
                vec![RouteKey::ControlPoint(name("SOLNET.SNAA"))],
            )
            .unwrap();
        assert_eq!(registry.entries().len(), 1);
    }

    #[test]
    fn lu7_capability_survives_export_and_metadata_change_retires_old_lease() {
        let mut registry = RouteRegistry::new();
        let key = lu("SOLNET.PRT01", "SOLNET.SNAA");
        let record = RouteRecord {
            key: key.clone(),
            supported_types: vec![LuType::Lu7],
        };
        registry
            .replace_records(
                owner("llc-printer"),
                attachment("llc-a"),
                RouteOrigin::Local,
                version(1, 1),
                vec![record.clone()],
            )
            .unwrap();
        let first = registry
            .resolve_lu(&name("SOLNET.PRT01"), None, None)
            .unwrap();
        assert_eq!(first.supported_types, vec![LuType::Lu7]);
        assert_eq!(
            registry.local_exports("SOLNET")[0].supported_types,
            vec![LuType::Lu7]
        );
        registry
            .replace_records(
                owner("llc-printer"),
                attachment("llc-a"),
                RouteOrigin::Local,
                version(1, 2),
                vec![record],
            )
            .unwrap();
        assert!(registry.validate_lease(&first.lease));
        registry
            .replace_records(
                owner("llc-printer"),
                attachment("llc-a"),
                RouteOrigin::Local,
                version(1, 3),
                vec![RouteRecord {
                    key,
                    supported_types: vec![LuType::Lu62],
                }],
            )
            .unwrap();
        assert!(!registry.validate_lease(&first.lease));
        assert_eq!(
            registry.local_exports("SOLNET")[0].supported_types,
            vec![LuType::Lu62]
        );
    }

    #[test]
    fn conflicting_lu_types_on_same_attachment_fail_closed() {
        let mut registry = RouteRegistry::new();
        let key = lu("SOLNET.PRT01", "SOLNET.SNAA");
        for (proof, kind) in [("proof-a", LuType::Lu7), ("proof-b", LuType::Lu62)] {
            registry
                .replace_records(
                    owner(proof),
                    attachment("llc-a"),
                    RouteOrigin::Local,
                    version(1, 1),
                    vec![RouteRecord {
                        key: key.clone(),
                        supported_types: vec![kind],
                    }],
                )
                .unwrap();
        }
        assert_eq!(
            registry.resolve_lu(&name("SOLNET.PRT01"), None, None),
            Err(RegistryError::AmbiguousRoute)
        );
        assert!(registry.local_exports("SOLNET").is_empty());
    }
}
