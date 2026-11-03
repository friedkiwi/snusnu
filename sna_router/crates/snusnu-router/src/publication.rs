//! One concentrator announcement built from verified local route owners.

use router_core::{
    route_registry::{LuType, RouteKey, RouteOrigin, RouteRecord, RouteSelection},
    session::QualifiedName,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use transport_ws::wire;

/// An EE attachment's complete verified reachability snapshot. The owner is
/// stable for that attachment and distinct from registry attachment IDs.
#[derive(Clone, Debug)]
pub(crate) struct EeOwnerExport {
    pub(crate) owner: String,
    pub(crate) records: Vec<RouteRecord>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PublicationSnapshot {
    cps: Vec<wire::SnaName>,
    lus: Vec<wire::LuReachability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LuClaim {
    owner: String,
    hosting_cp: QualifiedName,
    supported_types: BTreeSet<LuType>,
}

impl PublicationSnapshot {
    /// Conflicting owners are omitted. An LU is announced only when its CP is
    /// also unambiguous, and both identities belong to the assigned NETID.
    pub(crate) fn merge(
        allowed_netid: &str,
        registry_exports: impl IntoIterator<Item = RouteSelection>,
        ee_exports: impl IntoIterator<Item = EeOwnerExport>,
    ) -> Self {
        let mut cps: HashMap<QualifiedName, Option<String>> = HashMap::new();
        let mut lus: HashMap<QualifiedName, Option<LuClaim>> = HashMap::new();
        for selection in registry_exports {
            if selection.origin != RouteOrigin::Local {
                continue;
            }
            let owner = format!("registry:{}", selection.attachment.as_str());
            add_claim(
                &mut cps,
                &mut lus,
                allowed_netid,
                owner,
                RouteRecord {
                    key: selection.key,
                    supported_types: selection.supported_types,
                },
            );
        }
        for export in ee_exports {
            let owner = format!("ee:{}", export.owner);
            for record in export.records {
                add_claim(&mut cps, &mut lus, allowed_netid, owner.clone(), record);
            }
        }
        let cps = cps
            .into_iter()
            .filter_map(|(cp, owner)| owner.map(|_| cp))
            .collect::<HashSet<_>>();
        let mut wire_cps = cps.iter().map(wire_name).collect::<Vec<_>>();
        wire_cps.sort_by(|a, b| (&a.netid, &a.name).cmp(&(&b.netid, &b.name)));
        let mut wire_lus = lus
            .into_iter()
            .filter_map(|(lu, claim)| {
                let claim = claim?;
                cps.contains(&claim.hosting_cp)
                    .then(|| wire::LuReachability {
                        lu: Some(wire_name(&lu)),
                        hosting_cp: Some(wire_name(&claim.hosting_cp)),
                        supported_types: claim
                            .supported_types
                            .into_iter()
                            .map(wire_lu_type)
                            .collect(),
                    })
            })
            .collect::<Vec<_>>();
        wire_lus.sort_by(|a, b| {
            let a = a.lu.as_ref().expect("constructed LU");
            let b = b.lu.as_ref().expect("constructed LU");
            (&a.netid, &a.name).cmp(&(&b.netid, &b.name))
        });
        Self {
            cps: wire_cps,
            lus: wire_lus,
        }
    }

    pub(crate) fn wire_records(&self) -> (&[wire::SnaName], &[wire::LuReachability]) {
        (&self.cps, &self.lus)
    }
}

fn add_claim(
    cps: &mut HashMap<QualifiedName, Option<String>>,
    lus: &mut HashMap<QualifiedName, Option<LuClaim>>,
    allowed_netid: &str,
    owner: String,
    record: RouteRecord,
) {
    match record.key {
        RouteKey::ControlPoint(cp) if cp.netid == allowed_netid => {
            cps.entry(cp)
                .and_modify(|existing| {
                    if existing.as_ref() != Some(&owner) {
                        *existing = None;
                    }
                })
                .or_insert(Some(owner));
        }
        RouteKey::LogicalUnit { lu, hosting_cp }
            if lu.netid == allowed_netid && hosting_cp.netid == allowed_netid =>
        {
            let types = record.supported_types.into_iter().collect::<BTreeSet<_>>();
            lus.entry(lu)
                .and_modify(|existing| {
                    if let Some(claim) = existing {
                        if claim.owner == owner && claim.hosting_cp == hosting_cp {
                            claim.supported_types.extend(types.iter().copied());
                        } else {
                            *existing = None;
                        }
                    }
                })
                .or_insert(Some(LuClaim {
                    owner,
                    hosting_cp,
                    supported_types: types,
                }));
        }
        _ => {}
    }
}

fn wire_name(name: &QualifiedName) -> wire::SnaName {
    wire::SnaName {
        netid: name.netid.clone(),
        name: name.name.clone(),
    }
}

fn wire_lu_type(kind: LuType) -> i32 {
    match kind {
        LuType::Lu0 => wire::LuType::LuType0 as i32,
        LuType::Lu1 => wire::LuType::LuType1 as i32,
        LuType::Lu2 => wire::LuType::LuType2 as i32,
        LuType::Lu3 => wire::LuType::LuType3 as i32,
        LuType::Lu4 => wire::LuType::LuType4 as i32,
        LuType::Lu61 => wire::LuType::LuType61 as i32,
        LuType::Lu62 => wire::LuType::LuType62 as i32,
        LuType::Lu7 => wire::LuType::LuType7 as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::route_registry::{AttachmentId, OwnerId, OwnerVersion, RouteLease};

    fn name(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn selection(attachment: &str, record: RouteRecord) -> RouteSelection {
        RouteSelection {
            owner: OwnerId::new(attachment).unwrap(),
            attachment: AttachmentId::new(attachment).unwrap(),
            origin: RouteOrigin::Local,
            key: record.key.clone(),
            supported_types: record.supported_types,
            owner_version: OwnerVersion::new(1, 1).unwrap(),
            lease: RouteLease {
                owner: OwnerId::new(attachment).unwrap(),
                key: record.key,
                incarnation: 1,
            },
        }
    }

    #[test]
    fn combines_registry_lu7_and_ee_lu62_with_netid_filter() {
        let registry = [
            selection(
                "llc",
                RouteRecord::from(RouteKey::ControlPoint(name("NETA.LLCCP"))),
            ),
            selection(
                "llc",
                RouteRecord {
                    key: RouteKey::LogicalUnit {
                        lu: name("NETA.PRINTER"),
                        hosting_cp: name("NETA.LLCCP"),
                    },
                    supported_types: vec![LuType::Lu7],
                },
            ),
        ];
        let ee = [EeOwnerExport {
            owner: "udp-1".into(),
            records: vec![
                RouteRecord::from(RouteKey::ControlPoint(name("NETA.EECP"))),
                RouteRecord {
                    key: RouteKey::LogicalUnit {
                        lu: name("NETA.EELU"),
                        hosting_cp: name("NETA.EECP"),
                    },
                    supported_types: vec![LuType::Lu62],
                },
                RouteRecord::from(RouteKey::ControlPoint(name("OTHER.HIDDEN"))),
            ],
        }];
        let merged = PublicationSnapshot::merge("NETA", registry, ee);
        let (cps, lus) = merged.wire_records();
        assert_eq!(cps.len(), 2);
        assert_eq!(lus.len(), 2);
        assert_eq!(lus[0].supported_types, vec![wire::LuType::LuType62 as i32]);
        assert_eq!(lus[1].supported_types, vec![wire::LuType::LuType7 as i32]);
    }

    #[test]
    fn conflicting_cp_withholds_its_lus() {
        let registry = [
            selection(
                "llc",
                RouteRecord::from(RouteKey::ControlPoint(name("NETA.SHARED"))),
            ),
            selection(
                "llc",
                RouteRecord {
                    key: RouteKey::LogicalUnit {
                        lu: name("NETA.LU1"),
                        hosting_cp: name("NETA.SHARED"),
                    },
                    supported_types: vec![LuType::Lu7],
                },
            ),
        ];
        let ee = [EeOwnerExport {
            owner: "udp-1".into(),
            records: vec![RouteRecord::from(RouteKey::ControlPoint(name(
                "NETA.SHARED",
            )))],
        }];
        let merged = PublicationSnapshot::merge("NETA", registry, ee);
        assert_eq!(merged.wire_records(), (&[][..], &[][..]));
    }

    #[test]
    fn conflicting_lu_owners_are_omitted_and_upstream_is_never_republished() {
        let mut upstream = selection(
            "remote",
            RouteRecord::from(RouteKey::ControlPoint(name("NETA.REMOTE"))),
        );
        upstream.origin = RouteOrigin::Upstream;
        let ee = [
            EeOwnerExport {
                owner: "udp-1".into(),
                records: vec![
                    RouteRecord::from(RouteKey::ControlPoint(name("NETA.CP1"))),
                    RouteRecord {
                        key: RouteKey::LogicalUnit {
                            lu: name("NETA.SHAREDLU"),
                            hosting_cp: name("NETA.CP1"),
                        },
                        supported_types: vec![LuType::Lu62],
                    },
                ],
            },
            EeOwnerExport {
                owner: "udp-2".into(),
                records: vec![
                    RouteRecord::from(RouteKey::ControlPoint(name("NETA.CP2"))),
                    RouteRecord {
                        key: RouteKey::LogicalUnit {
                            lu: name("NETA.SHAREDLU"),
                            hosting_cp: name("NETA.CP2"),
                        },
                        supported_types: vec![LuType::Lu7],
                    },
                ],
            },
        ];
        let merged = PublicationSnapshot::merge("NETA", [upstream], ee);
        let (cps, lus) = merged.wire_records();
        assert_eq!(cps.len(), 2);
        assert!(lus.is_empty());
    }
}
