//! Route lifecycle across independent local and upstream attachments.

use router_core::{
    route_registry::{
        AttachmentId, LuType, OwnerId, OwnerVersion, RegistryError, RouteKey, RouteOrigin,
        RouteRecord, RouteRegistry,
    },
    session::QualifiedName,
};

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

fn cp(value: &str) -> RouteRecord {
    RouteKey::ControlPoint(name(value)).into()
}

fn lu(value: &str, host: &str, kind: LuType) -> RouteRecord {
    RouteRecord {
        key: RouteKey::LogicalUnit {
            lu: name(value),
            hosting_cp: name(host),
        },
        supported_types: vec![kind],
    }
}

#[test]
fn local_and_upstream_proofs_select_without_leaking_upstream_or_stale_routes() {
    let mut routes = RouteRegistry::new();
    let llc = attachment("llc-a");
    let mptn = attachment("mptn-b");
    let upstream = attachment("concentrator");
    let llc_mac = [0x06, 0x53, 0x4e, 0, 0, 1];
    let upstream_mac = [0x06, 0x53, 0x4e, 0, 0, 2];
    let printer = lu("SOLNET.PRT01", "SOLNET.SNAA", LuType::Lu7);
    let mptn_lu = lu("SOLNET.APP1", "SOLNET.SNAB", LuType::Lu62);
    let remote_lu = lu("QABOB.APP2", "QABOB.SNAC", LuType::Lu62);

    routes
        .replace_records(
            owner("llc-a/xid"),
            llc.clone(),
            RouteOrigin::Local,
            version(1, 1),
            vec![
                cp("SOLNET.SNAA"),
                printer.clone(),
                RouteKey::ProxyMac(llc_mac).into(),
            ],
        )
        .unwrap();
    routes
        .replace_records(
            owner("llc-a/bind"),
            llc.clone(),
            RouteOrigin::Local,
            version(1, 1),
            vec![printer.clone()],
        )
        .unwrap();
    routes
        .replace_records(
            owner("mptn-b/management"),
            mptn.clone(),
            RouteOrigin::Local,
            version(1, 1),
            vec![cp("SOLNET.SNAB"), mptn_lu.clone()],
        )
        .unwrap();
    routes
        .replace_records(
            owner("ws/origin-bob"),
            upstream.clone(),
            RouteOrigin::Upstream,
            version(1, 1),
            vec![
                cp("QABOB.SNAC"),
                remote_lu.clone(),
                RouteKey::ProxyMac(upstream_mac).into(),
            ],
        )
        .unwrap();

    let to_mptn = routes
        .resolve_lu(&name("SOLNET.APP1"), Some(&name("SOLNET.SNAB")), Some(&llc))
        .unwrap();
    assert_eq!(to_mptn.attachment, mptn);
    assert_eq!(to_mptn.supported_types, vec![LuType::Lu62]);
    assert_eq!(
        routes
            .resolve_lu(&name("QABOB.APP2"), None, Some(&llc))
            .unwrap()
            .attachment,
        upstream
    );
    assert_eq!(
        routes
            .resolve_mac(upstream_mac, Some(&llc))
            .unwrap()
            .attachment,
        upstream
    );
    let to_printer = routes
        .resolve_lu(&name("SOLNET.PRT01"), None, Some(&upstream))
        .unwrap();
    let llc_alias = routes.resolve_mac(llc_mac, Some(&upstream)).unwrap();
    assert_eq!(to_printer.attachment, llc);
    assert_eq!(to_printer.supported_types, vec![LuType::Lu7]);
    assert_eq!(
        routes.resolve_mac(llc_mac, Some(&llc)),
        Err(RegistryError::NoRoute)
    );

    let exports = routes.local_exports("SOLNET");
    assert_eq!(exports.len(), 4);
    assert!(exports
        .iter()
        .all(|entry| entry.origin == RouteOrigin::Local));
    assert!(exports
        .iter()
        .all(|entry| !matches!(&entry.key, RouteKey::ProxyMac(_))));
    assert!(exports
        .iter()
        .any(|entry| { entry.key == printer.key && entry.supported_types == vec![LuType::Lu7] }));
    assert!(routes.local_exports("QABOB").is_empty());

    routes
        .withdraw_owner(&owner("llc-a/xid"), RouteOrigin::Local, version(1, 2))
        .unwrap();
    assert_eq!(
        routes
            .resolve_lu(&name("SOLNET.PRT01"), None, Some(&upstream))
            .unwrap()
            .attachment,
        llc,
        "the independent BIND proof keeps this attachment reachable"
    );
    assert!(!routes.validate_lease(&llc_alias.lease));
    assert_eq!(
        routes.resolve_mac(llc_mac, Some(&upstream)),
        Err(RegistryError::NoRoute)
    );

    routes
        .withdraw_owner(
            &owner("mptn-b/management"),
            RouteOrigin::Local,
            version(1, 2),
        )
        .unwrap();
    assert_eq!(
        routes.resolve_lu(&name("SOLNET.APP1"), None, Some(&llc)),
        Err(RegistryError::NoRoute)
    );
    assert!(!routes.validate_lease(&to_mptn.lease));
    assert_eq!(
        routes.replace_records(
            owner("mptn-b/management"),
            mptn.clone(),
            RouteOrigin::Local,
            version(1, 1),
            vec![mptn_lu.clone()],
        ),
        Err(RegistryError::StaleUpdate)
    );
    routes
        .replace_records(
            owner("mptn-b/management"),
            mptn,
            RouteOrigin::Local,
            version(2, 1),
            vec![cp("SOLNET.SNAB"), mptn_lu],
        )
        .unwrap();
    assert!(!routes.validate_lease(&to_mptn.lease));

    // A remote origin claiming the same LU creates an explicit ambiguity.
    // Withdrawal restores the local route without changing its proof.
    routes
        .replace_records(
            owner("ws/origin-bob"),
            upstream.clone(),
            RouteOrigin::Upstream,
            version(1, 2),
            vec![printer.clone()],
        )
        .unwrap();
    assert_eq!(
        routes.resolve_lu(&name("SOLNET.PRT01"), None, None),
        Err(RegistryError::AmbiguousRoute)
    );
    assert!(routes
        .local_exports("SOLNET")
        .iter()
        .all(|entry| entry.key != printer.key));
    routes
        .withdraw_owner(
            &owner("ws/origin-bob"),
            RouteOrigin::Upstream,
            version(1, 3),
        )
        .unwrap();
    assert_eq!(
        routes
            .resolve_lu(&name("SOLNET.PRT01"), None, None)
            .unwrap()
            .attachment,
        llc
    );
    assert!(routes
        .local_exports("SOLNET")
        .iter()
        .any(|entry| entry.key == printer.key));
}
