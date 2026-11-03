//! Identity for one EE-facing APPN proxy CP, authorized by the upstream
//! directory before any local XID3 is sent.
//!
//! The router's authenticated UUID is assigned by the concentrator. It is
//! used only to derive a stable XID node ID; it is never published as an SNA
//! identity. The guest's CP/LU is learned separately from its own traffic.

use crate::{
    config::{self, EeConfig},
    ee_ldlc_endpoint::LocalEeXids,
    remote::AutoWsHub,
};
use router_core::{
    hpr_cv61::{ArbMode, ControlFlowsTower},
    session::QualifiedName,
    xid3::Xid3,
};
use std::io;
use transport_ws::wire;

const MAX_SEND_PACKET_SIZE: u16 = 1461;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// A directory-backed CP that this attachment may present to its EE guest.
/// The route reference is retained so a later withdrawal can revoke the
/// identity and tear down link/RTP state.
#[derive(Clone, Debug)]
pub(crate) struct AuthorizedEeIdentity {
    pub(crate) local_cp: QualifiedName,
    pub(crate) cp_route: wire::RouteReference,
    pub(crate) allowed_peer_netid: String,
    node_id: [u8; 4],
    link_label: [u8; 2],
    tower: ControlFlowsTower,
}

/// A CP owned by this router for an EE adjacency without a concentrator.
/// Its XID node ID is derived from the configured CP, attachment ID and
/// local IP, so restarting the process does not change the adjacent node.
/// Unlike an authenticated upstream assignment, there is no account NETID
/// restriction on the peer; the peer CP is learned from its validated XID.
#[derive(Clone, Debug)]
pub(crate) struct StandaloneEeIdentity {
    pub(crate) local_cp: QualifiedName,
    node_id: [u8; 4],
    link_label: [u8; 2],
    tower: ControlFlowsTower,
}

impl StandaloneEeIdentity {
    pub(crate) fn from_attachment(attachment: &EeConfig) -> io::Result<Self> {
        let configured = attachment
            .local_cp
            .as_deref()
            .ok_or_else(|| invalid("standalone EE requires local_cp"))?;
        let local_cp: QualifiedName = configured
            .parse()
            .map_err(|_| invalid("invalid standalone EE CP name"))?;
        let node_id = standalone_node_id(&local_cp, attachment);
        let label_suffix = label_suffix(node_id);
        Ok(Self {
            local_cp,
            node_id,
            link_label: [0x80, label_suffix],
            tower: control_flows_tower(node_id, label_suffix),
        })
    }

    pub(crate) fn build_xids(
        &self,
        peer_xid: &Xid3,
        network_node: bool,
    ) -> io::Result<LocalEeXids> {
        let peer_cp: QualifiedName = peer_xid
            .cp_name()
            .map_err(|_| invalid("invalid EE peer CP"))?
            .parse()
            .map_err(|_| invalid("invalid EE peer CP"))?;
        build_local_xids(
            &self.local_cp,
            &peer_cp,
            self.node_id,
            self.link_label,
            &self.tower,
            peer_xid,
            network_node,
        )
    }
}

impl AuthorizedEeIdentity {
    /// Returns None until the authenticated concentrator has published the
    /// configured CP. Ambiguous or stale directory entries fail closed.
    pub(crate) fn resolve(hub: &AutoWsHub, attachment: &EeConfig) -> io::Result<Option<Self>> {
        let configured = attachment
            .local_cp
            .as_deref()
            .ok_or_else(|| invalid("automatic EE local_cp is absent"))?;
        let cp = config::parse_cp(configured)?;
        let Some(reference) = hub.resolve_cp(&cp)? else {
            return Ok(None);
        };
        let route = hub
            .remote_route(&reference)
            .ok_or_else(|| invalid("EE proxy CP route disappeared"))?;
        if !matches!(
            route.resource,
            Some(wire::route_export::Resource::ControlPoint(ref found)) if found == &cp
        ) {
            return Err(invalid("EE proxy CP route changed"));
        }
        let local_cp: QualifiedName = configured
            .parse()
            .map_err(|_| invalid("invalid EE proxy CP name"))?;
        let router_id = hub.router_id_bytes()?;
        let node_id = stable_node_id(router_id, attachment.id.as_bytes());
        let label_suffix = label_suffix(node_id);
        let tower = control_flows_tower(node_id, label_suffix);
        Ok(Some(Self {
            local_cp,
            cp_route: reference,
            allowed_peer_netid: hub.allowed_netid().to_owned(),
            node_id,
            link_label: [0x80, label_suffix],
            tower,
        }))
    }

    /// A route withdrawal invalidates the identity even if a different
    /// origin later publishes the same CP name.
    pub(crate) fn still_authorized(&self, hub: &AutoWsHub) -> io::Result<bool> {
        let cp = config::parse_cp(&self.local_cp.to_string())?;
        Ok(hub.resolve_cp(&cp)?.as_ref() == Some(&self.cp_route))
    }

    /// Build this side's EE XIDs only after the first syntactically valid
    /// guest prenegotiation XID has revealed CP/NETID and TG number.
    pub(crate) fn build_xids(
        &self,
        peer_xid: &Xid3,
        network_node: bool,
    ) -> io::Result<LocalEeXids> {
        let peer_cp: QualifiedName = peer_xid
            .cp_name()
            .map_err(|_| invalid("invalid EE peer CP"))?
            .parse()
            .map_err(|_| invalid("invalid EE peer CP"))?;
        if peer_cp.netid != self.allowed_peer_netid {
            tracing::warn!(
                peer_cp = %peer_cp,
                observed_netid = %peer_cp.netid,
                allowed_netid = %self.allowed_peer_netid,
                "EE peer NETID does not match authenticated router assignment"
            );
            return Err(invalid(
                "EE peer NETID differs from authenticated router NETID",
            ));
        }
        build_local_xids(
            &self.local_cp,
            &peer_cp,
            self.node_id,
            self.link_label,
            &self.tower,
            peer_xid,
            network_node,
        )
    }
}

fn control_flows_tower(node_id: [u8; 4], label_suffix: u8) -> ControlFlowsTower {
    ControlFlowsTower {
        max_send_packet_size: MAX_SEND_PACKET_SIZE,
        path_switch_time_ms: 0,
        mobile: false,
        multilink_tg: false,
        arb_mode: ArbMode::Base,
        cp_nce_instance: node_id,
        route_setup_nce_instance: node_id,
        cp_nce_label: vec![0xa4, label_suffix],
        route_setup_nce_label: vec![0xa4, label_suffix],
    }
}

fn build_local_xids(
    local_cp: &QualifiedName,
    peer_cp: &QualifiedName,
    node_id: [u8; 4],
    link_label: [u8; 2],
    tower: &ControlFlowsTower,
    peer_xid: &Xid3,
    network_node: bool,
) -> io::Result<LocalEeXids> {
    let tg_number = peer_xid
        .encode()
        .map_err(|_| invalid("invalid EE peer XID"))?[16];
    let (node_id, tower) = local_profile_for_peer(node_id, tower, peer_xid.node_id());
    LocalEeXids::build(
        local_cp,
        peer_cp,
        node_id,
        tg_number,
        link_label,
        &tower,
        network_node,
    )
}

fn local_profile_for_peer(
    node_id: [u8; 4],
    tower: &ControlFlowsTower,
    peer_node_id: [u8; 4],
) -> ([u8; 4], ControlFlowsTower) {
    // The XID node ID and the two CV61 NCE instances must remain identical
    // even when avoiding a rare 20-bit collision with the adjacent guest.
    let node_id = node_id_for_peer(node_id, peer_node_id);
    let mut tower = tower.clone();
    tower.cp_nce_instance = node_id;
    tower.route_setup_nce_instance = node_id;
    (node_id, tower)
}

fn standalone_node_id(local_cp: &QualifiedName, attachment: &EeConfig) -> [u8; 4] {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let cp_name = local_cp.to_string();
    let local_ip = attachment.local_ip.to_string();
    for byte in b"snusnu-standalone-ee-node-v1"
        .iter()
        .chain([0].iter())
        .chain(cp_name.as_bytes().iter())
        .chain([0].iter())
        .chain(attachment.id.as_bytes())
        .chain([0].iter())
        .chain(local_ip.as_bytes().iter())
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let node = 0xfff0_0000u32 | ((hash as u32 & 0x000f_ffff).max(1));
    node.to_be_bytes()
}

/// FNV-1a with a fixed domain tag avoids process-random hash seeds. The XID3
/// node ID has a 12-bit FFF block and a 20-bit nonzero identifier.
fn stable_node_id(router_id: [u8; 16], attachment_id: &[u8]) -> [u8; 4] {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in b"snusnu-ee-node-v1"
        .iter()
        .chain(router_id.iter())
        .chain(attachment_id.iter())
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let node = 0xfff0_0000u32 | ((hash as u32 & 0x000f_ffff).max(1));
    node.to_be_bytes()
}

fn label_suffix(node_id: [u8; 4]) -> u8 {
    let raw = node_id[3];
    if raw == 0xff {
        0xfe
    } else {
        raw
    }
}

fn node_id_for_peer(local: [u8; 4], peer: [u8; 4]) -> [u8; 4] {
    if local != peer {
        return local;
    }
    let low = (u32::from_be_bytes(local) & 0x000f_ffff) % 0x000f_ffff + 1;
    (0xfff0_0000 | low).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::xid3::{ControlVector, Xid3};
    fn attachment(id: &str, local_cp: Option<&str>) -> EeConfig {
        let mut source = format!("id = '{id}'\nlocal_ip = '192.0.2.1'\npeer_ip = '192.0.2.2'\n");
        if let Some(cp) = local_cp {
            source.push_str(&format!("local_cp = '{cp}'\n"));
        }
        toml::from_str(&source).unwrap()
    }

    fn peer_xid(cp: &str, node_id: [u8; 4]) -> Xid3 {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(&node_id);
        fixed[9] = 0x08;
        fixed[16] = 1;
        fixed[21..23].copy_from_slice(&1461u16.to_be_bytes());
        fixed[27] = 7;
        let mut xid = Xid3::from_parts(
            fixed,
            vec![ControlVector {
                key: 0x0e,
                data: vec![0xf4, 0xc1, 0x4b, 0xc1],
            }],
        )
        .unwrap();
        xid.set_cp_name(cp).unwrap();
        xid
    }

    fn identity() -> AuthorizedEeIdentity {
        AuthorizedEeIdentity {
            local_cp: "SNUSNU.SVC".parse().unwrap(),
            cp_route: wire::RouteReference::default(),
            allowed_peer_netid: "SOLNET".to_owned(),
            node_id: [0xff, 0xf0, 0, 1],
            link_label: [0x80, 2],
            tower: ControlFlowsTower {
                max_send_packet_size: 1461,
                path_switch_time_ms: 0,
                mobile: false,
                multilink_tg: false,
                arb_mode: ArbMode::Base,
                cp_nce_instance: [0xff, 0xf0, 0, 1],
                route_setup_nce_instance: [0xff, 0xf0, 0, 1],
                cp_nce_label: vec![0xa4, 2],
                route_setup_nce_label: vec![0xa4, 2],
            },
        }
    }

    #[test]
    fn node_id_is_stable_across_processes_and_changes_per_attachment() {
        let router = [7u8; 16];
        let a = stable_node_id(router, b"ee-a");
        assert_eq!(a, stable_node_id(router, b"ee-a"));
        assert_ne!(a, stable_node_id(router, b"ee-b"));
        assert_eq!(a[0], 0xff);
        assert_eq!(a[1] & 0xf0, 0xf0);
        assert_ne!(u32::from_be_bytes(a) & 0x000f_ffff, 0);
        assert_ne!(label_suffix(a), 0xff);
    }

    #[test]
    fn wrong_authenticated_netid_is_rejected_before_local_xid() {
        let identity = identity();
        assert!(identity
            .build_xids(&peer_xid("QAALICE.SNAB", [0xff, 0xf0, 0, 2]), true)
            .is_err());
        assert!(identity
            .build_xids(&peer_xid("SOLNET.SNAB", [0xff, 0xf0, 0, 2]), true)
            .is_ok());
    }

    #[test]
    fn local_node_id_collision_is_resolved_deterministically() {
        let identity = identity();
        let peer = peer_xid("SOLNET.SNAB", identity.node_id);
        assert!(identity.build_xids(&peer, true).is_ok());
        let (node_id, tower) =
            local_profile_for_peer(identity.node_id, &identity.tower, peer.node_id());
        assert_eq!(node_id, [0xff, 0xf0, 0, 2]);
        assert_eq!(tower.cp_nce_instance, node_id);
        assert_eq!(tower.route_setup_nce_instance, node_id);
    }

    #[test]
    fn standalone_identity_is_stable_and_accepts_validated_foreign_netid_peer() {
        let first =
            StandaloneEeIdentity::from_attachment(&attachment("ee-a", Some("SOLNET.RTR"))).unwrap();
        let second =
            StandaloneEeIdentity::from_attachment(&attachment("ee-a", Some("SOLNET.RTR"))).unwrap();
        let other =
            StandaloneEeIdentity::from_attachment(&attachment("ee-b", Some("SOLNET.RTR"))).unwrap();
        assert_eq!(first.node_id, second.node_id);
        assert_eq!(first.link_label, second.link_label);
        assert_ne!(first.node_id, other.node_id);
        assert!(first
            .build_xids(&peer_xid("QAALICE.SNAB", [0xff, 0xf0, 0, 2]), true)
            .is_ok());
    }

    #[test]
    fn standalone_identity_requires_explicit_valid_cp() {
        assert!(StandaloneEeIdentity::from_attachment(&attachment("ee-a", None)).is_err());
        assert!(
            StandaloneEeIdentity::from_attachment(&attachment("ee-a", Some("INVALID"))).is_err()
        );
    }
}
