//! LU reachability learned from one verified EE end node.
//!
//! XID3 authenticates a CP, not its hosted LUs. Configured answer-only LUs
//! and LUs seen in validated BINDs are therefore scoped to that CP. A cached
//! observation is reused only after the same CP appears on the same EE
//! attachment; no stale route is published while the link is down.

use crate::{
    config::EeConfig,
    local_status::{now_ms, LocalPeerStatus},
};
use router_core::session::{QualifiedName, SessionIdentity};
use std::{collections::HashSet, io, net::IpAddr};

const MAX_PEER_LUS: usize = 64;

pub(crate) struct EePeerLus {
    attachment_id: String,
    peer_ip: IpAddr,
    configured: HashSet<QualifiedName>,
    cached_cp: Option<QualifiedName>,
    cached_lus: HashSet<QualifiedName>,
    active_cp: Option<QualifiedName>,
    learned: HashSet<QualifiedName>,
}

impl EePeerLus {
    pub(crate) fn from_attachment(attachment: &EeConfig) -> io::Result<Self> {
        let key = Self::key(&attachment.id, attachment.peer_ip);
        let cached = crate::status().and_then(|status| {
            status
                .snapshot()
                .local_peers
                .into_iter()
                .find(|peer| peer.key == key && peer.transport == "hpr_ip")
        });
        Self::from_parts(
            attachment.id.clone(),
            attachment.peer_ip,
            &attachment.peer_lus,
            cached,
        )
    }

    fn from_parts(
        attachment_id: String,
        peer_ip: IpAddr,
        configured: &[String],
        cached: Option<LocalPeerStatus>,
    ) -> io::Result<Self> {
        if configured.len() > MAX_PEER_LUS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many configured EE peer LUs",
            ));
        }
        let configured = configured
            .iter()
            .map(|name| {
                name.parse::<QualifiedName>()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
            })
            .collect::<io::Result<HashSet<_>>>()?;
        let cached_cp = cached
            .as_ref()
            .and_then(|peer| peer.cp.as_deref())
            .and_then(|name| name.parse().ok());
        let cached_lus = cached
            .into_iter()
            .flat_map(|peer| peer.lus)
            .filter_map(|name| name.parse::<QualifiedName>().ok())
            .take(MAX_PEER_LUS)
            .collect();
        Ok(Self {
            attachment_id,
            peer_ip,
            configured,
            cached_cp,
            cached_lus,
            active_cp: None,
            learned: HashSet::new(),
        })
    }

    /// Activate only after the live XID3 CP has passed the EE adjacency gate.
    /// Configured LUs in another NETID are ignored and called out in logs.
    pub(crate) fn activate(&mut self, peer_cp: &QualifiedName) {
        if self.active_cp.as_ref() != Some(peer_cp) {
            self.learned.clear();
        }
        if self.cached_cp.as_ref() == Some(peer_cp) {
            self.learned.extend(
                self.cached_lus
                    .iter()
                    .filter(|lu| lu.netid == peer_cp.netid)
                    .cloned(),
            );
        } else {
            self.cached_lus.clear();
        }
        self.cached_cp = Some(peer_cp.clone());
        self.active_cp = Some(peer_cp.clone());
        for lu in &self.configured {
            if lu.netid != peer_cp.netid {
                tracing::warn!(attachment = %self.attachment_id, peer_ip = %self.peer_ip,
                    peer_cp = %peer_cp, configured_lu = %lu,
                    "configured EE peer LU NETID differs from live XID CP; route withheld");
            }
        }
        self.persist("active");
    }

    /// Learn a source LU only from a BIND whose hosting CP matches this live
    /// adjacency. The caller must already have validated the BIND envelope.
    pub(crate) fn observe(&mut self, identity: &SessionIdentity) -> bool {
        let Some(peer_cp) = &self.active_cp else {
            return false;
        };
        if identity.source_cp.as_ref() != Some(peer_cp)
            || identity.source_lu.netid != peer_cp.netid
            || (!self.learned.contains(&identity.source_lu)
                && self.advertised().len() >= MAX_PEER_LUS)
        {
            return false;
        }
        let inserted = self.learned.insert(identity.source_lu.clone());
        if inserted {
            self.cached_lus = self.learned.clone();
            self.persist("active");
        }
        inserted
    }

    pub(crate) fn advertised(&self) -> Vec<QualifiedName> {
        let Some(peer_cp) = &self.active_cp else {
            return Vec::new();
        };
        let mut entries = self
            .configured
            .iter()
            .chain(&self.learned)
            .filter(|lu| lu.netid == peer_cp.netid)
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| (&left.netid, &left.name).cmp(&(&right.netid, &right.name)));
        entries.truncate(MAX_PEER_LUS);
        entries
    }

    pub(crate) fn peer_cp(&self) -> Option<&QualifiedName> {
        self.active_cp.as_ref()
    }

    pub(crate) fn deactivate(&mut self) {
        if self.active_cp.take().is_some() {
            self.persist("disconnected");
        }
    }

    fn persist(&self, state: &str) {
        let Some(status) = crate::status() else {
            return;
        };
        let now = now_ms();
        status.upsert_peer(LocalPeerStatus {
            key: Self::key(&self.attachment_id, self.peer_ip),
            transport: "hpr_ip".into(),
            locator: format!("{} {}", self.attachment_id, self.peer_ip),
            cp: self
                .active_cp
                .as_ref()
                .or(self.cached_cp.as_ref())
                .map(ToString::to_string),
            lus: {
                let mut learned = self
                    .learned
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                learned.sort();
                learned
            },
            state: state.into(),
            first_seen_ms: now,
            last_seen_ms: now,
            last_error: None,
        });
    }

    fn key(attachment_id: &str, peer_ip: IpAddr) -> String {
        format!("ee:{attachment_id}:{peer_ip}")
    }
}

impl Drop for EePeerLus {
    fn drop(&mut self) {
        self.deactivate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn cached(cp: &str, lus: &[&str]) -> LocalPeerStatus {
        LocalPeerStatus {
            key: "ee:ee1:192.0.2.2".into(),
            transport: "hpr_ip".into(),
            locator: "ee1 192.0.2.2".into(),
            cp: Some(cp.into()),
            lus: lus.iter().map(|lu| (*lu).into()).collect(),
            state: "stale".into(),
            first_seen_ms: 1,
            last_seen_ms: 1,
            last_error: None,
        }
    }

    #[test]
    fn routes_wait_for_live_cp_and_filter_mismatched_netids() {
        let mut directory = EePeerLus::from_parts(
            "ee1".into(),
            "192.0.2.2".parse().unwrap(),
            &["SOLNET.SNAB".into(), "OTHER.BAD".into()],
            Some(cached("SOLNET.SNAB", &["SOLNET.APP1", "OTHER.BAD"])),
        )
        .unwrap();
        assert!(directory.advertised().is_empty());
        directory.activate(&name("SOLNET.SNAB"));
        assert_eq!(
            directory.advertised(),
            vec![name("SOLNET.APP1"), name("SOLNET.SNAB")]
        );
        directory.deactivate();
        assert!(directory.advertised().is_empty());
    }

    #[test]
    fn cached_lus_do_not_follow_a_different_cp_at_same_ip() {
        let mut directory = EePeerLus::from_parts(
            "ee1".into(),
            "192.0.2.2".parse().unwrap(),
            &[],
            Some(cached("SOLNET.SNAB", &["SOLNET.APP1"])),
        )
        .unwrap();
        directory.activate(&name("SOLNET.OTHER"));
        assert!(directory.advertised().is_empty());
    }

    #[test]
    fn only_bound_source_lu_on_verified_cp_is_learned() {
        let mut directory =
            EePeerLus::from_parts("ee1".into(), "192.0.2.2".parse().unwrap(), &[], None).unwrap();
        directory.activate(&name("SOLNET.SNAB"));
        let valid = SessionIdentity::new(name("SOLNET.APP1"), name("SNUSNU.PING"))
            .with_control_points(Some(name("SOLNET.SNAB")), Some(name("SNUSNU.SVC")))
            .unwrap();
        assert!(directory.observe(&valid));
        assert!(!directory.observe(&valid));
        assert_eq!(directory.advertised(), vec![name("SOLNET.APP1")]);
        directory.deactivate();
        directory.activate(&name("SOLNET.SNAB"));
        assert_eq!(directory.advertised(), vec![name("SOLNET.APP1")]);

        let wrong = SessionIdentity::new(name("SOLNET.APP2"), name("SNUSNU.PING"))
            .with_control_points(Some(name("SOLNET.OTHER")), Some(name("SNUSNU.SVC")))
            .unwrap();
        assert!(!directory.observe(&wrong));
    }
}
