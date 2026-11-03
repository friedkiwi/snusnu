//! Reachability evidence owned by one MPTN gateway attachment.
//!
//! TCP62 management connections normally close after the exchange, so their
//! close is not evidence that the configured peer IP became unreachable.
//! Instead, validated LU and CP observations have a bounded freshness lease. The
//! attachment withdraws all evidence on a transport failure, and its runtime
//! polls the lease clock even when no new TCP connection arrives.

use std::{
    collections::HashMap,
    io,
    time::{Duration, Instant},
};

use router_core::session::QualifiedName;

/// A peer that neither renews management nor starts a user association is
/// eventually removed from local and upstream route tables.
pub(crate) const DISCOVERY_LEASE: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Consumed when the shared route registry replaces per-runtime export maps.
pub(crate) struct MptnDiscoverySnapshot {
    pub(crate) revision: u64,
    pub(crate) routes: Vec<(QualifiedName, QualifiedName)>,
}

#[derive(Debug)]
pub(crate) struct MptnDiscovery {
    lease: Duration,
    routes: HashMap<QualifiedName, (QualifiedName, Instant)>,
    revision: u64,
    changed: bool,
}

impl MptnDiscovery {
    pub(crate) fn new(lease: Duration) -> io::Result<Self> {
        if lease.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero MPTN discovery lease",
            ));
        }
        Ok(Self {
            lease,
            routes: HashMap::new(),
            revision: 0,
            changed: false,
        })
    }

    /// Publish an LU/CP pair only after the full SNASVCMG exchange completes.
    /// The CP is taken from its structurally validated X'60' FQPCID.
    pub(crate) fn observe(
        &mut self,
        lu: QualifiedName,
        cp: QualifiedName,
        now: Instant,
    ) -> io::Result<()> {
        if lu.netid != cp.netid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MPTN LU/CP NETID mismatch",
            ));
        }
        let expires_at = now.checked_add(self.lease).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "MPTN discovery lease overflows clock",
            )
        })?;
        let changed = self
            .routes
            .get(&lu)
            .is_none_or(|(known_cp, _)| known_cp != &cp);
        self.routes.insert(lu, (cp, expires_at));
        if changed {
            self.mark_changed()?;
        }
        Ok(())
    }

    /// A user BIND can renew an existing management proof, but cannot create one.
    pub(crate) fn refresh_if_known(
        &mut self,
        lu: &QualifiedName,
        cp: &QualifiedName,
        now: Instant,
    ) -> io::Result<bool> {
        let Some((known_cp, expires_at)) = self.routes.get_mut(lu) else {
            return Ok(false);
        };
        if known_cp != cp || *expires_at <= now {
            return Ok(false);
        }
        *expires_at = now.checked_add(self.lease).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "MPTN discovery lease overflows clock",
            )
        })?;
        Ok(true)
    }

    pub(crate) fn expire(&mut self, now: Instant) -> io::Result<()> {
        let before = self.routes.len();
        self.routes.retain(|_, (_, expires_at)| *expires_at > now);
        if self.routes.len() != before {
            self.mark_changed()?;
        }
        Ok(())
    }

    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.routes.values().map(|(_, expiry)| *expiry).min()
    }

    pub(crate) fn withdraw_all(&mut self) -> io::Result<()> {
        if !self.routes.is_empty() {
            self.routes.clear();
            self.mark_changed()?;
        }
        Ok(())
    }

    /// Returns the full attachment snapshot after every membership change.
    /// Existing LU refreshes extend leases without needless route revisions.
    pub(crate) fn take_changed_snapshot(&mut self) -> Option<MptnDiscoverySnapshot> {
        if !std::mem::take(&mut self.changed) {
            return None;
        }
        let mut routes = self
            .routes
            .iter()
            .map(|(lu, (cp, _))| (lu.clone(), cp.clone()))
            .collect::<Vec<_>>();
        routes.sort_by(|left, right| {
            (&left.0.netid, &left.0.name).cmp(&(&right.0.netid, &right.0.name))
        });
        Some(MptnDiscoverySnapshot {
            revision: self.revision,
            routes,
        })
    }

    fn mark_changed(&mut self) -> io::Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| io::Error::other("MPTN discovery revision exhausted"))?;
        self.changed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lu(name: &str) -> QualifiedName {
        name.parse().unwrap()
    }

    #[test]
    fn refreshed_lu_survives_old_deadline_without_extra_revision() {
        let start = Instant::now();
        let mut discovery = MptnDiscovery::new(Duration::from_secs(10)).unwrap();
        discovery
            .observe(lu("NETA.LUA"), lu("NETA.CPA"), start)
            .unwrap();
        assert_eq!(discovery.take_changed_snapshot().unwrap().revision, 1);
        discovery
            .observe(
                lu("NETA.LUA"),
                lu("NETA.CPA"),
                start + Duration::from_secs(8),
            )
            .unwrap();
        assert_eq!(
            discovery.next_expiry(),
            Some(start + Duration::from_secs(18))
        );
        discovery.expire(start + Duration::from_secs(11)).unwrap();
        assert!(discovery.take_changed_snapshot().is_none());
        discovery.expire(start + Duration::from_secs(18)).unwrap();
        assert_eq!(
            discovery.take_changed_snapshot().unwrap(),
            MptnDiscoverySnapshot {
                revision: 2,
                routes: Vec::new(),
            }
        );
    }

    #[test]
    fn failure_withdraws_entire_attachment_atomically() {
        let start = Instant::now();
        let mut discovery = MptnDiscovery::new(Duration::from_secs(10)).unwrap();
        discovery
            .observe(lu("NETA.LUB"), lu("NETA.CPA"), start)
            .unwrap();
        discovery
            .observe(lu("NETA.LUA"), lu("NETA.CPA"), start)
            .unwrap();
        assert_eq!(
            discovery.take_changed_snapshot().unwrap().routes,
            vec![
                (lu("NETA.LUA"), lu("NETA.CPA")),
                (lu("NETA.LUB"), lu("NETA.CPA"))
            ]
        );
        discovery.withdraw_all().unwrap();
        assert_eq!(
            discovery.take_changed_snapshot().unwrap(),
            MptnDiscoverySnapshot {
                revision: 3,
                routes: Vec::new(),
            }
        );
        discovery.withdraw_all().unwrap();
        assert!(discovery.take_changed_snapshot().is_none());
    }

    #[test]
    fn user_bind_only_refreshes_matching_completed_management_identity() {
        let start = Instant::now();
        let mut discovery = MptnDiscovery::new(Duration::from_secs(10)).unwrap();
        let peer_lu = lu("NETA.LUA");
        let peer_cp = lu("NETA.CPA");
        assert!(!discovery
            .refresh_if_known(&peer_lu, &peer_cp, start)
            .unwrap());
        discovery
            .observe(peer_lu.clone(), peer_cp.clone(), start)
            .unwrap();
        assert!(!discovery
            .refresh_if_known(&peer_lu, &lu("NETA.CPB"), start + Duration::from_secs(5))
            .unwrap());
        assert!(discovery
            .refresh_if_known(&peer_lu, &peer_cp, start + Duration::from_secs(5))
            .unwrap());
        assert_eq!(
            discovery.next_expiry(),
            Some(start + Duration::from_secs(15))
        );
        discovery.expire(start + Duration::from_secs(16)).unwrap();
        assert!(!discovery
            .refresh_if_known(&peer_lu, &peer_cp, start + Duration::from_secs(16))
            .unwrap());
    }
}
