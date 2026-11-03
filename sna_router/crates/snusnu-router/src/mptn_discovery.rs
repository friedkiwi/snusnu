//! Reachability evidence owned by one MPTN gateway attachment.
//!
//! TCP62 management connections normally close after the exchange, so their
//! close is not evidence that the configured peer IP became unreachable.
//! Instead, validated LU observations have a bounded freshness lease. The
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
    pub(crate) lus: Vec<QualifiedName>,
}

#[derive(Debug)]
pub(crate) struct MptnDiscovery {
    lease: Duration,
    lus: HashMap<QualifiedName, Instant>,
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
            lus: HashMap::new(),
            revision: 0,
            changed: false,
        })
    }

    /// Refresh one LU learned from a validated TCP62 management exchange or
    /// user BIND. CP ownership is intentionally absent: TCP62 does not prove
    /// the adjacent CP, which remains a separate operator assertion.
    pub(crate) fn observe(&mut self, lu: QualifiedName, now: Instant) -> io::Result<()> {
        let expires_at = now.checked_add(self.lease).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "MPTN discovery lease overflows clock",
            )
        })?;
        if self.lus.insert(lu, expires_at).is_none() {
            self.mark_changed()?;
        }
        Ok(())
    }

    pub(crate) fn expire(&mut self, now: Instant) -> io::Result<()> {
        let before = self.lus.len();
        self.lus.retain(|_, expires_at| *expires_at > now);
        if self.lus.len() != before {
            self.mark_changed()?;
        }
        Ok(())
    }

    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.lus.values().copied().min()
    }

    pub(crate) fn withdraw_all(&mut self) -> io::Result<()> {
        if !self.lus.is_empty() {
            self.lus.clear();
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
        let mut lus = self.lus.keys().cloned().collect::<Vec<_>>();
        lus.sort_by(|left, right| (&left.netid, &left.name).cmp(&(&right.netid, &right.name)));
        Some(MptnDiscoverySnapshot {
            revision: self.revision,
            lus,
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
        discovery.observe(lu("NETA.LUA"), start).unwrap();
        assert_eq!(discovery.take_changed_snapshot().unwrap().revision, 1);
        discovery
            .observe(lu("NETA.LUA"), start + Duration::from_secs(8))
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
                lus: Vec::new(),
            }
        );
    }

    #[test]
    fn failure_withdraws_entire_attachment_atomically() {
        let start = Instant::now();
        let mut discovery = MptnDiscovery::new(Duration::from_secs(10)).unwrap();
        discovery.observe(lu("NETA.LUB"), start).unwrap();
        discovery.observe(lu("NETA.LUA"), start).unwrap();
        assert_eq!(
            discovery.take_changed_snapshot().unwrap().lus,
            vec![lu("NETA.LUA"), lu("NETA.LUB")]
        );
        discovery.withdraw_all().unwrap();
        assert_eq!(
            discovery.take_changed_snapshot().unwrap(),
            MptnDiscoverySnapshot {
                revision: 3,
                lus: Vec::new(),
            }
        );
        discovery.withdraw_all().unwrap();
        assert!(discovery.take_changed_snapshot().is_none());
    }
}
