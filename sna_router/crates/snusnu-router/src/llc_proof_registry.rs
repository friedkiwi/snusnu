//! Live LLC identity evidence, scoped to the association that supplied it.
//!
//! A single guest MAC can use several proxy MACs at once. Closing one LLC2
//! association must not withdraw CP/LU reachability still proved by another.

use std::{
    collections::{HashMap, HashSet},
    io,
};

use router_core::session::QualifiedName;

use crate::routing::PortId;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct AssociationId {
    /// Distinguishes fabric sessions from gateway-local association numbers.
    pub(crate) origin: String,
    pub(crate) id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LlcProofSnapshot {
    pub(crate) cp: QualifiedName,
    pub(crate) lus: Vec<QualifiedName>,
    pub(crate) lu62: Vec<QualifiedName>,
    pub(crate) associations: Vec<AssociationId>,
}

#[derive(Default)]
struct AssociationProof {
    cp: Option<QualifiedName>,
    lus: HashSet<QualifiedName>,
    lu62: HashSet<QualifiedName>,
}

#[derive(Default)]
pub(crate) struct LlcProofRegistry {
    attachments: HashMap<PortId, HashMap<AssociationId, AssociationProof>>,
}

impl LlcProofRegistry {
    pub(crate) fn observe_cp(
        &mut self,
        attachment: &PortId,
        association: AssociationId,
        cp: &str,
    ) -> io::Result<()> {
        let cp = parse_name(cp)?;
        let proof = self
            .attachments
            .entry(attachment.clone())
            .or_default()
            .entry(association)
            .or_default();
        if proof.cp.as_ref() != Some(&cp) {
            proof.cp = Some(cp);
            proof.lus.clear();
            proof.lu62.clear();
        }
        Ok(())
    }

    pub(crate) fn observe_lu(
        &mut self,
        attachment: &PortId,
        association: &AssociationId,
        lu: &str,
    ) -> io::Result<()> {
        let lu = parse_name(lu)?;
        let cp = self
            .attachments
            .get_mut(attachment)
            .and_then(|proofs| proofs.get_mut(association))
            .and_then(|proof| proof.cp.as_ref().map(|cp| (cp, &mut proof.lus)))
            .ok_or_else(|| invalid("LLC LU has no live CP proof on this association"))?;
        if lu.netid != cp.0.netid {
            return Err(invalid("LLC LU NETID differs from its live CP"));
        }
        cp.1.insert(lu);
        Ok(())
    }

    pub(crate) fn observe_lu62(
        &mut self,
        attachment: &PortId,
        association: &AssociationId,
        lu: &str,
    ) -> io::Result<()> {
        self.observe_lu(attachment, association, lu)?;
        let lu = parse_name(lu)?;
        self.attachments
            .get_mut(attachment)
            .unwrap()
            .get_mut(association)
            .unwrap()
            .lu62
            .insert(lu);
        Ok(())
    }

    pub(crate) fn withdraw(&mut self, attachment: &PortId, association: &AssociationId) -> bool {
        let Some(proofs) = self.attachments.get_mut(attachment) else {
            return false;
        };
        let removed = proofs.remove(association).is_some();
        if proofs.is_empty() {
            self.attachments.remove(attachment);
        }
        removed
    }

    /// A CP conflict fails closed until one association withdraws. Unknown
    /// associations do not prove reachability. Only the matching live proofs
    /// contribute their LU observations.
    pub(crate) fn snapshot(&self, attachment: &PortId) -> Option<LlcProofSnapshot> {
        let proofs = self.attachments.get(attachment)?;
        let mut cp = None;
        let mut lus = HashSet::new();
        let mut lu62 = HashSet::new();
        let mut associations = Vec::new();
        for (id, proof) in proofs {
            let Some(observed_cp) = &proof.cp else {
                continue;
            };
            if cp.as_ref().is_some_and(|existing| existing != observed_cp) {
                return None;
            }
            cp = Some(observed_cp.clone());
            lus.extend(proof.lus.iter().cloned());
            lu62.extend(proof.lu62.iter().cloned());
            associations.push(id.clone());
        }
        let mut lus = lus.into_iter().collect::<Vec<_>>();
        lus.sort_by(|a, b| (&a.netid, &a.name).cmp(&(&b.netid, &b.name)));
        let mut lu62 = lu62.into_iter().collect::<Vec<_>>();
        lu62.sort_by(|a, b| (&a.netid, &a.name).cmp(&(&b.netid, &b.name)));
        associations.sort();
        Some(LlcProofSnapshot {
            cp: cp?,
            lus,
            lu62,
            associations,
        })
    }
}

fn parse_name(value: &str) -> io::Result<QualifiedName> {
    value
        .parse()
        .map_err(|_| invalid("invalid LLC CP or LU name"))
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(origin: &str, id: u64) -> AssociationId {
        AssociationId {
            origin: origin.into(),
            id,
        }
    }

    #[test]
    fn withdrawal_keeps_proof_from_another_live_association() {
        let attachment = PortId::new("llc-a");
        let mut registry = LlcProofRegistry::default();
        let first = id("fabric", 1);
        let second = id("fabric", 2);
        registry
            .observe_cp(&attachment, first.clone(), "SOLNET.SNAA")
            .unwrap();
        registry
            .observe_lu(&attachment, &first, "SOLNET.APP1")
            .unwrap();
        registry
            .observe_cp(&attachment, second.clone(), "SOLNET.SNAA")
            .unwrap();
        registry
            .observe_lu(&attachment, &second, "SOLNET.APP2")
            .unwrap();
        assert_eq!(registry.snapshot(&attachment).unwrap().lus.len(), 2);
        assert!(registry.withdraw(&attachment, &first));
        let snapshot = registry.snapshot(&attachment).unwrap();
        assert_eq!(snapshot.cp, "SOLNET.SNAA".parse().unwrap());
        assert_eq!(snapshot.lus, vec!["SOLNET.APP2".parse().unwrap()]);
        assert_eq!(snapshot.associations, vec![second.clone()]);
        assert!(registry.withdraw(&attachment, &second));
        assert!(registry.snapshot(&attachment).is_none());
    }

    #[test]
    fn conflicting_cp_fails_closed_then_recovers_on_withdraw() {
        let attachment = PortId::new("llc-a");
        let mut registry = LlcProofRegistry::default();
        let first = id("fabric", 1);
        let second = id("gateway:mptn-a", 1);
        registry
            .observe_cp(&attachment, first.clone(), "SOLNET.SNAA")
            .unwrap();
        registry
            .observe_cp(&attachment, second.clone(), "SOLNET.OTHER")
            .unwrap();
        assert!(registry.snapshot(&attachment).is_none());
        assert!(registry.withdraw(&attachment, &second));
        assert_eq!(
            registry.snapshot(&attachment).unwrap().cp,
            "SOLNET.SNAA".parse().unwrap()
        );
    }

    #[test]
    fn cp_change_clears_old_lu_and_lu_needs_same_association_cp() {
        let attachment = PortId::new("llc-a");
        let mut registry = LlcProofRegistry::default();
        let association = id("fabric", 1);
        assert_eq!(
            registry
                .observe_lu(&attachment, &association, "SOLNET.APP1")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
        );
        registry
            .observe_cp(&attachment, association.clone(), "SOLNET.SNAA")
            .unwrap();
        registry
            .observe_lu(&attachment, &association, "SOLNET.APP1")
            .unwrap();
        registry
            .observe_cp(&attachment, association.clone(), "QABOB.SNAB")
            .unwrap();
        assert!(registry.snapshot(&attachment).unwrap().lus.is_empty());
        assert_eq!(
            registry
                .observe_lu(&attachment, &association, "SOLNET.APP1")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
        );
    }

    #[test]
    fn lu62_capability_lives_only_while_bound_association_is_live() {
        let attachment = PortId::new("llc-a");
        let mut registry = LlcProofRegistry::default();
        let cp_only = id("fabric", 1);
        let bound = id("llc_upstream", 2);
        for owner in [&cp_only, &bound] {
            registry
                .observe_cp(&attachment, (*owner).clone(), "LOCAL.CPA")
                .unwrap();
        }
        registry
            .observe_lu62(&attachment, &bound, "LOCAL.LUA")
            .unwrap();
        let snapshot = registry.snapshot(&attachment).unwrap();
        assert_eq!(snapshot.lu62, vec!["LOCAL.LUA".parse().unwrap()]);
        registry.withdraw(&attachment, &bound);
        let snapshot = registry.snapshot(&attachment).unwrap();
        assert!(snapshot.lu62.is_empty());
        assert!(snapshot.lus.is_empty());
        assert_eq!(snapshot.cp, "LOCAL.CPA".parse().unwrap());
    }
}
