//! Router-side XID identity for a selected LLC destination.
//!
//! The CP comes from route selection, never from the LLC guest's own XID.
//! The node ID is stable for one attachment and CP without an EE bootstrap.

use std::io;

use router_core::{session::QualifiedName, xid3::Xid3};
use transport_ws::wire;

use crate::auto_gateway_runtime::virtual_xid;

pub(crate) struct LlcTargetIdentity {
    cp: QualifiedName,
    seed: Vec<u8>,
}

impl LlcTargetIdentity {
    pub(crate) fn new(cp: Option<&QualifiedName>, attachment_id: &str) -> io::Result<Self> {
        let cp = cp.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "LLC destination CP is unknown")
        })?;
        if attachment_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LLC attachment ID is empty",
            ));
        }
        let seed = format!("snusnu-llc-target-v1\0{attachment_id}").into_bytes();
        Ok(Self {
            cp: cp.clone(),
            seed,
        })
    }

    pub(crate) fn from_wire(cp: Option<&wire::SnaName>, attachment_id: &str) -> io::Result<Self> {
        let cp = cp
            .map(|name| {
                QualifiedName::new(&name.netid, &name.name)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
            })
            .transpose()?;
        Self::new(cp.as_ref(), attachment_id)
    }

    pub(crate) fn xid(&self) -> io::Result<Xid3> {
        virtual_xid(
            &wire::SnaName {
                netid: self.cp.netid.clone(),
                name: self.cp.name.clone(),
            },
            &self.seed,
            None,
            None,
            1,
        )
    }

    pub(crate) fn node_seed(&self) -> &[u8] {
        &self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_cp_and_attachment_determine_stable_xid_without_ee() {
        let cp: QualifiedName = "QABOB.SNAB".parse().unwrap();
        let identity = LlcTargetIdentity::new(Some(&cp), "guest-a").unwrap();
        let xid = identity.xid().unwrap();
        assert_eq!(xid.cp_name().unwrap(), "QABOB.SNAB");
        assert_eq!(xid.node_id(), identity.xid().unwrap().node_id());
        assert_ne!(
            xid.node_id(),
            LlcTargetIdentity::new(Some(&cp), "guest-b")
                .unwrap()
                .xid()
                .unwrap()
                .node_id()
        );
    }

    #[test]
    fn unknown_target_cp_fails_explicitly() {
        assert_eq!(
            LlcTargetIdentity::new(None, "guest-a")
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
