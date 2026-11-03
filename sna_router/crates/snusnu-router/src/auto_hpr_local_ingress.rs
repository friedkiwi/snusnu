//! LLC-originated sessions selected for one adjacent EE peer.
//!
//! A listener reserves the target's local proxy MAC at the first XID. The
//! private native converter proves the source CP and parses a user BIND
//! before the shared HPR reverse runtime receives the SessionSource.

use std::{collections::HashSet, io};

use crate::{
    auto_llc::LlcAutoListener,
    config::{self, LlcConfig},
    hpr_destination_directory::{Destination, HprDestinationDirectory},
    hpr_local_llc_ingress::LocalLlcIngress,
    hpr_session_source::{SessionSource, SourceUpdate},
};
use router_core::session::{QualifiedName, SessionEvent, SessionIdentity};

struct Listener {
    id: String,
    port: LlcAutoListener,
}

struct Pending {
    listener: usize,
    proxy_mac: [u8; 6],
    source: LocalLlcIngress,
}

pub(crate) struct ReadyLocalLlc {
    pub(crate) ingress_id: String,
    pub(crate) target_ee_id: String,
    pub(crate) proxy_mac: [u8; 6],
    pub(crate) identity: SessionIdentity,
    pub(crate) source: Box<dyn SessionSource>,
}

pub(crate) struct LocalToHprRuntime {
    target_ee_id: String,
    target_cp: QualifiedName,
    target_proxy_mac: [u8; 6],
    seed: Vec<u8>,
    listeners: Vec<Listener>,
    pending: Vec<Pending>,
    active: HashSet<(usize, [u8; 6])>,
}

impl LocalToHprRuntime {
    pub(crate) fn new(
        llc: &[LlcConfig],
        target_ee_id: &str,
        target_cp: QualifiedName,
        target_proxy_mac: [u8; 6],
        seed: &[u8],
    ) -> io::Result<Self> {
        if target_ee_id.is_empty() || seed.is_empty() {
            return Err(invalid("local EE target ID or identity seed is empty"));
        }
        let mut listeners = Vec::with_capacity(llc.len());
        for attachment in llc {
            let mut port = LlcAutoListener::open(
                &attachment.interface,
                config::parse_mac(&attachment.guest_mac)?,
            )?;
            port.allow_native_proxy_mac(target_proxy_mac)?;
            listeners.push(Listener {
                id: attachment.id.clone(),
                port,
            });
        }
        Ok(Self {
            target_ee_id: target_ee_id.to_owned(),
            target_cp,
            target_proxy_mac,
            seed: seed.to_vec(),
            listeners,
            pending: Vec::new(),
            active: HashSet::new(),
        })
    }

    /// Poll one offer per listener, then advance bounded pending associations.
    /// A returned source retains its first BIND until ReverseRuntime accepts
    /// it into SessionFabric. Other sessions remain owned by this manager.
    pub(crate) fn poll_ready(
        &mut self,
        directory: &HprDestinationDirectory,
    ) -> io::Result<Option<ReadyLocalLlc>> {
        for (index, listener) in self.listeners.iter_mut().enumerate() {
            let Some(offer) = listener.port.poll_offer()? else {
                continue;
            };
            if offer.proxy_mac != self.target_proxy_mac {
                listener.port.release(offer.proxy_mac);
                continue;
            }
            let proxy_mac = offer.proxy_mac;
            match LocalLlcIngress::from_offer(offer, self.target_cp.clone(), &self.seed) {
                Ok(source) => self.pending.push(Pending {
                    listener: index,
                    proxy_mac,
                    source,
                }),
                Err(error) => {
                    listener.port.release(proxy_mac);
                    tracing::warn!(attachment = %listener.id, error = %error,
                        "LLC-to-EE native association rejected");
                }
            }
        }
        let mut index = 0;
        while index < self.pending.len() {
            let result = self.pending[index].source.poll();
            match result {
                Ok(Some(SourceUpdate::Event(SessionEvent::BindRequest(_)))) => {
                    let Some(identity) = self.pending[index].source.identity().cloned() else {
                        self.reject(index, "LLC BIND lacks verified identity")?;
                        continue;
                    };
                    if !matches_ee_target(&identity, directory, &self.target_ee_id, &self.target_cp)
                    {
                        self.reject(index, "LLC BIND target is not a live EE LU")?;
                        continue;
                    }
                    let pending = self.pending.remove(index);
                    self.active.insert((pending.listener, pending.proxy_mac));
                    let ingress_id = self.listeners[pending.listener].id.clone();
                    tracing::info!(ingress = %ingress_id, target = %self.target_ee_id,
                        source_lu = %identity.source_lu, target_lu = %identity.target_lu,
                        "verified local LLC session selected for EE");
                    return Ok(Some(ReadyLocalLlc {
                        ingress_id,
                        target_ee_id: self.target_ee_id.clone(),
                        proxy_mac: pending.proxy_mac,
                        identity,
                        source: Box::new(pending.source),
                    }));
                }
                Ok(Some(SourceUpdate::Closed)) => {
                    self.reject(index, "LLC association closed before user BIND")?;
                }
                Ok(Some(SourceUpdate::Event(_))) => {
                    self.reject(index, "LLC association sent data before user BIND")?;
                }
                Ok(None) => index += 1,
                Err(error) => {
                    tracing::warn!(attachment = %self.listeners[self.pending[index].listener].id,
                        error = %error, "LLC-to-EE association failed before user BIND");
                    self.reject(index, "LLC association failed")?;
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn release(&mut self, ingress_id: &str, proxy_mac: [u8; 6]) -> io::Result<()> {
        let index = self
            .listeners
            .iter()
            .position(|listener| listener.id == ingress_id)
            .ok_or_else(|| invalid("unknown LLC ingress attachment"))?;
        if !self.active.remove(&(index, proxy_mac)) {
            return Err(invalid("LLC ingress reservation is not active"));
        }
        self.listeners[index].port.release(proxy_mac);
        Ok(())
    }

    fn reject(&mut self, index: usize, reason: &'static str) -> io::Result<()> {
        let mut pending = self.pending.remove(index);
        let listener = &mut self.listeners[pending.listener];
        if let Err(error) = pending.source.close() {
            tracing::warn!(attachment = %listener.id, error = %error,
                "failed to close rejected LLC-to-EE association");
        }
        listener.port.release(pending.proxy_mac);
        tracing::warn!(attachment = %listener.id, proxy_mac = ?pending.proxy_mac, reason,
            "LLC-to-EE association rejected");
        Ok(())
    }
}

fn matches_ee_target(
    identity: &SessionIdentity,
    directory: &HprDestinationDirectory,
    target_ee_id: &str,
    target_cp: &QualifiedName,
) -> bool {
    matches!(
        directory.resolve_lu(&identity.target_lu),
        Some(Destination::Ee { hosting_cp, attachment_id })
            if attachment_id == target_ee_id
                && hosting_cp == *target_cp
                && identity.target_cp.as_ref() == Some(target_cp)
    )
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_only_to_verified_ee_lu_and_exact_attachment() {
        let source_cp: QualifiedName = "SOLNET.SNAA".parse().unwrap();
        let target_cp: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let identity = SessionIdentity::new(source_cp.clone(), target_cp.clone())
            .with_control_points(Some(source_cp), Some(target_cp.clone()))
            .unwrap();
        let mut directory = HprDestinationDirectory::new();
        assert!(!matches_ee_target(&identity, &directory, "ee", &target_cp));
        directory
            .replace_owner(
                "ee",
                [(
                    target_cp.clone(),
                    Destination::Ee {
                        hosting_cp: target_cp.clone(),
                        attachment_id: "ee".into(),
                    },
                )],
            )
            .unwrap();
        assert!(matches_ee_target(&identity, &directory, "ee", &target_cp));
        assert!(!matches_ee_target(
            &identity, &directory, "other", &target_cp
        ));
        directory.withdraw_owner("ee").unwrap();
        assert!(!matches_ee_target(&identity, &directory, "ee", &target_cp));
    }
}
