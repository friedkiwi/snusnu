//! Live LLC probes and LU ownership for the EE session switch.
//!
//! Configured LU names are hints. An attachment becomes eligible only after
//! its own XID3 CP is verified and native management completes on the exact
//! LLC association that will later carry the user BIND.

use std::{
    collections::HashMap,
    io,
    time::{Duration, Instant},
};

use router_core::session::{QualifiedName, SessionUnit};

use crate::{
    auto_address::AutoProxyMacs,
    config::{parse_mac, RouterConfig},
    hpr_destination_directory::{
        configured_candidates, CandidateCarrier, ConfiguredCandidate, Destination,
    },
    hpr_local_llc::{HprToLlcProbe, HprToLlcSession},
    runtime::LlcPeer,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);

struct Attachment {
    id: String,
    interface: String,
    guest_mac: [u8; 6],
    proxy_mac: [u8; 6],
    expected_cp: Option<QualifiedName>,
    probe: Option<HprToLlcProbe>,
    active_user: bool,
    active_cp: Option<QualifiedName>,
    ready_logged: bool,
    retry_at: Instant,
}

pub(crate) struct HprLlcAttachments {
    attachments: Vec<Attachment>,
    candidates: Vec<ConfiguredCandidate>,
    source_cp: QualifiedName,
    seed: Vec<u8>,
}

/// Owned endpoint parameters for one exclusive, remotely sourced LLC user
/// session. The caller opens a fresh XID with the authenticated source CP.
pub(crate) struct ReservedLlcPeer {
    pub(crate) attachment_id: String,
    pub(crate) interface: String,
    pub(crate) guest_mac: [u8; 6],
    pub(crate) proxy_mac: [u8; 6],
    pub(crate) target_cp: QualifiedName,
}

impl ReservedLlcPeer {
    pub(crate) fn peer(&self) -> LlcPeer<'_> {
        LlcPeer {
            interface: &self.interface,
            guest_mac: self.guest_mac,
            proxy_mac: self.proxy_mac,
        }
    }
}

impl HprLlcAttachments {
    pub(crate) fn adjacent_cp(&self) -> &QualifiedName {
        &self.source_cp
    }

    pub(crate) fn new(
        config: &RouterConfig,
        source_cp: &QualifiedName,
        seed: &[u8],
    ) -> io::Result<Self> {
        let proxy_macs = AutoProxyMacs::from_ids(config.llc.iter().map(|llc| llc.id.as_str()))?;
        let attachments = config
            .llc
            .iter()
            .map(|llc| {
                Ok(Attachment {
                    id: llc.id.clone(),
                    interface: llc.interface.clone(),
                    guest_mac: parse_mac(&llc.guest_mac)?,
                    proxy_mac: proxy_macs
                        .get(&llc.id)
                        .ok_or_else(|| invalid("LLC proxy MAC missing"))?,
                    expected_cp: llc.local_cp.as_deref().map(parse_name).transpose()?,
                    probe: None,
                    active_user: false,
                    active_cp: None,
                    ready_logged: false,
                    retry_at: Instant::now(),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let candidates = configured_candidates(config)?
            .into_iter()
            .filter(|candidate| candidate.carrier == CandidateCarrier::Llc)
            .collect();
        Ok(Self {
            attachments,
            candidates,
            source_cp: source_cp.clone(),
            seed: seed.to_vec(),
        })
    }

    /// Drive each attachment independently. A failed or disconnected LLC
    /// peer cannot stop the other EE routes; its LUs disappear immediately
    /// and the association is retried after a bounded delay.
    pub(crate) fn pump(&mut self) {
        let now = Instant::now();
        for attachment in &mut self.attachments {
            if attachment.active_user || now < attachment.retry_at {
                continue;
            }
            let Some(target_cp) = attachment.expected_cp.as_ref() else {
                continue;
            };
            if attachment.probe.is_none() {
                let peer = LlcPeer {
                    interface: &attachment.interface,
                    guest_mac: attachment.guest_mac,
                    proxy_mac: attachment.proxy_mac,
                };
                match HprToLlcProbe::new(peer, &self.source_cp, target_cp, &self.seed) {
                    Ok(probe) => attachment.probe = Some(probe),
                    Err(error) => {
                        attachment.retry_at = now + RETRY_DELAY;
                        tracing::warn!(attachment = %attachment.id, interface = %attachment.interface,
                            guest_mac = %mac(attachment.guest_mac), expected_cp = %target_cp,
                            error = %error, "LLC probe could not open");
                        continue;
                    }
                }
            }
            if let Some(probe) = attachment.probe.as_mut() {
                match probe.pump() {
                    Ok(true) if !attachment.ready_logged => {
                        attachment.ready_logged = true;
                        tracing::info!(attachment = %attachment.id, interface = %attachment.interface,
                            guest_mac = %mac(attachment.guest_mac), verified_cp = %target_cp,
                            "LLC attachment verified for HPR local routes");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        attachment.probe = None;
                        attachment.ready_logged = false;
                        attachment.retry_at = now + RETRY_DELAY;
                        tracing::warn!(attachment = %attachment.id, interface = %attachment.interface,
                            guest_mac = %mac(attachment.guest_mac), expected_cp = %target_cp,
                            error = %error, "LLC probe lost XID or management proof");
                    }
                }
            }
        }
    }

    /// A snapshot for `HprDestinationDirectory::replace_owner`. It never
    /// includes a configured LU before the expected CP has been seen on the
    /// live association and native management is ready.
    pub(crate) fn verified_routes(&self) -> Vec<(QualifiedName, Destination)> {
        let candidates = self
            .attachments
            .iter()
            .flat_map(|attachment| {
                let observed = attachment
                    .probe
                    .as_ref()
                    .and_then(HprToLlcProbe::verified_target_cp)
                    .or(attachment.active_cp.as_ref());
                self.candidates
                    .iter()
                    .filter(move |candidate| candidate.attachment_id == attachment.id)
                    .filter_map(move |candidate| candidate.verify_cp(observed?))
            })
            .collect::<Vec<_>>();
        let mut unique = HashMap::<QualifiedName, Option<Destination>>::new();
        for (lu, destination) in candidates {
            unique
                .entry(lu)
                .and_modify(|owner| *owner = None)
                .or_insert(Some(destination));
        }
        unique
            .into_iter()
            .filter_map(|(lu, destination)| destination.map(|destination| (lu, destination)))
            .collect()
    }

    /// A configured LU can be pending on an answer-only LLC peer. The caller
    /// may retain RouteSetup until live XID/management proof arrives, but
    /// must never advertise this hint as verified reachability.
    pub(crate) fn has_candidate(&self, target_lu: &QualifiedName) -> bool {
        self.candidates.iter().any(|candidate| {
            &candidate.lu == target_lu
                && self.attachments.iter().any(|attachment| {
                    attachment.id == candidate.attachment_id && attachment.expected_cp.is_some()
                })
        })
    }

    pub(crate) fn take_session(
        &mut self,
        attachment_id: &str,
        source_lu: &QualifiedName,
        target_lu: &QualifiedName,
        bind: &SessionUnit,
    ) -> io::Result<Option<HprToLlcSession>> {
        let Some(attachment) = self.attachments.iter_mut().find(|a| a.id == attachment_id) else {
            return Err(invalid("unknown LLC attachment"));
        };
        if attachment.active_user {
            return Ok(None);
        }
        let Some(probe) = attachment.probe.as_ref() else {
            return Ok(None);
        };
        let Some(cp) = probe.verified_target_cp() else {
            return Ok(None);
        };
        let verified_cp = cp.clone();
        if !self.candidates.iter().any(|candidate| {
            candidate.attachment_id == attachment_id
                && candidate.lu == *target_lu
                && candidate.verify_cp(cp).is_some()
        }) {
            return Err(invalid("LLC target LU has no verified attachment binding"));
        }
        let probe = attachment.probe.take().unwrap();
        let session = match probe.into_session(source_lu, target_lu, bind) {
            Ok(session) => session,
            Err(error) => {
                attachment.retry_at = Instant::now() + RETRY_DELAY;
                return Err(error);
            }
        };
        attachment.active_user = true;
        attachment.active_cp = Some(verified_cp);
        Ok(Some(session))
    }

    /// Exclusively reserve a previously XID-verified attachment for a
    /// concentrator SessionV1 open. The old probe's source CP may belong to
    /// a different NETID, so it is closed before a new source-specific probe
    /// opens. Reachability is withdrawn until that new proof succeeds.
    pub(crate) fn reserve_external(
        &mut self,
        attachment_id: &str,
        target_lu: &QualifiedName,
    ) -> io::Result<Option<ReservedLlcPeer>> {
        let Some(attachment) = self.attachments.iter_mut().find(|a| a.id == attachment_id) else {
            return Err(invalid("unknown LLC attachment"));
        };
        if attachment.active_user {
            return Ok(None);
        }
        let Some(verified_cp) = attachment
            .probe
            .as_ref()
            .and_then(HprToLlcProbe::verified_target_cp)
            .cloned()
        else {
            return Ok(None);
        };
        if !self.candidates.iter().any(|candidate| {
            candidate.attachment_id == attachment_id
                && candidate.lu == *target_lu
                && candidate.verify_cp(&verified_cp).is_some()
        }) {
            return Err(invalid("LLC target LU has no verified attachment binding"));
        }
        let mut probe = attachment.probe.take().unwrap();
        probe.close()?;
        attachment.active_user = true;
        attachment.active_cp = None;
        attachment.ready_logged = false;
        Ok(Some(ReservedLlcPeer {
            attachment_id: attachment.id.clone(),
            interface: attachment.interface.clone(),
            guest_mac: attachment.guest_mac,
            proxy_mac: attachment.proxy_mac,
            target_cp: verified_cp,
        }))
    }

    /// Reinstate local reachability only after the new source-specific
    /// association has independently completed XID and management.
    pub(crate) fn mark_external_verified(
        &mut self,
        attachment_id: &str,
        target_cp: &QualifiedName,
    ) -> io::Result<()> {
        let attachment = self
            .attachments
            .iter_mut()
            .find(|a| a.id == attachment_id)
            .ok_or_else(|| invalid("unknown LLC attachment"))?;
        if !attachment.active_user || attachment.expected_cp.as_ref() != Some(target_cp) {
            return Err(invalid("LLC external proof disagrees with attachment"));
        }
        attachment.active_cp = Some(target_cp.clone());
        Ok(())
    }

    /// Call after the selected user session closes or resets. The next pump
    /// opens a fresh LLC association and repeats XID/management verification.
    pub(crate) fn release(&mut self, attachment_id: &str) {
        if let Some(attachment) = self.attachments.iter_mut().find(|a| a.id == attachment_id) {
            attachment.active_user = false;
            attachment.active_cp = None;
            attachment.ready_logged = false;
            attachment.probe = None;
            attachment.retry_at = Instant::now() + RETRY_DELAY;
        }
    }
}

fn parse_name(name: &str) -> io::Result<QualifiedName> {
    name.parse().map_err(|_| invalid("invalid LLC CP name"))
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
