//! Live TCP62 attachments for EE's local session switch.
//!
//! TCP62 management proves the peer LU and NETID, but its FQPCID repeats that
//! LU and does not disclose a separate CP. A configured `peer_cp` is therefore
//! an operator trust anchor. Routes remain unpublished until management has
//! disclosed the exact configured target LU on the same gateway, and an unset
//! `peer_cp` never becomes an inferred CP.

use std::{
    collections::HashSet,
    io,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use router_core::session::{QualifiedName, SessionIdentity, SessionUnit};
use transport_ip_sna::mptn_ingress::IngressOffer;

use crate::{
    auto_gateway_runtime::AutoMptnGateway,
    config::RouterConfig,
    hpr_destination_directory::{
        configured_candidates, CandidateCarrier, ConfiguredCandidate, Destination,
    },
    hpr_local_mptn::HprToMptnSession,
};

struct Attachment<'a> {
    gateway: AutoMptnGateway<'a>,
    trusted_peer_cp: Option<QualifiedName>,
    management_source_lu: Option<QualifiedName>,
    management_target_lu: Option<QualifiedName>,
    probe_result: Option<Receiver<io::Result<()>>>,
    probe_worker: Option<JoinHandle<()>>,
    retry_at: Instant,
    poll_retry_at: Instant,
    observed_peer_lus: HashSet<QualifiedName>,
    active_user: bool,
}

pub(crate) struct MptnIngressOffer {
    pub(crate) gateway_id: String,
    pub(crate) association: u64,
    pub(crate) offer: IngressOffer,
}

pub(crate) struct HprMptnAttachments<'a> {
    attachments: Vec<Attachment<'a>>,
    candidates: Vec<ConfiguredCandidate>,
}

impl<'a> HprMptnAttachments<'a> {
    pub(crate) fn new(config: &'a RouterConfig) -> io::Result<Self> {
        let attachments = config
            .mptn_gateway
            .iter()
            .map(|entry| {
                let trusted_peer_cp = if entry.peer_cp.is_empty() {
                    None
                } else {
                    Some(parse_name(&entry.peer_cp)?)
                };
                let management_source_lu = (!entry.source_lu.is_empty())
                    .then(|| parse_name(&entry.source_lu))
                    .transpose()?;
                let management_target_lu = (!entry.destination_lu.is_empty())
                    .then(|| parse_name(&entry.destination_lu))
                    .transpose()?;
                Ok(Attachment {
                    gateway: AutoMptnGateway::bind(entry)?,
                    trusted_peer_cp,
                    management_source_lu,
                    management_target_lu,
                    probe_result: None,
                    probe_worker: None,
                    retry_at: Instant::now(),
                    poll_retry_at: Instant::now(),
                    observed_peer_lus: HashSet::new(),
                    active_user: false,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let candidates = configured_candidates(config)?
            .into_iter()
            .filter(|candidate| candidate.carrier == CandidateCarrier::Mptn)
            .collect();
        Ok(Self {
            attachments,
            candidates,
        })
    }

    /// Poll all TCP62 listeners even while an EE user session owns a gateway's
    /// UDP lease. The underlying gateway then polls TCP only and never steals
    /// the user session's OOB packets.
    pub(crate) fn poll_once(&mut self) -> io::Result<Vec<MptnIngressOffer>> {
        let mut offered = Vec::new();
        for attachment in &mut self.attachments {
            let bind = if Instant::now() < attachment.poll_retry_at {
                None
            } else {
                match attachment.gateway.poll_once() {
                    Ok(bind) => bind,
                    Err(error) => {
                        attachment.observed_peer_lus.clear();
                        attachment.poll_retry_at = Instant::now() + Duration::from_secs(1);
                        tracing::warn!(gateway = attachment.gateway.id(), error = %error,
                            "MPTN gateway poll failed; learned routes withdrawn");
                        None
                    }
                }
            };
            for (peer_lu, local_lu) in attachment.gateway.take_management_lus() {
                let peer_lu = parse_name(&peer_lu)?;
                let local_lu = parse_name(&local_lu)?;
                if let Some(trusted_cp) = &attachment.trusted_peer_cp {
                    if peer_lu.netid != trusted_cp.netid {
                        tracing::warn!(gateway = attachment.gateway.id(), peer_lu = %peer_lu,
                            configured_peer_cp = %trusted_cp,
                            "MPTN management peer NETID disagrees with operator CP assertion");
                        continue;
                    }
                }
                tracing::info!(gateway = attachment.gateway.id(), peer_lu = %peer_lu,
                    local_lu = %local_lu, "MPTN management disclosed adjacent LU");
                attachment.observed_peer_lus.insert(peer_lu);
            }
            attachment.poll_probe();
            attachment.start_probe_if_needed()?;
            if let Some((association, offer)) = bind {
                offered.push(MptnIngressOffer {
                    gateway_id: attachment.gateway.id().to_owned(),
                    association,
                    offer,
                });
            }
        }
        Ok(offered)
    }

    /// Only live management LU evidence plus an explicit operator CP
    /// assertion may create an EE RouteSetup destination. The CP is not
    /// claimed to have come from TCP62's wire format.
    pub(crate) fn trusted_routes(&self) -> Vec<(QualifiedName, Destination)> {
        self.attachments
            .iter()
            .filter(|attachment| !attachment.active_user && attachment.gateway.udp_available())
            .flat_map(|attachment| {
                let gateway_id = attachment.gateway.id();
                self.candidates
                    .iter()
                    .filter(move |candidate| candidate.attachment_id == gateway_id)
                    .filter_map(move |candidate| {
                        route_for_candidate(
                            candidate,
                            attachment.trusted_peer_cp.as_ref(),
                            &attachment.observed_peer_lus,
                        )
                    })
            })
            .collect()
    }

    pub(crate) fn take_session(
        &mut self,
        gateway_id: &str,
        identity: &SessionIdentity,
        bind: &SessionUnit,
        timeout: Duration,
    ) -> io::Result<Option<HprToMptnSession>> {
        let attachment = self
            .attachments
            .iter_mut()
            .find(|entry| entry.gateway.id() == gateway_id)
            .ok_or_else(|| invalid("unknown MPTN attachment"))?;
        if attachment.active_user || !attachment.gateway.udp_available() {
            return Ok(None);
        }
        let cp = attachment
            .trusted_peer_cp
            .as_ref()
            .ok_or_else(|| invalid("MPTN peer CP has no operator trust anchor"))?;
        if !attachment.observed_peer_lus.contains(&identity.target_lu)
            || identity.target_cp.as_ref() != Some(cp)
            || !self.candidates.iter().any(|candidate| {
                candidate.attachment_id == gateway_id
                    && candidate.lu == identity.target_lu
                    && candidate.verify_cp(cp).is_some()
            })
        {
            return Err(invalid(
                "MPTN target LU has no live management and trusted CP binding",
            ));
        }
        let endpoint = attachment.gateway.outbound_endpoint();
        let udp = attachment.gateway.lease_udp()?;
        let session = match HprToMptnSession::new(endpoint, udp, identity, bind, timeout) {
            Ok(session) => session,
            Err(error) => {
                attachment.gateway.release_udp();
                return Err(error);
            }
        };
        attachment.active_user = true;
        Ok(Some(session))
    }

    pub(crate) fn release(&mut self, gateway_id: &str) {
        if let Some(attachment) = self
            .attachments
            .iter_mut()
            .find(|entry| entry.gateway.id() == gateway_id)
        {
            attachment.active_user = false;
            attachment.gateway.release_udp();
        }
    }

    pub(crate) fn reject_offer(
        &mut self,
        gateway_id: &str,
        association: u64,
        reason: &str,
    ) -> io::Result<()> {
        self.attachments
            .iter_mut()
            .find(|entry| entry.gateway.id() == gateway_id)
            .ok_or_else(|| invalid("unknown MPTN attachment"))?
            .gateway
            .reject_offer(association, reason)
    }
}

impl Attachment<'_> {
    fn poll_probe(&mut self) {
        let Some(receiver) = self.probe_result.as_ref() else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(io::Error::other(
                "MPTN management probe exited without result",
            )),
        };
        self.probe_result = None;
        if let Some(worker) = self.probe_worker.take() {
            if worker.join().is_err() {
                tracing::warn!(
                    gateway = self.gateway.id(),
                    "MPTN management probe panicked"
                );
                self.retry_at = Instant::now() + Duration::from_secs(5);
                return;
            }
        }
        match result {
            Ok(()) => {
                let target = self.management_target_lu.as_ref().unwrap();
                if self
                    .trusted_peer_cp
                    .as_ref()
                    .is_some_and(|cp| cp.netid != target.netid)
                {
                    tracing::warn!(gateway = self.gateway.id(), target_lu = %target,
                        "MPTN management probe LU NETID differs from configured peer CP");
                    self.retry_at = Instant::now() + Duration::from_secs(5);
                    return;
                }
                tracing::info!(gateway = self.gateway.id(), target_lu = %target,
                    "outbound MPTN management proved adjacent LU");
                self.observed_peer_lus.insert(target.clone());
            }
            Err(error) => {
                tracing::debug!(gateway = self.gateway.id(), error = %error,
                    "outbound MPTN management probe did not establish LU reachability");
                self.retry_at = Instant::now() + Duration::from_secs(5);
            }
        }
    }

    fn start_probe_if_needed(&mut self) -> io::Result<()> {
        let (Some(source), Some(target)) = (
            self.management_source_lu.as_ref(),
            self.management_target_lu.as_ref(),
        ) else {
            return Ok(());
        };
        if self.probe_result.is_some()
            || self.observed_peer_lus.contains(target)
            || Instant::now() < self.retry_at
        {
            return Ok(());
        }
        let source = source.to_string();
        let target = target.to_string();
        let endpoint = self.gateway.outbound_endpoint();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("sna-mptn-management-probe".into())
            .spawn(move || {
                let result =
                    endpoint.establish_v5_management(Duration::from_secs(5), &source, &target);
                let _ = sender.send(result);
            })?;
        self.probe_result = Some(receiver);
        self.probe_worker = Some(worker);
        Ok(())
    }
}

fn route_for_candidate(
    candidate: &ConfiguredCandidate,
    trusted_cp: Option<&QualifiedName>,
    observed_lus: &HashSet<QualifiedName>,
) -> Option<(QualifiedName, Destination)> {
    let cp = trusted_cp?;
    if candidate.carrier != CandidateCarrier::Mptn || !observed_lus.contains(&candidate.lu) {
        return None;
    }
    candidate.verify_cp(cp)
}

fn parse_name(value: &str) -> io::Result<QualifiedName> {
    value
        .parse()
        .map_err(|_| invalid("invalid MPTN qualified name"))
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_lu_needs_explicit_same_netid_cp_assertion() {
        let lu: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let candidate = ConfiguredCandidate {
            lu: lu.clone(),
            cp_hint: None,
            attachment_id: "mptn-a".into(),
            carrier: CandidateCarrier::Mptn,
        };
        let cp: QualifiedName = "SOLNET.CP400".parse().unwrap();
        let wrong_cp: QualifiedName = "OTHER.CP400".parse().unwrap();
        let mut observed = HashSet::new();
        assert!(route_for_candidate(&candidate, Some(&cp), &observed).is_none());
        observed.insert(lu.clone());
        assert!(route_for_candidate(&candidate, None, &observed).is_none());
        assert!(route_for_candidate(&candidate, Some(&wrong_cp), &observed).is_none());
        let mut conflicting_hint = candidate.clone();
        conflicting_hint.cp_hint = Some("SOLNET.OTHERCP".parse().unwrap());
        assert!(route_for_candidate(&conflicting_hint, Some(&cp), &observed).is_none());
        assert_eq!(
            route_for_candidate(&candidate, Some(&cp), &observed),
            Some((
                lu,
                Destination::Mptn {
                    hosting_cp: cp,
                    attachment_id: "mptn-a".into(),
                }
            ))
        );
    }
}
