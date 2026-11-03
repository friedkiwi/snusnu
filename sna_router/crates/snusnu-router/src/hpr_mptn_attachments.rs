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
    config::{MptnGatewayConfig, RouterConfig},
    hpr_destination_directory::{
        configured_candidates, CandidateCarrier, ConfiguredCandidate, Destination,
    },
    hpr_local_mptn::HprToMptnSession,
    hpr_mptn_session_source::MptnToHprSession,
    hpr_session_source::SessionSource,
};

struct Attachment<'a> {
    gateway: AutoMptnGateway<'a>,
    state: HprMptnPeerState,
}

/// EE-specific proof and session lease state for one TCP62 gateway. The
/// physical gateway may be owned and polled by a shared local runner.
pub(crate) struct HprMptnPeerState {
    gateway_id: String,
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

pub(crate) struct ReadyMptnSource {
    pub(crate) gateway_id: String,
    pub(crate) target_ee_id: String,
    pub(crate) identity: SessionIdentity,
    pub(crate) source: Box<dyn SessionSource>,
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
                Ok(Attachment {
                    gateway: AutoMptnGateway::bind(entry)?,
                    state: HprMptnPeerState::new(entry)?,
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
            if let Some(offer) = attachment.state.poll_gateway(&mut attachment.gateway)? {
                offered.push(offer);
            }
        }
        Ok(offered)
    }

    /// Keep the TCP62 listener and its peer evidence alive while no EE link
    /// can carry a user session. An incoming user offer is rejected on this
    /// attachment, without tearing down the other management associations.
    pub(crate) fn poll_without_ee(&mut self) -> io::Result<()> {
        for offered in self.poll_once()? {
            self.reject_offer(
                &offered.gateway_id,
                offered.association,
                "EE destination unavailable",
            )?;
        }
        Ok(())
    }

    /// A disappearing EE generation drops its user sessions, but the MPTN
    /// listener and independently observed management peers survive.
    pub(crate) fn release_all_users(&mut self) {
        for attachment in &mut self.attachments {
            if attachment.state.active_user {
                attachment.state.active_user = false;
                attachment.gateway.release_udp();
            }
        }
    }

    /// Only live management LU evidence plus an explicit operator CP
    /// assertion may create an EE RouteSetup destination. The CP is not
    /// claimed to have come from TCP62's wire format.
    pub(crate) fn trusted_routes(&self) -> Vec<(QualifiedName, Destination)> {
        self.attachments
            .iter()
            .flat_map(|attachment| {
                attachment
                    .state
                    .trusted_routes(&attachment.gateway, &self.candidates)
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
        let candidates = &self.candidates;
        let attachment = self
            .attachments
            .iter_mut()
            .find(|entry| entry.gateway.id() == gateway_id)
            .ok_or_else(|| invalid("unknown MPTN attachment"))?;
        attachment
            .state
            .take_session(&mut attachment.gateway, candidates, identity, bind, timeout)
    }

    pub(crate) fn take_ingress_session(
        &mut self,
        offered: MptnIngressOffer,
    ) -> io::Result<MptnToHprSession> {
        let attachment = self.attachment_mut(&offered.gateway_id)?;
        attachment
            .state
            .take_ingress_session(&mut attachment.gateway, offered)
    }

    pub(crate) fn take_source(
        &mut self,
        offered: MptnIngressOffer,
        directory: &crate::hpr_destination_directory::HprDestinationDirectory,
    ) -> io::Result<ReadyMptnSource> {
        let attachment = self.attachment_mut(&offered.gateway_id)?;
        attachment
            .state
            .take_source(&mut attachment.gateway, offered, directory)
    }

    pub(crate) fn release(&mut self, gateway_id: &str) {
        if let Ok(attachment) = self.attachment_mut(gateway_id) {
            attachment.state.release(&mut attachment.gateway);
        }
    }

    pub(crate) fn reject_offer(
        &mut self,
        gateway_id: &str,
        association: u64,
        reason: &str,
    ) -> io::Result<()> {
        let attachment = self.attachment_mut(gateway_id)?;
        attachment
            .state
            .reject_offer(&mut attachment.gateway, association, reason)
    }

    fn attachment_mut(&mut self, gateway_id: &str) -> io::Result<&mut Attachment<'a>> {
        self.attachments
            .iter_mut()
            .find(|entry| entry.gateway.id() == gateway_id)
            .ok_or_else(|| invalid("unknown MPTN attachment"))
    }
}

fn trusted_source_identity(
    source_lu: QualifiedName,
    target_lu: QualifiedName,
    trusted_peer_cp: Option<&QualifiedName>,
    observed_peer_lus: &HashSet<QualifiedName>,
    directory: &crate::hpr_destination_directory::HprDestinationDirectory,
) -> io::Result<(SessionIdentity, String)> {
    let source_cp =
        trusted_peer_cp.ok_or_else(|| invalid("MPTN peer CP has no operator trust anchor"))?;
    if source_lu.netid != source_cp.netid || !observed_peer_lus.contains(&source_lu) {
        return Err(invalid(
            "MPTN source LU lacks live management and trusted CP binding",
        ));
    }
    let Destination::Ee {
        hosting_cp,
        attachment_id,
    } = directory
        .resolve_lu(&target_lu)
        .ok_or_else(|| invalid("MPTN target LU has no live EE route"))?
    else {
        return Err(invalid("MPTN target LU is not a live EE destination"));
    };
    let identity = SessionIdentity::new(source_lu, target_lu)
        .with_control_points(Some(source_cp.clone()), Some(hosting_cp))
        .map_err(io::Error::other)?;
    Ok((identity, attachment_id))
}

impl HprMptnPeerState {
    pub(crate) fn new(entry: &MptnGatewayConfig) -> io::Result<Self> {
        let trusted_peer_cp = (!entry.peer_cp.is_empty())
            .then(|| parse_name(&entry.peer_cp))
            .transpose()?;
        let management_source_lu = (!entry.source_lu.is_empty())
            .then(|| parse_name(&entry.source_lu))
            .transpose()?;
        let management_target_lu = (!entry.destination_lu.is_empty())
            .then(|| parse_name(&entry.destination_lu))
            .transpose()?;
        Ok(Self {
            gateway_id: entry.id.clone(),
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
    }

    /// Compatibility wrapper while the shared runner takes over gateway
    /// polling. The state methods below can consume observations supplied by
    /// a different socket owner without opening another TCP62 listener.
    pub(crate) fn poll_gateway(
        &mut self,
        gateway: &mut AutoMptnGateway<'_>,
    ) -> io::Result<Option<MptnIngressOffer>> {
        self.check_gateway(gateway)?;
        let bind = if Instant::now() < self.poll_retry_at {
            None
        } else {
            match gateway.poll_once() {
                Ok(bind) => bind,
                Err(error) => {
                    self.observed_peer_lus.clear();
                    self.poll_retry_at = Instant::now() + Duration::from_secs(1);
                    tracing::warn!(gateway = %self.gateway_id, error = %error,
                        "MPTN gateway poll failed; learned routes withdrawn");
                    None
                }
            }
        };
        self.observe_management(gateway.take_management_lus())?;
        self.poll_probes(gateway)?;
        Ok(bind.map(|(association, offer)| MptnIngressOffer {
            gateway_id: self.gateway_id.clone(),
            association,
            offer,
        }))
    }

    pub(crate) fn observe_management(
        &mut self,
        observations: impl IntoIterator<Item = (String, String)>,
    ) -> io::Result<()> {
        for (peer_lu, local_lu) in observations {
            let peer_lu = parse_name(&peer_lu)?;
            let local_lu = parse_name(&local_lu)?;
            if let Some(trusted_cp) = &self.trusted_peer_cp {
                if peer_lu.netid != trusted_cp.netid {
                    tracing::warn!(gateway = %self.gateway_id, peer_lu = %peer_lu,
                        configured_peer_cp = %trusted_cp,
                        "MPTN management peer NETID disagrees with operator CP assertion");
                    continue;
                }
            }
            tracing::info!(gateway = %self.gateway_id, peer_lu = %peer_lu,
                local_lu = %local_lu, "MPTN management disclosed adjacent LU");
            self.observed_peer_lus.insert(peer_lu);
        }
        Ok(())
    }

    pub(crate) fn poll_probes(&mut self, gateway: &AutoMptnGateway<'_>) -> io::Result<()> {
        self.check_gateway(gateway)?;
        self.poll_probe();
        self.start_probe_if_needed(gateway)
    }

    pub(crate) fn trusted_routes(
        &self,
        gateway: &AutoMptnGateway<'_>,
        candidates: &[ConfiguredCandidate],
    ) -> Vec<(QualifiedName, Destination)> {
        if gateway.id() != self.gateway_id || self.active_user || !gateway.udp_available() {
            return Vec::new();
        }
        candidates
            .iter()
            .filter(|candidate| candidate.attachment_id == self.gateway_id)
            .filter_map(|candidate| {
                route_for_candidate(
                    candidate,
                    self.trusted_peer_cp.as_ref(),
                    &self.observed_peer_lus,
                )
            })
            .collect()
    }

    pub(crate) fn take_session(
        &mut self,
        gateway: &mut AutoMptnGateway<'_>,
        candidates: &[ConfiguredCandidate],
        identity: &SessionIdentity,
        bind: &SessionUnit,
        timeout: Duration,
    ) -> io::Result<Option<HprToMptnSession>> {
        self.check_gateway(gateway)?;
        if self.active_user || !gateway.udp_available() {
            return Ok(None);
        }
        let cp = self
            .trusted_peer_cp
            .as_ref()
            .ok_or_else(|| invalid("MPTN peer CP has no operator trust anchor"))?;
        if !self.observed_peer_lus.contains(&identity.target_lu)
            || identity.target_cp.as_ref() != Some(cp)
            || !candidates.iter().any(|candidate| {
                candidate.attachment_id == self.gateway_id
                    && candidate.lu == identity.target_lu
                    && candidate.verify_cp(cp).is_some()
            })
        {
            return Err(invalid(
                "MPTN target LU has no live management and trusted CP binding",
            ));
        }
        let endpoint = gateway.outbound_endpoint();
        let udp = gateway.lease_udp()?;
        let session = match HprToMptnSession::new(endpoint, udp, identity, bind, timeout) {
            Ok(session) => session,
            Err(error) => {
                gateway.release_udp();
                return Err(error);
            }
        };
        self.active_user = true;
        Ok(Some(session))
    }

    pub(crate) fn take_ingress_session(
        &mut self,
        gateway: &mut AutoMptnGateway<'_>,
        offered: MptnIngressOffer,
    ) -> io::Result<MptnToHprSession> {
        self.check_gateway(gateway)?;
        if offered.gateway_id != self.gateway_id {
            return Err(invalid("MPTN offer belongs to another gateway"));
        }
        if self.active_user {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "MPTN UDP lease is busy",
            ));
        }
        let endpoint = gateway.outbound_endpoint();
        let (detached, udp) = match gateway.detach_user_for_hpr(offered.association, &offered.offer)
        {
            Ok(detached) => detached,
            Err(error) => {
                let _ = gateway.reject_offer(offered.association, &error.to_string());
                return Err(error);
            }
        };
        let session = match MptnToHprSession::new(detached, udp, endpoint, offered.offer) {
            Ok(session) => session,
            Err(error) => {
                gateway.release_udp();
                return Err(error);
            }
        };
        self.active_user = true;
        Ok(session)
    }

    /// Rejects invalid source or destination proof before detaching the
    /// gateway offer. The shared socket owner must not reject it again.
    pub(crate) fn take_source(
        &mut self,
        gateway: &mut AutoMptnGateway<'_>,
        offered: MptnIngressOffer,
        directory: &crate::hpr_destination_directory::HprDestinationDirectory,
    ) -> io::Result<ReadyMptnSource> {
        self.check_gateway(gateway)?;
        if offered.gateway_id != self.gateway_id {
            return Err(invalid("MPTN offer belongs to another gateway"));
        }
        let gateway_id = offered.gateway_id.clone();
        let association = offered.association;
        let preflight = (|| -> io::Result<(SessionIdentity, String)> {
            let source_lu = parse_name(&offered.offer.connect().source.qualified_lu()?)?;
            let target_lu = parse_name(&offered.offer.connect().destination.qualified_lu()?)?;
            if self.active_user || !gateway.udp_available() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "MPTN UDP lease is busy",
                ));
            }
            trusted_source_identity(
                source_lu,
                target_lu,
                self.trusted_peer_cp.as_ref(),
                &self.observed_peer_lus,
                directory,
            )
        })();
        let (identity, target_ee_id) = match preflight {
            Ok(ready) => ready,
            Err(error) => {
                let _ = self.reject_offer(gateway, association, &error.to_string());
                return Err(error);
            }
        };
        let session = self.take_ingress_session(gateway, offered)?;
        tracing::info!(gateway = %gateway_id, target_ee = %target_ee_id,
            source_lu = %identity.source_lu, target_lu = %identity.target_lu,
            source_cp = %identity.source_cp.as_ref().unwrap(),
            "validated TCP62 user BIND selected local EE route");
        Ok(ReadyMptnSource {
            gateway_id,
            target_ee_id,
            identity,
            source: Box::new(session),
        })
    }

    pub(crate) fn release(&mut self, gateway: &mut AutoMptnGateway<'_>) {
        if self.check_gateway(gateway).is_err() {
            return;
        }
        if self.active_user {
            self.active_user = false;
            gateway.release_udp();
        }
    }

    pub(crate) fn reject_offer(
        &mut self,
        gateway: &mut AutoMptnGateway<'_>,
        association: u64,
        reason: &str,
    ) -> io::Result<()> {
        self.check_gateway(gateway)?;
        gateway.reject_offer(association, reason)
    }

    fn check_gateway(&self, gateway: &AutoMptnGateway<'_>) -> io::Result<()> {
        if gateway.id() == self.gateway_id {
            Ok(())
        } else {
            Err(invalid("MPTN state and gateway IDs disagree"))
        }
    }

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
                tracing::warn!(gateway = %self.gateway_id, "MPTN management probe panicked");
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
                    tracing::warn!(gateway = %self.gateway_id, target_lu = %target,
                        "MPTN management probe LU NETID differs from configured peer CP");
                    self.retry_at = Instant::now() + Duration::from_secs(5);
                    return;
                }
                tracing::info!(gateway = %self.gateway_id, target_lu = %target,
                    "outbound MPTN management proved adjacent LU");
                self.observed_peer_lus.insert(target.clone());
            }
            Err(error) => {
                tracing::debug!(gateway = %self.gateway_id, error = %error,
                    "outbound MPTN management probe did not establish LU reachability");
                self.retry_at = Instant::now() + Duration::from_secs(5);
            }
        }
    }

    fn start_probe_if_needed(&mut self, gateway: &AutoMptnGateway<'_>) -> io::Result<()> {
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
        let endpoint = gateway.outbound_endpoint();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("sna-mptn-management-probe".into())
            .spawn(move || {
                let result = endpoint.establish_v5_management(
                    Duration::from_secs(5),
                    &source,
                    &target,
                    None,
                );
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

    #[test]
    fn inbound_source_requires_live_management_cp_assertion_and_ee_target() {
        let source: QualifiedName = "BOBNET.SNAB".parse().unwrap();
        let target: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let source_cp: QualifiedName = "BOBNET.BOBCP".parse().unwrap();
        let target_cp: QualifiedName = "SOLNET.SNAB".parse().unwrap();
        let mut directory = crate::hpr_destination_directory::HprDestinationDirectory::new();
        directory
            .replace_owner(
                "ee",
                [(
                    target.clone(),
                    Destination::Ee {
                        hosting_cp: target_cp.clone(),
                        attachment_id: "ee-a".into(),
                    },
                )],
            )
            .unwrap();
        let observed = HashSet::from([source.clone()]);
        let (identity, attachment) = trusted_source_identity(
            source.clone(),
            target.clone(),
            Some(&source_cp),
            &observed,
            &directory,
        )
        .unwrap();
        assert_eq!(attachment, "ee-a");
        assert_eq!(identity.source_cp, Some(source_cp.clone()));
        assert_eq!(identity.target_cp, Some(target_cp));
        assert!(trusted_source_identity(
            source.clone(),
            target.clone(),
            None,
            &observed,
            &directory
        )
        .is_err());
        assert!(trusted_source_identity(
            source.clone(),
            target.clone(),
            Some(&source_cp),
            &HashSet::new(),
            &directory
        )
        .is_err());
        let wrong_cp: QualifiedName = "OTHER.BOBCP".parse().unwrap();
        assert!(trusted_source_identity(
            source.clone(),
            target.clone(),
            Some(&wrong_cp),
            &observed,
            &directory
        )
        .is_err());
        directory.withdraw_owner("ee").unwrap();
        assert!(
            trusted_source_identity(source, target, Some(&source_cp), &observed, &directory)
                .is_err()
        );
    }
}
