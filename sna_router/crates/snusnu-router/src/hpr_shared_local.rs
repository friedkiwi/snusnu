//! EE session adapters over the process-long LLC and TCP62 socket owner.

use std::{collections::HashMap, io, time::Duration};

use router_core::session::{QualifiedName, SessionIdentity, SessionUnit};

use crate::{
    auto_address::AutoProxyMacs,
    auto_hpr_local_ingress::ReadyLocalLlc,
    auto_runtime::AutoLocalSessionRunner,
    config::RouterConfig,
    hpr_destination_directory::{
        configured_candidates, CandidateCarrier, ConfiguredCandidate, Destination,
        HprDestinationDirectory,
    },
    hpr_local_mptn::HprToMptnSession,
    hpr_mptn_attachments::{HprMptnPeerState, MptnIngressOffer, ReadyMptnSource},
    hpr_session_source::SessionSource,
};

pub(crate) enum ReadyLocalHpr {
    Llc(ReadyLocalLlc),
    Mptn(ReadyMptnSource),
    Ee {
        target_ee_id: String,
        identity: SessionIdentity,
        source: Box<dyn SessionSource>,
    },
}

/// Owns protocol proof and EE session state, but never binds LLC or TCP62.
pub(crate) struct HprSharedLocal {
    mptn: HashMap<String, HprMptnPeerState>,
    mptn_owners: HashMap<String, String>,
    candidates: Vec<ConfiguredCandidate>,
    ee_llc: HashMap<String, EeLlcState>,
}

struct EeLlcState {
    attachments: Vec<String>,
    proxy_mac: [u8; 6],
}

impl HprSharedLocal {
    pub(crate) fn ee_proxy_mac(&self, attachment_id: &str) -> Option<[u8; 6]> {
        self.ee_llc.get(attachment_id).map(|state| state.proxy_mac)
    }

    pub(crate) fn new(config: &RouterConfig) -> io::Result<Self> {
        let mptn = config
            .mptn_gateway
            .iter()
            .map(|entry| Ok((entry.id.clone(), HprMptnPeerState::new(entry)?)))
            .collect::<io::Result<HashMap<_, _>>>()?;
        let candidates = configured_candidates(config)?
            .into_iter()
            .filter(|candidate| candidate.carrier == CandidateCarrier::Mptn)
            .collect();
        Ok(Self {
            mptn,
            mptn_owners: HashMap::new(),
            candidates,
            ee_llc: HashMap::new(),
        })
    }

    pub(crate) fn configure_ee(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        config: &RouterConfig,
        attachment_id: &str,
        peer_cp: QualifiedName,
    ) -> io::Result<()> {
        self.withdraw_ee(runner, attachment_id)?;
        if config.llc.is_empty() {
            return Ok(());
        }
        let proxy_mac = AutoProxyMacs::from_ids(
            config
                .llc
                .iter()
                .map(|entry| entry.id.as_str())
                .chain(config.mptn_gateway.iter().map(|entry| entry.id.as_str()))
                .chain(config.ee.iter().map(|entry| entry.id.as_str())),
        )?
        .get(attachment_id)
        .ok_or_else(|| io::Error::other("EE proxy MAC allocation failed"))?;
        let mut registered: Vec<String> = Vec::new();
        for entry in &config.llc {
            if let Err(error) = runner.allow_llc_proxy_mac(&entry.id, proxy_mac) {
                for id in registered {
                    let _ = runner.withdraw_llc_proxy_mac(&id, proxy_mac);
                }
                return Err(error);
            }
            registered.push(entry.id.clone());
        }
        if let Err(error) = runner.register_ee_llc_target(attachment_id, proxy_mac, peer_cp) {
            for id in registered {
                let _ = runner.withdraw_llc_proxy_mac(&id, proxy_mac);
            }
            return Err(error);
        }
        self.ee_llc.insert(
            attachment_id.to_owned(),
            EeLlcState {
                attachments: registered,
                proxy_mac,
            },
        );
        Ok(())
    }

    /// Advance adapter proof and consume offers from the shared socket owner.
    /// Rejected offers are released on that owner before returning.
    pub(crate) fn poll(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        directory: &HprDestinationDirectory,
        can_accept_user: bool,
    ) -> io::Result<Option<ReadyLocalHpr>> {
        for (id, observations) in runner.take_mptn_management() {
            if let Some(state) = self.mptn.get_mut(&id) {
                state.observe_management(observations)?;
            }
        }
        for (id, snapshot) in runner.take_mptn_discovery() {
            if let Some(state) = self.mptn.get_mut(&id) {
                state.observe_discovery(snapshot);
            }
        }
        for (id, state) in &mut self.mptn {
            runner.with_gateway(id, |gateway| state.poll_probes(gateway))?;
        }
        let mut ready = None;
        for (id, association, offer) in runner.take_unhandled_mptn_offers() {
            if !can_accept_user || ready.is_some() {
                runner.with_gateway(&id, |gateway| {
                    gateway.reject_offer(association, "EE session slot unavailable")
                })?;
                continue;
            }
            let Some(state) = self.mptn.get_mut(&id) else {
                runner.with_gateway(&id, |gateway| {
                    gateway.reject_offer(association, "unknown EE gateway")
                })?;
                continue;
            };
            let offered = MptnIngressOffer {
                gateway_id: id.clone(),
                association,
                offer,
            };
            match runner.with_gateway(&id, |gateway| {
                state.take_source(gateway, offered, directory)
            }) {
                Ok(source) => {
                    self.mptn_owners.insert(id, source.target_ee_id.clone());
                    ready = Some(ReadyLocalHpr::Mptn(source));
                }
                Err(error) => tracing::warn!(gateway = %id, association, error = %error,
                    "MPTN offer did not select a verified EE destination"),
            }
        }
        for (id, offer) in runner.take_unhandled_llc_offers() {
            runner.release_llc(&id, offer.proxy_mac)?;
        }
        for mut source in runner.take_ee_llc_handoffs() {
            if can_accept_user && ready.is_none() {
                ready = Some(ReadyLocalHpr::Llc(source));
            } else {
                if let Err(error) = source.source.close() {
                    tracing::warn!(attachment = %source.ingress_id, error = %error,
                        "failed to close LLC session while EE slot is busy");
                }
                runner.release_ee_llc_ingress(&source.ingress_id, source.proxy_mac)?;
            }
        }
        Ok(ready)
    }

    pub(crate) fn trusted_mptn_routes(
        &self,
        runner: &mut AutoLocalSessionRunner<'_>,
    ) -> io::Result<Vec<(QualifiedName, Destination)>> {
        let mut routes = Vec::new();
        for (id, state) in &self.mptn {
            routes.extend(runner.with_gateway(id, |gateway| {
                Ok(state.trusted_routes(gateway, &self.candidates))
            })?);
        }
        Ok(routes)
    }

    pub(crate) fn take_mptn_session(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        ee_attachment_id: &str,
        gateway_id: &str,
        identity: &SessionIdentity,
        bind: &SessionUnit,
        timeout: Duration,
    ) -> io::Result<Option<HprToMptnSession>> {
        let state = self
            .mptn
            .get_mut(gateway_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "MPTN peer state absent"))?;
        let session = runner.with_gateway(gateway_id, |gateway| {
            state.take_session(gateway, &self.candidates, identity, bind, timeout)
        })?;
        if session.is_some() {
            self.mptn_owners
                .insert(gateway_id.to_owned(), ee_attachment_id.to_owned());
        }
        Ok(session)
    }

    pub(crate) fn release_mptn(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        gateway_id: &str,
    ) -> io::Result<()> {
        let state = self
            .mptn
            .get_mut(gateway_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "MPTN peer state absent"))?;
        runner.with_gateway(gateway_id, |gateway| {
            state.release(gateway);
            Ok(())
        })?;
        self.mptn_owners.remove(gateway_id);
        Ok(())
    }

    pub(crate) fn release_llc(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        ingress_id: &str,
        proxy_mac: [u8; 6],
    ) -> io::Result<()> {
        runner.release_ee_llc_ingress(ingress_id, proxy_mac)
    }

    pub(crate) fn withdraw_ee(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        attachment_id: &str,
    ) -> io::Result<()> {
        if let Some(state) = self.ee_llc.remove(attachment_id) {
            runner.withdraw_ee_llc_target(attachment_id, state.proxy_mac)?;
            for id in state.attachments {
                runner.withdraw_llc_proxy_mac(&id, state.proxy_mac)?;
            }
        }
        let owned = self
            .mptn_owners
            .iter()
            .filter_map(|(gateway, ee)| (ee == attachment_id).then_some(gateway.clone()))
            .collect::<Vec<_>>();
        for id in owned {
            let state = self.mptn.get_mut(&id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "MPTN owner has no gateway state")
            })?;
            runner.with_gateway(&id, |gateway| {
                state.release(gateway);
                Ok(())
            })?;
            self.mptn_owners.remove(&id);
        }
        Ok(())
    }
}
