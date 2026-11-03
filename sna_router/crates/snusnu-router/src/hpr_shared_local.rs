//! EE session adapters over the process-long LLC and TCP62 socket owner.

use std::{collections::HashMap, io, time::Duration};

use router_core::session::{QualifiedName, SessionIdentity, SessionUnit};

use crate::{
    auto_address::AutoProxyMacs,
    auto_hpr_local_ingress::{LocalToHprState, ReadyLocalLlc},
    auto_runtime::AutoLocalSessionRunner,
    config::RouterConfig,
    hpr_destination_directory::{
        configured_candidates, CandidateCarrier, ConfiguredCandidate, Destination,
        HprDestinationDirectory,
    },
    hpr_local_mptn::HprToMptnSession,
    hpr_mptn_attachments::{HprMptnPeerState, MptnIngressOffer, ReadyMptnSource},
};

pub(crate) enum ReadyLocalHpr {
    Llc(ReadyLocalLlc),
    Mptn(ReadyMptnSource),
}

/// Owns protocol proof and EE session state, but never binds LLC or TCP62.
pub(crate) struct HprSharedLocal {
    mptn: HashMap<String, HprMptnPeerState>,
    candidates: Vec<ConfiguredCandidate>,
    llc: Option<LocalToHprState>,
    llc_proxy: Option<(Vec<String>, [u8; 6])>,
}

impl HprSharedLocal {
    pub(crate) fn ee_proxy_mac(&self) -> Option<[u8; 6]> {
        self.llc_proxy.as_ref().map(|(_, mac)| *mac)
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
            candidates,
            llc: None,
            llc_proxy: None,
        })
    }

    pub(crate) fn configure_ee(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        config: &RouterConfig,
        attachment_id: &str,
        peer_cp: QualifiedName,
    ) -> io::Result<()> {
        self.withdraw_ee(runner)?;
        if config.llc.is_empty() {
            return Ok(());
        }
        let proxy_mac = AutoProxyMacs::from_ids(
            config
                .llc
                .iter()
                .map(|entry| entry.id.as_str())
                .chain(config.mptn_gateway.iter().map(|entry| entry.id.as_str()))
                .chain(std::iter::once(attachment_id)),
        )?
        .get(attachment_id)
        .ok_or_else(|| io::Error::other("EE proxy MAC allocation failed"))?;
        let state = LocalToHprState::new(attachment_id, peer_cp, proxy_mac)?;
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
        self.llc = Some(state);
        self.llc_proxy = Some((registered, proxy_mac));
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
                Ok(source) => ready = Some(ReadyLocalHpr::Mptn(source)),
                Err(error) => tracing::warn!(gateway = %id, association, error = %error,
                    "MPTN offer did not select a verified EE destination"),
            }
        }
        for (id, offer) in runner.take_unhandled_llc_offers() {
            if can_accept_user {
                if let Some(state) = self.llc.as_mut() {
                    state.accept_offer(&id, offer);
                } else {
                    runner.release_llc(&id, offer.proxy_mac)?;
                }
            } else {
                runner.release_llc(&id, offer.proxy_mac)?;
            }
        }
        if let Some(state) = self.llc.as_mut() {
            if let Some(mut source) = state.poll_ready(directory)? {
                if can_accept_user && ready.is_none() {
                    ready = Some(ReadyLocalHpr::Llc(source));
                } else {
                    if let Err(error) = source.source.close() {
                        tracing::warn!(attachment = %source.ingress_id, error = %error,
                            "failed to close LLC session while EE slot is busy");
                    }
                    state.release(&source.ingress_id, source.proxy_mac)?;
                }
            }
            release_llc(runner, state)?;
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
        gateway_id: &str,
        identity: &SessionIdentity,
        bind: &SessionUnit,
        timeout: Duration,
    ) -> io::Result<Option<HprToMptnSession>> {
        let state = self
            .mptn
            .get_mut(gateway_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "MPTN peer state absent"))?;
        runner.with_gateway(gateway_id, |gateway| {
            state.take_session(gateway, &self.candidates, identity, bind, timeout)
        })
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
        })
    }

    pub(crate) fn release_llc(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
        ingress_id: &str,
        proxy_mac: [u8; 6],
    ) -> io::Result<()> {
        let state = self.llc.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "EE LLC session state absent")
        })?;
        state.release(ingress_id, proxy_mac)?;
        release_llc(runner, state)
    }

    pub(crate) fn withdraw_ee(
        &mut self,
        runner: &mut AutoLocalSessionRunner<'_>,
    ) -> io::Result<()> {
        if let Some(mut state) = self.llc.take() {
            state.shutdown();
            release_llc(runner, &mut state)?;
        }
        if let Some((attachments, proxy_mac)) = self.llc_proxy.take() {
            for id in attachments {
                runner.withdraw_llc_proxy_mac(&id, proxy_mac)?;
            }
        }
        for (id, state) in &mut self.mptn {
            runner.with_gateway(id, |gateway| {
                state.release(gateway);
                Ok(())
            })?;
        }
        Ok(())
    }
}

fn release_llc(
    runner: &mut AutoLocalSessionRunner<'_>,
    state: &mut LocalToHprState,
) -> io::Result<()> {
    for (id, mac) in state.take_releases() {
        runner.release_llc(&id, mac)?;
    }
    Ok(())
}
