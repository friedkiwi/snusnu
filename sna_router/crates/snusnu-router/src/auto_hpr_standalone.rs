//! EE link lifecycle for a router-owned CP without a concentrator.
//!
//! The link only authenticates the adjacent XID and delivers validated NLPs.
//! CP management, RTP and LU routing remain in the shared HPR session runtime.

use std::{
    collections::VecDeque,
    io,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

use crate::{
    auto_hpr_identity::StandaloneEeIdentity,
    auto_hpr_runtime::DirectHprRuntime,
    config::{EeConfig, RouterConfig},
    ee_ldlc_endpoint::EeLdlcEndpoint,
    hpr_mptn_attachments::HprMptnAttachments,
    STOP,
};
use router_core::{
    hpr_control_bootstrap::HprControlBootstrap, hpr_ip_activation::Phase, ConnectionGeneration,
};
use transport_ip_sna::ee::Datagram;

pub(crate) enum StandaloneEvent {
    Activated(Box<HprControlBootstrap>),
    Datagram(Datagram),
    Deactivated,
}

pub(crate) struct StandaloneEeLink {
    link: EeLdlcEndpoint,
    active_generation: Option<ConnectionGeneration>,
    pending: VecDeque<StandaloneEvent>,
}

const IDLE_POLL: Duration = Duration::from_micros(200);
const RESTART_BACKOFF: Duration = Duration::from_secs(1);

/// Run EE with the same CP/RTP/session engine as the concentrator path. The
/// live local directory selects LLC and MPTN destinations after peer proof.
pub(crate) fn run_standalone(config: &RouterConfig) -> io::Result<()> {
    let attachment = config.ee.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "standalone EE attachment missing",
        )
    })?;
    while !STOP.load(Ordering::Relaxed) {
        if let Err(error) = run_link(config, attachment) {
            tracing::warn!(attachment = %attachment.id, error = %error,
                "standalone EE adjacency reset");
        }
        if !STOP.load(Ordering::Relaxed) {
            thread::sleep(RESTART_BACKOFF);
        }
    }
    Ok(())
}

fn run_link(config: &RouterConfig, attachment: &EeConfig) -> io::Result<()> {
    // The TCP62 listener is an independent local attachment. It remains
    // bound while the EE adjacency is absent or renegotiates.
    let mut local_mptn = (!config.mptn_gateway.is_empty())
        .then(|| HprMptnAttachments::new(config))
        .transpose()?;
    let mut link = StandaloneEeLink::bind(attachment)?;
    let clock = Instant::now();
    let mut active: Option<DirectHprRuntime<'_>> = None;
    while !STOP.load(Ordering::Relaxed) {
        match link.poll(Instant::now())? {
            Some(StandaloneEvent::Activated(bootstrap)) => {
                if let Some(mut previous) = active.take() {
                    local_mptn = previous.detach_local_mptn();
                }
                let peer_cp = bootstrap.peer.cp.clone();
                let generation = bootstrap.generation;
                let mut runtime = DirectHprRuntime::new(*bootstrap);
                runtime.configure_peer_lus(attachment)?;
                runtime.configure_local_llc(config)?;
                runtime.attach_local_mptn(local_mptn.take());
                runtime.configure_local_ingress(config, attachment)?;
                active = Some(runtime);
                tracing::info!(attachment = %attachment.id, peer_cp = %peer_cp,
                    generation = generation.get(),
                    "standalone EE peer activated; local routes available");
            }
            Some(StandaloneEvent::Datagram(datagram)) => {
                if let Some(runtime) = active.as_mut() {
                    runtime.on_datagram(
                        link.link(),
                        &datagram,
                        clock.elapsed().as_micros() as u64,
                    )?;
                }
            }
            Some(StandaloneEvent::Deactivated) => {
                if let Some(mut runtime) = active.take() {
                    local_mptn = runtime.detach_local_mptn();
                }
                tracing::warn!(attachment = %attachment.id,
                    "standalone EE peer deactivated; local sessions withdrawn");
            }
            None => {}
        }
        if let Some(runtime) = active.as_mut() {
            let now_us = clock.elapsed().as_micros() as u64;
            runtime.tick(link.link(), now_us)?;
            runtime.pump(link.link(), None, now_us)?;
        } else if let Some(mptn) = local_mptn.as_mut() {
            mptn.poll_without_ee()?;
        }
        thread::sleep(IDLE_POLL);
    }
    Ok(())
}

impl StandaloneEeLink {
    pub(crate) fn bind(attachment: &EeConfig) -> io::Result<Self> {
        let identity = StandaloneEeIdentity::from_attachment(attachment)?;
        let peer_identity = identity.clone();
        let link =
            EeLdlcEndpoint::bind_dynamic(attachment.local_ip, attachment.peer_ip, move |xid| {
                peer_identity.build_xids(xid, true)
            })?;
        tracing::info!(attachment = %attachment.id, local_ip = %attachment.local_ip,
            peer_ip = %attachment.peer_ip, local_cp = %identity.local_cp,
            "standalone EE attachment listening");
        Ok(Self {
            link,
            active_generation: None,
            pending: VecDeque::new(),
        })
    }

    pub(crate) fn link(&self) -> &EeLdlcEndpoint {
        &self.link
    }

    /// Emit activation before a same-poll NLP, so the session runtime can
    /// allocate generation-scoped RTP state before handling its first packet.
    pub(crate) fn poll(&mut self, now: Instant) -> io::Result<Option<StandaloneEvent>> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(Some(event));
        }
        self.link.tick(now)?;
        let datagram = self.link.poll(now)?;
        let generation = (self.link.phase() == Phase::Active).then(|| self.link.generation());
        if self.active_generation != generation {
            self.active_generation = generation;
            match generation {
                Some(generation) => {
                    let bootstrap = self.link.control_bootstrap()?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "active EE link lacks bootstrap")
                    })?;
                    tracing::info!(generation = generation.get(), "standalone EE link active");
                    self.pending
                        .push_back(StandaloneEvent::Activated(Box::new(bootstrap)));
                }
                None => {
                    tracing::info!("standalone EE link deactivated");
                    self.pending.push_back(StandaloneEvent::Deactivated);
                }
            }
        }
        if generation.is_some() {
            if let Some(datagram) = datagram {
                self.pending.push_back(StandaloneEvent::Datagram(datagram));
            }
        }
        Ok(self.pending.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_link_binds_without_concentrator_and_waits_for_peer_xid() {
        let attachment: EeConfig = toml::from_str(
            "id = 'standalone-ee'\nlocal_ip = '127.88.0.1'\npeer_ip = '127.88.0.2'\nlocal_cp = 'SOLNET.RTR'\n",
        )
        .unwrap();
        let mut link = StandaloneEeLink::bind(&attachment).unwrap();
        assert!(link.poll(Instant::now()).unwrap().is_none());
        assert_ne!(link.link().phase(), Phase::Active);
    }
}
