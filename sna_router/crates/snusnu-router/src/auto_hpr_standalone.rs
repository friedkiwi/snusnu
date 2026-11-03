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
    auto_hpr_runtime::{DirectHprRuntime, SharedLocalAccess},
    auto_runtime::AutoLocalSessionRunner,
    config::{EeConfig, RouterConfig},
    ee_ldlc_endpoint::EeLdlcEndpoint,
    hpr_destination_directory::{Destination, HprDestinationDirectory},
    hpr_shared_local::{HprSharedLocal, ReadyLocalHpr},
    STOP,
};
use router_core::{
    hpr_control_bootstrap::HprControlBootstrap, hpr_ip_activation::Phase, route_registry::RouteKey,
    ConnectionGeneration,
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
    if config.ee.len() > 1 {
        return run_multi_standalone(config);
    }
    let attachment = config.ee.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "standalone EE attachment missing",
        )
    })?;
    let mut local = AutoLocalSessionRunner::new(config)?;
    let mut shared = HprSharedLocal::new(config)?;
    while !STOP.load(Ordering::Relaxed) {
        if let Err(error) = run_link(config, attachment, &mut local, &mut shared) {
            tracing::warn!(attachment = %attachment.id, error = %error,
                "standalone EE adjacency reset");
        }
        if !STOP.load(Ordering::Relaxed) {
            local.poll_local(None)?;
            shared.poll(&mut local, &HprDestinationDirectory::new(), false)?;
            thread::sleep(RESTART_BACKOFF);
        }
    }
    Ok(())
}

struct MultiEeSlot<'a> {
    attachment: &'a EeConfig,
    link: Option<StandaloneEeLink>,
    active: Option<DirectHprRuntime<'a>>,
    retry_at: Instant,
}

/// Poll every EE socket from one coordinator while LLC and TCP62 retain one
/// process-long owner. A local offer is consumed once and delivered only to
/// the EE attachment whose verified LU selected it.
fn run_multi_standalone(config: &RouterConfig) -> io::Result<()> {
    let mut local = AutoLocalSessionRunner::new(config)?;
    let mut shared = HprSharedLocal::new(config)?;
    let mut slots = config
        .ee
        .iter()
        .map(|attachment| {
            Ok(MultiEeSlot {
                attachment,
                link: Some(StandaloneEeLink::bind(attachment)?),
                active: None,
                retry_at: Instant::now(),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let clock = Instant::now();
    let result = (|| -> io::Result<()> {
        while !STOP.load(Ordering::Relaxed) {
            local.poll_local(None)?;
            for slot in &mut slots {
                if slot.link.is_none() && Instant::now() >= slot.retry_at {
                    match StandaloneEeLink::bind(slot.attachment) {
                        Ok(link) => slot.link = Some(link),
                        Err(error) => {
                            tracing::warn!(attachment = %slot.attachment.id, error = %error,
                                "standalone EE listener restart failed");
                            slot.retry_at = Instant::now() + RESTART_BACKOFF;
                        }
                    }
                }
                let Some(link) = slot.link.as_mut() else {
                    continue;
                };
                let event = match link.poll(Instant::now()) {
                    Ok(event) => event,
                    Err(error) => {
                        tracing::warn!(attachment = %slot.attachment.id, error = %error,
                            "standalone EE link failed; withdrawing only this attachment");
                        retire_slot(slot, &mut local, &mut shared)?;
                        slot.link = None;
                        slot.retry_at = Instant::now() + RESTART_BACKOFF;
                        continue;
                    }
                };
                match event {
                    Some(StandaloneEvent::Activated(bootstrap)) => {
                        retire_slot(slot, &mut local, &mut shared)?;
                        let peer_cp = bootstrap.peer.cp.clone();
                        let mut runtime = DirectHprRuntime::new(*bootstrap);
                        runtime.configure_peer_lus(slot.attachment)?;
                        runtime.use_shared_publication();
                        shared.configure_ee(&mut local, config, &slot.attachment.id, peer_cp)?;
                        let export = runtime.ee_owner_export();
                        local.replace_ee_records(&export.owner, export.records)?;
                        slot.active = Some(runtime);
                    }
                    Some(StandaloneEvent::Datagram(datagram)) => {
                        if let Some(runtime) = slot.active.as_mut() {
                            let result = runtime.on_datagram(
                                slot.link.as_ref().unwrap().link(),
                                &datagram,
                                clock.elapsed().as_micros() as u64,
                            );
                            if let Err(error) = result {
                                fail_slot(slot, &mut local, &mut shared, error)?;
                            }
                        }
                    }
                    Some(StandaloneEvent::Deactivated) => {
                        retire_slot(slot, &mut local, &mut shared)?;
                    }
                    None => {}
                }
            }
            let mut directory = HprDestinationDirectory::new();
            let mut ee_routes = Vec::new();
            for slot in &mut slots {
                if let Some(runtime) = slot.active.as_mut() {
                    if let Err(error) =
                        runtime.refresh_shared_local(&mut local, &mut shared, config)
                    {
                        fail_slot(slot, &mut local, &mut shared, error)?;
                        continue;
                    }
                    let export = runtime.ee_owner_export();
                    for record in &export.records {
                        if let RouteKey::LogicalUnit { lu, hosting_cp } = &record.key {
                            ee_routes.push((
                                lu.clone(),
                                Destination::Ee {
                                    hosting_cp: hosting_cp.clone(),
                                    attachment_id: slot.attachment.id.clone(),
                                },
                            ));
                        }
                    }
                    local.replace_ee_records(&export.owner, export.records)?;
                }
            }
            for slot in &slots {
                if slot.active.is_some() {
                    directory.replace_owner(
                        &format!("ee:{}", slot.attachment.id),
                        ee_routes
                            .iter()
                            .filter(|(_, destination)| {
                                destination.attachment_id() == slot.attachment.id
                            })
                            .cloned(),
                    )?;
                }
            }
            for slot in &mut slots {
                if let Some(runtime) = slot.active.as_mut() {
                    runtime.replace_other_ee_routes(
                        ee_routes
                            .iter()
                            .filter(|(_, destination)| {
                                destination.attachment_id() != slot.attachment.id
                            })
                            .cloned()
                            .collect(),
                    )?;
                }
            }
            let can_accept = slots.iter().any(|slot| {
                slot.active
                    .as_ref()
                    .is_some_and(DirectHprRuntime::can_accept_local)
            });
            if let Some(ready) = shared.poll(&mut local, &directory, can_accept)? {
                let target = match &ready {
                    ReadyLocalHpr::Llc(source) => &source.target_ee_id,
                    ReadyLocalHpr::Mptn(source) => &source.target_ee_id,
                    ReadyLocalHpr::Ee { target_ee_id, .. } => target_ee_id,
                };
                if let Some(slot) = slots.iter_mut().find(|slot| slot.attachment.id == *target) {
                    if let Some(runtime) = slot.active.as_mut() {
                        if let Err(error) = runtime.accept_shared_source(
                            ready,
                            slot.link.as_ref().unwrap().link(),
                            &mut shared,
                            &mut local,
                        ) {
                            tracing::warn!(attachment = %slot.attachment.id, error = %error,
                                "shared local source could not enter EE session");
                        }
                    }
                }
            }
            let mut handoffs = Vec::new();
            for slot in &mut slots {
                if let Some(runtime) = slot.active.as_mut() {
                    let now_us = clock.elapsed().as_micros() as u64;
                    let link = slot.link.as_ref().unwrap();
                    let result = runtime.tick(link.link(), now_us).and_then(|()| {
                        let mut access = SharedLocalAccess {
                            shared: &mut shared,
                            runner: &mut local,
                            config,
                        };
                        runtime.pump(link.link(), None, now_us, Some(&mut access))
                    });
                    match result {
                        Ok(()) => handoffs.extend(runtime.take_ee_handoffs()),
                        Err(error) => fail_slot(slot, &mut local, &mut shared, error)?,
                    }
                }
            }
            for ready in handoffs {
                let ReadyLocalHpr::Ee { target_ee_id, .. } = &ready else {
                    continue;
                };
                if let Some(slot) = slots
                    .iter_mut()
                    .find(|slot| slot.attachment.id == *target_ee_id)
                {
                    if let Some(runtime) = slot.active.as_mut() {
                        if let Err(error) = runtime.accept_shared_source(
                            ready,
                            slot.link.as_ref().unwrap().link(),
                            &mut shared,
                            &mut local,
                        ) {
                            tracing::warn!(attachment = %slot.attachment.id, error = %error,
                                "EE bridge source could not enter destination EE session");
                        }
                    }
                }
            }
            thread::sleep(IDLE_POLL);
        }
        Ok(())
    })();
    for slot in &mut slots {
        let _ = retire_slot(slot, &mut local, &mut shared);
    }
    result
}

fn retire_slot(
    slot: &mut MultiEeSlot<'_>,
    local: &mut AutoLocalSessionRunner<'_>,
    shared: &mut HprSharedLocal,
) -> io::Result<()> {
    if let Some(mut runtime) = slot.active.take() {
        runtime.release_shared_llc(local)?;
    }
    shared.withdraw_ee(local, &slot.attachment.id)?;
    local.withdraw_ee_records(&slot.attachment.id)?;
    Ok(())
}

fn fail_slot(
    slot: &mut MultiEeSlot<'_>,
    local: &mut AutoLocalSessionRunner<'_>,
    shared: &mut HprSharedLocal,
    error: io::Error,
) -> io::Result<()> {
    tracing::warn!(attachment = %slot.attachment.id, error = %error,
        "standalone EE attachment failed; other attachments remain active");
    retire_slot(slot, local, shared)?;
    slot.link = None;
    slot.retry_at = Instant::now() + RESTART_BACKOFF;
    Ok(())
}

fn run_link<'a>(
    config: &'a RouterConfig,
    attachment: &EeConfig,
    local: &mut AutoLocalSessionRunner<'a>,
    shared: &mut HprSharedLocal,
) -> io::Result<()> {
    let mut link = StandaloneEeLink::bind(attachment)?;
    let clock = Instant::now();
    let mut active: Option<DirectHprRuntime<'_>> = None;
    let result = (|| -> io::Result<()> {
        while !STOP.load(Ordering::Relaxed) {
            local.poll_local(None)?;
            match link.poll(Instant::now())? {
                Some(StandaloneEvent::Activated(bootstrap)) => {
                    if let Some(mut previous) = active.take() {
                        previous.release_shared_llc(local)?;
                    }
                    shared.withdraw_ee(local, &attachment.id)?;
                    local.withdraw_ee_records(&attachment.id)?;
                    let peer_cp = bootstrap.peer.cp.clone();
                    let generation = bootstrap.generation;
                    let mut runtime = DirectHprRuntime::new(*bootstrap);
                    runtime.configure_peer_lus(attachment)?;
                    runtime.use_shared_publication();
                    shared.configure_ee(local, config, &attachment.id, peer_cp.clone())?;
                    let export = runtime.ee_owner_export();
                    local.replace_ee_records(&export.owner, export.records)?;
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
                        runtime.release_shared_llc(local)?;
                    }
                    shared.withdraw_ee(local, &attachment.id)?;
                    local.withdraw_ee_records(&attachment.id)?;
                    tracing::warn!(attachment = %attachment.id,
                    "standalone EE peer deactivated; local sessions withdrawn");
                }
                None => {}
            }
            if let Some(runtime) = active.as_mut() {
                let now_us = clock.elapsed().as_micros() as u64;
                runtime.poll_shared_local(link.link(), shared, local, config)?;
                runtime.tick(link.link(), now_us)?;
                let mut access = SharedLocalAccess {
                    shared,
                    runner: local,
                    config,
                };
                runtime.pump(link.link(), None, now_us, Some(&mut access))?;
                let export = runtime.ee_owner_export();
                local.replace_ee_records(&export.owner, export.records)?;
            } else {
                shared.poll(local, &HprDestinationDirectory::new(), false)?;
            }
            thread::sleep(IDLE_POLL);
        }
        Ok(())
    })();
    if let Some(mut runtime) = active.take() {
        let _ = runtime.release_shared_llc(local);
    }
    let _ = shared.withdraw_ee(local, &attachment.id);
    let _ = local.withdraw_ee_records(&attachment.id);
    result
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
    use router_core::{
        route_registry::{LuType, RouteRecord},
        session::QualifiedName,
    };

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

    #[test]
    fn two_ee_links_bind_and_poll_independently() {
        let first: EeConfig = toml::from_str(
            "id = 'ee-a'\nlocal_ip = '127.88.1.1'\npeer_ip = '127.88.1.2'\nlocal_cp = 'SOLNET.RTRA'\n",
        )
        .unwrap();
        let second: EeConfig = toml::from_str(
            "id = 'ee-b'\nlocal_ip = '127.88.2.1'\npeer_ip = '127.88.2.2'\nlocal_cp = 'SOLNET.RTRB'\n",
        )
        .unwrap();
        let mut a = StandaloneEeLink::bind(&first).unwrap();
        let mut b = StandaloneEeLink::bind(&second).unwrap();
        assert!(a.poll(Instant::now()).unwrap().is_none());
        assert!(b.poll(Instant::now()).unwrap().is_none());
        assert_ne!(a.link().phase(), Phase::Active);
        assert_ne!(b.link().phase(), Phase::Active);
    }

    #[test]
    fn one_ee_failure_withdraws_only_its_route() {
        let config: RouterConfig = toml::from_str(
            "[[hpr_ip]]\nid = 'ee-a'\nlocal_ip = '127.89.1.1'\npeer_ip = '127.89.1.2'\nlocal_cp = 'SOLNET.RTRA'\n\
             [[hpr_ip]]\nid = 'ee-b'\nlocal_ip = '127.89.2.1'\npeer_ip = '127.89.2.2'\nlocal_cp = 'SOLNET.RTRB'\n",
        )
        .unwrap();
        let mut local = AutoLocalSessionRunner::new(&config).unwrap();
        let mut shared = HprSharedLocal::new(&config).unwrap();
        let cp_a: QualifiedName = "SOLNET.RTRA".parse().unwrap();
        let cp_b: QualifiedName = "SOLNET.RTRB".parse().unwrap();
        let lu_a: QualifiedName = "SOLNET.LUA".parse().unwrap();
        let lu_b: QualifiedName = "SOLNET.LUB".parse().unwrap();
        for (id, lu, cp) in [("ee-a", lu_a.clone(), cp_a), ("ee-b", lu_b.clone(), cp_b)] {
            local
                .replace_ee_records(
                    id,
                    vec![RouteRecord {
                        key: RouteKey::LogicalUnit { lu, hosting_cp: cp },
                        supported_types: vec![LuType::Lu62],
                    }],
                )
                .unwrap();
        }
        let mut slot = MultiEeSlot {
            attachment: &config.ee[0],
            link: Some(StandaloneEeLink::bind(&config.ee[0]).unwrap()),
            active: None,
            retry_at: Instant::now(),
        };
        fail_slot(
            &mut slot,
            &mut local,
            &mut shared,
            io::Error::other("test reset"),
        )
        .unwrap();
        let exports = local.local_exports("SOLNET");
        assert!(exports.iter().all(|route| route.key
            != RouteKey::LogicalUnit {
                lu: lu_a.clone(),
                hosting_cp: "SOLNET.RTRA".parse().unwrap(),
            }));
        assert!(exports.iter().any(|route| route.key
            == RouteKey::LogicalUnit {
                lu: lu_b.clone(),
                hosting_cp: "SOLNET.RTRB".parse().unwrap(),
            }));
        assert!(slot.link.is_none());
    }
}
