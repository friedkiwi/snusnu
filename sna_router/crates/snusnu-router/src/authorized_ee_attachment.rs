//! Authenticated EE adjacency lifecycle, independent of route discovery.
//!
//! This object owns only the UDP/LDLC link and its concentrator-backed CP
//! authorization. Local LLC and MPTN attachments must outlive it when their
//! own peers remain reachable.

use std::{
    io,
    time::{Duration, Instant},
};

use router_core::hpr_ip_activation::Phase;
use transport_ip_sna::ee::Datagram;

use crate::{
    auto_hpr_identity::AuthorizedEeIdentity, config::EeConfig, ee_ldlc_endpoint::EeLdlcEndpoint,
    remote::AutoWsHub,
};

pub(crate) struct AuthorizedEeAttachment {
    identity: AuthorizedEeIdentity,
    link: EeLdlcEndpoint,
    started: Instant,
}

impl AuthorizedEeAttachment {
    pub(crate) fn bind(config: &EeConfig, identity: AuthorizedEeIdentity) -> io::Result<Self> {
        let peer_identity = identity.clone();
        let link = EeLdlcEndpoint::bind_dynamic(config.local_ip, config.peer_ip, move |xid| {
            peer_identity.build_xids(xid, true)
        })?;
        Ok(Self {
            identity,
            link,
            started: Instant::now(),
        })
    }

    pub(crate) fn authorized(&self, hub: &AutoWsHub) -> io::Result<bool> {
        self.identity.still_authorized(hub)
    }

    pub(crate) fn local_cp(&self) -> &router_core::session::QualifiedName {
        &self.identity.local_cp
    }

    pub(crate) fn link(&self) -> &EeLdlcEndpoint {
        &self.link
    }

    pub(crate) fn tick(&mut self, now: Instant) -> io::Result<()> {
        self.link.tick(now)
    }

    pub(crate) fn poll(&mut self, now: Instant) -> io::Result<Option<Datagram>> {
        self.link.poll(now)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.link.phase() == Phase::Active
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}
