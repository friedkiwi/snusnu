//! Session-selected routing when a config has no explicit `[[route]]` table.

use crate::{
    auto_address::AutoProxyMacs,
    auto_llc::{AutoLlcPort, LlcAutoListener},
    config::{self, RouterConfig},
    local_status::LocalProxyMacStatus,
    routing::{AutomaticFabric, PortId, RouteAddress},
    STOP,
};
use std::{collections::HashMap, io, sync::atomic::Ordering, thread, time::Duration};

const IDLE_POLL: Duration = Duration::from_micros(200);

struct LlcSession {
    ingress: usize,
    ingress_proxy: [u8; 6],
    egress: usize,
    egress_proxy: [u8; 6],
}

/// Keep automatic mode separate from the explicit pair router. Attachments
/// that are not yet backed by a per-session adapter fail at startup instead
/// of appearing to run while dropping sessions.
pub(crate) fn run(config: &RouterConfig) -> io::Result<()> {
    let proxies = AutoProxyMacs::from_ids(
        config.llc.iter().map(|peer| peer.id.as_str()).chain(
            config.mptn_gateway.iter().map(|peer| peer.id.as_str()),
        ),
    )?;
    if let Some(status) = crate::status() {
        status.replace_local_proxy_macs(
            proxies.iter().map(|(id, mac)| LocalProxyMacStatus {
                attachment_id: id.into(),
                mac: crate::endpoint::format_mac(mac),
            }).collect(),
        );
    }
    if !config.mptn_gateway.is_empty() || !config.remote.is_empty()
        || !config.anynet.is_empty() || !config.ee.is_empty() || !config.hpr_lan.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic LLC/MPTN/concentrator session routing is still being connected",
        ));
    }
    run_local_llc(config, proxies)
}

fn run_local_llc(config: &RouterConfig, proxies: AutoProxyMacs) -> io::Result<()> {
    let mut fabric = AutomaticFabric::new();
    for peer in &config.llc {
        let mac = proxies.get(&peer.id).expect("local LLC proxy allocated");
        fabric.directory_mut().replace(
            PortId::new(&peer.id),
            [RouteAddress::Mac(mac)],
        );
    }
    let mut listeners = Vec::with_capacity(config.llc.len());
    for peer in &config.llc {
        let mut listener = LlcAutoListener::open(
            &peer.interface,
            config::parse_mac(&peer.guest_mac)?,
        )?;
        for (target, mac) in proxies.iter() {
            if target != peer.id {
                listener.allow_proxy_mac(mac)?;
            }
        }
        listeners.push(listener);
    }
    let mut sessions = HashMap::<u64, LlcSession>::new();
    let mut next_id = 0u64;
    tracing::info!(attachments = listeners.len(), "automatic local LLC routing started");
    while !STOP.load(Ordering::Relaxed) {
        let mut active = fabric.poll_once()?;
        for closed in fabric.take_closed_sessions() {
            if let Some(session) = sessions.remove(&closed) {
                listeners[session.ingress].release(session.ingress_proxy);
                listeners[session.egress].release(session.egress_proxy);
                active = true;
            }
        }
        for ingress in 0..listeners.len() {
            let Some(offer) = listeners[ingress].poll_offer()? else { continue };
            active = true;
            let ingress_proxy = offer.proxy_mac;
            let ingress_id = PortId::new(&config.llc[ingress].id);
            let destination = RouteAddress::Mac(ingress_proxy);
            let target = match fabric.resolve(&ingress_id, &destination) {
                Ok(target) => target,
                Err(error) => {
                    tracing::warn!(ingress = %ingress_id.0, proxy_mac = %crate::endpoint::format_mac(ingress_proxy), error = %error, "automatic LLC destination unresolved");
                    listeners[ingress].release(ingress_proxy);
                    continue;
                }
            };
            let egress = config.llc.iter().position(|peer| peer.id == target.0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "selected LLC attachment absent"))?;
            let egress_proxy = proxies.get(&config.llc[ingress].id)
                .expect("ingress local proxy allocated");
            if !listeners[egress].reserve(egress_proxy)? {
                tracing::warn!(ingress = %ingress_id.0, egress = %target.0, "automatic LLC destination busy");
                listeners[ingress].release(ingress_proxy);
                continue;
            }
            let result = (|| -> io::Result<()> {
                let ingress_port = offer.open_port()?;
                let peer = &config.llc[egress];
                let egress_port = AutoLlcPort::open_outbound(
                    &peer.interface,
                    config::parse_mac(&peer.guest_mac)?,
                    egress_proxy,
                )?;
                next_id = next_id.checked_add(1)
                    .ok_or_else(|| io::Error::other("automatic session ID exhausted"))?;
                fabric.open_pair(next_id, &ingress_id, &destination, &target,
                    Box::new(ingress_port), Box::new(egress_port))?;
                sessions.insert(next_id, LlcSession {
                    ingress, ingress_proxy, egress, egress_proxy,
                });
                Ok(())
            })();
            if let Err(error) = result {
                listeners[ingress].release(ingress_proxy);
                listeners[egress].release(egress_proxy);
                return Err(error);
            }
        }
        if !active { thread::sleep(IDLE_POLL); }
    }
    for session_id in sessions.keys().copied().collect::<Vec<_>>() {
        fabric.close_pair(session_id)?;
    }
    Ok(())
}
