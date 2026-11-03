//! Cooperative dispatch of LLC-originated sessions to an MPTN attachment.
//!
//! The converter owns its native endpoint and a leased UDP/397 socket on a
//! worker thread. The main router loop can continue polling other circuits;
//! it releases the gateway's UDP lease and LLC proxy after completion.

use crate::{
    auto_gateway_runtime::AutoMptnGateway,
    auto_llc::LlcIngressOffer,
    auto_local_converter::{run_llc_to_mptn, virtual_xid_for_target},
};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use transport_ws::wire;

pub(crate) struct CompletedLocalSession {
    pub(crate) id: u64,
    pub(crate) ingress_id: String,
    pub(crate) proxy_mac: [u8; 6],
    pub(crate) gateway_id: String,
    pub(crate) result: io::Result<()>,
}

struct Active {
    ingress_id: String,
    proxy_mac: [u8; 6],
    gateway_id: String,
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

pub(crate) struct AutoLocalDispatch {
    next_id: u64,
    sender: Sender<(u64, io::Result<()>)>,
    receiver: Receiver<(u64, io::Result<()>)>,
    active: HashMap<u64, Active>,
}

impl AutoLocalDispatch {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            next_id: 0,
            sender,
            receiver,
            active: HashMap::new(),
        }
    }

    pub(crate) fn gateway_busy(&self, gateway_id: &str) -> bool {
        self.active
            .values()
            .any(|active| active.gateway_id == gateway_id)
    }

    pub(crate) fn start(
        &mut self,
        ingress_id: &str,
        offer: LlcIngressOffer,
        gateway: &mut AutoMptnGateway<'_>,
        target_cp: &wire::SnaName,
        seed: &[u8],
        timeout: Duration,
    ) -> io::Result<u64> {
        if self.gateway_busy(gateway.id()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "MPTN gateway already has a local circuit",
            ));
        }
        let virtual_xid = virtual_xid_for_target(target_cp, seed)?;
        let proxy_mac = offer.proxy_mac;
        let gateway_id = gateway.id().to_owned();
        let target = gateway.outbound_endpoint();
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("automatic local session ID exhausted"))?;
        let udp = gateway.lease_udp()?;
        let sender = self.sender.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let handle = match thread::Builder::new()
            .name("snusnu-local-mptn".into())
            .spawn(move || {
                let result =
                    run_llc_to_mptn(offer, virtual_xid, udp, target, timeout, &worker_cancel);
                let _ = sender.send((id, result));
            }) {
            Ok(handle) => handle,
            Err(error) => {
                gateway.release_udp();
                return Err(error);
            }
        };
        self.next_id = id;
        self.active.insert(
            id,
            Active {
                ingress_id: ingress_id.into(),
                proxy_mac,
                gateway_id,
                cancel,
                handle,
            },
        );
        Ok(id)
    }

    /// Return finished sessions; caller must release each gateway UDP lease
    /// and listener proxy MAC before another session uses that attachment.
    pub(crate) fn poll_completed(&mut self) -> Vec<CompletedLocalSession> {
        let mut completed = Vec::new();
        while let Ok((id, result)) = self.receiver.try_recv() {
            if let Some(active) = self.active.remove(&id) {
                let joined = active.handle.join();
                completed.push(CompletedLocalSession {
                    id,
                    ingress_id: active.ingress_id,
                    proxy_mac: active.proxy_mac,
                    gateway_id: active.gateway_id,
                    result: if joined.is_err() {
                        Err(io::Error::other("local converter worker panicked"))
                    } else {
                        result
                    },
                });
            }
        }
        // A panicking worker cannot send its completion. Detect that case so
        // the router does not retain the UDP lease indefinitely.
        let panicked = self
            .active
            .iter()
            .filter_map(|(id, active)| active.handle.is_finished().then_some(*id))
            .collect::<Vec<_>>();
        for id in panicked {
            if let Some(active) = self.active.remove(&id) {
                let result = active.handle.join();
                completed.push(CompletedLocalSession {
                    id,
                    ingress_id: active.ingress_id,
                    proxy_mac: active.proxy_mac,
                    gateway_id: active.gateway_id,
                    result: match result {
                        Ok(()) => Err(io::Error::other("local converter completed without result")),
                        Err(_) => Err(io::Error::other("local converter worker panicked")),
                    },
                });
            }
        }
        completed
    }
}

impl Drop for AutoLocalDispatch {
    fn drop(&mut self) {
        for active in self.active.values() {
            active.cancel.store(true, Ordering::Relaxed);
        }
        for (_, active) in self.active.drain() {
            if active.handle.join().is_err() {
                tracing::warn!(gateway = %active.gateway_id, ingress = %active.ingress_id,
                    "local converter worker panicked during shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_dispatch_cancels_and_joins_active_workers() {
        let mut dispatch = AutoLocalDispatch::new();
        let cancel = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let worker_finished = finished.clone();
        let handle = thread::spawn(move || {
            while !worker_cancel.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1));
            }
            worker_finished.store(true, Ordering::Relaxed);
        });
        dispatch.active.insert(
            1,
            Active {
                ingress_id: "llc-a".into(),
                proxy_mac: [6, 0x53, 0x4e, 0, 0, 1],
                gateway_id: "mptn-b".into(),
                cancel,
                handle,
            },
        );
        drop(dispatch);
        assert!(finished.load(Ordering::Relaxed));
    }
}
