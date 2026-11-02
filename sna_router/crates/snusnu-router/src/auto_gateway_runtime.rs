//! Identity helpers for session-selected TCP62/native gateway circuits.
//!
//! A TCP62 Connect names LUs, not APPN control points. The router therefore
//! gives its virtual APPN link a stable, distinct CP name in the source LU's
//! network. The target CP must come from an actual route's `hosting_cp` (or an
//! explicit operator hint); it cannot be guessed from the target LU name.

use crate::{
    config::{self, MptnGatewayConfig},
    mptn_bidirectional_gateway::{fresh_management, pump_virtual},
    mptn_gateway_port::{GatewayConfig, GatewayEvent, MptnGatewayPort},
    remote::WsRoutePort,
    virtual_ws_port::VirtualWsPort,
};
use router_core::{xid3::{Role, Xid3}, xid3_local::LocalLlcProfile};
use std::{collections::HashMap, io, net::SocketAddr, time::{Duration, Instant}};
use transport_ip_sna::{
    anynet::TcpRecord,
    mptn_compensations::CompensationSet,
    mptn_ingress::IngressOffer,
    mptn_management_responder::V5Options,
    mptn_reverse_user_bind::NativeAddress,
};
use transport_ws::wire;

const BASE36: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn stable_hash(seed: &[u8], netid: &str, name: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed
        .iter()
        .copied()
        .chain([0xff])
        .chain(netid.bytes())
        .chain([0xff])
        .chain(name.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Build the router-owned CP for one TCP62 attachment. `seed` should contain
/// a stable router identity and attachment ID, so reconnects retain the name.
/// An explicit CP may override the generated name, but must be in the LU's
/// NETID because the concentrator can only publish this router's NETID.
pub(crate) fn virtual_cp_for_source(
    source_lu: &wire::SnaName,
    seed: &[u8],
    configured_cp: Option<&str>,
) -> io::Result<wire::SnaName> {
    let source = config::parse_cp(&format!("{}.{}", source_lu.netid, source_lu.name))?;
    if let Some(configured_cp) = configured_cp.filter(|value| !value.is_empty()) {
        let cp = config::parse_cp(configured_cp)?;
        if cp.netid != source.netid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured virtual CP is outside the source LU NETID",
            ));
        }
        return Ok(cp);
    }
    // FNV-1a has defined, repeatable output across runs and Rust versions.
    // The seven base-36 digits give a stable router-specific SNA name.
    let mut hash = stable_hash(seed, &source.netid, &source.name);
    let mut name = [b'R'; 8];
    for position in (1..8).rev() {
        name[position] = BASE36[(hash % 36) as usize];
        hash /= 36;
    }
    Ok(wire::SnaName {
        netid: source.netid,
        name: String::from_utf8(name.to_vec()).expect("base36 is ASCII"),
    })
}

/// Build a virtual native APPN profile for a selected MPTN session. This
/// node ID belongs to the router's virtual link, not to the OS/400 peer.
pub(crate) fn virtual_xid(
    cp: &wire::SnaName,
    seed: &[u8],
    configured_station: Option<&str>,
    configured_node_id: Option<&str>,
    tg_number: u8,
) -> io::Result<Xid3> {
    let cp_qualified = format!("{}.{}", cp.netid, cp.name);
    config::parse_cp(&cp_qualified)?;
    let station = configured_station
        .filter(|value| !value.is_empty())
        .unwrap_or(&cp.name);
    let node_id = if let Some(value) = configured_node_id.filter(|value| !value.is_empty()) {
        if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "gateway local_node_id must be eight hex digits"));
        }
        u32::from_str_radix(value, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid gateway local_node_id"))?
    } else {
        0xfff00000 | ((stable_hash(seed, &cp.netid, &cp.name) as u32) & 0x000fffff)
    };
    LocalLlcProfile {
        cp_name: cp_qualified,
        station_name: station.into(),
        node_id: node_id.to_be_bytes(),
        tg_number,
        max_receive_btu: 1496,
        max_iframes_before_ack: 1,
        role: Role::Secondary,
    }
    .build()
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("virtual XID3: {error}")))
}

/// An LU route needs a proven hosting CP before native APPN conversion.
pub(crate) fn require_hosting_cp(
    target_lu: &wire::SnaName,
    hosting_cp: Option<wire::SnaName>,
    configured_cp: Option<&str>,
) -> io::Result<wire::SnaName> {
    let hint = configured_cp
        .filter(|value| !value.is_empty())
        .map(config::parse_cp)
        .transpose()?;
    let cp = match hosting_cp {
        Some(cp) => cp,
        None => hint.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "target LU has no hosting CP")
        })?,
    };
    if cp.netid != target_lu.netid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target LU hosting CP is in another NETID",
        ));
    }
    let cp = config::parse_cp(&format!("{}.{}", cp.netid, cp.name))?;
    if hint.is_some_and(|hint| hint != cp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configured target CP disagrees with advertised LU hosting CP",
        ));
    }
    Ok(cp)
}

/// One TCP62 listener and its active, independent native WebSocket circuits.
/// The owning runtime calls `poll_once` alongside LLC and upstream polling.
pub(crate) struct AutoMptnGateway<'a> {
    config: &'a MptnGatewayConfig,
    listener: MptnGatewayPort,
    sessions: HashMap<u64, MptnToWsSession>,
}

impl<'a> AutoMptnGateway<'a> {
    pub(crate) fn bind(config: &'a MptnGatewayConfig) -> io::Result<Self> {
        let required = CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
            .map_err(io::Error::other)?;
        let listener = MptnGatewayPort::bind_dynamic(GatewayConfig {
            local: SocketAddr::new(config.local_ip, 397),
            peer_ip: config.peer_ip,
            source_lu: config.source_lu.clone(),
            destination_lu: config.destination_lu.clone(),
            available_compensations: required,
            options: V5Options { son_handler: false, keepalive_handler: false },
            cnos_mode: String::new(),
            cnos_limit: 8,
            allow_resumed_user: true,
        })?;
        Ok(Self { config, listener, sessions: HashMap::new() })
    }

    pub(crate) fn id(&self) -> &str { &self.config.id }

    pub(crate) fn active_sessions(&self) -> usize { self.sessions.len() }

    /// Poll one transport event while progressing all active converters. A
    /// validated user BIND is returned to the owning fabric for destination
    /// selection; it remains pending in the TCP62 association until accepted.
    pub(crate) fn poll_once(&mut self) -> io::Result<Option<(u64, IngressOffer)>> {
        let ids = self.sessions.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let result = self.sessions.get_mut(&id).expect("session ID collected").pump(
                &mut self.listener,
            );
            match result {
                Ok(true) => {}
                Ok(false) => { self.sessions.remove(&id); }
                Err(error) => {
                    tracing::warn!(gateway = %self.config.id, association = id, error = %error,
                        "automatic TCP62 circuit failed");
                    let _ = self.listener.close_association_for(id);
                    self.sessions.remove(&id);
                }
            }
        }
        let sessions = &self.sessions;
        let event = self.listener.poll_association_once_with_credit(|id| {
            sessions.get(&id).is_none_or(MptnToWsSession::can_accept)
        })?;
        let Some((id, event)) = event else { return Ok(None) };
        if let Some(session) = self.sessions.get_mut(&id) {
            match session.on_event(event, &mut self.listener) {
                Ok(true) => {}
                Ok(false) => { self.sessions.remove(&id); }
                Err(error) => {
                    tracing::warn!(gateway = %self.config.id, association = id, error = %error,
                        "automatic TCP62 circuit event rejected");
                    let _ = self.listener.close_association_for(id);
                    self.sessions.remove(&id);
                }
            }
            return Ok(None);
        }
        match event {
            GatewayEvent::UserBind(offer) => Ok(Some((id, offer))),
            GatewayEvent::ManagementReady | GatewayEvent::Closed => Ok(None),
            GatewayEvent::Rejected(reason) => {
                tracing::warn!(gateway = %self.config.id, association = id, reason,
                    "automatic TCP62 association rejected");
                Ok(None)
            }
            _ => {
                self.listener.close_association_for(id)?;
                Ok(None)
            }
        }
    }

    pub(crate) fn offer_lus(offer: &IngressOffer) -> io::Result<(String, String)> {
        MptnGatewayPort::offer_lus(offer)
    }

    /// Start one independently credited converter after the runtime has
    /// selected a unique destination and obtained a WebSocket circuit port.
    pub(crate) fn start_to_ws(
        &mut self,
        association: u64,
        offer: IngressOffer,
        ws: WsRoutePort,
        local_cp: &wire::SnaName,
        target_cp: &wire::SnaName,
        seed: &[u8],
        timeout: Duration,
    ) -> io::Result<()> {
        if self.sessions.contains_key(&association) || timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "TCP62 association already active or timeout invalid"));
        }
        let (source_lu, destination_lu) = Self::offer_lus(&offer)?;
        let source = config::parse_cp(&source_lu)?;
        let destination = config::parse_cp(&destination_lu)?;
        if source.netid != local_cp.netid || destination.netid != target_cp.netid {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "TCP62 offer NETIDs disagree with selected CPs"));
        }
        let xid = virtual_xid(
            local_cp, seed,
            Some(&self.config.local_station),
            Some(&self.config.local_node_id),
            self.config.tg_number,
        )?;
        let local = format!("{}.{}", local_cp.netid, local_cp.name);
        let target = format!("{}.{}", target_cp.netid, target_cp.name);
        let mut port = VirtualWsPort::new(ws, xid, &local, &target)?;
        port.attach_management(fresh_management(&local, &target)?)?;
        self.sessions.insert(association, MptnToWsSession {
            association,
            port,
            pending_offer: Some(offer),
            pending_tcp: None,
            pending_udp: None,
            user_started: false,
            setup_deadline: Instant::now() + timeout,
        });
        tracing::info!(gateway = %self.config.id, association, source_lu, destination_lu,
            local_cp = %local, target_cp = %target,
            "automatic TCP62 circuit selected WebSocket destination");
        Ok(())
    }

    pub(crate) fn reject_offer(&mut self, association: u64, reason: &str) -> io::Result<()> {
        tracing::warn!(gateway = %self.config.id, association, reason,
            "automatic TCP62 offer has no route");
        self.listener.close_association_for(association)
    }

    pub(crate) fn clone_udp_socket(&self) -> io::Result<std::net::UdpSocket> {
        self.listener.clone_udp_socket()
    }
}

struct MptnToWsSession {
    association: u64,
    port: VirtualWsPort<WsRoutePort>,
    pending_offer: Option<IngressOffer>,
    pending_tcp: Option<TcpRecord>,
    pending_udp: Option<(u16, Vec<u8>, bool)>,
    user_started: bool,
    setup_deadline: Instant,
}

impl MptnToWsSession {
    fn can_accept(&self) -> bool {
        self.pending_tcp.is_none() && self.pending_udp.is_none()
    }

    /// Return false when this private circuit has completed and can retire.
    fn pump(&mut self, listener: &mut MptnGatewayPort) -> io::Result<bool> {
        if !self.user_started && Instant::now() >= self.setup_deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut,
                "automatic TCP62 gateway setup timed out"));
        }
        pump_virtual(&mut self.port)?;
        if self.port.management_complete() {
            if let Some(offer) = self.pending_offer.take() {
                // Native address assignment remains private to this circuit.
                self.port.begin_user_bind(&offer, NativeAddress {
                    daf: 2, oaf: 2, odai: true,
                })?;
            }
        }
        if self.port.user_closed() { return Ok(false) }
        if self.port.take_expedited_native_completed() {
            listener.complete_tcp_expedited_for(self.association)?;
        }
        if let Some(sequence) = self.port.take_completed_udp_expedited() {
            listener.complete_udp_expedited_for(self.association, sequence)?;
        }
        if let Some(sequence) = self.port.take_completed_udp_abort() {
            listener.complete_udp_abort_for(self.association, sequence)?;
            return Ok(false);
        }
        if let Some((sequence, reduced, abort)) = self.pending_udp.as_ref() {
            let accepted = if *abort {
                self.port.submit_udp_abort(*sequence, reduced)?
            } else {
                self.port.submit_udp_expedited(*sequence, reduced)?
            };
            if accepted { self.pending_udp = None; }
        }
        if let Some(record) = self.pending_tcp.as_ref() {
            if self.port.submit_tcp_user_record(record)? {
                self.pending_tcp = None;
                listener.complete_user_record_for(self.association)?;
            }
        }
        if let Some(bytes) = self.port.tcp_bind_response().map(ToOwned::to_owned) {
            if listener.queue_user_bind_response_for(self.association, &bytes)? {
                self.port.mark_tcp_bind_response_enqueued(&bytes)?;
            }
        }
        self.user_started |= listener.user_active_for(self.association);
        if self.user_started {
            if let Some(record) = self.port.udp_abort_record().cloned() {
                if listener.queue_udp_abort_for(self.association, &record)? {
                    self.port.mark_udp_abort_enqueued(&record)?;
                }
            }
            if let Some(record) = self.port.tcp_user_record().cloned() {
                if listener.queue_user_record_for(self.association, &record)? {
                    self.port.mark_tcp_user_record_enqueued(&record)?;
                }
            }
        }
        self.port.complete_tcp_user_records(
            listener.take_completed_user_records_for(self.association))?;
        Ok(true)
    }

    fn on_event(&mut self, event: GatewayEvent, listener: &mut MptnGatewayPort)
        -> io::Result<bool>
    {
        match event {
            GatewayEvent::ManagementReady => Ok(true),
            GatewayEvent::UserBind(_) => Err(io::Error::new(io::ErrorKind::InvalidData,
                "duplicate TCP62 user BIND")),
            GatewayEvent::UserNormal(record)
            | GatewayEvent::UserExpedited(record)
            | GatewayEvent::UserAbort(record) => {
                if self.port.submit_tcp_user_record(&record)? {
                    listener.complete_user_record_for(self.association)?;
                } else { self.pending_tcp = Some(record); }
                Ok(true)
            }
            GatewayEvent::UserUdpExpedited { sequence, reduced } => {
                if !self.port.submit_udp_expedited(sequence, &reduced)? {
                    self.pending_udp = Some((sequence, reduced, false));
                }
                Ok(true)
            }
            GatewayEvent::UserUdpAbort { sequence, reduced } => {
                if !self.port.submit_udp_abort(sequence, &reduced)? {
                    self.pending_udp = Some((sequence, reduced, true));
                }
                Ok(true)
            }
            GatewayEvent::OutboundUdpAbortAcknowledged => {
                self.port.complete_udp_abort_response()?;
                Ok(true)
            }
            GatewayEvent::Closed => Ok(false),
            GatewayEvent::Rejected(reason) => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("TCP62 peer rejected: {reason}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(netid: &str, name: &str) -> wire::SnaName {
        wire::SnaName {
            netid: netid.into(),
            name: name.into(),
        }
    }

    #[test]
    fn generated_cp_is_stable_valid_and_source_scoped() {
        let lu = name("QABOB", "PAYROLL");
        let a = virtual_cp_for_source(&lu, b"router-one/mptn", None).unwrap();
        assert_eq!(a, virtual_cp_for_source(&lu, b"router-one/mptn", None).unwrap());
        assert_eq!(a.netid, "QABOB");
        assert_eq!(a.name.len(), 8);
        assert!(a.name.starts_with('R'));
        assert_ne!(a, virtual_cp_for_source(&lu, b"router-two/mptn", None).unwrap());
        assert_ne!(a.name, lu.name);
        config::parse_cp(&format!("{}.{}", a.netid, a.name)).unwrap();
    }

    #[test]
    fn configured_cp_and_hosting_cp_require_matching_netids() {
        let lu = name("QABOB", "SNAB");
        assert_eq!(
            virtual_cp_for_source(&lu, b"seed", Some("QABOB.GATEWAY"))
                .unwrap()
                .name,
            "GATEWAY"
        );
        assert!(virtual_cp_for_source(&lu, b"seed", Some("QAALICE.GATEWAY")).is_err());
        assert!(require_hosting_cp(&lu, None, None).is_err());
        assert_eq!(
            require_hosting_cp(&lu, Some(name("QABOB", "HOST")), None)
                .unwrap()
                .name,
            "HOST"
        );
        assert!(require_hosting_cp(&lu, Some(name("QAALICE", "HOST")), None).is_err());
        assert!(require_hosting_cp(&lu, Some(name("QABOB", "HOST")), Some("QABOB.OTHER")).is_err());
    }

    #[test]
    fn generated_virtual_xid_uses_router_cp() {
        let cp = virtual_cp_for_source(&name("QABOB", "SNAB"), b"seed", None).unwrap();
        let xid = virtual_xid(&cp, b"seed", None, None, 1).unwrap();
        assert_eq!(xid.cp_name().unwrap(), format!("{}.{}", cp.netid, cp.name));
        assert!(virtual_xid(&cp, b"seed", None, Some("bad"), 1).is_err());
    }
}
