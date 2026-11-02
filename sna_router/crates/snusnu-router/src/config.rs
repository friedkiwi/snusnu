//! Declarative local router configuration. Each LLC entry is one independent
//! association, even when several entries share an Ethernet interface.

use crate::{
    mptn_llc_reverse::ReverseLlcConfig, mptn_outbound_port::OutboundEndpoint,
    mptn_ws_reverse::ReverseWsConfig, native_probe::parse_tp, remote::Config as WsConfig,
};
use router_core::xid3::Role;
use serde::{Deserialize, Deserializer};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs, io,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use transport_ws::wire;

#[derive(Debug)]
pub(crate) struct RouterConfig {
    pub(crate) web: Option<WebConfig>,
    pub(crate) llc: Vec<LlcConfig>,
    pub(crate) ee: Vec<EeConfig>,
    pub(crate) anynet: Vec<AnyNetConfig>,
    pub(crate) mptn_gateway: Vec<MptnGatewayConfig>,
    pub(crate) hpr_lan: Vec<HprLanConfig>,
    pub(crate) route: Vec<RouteConfig>,
    pub(crate) remote: Vec<RemoteConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterConfig {
    web: Option<WebConfig>,
    #[serde(default)]
    llc: Vec<LlcConfig>,
    #[serde(default)]
    hpr_ip: Vec<EeConfig>,
    #[serde(default)]
    mptn: Vec<MptnConfig>,
    #[serde(default)]
    hpr_lan: Vec<HprLanConfig>,
    #[serde(default)]
    route: Vec<RouteConfig>,
    #[serde(default, rename = "concentrator", alias = "remote")]
    remote: Vec<RemoteConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case")]
enum MptnConfig {
    Relay(AnyNetConfig),
    Gateway(MptnGatewayConfig),
}

impl<'de> Deserialize<'de> for RouterConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterConfig::deserialize(deserializer)?;
        let mut anynet = Vec::new();
        let mut mptn_gateway = Vec::new();
        for peer in raw.mptn {
            match peer {
                MptnConfig::Relay(peer) => anynet.push(peer),
                MptnConfig::Gateway(mut peer) => {
                    if peer.source_lu.is_empty() {
                        peer.source_lu.clone_from(&peer.local_cp);
                    }
                    if peer.destination_lu.is_empty() {
                        peer.destination_lu.clone_from(&peer.peer_cp);
                    }
                    if peer.local_station.is_empty() {
                        peer.local_station = peer
                            .local_cp
                            .rsplit_once('.')
                            .map_or(peer.local_cp.as_str(), |(_, name)| name)
                            .to_owned();
                    }
                    mptn_gateway.push(peer);
                }
            }
        }
        Ok(Self {
            web: raw.web,
            llc: raw.llc,
            ee: raw.hpr_ip,
            anynet,
            mptn_gateway,
            hpr_lan: raw.hpr_lan,
            route: raw.route,
            remote: raw.remote,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebConfig {
    pub(crate) listen: SocketAddr,
    #[serde(default)]
    pub(crate) password: String,
}

impl fmt::Debug for WebConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebConfig")
            .field("listen", &self.listen)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EeConfig {
    pub(crate) id: String,
    pub(crate) local_ip: IpAddr,
    pub(crate) peer_ip: IpAddr,
    /// CP presented to this EE neighbor. A concentrator-owned proxy CP must
    /// be verified against the received directory before XID3 is sent.
    #[serde(default)]
    pub(crate) local_cp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnyNetConfig {
    pub(crate) id: String,
    pub(crate) local_ip: IpAddr,
    pub(crate) peer_ip: IpAddr,
    pub(crate) local_lu: Option<String>,
    pub(crate) remote_lu: Option<String>,
}

/// One TCP62 ingress converted to a native WebSocket circuit. The local CP
/// speaks for the source LU; the peer CP names the remote LLC-facing system.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MptnGatewayConfig {
    pub(crate) id: String,
    pub(crate) local_ip: IpAddr,
    pub(crate) peer_ip: IpAddr,
    /// In automatic mode these identities are learned from admitted sessions.
    #[serde(default)]
    pub(crate) local_cp: String,
    #[serde(default)]
    pub(crate) peer_cp: String,
    #[serde(default)]
    pub(crate) source_lu: String,
    #[serde(default)]
    pub(crate) destination_lu: String,
    #[serde(default)]
    pub(crate) local_station: String,
    #[serde(default)]
    pub(crate) local_node_id: String,
    #[serde(default = "default_tg_number")]
    pub(crate) tg_number: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HprLanConfig {
    pub(crate) id: String,
    pub(crate) interface: String,
    pub(crate) guest_mac: String,
    pub(crate) proxy_mac: String,
    pub(crate) experimental: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LlcConfig {
    pub(crate) id: String,
    pub(crate) interface: String,
    pub(crate) guest_mac: String,
    pub(crate) local_cp: Option<String>,
    #[serde(default)]
    pub(crate) lus: Vec<String>,
    #[serde(default)]
    pub(crate) lu_types: HashMap<String, Vec<ConfiguredLuType>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteConfig {
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default = "default_bidirectional")]
    pub(crate) bidirectional: bool,
    pub(crate) converter: Option<RouteConverter>,
    /// LLC-facing address of this route's target. Omit for a concentrator
    /// binding or when the target is another configured LLC peer.
    pub(crate) proxy_mac: Option<String>,
    /// Selects a TCP62 gateway circuit by the network-qualified destination
    /// LU in an incoming Connect. Omit for a gateway with one destination.
    pub(crate) destination_lu: Option<String>,
    /// Required for a native LLC or concentrator initiated MPTN session.
    pub(crate) user_tp_hex: Option<String>,
    /// Bounded lifetime for one native LLC initiated MPTN circuit.
    pub(crate) timeout_seconds: Option<u64>,
}

/// One configured gateway and concentrator share a route whose MPTN and
/// native sides can each initiate a separate LU6.2 session.
pub(crate) struct BidirectionalGatewayConfig<'a> {
    pub(crate) gateway: &'a MptnGatewayConfig,
    pub(crate) concentrator: &'a RemoteConfig,
    #[allow(dead_code)] // Retained for the configured gateway's route metadata and tests.
    pub(crate) route: &'a RouteConfig,
    pub(crate) reverse: ReverseWsConfig,
}

/// A route names a converter explicitly before two different session
/// profiles can be joined. No converter is currently enabled at runtime.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RouteConverter {
    MptnLu62,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteConfig {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) target_cp: Option<String>,
    pub(crate) target_lu: Option<String>,
    /// Concentrator bearer credential. Empty selects an unauthenticated link.
    #[serde(default)]
    pub(crate) token: String,
}

impl fmt::Debug for RemoteConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteConfig")
            .field("id", &self.id)
            .field("url", &"<redacted>")
            .field("target_cp", &self.target_cp)
            .field("target_lu", &self.target_lu)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
pub(crate) enum ConfiguredLuType {
    #[serde(rename = "lu_0")]
    Lu0,
    #[serde(rename = "lu_1")]
    Lu1,
    #[serde(rename = "lu_2")]
    Lu2,
    #[serde(rename = "lu_3")]
    Lu3,
    #[serde(rename = "lu_6_2")]
    Lu6_2,
}

impl ConfiguredLuType {
    pub(crate) fn wire_value(self) -> i32 {
        match self {
            Self::Lu0 => wire::LuType::LuType0 as i32,
            Self::Lu1 => wire::LuType::LuType1 as i32,
            Self::Lu2 => wire::LuType::LuType2 as i32,
            Self::Lu3 => wire::LuType::LuType3 as i32,
            Self::Lu6_2 => wire::LuType::LuType62 as i32,
        }
    }
}

fn default_bidirectional() -> bool {
    true
}

fn default_tg_number() -> u8 {
    1
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn load(path: &Path) -> io::Result<RouterConfig> {
    let content = fs::read_to_string(path)?;
    let config: RouterConfig = toml::from_str(&content)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    config.validate()?;
    Ok(config)
}

impl RemoteConfig {
    pub(crate) fn bearer_token(&self) -> io::Result<String> {
        Ok(self.token.clone())
    }
}

impl RouterConfig {
    /// An empty route table selects destination based routing at runtime.
    pub(crate) fn automatic(&self) -> bool {
        self.route.is_empty()
    }

    /// Routes served by one TCP62 listener. The returned LU is the exact
    /// destination in an incoming Connect.
    pub(crate) fn gateway_routes<'a>(&'a self, id: &str) -> Vec<(&'a RouteConfig, &'a str)> {
        let Some(gateway) = self.mptn_gateway.iter().find(|gateway| gateway.id == id) else {
            return Vec::new();
        };
        self.route
            .iter()
            .filter(|route| route.from == id || route.to == id)
            .map(|route| {
                (
                    route,
                    route
                        .destination_lu
                        .as_deref()
                        .unwrap_or(&gateway.destination_lu),
                )
            })
            .collect()
    }

    /// Address presented to one local LLC peer for its configured route.
    /// `None` means the concentrator must supply the managed target address.
    pub(crate) fn llc_proxy_mac(&self, llc_id: &str) -> io::Result<Option<[u8; 6]>> {
        if !self.llc.iter().any(|peer| peer.id == llc_id) {
            return Err(invalid(format!("unknown LLC peer {llc_id}")));
        }
        let route = self
            .route
            .iter()
            .find(|route| route.from == llc_id || (route.to == llc_id && route.bidirectional))
            .ok_or_else(|| invalid(format!("LLC peer {llc_id} has no outgoing route")))?;
        let target_id = if route.from == llc_id {
            route.to.as_str()
        } else {
            route.from.as_str()
        };
        if let Some(mac) = route.proxy_mac.as_deref() {
            return Ok(Some(parse_mac(mac)?));
        }
        if let Some(target) = self.llc.iter().find(|target| target.id == target_id) {
            return Ok(Some(parse_mac(&target.guest_mac)?));
        }
        if self.remote.iter().any(|target| target.id == target_id) {
            return Ok(None);
        }
        Err(invalid(format!(
            "LLC route {llc_id} to {target_id} requires proxy_mac"
        )))
    }

    pub(crate) fn concentrator_local_id<'a>(&'a self, entry: &RemoteConfig) -> io::Result<&'a str> {
        self.route
            .iter()
            .find_map(|route| {
                if route.from == entry.id {
                    Some(route.to.as_str())
                } else if route.to == entry.id && route.bidirectional {
                    Some(route.from.as_str())
                } else {
                    None
                }
            })
            .ok_or_else(|| invalid(format!("concentrator {} has no local route", entry.id)))
    }

    /// Resolve the one supported standalone native LLC to MPTN circuit.
    /// Other gateway topologies use the separate inbound WebSocket gateway.
    pub(crate) fn reverse_llc_config(&self) -> io::Result<Option<ReverseLlcConfig>> {
        let Some(route) = self.route.iter().find(|route| {
            self.llc.iter().any(|llc| llc.id == route.from)
                && self
                    .mptn_gateway
                    .iter()
                    .any(|gateway| gateway.id == route.to)
        }) else {
            return Ok(None);
        };
        if self.llc.len() != 1
            || self.mptn_gateway.len() != 1
            || self.route.len() != 1
            || !self.remote.is_empty()
            || !self.ee.is_empty()
            || !self.anynet.is_empty()
            || !self.hpr_lan.is_empty()
            || !route.bidirectional
            || !matches!(route.converter, Some(RouteConverter::MptnLu62))
        {
            return Err(invalid(
                "native LLC to MPTN requires one LLC peer, one gateway and one bidirectional route",
            ));
        }
        let llc = &self.llc[0];
        let gateway = &self.mptn_gateway[0];
        let guest_cp = llc
            .local_cp
            .as_deref()
            .ok_or_else(|| invalid("native LLC to MPTN requires LLC local_cp"))?;
        if guest_cp != gateway.peer_cp {
            return Err(invalid("native LLC CP must match TCP62 gateway peer_cp"));
        }
        let [source_lu] = llc.lus.as_slice() else {
            return Err(invalid(
                "native LLC to MPTN requires exactly one LLC source LU",
            ));
        };
        let selector = route
            .destination_lu
            .as_deref()
            .unwrap_or(&gateway.destination_lu);
        if selector != source_lu {
            return Err(invalid(
                "native LLC source LU must match TCP62 gateway route destination_lu",
            ));
        }
        let proxy_mac = route
            .proxy_mac
            .as_deref()
            .ok_or_else(|| invalid("native LLC to MPTN requires route proxy_mac"))?;
        let user_tp_hex = route
            .user_tp_hex
            .as_deref()
            .ok_or_else(|| invalid("native LLC to MPTN requires route user_tp_hex"))?;
        let timeout = route.timeout_seconds.unwrap_or(600);
        if !(1..=600).contains(&timeout) {
            return Err(invalid(
                "native LLC to MPTN timeout_seconds must be 1..=600",
            ));
        }
        let config = ReverseLlcConfig {
            interface: llc.interface.clone(),
            guest_mac: parse_mac(&llc.guest_mac)?,
            proxy_mac: parse_mac(proxy_mac)?,
            local_cp: gateway.local_cp.clone(),
            guest_cp: guest_cp.to_owned(),
            local_station: gateway.local_station.clone(),
            local_node_id: u32::from_str_radix(&gateway.local_node_id, 16)
                .map_err(|_| invalid("invalid TCP62 gateway local_node_id"))?
                .to_be_bytes(),
            tg_number: gateway.tg_number,
            role: Role::Secondary,
            source_lu: source_lu.clone(),
            destination_lu: gateway.source_lu.clone(),
            user_tp: parse_tp(user_tp_hex)?,
            endpoint: OutboundEndpoint {
                local_ip: gateway.local_ip,
                peer_ip: gateway.peer_ip,
            },
            timeout: Duration::from_secs(timeout),
        };
        config.validate()?;
        Ok(Some(config))
    }

    /// Resolve the one supported concentrator initiated MPTN circuit. The
    /// explicit route direction distinguishes it from MPTN ingress through
    /// the same gateway profile.
    pub(crate) fn reverse_ws_config(&self) -> io::Result<Option<ReverseWsConfig>> {
        let Some(route) = self.route.iter().find(|route| {
            self.remote.iter().any(|remote| remote.id == route.from)
                && self
                    .mptn_gateway
                    .iter()
                    .any(|gateway| gateway.id == route.to)
        }) else {
            return Ok(None);
        };
        self.reverse_ws_for_route(route).map(Some)
    }

    /// Select the same physical gateway and WebSocket hop for initiation on
    /// either side. A route TP is the explicit opt-in for the combined
    /// runtime; older inbound-only lab configurations remain distinct.
    pub(crate) fn bidirectional_gateway_config(
        &self,
    ) -> io::Result<Option<BidirectionalGatewayConfig<'_>>> {
        let Some(route) = self.route.iter().find(|route| {
            self.mptn_gateway
                .iter()
                .any(|gateway| gateway.id == route.from)
                && self.remote.iter().any(|remote| remote.id == route.to)
                && route.user_tp_hex.is_some()
        }) else {
            return Ok(None);
        };
        let reverse = self.reverse_ws_for_route(route)?;
        Ok(Some(BidirectionalGatewayConfig {
            gateway: &self.mptn_gateway[0],
            concentrator: &self.remote[0],
            route,
            reverse,
        }))
    }

    fn reverse_ws_for_route(&self, route: &RouteConfig) -> io::Result<ReverseWsConfig> {
        if !self.llc.is_empty()
            || !self.ee.is_empty()
            || !self.anynet.is_empty()
            || !self.hpr_lan.is_empty()
            || self.remote.len() != 1
            || self.mptn_gateway.len() != 1
            || self.route.len() != 1
            || !route.bidirectional
            || !matches!(route.converter, Some(RouteConverter::MptnLu62))
            || route.proxy_mac.is_some()
        {
            return Err(invalid("concentrator to MPTN requires one concentrator, one gateway and one bidirectional route"));
        }
        let remote = &self.remote[0];
        let gateway = &self.mptn_gateway[0];
        let selected = route
            .destination_lu
            .as_deref()
            .unwrap_or(&gateway.destination_lu);
        let source_cp = remote.target_cp.as_deref().unwrap_or(&gateway.peer_cp);
        let source_lu = remote.target_lu.as_deref().unwrap_or(selected);
        if source_cp != gateway.peer_cp || source_lu != selected {
            return Err(invalid("concentrator source CP/LU must match TCP62 gateway peer CP and route destination LU"));
        }
        let user_tp_hex = route
            .user_tp_hex
            .as_deref()
            .ok_or_else(|| invalid("concentrator to MPTN requires route user_tp_hex"))?;
        let timeout = route.timeout_seconds.unwrap_or(600);
        if !(1..=600).contains(&timeout) {
            return Err(invalid(
                "concentrator to MPTN timeout_seconds must be 1..=600",
            ));
        }
        let config = ReverseWsConfig {
            remote: WsConfig {
                url: remote.url.clone(),
                bearer: remote.bearer_token()?,
                local_cp: parse_cp(&gateway.local_cp)?,
                target_cp: parse_cp(source_cp)?,
                target_lu: Some(parse_cp(source_lu)?),
            },
            hosted_cp: gateway.local_cp.clone(),
            hosted_lu: gateway.source_lu.clone(),
            source_cp: source_cp.to_owned(),
            source_lu: source_lu.to_owned(),
            local_station: gateway.local_station.clone(),
            local_node_id: u32::from_str_radix(&gateway.local_node_id, 16)
                .map_err(|_| invalid("invalid TCP62 gateway local_node_id"))?
                .to_be_bytes(),
            tg_number: gateway.tg_number,
            user_tp: parse_tp(user_tp_hex)?,
            endpoint: OutboundEndpoint {
                local_ip: gateway.local_ip,
                peer_ip: gateway.peer_ip,
            },
            timeout: Duration::from_secs(timeout),
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.llc.is_empty()
            && self.ee.is_empty()
            && self.anynet.is_empty()
            && self.mptn_gateway.is_empty()
            && self.hpr_lan.is_empty()
        {
            return Err(invalid(
                "at least one [[llc]], [[hpr_ip]], [[mptn]] or [[hpr_lan]] peer is required",
            ));
        }
        let mut peers = HashSet::new();
        let mut ids = HashSet::new();
        let mut kinds = HashMap::<&str, &str>::new();
        for peer in &self.llc {
            validate_id(&peer.id)?;
            if peer.interface.is_empty() {
                return Err(invalid(format!(
                    "LLC peer {} has an empty interface",
                    peer.id
                )));
            }
            if !ids.insert(peer.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", peer.id)));
            }
            kinds.insert(&peer.id, "llc");
            parse_mac(&peer.guest_mac)?;
            if let Some(local_cp) = &peer.local_cp {
                parse_cp(local_cp)?;
            } else if !peer.lus.is_empty() {
                return Err(invalid(format!(
                    "LLC peer {} declares LUs without local_cp",
                    peer.id
                )));
            }
            let mut local_lus = HashSet::new();
            for lu in &peer.lus {
                let name = parse_cp(lu)?;
                if peer
                    .local_cp
                    .as_ref()
                    .is_some_and(|cp| parse_cp(cp).ok().is_some_and(|cp| cp.netid != name.netid))
                {
                    return Err(invalid(format!(
                        "LLC peer {} LU {lu} is outside its local NETID",
                        peer.id
                    )));
                }
                if !local_lus.insert((name.netid, name.name)) {
                    return Err(invalid(format!(
                        "duplicate LU {lu} on LLC peer {}",
                        peer.id
                    )));
                }
            }
            for (lu, types) in &peer.lu_types {
                if !peer.lus.contains(lu) {
                    return Err(invalid(format!(
                        "LU type declaration for unexported LU {lu}"
                    )));
                }
                let mut unique = HashSet::new();
                if types.is_empty() || types.iter().any(|lu_type| !unique.insert(*lu_type)) {
                    return Err(invalid(format!(
                        "empty or duplicate LU type declaration for {lu}"
                    )));
                }
            }
        }
        for peer in &self.hpr_lan {
            validate_id(&peer.id)?;
            if !peer.experimental {
                return Err(invalid(format!(
                    "HPR LAN peer {} requires experimental = true",
                    peer.id
                )));
            }
            if peer.interface.is_empty() {
                return Err(invalid(format!(
                    "HPR LAN peer {} has an empty interface",
                    peer.id
                )));
            }
            if !ids.insert(peer.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", peer.id)));
            }
            kinds.insert(&peer.id, "hpr_lan");
            let guest = parse_mac(&peer.guest_mac)?;
            let proxy = parse_mac(&peer.proxy_mac)?;
            if guest == proxy {
                return Err(invalid(format!(
                    "HPR LAN peer {} has equal guest and proxy MACs",
                    peer.id
                )));
            }
            if !peers.insert((peer.interface.as_str(), guest, Some(proxy))) {
                return Err(invalid(format!(
                    "duplicate LAN association on {}",
                    peer.interface
                )));
            }
        }
        let mut ee_listeners = HashSet::new();
        for peer in &self.ee {
            validate_id(&peer.id)?;
            if !ids.insert(peer.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", peer.id)));
            }
            kinds.insert(&peer.id, "hpr_ip");
            if let Some(local_cp) = &peer.local_cp {
                parse_cp(local_cp)?;
            }
            if peer.local_ip == peer.peer_ip
                || peer.local_ip.is_ipv4() != peer.peer_ip.is_ipv4()
                || peer.local_ip.is_unspecified()
                || peer.peer_ip.is_unspecified()
            {
                return Err(invalid(format!(
                    "invalid HPR/IP address pair for {}",
                    peer.id
                )));
            }
            if !ee_listeners.insert(peer.local_ip) {
                return Err(invalid(format!(
                    "duplicate HPR/IP UDP listener IP {}",
                    peer.local_ip
                )));
            }
        }
        let mut anynet_listeners = HashSet::new();
        for peer in &self.anynet {
            validate_id(&peer.id)?;
            if !ids.insert(peer.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", peer.id)));
            }
            kinds.insert(&peer.id, "mptn_relay");
            if peer.local_ip == peer.peer_ip
                || peer.local_ip.is_ipv4() != peer.peer_ip.is_ipv4()
                || peer.local_ip.is_unspecified()
                || peer.peer_ip.is_unspecified()
            {
                return Err(invalid(format!(
                    "invalid MPTN relay IP pair for {}",
                    peer.id
                )));
            }
            if !anynet_listeners.insert(peer.local_ip) {
                return Err(invalid(format!(
                    "duplicate MPTN TCP/UDP listener IP {}",
                    peer.local_ip
                )));
            }
            match (&peer.local_lu, &peer.remote_lu) {
                (Some(local), Some(remote)) => {
                    let local = parse_cp(local)?;
                    let remote = parse_cp(remote)?;
                    if local == remote {
                        return Err(invalid(format!(
                            "MPTN relay LU pair for {} is identical",
                            peer.id
                        )));
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(invalid(format!(
                        "MPTN relay peer {} requires both local_lu and remote_lu",
                        peer.id
                    )));
                }
            }
        }
        for peer in &self.mptn_gateway {
            validate_id(&peer.id)?;
            if !ids.insert(peer.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", peer.id)));
            }
            kinds.insert(&peer.id, "mptn_gateway");
            if peer.local_ip == peer.peer_ip
                || peer.local_ip.is_ipv4() != peer.peer_ip.is_ipv4()
                || peer.local_ip.is_unspecified()
                || peer.peer_ip.is_unspecified()
                || !anynet_listeners.insert(peer.local_ip)
            {
                return Err(invalid(format!(
                    "invalid TCP62 ingress IP pair for {}",
                    peer.id
                )));
            }
            if self.automatic() {
                let local_cp = peer.local_cp.as_str();
                let peer_cp = peer.peer_cp.as_str();
                let source_lu = peer.source_lu.as_str();
                let destination_lu = peer.destination_lu.as_str();
                for name in [local_cp, peer_cp, source_lu, destination_lu] {
                    if !name.is_empty() {
                        parse_cp(name)?;
                    }
                }
                if !peer.local_station.is_empty() && !valid_sna_name(&peer.local_station) {
                    return Err(invalid(format!(
                        "invalid TCP62 gateway local station for {}",
                        peer.id
                    )));
                }
                if !peer.local_node_id.is_empty()
                    && (peer.local_node_id.len() != 8
                        || !peer
                            .local_node_id
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit()))
                {
                    return Err(invalid(format!(
                        "invalid TCP62 gateway local node ID for {}",
                        peer.id
                    )));
                }
                if peer.tg_number == 0 {
                    return Err(invalid(format!(
                        "invalid TCP62 gateway TG number for {}",
                        peer.id
                    )));
                }
                if !local_cp.is_empty()
                    && !source_lu.is_empty()
                    && parse_cp(local_cp)?.netid != parse_cp(source_lu)?.netid
                {
                    return Err(invalid(format!(
                        "TCP62 gateway {} source LU differs from local CP NETID",
                        peer.id
                    )));
                }
                if !peer_cp.is_empty()
                    && !destination_lu.is_empty()
                    && parse_cp(peer_cp)?.netid != parse_cp(destination_lu)?.netid
                {
                    return Err(invalid(format!(
                        "TCP62 gateway {} destination LU differs from peer CP NETID",
                        peer.id
                    )));
                }
            } else {
                let local_cp = parse_cp(&peer.local_cp)?;
                let peer_cp = parse_cp(&peer.peer_cp)?;
                let source_lu = parse_cp(&peer.source_lu)?;
                let destination_lu = parse_cp(&peer.destination_lu)?;
                if local_cp.netid != source_lu.netid
                    || peer_cp.netid != destination_lu.netid
                    || source_lu == destination_lu
                    || !valid_sna_name(&peer.local_station)
                    || peer.local_node_id.len() != 8
                    || !peer
                        .local_node_id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || peer.tg_number == 0
                {
                    return Err(invalid(format!(
                        "invalid TCP62 gateway identity for {}",
                        peer.id
                    )));
                }
            }
        }
        for remote in &self.remote {
            validate_id(&remote.id)?;
            if !ids.insert(remote.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", remote.id)));
            }
            kinds.insert(&remote.id, "remote");
            if !remote.url.starts_with("ws://") && !remote.url.starts_with("wss://") {
                return Err(invalid("concentrator.url must be a ws:// or wss:// URL"));
            }
            let target_cp = remote.target_cp.as_deref().map(parse_cp).transpose()?;
            if let Some(target_lu) = &remote.target_lu {
                let target_lu = parse_cp(target_lu)?;
                if target_cp
                    .as_ref()
                    .is_some_and(|cp| target_lu.netid != cp.netid)
                {
                    return Err(invalid(format!(
                        "target LU {} has a different NETID from target CP {}",
                        remote.target_lu.as_deref().unwrap_or_default(),
                        remote.target_cp.as_deref().unwrap_or_default()
                    )));
                }
            }
        }
        if self
            .remote
            .windows(2)
            .any(|pair| pair[0].url != pair[1].url)
        {
            return Err(invalid(
                "all concentrator circuits must share one WebSocket URL",
            ));
        }
        if self
            .remote
            .windows(2)
            .any(|pair| pair[0].token != pair[1].token)
        {
            return Err(invalid(
                "all concentrator circuits must share one bearer token",
            ));
        }
        if self.remote.iter().any(|entry| entry.target_lu.is_some())
            && self.remote.iter().any(|entry| entry.target_lu.is_none())
        {
            return Err(invalid(
                "all concentrator circuits on one WebSocket must use the same protocol version",
            ));
        }
        if self.automatic() {
            return self.validate_automatic();
        }
        let mut directed = HashMap::<&str, &str>::new();
        let mut gateway_destinations = HashMap::<(&str, &str), &str>::new();
        for route in &self.route {
            if !ids.contains(route.from.as_str())
                || !ids.contains(route.to.as_str())
                || route.from == route.to
            {
                return Err(invalid(format!(
                    "invalid route {} -> {}",
                    route.from, route.to
                )));
            }
            let source_kind = kinds[route.from.as_str()];
            let target_kind = kinds[route.to.as_str()];
            let gateway_id = if source_kind == "mptn_gateway" {
                Some(route.from.as_str())
            } else if target_kind == "mptn_gateway" {
                Some(route.to.as_str())
            } else {
                None
            };
            if let Some(id) = gateway_id {
                if !route.bidirectional {
                    return Err(invalid(format!(
                        "TCP62 gateway route {} -> {} must be bidirectional",
                        route.from, route.to
                    )));
                }
                let gateway = self
                    .mptn_gateway
                    .iter()
                    .find(|gateway| gateway.id == id)
                    .expect("gateway kind checked");
                let destination = route
                    .destination_lu
                    .as_deref()
                    .unwrap_or(&gateway.destination_lu);
                parse_cp(destination)?;
                if let Some(old) = gateway_destinations.insert(
                    (id, destination),
                    if id == route.from {
                        &route.to
                    } else {
                        &route.from
                    },
                ) {
                    return Err(invalid(format!(
                        "duplicate TCP62 gateway destination {destination} on {id}: {old}"
                    )));
                }
            } else if route.destination_lu.is_some() {
                return Err(invalid(format!(
                    "route {} -> {} destination_lu requires a TCP62 gateway",
                    route.from, route.to
                )));
            }
            if (route.user_tp_hex.is_some() || route.timeout_seconds.is_some())
                && !matches!(
                    (source_kind, target_kind),
                    ("llc", "mptn_gateway")
                        | ("remote", "mptn_gateway")
                        | ("mptn_gateway", "remote")
                )
            {
                return Err(invalid(format!(
                    "route {} -> {} user_tp_hex and timeout_seconds require a native source to TCP62 gateway",
                    route.from, route.to
                )));
            }
            if let Some(mac) = &route.proxy_mac {
                parse_mac(mac)?;
                if source_kind != "llc" && target_kind != "llc" {
                    return Err(invalid(format!(
                        "route {} -> {} proxy_mac requires an LLC endpoint",
                        route.from, route.to
                    )));
                }
                if source_kind == "llc" && target_kind == "llc" && route.bidirectional {
                    return Err(invalid(format!(
                        "bidirectional LLC route {} -> {} cannot use one proxy_mac for both peers",
                        route.from, route.to
                    )));
                }
            }
            if let Some(converter) = route.converter {
                if matches!((source_kind, target_kind), ("llc", "mptn_gateway"))
                    && matches!(converter, RouteConverter::MptnLu62)
                {
                    self.reverse_llc_config()?;
                    add_directed(&mut directed, &route.from, &route.to)?;
                    continue;
                }
                if matches!(
                    (source_kind, target_kind),
                    ("mptn_gateway", "remote") | ("remote", "mptn_gateway")
                ) && matches!(converter, RouteConverter::MptnLu62)
                {
                    if source_kind == "remote" {
                        self.reverse_ws_config()?;
                    } else if route.user_tp_hex.is_some() {
                        self.bidirectional_gateway_config()?.ok_or_else(|| {
                            invalid("bidirectional TCP62 gateway route is absent")
                        })?;
                    }
                    if source_kind != "mptn_gateway" {
                        add_directed(&mut directed, &route.from, &route.to)?;
                    }
                    if route.bidirectional && target_kind != "mptn_gateway" {
                        add_directed(&mut directed, &route.to, &route.from)?;
                    }
                    continue;
                }
                if matches!(
                    (source_kind, target_kind),
                    ("llc", "mptn_relay") | ("mptn_relay", "llc")
                ) && matches!(converter, RouteConverter::MptnLu62)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "LLC to MPTN relay LU6.2 conversion requires an operational MPTN session gateway",
                    ));
                }
                return Err(invalid(format!(
                    "converter {converter:?} is incompatible with route {} -> {}",
                    route.from, route.to
                )));
            }
            if !matches!(
                (source_kind, target_kind),
                ("llc", "llc")
                    | ("llc", "remote")
                    | ("remote", "llc")
                    | ("hpr_ip", "hpr_ip")
                    | ("hpr_lan", "hpr_ip")
                    | ("hpr_ip", "hpr_lan")
                    | ("mptn_relay", "mptn_relay")
            ) {
                return Err(invalid(format!(
                    "unsupported route {} ({source_kind}) -> {} ({target_kind})",
                    route.from, route.to
                )));
            }
            if source_kind == "mptn_relay" {
                let from = self
                    .anynet
                    .iter()
                    .find(|peer| peer.id == route.from)
                    .expect("kind checked");
                let to = self
                    .anynet
                    .iter()
                    .find(|peer| peer.id == route.to)
                    .expect("kind checked");
                if from.local_lu != to.remote_lu || from.remote_lu != to.local_lu {
                    return Err(invalid(format!(
                        "MPTN relay LU policy mismatch between {} and {}",
                        route.from, route.to
                    )));
                }
            }
            add_directed(&mut directed, &route.from, &route.to)?;
            if route.bidirectional {
                add_directed(&mut directed, &route.to, &route.from)?;
            }
        }
        let mut exported_cps = HashSet::new();
        let mut exported_lus = HashSet::new();
        let mut exported_gateways = HashSet::new();
        for remote in &self.remote {
            // The current WebSocket adapter has one circuit and one credit
            // stream. It cannot safely multiplex several local associations.
            let attached = self
                .route
                .iter()
                .filter(|route| {
                    (route.from == remote.id && route.bidirectional)
                        || (route.to == remote.id && route.bidirectional)
                })
                .count();
            if attached != 1 || !directed.contains_key(remote.id.as_str()) {
                return Err(invalid(
                    "remote requires exactly one local route in each direction",
                ));
            }
            let local_id = directed[remote.id.as_str()];
            if let Some(gateway) = self.mptn_gateway.iter().find(|peer| peer.id == local_id) {
                let selected_lu = self
                    .gateway_routes(&gateway.id)
                    .into_iter()
                    .find_map(|(route, lu)| {
                        if route.from == remote.id || route.to == remote.id {
                            Some(lu)
                        } else {
                            None
                        }
                    })
                    .expect("remote has one gateway route");
                let selected_name = parse_cp(selected_lu)?;
                let target_cp_name =
                    parse_cp(remote.target_cp.as_deref().unwrap_or(&gateway.peer_cp))?;
                if selected_name.netid != target_cp_name.netid {
                    return Err(invalid(format!(
                        "TCP62 gateway destination LU {selected_lu} has a different NETID from concentrator {} target CP",
                        remote.id
                    )));
                }
                if remote.target_cp.as_deref().is_some_and(|cp| {
                    cp != gateway.peer_cp && selected_lu == gateway.destination_lu
                }) || remote
                    .target_lu
                    .as_deref()
                    .is_some_and(|lu| lu != selected_lu)
                {
                    return Err(invalid(format!(
                        "concentrator {} target does not match TCP62 gateway {} destination",
                        remote.id, gateway.id
                    )));
                }
                let local_cp = parse_cp(&gateway.local_cp)?;
                let source_lu = parse_cp(&gateway.source_lu)?;
                if exported_gateways.insert(&gateway.id)
                    && (!exported_cps.insert((local_cp.netid, local_cp.name))
                        || !exported_lus.insert((source_lu.netid, source_lu.name)))
                {
                    return Err(invalid("duplicate local CP or LU export"));
                }
                continue;
            }
            let peer = self
                .llc
                .iter()
                .find(|peer| peer.id == local_id)
                .ok_or_else(|| {
                    invalid(format!("remote {} must attach to an LLC peer", remote.id))
                })?;
            let owned_cp = peer.local_cp.as_ref().ok_or_else(|| {
                invalid(format!(
                    "concentrator {} cannot publish CP without local_cp on LLC peer {}",
                    remote.id, peer.id
                ))
            })?;
            if remote.target_cp.is_none() {
                return Err(invalid(format!(
                    "concentrator {} LLC route requires target_cp",
                    remote.id
                )));
            }
            if remote.target_lu.is_some() && peer.lus.len() != 1 {
                return Err(invalid(format!(
                    "concentrator {} v2 route requires exactly one local LU",
                    remote.id
                )));
            }
            let local_cp = parse_cp(owned_cp)?;
            if !exported_cps.insert((local_cp.netid, local_cp.name)) {
                return Err(invalid("duplicate local CP export"));
            }
            for lu in &peer.lus {
                let name = parse_cp(lu)?;
                if !exported_lus.insert((name.netid, name.name)) {
                    return Err(invalid("duplicate local LU export"));
                }
            }
        }
        let mut resolved_associations = HashSet::new();
        for peer in &self.llc {
            let guest = parse_mac(&peer.guest_mac)?;
            let proxy = self.llc_proxy_mac(&peer.id)?;
            if !resolved_associations.insert((peer.interface.as_str(), guest, proxy)) {
                return Err(invalid(format!(
                    "duplicate resolved LLC association on {}",
                    peer.interface
                )));
            }
            if let Some(proxy) = proxy {
                if proxy == guest {
                    return Err(invalid(format!(
                        "LLC peer {} has equal guest and proxy MACs",
                        peer.id
                    )));
                }
                let target_id = directed[peer.id.as_str()];
                if self.remote.iter().any(|remote| remote.id == target_id)
                    && proxy[..3] != [0x02, 0x53, 0x4e]
                {
                    return Err(invalid(format!(
                        "concentrator LLC peer {} must use assigned 02:53:4e virtual MAC",
                        peer.id
                    )));
                }
            }
        }
        for id in ids {
            if !directed.contains_key(id)
                && !self
                    .mptn_gateway
                    .iter()
                    .any(|gateway| gateway.id == id && !self.gateway_routes(id).is_empty())
            {
                return Err(invalid(format!("port {id} has no outgoing route")));
            }
        }
        let mut target_sources = HashMap::<&str, &str>::new();
        for (source, target) in directed {
            if self.mptn_gateway.iter().any(|gateway| gateway.id == target) {
                continue;
            }
            if let Some(old) = target_sources.insert(target, source) {
                if old != source {
                    return Err(invalid(format!(
                        "multiple ingress ports target {target}: {old} and {source}"
                    )));
                }
            }
        }
        if !self.hpr_lan.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HPR LAN to HPR/IP is experimental and awaits cross-medium XID3/TG validation before SETMODE",
            ));
        }
        Ok(())
    }

    fn validate_automatic(&self) -> io::Result<()> {
        // A concentrator is one shared directory connection in automatic mode,
        // not one statically selected circuit per destination.
        if self.remote.len() > 1 {
            return Err(invalid(
                "automatic routing supports one [[concentrator]] connection",
            ));
        }
        if self
            .remote
            .iter()
            .any(|remote| remote.target_cp.is_some() || remote.target_lu.is_some())
        {
            return Err(invalid(
                "automatic routing selects concentrator destinations from the received directory; omit target_cp and target_lu",
            ));
        }
        let mut llc_peers = HashSet::new();
        for peer in &self.llc {
            let key = (peer.interface.as_str(), parse_mac(&peer.guest_mac)?);
            if !llc_peers.insert(key) {
                return Err(invalid(format!(
                    "duplicate automatic LLC association on {} for {}",
                    peer.interface, peer.guest_mac
                )));
            }
        }
        if !self.hpr_lan.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HPR LAN attachment is experimental and cannot join automatic routing yet",
            ));
        }
        if !self.ee.is_empty() {
            if self.ee.len() != 1
                || self.remote.len() != 1
                || !self.llc.is_empty()
                || !self.mptn_gateway.is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "automatic HPR/IP currently requires one [[hpr_ip]] and one [[concentrator]] with no other attachments",
                ));
            }
            if self.ee[0].local_cp.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "automatic HPR/IP requires local_cp until stable router-owned CP identity is available",
                ));
            }
        }
        if !self.anynet.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "MPTN relay attachments cannot join automatic routing yet; use a gateway profile or explicit relay route",
            ));
        }
        Ok(())
    }
}

fn add_directed<'a>(
    routes: &mut HashMap<&'a str, &'a str>,
    from: &'a str,
    to: &'a str,
) -> io::Result<()> {
    if let Some(old) = routes.insert(from, to) {
        if old != to {
            return Err(invalid(format!(
                "ambiguous routes from {from}: {old} and {to}"
            )));
        }
    }
    Ok(())
}

fn validate_id(id: &str) -> io::Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(invalid(format!("invalid port ID {id:?}")));
    }
    Ok(())
}

pub(crate) fn parse_mac(input: &str) -> io::Result<[u8; 6]> {
    let mut mac = [0; 6];
    let mut parts = input.split(':');
    for byte in &mut mac {
        let part = parts
            .next()
            .filter(|part| part.len() == 2)
            .ok_or_else(|| invalid(format!("invalid MAC {input}")))?;
        *byte =
            u8::from_str_radix(part, 16).map_err(|_| invalid(format!("invalid MAC {input}")))?;
    }
    if parts.next().is_some() || mac[0] & 1 != 0 || mac == [0; 6] {
        return Err(invalid(format!("invalid unicast MAC {input}")));
    }
    Ok(mac)
}

pub(crate) fn parse_cp(input: &str) -> io::Result<wire::SnaName> {
    let (netid, name) = input
        .split_once('.')
        .ok_or_else(|| invalid(format!("invalid CP name {input}")))?;
    if name.contains('.') || !valid_sna_name(netid) || !valid_sna_name(name) {
        return Err(invalid(format!("invalid CP name {input}")));
    }
    Ok(wire::SnaName {
        netid: netid.to_owned(),
        name: name.to_owned(),
    })
}

fn valid_sna_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8
        && matches!(value.as_bytes()[0], b'A'..=b'Z' | b'@' | b'#' | b'$')
        && value.bytes().all(|b| {
            b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'@' | b'#' | b'$')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> RouterConfig {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn local_web_requires_listen_and_defaults_to_no_password() {
        let config = parse("[web]\nlisten = \"127.0.0.1:8082\"\n");
        let web = config.web.unwrap();
        assert_eq!(web.listen, "127.0.0.1:8082".parse().unwrap());
        assert!(web.password.is_empty());
        assert!(parse("").web.is_none());
        assert!(toml::from_str::<RouterConfig>("[web]\npassword = \"secret\"\n").is_err());
        let protected = parse("[web]\nlisten = \"127.0.0.1:8082\"\npassword = \"secret\"\n");
        assert!(!format!("{:?}", protected.web.unwrap()).contains("secret"));
    }

    #[test]
    fn qualified_names_match_server_sna_identity_syntax() {
        assert!(parse_cp("SOLNET.CP1").is_ok());
        assert!(parse_cp("1OLNET.CP1").is_err());
        assert!(parse_cp("SOLNET.1P1").is_err());
    }

    const GOOD: &str = r#"
[[llc]]
id = "a"
interface = "sol5"
guest_mac = "02:00:00:00:00:01"

[[llc]]
id = "b"
interface = "sol5"
guest_mac = "02:00:00:00:00:03"

[[route]]
from = "a"
to = "b"
"#;

    #[test]
    fn permits_multiple_peers_on_one_interface() {
        let derived = parse(GOOD);
        derived.validate().unwrap();
        assert_eq!(
            derived.llc_proxy_mac("a").unwrap(),
            Some(parse_mac("02:00:00:00:00:03").unwrap())
        );
        assert_eq!(
            derived.llc_proxy_mac("b").unwrap(),
            Some(parse_mac("02:00:00:00:00:01").unwrap())
        );
        let ambiguous = GOOD.replace(
            "to = \"b\"",
            "to = \"b\"\nproxy_mac = \"02:53:4e:00:00:05\"",
        );
        assert!(parse(&ambiguous)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot use one proxy_mac"));
    }

    #[test]
    fn directional_llc_routes_can_select_distinct_target_aliases() {
        let config = r#"
[[llc]]
id = "a"
interface = "sol5"
guest_mac = "02:00:00:00:00:01"
[[llc]]
id = "b"
interface = "sol5"
guest_mac = "02:00:00:00:00:02"
[[route]]
from = "a"
to = "b"
bidirectional = false
proxy_mac = "02:53:4e:00:00:05"
[[route]]
from = "b"
to = "a"
bidirectional = false
proxy_mac = "02:53:4e:00:00:06"
"#;
        let config = parse(config);
        config.validate().unwrap();
        assert_eq!(
            config.llc_proxy_mac("a").unwrap(),
            Some(parse_mac("02:53:4e:00:00:05").unwrap())
        );
        assert_eq!(
            config.llc_proxy_mac("b").unwrap(),
            Some(parse_mac("02:53:4e:00:00:06").unwrap())
        );
    }

    #[test]
    fn rejects_missing_and_ambiguous_routes() {
        assert!(parse(&GOOD.replace("to = \"b\"", "to = \"missing\""))
            .validate()
            .is_err());
        assert!(parse(&format!(
            "{GOOD}\n[[route]]\nfrom = \"a\"\nto = \"b\"\nbidirectional = false\n"
        ))
        .validate()
        .is_ok());
        assert!(parse(&format!("{GOOD}\n[[llc]]\nid=\"c\"\ninterface=\"sol6\"\nguest_mac=\"02:00:00:00:00:05\"\n[[route]]\nfrom=\"a\"\nto=\"c\"\n")).validate().is_err());
    }

    #[test]
    fn rejects_duplicate_association_and_malformed_mac() {
        assert!(
            parse(&GOOD.replace("02:00:00:00:00:03", "02:00:00:00:00:01"))
                .validate()
                .is_err()
        );
        assert!(
            parse(&GOOD.replace("02:00:00:00:00:03", "03:00:00:00:00:03"))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn same_guest_can_address_two_distinct_proxy_macs() {
        let config = parse(
            r#"
[[llc]]
id = "a1"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
[[llc]]
id = "a2"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
[[llc]]
id = "b1"
interface = "sol4"
guest_mac = "02:00:35:27:23:02"
[[llc]]
id = "b2"
interface = "sol4"
guest_mac = "02:00:35:27:23:02"
[[route]]
from = "a1"
to = "b1"
bidirectional = false
proxy_mac = "02:53:4e:00:00:01"
[[route]]
from = "b1"
to = "a1"
bidirectional = false
proxy_mac = "02:53:4e:00:00:03"
[[route]]
from = "a2"
to = "b2"
bidirectional = false
proxy_mac = "02:53:4e:00:00:02"
[[route]]
from = "b2"
to = "a2"
bidirectional = false
proxy_mac = "02:53:4e:00:00:04"
"#,
        );
        config.validate().unwrap();
    }

    #[test]
    fn ee_only_route_is_valid_and_llc_to_ee_is_rejected() {
        let ee = r#"
[[hpr_ip]]
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[hpr_ip]]
id = "west"
local_ip = "127.0.0.4"
peer_ip = "127.0.0.5"
[[route]]
from = "east"
to = "west"
"#;
        parse(ee).validate().unwrap();
        let mixed = r#"
[[llc]]
id = "a"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
[[hpr_ip]]
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[route]]
from = "a"
to = "east"
"#;
        assert!(parse(mixed)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unsupported route"));
        assert!(toml::from_str::<RouterConfig>(
            "[[ee]]\nid='old'\nlocal_ip='127.0.0.2'\npeer_ip='127.0.0.3'\n"
        )
        .is_err());
    }

    #[test]
    fn concentrator_exports_are_derived_from_attached_llc_peer() {
        let config = r#"
[[llc]]
id = "a"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
local_cp = "SOLNET.SNAA"
lus = ["SOLNET.LUA"]
lu_types = { "SOLNET.LUA" = ["lu_6_2"] }
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
target_cp = "DSTNET.SNAB"
target_lu = "DSTNET.PAYROLL"
token = "test-token"
[[route]]
from = "a"
to = "upstream"
"#;
        let parsed = parse(config);
        parsed.validate().unwrap();
        assert_eq!(parsed.llc_proxy_mac("a").unwrap(), None);
        let route_proxy = config.replace(
            "to = \"upstream\"",
            "to = \"upstream\"\nproxy_mac = \"02:53:4e:00:00:09\"",
        );
        let route_proxy = parse(&route_proxy);
        route_proxy.validate().unwrap();
        assert_eq!(
            route_proxy.llc_proxy_mac("a").unwrap(),
            Some(parse_mac("02:53:4e:00:00:09").unwrap())
        );
        assert!(toml::from_str::<RouterConfig>(&config.replace(
            "guest_mac = \"02:00:35:27:23:01\"",
            "guest_mac = \"02:00:35:27:23:01\"\nproxy_mac = \"02:53:4e:00:00:09\""
        ))
        .is_err());
        assert_eq!(
            parsed.concentrator_local_id(&parsed.remote[0]).unwrap(),
            "a"
        );
        assert_eq!(parsed.remote[0].bearer_token().unwrap(), "test-token");
        assert!(!format!("{:?}", parsed).contains("test-token"));
        let without_token = parse(&config.replace("token = \"test-token\"\n", ""));
        without_token.validate().unwrap();
        assert_eq!(without_token.remote[0].bearer_token().unwrap(), "");
        parse(&config.replace("[[concentrator]]", "[[remote]]"))
            .validate()
            .unwrap();
        assert_eq!(
            parsed.llc[0].lu_types["SOLNET.LUA"],
            vec![ConfiguredLuType::Lu6_2]
        );
        assert!(
            parse(&config.replace("02:00:35:27:23:01", "03:00:35:27:23:01"))
                .validate()
                .unwrap_err()
                .to_string()
                .contains("invalid unicast MAC")
        );
        assert!(parse(&config.replace("target_cp = \"DSTNET.SNAB\"", ""))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires target_cp"));
        assert!(parse(&config.replace("DSTNET.PAYROLL", "SOLNET.PAYROLL"))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("different NETID"));
        assert!(parse(&config.replace("SOLNET.LUA", "OTHER.LUA"))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("outside its local NETID"));
        assert!(parse(&config.replace(
            "lu_types = { \"SOLNET.LUA\" = [\"lu_6_2\"] }",
            "lu_types = { \"SOLNET.OTHER\" = [\"lu_6_2\"] }"
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("unexported LU"));
        assert!(toml::from_str::<RouterConfig>(
            &config.replace("token = \"test-token\"", "source_lu = \"SOLNET.LUA\"")
        )
        .is_err());
    }

    #[test]
    fn concentrator_circuits_cannot_mix_protocol_versions() {
        let config = r#"
[[llc]]
id = "a"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
local_cp = "SOLNET.SNAA"
lus = ["SOLNET.LUA"]
[[llc]]
id = "b"
interface = "sol6"
guest_mac = "02:00:35:27:23:02"
local_cp = "SOLNET.SNAB"
lus = ["SOLNET.LUB"]
[[concentrator]]
id = "upstream_a"
url = "ws://127.0.0.1:8081/router/v1/ws"
target_cp = "DSTNET.PEERA"
target_lu = "DSTNET.LUA"
token = "shared"
[[concentrator]]
id = "upstream_b"
url = "ws://127.0.0.1:8081/router/v1/ws"
target_cp = "DSTNET.PEERB"
token = "shared"
[[route]]
from = "a"
to = "upstream_a"
[[route]]
from = "b"
to = "upstream_b"
"#;
        assert!(parse(config)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("same protocol version"));
    }

    #[test]
    fn tcp62_gateway_derives_exports_and_target_from_gateway_definition() {
        let gateway = r#"
[[mptn]]
profile = "gateway"
id = "bob"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
source_lu = "QABOB.SNAB"
destination_lu = "QAALICE.SNAA"
local_station = "BOB"
local_node_id = "FFF12345"
tg_number = 1
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = ""
[[route]]
from = "bob"
to = "upstream"
converter = "mptn_lu62"
"#;
        let parsed = parse(gateway);
        parsed.validate().unwrap();
        assert_eq!(
            parsed.concentrator_local_id(&parsed.remote[0]).unwrap(),
            "bob"
        );
        assert_eq!(parsed.remote[0].bearer_token().unwrap(), "");
        assert!(parse(&gateway.replace("converter = \"mptn_lu62\"", ""))
            .validate()
            .is_err());
        assert!(
            parse(&gateway.replace("token = \"\"", "target_lu = \"QAALICE.OTHER\""))
                .validate()
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn concentrator_to_mptn_reverse_requires_exact_explicit_source() {
        let config = r#"
[[mptn]]
profile = "gateway"
id = "bob"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
source_lu = "QABOB.SNAB"
destination_lu = "QAALICE.SNAA"
local_station = "BOB"
local_node_id = "FFF12345"
tg_number = 1
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
target_cp = "QAALICE.SNAA"
target_lu = "QAALICE.SNAA"
token = ""
[[route]]
from = "upstream"
to = "bob"
converter = "mptn_lu62"
destination_lu = "QAALICE.SNAA"
user_tp_hex = "D7C1E2E3"
timeout_seconds = 120
"#;
        let parsed = parse(config);
        parsed.validate().unwrap();
        let reverse = parsed.reverse_ws_config().unwrap().unwrap();
        assert_eq!(reverse.hosted_lu, "QABOB.SNAB");
        assert_eq!(reverse.source_lu, "QAALICE.SNAA");
        assert_eq!(reverse.timeout, Duration::from_secs(120));
        assert_eq!(reverse.endpoint.peer_ip.to_string(), "10.99.4.3");
        let inbound = parse(&config.replace(
            "from = \"upstream\"\nto = \"bob\"",
            "from = \"bob\"\nto = \"upstream\"",
        ));
        inbound.validate().unwrap();
        assert!(inbound.reverse_ws_config().unwrap().is_none());
        let duplex = inbound.bidirectional_gateway_config().unwrap().unwrap();
        assert_eq!(duplex.gateway.id, "bob");
        assert_eq!(duplex.concentrator.id, "upstream");
        assert_eq!(duplex.reverse.hosted_lu, "QABOB.SNAB");
        assert_eq!(duplex.reverse.source_lu, "QAALICE.SNAA");
        assert_eq!(duplex.route.destination_lu.as_deref(), Some("QAALICE.SNAA"));
        assert!(parse(&config.replace(
            "target_lu = \"QAALICE.SNAA\"",
            "target_lu = \"QAALICE.OTHER\""
        ))
        .validate()
        .is_err());
        assert!(parse(&config.replace("user_tp_hex = \"D7C1E2E3\"", ""))
            .validate()
            .is_err());
    }

    #[test]
    fn single_target_duplex_gateway_derives_repeated_peer_identity() {
        let config = parse(
            r#"
[[mptn]]
profile = "gateway"
id = "bob"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
local_node_id = "FFF12345"
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
[[route]]
from = "bob"
to = "upstream"
converter = "mptn_lu62"
user_tp_hex = "30f0f0f5"
"#,
        );
        config.validate().unwrap();
        let gateway = &config.mptn_gateway[0];
        assert_eq!(gateway.source_lu, "QABOB.SNAB");
        assert_eq!(gateway.destination_lu, "QAALICE.SNAA");
        assert_eq!(gateway.local_station, "SNAB");
        assert_eq!(gateway.tg_number, 1);
        let duplex = config.bidirectional_gateway_config().unwrap().unwrap();
        assert_eq!(duplex.reverse.source_cp, "QAALICE.SNAA");
        assert_eq!(duplex.reverse.source_lu, "QAALICE.SNAA");
        assert_eq!(duplex.reverse.remote.bearer, "");
    }

    #[test]
    fn tcp62_gateway_routes_multiple_destination_lus_on_one_listener() {
        let config = r#"
[[mptn]]
profile = "gateway"
id = "bob"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
local_cp = "QABOB.SNAB"
peer_cp = "QAALICE.SNAA"
source_lu = "QABOB.SNAB"
destination_lu = "QAALICE.SNAA"
local_station = "BOB"
local_node_id = "FFF12345"
tg_number = 1
[[concentrator]]
id = "alice"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = ""
target_cp = "QAALICE.SNAA"
target_lu = "QAALICE.SNAA"
[[concentrator]]
id = "carol"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = ""
target_cp = "QACAROL.SNAC"
target_lu = "QACAROL.SNAC"
[[route]]
from = "bob"
to = "alice"
converter = "mptn_lu62"
destination_lu = "QAALICE.SNAA"
[[route]]
from = "bob"
to = "carol"
converter = "mptn_lu62"
destination_lu = "QACAROL.SNAC"
"#;
        let parsed = parse(config);
        parsed.validate().unwrap();
        assert_eq!(
            parsed
                .gateway_routes("bob")
                .into_iter()
                .map(|(route, lu)| (route.to.as_str(), lu))
                .collect::<Vec<_>>(),
            vec![("alice", "QAALICE.SNAA"), ("carol", "QACAROL.SNAC")]
        );
        assert!(
            parse(&config.replace("QACAROL.SNAC\"\n[[route]]", "QAALICE.SNAA\"\n[[route]]"))
                .validate()
                .is_err()
        );
        assert!(parse(&config.replace(
            "destination_lu = \"QACAROL.SNAC\"",
            "destination_lu = \"QAALICE.SNAA\""
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("duplicate TCP62 gateway destination"));
        assert!(parse(
            &config
                .replace(
                    "target_cp = \"QACAROL.SNAC\"",
                    "target_cp = \"QAALICE.SNAC\""
                )
                .replace(
                    "target_lu = \"QACAROL.SNAC\"",
                    "target_lu = \"QAALICE.OTHER\""
                )
        )
        .validate()
        .unwrap_err()
        .to_string()
        .contains("different NETID from concentrator carol target CP"));
        assert!(parse(&config.replace(
            "from = \"bob\"\nto = \"carol\"",
            "from = \"bob\"\nto = \"carol\"\nbidirectional = false"
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("must be bidirectional"));
    }

    #[test]
    fn anynet_only_route_is_valid_and_mixed_profile_is_rejected() {
        let anynet = r#"
[[mptn]]
profile = "relay"
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[mptn]]
profile = "relay"
id = "west"
local_ip = "127.0.0.4"
peer_ip = "127.0.0.5"
[[route]]
from = "east"
to = "west"
"#;
        parse(anynet).validate().unwrap();
        let duplicate_listener = anynet.replace("127.0.0.4", "127.0.0.2");
        assert!(parse(&duplicate_listener).validate().is_err());
        let mixed = r#"
[[mptn]]
profile = "relay"
id = "mptn"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[hpr_ip]]
id = "hpr"
local_ip = "127.0.0.4"
peer_ip = "127.0.0.5"
[[route]]
from = "mptn"
to = "hpr"
"#;
        assert!(parse(mixed)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unsupported route"));
    }

    #[test]
    fn mptn_profile_is_required_and_old_sections_are_rejected() {
        let relay = r#"
[[mptn]]
profile = "relay"
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[mptn]]
profile = "relay"
id = "west"
local_ip = "127.0.0.4"
peer_ip = "127.0.0.5"
[[route]]
from = "east"
to = "west"
"#;
        parse(relay).validate().unwrap();
        assert!(
            toml::from_str::<RouterConfig>(&relay.replace("profile = \"relay\"\n", "")).is_err()
        );
        assert!(toml::from_str::<RouterConfig>(&relay.replace("[[mptn]]", "[[anynet]]")).is_err());
        assert!(
            toml::from_str::<RouterConfig>(&relay.replace("[[mptn]]", "[[mptn_gateway]]")).is_err()
        );
        assert!(
            parse(&relay.replace("profile = \"relay\"", "profile = \"gateway\""))
                .validate()
                .is_err()
        );
        assert!(toml::from_str::<RouterConfig>(&relay.replace(
            "peer_ip = \"127.0.0.3\"",
            "peer_ip = \"127.0.0.3\"\nlocal_cp = \"SOLNET.SNAA\""
        ))
        .is_err());
    }

    #[test]
    fn anynet_lu_policy_must_be_complete_and_reciprocal() {
        let strict = r#"
[[mptn]]
profile = "relay"
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
local_lu = "SOLNET.SNAA"
remote_lu = "SOLNET.SNAB"
[[mptn]]
profile = "relay"
id = "west"
local_ip = "127.0.0.4"
peer_ip = "127.0.0.5"
local_lu = "SOLNET.SNAB"
remote_lu = "SOLNET.SNAA"
[[route]]
from = "east"
to = "west"
"#;
        parse(strict).validate().unwrap();
        assert!(parse(&strict.replace(
            "remote_lu = \"SOLNET.SNAA\"",
            "remote_lu = \"SOLNET.OTHER\""
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy mismatch"));
        assert!(parse(&strict.replace("local_lu = \"SOLNET.SNAA\"", ""))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires both"));
    }

    #[test]
    fn hpr_lan_requires_explicit_experiment_and_ee_target() {
        let mixed = r#"
[[hpr_lan]]
id = "lan"
interface = "sol6"
guest_mac = "02:04:ac:05:45:04"
proxy_mac = "02:53:4e:00:00:04"
experimental = true
[[hpr_ip]]
id = "ip"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[route]]
from = "lan"
to = "ip"
"#;
        assert_eq!(
            parse(mixed).validate().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(
            parse(&mixed.replace("experimental = true", "experimental = false"))
                .validate()
                .unwrap_err()
                .to_string()
                .contains("experimental")
        );
        assert!(parse(&mixed.replace("to = \"ip\"", "to = \"lan\""))
            .validate()
            .is_err());
        assert!(
            parse(&mixed.replace("[[hpr_ip]]", "[[mptn]]\nprofile = \"relay\""))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn llc_anynet_converter_intent_is_explicit_and_disabled() {
        let gateway = r#"
[[llc]]
id = "lan"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
[[mptn]]
profile = "relay"
id = "mptn"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
local_lu = "SOLNET.SNAB"
remote_lu = "SOLNET.SNAA"
[[route]]
from = "lan"
to = "mptn"
converter = "mptn_lu62"
"#;
        let error = parse(gateway).validate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("MPTN session gateway"));
        assert!(parse(&gateway.replace("converter = \"mptn_lu62\"", ""))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unsupported route"));
        assert!(toml::from_str::<RouterConfig>(
            &gateway.replace("converter = \"mptn_lu62\"", "converter = \"unknown\"")
        )
        .is_err());
    }

    #[test]
    fn standalone_llc_to_mptn_resolves_one_exact_reverse_circuit() {
        let config = r#"
[[llc]]
id = "alice"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
local_cp = "SOLNET.SNAA"
lus = ["SOLNET.SNAA"]
[[mptn]]
profile = "gateway"
id = "bob"
local_ip = "10.99.4.10"
peer_ip = "10.99.4.3"
local_cp = "SOLNET.SNAB"
peer_cp = "SOLNET.SNAA"
source_lu = "SOLNET.SNAB"
destination_lu = "SOLNET.SNAA"
local_station = "BOB"
local_node_id = "FFF12345"
tg_number = 1
[[route]]
from = "alice"
to = "bob"
converter = "mptn_lu62"
proxy_mac = "02:53:4e:00:00:02"
user_tp_hex = "30f0f0f5"
timeout_seconds = 600
"#;
        let parsed = parse(config);
        parsed.validate().unwrap();
        let reverse = parsed.reverse_llc_config().unwrap().unwrap();
        assert_eq!(reverse.source_lu, "SOLNET.SNAA");
        assert_eq!(reverse.destination_lu, "SOLNET.SNAB");
        assert_eq!(reverse.user_tp, [0x30, 0xf0, 0xf0, 0xf5]);
        assert_eq!(reverse.proxy_mac, [0x02, 0x53, 0x4e, 0, 0, 2]);
        assert_eq!(reverse.timeout, Duration::from_secs(600));
        for bad in [
            config.replace("user_tp_hex = \"30f0f0f5\"", ""),
            config.replace("lus = [\"SOLNET.SNAA\"]", "lus = []"),
            config.replace(
                "destination_lu = \"SOLNET.SNAA\"",
                "destination_lu = \"SOLNET.SNAC\"",
            ),
            config.replace("timeout_seconds = 600", "timeout_seconds = 601"),
            config.replace("proxy_mac = \"02:53:4e:00:00:02\"", ""),
            config.replace("to = \"bob\"", "to = \"bob\"\nbidirectional = false"),
        ] {
            assert!(parse(&bad).validate().is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn route_free_config_selects_automatic_mode_with_minimal_attachments() {
        let config = parse(
            r#"
[web]
listen = "127.0.0.1:8082"
password = "secret"
[[llc]]
id = "v4"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
[[mptn]]
profile = "gateway"
id = "v5"
local_ip = "10.99.4.11"
peer_ip = "10.99.4.3"
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
token = "router-token"
"#,
        );
        assert!(config.automatic());
        config.validate().unwrap();
        assert_eq!(config.mptn_gateway[0].local_cp, "");
        assert_eq!(config.mptn_gateway[0].local_node_id, "");
        assert!(config.remote[0].target_cp.is_none());
    }

    #[test]
    fn automatic_mode_rejects_ambiguous_or_fixed_destinations() {
        let base = r#"
[[llc]]
id = "v4"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
[[concentrator]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
"#;
        assert!(parse(base).validate().is_ok());
        let fixed = base.replace(
            "id = \"upstream\"",
            "id = \"upstream\"\ntarget_cp = \"OTHERNET.CP\"",
        );
        assert!(parse(&fixed)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("omit target_cp"));
        let duplicate = base.replace(
            "[[concentrator]]",
            "[[llc]]\nid = \"v4b\"\ninterface = \"sol5\"\nguest_mac = \"02:00:35:27:23:01\"\n[[concentrator]]",
        );
        assert!(parse(&duplicate)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate automatic LLC"));
        let second = format!(
            "{base}\n[[concentrator]]\nid = \"second\"\nurl = \"ws://127.0.0.1:8081/router/v1/ws\"\n"
        );
        assert!(parse(&second)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("one [[concentrator]]"));
    }

    #[test]
    fn automatic_mode_admits_single_hpr_attachment_with_concentrator() {
        let ee = parse("[[hpr_ip]]\nid='ee'\nlocal_ip='192.0.2.1'\npeer_ip='192.0.2.2'\n");
        let error = ee.validate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("one [[concentrator]]"));

        let with_upstream = parse(
            "[[hpr_ip]]\nid='ee'\nlocal_ip='192.0.2.1'\npeer_ip='192.0.2.2'\nlocal_cp='SNUSNU.SVC'\n[[concentrator]]\nid='upstream'\nurl='ws://127.0.0.1:8081/router/v1/ws'\n",
        );
        with_upstream.validate().unwrap();
        assert!(with_upstream.automatic());
        assert!(parse(
            "[[hpr_ip]]\nid='ee'\nlocal_ip='192.0.2.1'\npeer_ip='192.0.2.2'\n[[concentrator]]\nid='upstream'\nurl='ws://127.0.0.1:8081/router/v1/ws'\n",
        )
        .validate()
        .unwrap_err()
        .to_string()
        .contains("requires local_cp"));

        let duplicate = parse(
            "[[hpr_ip]]\nid='ee'\nlocal_ip='192.0.2.1'\npeer_ip='192.0.2.2'\n[[hpr_ip]]\nid='other'\nlocal_ip='192.0.2.3'\npeer_ip='192.0.2.4'\n[[concentrator]]\nid='upstream'\nurl='ws://127.0.0.1:8081/router/v1/ws'\n",
        );
        assert_eq!(
            duplicate.validate().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let relay = parse(
            "[[mptn]]\nprofile='relay'\nid='relay'\nlocal_ip='192.0.2.3'\npeer_ip='192.0.2.4'\n",
        );
        let error = relay.validate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("MPTN relay attachments"));
    }
}
