//! Declarative local router configuration. Each LLC entry is one independent
//! association, even when several entries share an Ethernet interface.

use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::IpAddr,
    path::Path,
};
use transport_ws::wire;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouterConfig {
    #[serde(default)]
    pub(crate) llc: Vec<LlcConfig>,
    #[serde(default)]
    pub(crate) ee: Vec<EeConfig>,
    #[serde(default)]
    pub(crate) anynet: Vec<AnyNetConfig>,
    #[serde(default)]
    pub(crate) hpr_lan: Vec<HprLanConfig>,
    #[serde(default)]
    pub(crate) route: Vec<RouteConfig>,
    #[serde(default)]
    pub(crate) remote: Vec<RemoteConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EeConfig {
    pub(crate) id: String,
    pub(crate) local_ip: IpAddr,
    pub(crate) peer_ip: IpAddr,
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
    pub(crate) proxy_mac: String,
    pub(crate) local_cp: Option<String>,
    #[serde(default)]
    pub(crate) lus: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteConfig {
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default = "default_bidirectional")]
    pub(crate) bidirectional: bool,
    pub(crate) converter: Option<RouteConverter>,
}

/// A route names a converter explicitly before two different session
/// profiles can be joined. No converter is currently enabled at runtime.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RouteConverter {
    MptnLu62,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteConfig {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) local_cp: String,
    pub(crate) target_cp: String,
    pub(crate) target_lu: Option<String>,
    #[serde(default)]
    pub(crate) lus: Vec<String>,
    #[serde(default)]
    pub(crate) lu_types: HashMap<String, Vec<ConfiguredLuType>>,
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

impl RouterConfig {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.llc.is_empty()
            && self.ee.is_empty()
            && self.anynet.is_empty()
            && self.hpr_lan.is_empty()
        {
            return Err(invalid(
                "at least one [[llc]], [[ee]], [[anynet]] or [[hpr_lan]] peer is required",
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
            let guest = parse_mac(&peer.guest_mac)?;
            let proxy = parse_mac(&peer.proxy_mac)?;
            if guest == proxy {
                return Err(invalid(format!(
                    "LLC peer {} has equal guest and proxy MACs",
                    peer.id
                )));
            }
            if !peers.insert((peer.interface.as_str(), guest, proxy)) {
                return Err(invalid(format!(
                    "duplicate LLC association on {}",
                    peer.interface
                )));
            }
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
                if !local_lus.insert((name.netid, name.name)) {
                    return Err(invalid(format!(
                        "duplicate LU {lu} on LLC peer {}",
                        peer.id
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
            if !peers.insert((peer.interface.as_str(), guest, proxy)) {
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
            kinds.insert(&peer.id, "ee");
            if peer.local_ip == peer.peer_ip
                || peer.local_ip.is_ipv4() != peer.peer_ip.is_ipv4()
                || peer.local_ip.is_unspecified()
                || peer.peer_ip.is_unspecified()
            {
                return Err(invalid(format!("invalid EE IP pair for {}", peer.id)));
            }
            if !ee_listeners.insert(peer.local_ip) {
                return Err(invalid(format!(
                    "duplicate EE UDP listener IP {}",
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
            kinds.insert(&peer.id, "anynet");
            if peer.local_ip == peer.peer_ip
                || peer.local_ip.is_ipv4() != peer.peer_ip.is_ipv4()
                || peer.local_ip.is_unspecified()
                || peer.peer_ip.is_unspecified()
            {
                return Err(invalid(format!("invalid AnyNet IP pair for {}", peer.id)));
            }
            if !anynet_listeners.insert(peer.local_ip) {
                return Err(invalid(format!(
                    "duplicate AnyNet TCP/UDP listener IP {}",
                    peer.local_ip
                )));
            }
            match (&peer.local_lu, &peer.remote_lu) {
                (Some(local), Some(remote)) => {
                    let local = parse_cp(local)?;
                    let remote = parse_cp(remote)?;
                    if local == remote {
                        return Err(invalid(format!(
                            "AnyNet LU pair for {} is identical",
                            peer.id
                        )));
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(invalid(format!(
                        "AnyNet peer {} requires both local_lu and remote_lu",
                        peer.id
                    )))
                }
            }
        }
        let mut exported_cps = HashSet::new();
        let mut exported_lus = HashSet::new();
        for remote in &self.remote {
            validate_id(&remote.id)?;
            if !ids.insert(remote.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", remote.id)));
            }
            kinds.insert(&remote.id, "remote");
            if !remote.url.starts_with("ws://") && !remote.url.starts_with("wss://") {
                return Err(invalid("remote.url must be a ws:// or wss:// URL"));
            }
            let local_cp = parse_cp(&remote.local_cp)?;
            if !exported_cps.insert((local_cp.netid.clone(), local_cp.name.clone())) {
                return Err(invalid(format!(
                    "duplicate exported CP {}",
                    remote.local_cp
                )));
            }
            let target_cp = parse_cp(&remote.target_cp)?;
            if let Some(target_lu) = &remote.target_lu {
                let target_lu = parse_cp(target_lu)?;
                if target_lu.netid != target_cp.netid {
                    return Err(invalid(format!(
                        "target LU {} has a different NETID from target CP {}",
                        remote.target_lu.as_deref().unwrap_or_default(),
                        remote.target_cp
                    )));
                }
            }
            for lu in &remote.lus {
                let lu_name = parse_cp(lu)?;
                if !exported_lus.insert((lu_name.netid, lu_name.name)) {
                    return Err(invalid(format!("duplicate exported LU {lu}")));
                }
            }
            for (lu, types) in &remote.lu_types {
                if !remote.lus.contains(lu) {
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
        if self
            .remote
            .windows(2)
            .any(|pair| pair[0].url != pair[1].url)
        {
            return Err(invalid("all remote circuits must share one WebSocket URL"));
        }
        let mut directed = HashMap::<&str, &str>::new();
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
            if let Some(converter) = route.converter {
                if matches!(
                    (source_kind, target_kind),
                    ("llc", "anynet") | ("anynet", "llc")
                ) && matches!(converter, RouteConverter::MptnLu62)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "LLC to AnyNet LU6.2 conversion requires an operational MPTN session gateway",
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
                    | ("ee", "ee")
                    | ("hpr_lan", "ee")
                    | ("ee", "hpr_lan")
                    | ("anynet", "anynet")
            ) {
                return Err(invalid(format!(
                    "unsupported route {} ({source_kind}) -> {} ({target_kind})",
                    route.from, route.to
                )));
            }
            if source_kind == "anynet" {
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
                        "AnyNet LU policy mismatch between {} and {}",
                        route.from, route.to
                    )));
                }
            }
            add_directed(&mut directed, &route.from, &route.to)?;
            if route.bidirectional {
                add_directed(&mut directed, &route.to, &route.from)?;
            }
        }
        for remote in &self.remote {
            // The current WebSocket adapter has one circuit and one credit
            // stream. It cannot safely multiplex several local associations.
            let attached = directed
                .iter()
                .filter(|(_, target)| **target == remote.id)
                .count();
            if attached != 1 || !directed.contains_key(remote.id.as_str()) {
                return Err(invalid(
                    "remote requires exactly one local LLC route in each direction",
                ));
            }
            let local_id = directed[remote.id.as_str()];
            let peer = self
                .llc
                .iter()
                .find(|peer| peer.id == local_id)
                .ok_or_else(|| {
                    invalid(format!("remote {} must attach to an LLC peer", remote.id))
                })?;
            let proxy = parse_mac(&peer.proxy_mac)?;
            if proxy[..3] != [0x02, 0x53, 0x4e] {
                return Err(invalid(format!(
                    "remote LLC peer {} must use assigned 02:53:4e virtual MAC",
                    peer.id
                )));
            }
            let owned_cp = peer.local_cp.as_ref().ok_or_else(|| {
                invalid(format!(
                    "remote {} cannot publish CP without local_cp on LLC peer {}",
                    remote.id, peer.id
                ))
            })?;
            if parse_cp(owned_cp)? != parse_cp(&remote.local_cp)? {
                return Err(invalid(format!(
                    "remote {} publishes CP {} not owned by LLC peer {}",
                    remote.id, remote.local_cp, peer.id
                )));
            }
            let owned_lus = peer
                .lus
                .iter()
                .map(|lu| parse_cp(lu))
                .collect::<io::Result<HashSet<_>>>()?;
            for lu in &remote.lus {
                if !owned_lus.contains(&parse_cp(lu)?) {
                    return Err(invalid(format!(
                        "remote {} publishes LU {lu} not owned by LLC peer {}",
                        remote.id, peer.id
                    )));
                }
            }
        }
        for id in ids {
            if !directed.contains_key(id) {
                return Err(invalid(format!("port {id} has no outgoing route")));
            }
        }
        let mut target_sources = HashMap::<&str, &str>::new();
        for (source, target) in directed {
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
                "HPR LAN to EE is experimental and awaits cross-medium XID3/TG validation before SETMODE",
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
proxy_mac = "02:53:4e:00:00:02"

[[llc]]
id = "b"
interface = "sol5"
guest_mac = "02:00:00:00:00:03"
proxy_mac = "02:53:4e:00:00:04"

[[route]]
from = "a"
to = "b"
"#;

    #[test]
    fn permits_multiple_peers_on_one_interface() {
        parse(GOOD).validate().unwrap();
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
        assert!(parse(&format!("{GOOD}\n[[llc]]\nid=\"c\"\ninterface=\"sol6\"\nguest_mac=\"02:00:00:00:00:05\"\nproxy_mac=\"02:53:4e:00:00:06\"\n[[route]]\nfrom=\"a\"\nto=\"c\"\n")).validate().is_err());
    }

    #[test]
    fn rejects_duplicate_association_and_malformed_mac() {
        assert!(parse(
            &GOOD
                .replace("02:00:00:00:00:03", "02:00:00:00:00:01")
                .replace("02:53:4e:00:00:04", "02:53:4e:00:00:02")
        )
        .validate()
        .is_err());
        assert!(
            parse(&GOOD.replace("02:53:4e:00:00:04", "03:53:4e:00:00:04"))
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
proxy_mac = "02:53:4e:00:00:01"
[[llc]]
id = "a2"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:53:4e:00:00:02"
[[llc]]
id = "b1"
interface = "sol4"
guest_mac = "02:00:35:27:23:02"
proxy_mac = "02:53:4e:00:00:03"
[[llc]]
id = "b2"
interface = "sol4"
guest_mac = "02:00:35:27:23:02"
proxy_mac = "02:53:4e:00:00:04"
[[route]]
from = "a1"
to = "b1"
[[route]]
from = "a2"
to = "b2"
"#,
        );
        config.validate().unwrap();
    }

    #[test]
    fn ee_only_route_is_valid_and_llc_to_ee_is_rejected() {
        let ee = r#"
[[ee]]
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[ee]]
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
proxy_mac = "02:53:4e:00:00:01"
[[ee]]
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
    }

    #[test]
    fn remote_exports_require_managed_mac_and_one_local_peer() {
        let remote = r#"
[[llc]]
id = "a"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:53:4e:00:00:01"
local_cp = "SOLNET.SNAA"
lus = ["SOLNET.LUA"]
[[remote]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
local_cp = "SOLNET.SNAA"
target_cp = "SOLNET.SNAB"
lus = ["SOLNET.LUA"]
lu_types = { "SOLNET.LUA" = ["lu_6_2"] }
[[route]]
from = "a"
to = "upstream"
"#;
        let configured = parse(remote);
        configured.validate().unwrap();
        assert_eq!(
            configured.remote[0].lu_types["SOLNET.LUA"],
            vec![ConfiguredLuType::Lu6_2]
        );
        let cross_netid = remote.replace(
            "target_cp = \"SOLNET.SNAB\"",
            "target_cp = \"DSTNET.SNAB\"\ntarget_lu = \"DSTNET.PAYROLL\"",
        );
        parse(&cross_netid).validate().unwrap();
        assert_eq!(
            parse(&cross_netid).remote[0].target_lu.as_deref(),
            Some("DSTNET.PAYROLL")
        );
        assert!(
            parse(&cross_netid.replace("DSTNET.PAYROLL", "SOLNET.PAYROLL"))
                .validate()
                .unwrap_err()
                .to_string()
                .contains("different NETID")
        );
        assert!(parse(&remote.replace("02:53:4e", "02:00:4e"))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("virtual MAC"));
        assert!(parse(&remote.replace("SOLNET.LUA", "bad.lu"))
            .validate()
            .is_err());
        assert!(
            parse(&remote.replace("local_cp = \"SOLNET.SNAA\"\nlus = [\"SOLNET.LUA\"]\n", ""))
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cannot publish CP")
        );
        assert!(parse(&remote.replacen(
            "local_cp = \"SOLNET.SNAA\"\n",
            "local_cp = \"SOLNET.OTHER\"\n",
            1
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("not owned"));
        assert!(parse(&remote.replace(
            "target_cp = \"SOLNET.SNAB\"\nlus = [\"SOLNET.LUA\"]\nlu_types = { \"SOLNET.LUA\" = [\"lu_6_2\"] }",
            "target_cp = \"SOLNET.SNAB\"\nlus = [\"SOLNET.LUB\"]"
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("not owned"));
        assert!(parse(&remote.replace(
            "lu_types = { \"SOLNET.LUA\" = [\"lu_6_2\"] }",
            "lu_types = { \"SOLNET.LUB\" = [\"lu_6_2\"] }"
        ))
        .validate()
        .unwrap_err()
        .to_string()
        .contains("unexported LU"));
    }

    #[test]
    fn anynet_only_route_is_valid_and_mixed_profile_is_rejected() {
        let anynet = r#"
[[anynet]]
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[anynet]]
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
[[anynet]]
id = "mptn"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
[[ee]]
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
    fn anynet_lu_policy_must_be_complete_and_reciprocal() {
        let strict = r#"
[[anynet]]
id = "east"
local_ip = "127.0.0.2"
peer_ip = "127.0.0.3"
local_lu = "SOLNET.SNAA"
remote_lu = "SOLNET.SNAB"
[[anynet]]
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
[[ee]]
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
        assert!(parse(&mixed.replace("[[ee]]", "[[anynet]]"))
            .validate()
            .is_err());
    }

    #[test]
    fn llc_anynet_converter_intent_is_explicit_and_disabled() {
        let gateway = r#"
[[llc]]
id = "lan"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:53:4e:00:00:02"
[[anynet]]
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
}
