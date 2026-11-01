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
pub(crate) struct LlcConfig {
    pub(crate) id: String,
    pub(crate) interface: String,
    pub(crate) guest_mac: String,
    pub(crate) proxy_mac: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteConfig {
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default = "default_bidirectional")]
    pub(crate) bidirectional: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteConfig {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) local_cp: String,
    pub(crate) target_cp: String,
    #[serde(default)]
    pub(crate) lus: Vec<String>,
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
        if self.llc.is_empty() && self.ee.is_empty() {
            return Err(invalid("at least one [[llc]] or [[ee]] peer is required"));
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
        }
        let mut ee_listeners = HashSet::new();
        for peer in &self.ee {
            validate_id(&peer.id)?;
            if !ids.insert(peer.id.as_str()) {
                return Err(invalid(format!("duplicate port ID {}", peer.id)));
            }
            kinds.insert(&peer.id, "ee");
            if peer.local_ip == peer.peer_ip
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
            parse_cp(&remote.target_cp)?;
            for lu in &remote.lus {
                let lu_name = parse_cp(lu)?;
                if !exported_lus.insert((lu_name.netid, lu_name.name)) {
                    return Err(invalid(format!("duplicate exported LU {lu}")));
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
            if !matches!(
                (source_kind, target_kind),
                ("llc", "llc") | ("llc", "remote") | ("remote", "llc") | ("ee", "ee")
            ) {
                return Err(invalid(format!(
                    "unsupported route {} ({source_kind}) -> {} ({target_kind})",
                    route.from, route.to
                )));
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
            if let Some(peer) = self.llc.iter().find(|peer| peer.id == local_id) {
                let proxy = parse_mac(&peer.proxy_mac)?;
                if proxy[..3] != [0x02, 0x53, 0x4e] {
                    return Err(invalid(format!(
                        "remote LLC peer {} must use assigned 02:53:4e virtual MAC",
                        peer.id
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
[[remote]]
id = "upstream"
url = "ws://127.0.0.1:8081/router/v1/ws"
local_cp = "SOLNET.SNAA"
target_cp = "SOLNET.SNAB"
lus = ["SOLNET.LUA"]
[[route]]
from = "a"
to = "upstream"
"#;
        parse(remote).validate().unwrap();
        assert!(parse(&remote.replace("02:53:4e", "02:00:4e"))
            .validate()
            .unwrap_err()
            .to_string()
            .contains("virtual MAC"));
        assert!(parse(&remote.replace("SOLNET.LUA", "bad.lu"))
            .validate()
            .is_err());
    }
}
