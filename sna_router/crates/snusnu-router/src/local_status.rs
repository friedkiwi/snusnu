//! Thread-safe, read-only view of router observations for the local UI.
//!
//! The status store records what local transports and the upstream have
//! reported. It does not decide whether a peer is enabled or publish routes.

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use transport_ws::wire;

const PEER_CACHE_VERSION: u32 = 1;
static CACHE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StatusSnapshot {
    pub(crate) started_at_ms: u64,
    pub(crate) local_peers: Vec<LocalPeerStatus>,
    pub(crate) local_proxy_macs: Vec<LocalProxyMacStatus>,
    pub(crate) upstream_routes: Vec<UpstreamRouteStatus>,
    pub(crate) managed_macs: Vec<ManagedMacStatus>,
    pub(crate) circuits: Vec<CircuitStatus>,
    pub(crate) concentrator: Option<ConcentratorStatus>,
}

#[derive(Serialize)]
pub(crate) struct StatusView {
    started_at_ms: u64,
    local_peers: Vec<LocalPeerStatus>,
    local_proxy_macs: Vec<LocalProxyMacStatus>,
    upstream_route_count: usize,
    managed_macs: Vec<ManagedMacStatus>,
    circuits: Vec<CircuitStatus>,
    concentrator: Option<ConcentratorStatus>,
}

#[derive(Serialize)]
pub(crate) struct RoutePage {
    items: Vec<UpstreamRouteStatus>,
    total: usize,
    page: usize,
    per_page: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LocalPeerStatus {
    /// Stable local attachment key, such as an LLC interface/MAC pair.
    pub(crate) key: String,
    pub(crate) transport: String,
    pub(crate) locator: String,
    pub(crate) cp: Option<String>,
    pub(crate) lus: Vec<String>,
    pub(crate) state: String,
    pub(crate) first_seen_ms: u64,
    pub(crate) last_seen_ms: u64,
    pub(crate) last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LocalProxyMacStatus {
    pub(crate) attachment_id: String,
    pub(crate) mac: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UpstreamRouteStatus {
    pub(crate) key: String,
    pub(crate) origin_router_id: String,
    pub(crate) resource: String,
    pub(crate) hosting_cp: Option<String>,
    pub(crate) generation: u64,
    pub(crate) last_seen_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ManagedMacStatus {
    pub(crate) cp: String,
    pub(crate) mac: String,
    pub(crate) last_seen_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CircuitStatus {
    pub(crate) id: String,
    pub(crate) ingress: String,
    pub(crate) egress: String,
    pub(crate) state: String,
    pub(crate) bytes_in: u64,
    pub(crate) bytes_out: u64,
    pub(crate) last_change_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ConcentratorStatus {
    pub(crate) state: String,
    /// Authority only; never store a URL that could contain credentials.
    pub(crate) authority: String,
    pub(crate) router_id: Option<String>,
    pub(crate) allowed_netid: Option<String>,
    pub(crate) connection_epoch: Option<String>,
    pub(crate) last_change_ms: u64,
    pub(crate) last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct LocalStatus {
    inner: Arc<RwLock<StatusSnapshot>>,
    cache_path: Option<Arc<PathBuf>>,
    persist_lock: Arc<Mutex<()>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PeerCache {
    schema_version: u32,
    local_peers: Vec<LocalPeerStatus>,
}

impl LocalStatus {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StatusSnapshot {
                started_at_ms: now_ms(),
                local_peers: Vec::new(),
                local_proxy_macs: Vec::new(),
                upstream_routes: Vec::new(),
                managed_macs: Vec::new(),
                circuits: Vec::new(),
                concentrator: None,
            })),
            cache_path: None,
            persist_lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn with_cache(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let mut status = Self::new();
        match fs::read_to_string(&path) {
            Ok(content) => {
                let cache: PeerCache = toml::from_str(&content).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("peer cache: {error}"))
                })?;
                if cache.schema_version != PEER_CACHE_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported peer cache schema version",
                    ));
                }
                let mut peers = cache.local_peers;
                for peer in &mut peers {
                    peer.state = "stale".into();
                    peer.last_error = None;
                }
                status.update(|snapshot| snapshot.local_peers = peers);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        status.cache_path = Some(Arc::new(path));
        Ok(status)
    }

    pub(crate) fn snapshot(&self) -> StatusSnapshot {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn view(&self) -> StatusView {
        let snapshot = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        StatusView {
            started_at_ms: snapshot.started_at_ms,
            local_peers: snapshot.local_peers.clone(),
            local_proxy_macs: snapshot.local_proxy_macs.clone(),
            upstream_route_count: snapshot.upstream_routes.len(),
            managed_macs: snapshot.managed_macs.clone(),
            circuits: snapshot.circuits.clone(),
            concentrator: snapshot.concentrator.clone(),
        }
    }

    pub(crate) fn route_page(&self, query: &str, page: usize, per_page: usize) -> RoutePage {
        let needle = query.to_ascii_lowercase();
        let snapshot = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let mut items = Vec::with_capacity(per_page);
        let mut total = 0;
        for route in &snapshot.upstream_routes {
            if route.resource.to_ascii_lowercase().contains(&needle)
                || route
                    .origin_router_id
                    .to_ascii_lowercase()
                    .contains(&needle)
                || route
                    .hosting_cp
                    .as_ref()
                    .is_some_and(|cp| cp.to_ascii_lowercase().contains(&needle))
            {
                if total >= offset && items.len() < per_page {
                    items.push(route.clone());
                }
                total += 1;
            }
        }
        RoutePage {
            items,
            total,
            page,
            per_page,
        }
    }

    fn update(&self, update: impl FnOnce(&mut StatusSnapshot)) {
        let mut snapshot = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        update(&mut snapshot);
    }

    pub(crate) fn set_concentrator(&self, status: Option<ConcentratorStatus>) {
        self.update(|snapshot| snapshot.concentrator = status);
    }

    pub(crate) fn replace_local_proxy_macs(&self, mut entries: Vec<LocalProxyMacStatus>) {
        entries.sort_by(|left, right| left.attachment_id.cmp(&right.attachment_id));
        self.update(|snapshot| snapshot.local_proxy_macs = entries);
    }

    pub(crate) fn upsert_peer(&self, mut peer: LocalPeerStatus) {
        self.update(|snapshot| {
            if let Some(existing) = snapshot
                .local_peers
                .iter_mut()
                .find(|existing| existing.key == peer.key)
            {
                peer.first_seen_ms = existing.first_seen_ms;
                *existing = peer;
            } else {
                snapshot.local_peers.push(peer);
                snapshot.local_peers.sort_by(|a, b| a.key.cmp(&b.key));
            }
        });
        self.persist_or_warn();
    }

    #[allow(dead_code)] // Reserved for a future local peer cache reset action.
    pub(crate) fn remove_peer(&self, key: &str) {
        self.update(|snapshot| snapshot.local_peers.retain(|peer| peer.key != key));
        self.persist_or_warn();
    }

    fn persist_or_warn(&self) {
        if let Some(path) = &self.cache_path {
            if let Err(error) = self.persist_peers(path) {
                tracing::warn!(path = %path.display(), error = %error, "local peer cache write failed");
            }
        }
    }

    fn persist_peers(&self, path: &Path) -> io::Result<()> {
        let _serial = self
            .persist_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cache = PeerCache {
            schema_version: PEER_CACHE_VERSION,
            local_peers: self.snapshot().local_peers,
        };
        let contents = toml::to_string(&cache).map_err(io::Error::other)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }
        let sequence = CACHE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = path.as_os_str().to_os_string();
        temp_name.push(format!(".tmp.{}.{}", std::process::id(), sequence));
        let temp = PathBuf::from(temp_name);
        let write = (|| -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temp, path)?;
            if let Some(parent) = parent {
                fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if write.is_err() {
            let _ = fs::remove_file(&temp);
        }
        write
    }

    /// One origin sends complete snapshots independently of other origins.
    pub(crate) fn replace_origin_routes(
        &self,
        origin_router_id: &str,
        mut routes: Vec<UpstreamRouteStatus>,
    ) {
        routes.retain(|route| route.origin_router_id == origin_router_id);
        self.update(|snapshot| {
            snapshot
                .upstream_routes
                .retain(|route| route.origin_router_id != origin_router_id);
            snapshot.upstream_routes.extend(routes);
            snapshot.upstream_routes.sort_by(|a, b| a.key.cmp(&b.key));
        });
    }

    pub(crate) fn withdraw_origin(&self, origin_router_id: &str) {
        self.replace_origin_routes(origin_router_id, Vec::new());
    }

    /// Record an already validated full origin snapshot from the concentrator.
    pub(crate) fn observe_origin_snapshot(&self, origin: &wire::OriginRouteSnapshot) {
        let origin_router_id = format_uuid(&origin.router_id);
        let seen = now_ms();
        let routes = origin
            .snapshot
            .iter()
            .flat_map(|snapshot| &snapshot.routes)
            .filter_map(|route| {
                let (resource, hosting_cp) = match route.resource.as_ref()? {
                    wire::route_export::Resource::ControlPoint(cp) => (format_name(cp), None),
                    wire::route_export::Resource::LogicalUnit(lu) => (
                        format_name(lu.lu.as_ref()?),
                        lu.hosting_cp.as_ref().map(format_name),
                    ),
                };
                Some(UpstreamRouteStatus {
                    key: format!("{origin_router_id}/{}", route.id),
                    origin_router_id: origin_router_id.clone(),
                    resource,
                    hosting_cp,
                    generation: route.generation,
                    last_seen_ms: seen,
                })
            })
            .collect();
        self.replace_origin_routes(&origin_router_id, routes);
    }

    pub(crate) fn withdraw_origin_bytes(&self, router_id: &[u8]) {
        self.withdraw_origin(&format_uuid(router_id));
    }

    /// The managed CP binding message is a complete revision, not a delta.
    pub(crate) fn replace_managed_macs(&self, mut bindings: Vec<ManagedMacStatus>) {
        bindings.sort_by(|a, b| a.cp.cmp(&b.cp));
        self.update(|snapshot| snapshot.managed_macs = bindings);
    }

    /// Record an already validated full managed CP binding revision.
    pub(crate) fn observe_managed_snapshot(&self, bindings: &wire::ManagedCpBindingSnapshot) {
        let seen = now_ms();
        self.replace_managed_macs(
            bindings
                .bindings
                .iter()
                .filter_map(|binding| {
                    Some(ManagedMacStatus {
                        cp: format_name(binding.control_point.as_ref()?),
                        mac: format_mac(&binding.virtual_mac),
                        last_seen_ms: seen,
                    })
                })
                .collect(),
        );
    }

    pub(crate) fn upsert_circuit(&self, circuit: CircuitStatus) {
        self.update(|snapshot| {
            if let Some(existing) = snapshot
                .circuits
                .iter_mut()
                .find(|existing| existing.id == circuit.id)
            {
                *existing = circuit;
            } else {
                snapshot.circuits.push(circuit);
                snapshot.circuits.sort_by(|a, b| a.id.cmp(&b.id));
            }
        });
    }

    pub(crate) fn remove_circuit(&self, id: &str) {
        self.update(|snapshot| snapshot.circuits.retain(|circuit| circuit.id != id));
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn format_name(name: &wire::SnaName) -> String {
    format!("{}.{}", name.netid, name.name)
}

fn format_uuid(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    if hex.len() != 32 {
        return hex;
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_snapshots_replace_one_origin_without_losing_other_origins() {
        let status = LocalStatus::new();
        let route = |origin: &str, resource: &str| UpstreamRouteStatus {
            key: format!("{origin}/{resource}"),
            origin_router_id: origin.into(),
            resource: resource.into(),
            hosting_cp: None,
            generation: 1,
            last_seen_ms: now_ms(),
        };
        status.replace_origin_routes("alice", vec![route("alice", "NETA.CPA")]);
        status.replace_origin_routes("bob", vec![route("bob", "NETB.CPB")]);
        status.replace_origin_routes("alice", vec![route("alice", "NETA.LUA")]);
        let snapshot = status.snapshot();
        assert_eq!(snapshot.upstream_routes.len(), 2);
        assert!(snapshot
            .upstream_routes
            .iter()
            .any(|route| route.resource == "NETA.LUA"));
        assert!(snapshot
            .upstream_routes
            .iter()
            .any(|route| route.resource == "NETB.CPB"));
        status.withdraw_origin("bob");
        assert_eq!(status.snapshot().upstream_routes.len(), 1);
    }

    #[test]
    fn route_page_filters_and_limits_without_putting_routes_in_view() {
        let status = LocalStatus::new();
        let routes = (0..55)
            .map(|index| UpstreamRouteStatus {
                key: format!("origin/{index:03}"),
                origin_router_id: "origin".into(),
                resource: format!("NETA.LU{index:03}"),
                hosting_cp: Some("NETA.CPA".into()),
                generation: 1,
                last_seen_ms: 1,
            })
            .collect();
        status.replace_origin_routes("origin", routes);
        let page = serde_json::to_value(status.route_page("lu0", 3, 20)).unwrap();
        assert_eq!(page["total"], 55);
        assert_eq!(page["items"].as_array().unwrap().len(), 15);
        assert_eq!(page["items"][0]["resource"], "NETA.LU040");
        assert_eq!(status.route_page("cpa", 1, 10).total, 55);
        assert_eq!(status.route_page("missing", 1, 10).total, 0);
        let view = serde_json::to_value(status.view()).unwrap();
        assert_eq!(view["upstream_route_count"], 55);
        assert!(view.get("upstream_routes").is_none());
    }

    #[test]
    fn peer_update_preserves_first_seen_and_clone_shares_state() {
        let status = LocalStatus::new();
        let other_reader = status.clone();
        let peer = LocalPeerStatus {
            key: "tap0/02:00:00:00:00:01".into(),
            transport: "llc".into(),
            locator: "tap0 02:00:00:00:00:01".into(),
            cp: Some("NETA.CPA".into()),
            lus: vec![],
            state: "observed".into(),
            first_seen_ms: 10,
            last_seen_ms: 10,
            last_error: None,
        };
        status.upsert_peer(peer.clone());
        status.upsert_peer(LocalPeerStatus {
            last_seen_ms: 20,
            ..peer
        });
        let snapshot = other_reader.snapshot();
        assert_eq!(snapshot.local_peers[0].first_seen_ms, 10);
        assert_eq!(snapshot.local_peers[0].last_seen_ms, 20);
    }

    #[test]
    fn cache_restores_only_local_peer_observations_as_stale() {
        let path = std::env::temp_dir().join(format!(
            "snusnu-peer-cache-{}-{}.toml",
            std::process::id(),
            CACHE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let status = LocalStatus::with_cache(&path).unwrap();
        status.upsert_peer(LocalPeerStatus {
            key: "tap0/02:00:00:00:00:01".into(),
            transport: "llc".into(),
            locator: "tap0 02:00:00:00:00:01".into(),
            cp: Some("NETA.CPA".into()),
            lus: vec!["NETA.LUA".into()],
            state: "active".into(),
            first_seen_ms: 10,
            last_seen_ms: 20,
            last_error: Some("old error".into()),
        });
        status.replace_origin_routes(
            "other",
            vec![UpstreamRouteStatus {
                key: "other/NETB.CPB".into(),
                origin_router_id: "other".into(),
                resource: "NETB.CPB".into(),
                hosting_cp: None,
                generation: 1,
                last_seen_ms: 30,
            }],
        );
        let restored = LocalStatus::with_cache(&path).unwrap().snapshot();
        assert_eq!(restored.local_peers.len(), 1);
        assert_eq!(restored.local_peers[0].cp.as_deref(), Some("NETA.CPA"));
        assert_eq!(restored.local_peers[0].state, "stale");
        assert_eq!(restored.local_peers[0].last_seen_ms, 20);
        assert!(restored.local_peers[0].last_error.is_none());
        assert!(restored.upstream_routes.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn wire_snapshots_show_lu_host_and_managed_mac() {
        let status = LocalStatus::new();
        let cp = wire::SnaName {
            netid: "NETA".into(),
            name: "CPA".into(),
        };
        let lu = wire::SnaName {
            netid: "NETA".into(),
            name: "LUA".into(),
        };
        let router_id = vec![0x11; 16];
        status.observe_origin_snapshot(&wire::OriginRouteSnapshot {
            router_id: router_id.clone(),
            snapshot: Some(wire::RouteSnapshot {
                epoch: vec![0x22; 16],
                revision: 1,
                routes: vec![wire::RouteExport {
                    id: 3,
                    generation: 7,
                    resource: Some(wire::route_export::Resource::LogicalUnit(
                        wire::LuReachability {
                            lu: Some(lu),
                            hosting_cp: Some(cp.clone()),
                            supported_types: vec![],
                        },
                    )),
                }],
            }),
        });
        status.observe_managed_snapshot(&wire::ManagedCpBindingSnapshot {
            schema_version: 1,
            recipient_epoch: vec![0x33; 16],
            revision: 1,
            bindings: vec![wire::ManagedCpBinding {
                address_id: vec![0x44; 16],
                control_point: Some(cp),
                virtual_mac: vec![0x02, 0x53, 0x4e, 1, 2, 3],
                candidates: vec![],
            }],
        });
        let snapshot = status.snapshot();
        assert_eq!(snapshot.upstream_routes[0].resource, "NETA.LUA");
        assert_eq!(
            snapshot.upstream_routes[0].hosting_cp.as_deref(),
            Some("NETA.CPA")
        );
        assert_eq!(snapshot.upstream_routes[0].generation, 7);
        assert_eq!(snapshot.managed_macs[0].mac, "02:53:4e:01:02:03");
        status.withdraw_origin_bytes(&router_id);
        assert!(status.snapshot().upstream_routes.is_empty());
    }
}
