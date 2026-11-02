//! One-shot virtual native management exchange over a v2 WebSocket circuit.
//!
//! This intentionally does not open TCP62. It proves the Bob CP identity,
//! Alice LLC contact, and native SNASVCMG exchange before user admission.

use crate::{
    config::{self, RouterConfig},
    remote::{Config as RemoteConfig, WsRoutePort},
    routing::{RoutePort, RouterEvent},
    virtual_ws_port::VirtualWsPort,
    STOP,
};
use router_core::{
    native_management_initiator::NativeManagementInitiator, xid3::Role, xid3_local::LocalLlcProfile,
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
use transport_ws::wire;

const TIMEOUT: Duration = Duration::from_secs(180);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn node_id(value: &str) -> io::Result<[u8; 4]> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("gateway local_node_id must be eight hex digits"));
    }
    Ok(u32::from_str_radix(value, 16)
        .map_err(|_| invalid("invalid gateway local_node_id"))?
        .to_be_bytes())
}

fn one_gateway(
    config: &RouterConfig,
) -> io::Result<(RemoteConfig, wire::SnaName, LocalLlcProfile, String)> {
    if config.mptn_gateway.len() != 1
        || config.remote.len() != 1
        || !config.llc.is_empty()
        || !config.ee.is_empty()
        || !config.anynet.is_empty()
        || !config.hpr_lan.is_empty()
        || config.route.len() != 1
    {
        return Err(invalid(
            "virtual management lab needs exactly one gateway, concentrator and route",
        ));
    }
    let gateway = &config.mptn_gateway[0];
    let remote = &config.remote[0];
    let profile = LocalLlcProfile {
        cp_name: gateway.local_cp.clone(),
        station_name: gateway.local_station.clone(),
        node_id: node_id(&gateway.local_node_id)?,
        tg_number: gateway.tg_number,
        max_receive_btu: 1496,
        max_iframes_before_ack: 1,
        role: Role::Secondary,
    };
    let route = RemoteConfig {
        url: remote.url.clone(),
        bearer: remote.bearer_token()?,
        local_cp: config::parse_cp(&gateway.local_cp)?,
        target_cp: config::parse_cp(&gateway.peer_cp)?,
        target_lu: Some(config::parse_cp(&gateway.destination_lu)?),
    };
    Ok((
        route,
        config::parse_cp(&gateway.source_lu)?,
        profile,
        gateway.peer_cp.clone(),
    ))
}

pub(crate) fn run(path: &Path) -> io::Result<()> {
    let config = config::load(path)?;
    let (route, source_lu, profile, peer_cp) = one_gateway(&config)?;
    let local_cp = profile.cp_name.clone();
    let local_xid = profile
        .build()
        .map_err(|error| invalid(format!("local XID3 profile: {error}")))?;
    let source = wire::LuReachability {
        lu: Some(source_lu.clone()),
        hosting_cp: Some(route.local_cp.clone()),
        supported_types: vec![wire::LuType::LuType62 as i32],
    };
    let upstream = route.url.clone();
    let ws = WsRoutePort::connect_gateway_v2(route, vec![source], source_lu)?;
    let mut port = VirtualWsPort::new(ws, local_xid, &local_cp, &peer_cp)?;
    let mut random = [0u8; 14];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut token = [0u8; 7];
    token[0] = 0x23;
    token[1..].copy_from_slice(&random[8..]);
    let management = NativeManagementInitiator::new(
        &local_cp,
        &peer_cp,
        0x2f,
        1,
        2,
        random[..8].try_into().expect("eight bytes"),
        token,
        "",
        8,
    )
    .map_err(|error| invalid(format!("native management policy: {error}")))?;
    port.attach_management(management)?;
    tracing::info!(
        local_cp,
        peer_cp,
        upstream,
        "experimental virtual WS management lab started"
    );
    let deadline = Instant::now() + TIMEOUT;
    while !STOP.load(Ordering::Relaxed) && Instant::now() < deadline {
        if let Some(events) = port.poll(false)? {
            for event in events {
                match event {
                    RouterEvent::Ready => {
                        tracing::info!(local_cp, peer_cp, "virtual native LLC link ready")
                    }
                    RouterEvent::Closed | RouterEvent::TimedOut => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "virtual WS management link closed",
                        ));
                    }
                    RouterEvent::Unit(_) | RouterEvent::ManagedMac(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected virtual management route event",
                        ));
                    }
                }
            }
        }
        port.tick()?;
        port.flush()?;
        if port.management_complete() {
            tracing::info!(
                local_cp,
                peer_cp,
                "virtual WS management exchange completed"
            );
            return Ok(());
        }
        thread::sleep(Duration::from_micros(200));
    }
    if STOP.load(Ordering::Relaxed) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "virtual WS management exchange timed out",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_derives_qualified_source_lu62_and_fixed_secondary_profile() {
        let input = r#"
[[mptn_gateway]]
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
token = "test-token"
[[route]]
from = "bob"
to = "upstream"
converter = "mptn_lu62"
"#;
        let config: RouterConfig = toml::from_str(input).unwrap();
        config.validate().unwrap();
        let (route, source, profile, peer) = one_gateway(&config).unwrap();
        assert_eq!(source.netid, "QABOB");
        assert_eq!(route.target_lu.unwrap().netid, "QAALICE");
        assert_eq!(route.bearer, "test-token");
        assert_eq!(profile.role, Role::Secondary);
        assert_eq!(profile.node_id, [0xff, 0xf1, 0x23, 0x45]);
        assert_eq!(peer, "QAALICE.SNAA");
    }
}
