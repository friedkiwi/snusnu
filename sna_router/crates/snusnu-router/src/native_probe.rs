//! One-shot, isolated XID3/LLC2 probe against one configured SNA guest.
//! It stops after receiving SNASVCMG BIND and never enables a routed circuit.

use crate::{
    config::parse_mac, native_peer_port::NativePeerPort, routing::RoutePort, runtime::LlcPeer, STOP,
};
use router_core::{xid3::Role, xid3_local::LocalLlcProfile};
use serde::Deserialize;
use std::{
    fs, io,
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeConfig {
    pub(crate) interface: String,
    pub(crate) guest_mac: String,
    pub(crate) proxy_mac: String,
    pub(crate) local_cp: String,
    #[serde(default)]
    pub(crate) remote_cp: Option<String>,
    #[serde(default)]
    pub(crate) user_plu: Option<String>,
    #[serde(default)]
    pub(crate) user_slu: Option<String>,
    #[serde(default)]
    pub(crate) user_tp_hex: Option<String>,
    pub(crate) local_station: String,
    pub(crate) local_node_id: String,
    pub(crate) tg_number: u8,
    pub(crate) role: ProbeRole,
    /// Opt in to starting XID toward an answering controller. The plain
    /// probe then stops after LLC2 contact, before management initiation.
    #[serde(default)]
    pub(crate) active_xid: bool,
    #[serde(default = "default_timeout")]
    pub(crate) timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeRole {
    Primary,
    Secondary,
}

impl From<ProbeRole> for Role {
    fn from(value: ProbeRole) -> Self {
        match value {
            ProbeRole::Primary => Role::Primary,
            ProbeRole::Secondary => Role::Secondary,
        }
    }
}

fn default_timeout() -> u64 {
    180
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.into())
}

fn parse_node_id(value: &str) -> io::Result<[u8; 4]> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("local_node_id must be eight hexadecimal digits"));
    }
    Ok(u32::from_str_radix(value, 16)
        .map_err(|_| invalid("invalid local_node_id"))?
        .to_be_bytes())
}

pub(crate) fn parse_tp(value: &str) -> io::Result<[u8; 4]> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("user_tp_hex must be eight hexadecimal digits"));
    }
    Ok(u32::from_str_radix(value, 16)
        .map_err(|_| invalid("invalid user_tp_hex"))?
        .to_be_bytes())
}

impl ProbeConfig {
    pub(crate) fn load(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
        if config.interface.is_empty() || !(1..=600).contains(&config.timeout_seconds) {
            return Err(invalid(
                "native probe needs an interface and timeout_seconds 1..600",
            ));
        }
        Ok(config)
    }

    pub(crate) fn profile(&self) -> io::Result<LocalLlcProfile> {
        Ok(LocalLlcProfile {
            cp_name: self.local_cp.clone(),
            station_name: self.local_station.clone(),
            node_id: parse_node_id(&self.local_node_id)?,
            tg_number: self.tg_number,
            // Endpoint accepts up to one 1496-byte information field in the
            // 802.3 MTU and acknowledges each I-frame. Advertise that actual
            // capacity, not a user-selected larger window.
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: self.role.into(),
        })
    }
}

pub(crate) fn run(path: &Path) -> io::Result<()> {
    run_with_mode(path, false, false, false)
}

pub(crate) fn run_management(path: &Path) -> io::Result<()> {
    run_with_mode(path, true, false, false)
}

pub(crate) fn run_user_bind(path: &Path) -> io::Result<()> {
    run_with_mode(path, true, true, false)
}

pub(crate) fn run_user_pacing(path: &Path) -> io::Result<()> {
    run_with_mode(path, true, true, true)
}

fn run_with_mode(
    path: &Path,
    management: bool,
    user_bind: bool,
    user_pacing: bool,
) -> io::Result<()> {
    let config = ProbeConfig::load(path)?;
    if config.active_xid && management {
        return Err(invalid(
            "active_xid is supported only by the link probe until management initiation is wired",
        ));
    }
    let profile = config.profile()?;
    let xid = profile
        .build()
        .map_err(|error| invalid(format!("invalid local XID3 profile: {error}")))?;
    let guest_mac = parse_mac(&config.guest_mac)?;
    let proxy_mac = parse_mac(&config.proxy_mac)?;
    tracing::info!(
        interface = %config.interface,
        guest_mac = %config.guest_mac,
        proxy_mac = %config.proxy_mac,
        local_cp = %profile.cp_name,
        local_station = %profile.station_name,
        local_node_id = %config.local_node_id,
        tg_number = profile.tg_number,
        role = ?profile.role,
        timeout_seconds = config.timeout_seconds,
        "native APPN one-shot probe starting"
    );
    let peer = LlcPeer {
        interface: &config.interface,
        guest_mac,
        proxy_mac,
    };
    let mut port = if management {
        let remote_cp = config
            .remote_cp
            .clone()
            .ok_or_else(|| invalid("remote_cp required for management probe"))?;
        if user_pacing {
            NativePeerPort::open_user_pacing_probe(
                peer,
                xid,
                remote_cp,
                config.local_cp.clone(),
                config
                    .user_plu
                    .clone()
                    .ok_or_else(|| invalid("user_plu required for pacing probe"))?,
                config
                    .user_slu
                    .clone()
                    .ok_or_else(|| invalid("user_slu required for pacing probe"))?,
                parse_tp(
                    config
                        .user_tp_hex
                        .as_deref()
                        .ok_or_else(|| invalid("user_tp_hex required for pacing probe"))?,
                )?,
            )?
        } else if user_bind {
            NativePeerPort::open_user_bind_probe(peer, xid, remote_cp, config.local_cp.clone())?
        } else {
            NativePeerPort::open_management(peer, xid, remote_cp, config.local_cp.clone())?
        }
    } else {
        NativePeerPort::open(peer, xid)?
    };
    if config.active_xid {
        port.begin_active_xid()?;
    }
    let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
    while !STOP.load(Ordering::Relaxed) {
        let had_frame = port.poll(true)?.is_some();
        if config.active_xid && port.link_established() {
            tracing::info!(peer_cp = ?config.remote_cp, "native active XID probe reached LLC2 contact; stopped before management BIND");
            return Ok(());
        }
        if management && !user_bind && port.management_complete() {
            tracing::info!("native management probe completed bounded UNBIND exchange; user routing remains disabled");
            return Ok(());
        }
        if !management && port.reached_management_bind() {
            tracing::info!("native probe reached SNASVCMG BIND after LLC2 contact; stopped before unsupported response");
            return Ok(());
        }
        port.tick()?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                if user_pacing {
                    "native user pacing probe timed out before next user PIU"
                } else if user_bind {
                    "native user BIND probe timed out before peer follow-up"
                } else if management {
                    "native management probe timed out before UNBIND completion"
                } else if config.active_xid {
                    "native active XID probe timed out before LLC2 contact"
                } else {
                    "native probe timed out before SNASVCMG BIND"
                },
            ));
        }
        if !had_frame {
            thread::sleep(Duration::from_micros(200));
        }
    }
    tracing::info!("native probe interrupted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_local_profile_with_actual_llc_receive_window() {
        let config: ProbeConfig = toml::from_str(
            r#"
interface = "sol5"
guest_mac = "02:00:35:27:23:01"
proxy_mac = "02:00:35:27:23:02"
local_cp = "SOLNET.SNAB"
local_station = "SNAB"
local_node_id = "fff12345"
tg_number = 1
role = "primary"
"#,
        )
        .unwrap();
        let profile = config.profile().unwrap();
        assert_eq!(profile.max_iframes_before_ack, 1);
        assert_eq!(profile.max_receive_btu, 1496);
        assert_eq!(profile.role, Role::Primary);
        assert!(!config.active_xid);
        assert_eq!(profile.build().unwrap().node_id(), [0xff, 0xf1, 0x23, 0x45]);
        assert!(parse_node_id("05633950").is_ok());
        assert!(parse_node_id("0563395").is_err());
    }

    #[test]
    fn answering_guest_link_probe_requires_explicit_active_xid() {
        let config: ProbeConfig = toml::from_str(
            r#"
interface = "sol5"
guest_mac = "02:00:35:27:23:02"
proxy_mac = "02:00:35:27:23:01"
local_cp = "QAALICE.SNAA"
remote_cp = "QABOB.SNAB"
local_station = "SNAA"
local_node_id = "fff12345"
tg_number = 1
role = "secondary"
active_xid = true
"#,
        )
        .unwrap();
        assert!(config.active_xid);
        assert_eq!(config.profile().unwrap().role, Role::Secondary);
    }
}
