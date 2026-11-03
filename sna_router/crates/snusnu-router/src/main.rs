use std::{
    env, io, process,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    thread,
    time::Duration,
};
use tracing_subscriber::{fmt::time::UtcTime, EnvFilter};

#[cfg(target_os = "linux")]
mod anynet_port;
#[cfg(target_os = "linux")]
mod auto_address;
#[cfg(target_os = "linux")]
mod auto_gateway_runtime;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // The EE runtime uses this once its live session loop is wired.
mod auto_hpr_identity;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Inbound EE admission is activated with outbound user RTP.
mod auto_hpr_inbound;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Prepared for HPR gateway integration; automatic config remains gated.
mod auto_hpr_ip;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Prepared session switch; HPR endpoint remains gated.
mod auto_hpr_runtime;
#[cfg(target_os = "linux")]
mod auto_llc;
#[cfg(target_os = "linux")]
mod auto_llc_ws;
#[cfg(target_os = "linux")]
mod auto_local_converter;
#[cfg(target_os = "linux")]
mod auto_local_dispatch;
#[cfg(target_os = "linux")]
mod auto_runtime;
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // The EE endpoint is gated until control RTP and APPN are available.
mod ee_ldlc_endpoint;
#[cfg(target_os = "linux")]
mod ee_peer_lus;
#[cfg(target_os = "linux")]
mod endpoint;
#[cfg(target_os = "linux")]
mod hpr_lan_port;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // The HPR session loop attaches this adapter once wired.
mod hpr_rtp_port;
#[cfg(target_os = "linux")]
mod ip_ports;
#[cfg(target_os = "linux")]
mod lab;
#[cfg(target_os = "linux")]
mod local_status;
#[cfg(target_os = "linux")]
mod local_web;
#[cfg(target_os = "linux")]
mod mptn_bidirectional_gateway;
#[cfg(target_os = "linux")]
mod mptn_gateway_port;
#[cfg(target_os = "linux")]
mod mptn_ingress_lab;
#[cfg(target_os = "linux")]
mod mptn_llc_reverse;
#[cfg(target_os = "linux")]
mod mptn_outbound_port;
#[cfg(target_os = "linux")]
mod mptn_ws_gateway_lab;
#[cfg(target_os = "linux")]
mod mptn_ws_reverse;
#[cfg(target_os = "linux")]
mod native_converter_lab;
#[cfg(target_os = "linux")]
mod native_llc_port;
#[cfg(target_os = "linux")]
mod native_peer_port;
#[cfg(target_os = "linux")]
mod native_probe;
#[cfg(target_os = "linux")]
mod native_type1;
#[cfg(target_os = "linux")]
mod remote;
#[cfg(target_os = "linux")]
mod routing;
#[cfg(target_os = "linux")]
mod runtime;
mod virtual_native_cp;
#[cfg(target_os = "linux")]
mod virtual_ws_management_lab;
mod virtual_ws_port;
#[cfg(target_os = "linux")]
mod ws_native_responder;

static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static LOCAL_STATUS: OnceLock<local_status::LocalStatus> = OnceLock::new();

#[cfg(target_os = "linux")]
fn status() -> Option<&'static local_status::LocalStatus> {
    LOCAL_STATUS.get()
}

extern "C" fn handle_signal(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}

fn main() {
    if let Err(err) = init_logging() {
        eprintln!("snusnu-router: logging: {err}");
        process::exit(2);
    }
    if let Err(err) = run() {
        tracing::error!(error = %err, "router stopped");
        process::exit(1);
    }
}

fn init_logging() -> io::Result<()> {
    let directives = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
    let filter = EnvFilter::try_new(directives).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid RUST_LOG: {error}"),
        )
    })?;
    let format = env::var("SNUSNU_LOG_FORMAT").unwrap_or_else(|_| "text".to_owned());
    match format.as_str() {
        "text" => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_timer(UtcTime::rfc_3339())
            .with_writer(io::stderr)
            .with_ansi(false)
            .try_init()
            .map_err(io::Error::other),
        "json" => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_timer(UtcTime::rfc_3339())
            .with_writer(io::stderr)
            .json()
            .try_init()
            .map_err(io::Error::other),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SNUSNU_LOG_FORMAT must be text or json",
        )),
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next();
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--config") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        let config = config::load(std::path::Path::new(&path))?;
        install_signals();
        let cache_path = std::path::Path::new(&path).with_extension("peers.toml");
        let status = local_status::LocalStatus::with_cache(&cache_path).unwrap_or_else(|error| {
            tracing::warn!(path = %cache_path.display(), error = %error, "local peer cache unavailable");
            local_status::LocalStatus::new()
        });
        if let Some(remote) = config.remote.first() {
            status.set_concentrator(Some(local_status::ConcentratorStatus {
                state: "connecting".into(),
                authority: remote::server_authority(&remote.url).into(),
                router_id: None,
                allowed_netid: None,
                connection_epoch: None,
                last_change_ms: local_status::now_ms(),
                last_error: None,
            }));
        }
        LOCAL_STATUS.set(status.clone()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "local status already initialized",
            )
        })?;
        if let Some(web) = &config.web {
            let _web_thread = local_web::start(web, status)?;
        }
        return runtime::run_config(&config);
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-probe") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        install_signals();
        return native_probe::run(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-management-probe") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        install_signals();
        return native_probe::run_management(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-user-bind-probe") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        install_signals();
        return native_probe::run_user_bind(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-user-pacing-probe") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        install_signals();
        return native_probe::run_user_pacing(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-converter-mock-lab") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        install_signals();
        return native_converter_lab::run(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-converter-v5-lab") {
        let path = args.next().ok_or_else(usage_error)?;
        let local_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        let remote_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        if args.next().as_deref() != Some("--acknowledge-experimental-x83") || args.next().is_some()
        {
            return Err(usage_error());
        }
        install_signals();
        return native_converter_lab::run_v5(std::path::Path::new(&path), local_ip, remote_ip);
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--native-converter-v5-flow-lab") {
        let path = args.next().ok_or_else(usage_error)?;
        let local_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        let remote_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        if args.next().as_deref() != Some("--acknowledge-experimental-x83") || args.next().is_some()
        {
            return Err(usage_error());
        }
        install_signals();
        return native_converter_lab::run_v5_flow(std::path::Path::new(&path), local_ip, remote_ip);
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--mptn-llc-reverse-lab") {
        let path = args.next().ok_or_else(usage_error)?;
        let local_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        let peer_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        if args.next().as_deref() != Some("--acknowledge-experimental-x83") || args.next().is_some()
        {
            return Err(usage_error());
        }
        install_signals();
        return mptn_llc_reverse::run_probe(std::path::Path::new(&path), local_ip, peer_ip);
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--mptn-ingress-management-lab") {
        let local_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        let peer_ip = args
            .next()
            .ok_or_else(usage_error)?
            .parse()
            .map_err(|_| usage_error())?;
        let peer_lu = args.next().ok_or_else(usage_error)?;
        let local_lu = args.next().ok_or_else(usage_error)?;
        if args.next().as_deref() != Some("--acknowledge-experimental-x83") || args.next().is_some()
        {
            return Err(usage_error());
        }
        install_signals();
        return mptn_ingress_lab::run(local_ip, peer_ip, &peer_lu, &local_lu);
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--virtual-ws-management-lab") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() {
            return Err(usage_error());
        }
        install_signals();
        return virtual_ws_management_lab::run(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--mptn-ws-gateway-lab") {
        let path = args.next().ok_or_else(usage_error)?;
        if args.next().as_deref() != Some("--acknowledge-experimental-x83") || args.next().is_some()
        {
            return Err(usage_error());
        }
        install_signals();
        return mptn_ws_gateway_lab::run(std::path::Path::new(&path));
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--lab-link") {
        let interface_a = args.next().ok_or_else(usage_error)?;
        let interface_b = args.next().ok_or_else(usage_error)?;
        let mac_a = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        let mac_b = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        if args.next().is_some() || interface_a == interface_b || mac_a == mac_b {
            return Err(usage_error());
        }
        install_signals();
        return lab::run(&interface_a, &interface_b, mac_a, mac_b);
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--local-link") {
        let interface_a = args.next().ok_or_else(usage_error)?;
        let guest_a = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        let proxy_a = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        let interface_b = args.next().ok_or_else(usage_error)?;
        let guest_b = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        let proxy_b = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        if args.next().is_some()
            || interface_a == interface_b
            || guest_a == proxy_a
            || guest_b == proxy_b
        {
            return Err(usage_error());
        }
        install_signals();
        return runtime::run(
            runtime::LlcPeer {
                interface: &interface_a,
                guest_mac: guest_a,
                proxy_mac: proxy_a,
            },
            runtime::LlcPeer {
                interface: &interface_b,
                guest_mac: guest_b,
                proxy_mac: proxy_b,
            },
        );
    }
    #[cfg(target_os = "linux")]
    if first.as_deref() == Some("--remote-link") {
        let interface = args.next().ok_or_else(usage_error)?;
        let guest_mac = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        let proxy_mac = parse_mac(&args.next().ok_or_else(usage_error)?)?;
        let local_cp = parse_cp_name(&args.next().ok_or_else(usage_error)?)?;
        let target_cp = parse_cp_name(&args.next().ok_or_else(usage_error)?)?;
        let url = args.next().ok_or_else(usage_error)?;
        if args.next().is_some() || guest_mac == proxy_mac {
            return Err(usage_error());
        }
        let bearer = env::var("SNUSNU_ROUTER_TOKEN").map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SNUSNU_ROUTER_TOKEN is required",
            )
        })?;
        install_signals();
        return runtime::run_remote(
            runtime::LlcPeer {
                interface: &interface,
                guest_mac,
                proxy_mac,
            },
            remote::Config {
                url,
                bearer,
                local_cp,
                target_cp,
                target_lu: None,
            },
        );
    }
    let site = match first.as_deref() {
        None => "local-dev".to_owned(),
        Some("--help") if args.next().is_none() => {
            println!(
                "usage: snusnu-router --config FILE | --mptn-llc-reverse-lab FILE LOCAL_IP PEER_IP --acknowledge-experimental-x83 | --mptn-ws-gateway-lab FILE --acknowledge-experimental-x83 | --virtual-ws-management-lab FILE | --native-probe FILE | --native-management-probe FILE | --native-user-bind-probe FILE | --native-user-pacing-probe FILE | --native-converter-mock-lab FILE | --native-converter-v5-lab FILE LOCAL_IPV4 REMOTE_IPV4 --acknowledge-experimental-x83 | --native-converter-v5-flow-lab FILE LOCAL_IPV4 REMOTE_IPV4 --acknowledge-experimental-x83 | --mptn-ingress-management-lab LOCAL_IPV4 PEER_IPV4 PEER_NETID.CP LOCAL_NETID.CP --acknowledge-experimental-x83 | [--site-id ID] | --lab-link IFACE_A IFACE_B MAC_A MAC_B | --local-link IFACE_A GUEST_A PROXY_A IFACE_B GUEST_B PROXY_B | --remote-link IFACE GUEST_MAC PROXY_MAC LOCAL_NETID.CP TARGET_NETID.CP WS_URL (token in SNUSNU_ROUTER_TOKEN)"
            );
            return Ok(());
        }
        Some("--site-id") => args
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing site ID"))?,
        _ => return Err(usage_error()),
    };
    if args.next().is_some()
        || site.is_empty()
        || site.len() > 64
        || !site.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "site ID must be 1-64 ASCII letters, digits or hyphens",
        ));
    }
    install_signals();
    tracing::info!(site_id = %site, "router foundation ready");
    while !STOP.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: snusnu-router --config FILE | --mptn-llc-reverse-lab FILE LOCAL_IP PEER_IP --acknowledge-experimental-x83 | --mptn-ws-gateway-lab FILE --acknowledge-experimental-x83 | --virtual-ws-management-lab FILE | --native-probe FILE | --native-management-probe FILE | --native-user-bind-probe FILE | --native-user-pacing-probe FILE | --native-converter-mock-lab FILE | --native-converter-v5-lab FILE LOCAL_IPV4 REMOTE_IPV4 --acknowledge-experimental-x83 | --native-converter-v5-flow-lab FILE LOCAL_IPV4 REMOTE_IPV4 --acknowledge-experimental-x83 | --mptn-ingress-management-lab LOCAL_IPV4 PEER_IPV4 PEER_NETID.CP LOCAL_NETID.CP --acknowledge-experimental-x83 | [--site-id ID] | --lab-link IFACE_A IFACE_B MAC_A MAC_B | --local-link IFACE_A GUEST_A PROXY_A IFACE_B GUEST_B PROXY_B | --remote-link IFACE GUEST_MAC PROXY_MAC LOCAL_NETID.CP TARGET_NETID.CP WS_URL (token in SNUSNU_ROUTER_TOKEN)",
    )
}

#[cfg(target_os = "linux")]
fn parse_mac(input: &str) -> io::Result<[u8; 6]> {
    let mut mac = [0; 6];
    let mut parts = input.split(':');
    for byte in &mut mac {
        let part = parts
            .next()
            .filter(|part| part.len() == 2)
            .ok_or_else(usage_error)?;
        *byte = u8::from_str_radix(part, 16).map_err(|_| usage_error())?;
    }
    if parts.next().is_some() || mac[0] & 1 != 0 {
        return Err(usage_error());
    }
    Ok(mac)
}

#[cfg(target_os = "linux")]
fn parse_cp_name(input: &str) -> io::Result<transport_ws::wire::SnaName> {
    let (netid, name) = input.split_once('.').ok_or_else(usage_error)?;
    if name.contains('.') {
        return Err(usage_error());
    }
    Ok(transport_ws::wire::SnaName {
        netid: netid.to_owned(),
        name: name.to_owned(),
    })
}

fn install_signals() {
    #[cfg(unix)]
    {
        use std::os::raw::c_int;
        unsafe extern "C" {
            fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
        }
        unsafe {
            signal(2, handle_signal);
            signal(15, handle_signal);
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_unicast_mac() {
        assert_eq!(
            super::parse_mac("02:00:35:27:23:01").unwrap(),
            [2, 0, 53, 39, 35, 1]
        );
        assert!(super::parse_mac("03:00:35:27:23:01").is_err());
        assert!(super::parse_mac("02:00:35:27:23").is_err());
    }
}
