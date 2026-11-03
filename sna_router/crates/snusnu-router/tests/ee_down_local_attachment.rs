//! A carrier may be unavailable without suppressing other configured listeners.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct RouterProcess {
    child: Child,
    config: PathBuf,
    log: PathBuf,
}

impl RouterProcess {
    fn start(ee_ip: Ipv4Addr, ee_peer: Ipv4Addr, mptn_ip: Ipv4Addr, mptn_peer: Ipv4Addr) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stem =
            std::env::temp_dir().join(format!("snusnu-independent-{}-{nonce}", std::process::id()));
        let config = stem.with_extension("toml");
        let log = stem.with_extension("log");
        fs::write(
            &config,
            format!(
                "[[hpr_ip]]\nid='ee'\nlocal_ip='{ee_ip}'\npeer_ip='{ee_peer}'\nlocal_cp='SNUSNU.SVC'\n\
                 [[mptn]]\nprofile='gateway'\nid='mptn'\nlocal_ip='{mptn_ip}'\npeer_ip='{mptn_peer}'\n"
            ),
        )
        .unwrap();
        let log_file = fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_snusnu-router"))
            .args(["--config", config.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        Self { child, config, log }
    }
}

impl Drop for RouterProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
        let _ = fs::remove_file(&self.log);
    }
}

#[test]
#[ignore = "requires CAP_NET_BIND_SERVICE to open TCP/397"]
fn mptn_listener_stays_available_while_unrelated_ee_peer_is_down() {
    // Linux routes all of 127/8 locally, so this needs neither TAP nor root.
    let subnet = (std::process::id() % 250) as u8 + 1;
    let ee_ip = Ipv4Addr::new(127, 97, subnet, 1);
    let ee_peer = Ipv4Addr::new(127, 97, subnet, 2);
    let mptn_ip = Ipv4Addr::new(127, 97, subnet, 3);
    let mptn_peer = Ipv4Addr::new(127, 97, subnet, 4);
    let mut router = RouterProcess::start(ee_ip, ee_peer, mptn_ip, mptn_peer);
    let destination = SocketAddr::V4(SocketAddrV4::new(mptn_ip, 397));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = router.child.try_wait().unwrap() {
            panic!(
                "router exited with {status}: {}",
                fs::read_to_string(&router.log).unwrap_or_default()
            );
        }
        if TcpStream::connect_timeout(&destination, Duration::from_millis(100)).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "MPTN listener did not open while EE peer was absent: {}",
            fs::read_to_string(&router.log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
