//! Privileged Linux integration check for two LLC associations on one LAN.
//!
//! Build as an ordinary user, then run the test executable with CAP_NET_ADMIN
//! and CAP_NET_RAW (`sudo ... --ignored --nocapture`). It creates only its own
//! veth devices and removes them even if an assertion fails.

#![cfg(target_os = "linux")]

use link_linux::packet::{PacketPort, MAX_FRAME_LEN};
use router_core::llc::parse_8023;
use std::{
    fs, io,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const GUEST_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const PROXY_A1: [u8; 6] = [0x02, 0x53, 0x4e, 0, 0, 0x11];
const PROXY_A2: [u8; 6] = [0x02, 0x53, 0x4e, 0, 0, 0x12];
const GUEST_B1: [u8; 6] = [0x02, 0, 0, 0, 0, 0x21];
const GUEST_B2: [u8; 6] = [0x02, 0, 0, 0, 0, 0x22];
const PROXY_B1: [u8; 6] = [0x02, 0x53, 0x4e, 0, 0, 0x31];
const PROXY_B2: [u8; 6] = [0x02, 0x53, 0x4e, 0, 0, 0x32];

struct Lab {
    router: Option<Child>,
    devices: Vec<String>,
    config: PathBuf,
    log: PathBuf,
}

impl Lab {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .subsec_nanos();
        let suffix = format!("{:06x}", (std::process::id() ^ nanos) & 0xff_ffff);
        let base = std::env::temp_dir().join(format!("snusnu-multi-llc-{suffix}"));
        Self {
            router: None,
            devices: Vec::new(),
            config: base.with_extension("toml"),
            log: base.with_extension("log"),
        }
    }

    fn pair(&mut self, router_side: &str, guest_side: &str) {
        let output = Command::new("ip")
            .args([
                "link",
                "add",
                router_side,
                "type",
                "veth",
                "peer",
                "name",
                guest_side,
            ])
            .output()
            .expect("ip command is required");
        assert!(
            output.status.success(),
            "creating veth pair requires CAP_NET_ADMIN: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Deleting the router side also deletes its peer. Register it before
        // bringing either side up so panic unwinding still cleans it up.
        self.devices.push(router_side.to_owned());
        for device in [router_side, guest_side] {
            let output = Command::new("ip")
                .args(["link", "set", "dev", device, "up"])
                .output()
                .expect("ip command is required");
            assert!(
                output.status.success(),
                "bringing {device} up failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        if let Some(mut router) = self.router.take() {
            let _ = router.kill();
            let _ = router.wait();
        }
        for device in &self.devices {
            let _ = Command::new("ip").args(["link", "del", device]).status();
        }
        let _ = fs::remove_file(&self.config);
        let _ = fs::remove_file(&self.log);
    }
}

fn mac(value: [u8; 6]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn test_frame(destination: [u8; 6], marker: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(60);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&GUEST_A);
    frame.extend_from_slice(&5u16.to_be_bytes());
    frame.extend_from_slice(&[4, 4, 0xe3, marker, 0x55]);
    frame.resize(60, 0);
    frame
}

fn collect_markers(
    port: &PacketPort,
    source: [u8; 6],
    destination: [u8; 6],
) -> io::Result<Vec<u8>> {
    let mut markers = Vec::new();
    let mut buffer = [0u8; MAX_FRAME_LEN];
    loop {
        match port.receive_frame(&mut buffer) {
            Ok(length) => {
                if let Ok(frame) = parse_8023(&buffer[..length]) {
                    if frame.source == source
                        && frame.destination == destination
                        && frame.dsap == 4
                        && frame.ssap == 4
                        && frame.information.len() == 2
                    {
                        markers.push(frame.information[0]);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(markers),
            Err(error) => return Err(error),
        }
    }
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and CAP_NET_RAW; run the built test binary with sudo --ignored"]
fn distinct_proxy_macs_on_one_interface_select_distinct_llc_routes() {
    let mut lab = Lab::new();
    let suffix = lab
        .config
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .rsplit('-')
        .next()
        .unwrap()
        .to_owned();
    let names = [
        format!("s{suffix}a0"),
        format!("s{suffix}a1"),
        format!("s{suffix}b0"),
        format!("s{suffix}b1"),
        format!("s{suffix}c0"),
        format!("s{suffix}c1"),
    ];
    lab.pair(&names[0], &names[1]);
    lab.pair(&names[2], &names[3]);
    lab.pair(&names[4], &names[5]);

    let config = format!(
        "[[llc]]\nid='a1'\ninterface='{shared}'\nguest_mac='{guest_a}'\nproxy_mac='{proxy_a1}'\n\
         [[llc]]\nid='a2'\ninterface='{shared}'\nguest_mac='{guest_a}'\nproxy_mac='{proxy_a2}'\n\
         [[llc]]\nid='b1'\ninterface='{out1}'\nguest_mac='{guest_b1}'\nproxy_mac='{proxy_b1}'\n\
         [[llc]]\nid='b2'\ninterface='{out2}'\nguest_mac='{guest_b2}'\nproxy_mac='{proxy_b2}'\n\
         [[route]]\nfrom='a1'\nto='b1'\n\
         [[route]]\nfrom='a2'\nto='b2'\n",
        shared = names[0],
        out1 = names[2],
        out2 = names[4],
        guest_a = mac(GUEST_A),
        proxy_a1 = mac(PROXY_A1),
        proxy_a2 = mac(PROXY_A2),
        guest_b1 = mac(GUEST_B1),
        proxy_b1 = mac(PROXY_B1),
        guest_b2 = mac(GUEST_B2),
        proxy_b2 = mac(PROXY_B2),
    );
    fs::write(&lab.config, config).expect("write config");
    let log = fs::File::create(&lab.log).expect("create router log");
    lab.router = Some(
        Command::new(env!("CARGO_BIN_EXE_snusnu-router"))
            .args(["--config", lab.config.to_str().expect("UTF-8 path")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start router"),
    );
    let injection = PacketPort::open(&names[1]).expect("open source veth");
    let capture_b1 = PacketPort::open(&names[3]).expect("capture first target");
    let capture_b2 = PacketPort::open(&names[5]).expect("capture second target");
    thread::sleep(Duration::from_millis(150));
    if let Some(status) = lab
        .router
        .as_mut()
        .unwrap()
        .try_wait()
        .expect("poll router")
    {
        panic!(
            "router exited before traffic: {status}; log: {}",
            fs::read_to_string(&lab.log).unwrap()
        );
    }

    injection
        .send_frame(&test_frame(PROXY_A1, 0xa1))
        .expect("send first TEST frame");
    injection
        .send_frame(&test_frame(PROXY_A2, 0xa2))
        .expect("send second TEST frame");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut first = Vec::new();
    let mut second = Vec::new();
    while Instant::now() < deadline {
        first.extend(collect_markers(&capture_b1, PROXY_B1, GUEST_B1).unwrap());
        second.extend(collect_markers(&capture_b2, PROXY_B2, GUEST_B2).unwrap());
        if first.len() >= 1 && second.len() >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    // Drain once more to catch unintended duplicates or cross-delivery.
    thread::sleep(Duration::from_millis(50));
    first.extend(collect_markers(&capture_b1, PROXY_B1, GUEST_B1).unwrap());
    second.extend(collect_markers(&capture_b2, PROXY_B2, GUEST_B2).unwrap());
    assert_eq!(first, [0xa1], "first route must receive only first marker");
    assert_eq!(
        second,
        [0xa2],
        "second route must receive only second marker"
    );
}
