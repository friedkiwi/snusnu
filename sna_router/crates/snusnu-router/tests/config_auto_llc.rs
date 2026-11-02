//! Automatic LLC routing across two independent Ethernet attachments.
//!
//! Run the built test executable with CAP_NET_ADMIN and CAP_NET_RAW. The two
//! veth pairs stand in for the two guest TAP links and are removed on exit.

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
const GUEST_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
// Stable local target addresses for attachment IDs "a" and "b".
const PROXY_A: [u8; 6] = [0x06, 0x53, 0x4e, 0x05, 0x7f, 0xed];
const PROXY_B: [u8; 6] = [0x06, 0x53, 0x4e, 0x05, 0x7a, 0xd4];

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
        let base = std::env::temp_dir().join(format!("snusnu-auto-llc-{suffix}"));
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
        self.devices.push(router_side.into());
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

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
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

fn frame(source: [u8; 6], destination: [u8; 6], marker: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(60);
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&5u16.to_be_bytes());
    bytes.extend_from_slice(&[4, 4, 0xe3, marker, 0x55]);
    bytes.resize(60, 0);
    bytes
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

fn await_marker(
    port: &PacketPort,
    source: [u8; 6],
    destination: [u8; 6],
    marker: u8,
) -> io::Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if collect_markers(port, source, destination)?.contains(&marker) {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(false)
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and CAP_NET_RAW; run the built test binary with sudo --ignored"]
fn no_route_config_forwards_type1_both_ways_by_target_proxy_mac() {
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
    ];
    lab.pair(&names[0], &names[1]);
    lab.pair(&names[2], &names[3]);

    fs::write(
        &lab.config,
        format!(
            "[[llc]]\nid='a'\ninterface='{a}'\nguest_mac='02:00:00:00:00:01'\n\
             [[llc]]\nid='b'\ninterface='{b}'\nguest_mac='02:00:00:00:00:02'\n",
            a = names[0],
            b = names[2]
        ),
    )
    .expect("write config");
    let log = fs::File::create(&lab.log).expect("create router log");
    lab.router = Some(
        Command::new(env!("CARGO_BIN_EXE_snusnu-router"))
            .args(["--config", lab.config.to_str().expect("UTF-8 path")])
            .env("RUST_LOG", "snusnu_router=info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start router"),
    );
    let inject_a = PacketPort::open(&names[1]).expect("open first guest link");
    let inject_b = PacketPort::open(&names[3]).expect("open second guest link");
    thread::sleep(Duration::from_millis(150));
    assert!(
        lab.router.as_mut().unwrap().try_wait().unwrap().is_none(),
        "router exited: {}",
        lab.log()
    );

    inject_a.send_frame(&frame(GUEST_A, PROXY_B, 0xa1)).unwrap();
    assert!(
        await_marker(&inject_b, PROXY_A, GUEST_B, 0xa1).unwrap(),
        "A Type1 did not reach B through automatic route: {}",
        lab.log()
    );
    inject_b.send_frame(&frame(GUEST_B, PROXY_A, 0xb1)).unwrap();
    assert!(
        await_marker(&inject_a, PROXY_B, GUEST_A, 0xb1).unwrap(),
        "B Type1 did not return to A through automatic route: {}",
        lab.log()
    );
}
