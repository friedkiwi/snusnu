//! End-to-end coverage for configured EE adjacencies without raw sockets.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CONTROL_PORT: u16 = 12000;
const HIGH_PORT: u16 = 12002;

struct RouterProcess {
    child: Child,
    config: PathBuf,
    log: PathBuf,
}

impl RouterProcess {
    fn start(
        first: Ipv4Addr,
        first_peer: Ipv4Addr,
        second: Ipv4Addr,
        second_peer: Ipv4Addr,
    ) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stem = std::env::temp_dir().join(format!("snusnu-ee-{}-{nonce}", std::process::id()));
        let config = stem.with_extension("toml");
        let log = stem.with_extension("log");
        fs::write(
            &config,
            format!(
                "[[hpr_ip]]\nid='first'\nlocal_ip='{first}'\npeer_ip='{first_peer}'\n\
                 [[hpr_ip]]\nid='second'\nlocal_ip='{second}'\npeer_ip='{second_peer}'\n\
                 [[route]]\nfrom='first'\nto='second'\n"
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

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            panic!(
                "configured EE router exited with {status}: {}",
                fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
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

fn socket(ip: Ipv4Addr, port: u16) -> UdpSocket {
    UdpSocket::bind(SocketAddrV4::new(ip, port)).unwrap()
}

fn expect_datagram(socket: &UdpSocket, payload: &[u8], source: SocketAddrV4) {
    let mut buf = [0; 128];
    let (len, actual_source) = socket
        .recv_from(&mut buf)
        .expect("EE datagram was not routed");
    assert_eq!(&buf[..len], payload);
    assert_eq!(actual_source, source.into());
}

#[test]
fn configured_ee_route_forwards_both_directions_and_priority_and_filters_source() {
    // Each process gets distinct loopback listeners. This test needs no host
    // interface setup or privileges; Linux routes all of 127/8 locally.
    let subnet = (std::process::id() % 250) as u8 + 1;
    let first = Ipv4Addr::new(127, 83, subnet, 1);
    let first_peer = Ipv4Addr::new(127, 83, subnet, 2);
    let second = Ipv4Addr::new(127, 83, subnet, 3);
    let second_peer = Ipv4Addr::new(127, 83, subnet, 4);
    let stranger = Ipv4Addr::new(127, 83, subnet, 5);

    let first_control = socket(first_peer, CONTROL_PORT);
    let second_control = socket(second_peer, CONTROL_PORT);
    let second_high = socket(second_peer, HIGH_PORT);
    let first_sender = socket(first_peer, 0);
    let second_sender = socket(second_peer, 0);
    let stranger_sender = socket(stranger, 0);
    for receiver in [&first_control, &second_control, &second_high] {
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
    }

    let mut router = RouterProcess::start(first, first_peer, second, second_peer);
    let startup_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        router.assert_running();
        // A successful bind means startup has not finished yet.
        if let Err(error) = UdpSocket::bind(SocketAddrV4::new(second, CONTROL_PORT)) {
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
            break;
        }
        assert!(
            Instant::now() < startup_deadline,
            "EE router did not bind UDP listeners"
        );
        thread::sleep(Duration::from_millis(5));
    }

    stranger_sender
        .send_to(&[4, 4, 0xaf, 0x81], SocketAddrV4::new(first, CONTROL_PORT))
        .unwrap();
    let mut scratch = [0; 128];
    let error = second_control
        .recv_from(&mut scratch)
        .expect_err("unconfigured source was forwarded");
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "unexpected receive error: {error}"
    );

    let xid = [4, 4, 0xaf, 0x81];
    first_sender
        .send_to(&xid, SocketAddrV4::new(first, CONTROL_PORT))
        .unwrap();
    expect_datagram(
        &second_control,
        &xid,
        SocketAddrV4::new(second, CONTROL_PORT),
    );

    let response = [4, 5, 0xaf, 0x82];
    second_sender
        .send_to(&response, SocketAddrV4::new(second, CONTROL_PORT))
        .unwrap();
    expect_datagram(
        &first_control,
        &response,
        SocketAddrV4::new(first, CONTROL_PORT),
    );

    let nlp = [0x80, 0x80, 0x03, 0x12];
    first_sender
        .send_to(&nlp, SocketAddrV4::new(first, HIGH_PORT))
        .unwrap();
    expect_datagram(&second_high, &nlp, SocketAddrV4::new(second, HIGH_PORT));
    router.assert_running();
}
