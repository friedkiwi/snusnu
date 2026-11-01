use std::{
    env, io, process,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
mod lab;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}

fn main() {
    if let Err(err) = run() {
        eprintln!("snusnu-router: {err}");
        process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next();
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
    let site = match first.as_deref() {
        None => "local-dev".to_owned(),
        Some("--help") if args.next().is_none() => {
            println!(
                "usage: snusnu-router [--site-id ID] | --lab-link IFACE_A IFACE_B MAC_A MAC_B"
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
    println!("snusnu-router site {site} ready (foundation only); send SIGINT or SIGTERM to stop");
    while !STOP.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: snusnu-router [--site-id ID] | --lab-link IFACE_A IFACE_B MAC_A MAC_B",
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
