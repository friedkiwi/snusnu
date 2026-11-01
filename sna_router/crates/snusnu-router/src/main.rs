use std::{
    env, io, process,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

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
    let site = match args.next().as_deref() {
        None => "local-dev".to_owned(),
        Some("--help") if args.next().is_none() => {
            println!("usage: snusnu-router [--site-id ID] (foundation only; no LLC2 or WSS)");
            return Ok(());
        }
        Some("--site-id") => args
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing site ID"))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: snusnu-router [--site-id ID]",
            ))
        }
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
    // The executable has no packet or network privileges in this milestone.
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
    println!("snusnu-router site {site} ready (foundation only); send SIGINT or SIGTERM to stop");
    while !STOP.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
