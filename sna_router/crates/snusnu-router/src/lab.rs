//! Two isolated TAPs joined by the reusable LLC endpoints.

use super::{
    endpoint::{Endpoint, Event},
    STOP,
};
use router_core::llc2::State;
use std::{io, sync::atomic::Ordering, thread, time::Duration};

const CONNECT_BARRIER: Duration = Duration::from_millis(200);

pub(super) fn run(
    interface_a: &str,
    interface_b: &str,
    mac_a: [u8; 6],
    mac_b: [u8; 6],
) -> io::Result<()> {
    let mut endpoints = [
        Endpoint::open(interface_a, mac_a, mac_b)?,
        Endpoint::open(interface_b, mac_b, mac_a)?,
    ];
    let mut delivered = [0u64; 2];
    tracing::info!(interface_a, interface_b, sap = 4, "lab LLC link started");
    while !STOP.load(Ordering::Relaxed) {
        let mut received = false;
        for side in 0..2 {
            loop {
                let capacity = endpoints[1 - side].has_capacity();
                let Some(events) = endpoints[side].poll(capacity)? else {
                    break;
                };
                received = true;
                handle(&mut endpoints, &mut delivered, side, events)?;
            }
        }
        for side in 0..2 {
            if endpoints[1 - side].state() != State::Connected {
                endpoints[side].cancel_connect();
            }
            let events = endpoints[side].tick()?;
            handle(&mut endpoints, &mut delivered, side, events)?;
        }
        if !received {
            thread::sleep(Duration::from_micros(200));
        }
    }
    Ok(())
}

fn handle(
    endpoints: &mut [Endpoint; 2],
    delivered: &mut [u64; 2],
    side: usize,
    events: Vec<Event>,
) -> io::Result<()> {
    let (local, remote) = split(endpoints, side);
    for event in events {
        match event {
            Event::Type1(pdu) => {
                remote.send_type1(&pdu)?;
                tracing::debug!(
                    source_leg = side,
                    target_leg = 1 - side,
                    bytes = pdu.len(),
                    "LLC Type1 relayed"
                );
            }
            Event::Information(information) => {
                if !remote.queue_information(information)? {
                    // poll checks remote capacity before accepting this LLC I-frame.
                    return Err(io::Error::other("LLC relay capacity changed"));
                }
                delivered[side] += 1;
                if delivered[side] == 1 || delivered[side].is_multiple_of(10) {
                    tracing::debug!(
                        source_leg = side,
                        target_leg = 1 - side,
                        delivered = delivered[side],
                        "SNA information relayed"
                    );
                }
            }
            Event::Connected => {
                tracing::info!(leg = side, "lab LLC leg connected");
                if remote.state() == State::Disconnected {
                    // The answering SNA endpoint may still be exchanging XIDs
                    // and can initiate SABME itself during this interval.
                    remote.begin_connect_after(CONNECT_BARRIER);
                }
            }
            Event::Disconnected => {
                tracing::info!(leg = side, "lab LLC leg disconnected");
                local.disconnect()?;
                remote.disconnect()?;
            }
            Event::TimedOut => {
                tracing::warn!(leg = side, "lab LLC leg timed out");
                if local.state() == State::Disconnected {
                    remote.disconnect()?;
                }
            }
        }
    }
    local.flush()?;
    remote.flush()?;
    local.set_local_busy(!remote.has_capacity())?;
    remote.set_local_busy(!local.has_capacity())?;
    Ok(())
}

fn split(endpoints: &mut [Endpoint; 2], side: usize) -> (&mut Endpoint, &mut Endpoint) {
    if side == 0 {
        let (local, remote) = endpoints.split_at_mut(1);
        (&mut local[0], &mut remote[0])
    } else {
        let (remote, local) = endpoints.split_at_mut(1);
        (&mut local[0], &mut remote[0])
    }
}
