//! Native LLC user session to one concentrator SessionV1 circuit.

use std::{
    io,
    time::{Duration, Instant},
};

use router_core::session::SessionEvent;

use crate::{
    auto_hpr_runtime::{from_session_wire, to_session_wire},
    hpr_local_llc_ingress::LocalLlcIngress,
    hpr_session_source::{SessionSource, SourceUpdate},
    remote::{SessionWsPort, SessionWsUpdate},
};

const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct LlcSourceWs {
    source: LocalLlcIngress,
    ws: SessionWsPort,
    pending_ws: Option<(SessionEvent, bool, Instant)>,
    opened_at: Instant,
}

impl LlcSourceWs {
    pub(crate) fn new(source: LocalLlcIngress, ws: SessionWsPort) -> Self {
        Self {
            source,
            ws,
            pending_ws: None,
            opened_at: Instant::now(),
        }
    }

    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if !self.ws.is_open() && self.opened_at.elapsed() >= OPEN_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "LLC SessionV1 concentrator open timed out",
            ));
        }
        if self
            .pending_ws
            .as_ref()
            .is_some_and(|(_, _, since)| since.elapsed() >= EVENT_TIMEOUT)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "LLC SessionV1 native egress stalled",
            ));
        }
        if self.pending_ws.is_none() {
            match self.ws.poll()? {
                Some(SessionWsUpdate::Event(wire)) => {
                    let event = from_session_wire(wire)?;
                    let charged = !matches!(event, SessionEvent::Credit { .. });
                    self.pending_ws = Some((event, charged, Instant::now()));
                }
                Some(SessionWsUpdate::Closed) => {
                    self.close()?;
                    return Ok(false);
                }
                Some(SessionWsUpdate::Opened) | None => {}
            }
        } else if self.ws.poll_control()? {
            self.close()?;
            return Ok(false);
        }
        if let Some((event, charged, _)) = &self.pending_ws {
            if self.source.send(event)? {
                if *charged {
                    self.ws.complete_received(1)?;
                }
                self.pending_ws = None;
            }
        }
        if let Some(update) = self.source.poll()? {
            match update {
                SourceUpdate::Event(event) => {
                    let Some(wire) = to_session_wire(&event) else {
                        self.close()?;
                        return Ok(false);
                    };
                    if self.ws.send(wire)? {
                        self.source
                            .complete_received(!matches!(event, SessionEvent::Credit { .. }))?;
                    }
                }
                SourceUpdate::Closed => {
                    self.close()?;
                    return Ok(false);
                }
            }
        }
        let _ = self.ws.take_completed_send_count();
        Ok(true)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.source.close()?;
        self.ws.close()
    }
}
