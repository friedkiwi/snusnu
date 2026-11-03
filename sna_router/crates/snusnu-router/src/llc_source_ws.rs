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
const BIND_RESULT_TIMEOUT: Duration = Duration::from_secs(60);

fn bind_result_expired(sent: Option<Instant>, bound: bool, now: Instant) -> bool {
    !bound && sent.is_some_and(|sent| now.duration_since(sent) >= BIND_RESULT_TIMEOUT)
}

pub(crate) struct LlcSourceWs {
    attachment_id: String,
    session_id: u64,
    source: LocalLlcIngress,
    ws: SessionWsPort,
    pending_ws: Option<(SessionEvent, bool, Instant)>,
    opened_at: Instant,
    bind_sent_at: Option<Instant>,
    bound: bool,
    user_rejected: bool,
    source_closed: bool,
}

impl LlcSourceWs {
    pub(crate) fn new(
        source: LocalLlcIngress,
        ws: SessionWsPort,
        attachment_id: String,
        session_id: u64,
    ) -> Self {
        Self {
            attachment_id,
            session_id,
            source,
            ws,
            pending_ws: None,
            opened_at: Instant::now(),
            bind_sent_at: None,
            bound: false,
            user_rejected: false,
            source_closed: false,
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
        if bind_result_expired(self.bind_sent_at, self.bound, Instant::now()) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "LLC SessionV1 remote BIND result timed out",
            ));
        }
        if self.pending_ws.is_none() {
            match self.ws.poll()? {
                Some(SessionWsUpdate::Event(wire)) => {
                    let event = from_session_wire(wire)?;
                    if let SessionEvent::BindResult { accepted, .. } = &event {
                        tracing::info!(session = self.session_id,
                            attachment = %self.attachment_id, accepted,
                            elapsed_ms = self.bind_sent_at.map(|sent| sent.elapsed().as_millis()),
                            "LLC SessionV1 remote BIND result received");
                        self.bound = *accepted;
                        if !accepted {
                            self.bind_sent_at = None;
                        }
                    }
                    let charged = !matches!(event, SessionEvent::Credit { .. });
                    self.pending_ws = Some((event, charged, Instant::now()));
                }
                Some(SessionWsUpdate::Closed) => {
                    return Ok(false);
                }
                Some(SessionWsUpdate::Opened) | None => {}
            }
        } else if self.ws.poll_control()? {
            return Ok(false);
        }
        if let Some((event, charged, _)) = &self.pending_ws {
            if matches!(
                event,
                SessionEvent::BindResult {
                    accepted: false,
                    ..
                }
            ) {
                if !self.source.reject_user_bind()? {
                    return Ok(true);
                }
                if *charged {
                    self.ws.complete_received(1)?;
                }
                self.user_rejected = true;
                self.pending_ws = None;
                return Ok(false);
            }
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
                        if matches!(event, SessionEvent::BindRequest(_)) {
                            self.bind_sent_at = Some(Instant::now());
                            tracing::info!(session = self.session_id,
                                attachment = %self.attachment_id,
                                "LLC SessionV1 user BIND sent to concentrator");
                        }
                        self.source
                            .complete_received(!matches!(event, SessionEvent::Credit { .. }))?;
                    }
                }
                SourceUpdate::Closed => {
                    self.source_closed = true;
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

    /// Return the carrier link after an unsuccessful user circuit. Its CP/LU
    /// proof and LLC2 reservation remain owned by the surrounding runtime.
    pub(crate) fn into_idle_source(mut self) -> io::Result<LocalLlcIngress> {
        if self.bound || self.source_closed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LLC user circuit cannot return a closed or bound link",
            ));
        }
        if !self.user_rejected && !self.source.reject_user_bind()? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native negative BIND response queue is full",
            ));
        }
        self.ws.close()?;
        Ok(self.source)
    }

    pub(crate) fn can_return_idle(&self) -> bool {
        !self.bound && !self.source_closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unanswered_bind_is_bounded_after_open() {
        let now = Instant::now();
        assert!(!bind_result_expired(None, false, now));
        let sent = now - BIND_RESULT_TIMEOUT;
        assert!(bind_result_expired(Some(sent), false, now));
        assert!(!bind_result_expired(Some(sent), true, now));
    }
}
