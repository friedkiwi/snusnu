//! LLC dialout to a local TCP62 peer over the common LU session event path.
//! The LLC adjacency remains owned by the runner and can be parked after
//! a correlated user UNBIND or a rejected BIND.

use std::{
    io,
    time::{Duration, Instant},
};

use router_core::session::SessionEvent;

use crate::{
    hpr_local_llc_ingress::LocalLlcIngress,
    hpr_local_mptn::HprToMptnSession,
    hpr_session_source::{SessionSource, SourceUpdate},
};

const REJECT_DRAIN: Duration = Duration::from_secs(15);

pub(crate) struct LlcLocalMptnSession {
    source: LocalLlcIngress,
    target: HprToMptnSession,
    gateway_id: String,
    carrier_id: u64,
    rejection_at: Option<Instant>,
}

impl LlcLocalMptnSession {
    pub(crate) fn new(
        source: LocalLlcIngress,
        target: HprToMptnSession,
        gateway_id: String,
        carrier_id: u64,
    ) -> Self {
        Self {
            source,
            target,
            gateway_id,
            carrier_id,
            rejection_at: None,
        }
    }

    pub(crate) fn gateway_id(&self) -> &str {
        &self.gateway_id
    }
    pub(crate) fn carrier_id(&self) -> u64 {
        self.carrier_id
    }

    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if self
            .rejection_at
            .is_some_and(|at| at.elapsed() > REJECT_DRAIN)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local LLC negative BIND did not release its carrier",
            ));
        }
        if self.source.return_idle_after_user()? {
            return Ok(false);
        }
        if self.rejection_at.is_none() {
            if let Some(update) = self.source.poll()? {
                match update {
                    SourceUpdate::Closed => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "local LLC dialout carrier closed",
                        ))
                    }
                    SourceUpdate::Event(event) => {
                        if self.target.send(&event)? {
                            self.source
                                .complete_received(!matches!(event, SessionEvent::Credit { .. }))?;
                        }
                    }
                }
            }
            if let Some(event) = self.target.poll()? {
                if matches!(
                    event,
                    SessionEvent::BindResult {
                        accepted: false,
                        ..
                    }
                ) {
                    if self.source.reject_user_bind()? {
                        self.target.confirm_polled()?;
                        self.rejection_at = Some(Instant::now());
                    }
                } else if self.source.send(&event)? {
                    self.target.confirm_polled()?;
                }
            }
        } else {
            self.source.poll_carrier_control()?;
        }
        Ok(true)
    }

    pub(crate) fn into_idle_source(mut self) -> io::Result<LocalLlcIngress> {
        if !self.source.return_idle_after_user()? {
            let _ = self.close();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local LLC carrier is not ready for another session",
            ));
        }
        self.target.close();
        Ok(self.source)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.target.close();
        self.source.close()
    }
}
