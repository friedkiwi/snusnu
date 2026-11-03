//! Local TCP62 ingress to an LLC peer on its verified dialout association.
//! The LLC carrier is returned to discovery after a completed user teardown.

use std::{
    io,
    time::{Duration, Instant},
};

use router_core::session::{QualifiedName, SessionEvent, SessionIdentity};

use crate::{
    hpr_local_llc::HprToLlcSession,
    hpr_mptn_session_source::MptnToHprSession,
    hpr_session_source::{SessionSource, SourceUpdate},
    native_peer_port::NativePeerPort,
    routing::RoutePort,
};

const CLOSE_DRAIN: Duration = Duration::from_secs(15);

pub(crate) struct MptnLocalLlcSession {
    source: MptnToHprSession,
    native: Option<NativePeerPort>,
    target: Option<HprToLlcSession<NativePeerPort>>,
    identity: SessionIdentity,
    gateway_id: String,
    carrier_id: u64,
    draining_since: Option<Instant>,
    target_closed_since: Option<Instant>,
    verified_target_lu: Option<QualifiedName>,
}

impl MptnLocalLlcSession {
    pub(crate) fn new(
        source: MptnToHprSession,
        native: NativePeerPort,
        identity: SessionIdentity,
        gateway_id: String,
        carrier_id: u64,
    ) -> Self {
        Self {
            source,
            native: Some(native),
            target: None,
            identity,
            gateway_id,
            carrier_id,
            draining_since: None,
            target_closed_since: None,
            verified_target_lu: None,
        }
    }

    pub(crate) fn gateway_id(&self) -> &str {
        &self.gateway_id
    }
    pub(crate) fn carrier_id(&self) -> u64 {
        self.carrier_id
    }

    /// The exact LU that accepted a native user BIND on this LLC adjacency.
    pub(crate) fn take_verified_target_lu(&mut self) -> Option<QualifiedName> {
        self.verified_target_lu.take()
    }

    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if let Some(since) = self.draining_since {
            if since.elapsed() > CLOSE_DRAIN {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local LLC user teardown did not complete",
                ));
            }
            return self.target.as_mut().map_or(Ok(false), |target| {
                target.drain_after_remote_close().map(|closed| !closed)
            });
        }
        if let Some(update) = self.source.poll()? {
            match update {
                SourceUpdate::Closed => {
                    self.source.complete_received(false)?;
                    self.source.close()?;
                    self.draining_since = Some(Instant::now());
                    return Ok(self.target.is_some());
                }
                SourceUpdate::Event(event) => {
                    if self.target.is_none() {
                        let SessionEvent::BindRequest(bind) = &event else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "local LLC circuit did not start with BIND",
                            ));
                        };
                        let native = self.native.take().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "verified LLC carrier is absent",
                            )
                        })?;
                        self.target = Some(HprToLlcSession::from_verified_port(
                            native,
                            self.identity.source_cp.as_ref().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "MPTN source CP is absent",
                                )
                            })?,
                            self.identity.target_cp.as_ref().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "LLC target CP is absent",
                                )
                            })?,
                            &self.identity.source_lu,
                            &self.identity.target_lu,
                            bind,
                        )?);
                    }
                    if self.target.as_mut().unwrap().send(&event)? {
                        self.source
                            .complete_received(!matches!(event, SessionEvent::Credit { .. }))?;
                    }
                }
            }
        }
        if let Some(target) = self.target.as_mut() {
            if let Some(event) = target.poll()? {
                if self.source.send(&event)? {
                    target.confirm_polled()?;
                    if matches!(event, SessionEvent::BindResult { accepted: true, .. }) {
                        self.verified_target_lu = Some(self.identity.target_lu.clone());
                    }
                    if matches!(
                        event,
                        SessionEvent::BindResult {
                            accepted: false,
                            ..
                        }
                    ) {
                        self.draining_since = Some(Instant::now());
                    }
                }
            }
            if target.verified_user_closed() {
                let since = self.target_closed_since.get_or_insert_with(Instant::now);
                if since.elapsed() > CLOSE_DRAIN {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "MPTN source did not finish after LLC user teardown",
                    ));
                }
            }
        }
        Ok(true)
    }

    pub(crate) fn into_live_adjacency(mut self) -> io::Result<NativePeerPort> {
        self.source.close()?;
        if let Some(native) = self.native.take() {
            return Ok(native);
        }
        let mut target = self.target.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "local LLC session lost its carrier",
            )
        })?;
        if !target.verified_user_closed() {
            target.close()?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local LLC user session has not completed teardown",
            ));
        }
        target.into_verified_port()
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.source.close()?;
        if let Some(target) = self.target.as_mut() {
            target.close()?;
        }
        if let Some(native) = self.native.as_mut() {
            native.disconnect()?;
        }
        Ok(())
    }
}
