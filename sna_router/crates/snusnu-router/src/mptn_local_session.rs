//! A local TCP62 to TCP62 circuit on the shared LU session event pipeline.
//! Each attachment owns its own TCP association and exclusive UDP/397 lease.

use std::{io, net::UdpSocket, time::Duration};

use router_core::session::{SessionEvent, SessionIdentity};

use crate::{
    hpr_local_mptn::HprToMptnSession,
    hpr_mptn_session_source::MptnToHprSession,
    hpr_session_source::{SessionSource, SourceUpdate},
    mptn_outbound_port::OutboundEndpoint,
};

pub(crate) struct MptnLocalSession {
    source: MptnToHprSession,
    target: Option<HprToMptnSession>,
    target_udp: Option<UdpSocket>,
    target_endpoint: OutboundEndpoint,
    identity: SessionIdentity,
    source_gateway: String,
    target_gateway: String,
}

impl MptnLocalSession {
    pub(crate) fn new(
        source: MptnToHprSession,
        target_udp: UdpSocket,
        target_endpoint: OutboundEndpoint,
        identity: SessionIdentity,
        source_gateway: String,
        target_gateway: String,
    ) -> Self {
        Self {
            source,
            target: None,
            target_udp: Some(target_udp),
            target_endpoint,
            identity,
            source_gateway,
            target_gateway,
        }
    }

    pub(crate) fn gateways(&self) -> (&str, &str) {
        (&self.source_gateway, &self.target_gateway)
    }

    /// An event stays leased to its carrier until the other carrier accepts it.
    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if let Some(update) = self.source.poll()? {
            match update {
                SourceUpdate::Closed => {
                    self.source.complete_received(false)?;
                    self.close()?;
                    return Ok(false);
                }
                SourceUpdate::Event(event) => {
                    if self.target.is_none() {
                        let SessionEvent::BindRequest(bind) = &event else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "local MPTN circuit did not start with BIND",
                            ));
                        };
                        let udp = self.target_udp.take().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "local MPTN target UDP lease missing",
                            )
                        })?;
                        self.target = Some(HprToMptnSession::new(
                            self.target_endpoint,
                            udp,
                            &self.identity,
                            bind,
                            Duration::from_secs(600),
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
                }
            }
        }
        Ok(true)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.source.close()?;
        if let Some(target) = self.target.as_mut() {
            target.close();
        }
        self.target_udp.take();
        Ok(())
    }
}
