//! SessionV1 WebSocket bridge for one validated MPTN user association.
//!
//! The concentrator sees LU session events. The adapter retains TCP62/UDP
//! framing, expedited acknowledgements, and UNBIND correlation locally.

use std::io;

use router_core::session::SessionEvent;

use crate::{
    auto_hpr_runtime::{from_session_wire, to_session_wire},
    hpr_mptn_session_source::MptnToHprSession,
    hpr_session_source::{SessionSource, SourceUpdate},
    remote::{SessionWsPort, SessionWsUpdate},
};

pub(crate) struct MptnSessionWs {
    source: MptnToHprSession,
    ws: SessionWsPort,
    gateway_id: String,
    pending_ws: Option<(SessionEvent, bool)>,
}

impl MptnSessionWs {
    pub(crate) fn new(source: MptnToHprSession, ws: SessionWsPort, gateway_id: String) -> Self {
        Self {
            source,
            ws,
            gateway_id,
            pending_ws: None,
        }
    }

    pub(crate) fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// True while the circuit is alive. A false result means the owner must
    /// remove this bridge and release its gateway's exclusive UDP lease.
    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        if self.pending_ws.is_none() {
            match self.ws.poll()? {
                Some(SessionWsUpdate::Event(event)) => {
                    let event = from_session_wire(event)?;
                    let charge = !matches!(event, SessionEvent::Credit { .. });
                    self.pending_ws = Some((event, charge));
                }
                Some(SessionWsUpdate::Closed) => {
                    self.source.close()?;
                    return Ok(false);
                }
                Some(SessionWsUpdate::Opened) | None => {}
            }
        }
        if let Some((event, charge)) = &self.pending_ws {
            if self.source.send(event)? {
                if *charge {
                    self.ws.complete_received(1)?;
                }
                self.pending_ws = None;
            }
        }
        if let Some(update) = self.source.poll()? {
            match update {
                SourceUpdate::Event(event) => {
                    let Some(wire_event) = to_session_wire(&event) else {
                        self.ws.close()?;
                        self.source.close()?;
                        return Ok(false);
                    };
                    if self.ws.send(wire_event)? {
                        self.source
                            .complete_received(!matches!(event, SessionEvent::Credit { .. }))?;
                    }
                }
                SourceUpdate::Closed => {
                    self.source.complete_received(false)?;
                    self.ws.close()?;
                    self.source.close()?;
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
