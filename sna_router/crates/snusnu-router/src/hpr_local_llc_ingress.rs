//! Native LLC ingress for sessions headed toward an EE peer.
//!
//! `NativePeerPort` owns XID3, LLC2 and CP management. This wrapper retains
//! one native user event until the carrier-neutral session adapter accepts it.

use std::io;

use crate::{
    auto_llc::LlcIngressOffer,
    hpr_fid2_session::NativeFid2Session,
    hpr_session_source::{SessionSource, SourceUpdate},
    llc_target_identity::LlcTargetIdentity,
    native_peer_port::{NativeLlcEvent, NativePeerPort},
    routing::RoutePort,
};
use router_core::session::{QualifiedName, SessionEvent, SessionIdentity};

pub(crate) struct LocalLlcNative {
    port: NativePeerPort,
    pending: Option<NativeLlcEvent>,
}

pub(crate) struct LocalLlcIngress {
    native: LocalLlcNative,
    target_cp: QualifiedName,
    identity: Option<SessionIdentity>,
    codec: Option<NativeFid2Session>,
    candidate: Option<NativeFid2Session>,
    pending: Option<SourceUpdate>,
    pending_grant: Option<(NativeFid2Session, Vec<u8>)>,
    closed: bool,
}

impl LocalLlcIngress {
    pub(crate) fn from_offer(
        offer: LlcIngressOffer,
        target_cp: QualifiedName,
        attachment_id: &str,
    ) -> io::Result<Self> {
        let native = LocalLlcNative::from_offer(offer, &target_cp, attachment_id)?;
        Ok(Self {
            native,
            target_cp,
            identity: None,
            codec: None,
            candidate: None,
            pending: None,
            pending_grant: None,
            closed: false,
        })
    }

    /// The first BIND remains leased at `poll` until ReverseRuntime admits
    /// this identity and calls `complete_received` through SessionSource.
    pub(crate) fn identity(&self) -> Option<&SessionIdentity> {
        self.identity.as_ref()
    }

    pub(crate) fn target_cp(&self) -> &QualifiedName {
        &self.target_cp
    }

    pub(crate) fn can_lease_reverse(&self) -> bool {
        !self.closed
            && self.pending.is_none()
            && self.codec.is_none()
            && self.native.pending.is_none()
            && self.native.port.reverse_link_available()
    }

    /// Finish a correlated user UNBIND and keep the dialout LLC2 carrier for
    /// later reverse sessions. The native transmit queue must be empty first.
    pub(crate) fn return_idle_after_user(&mut self) -> io::Result<bool> {
        if self.closed || self.pending.is_some() || self.pending_grant.is_some() {
            return Ok(false);
        }
        if let Some(codec) = self.codec.as_ref() {
            if !codec.is_closed() || !self.native.port.retire_converter_user()? {
                return Ok(false);
            }
            self.codec = None;
            self.identity = None;
            self.candidate = None;
            return Ok(self.can_lease_reverse());
        }
        self.native.port.tick()?;
        self.native.port.poll(true)?;
        Ok(self.can_lease_reverse())
    }

    pub(crate) fn into_verified_port(self) -> io::Result<NativePeerPort> {
        if !self.can_lease_reverse() {
            return Err(invalid(
                "native LLC adjacency still has an active user session",
            ));
        }
        Ok(self.native.port)
    }

    pub(crate) fn from_verified_port(port: NativePeerPort, target_cp: QualifiedName) -> Self {
        Self {
            native: LocalLlcNative {
                port,
                pending: None,
            },
            target_cp,
            identity: None,
            codec: None,
            candidate: None,
            pending: None,
            pending_grant: None,
            closed: false,
        }
    }

    /// Release a failed user BIND while retaining the carrier-owned LLC2
    /// association and its CP/LU discovery proof. The caller retries when
    /// the native transmit queue has no room yet.
    pub(crate) fn reject_user_bind(&mut self) -> io::Result<bool> {
        if !self.native.reject_user_bind()? {
            return Ok(false);
        }
        self.native.discard_pending();
        self.identity = None;
        self.codec = None;
        self.candidate = None;
        self.pending = None;
        self.pending_grant = None;
        Ok(true)
    }

    /// Advance SNASVCMG teardown while a user BIND remains leased for a
    /// negative response. `poll` would replay that BIND and stall control.
    pub(crate) fn poll_carrier_control(&mut self) -> io::Result<()> {
        self.native.port.tick()?;
        self.native.port.poll(true)?;
        if !self.native.port.link_established() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "native LLC adjacency closed while rejecting user BIND",
            ));
        }
        Ok(())
    }
}

impl SessionSource for LocalLlcIngress {
    fn poll(&mut self) -> io::Result<Option<SourceUpdate>> {
        if let Some(update) = &self.pending {
            return Ok(Some(update.clone()));
        }
        if let Some((candidate, piu)) = self.pending_grant.as_ref() {
            if !self.native.send_piu(piu)? {
                return Ok(None);
            }
            self.codec = Some(candidate.clone());
            self.pending_grant = None;
        }
        for _ in 0..8 {
            let raw = match self.native.poll_native()? {
                Some(NativeLlcEvent::UserBind(piu)) => RawNative::Bind(piu.clone()),
                Some(NativeLlcEvent::FirstAttach(piu))
                | Some(NativeLlcEvent::UserInformation(piu)) => RawNative::Information(piu.clone()),
                Some(NativeLlcEvent::BindResponseAck | NativeLlcEvent::EgressAck(_)) => {
                    RawNative::Internal
                }
                Some(NativeLlcEvent::Closed) => RawNative::Closed,
                None => return Ok(None),
            };
            match raw {
                RawNative::Bind(piu) => {
                    if self.codec.is_some() {
                        return Err(invalid("duplicate native user BIND"));
                    }
                    let peer_cp = self.native.verified_peer_cp()?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "LLC CP not verified")
                    })?;
                    let (candidate, identity, event) = NativeFid2Session::from_user_bind(
                        &piu,
                        &peer_cp,
                        Some(self.target_cp.clone()),
                    )?;
                    self.identity = Some(identity);
                    self.candidate = Some(candidate);
                    self.pending = Some(SourceUpdate::Event(event));
                    return Ok(self.pending.clone());
                }
                RawNative::Information(piu) => {
                    let codec = self
                        .codec
                        .as_ref()
                        .ok_or_else(|| invalid("native user information before routed BIND"))?;
                    let (candidate, event) = codec.preview_native(&piu)?;
                    if let Some(event) = event {
                        self.candidate = Some(candidate);
                        self.pending = Some(SourceUpdate::Event(event));
                        return Ok(self.pending.clone());
                    }
                    self.codec = Some(candidate);
                    self.native.confirm_native()?;
                }
                RawNative::Internal => self.native.confirm_native()?,
                RawNative::Closed => {
                    self.closed = true;
                    self.pending = Some(SourceUpdate::Closed);
                    return Ok(self.pending.clone());
                }
            }
        }
        Ok(None)
    }

    fn complete_received(&mut self, _charge: bool) -> io::Result<()> {
        if !matches!(self.pending, Some(SourceUpdate::Event(_))) {
            return Err(invalid("no native event to complete"));
        }
        let candidate = self
            .candidate
            .take()
            .ok_or_else(|| invalid("native event candidate missing"))?;
        let grant = candidate.preview_native_grant()?;
        self.native.confirm_native()?;
        self.codec = Some(candidate);
        self.pending_grant = grant;
        self.pending = None;
        Ok(())
    }

    fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        let codec = self
            .codec
            .as_ref()
            .ok_or_else(|| invalid("native user session has no BIND"))?;
        let positive = matches!(event, SessionEvent::BindResult { accepted: true, .. });
        let fixed = if positive {
            Some(self.native.positive_bind_response()?)
        } else {
            None
        };
        let (candidate, piu) = codec.preview_event(event, fixed.as_deref())?;
        if let Some(piu) = piu {
            if !self.native.send_piu(&piu)? {
                return Ok(false);
            }
        } else if matches!(
            event,
            SessionEvent::BindResult {
                accepted: false,
                ..
            } | SessionEvent::Reset
        ) {
            self.native.close()?;
            self.closed = true;
        }
        self.codec = Some(candidate);
        Ok(true)
    }

    fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            self.native.close()?;
            self.closed = true;
        }
        Ok(())
    }
}

enum RawNative {
    Bind(Vec<u8>),
    Information(Vec<u8>),
    Internal,
    Closed,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

impl LocalLlcNative {
    /// The local XID presents the selected EE peer's CP to the LLC guest.
    /// The guest's own CP remains tentative until the private Type1 exchange
    /// has completed inside `NativePeerPort`.
    pub(crate) fn from_offer(
        offer: LlcIngressOffer,
        target_cp: &QualifiedName,
        attachment_id: &str,
    ) -> io::Result<Self> {
        let interface = offer.interface.clone();
        let xid = LlcTargetIdentity::new(Some(target_cp), attachment_id)?.xid()?;
        let (endpoint, first_events, observed_cp) = offer.into_endpoint()?;
        let port = NativePeerPort::open_dynamic_converter_from_endpoint(
            endpoint,
            first_events,
            &interface,
            xid,
            observed_cp,
        )?;
        Ok(Self {
            port,
            pending: None,
        })
    }

    pub(crate) fn verified_peer_cp(&self) -> io::Result<Option<QualifiedName>> {
        self.port
            .converter_peer_cp()
            .map(|name| {
                name.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid verified LLC peer CP")
                })
            })
            .transpose()
    }

    pub(crate) fn poll_native(&mut self) -> io::Result<Option<&NativeLlcEvent>> {
        if self.pending.is_none() {
            self.port.tick()?;
            self.port.poll(true)?;
            self.pending = self.port.take_converter_event();
        }
        Ok(self.pending.as_ref())
    }

    pub(crate) fn confirm_native(&mut self) -> io::Result<()> {
        if self.pending.take().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no native LLC event to confirm",
            ));
        }
        Ok(())
    }

    fn discard_pending(&mut self) {
        self.pending = None;
    }

    pub(crate) fn send_piu(&mut self, piu: &[u8]) -> io::Result<bool> {
        self.port.enqueue_converter_piu(piu)
    }

    pub(crate) fn positive_bind_response(&self) -> io::Result<Vec<u8>> {
        self.port.converter_positive_bind_response()
    }

    pub(crate) fn reject_user_bind(&mut self) -> io::Result<bool> {
        // X'08A00002': the selected remote LU session is unavailable.
        self.port.reject_converter_user_bind([0x08, 0xa0, 0, 2])
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.port.disconnect()
    }
}
