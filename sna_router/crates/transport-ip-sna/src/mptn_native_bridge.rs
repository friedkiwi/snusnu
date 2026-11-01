//! Pure native user BIND to TCP62 gate. It does not activate a runtime route.

use crate::{
    anynet::TcpRecord,
    mptn_compensations::CompensationSet,
    mptn_connect::Connect,
    mptn_session::{BindPolicy, GatewaySession, Phase as GatewayPhase},
};
use router_core::{
    fid2_session_control::ManagementBind,
    user_bind::UserBindOffer,
    user_pacing::{FirstAttachRoute, UserPacingSession},
};
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle,
    AwaitConnect,
    NativeBindPrepared,
    AwaitNativeBindAck,
    Active,
    AttachPrepared,
    NormalPrepared,
    PositiveResponsePrepared,
    NativeNormalPrepared,
    AwaitNativeNormalAck,
    IprPrepared,
    Closed,
}

pub struct Bridge {
    gateway: GatewaySession,
    management: ManagementBind,
    mode: String,
    tp: [u8; 4],
    window: u8,
    offer: Option<UserBindOffer>,
    pacing: Option<UserPacingSession>,
    attach: Option<TcpRecord>,
    normal: Option<(TcpRecord, bool)>,
    positive_response: Option<TcpRecord>,
    native_normal: Option<(Vec<u8>, usize)>,
    // The admitted first LU6.2 bracket is implied by BIND. A definite
    // response to its FM data uses SNF 0x8000, not the request's own SNF.
    outstanding_implied_bracket_dr: bool,
    first_attach_complete: bool,
    phase: Phase,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn wrong_phase() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "native TCP62 bridge is in wrong phase",
    )
}

impl Bridge {
    pub fn new(
        policy: BindPolicy,
        available: CompensationSet,
        management: ManagementBind,
        tp: [u8; 4],
        window: u8,
    ) -> io::Result<Self> {
        if policy.plu != management.plu()
            || policy.slu != management.slu()
            || !(1..=3).contains(&window)
        {
            return Err(invalid("native bridge LU pair or pacing policy is invalid"));
        }
        let mode = policy.mode.clone().unwrap_or_default();
        Ok(Self {
            gateway: GatewaySession::new(policy, available)?,
            management,
            mode,
            tp,
            window,
            offer: None,
            pacing: None,
            attach: None,
            normal: None,
            positive_response: None,
            native_normal: None,
            outstanding_implied_bracket_dr: false,
            first_attach_complete: false,
            phase: Phase::Idle,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn pending_bytes(&self) -> (usize, usize) {
        self.gateway.pending_bytes()
    }

    pub fn begin_native_bind(&mut self, piu: &[u8], template: Connect) -> io::Result<TcpRecord> {
        self.begin_native_bind_internal(piu, template, false)
    }

    pub fn begin_native_bind_after_management(
        &mut self,
        piu: &[u8],
        template: Connect,
    ) -> io::Result<TcpRecord> {
        self.begin_native_bind_internal(piu, template, true)
    }

    fn begin_native_bind_internal(
        &mut self,
        piu: &[u8],
        template: Connect,
        management_closed: bool,
    ) -> io::Result<TcpRecord> {
        if self.phase != Phase::Idle {
            return Err(wrong_phase());
        }
        let policy = router_core::user_bind::UserBindPolicy {
            plu: self.management.plu(),
            slu: self.management.slu(),
            mode: &self.mode,
        };
        let offer = if management_closed {
            UserBindOffer::from_request_after_management(piu, &self.management, policy)
        } else {
            UserBindOffer::from_request_with_policy(piu, &self.management, policy)
        }
        .map_err(|_| invalid("native user BIND does not match route policy"))?;
        let pacing = if management_closed {
            UserPacingSession::new_after_management(&offer, &self.management, self.window)
        } else {
            UserPacingSession::new(&offer, &self.management, self.window)
        }
        .map_err(|_| invalid("native user BIND cannot negotiate fixed pacing"))?;
        // GatewaySession checks the full required X'19' capability set here.
        let record = self.gateway.begin_native_bind(piu, template)?;
        self.offer = Some(offer);
        self.pacing = Some(pacing);
        self.phase = Phase::AwaitConnect;
        Ok(record)
    }

    /// Validate remote RSP(BIND); return a separate local fixed-pacing
    /// response. TCP62's negotiated pacing is not copied onto LLC.
    pub fn accept_connect_response(&mut self, record: &TcpRecord) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AwaitConnect {
            return Err(wrong_phase());
        }
        if let Err(error) = self.gateway.receive_connect_response(record) {
            if self.gateway.phase() == GatewayPhase::Closed {
                self.phase = Phase::Closed;
            }
            return Err(error);
        }
        self.phase = Phase::NativeBindPrepared;
        Ok(self
            .pacing
            .as_ref()
            .unwrap()
            .prepared_bind_response()
            .to_vec())
    }
    pub fn mark_native_bind_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::NativeBindPrepared {
            return Err(wrong_phase());
        }
        self.pacing
            .as_mut()
            .unwrap()
            .mark_bind_enqueued(piu)
            .map_err(|_| invalid("native BIND egress differs from prepared response"))?;
        self.phase = Phase::AwaitNativeBindAck;
        Ok(())
    }
    pub fn acknowledge_native_bind(&mut self, completed: usize) -> io::Result<()> {
        if self.phase != Phase::AwaitNativeBindAck {
            return Err(wrong_phase());
        }
        self.pacing
            .as_mut()
            .unwrap()
            .acknowledge_bind(completed)
            .map_err(|_| invalid("native BIND acknowledgement is invalid"))?;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Validate the first FMH-5 TP route and convert its opaque application
    /// bytes to a TCP62 normal record. No native receive credit is granted.
    pub fn first_attach(&mut self, piu: &[u8]) -> io::Result<(TcpRecord, FirstAttachRoute)> {
        if self.phase != Phase::Active {
            return Err(wrong_phase());
        }
        let (record, pi) = self.gateway.native_normal_observe_pacing(piu)?;
        if !pi {
            self.gateway.complete_tcp_delivery(record.bytes.len())?;
            return Err(invalid("first user Attach lacks pacing indication"));
        }
        let route = match self.pacing.as_mut().unwrap().observe_first_attach(
            self.offer.as_ref().unwrap(),
            &self.tp,
            piu,
        ) {
            Ok(route) => route,
            Err(_) => {
                // Prepared record was never queued; return reserved credit.
                self.gateway.complete_tcp_delivery(record.bytes.len())?;
                return Err(invalid("first user Attach does not match TP route"));
            }
        };
        self.attach = Some(record.clone());
        self.phase = Phase::AttachPrepared;
        Ok((record, route))
    }

    /// Call only after exact TCP queue acceptance. A full native IPR queue
    /// leaves this phase retryable without granting another receive window.
    pub fn mark_attach_enqueued(
        &mut self,
        record: &TcpRecord,
        native_slots: usize,
    ) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AttachPrepared || self.attach.as_ref() != Some(record) {
            return Err(wrong_phase());
        }
        let ipr = self
            .pacing
            .as_mut()
            .unwrap()
            .prepare_ipr(native_slots)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "native IPR slot unavailable"))?
            .to_vec();
        self.phase = Phase::IprPrepared;
        Ok(ipr)
    }
    pub fn mark_ipr_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::IprPrepared {
            return Err(wrong_phase());
        }
        self.pacing
            .as_mut()
            .unwrap()
            .mark_egress_enqueued(piu)
            .map_err(|_| invalid("native IPR differs from prepared egress"))?;
        if self.attach.is_some() {
            self.first_attach_complete = true;
        }
        self.attach = None;
        self.normal = None;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Convert one later, complete FM request after the first Attach has
    /// entered TCP and its native pacing grant has entered LLC egress. The
    /// application RU stays opaque; DFC, session control, and responses need
    /// separate handlers. A rejected PIU releases any reserved TCP credit.
    pub fn next_native_normal(&mut self, piu: &[u8]) -> io::Result<(TcpRecord, bool)> {
        if self.phase != Phase::Active || !self.first_attach_complete {
            return Err(wrong_phase());
        }
        if piu.len() < 10 || piu[6] & 0xe0 != 0 {
            return Err(invalid("later native PIU is not an FM request"));
        }
        let (record, pacing_requested) = self.gateway.native_normal_observe_pacing(piu)?;
        if self
            .pacing
            .as_mut()
            .unwrap()
            .observe_normal_request(piu)
            .is_err()
        {
            self.gateway.complete_tcp_delivery(record.bytes.len())?;
            return Err(invalid("later native PIU violates user-session pacing"));
        }
        self.normal = Some((record.clone(), pacing_requested));
        self.phase = Phase::NormalPrepared;
        Ok((record, pacing_requested))
    }

    /// Confirm exact TCP queue acceptance. A PI-bearing request needs a
    /// native IPR, prepared only when the next receive window has storage.
    /// Queue backpressure leaves this record retryable without double charge.
    pub fn mark_normal_enqueued(
        &mut self,
        record: &TcpRecord,
        native_slots: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        if self.phase != Phase::NormalPrepared
            || self.normal.as_ref().map(|(pending, _)| pending) != Some(record)
        {
            return Err(wrong_phase());
        }
        if self.normal.as_ref().unwrap().1 {
            let ipr = self
                .pacing
                .as_mut()
                .unwrap()
                .prepare_ipr(native_slots)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "native IPR slot unavailable")
                })?
                .to_vec();
            self.phase = Phase::IprPrepared;
            Ok(Some(ipr))
        } else {
            self.normal = None;
            self.phase = Phase::Active;
            Ok(None)
        }
    }
    pub fn complete_tcp_delivery(&mut self, bytes: usize) -> io::Result<()> {
        self.gateway.complete_tcp_delivery(bytes)
    }

    /// Forward the observed V4R4 positive FM response to TCP62. IBM SNA
    /// Formats specifies SNF 0x8000 for a response to an implied first LU6.2
    /// bracket, even though the FM request itself has a different SNF. This
    /// response is independent of the hop-local IPR and grants no pacing.
    pub fn next_native_positive_response(&mut self, piu: &[u8]) -> io::Result<TcpRecord> {
        if self.phase != Phase::Active || !self.first_attach_complete {
            return Err(wrong_phase());
        }
        if !self.outstanding_implied_bracket_dr
            || piu.len() != 9
            || piu[4..6] != [0x80, 0x00]
            || piu[6..9] != [0x83, 0xa0, 0x00]
        {
            return Err(invalid(
                "native positive response has no matching implied-bracket DR",
            ));
        }
        // GatewaySession validates the negotiated FID2 address and ODAI,
        // strips only the native TH address, and reserves bounded TCP credit.
        let record = self.gateway.native_normal(piu)?;
        self.positive_response = Some(record.clone());
        self.phase = Phase::PositiveResponsePrepared;
        Ok(record)
    }

    /// Commit only after the exact TCP62 response enters the socket queue.
    pub fn mark_native_positive_response_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.phase != Phase::PositiveResponsePrepared
            || self.positive_response.as_ref() != Some(record)
        {
            return Err(wrong_phase());
        }
        self.positive_response = None;
        self.outstanding_implied_bracket_dr = false;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Convert one TCP62 normal record (or a final segmented record) to the
    /// established native user session. The native send window supplies PI;
    /// TCP62 pacing bits and SNA session/DFC control remain unsupported.
    /// `None` retains a bounded partial TCP62 RU without consuming LLC credit.
    pub fn next_mptn_normal(&mut self, record: &TcpRecord) -> io::Result<Option<Vec<u8>>> {
        if self.phase != Phase::Active || !self.first_attach_complete {
            return Err(wrong_phase());
        }
        let Some(piu) = self.gateway.mptn_normal(record)? else {
            return Ok(None);
        };
        if piu.len() < 10 || piu[6] & 0xe0 != 0 {
            self.gateway.complete_native_delivery(piu.len())?;
            return Err(invalid("TCP62 normal data is not an FM request"));
        }
        // The first observed V4R4 reply asks for both DR1 and DR2. Admit
        // only one outstanding response in the implied first bracket, so a
        // later 0x8000 response has an unambiguous local correspondent.
        if piu[7] & 0xa0 != 0 && (piu[7] & 0xa0 != 0xa0 || self.outstanding_implied_bracket_dr) {
            self.gateway.complete_native_delivery(piu.len())?;
            return Err(invalid(
                "TCP62 definite response request is unsupported or outstanding",
            ));
        }
        let prepared = match self.pacing.as_mut().unwrap().prepare_normal_send(&piu) {
            Ok(prepared) => prepared.to_vec(),
            Err(_) => {
                self.gateway.complete_native_delivery(piu.len())?;
                return Err(invalid("TCP62 normal data violates native send pacing"));
            }
        };
        self.native_normal = Some((prepared.clone(), piu.len()));
        self.phase = Phase::NativeNormalPrepared;
        Ok(Some(prepared))
    }

    /// Commit the exact PIU after it enters the native LLC egress queue.
    /// Failed enqueue attempts leave both the prepared PIU and TCP credit.
    pub fn mark_native_normal_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::NativeNormalPrepared
            || self
                .native_normal
                .as_ref()
                .map(|(pending, _)| pending.as_slice())
                != Some(piu)
        {
            return Err(wrong_phase());
        }
        self.pacing
            .as_mut()
            .unwrap()
            .mark_egress_enqueued(piu)
            .map_err(|_| invalid("native normal egress differs from prepared PIU"))?;
        if piu[7] & 0xa0 == 0xa0 {
            self.outstanding_implied_bracket_dr = true;
        }
        self.phase = Phase::AwaitNativeNormalAck;
        Ok(())
    }

    /// One LLC2 completion retires the single native I-frame and releases
    /// exactly its reserved gateway byte count.
    pub fn acknowledge_native_normal(&mut self, completed: usize) -> io::Result<()> {
        if self.phase != Phase::AwaitNativeNormalAck || completed != 1 {
            return Err(wrong_phase());
        }
        let bytes = self.native_normal.as_ref().unwrap().1;
        self.gateway.complete_native_delivery(bytes)?;
        self.native_normal = None;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Consume a correlated native user pacing response locally. It grants
    /// the next native send window and must never cross the TCP62 boundary.
    pub fn observe_native_ipr(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::Active || !self.first_attach_complete {
            return Err(wrong_phase());
        }
        self.pacing
            .as_mut()
            .unwrap()
            .observe_ipr(piu)
            .map_err(|_| invalid("native user IPR violates session pacing"))
    }
}
