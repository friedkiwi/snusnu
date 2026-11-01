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
        if self.phase != Phase::Idle {
            return Err(wrong_phase());
        }
        let offer = UserBindOffer::from_request(piu, &self.management, &self.mode)
            .map_err(|_| invalid("native user BIND does not match route policy"))?;
        let pacing = UserPacingSession::new(&offer, &self.management, self.window)
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
        self.attach = None;
        self.phase = Phase::Active;
        Ok(())
    }
    pub fn complete_tcp_delivery(&mut self, bytes: usize) -> io::Result<()> {
        self.gateway.complete_tcp_delivery(bytes)
    }
}
