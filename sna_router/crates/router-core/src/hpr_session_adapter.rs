//! One verified HPR FID5 LU session at the carrier-neutral boundary.
//!
//! RTP setup, reliable delivery, and complete-message assembly belong to
//! the caller. This adapter binds a generation and directional TCIDs to the
//! FID5 BIND/CV62 address exchange, then removes or restores FID5 framing.
//! It does not admit CP-CP or SNA management BINDs as user LU sessions.

use std::str::FromStr;

use crate::{
    fid2_bind::BindClass,
    fixed_pacing::{is_canonical_ipr, FixedPacing, PacingError, IPR_RH, PACING_INDICATOR},
    hpr_fid5::{encode_whole_biu, Fid5Error, Fid5WholeBiu},
    hpr_session_address::{
        AssociationError, Direction, Fid5AddressAssociation, RtpAssociationScope, RtpObservation,
    },
    session::{Flow, QualifiedName, SessionError, SessionEvent, SessionIdentity, SessionUnit},
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const MAX_BIND_RESPONSE: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HprSessionRole {
    /// The HPR peer sends BIND as PLU; this adapter responds as SLU.
    PeerPlu,
    /// The router sends BIND as PLU; the HPR peer responds as SLU.
    RouterPlu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HprSessionPhase {
    AwaitBind,
    AwaitBindResult,
    Open,
    AwaitUnbindResult,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HprIngress {
    /// Present only on a peer-originated BIND, before route selection.
    pub identity: Option<SessionIdentity>,
    pub event: SessionEvent,
    /// A normal response may carry both an information unit and a grant.
    pub extra_credit: Option<SessionEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HprEgress {
    pub observation: RtpObservation,
    /// One complete FID5 BIU; RTP segmentation and transmission remain with
    /// the validated connection that owns `observation`.
    pub message: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HprAdapterError {
    InvalidLocalAddress,
    InvalidPhase,
    WrongDirection,
    ManagementBind,
    UnqualifiedBind,
    InvalidBindResult,
    DuplicateAddressVector,
    MissingPacingProfile,
    UnsupportedPacing,
    InvalidCredit,
    Pacing(PacingError),
    InvalidMessage(Fid5Error),
    InvalidAssociation(AssociationError),
    InvalidSession(SessionError),
}

impl From<Fid5Error> for HprAdapterError {
    fn from(value: Fid5Error) -> Self {
        Self::InvalidMessage(value)
    }
}

impl From<AssociationError> for HprAdapterError {
    fn from(value: AssociationError) -> Self {
        Self::InvalidAssociation(value)
    }
}

impl From<SessionError> for HprAdapterError {
    fn from(value: SessionError) -> Self {
        Self::InvalidSession(value)
    }
}

#[derive(Clone)]
pub struct HprSessionAdapter {
    role: HprSessionRole,
    scope: RtpAssociationScope,
    association: Fid5AddressAssociation,
    local_assigned_sa: u64,
    local_cp: Option<QualifiedName>,
    peer_cp: Option<QualifiedName>,
    identity: Option<SessionIdentity>,
    phase: HprSessionPhase,
    pacing: Option<FixedPacing>,
    send_window: u8,
    receive_window: u8,
    pending_pacing_snf: Option<u16>,
    pending_unbind_snf: Option<[u8; 2]>,
}

impl HprSessionAdapter {
    /// `local_assigned_sa` has its assignor bit set and reserved bit clear.
    /// The caller allocates it uniquely within the validated RTP generation.
    pub fn new(
        role: HprSessionRole,
        scope: RtpAssociationScope,
        local_assigned_sa: u64,
        local_cp: Option<QualifiedName>,
        peer_cp: Option<QualifiedName>,
    ) -> Result<Self, HprAdapterError> {
        Self::with_association(
            role,
            scope,
            Fid5AddressAssociation::new(scope),
            local_assigned_sa,
            local_cp,
            peer_cp,
        )
    }

    /// Start a distinct LU session on an already established, validated RTP
    /// connection. BIND uses the subsequent PLU TCID; data and responses
    /// retain the same directional TCIDs and independent FID5 SA exchange.
    pub fn new_subsequent(
        role: HprSessionRole,
        scope: RtpAssociationScope,
        local_assigned_sa: u64,
        local_cp: Option<QualifiedName>,
        peer_cp: Option<QualifiedName>,
    ) -> Result<Self, HprAdapterError> {
        Self::with_association(
            role,
            scope,
            Fid5AddressAssociation::new_subsequent(scope),
            local_assigned_sa,
            local_cp,
            peer_cp,
        )
    }

    fn with_association(
        role: HprSessionRole,
        scope: RtpAssociationScope,
        association: Fid5AddressAssociation,
        local_assigned_sa: u64,
        local_cp: Option<QualifiedName>,
        peer_cp: Option<QualifiedName>,
    ) -> Result<Self, HprAdapterError> {
        if local_assigned_sa & (ASSIGNOR | RESERVED) != ASSIGNOR
            || local_assigned_sa & !(ASSIGNOR | RESERVED) == 0
        {
            return Err(HprAdapterError::InvalidLocalAddress);
        }
        Ok(Self {
            role,
            scope,
            association,
            local_assigned_sa,
            local_cp,
            peer_cp,
            identity: None,
            phase: HprSessionPhase::AwaitBind,
            pacing: None,
            send_window: 0,
            receive_window: 0,
            pending_pacing_snf: None,
            pending_unbind_snf: None,
        })
    }

    pub fn phase(&self) -> HprSessionPhase {
        self.phase
    }

    /// Parse on a candidate. The caller commits the returned adapter only
    /// after the fabric has accepted its event; dropping it leaves all local
    /// BIND, SA, and pacing state unchanged.
    pub fn preview_ingress(
        &self,
        observation: RtpObservation,
        message: &[u8],
    ) -> Result<(Self, HprIngress), HprAdapterError> {
        let mut candidate = self.clone();
        let ingress = candidate.ingest_verified(observation, message)?;
        Ok((candidate, ingress))
    }

    /// Encode on a candidate. The caller commits the returned adapter only
    /// after RTP accepted the message for transmission. A rejected candidate
    /// can be retried without spending a pacing window or closing a session.
    pub fn preview_egress(
        &self,
        event: SessionEvent,
    ) -> Result<(Self, Option<HprEgress>), HprAdapterError> {
        let mut candidate = self.clone();
        let egress = candidate.encode_event(event)?;
        Ok((candidate, egress))
    }

    pub fn identity(&self) -> Option<&SessionIdentity> {
        self.identity.as_ref()
    }

    /// A native egress may grant the next HPR receive window only after it
    /// has accepted the PI-bearing request into its own bounded queue.
    pub fn needs_receive_grant(&self) -> bool {
        self.phase == HprSessionPhase::Open && self.pending_pacing_snf.is_some()
    }

    /// Exact credit needed to acknowledge the pending PI-bearing HPR unit.
    /// The caller submits it only after the selected egress accepts that
    /// unit, keeping HPR and native pacing windows independent.
    pub fn receive_grant(&self) -> Option<SessionEvent> {
        self.needs_receive_grant().then_some(SessionEvent::Credit {
            normal: u32::from(self.receive_window),
            expedited: 0,
        })
    }

    /// Install the negotiated session pacing windows after a positive BIND
    /// and before any information is delivered. The caller derives these
    /// values from the accepted BIND profile; RTP ARB is separate.
    pub fn configure_fixed_pacing(
        &mut self,
        send_window: u8,
        receive_window: u8,
    ) -> Result<(), HprAdapterError> {
        if self.phase != HprSessionPhase::Open || self.pacing.is_some() {
            return Err(HprAdapterError::InvalidPhase);
        }
        self.pacing =
            Some(FixedPacing::new(send_window, receive_window).map_err(HprAdapterError::Pacing)?);
        self.send_window = send_window;
        self.receive_window = receive_window;
        Ok(())
    }

    /// Accept one complete, reassembled message from a validated RTP
    /// connection. A wrong generation, TCID, SA, or BIND sequence cannot
    /// advance this session.
    pub fn ingest_verified(
        &mut self,
        observation: RtpObservation,
        message: &[u8],
    ) -> Result<HprIngress, HprAdapterError> {
        let fid5 = Fid5WholeBiu::parse_complete(message)?;
        match (self.role, self.phase) {
            (HprSessionRole::PeerPlu, HprSessionPhase::AwaitBind) => {
                let identity =
                    user_bind_identity(fid5, self.peer_cp.clone(), self.local_cp.clone())?;
                self.association.observe_bind_request(observation, fid5)?;
                self.identity = Some(identity.clone());
                self.phase = HprSessionPhase::AwaitBindResult;
                Ok(HprIngress {
                    identity: Some(identity),
                    event: SessionEvent::BindRequest(fid5.session_unit()?),
                    extra_credit: None,
                })
            }
            (HprSessionRole::RouterPlu, HprSessionPhase::AwaitBindResult) => {
                if is_negative_bind_response(fid5) {
                    self.validate_negative_bind(observation, fid5)?;
                    let unit = fid5.session_unit()?;
                    self.disconnect();
                    return Ok(HprIngress {
                        identity: None,
                        event: SessionEvent::BindResult {
                            accepted: false,
                            unit,
                        },
                        extra_credit: None,
                    });
                }
                self.association.observe_bind_response(observation, fid5)?;
                self.phase = HprSessionPhase::Open;
                Ok(HprIngress {
                    identity: None,
                    event: SessionEvent::BindResult {
                        accepted: true,
                        // CV62 belongs to the HPR directional-address
                        // exchange, not to a carrier-neutral BIND result.
                        unit: remove_cv62(&fid5.session_unit()?)?,
                    },
                    extra_credit: None,
                })
            }
            (_, HprSessionPhase::Open | HprSessionPhase::AwaitUnbindResult) => {
                let direction = self.inbound_direction();
                self.association
                    .observe_data(direction, observation, fid5)?;
                let unit = fid5.session_unit()?;
                if is_unbind_request(&unit) {
                    if self.phase != HprSessionPhase::Open {
                        return Err(HprAdapterError::InvalidPhase);
                    }
                    self.pending_unbind_snf = Some(unit.snf().try_into().unwrap());
                    self.phase = HprSessionPhase::AwaitUnbindResult;
                    return Ok(HprIngress {
                        identity: None,
                        event: SessionEvent::Unbind(clear_pacing_indicator(&unit)?),
                        extra_credit: None,
                    });
                }
                if is_unbind_response(&unit) {
                    if self.phase != HprSessionPhase::AwaitUnbindResult
                        || self.pending_unbind_snf.as_ref().map(|snf| snf.as_slice())
                            != Some(unit.snf())
                    {
                        return Err(HprAdapterError::InvalidPhase);
                    }
                    self.disconnect();
                    return Ok(HprIngress {
                        identity: None,
                        event: SessionEvent::Unbind(clear_pacing_indicator(&unit)?),
                        extra_credit: None,
                    });
                }
                if self.phase != HprSessionPhase::Open {
                    return Err(HprAdapterError::InvalidPhase);
                }
                let pacing = self
                    .pacing
                    .as_mut()
                    .ok_or(HprAdapterError::MissingPacingProfile)?;
                if is_canonical_ipr(unit.rh(), unit.ru()) {
                    pacing
                        .receive_pacing_response()
                        .map_err(HprAdapterError::Pacing)?;
                    return Ok(HprIngress {
                        identity: None,
                        event: SessionEvent::Credit {
                            normal: u32::from(self.send_window),
                            expedited: 0,
                        },
                        extra_credit: None,
                    });
                }
                let mut extra_credit = None;
                if !fid5.expedited {
                    if unit.rh()[0] & 0x80 == 0 {
                        let pi = unit.rh()[1] & PACING_INDICATOR != 0;
                        pacing
                            .receive_request(pi)
                            .map_err(HprAdapterError::Pacing)?;
                        if pi {
                            self.pending_pacing_snf = Some(fid5.sequence_number);
                        }
                    } else if unit.rh()[1] & PACING_INDICATOR != 0 {
                        pacing
                            .receive_pacing_response()
                            .map_err(HprAdapterError::Pacing)?;
                        extra_credit = Some(SessionEvent::Credit {
                            normal: u32::from(self.send_window),
                            expedited: 0,
                        });
                    }
                }
                let event = SessionEvent::Information {
                    flow: if fid5.expedited {
                        Flow::Expedited
                    } else {
                        Flow::Normal
                    },
                    unit: clear_pacing_indicator(&unit)?,
                };
                Ok(HprIngress {
                    identity: None,
                    event,
                    extra_credit,
                })
            }
            _ => Err(HprAdapterError::InvalidPhase),
        }
    }

    /// Prepare one event from the session fabric for the HPR RTP sender.
    /// The caller must preserve ordering and hand `message` to the RTP
    /// connection identified by `observation`.
    pub fn encode_event(
        &mut self,
        event: SessionEvent,
    ) -> Result<Option<HprEgress>, HprAdapterError> {
        let (tcid, flow, address, unit) = match (self.role, self.phase, event) {
            (
                HprSessionRole::RouterPlu,
                HprSessionPhase::AwaitBind,
                SessionEvent::BindRequest(unit),
            ) => {
                let message =
                    encode_whole_biu(self.local_assigned_sa.to_be_bytes(), Flow::Expedited, &unit)?;
                let fid5 = Fid5WholeBiu::parse_complete(&message)?;
                let identity =
                    user_bind_identity(fid5, self.local_cp.clone(), self.peer_cp.clone())?;
                self.association.observe_bind_request(
                    RtpObservation {
                        generation: self.scope.generation,
                        tcid: self.association.bind_tcid(),
                    },
                    fid5,
                )?;
                self.identity = Some(identity);
                self.phase = HprSessionPhase::AwaitBindResult;
                return Ok(Some(HprEgress {
                    observation: RtpObservation {
                        generation: self.scope.generation,
                        tcid: self.association.bind_tcid(),
                    },
                    message,
                }));
            }
            (
                HprSessionRole::PeerPlu,
                HprSessionPhase::AwaitBindResult,
                SessionEvent::BindResult {
                    accepted: true,
                    unit,
                },
            ) => {
                let response = add_cv62(&unit, self.local_assigned_sa)?;
                let address = self
                    .association
                    .bind_response_address()
                    .ok_or(HprAdapterError::InvalidPhase)?;
                let message = encode_whole_biu(address, Flow::Expedited, &response)?;
                self.association.observe_bind_response(
                    RtpObservation {
                        generation: self.scope.generation,
                        tcid: self.scope.slu_tcid,
                    },
                    Fid5WholeBiu::parse_complete(&message)?,
                )?;
                self.phase = HprSessionPhase::Open;
                return Ok(Some(HprEgress {
                    observation: RtpObservation {
                        generation: self.scope.generation,
                        tcid: self.scope.slu_tcid,
                    },
                    message,
                }));
            }
            (
                HprSessionRole::PeerPlu,
                HprSessionPhase::AwaitBindResult,
                SessionEvent::BindResult {
                    accepted: false,
                    unit,
                },
            ) => {
                let address = self
                    .association
                    .bind_response_address()
                    .ok_or(HprAdapterError::InvalidPhase)?;
                let message = encode_whole_biu(address, Flow::Expedited, &unit)?;
                self.validate_negative_bind(
                    RtpObservation {
                        generation: self.scope.generation,
                        tcid: self.scope.slu_tcid,
                    },
                    Fid5WholeBiu::parse_complete(&message)?,
                )?;
                self.disconnect();
                return Ok(Some(HprEgress {
                    observation: RtpObservation {
                        generation: self.scope.generation,
                        tcid: self.scope.slu_tcid,
                    },
                    message,
                }));
            }
            (_, HprSessionPhase::Open, SessionEvent::Information { flow, unit }) => {
                let direction = self.outbound_direction();
                let address = self
                    .association
                    .data_address(direction)
                    .ok_or(HprAdapterError::InvalidPhase)?;
                let mut unit = clear_pacing_indicator(&unit)?;
                if flow == Flow::Normal && unit.rh()[0] & 0x80 == 0 {
                    let pacing = self
                        .pacing
                        .as_mut()
                        .ok_or(HprAdapterError::MissingPacingProfile)?;
                    let mut candidate = pacing.clone();
                    let pi = candidate.send_request().map_err(HprAdapterError::Pacing)?;
                    let mut bytes = unit.as_reduced().to_vec();
                    bytes[3] = (bytes[3] & !PACING_INDICATOR) | u8::from(pi);
                    unit = SessionUnit::from_reduced(&bytes)?;
                    *pacing = candidate;
                }
                (self.outbound_tcid(), flow, address, unit)
            }
            (_, HprSessionPhase::Open, SessionEvent::Credit { normal, expedited }) => {
                if expedited != 0 || normal != u32::from(self.receive_window) {
                    return Err(HprAdapterError::InvalidCredit);
                }
                let pacing = self
                    .pacing
                    .as_mut()
                    .ok_or(HprAdapterError::MissingPacingProfile)?;
                let snf = self
                    .pending_pacing_snf
                    .ok_or(HprAdapterError::InvalidCredit)?;
                pacing
                    .grant_receive_window()
                    .map_err(HprAdapterError::Pacing)?;
                self.pending_pacing_snf = None;
                let mut reduced = snf.to_be_bytes().to_vec();
                reduced.extend_from_slice(&IPR_RH);
                let unit = SessionUnit::from_reduced(&reduced)?;
                let address = self
                    .association
                    .data_address(self.outbound_direction())
                    .ok_or(HprAdapterError::InvalidPhase)?;
                (self.outbound_tcid(), Flow::Expedited, address, unit)
            }
            (
                _,
                HprSessionPhase::Open | HprSessionPhase::AwaitUnbindResult,
                SessionEvent::Unbind(unit),
            ) => {
                if self.phase == HprSessionPhase::Open {
                    if !is_unbind_request(&unit) {
                        return Err(HprAdapterError::InvalidPhase);
                    }
                } else if !is_unbind_response(&unit)
                    || self.pending_unbind_snf.as_ref().map(|snf| snf.as_slice())
                        != Some(unit.snf())
                {
                    return Err(HprAdapterError::InvalidPhase);
                }
                let direction = self.outbound_direction();
                let address = self
                    .association
                    .data_address(direction)
                    .ok_or(HprAdapterError::InvalidPhase)?;
                (
                    self.outbound_tcid(),
                    Flow::Expedited,
                    address,
                    clear_pacing_indicator(&unit)?,
                )
            }
            (_, _, SessionEvent::Reset) => {
                self.disconnect();
                return Ok(None);
            }
            _ => return Err(HprAdapterError::InvalidPhase),
        };
        let is_unbind_request = is_unbind_request(&unit);
        let is_unbind_response = is_unbind_response(&unit);
        let message = encode_whole_biu(address, flow, &unit)?;
        if is_unbind_request {
            self.pending_unbind_snf = Some(unit.snf().try_into().unwrap());
            self.phase = HprSessionPhase::AwaitUnbindResult;
        } else if is_unbind_response {
            self.disconnect();
        }
        Ok(Some(HprEgress {
            observation: RtpObservation {
                generation: self.scope.generation,
                tcid,
            },
            message,
        }))
    }

    pub fn disconnect(&mut self) {
        self.phase = HprSessionPhase::Closed;
        self.association.disconnect();
        self.pacing = None;
        self.pending_pacing_snf = None;
        self.pending_unbind_snf = None;
        self.identity = None;
    }

    fn inbound_direction(&self) -> Direction {
        match self.role {
            HprSessionRole::PeerPlu => Direction::PluToSlu,
            HprSessionRole::RouterPlu => Direction::SluToPlu,
        }
    }

    fn outbound_direction(&self) -> Direction {
        match self.role {
            HprSessionRole::PeerPlu => Direction::SluToPlu,
            HprSessionRole::RouterPlu => Direction::PluToSlu,
        }
    }

    fn outbound_tcid(&self) -> u64 {
        match self.role {
            HprSessionRole::PeerPlu => self.scope.slu_tcid,
            HprSessionRole::RouterPlu => self.scope.subsequent_plu_tcid,
        }
    }

    fn validate_negative_bind(
        &self,
        observation: RtpObservation,
        fid5: Fid5WholeBiu<'_>,
    ) -> Result<(), HprAdapterError> {
        if observation.generation != self.scope.generation {
            return Err(AssociationError::StaleGeneration.into());
        }
        if observation.tcid != self.scope.slu_tcid {
            return Err(AssociationError::WrongRtpConnection.into());
        }
        if fid5.session_address
            != self
                .association
                .bind_response_address()
                .ok_or(HprAdapterError::InvalidPhase)?
        {
            return Err(AssociationError::WrongResponseAddress.into());
        }
        if fid5.sequence_number
            != self
                .association
                .pending_bind_sequence()
                .ok_or(HprAdapterError::InvalidPhase)?
        {
            return Err(AssociationError::WrongBindSequence.into());
        }
        if !is_negative_bind_response(fid5) {
            return Err(HprAdapterError::InvalidBindResult);
        }
        Ok(())
    }
}

fn user_bind_identity(
    fid5: Fid5WholeBiu<'_>,
    source_cp: Option<QualifiedName>,
    target_cp: Option<QualifiedName>,
) -> Result<SessionIdentity, HprAdapterError> {
    let bind = fid5
        .classify_bind()
        .map_err(|_| HprAdapterError::UnqualifiedBind)?
        .ok_or(HprAdapterError::UnqualifiedBind)?;
    if let BindClass::Management { ref mode } = bind.class {
        // IBM i can send a service-directed LU 6.2 BIND with SNASVCMG as its
        // mode. The route and hosting CP are verified by the caller; allow
        // any advertised concentrator service LU under SNUSNU.SVC. A CP BIND
        // itself still stays out of the user-session fabric.
        if mode != "SNASVCMG"
            || !is_concentrator_service_lu(&bind.slu)
            || !target_cp
                .as_ref()
                .is_some_and(|cp| cp.netid == "SNUSNU" && cp.name == "SVC")
            || source_cp.is_none()
        {
            return Err(HprAdapterError::ManagementBind);
        }
    }
    let source_lu =
        QualifiedName::from_str(&bind.plu).map_err(|_| HprAdapterError::UnqualifiedBind)?;
    let target_lu =
        QualifiedName::from_str(&bind.slu).map_err(|_| HprAdapterError::UnqualifiedBind)?;
    Ok(SessionIdentity::new(source_lu, target_lu).with_control_points(source_cp, target_cp)?)
}

fn is_concentrator_service_lu(name: &str) -> bool {
    QualifiedName::from_str(name).is_ok_and(|lu| lu.netid == "SNUSNU" && lu.name != "SVC")
}

fn is_unbind_request(unit: &SessionUnit) -> bool {
    unit.rh()[0] & 0xe0 == 0x60 && unit.ru().first() == Some(&0x32)
}

fn is_unbind_response(unit: &SessionUnit) -> bool {
    unit.rh()[0] & 0xe0 == 0xe0 && unit.ru().first() == Some(&0x32)
}

fn is_negative_bind_response(fid5: Fid5WholeBiu<'_>) -> bool {
    fid5.expedited
        && fid5.rh[0] & 0xeb == 0xeb
        && fid5.rh[1] & 0x10 != 0
        && fid5.rh[2] == 0
        && fid5.ru.len() >= 4
}

/// The fixed one-stage windows negotiated by a positive user BIND response.
/// IBM SNA Formats defines BIND RU bytes 8/9 and 12/13 as the secondary send
/// and receive pacing fields. In the conservative APING profile, the response
/// selects fixed pacing, and each side's send window equals its partner's
/// receive window. Adaptive pacing and unsupported profiles fail closed.
pub fn negotiated_fixed_windows(
    role: HprSessionRole,
    request: &SessionUnit,
    response: &SessionUnit,
) -> Result<(u8, u8), HprAdapterError> {
    let offered = request.ru();
    let accepted = response.ru();
    if request.snf() != response.snf()
        || offered.len() < 27
        || accepted.len() < 31
        || offered[0] != 0x31
        || accepted[0] != 0x31
        || offered[2..4] != [0x13, 0x07]
        || accepted[2..4] != [0x13, 0x07]
        || offered[14..16] != [0x06, 0x02]
        || accepted[14..16] != [0x06, 0x02]
        || response.rh()[0] & 0xeb != 0xeb
        || response.rh()[1] & 0x10 != 0
    {
        return Err(HprAdapterError::UnsupportedPacing);
    }
    let secondary_send = accepted[8];
    let secondary_receive = accepted[9];
    if !(1..=63).contains(&secondary_send)
        || !(1..=63).contains(&secondary_receive)
        || accepted[12] != (0x80 | secondary_receive)
        || accepted[13] != secondary_send
    {
        return Err(HprAdapterError::UnsupportedPacing);
    }
    Ok(match role {
        HprSessionRole::PeerPlu => (secondary_send, secondary_receive),
        HprSessionRole::RouterPlu => (secondary_receive, secondary_send),
    })
}

fn clear_pacing_indicator(unit: &SessionUnit) -> Result<SessionUnit, HprAdapterError> {
    if unit.rh()[1] & PACING_INDICATOR == 0 {
        return Ok(unit.clone());
    }
    let mut reduced = unit.as_reduced().to_vec();
    reduced[3] &= !PACING_INDICATOR;
    SessionUnit::from_reduced(&reduced).map_err(Into::into)
}

fn add_cv62(unit: &SessionUnit, assigned_sa: u64) -> Result<SessionUnit, HprAdapterError> {
    let ru = unit.ru();
    if unit.rh()[0] & 0xeb != 0xeb
        || unit.rh()[1] & 0x10 != 0
        || unit.rh()[2] != 0
        || ru.len() < 31
        || ru.len() + 10 > MAX_BIND_RESPONSE
        || ru[0] != 0x31
        || ru[26] != 0
        || ru[27] != 0
    {
        return Err(HprAdapterError::InvalidBindResult);
    }
    let user_end = 29usize
        .checked_add(usize::from(ru[28]))
        .filter(|&end| end < ru.len())
        .ok_or(HprAdapterError::InvalidBindResult)?;
    let retired = user_end
        .checked_add(1 + usize::from(ru[user_end]))
        .filter(|&end| end < ru.len())
        .ok_or(HprAdapterError::InvalidBindResult)?;
    if ru[retired] != 0 {
        return Err(HprAdapterError::InvalidBindResult);
    }
    let mut cursor = retired + 1;
    while cursor < ru.len() {
        let header = ru
            .get(cursor..cursor + 2)
            .ok_or(HprAdapterError::InvalidBindResult)?;
        if header[0] == 0x62 {
            return Err(HprAdapterError::DuplicateAddressVector);
        }
        cursor = cursor
            .checked_add(2 + usize::from(header[1]))
            .filter(|&end| end <= ru.len())
            .ok_or(HprAdapterError::InvalidBindResult)?;
    }
    let mut reduced = unit.as_reduced().to_vec();
    reduced.extend_from_slice(&[0x62, 8]);
    reduced.extend_from_slice(&assigned_sa.to_be_bytes());
    SessionUnit::from_reduced(&reduced).map_err(Into::into)
}

fn remove_cv62(unit: &SessionUnit) -> Result<SessionUnit, HprAdapterError> {
    let ru = unit.ru();
    if ru.len() < 31 || ru.len() > MAX_BIND_RESPONSE || ru[0] != 0x31 || ru[26] != 0 || ru[27] != 0
    {
        return Err(HprAdapterError::InvalidBindResult);
    }
    let user_end = 29usize
        .checked_add(usize::from(ru[28]))
        .filter(|&end| end < ru.len())
        .ok_or(HprAdapterError::InvalidBindResult)?;
    let retired = user_end
        .checked_add(1 + usize::from(ru[user_end]))
        .filter(|&end| end < ru.len())
        .ok_or(HprAdapterError::InvalidBindResult)?;
    if ru[retired] != 0 {
        return Err(HprAdapterError::InvalidBindResult);
    }
    let mut cursor = retired + 1;
    let mut found = None;
    while cursor < ru.len() {
        let header = ru
            .get(cursor..cursor + 2)
            .ok_or(HprAdapterError::InvalidBindResult)?;
        let end = cursor
            .checked_add(2 + usize::from(header[1]))
            .filter(|&end| end <= ru.len())
            .ok_or(HprAdapterError::InvalidBindResult)?;
        if header[0] == 0x62 && found.replace((cursor, end)).is_some() {
            return Err(HprAdapterError::DuplicateAddressVector);
        }
        cursor = end;
    }
    let (start, end) = found.ok_or(HprAdapterError::InvalidBindResult)?;
    let mut reduced = unit.as_reduced().to_vec();
    reduced.drain(5 + start..5 + end);
    SessionUnit::from_reduced(&reduced).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionGeneration;

    const PLU_SA: u64 = 0x8000_0000_0000_1111;
    const SLU_SA: u64 = 0x8000_0000_0000_2222;

    fn scope() -> RtpAssociationScope {
        RtpAssociationScope {
            generation: ConnectionGeneration::new(9).unwrap(),
            initial_plu_tcid: 0x8015_0000_0000_0040,
            subsequent_plu_tcid: 0x0016_0000_0000_0040,
            slu_tcid: 0x0015_0000_0000_0040,
        }
    }

    fn cp(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn bind_unit() -> SessionUnit {
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        let plu = [0xd5, 0xc5, 0xe3, 0xc1, 0x4b, 0xd3, 0xe4, 0xc1];
        let slu = [0xd5, 0xc5, 0xe3, 0xc2, 0x4b, 0xd3, 0xe4, 0xc2];
        ru.push(plu.len() as u8);
        ru.extend_from_slice(&plu);
        ru.extend_from_slice(&[1, 0, 0]);
        ru.push(slu.len() as u8);
        ru.extend_from_slice(&slu);
        let mut reduced = vec![0x80, 1, 0x6b, 0x80, 0];
        reduced.extend_from_slice(&ru);
        SessionUnit::from_reduced(&reduced).unwrap()
    }

    fn bind_response_unit() -> SessionUnit {
        let mut ru = vec![0; 29];
        ru[0] = 0x31;
        ru[2..4].copy_from_slice(&[0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        ru.extend_from_slice(&[0, 0]);
        let mut reduced = vec![0x80, 1, 0xeb, 0x80, 0];
        reduced.extend_from_slice(&ru);
        SessionUnit::from_reduced(&reduced).unwrap()
    }

    fn fixed_bind_response_unit() -> SessionUnit {
        let mut reduced = bind_response_unit().as_reduced().to_vec();
        reduced[5 + 8] = 3;
        reduced[5 + 9] = 1;
        reduced[5 + 12] = 0x81;
        reduced[5 + 13] = 3;
        SessionUnit::from_reduced(&reduced).unwrap()
    }

    fn observation(tcid: u64) -> RtpObservation {
        RtpObservation {
            generation: scope().generation,
            tcid,
        }
    }

    fn data_unit() -> SessionUnit {
        SessionUnit::from_reduced(&[0, 2, 0x03, 0x81, 0, 0x22]).unwrap()
    }

    #[test]
    fn peer_plu_bind_and_data_use_both_receiver_assigned_addresses() {
        let s = scope();
        let mut adapter = HprSessionAdapter::new(
            HprSessionRole::PeerPlu,
            s,
            SLU_SA,
            Some(cp("NETB.CPB")),
            Some(cp("NETA.CPA")),
        )
        .unwrap();
        let bind = encode_whole_biu(PLU_SA.to_be_bytes(), Flow::Expedited, &bind_unit()).unwrap();
        let ingress = adapter
            .ingest_verified(observation(s.initial_plu_tcid), &bind)
            .unwrap();
        assert_eq!(ingress.identity.unwrap().source_lu, cp("NETA.LUA"));
        assert!(matches!(ingress.event, SessionEvent::BindRequest(_)));
        assert_eq!(adapter.phase(), HprSessionPhase::AwaitBindResult);

        let response = adapter
            .encode_event(SessionEvent::BindResult {
                accepted: true,
                unit: bind_response_unit(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(response.observation.tcid, s.slu_tcid);
        let response_fid5 = Fid5WholeBiu::parse_complete(&response.message).unwrap();
        assert_eq!(
            response_fid5.session_address,
            (PLU_SA & !ASSIGNOR).to_be_bytes()
        );
        assert!(response_fid5
            .ru
            .ends_with(&[0x62, 8, 0x80, 0, 0, 0, 0, 0, 0x22, 0x22]));
        assert_eq!(adapter.phase(), HprSessionPhase::Open);
        adapter.configure_fixed_pacing(7, 1).unwrap();
        assert!(!adapter.needs_receive_grant());
        assert_eq!(adapter.receive_grant(), None);

        let inbound = encode_whole_biu(
            (SLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Normal,
            &data_unit(),
        )
        .unwrap();
        let ingress = adapter
            .ingest_verified(observation(s.subsequent_plu_tcid), &inbound)
            .unwrap();
        assert!(matches!(
            ingress.event,
            SessionEvent::Information {
                flow: Flow::Normal,
                ..
            }
        ));
        assert!(adapter.needs_receive_grant());
        assert_eq!(
            adapter.receive_grant(),
            Some(SessionEvent::Credit {
                normal: 1,
                expedited: 0,
            })
        );
        let grant = adapter
            .encode_event(SessionEvent::Credit {
                normal: 1,
                expedited: 0,
            })
            .unwrap()
            .unwrap();
        assert!(!adapter.needs_receive_grant());
        assert_eq!(adapter.receive_grant(), None);
        let grant_fid5 = Fid5WholeBiu::parse_complete(&grant.message).unwrap();
        assert_eq!(grant_fid5.sequence_number, 2);
        assert_eq!(grant_fid5.rh, IPR_RH);
        assert!(grant_fid5.ru.is_empty());
        let egress = adapter
            .encode_event(SessionEvent::Information {
                flow: Flow::Expedited,
                unit: data_unit(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(egress.observation.tcid, s.slu_tcid);
        let data = Fid5WholeBiu::parse_complete(&egress.message).unwrap();
        assert_eq!(data.session_address, (PLU_SA & !ASSIGNOR).to_be_bytes());
        assert_eq!(data.rh[1] & PACING_INDICATOR, 0); // expedited flow carries no normal pacing PI
    }

    #[test]
    fn router_plu_bind_and_data_roundtrip() {
        let s = scope();
        let mut adapter = HprSessionAdapter::new(
            HprSessionRole::RouterPlu,
            s,
            PLU_SA,
            Some(cp("NETA.CPA")),
            Some(cp("NETB.CPB")),
        )
        .unwrap();
        let request = adapter
            .encode_event(SessionEvent::BindRequest(bind_unit()))
            .unwrap()
            .unwrap();
        assert_eq!(request.observation.tcid, s.initial_plu_tcid);
        assert_eq!(
            Fid5WholeBiu::parse_complete(&request.message)
                .unwrap()
                .session_address,
            PLU_SA.to_be_bytes()
        );
        let response = add_cv62(&bind_response_unit(), SLU_SA).unwrap();
        let message = encode_whole_biu(
            (PLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Expedited,
            &response,
        )
        .unwrap();
        let ingress = adapter
            .ingest_verified(observation(s.slu_tcid), &message)
            .unwrap();
        assert_eq!(
            ingress.event,
            SessionEvent::BindResult {
                accepted: true,
                unit: bind_response_unit()
            }
        );
        assert_eq!(adapter.phase(), HprSessionPhase::Open);
        adapter.configure_fixed_pacing(7, 1).unwrap();
        let outgoing = adapter
            .encode_event(SessionEvent::Information {
                flow: Flow::Normal,
                unit: data_unit(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(outgoing.observation.tcid, s.subsequent_plu_tcid);
        assert_eq!(
            Fid5WholeBiu::parse_complete(&outgoing.message)
                .unwrap()
                .session_address,
            (SLU_SA & !ASSIGNOR).to_be_bytes()
        );
    }

    #[test]
    fn wrong_generation_and_address_do_not_advance_session() {
        let s = scope();
        let mut adapter =
            HprSessionAdapter::new(HprSessionRole::PeerPlu, s, SLU_SA, None, None).unwrap();
        let bind = encode_whole_biu(PLU_SA.to_be_bytes(), Flow::Expedited, &bind_unit()).unwrap();
        let old = RtpObservation {
            generation: ConnectionGeneration::new(8).unwrap(),
            tcid: s.initial_plu_tcid,
        };
        assert!(matches!(
            adapter.ingest_verified(old, &bind),
            Err(HprAdapterError::InvalidAssociation(
                AssociationError::StaleGeneration
            ))
        ));
        assert_eq!(adapter.phase(), HprSessionPhase::AwaitBind);
        adapter
            .ingest_verified(observation(s.initial_plu_tcid), &bind)
            .unwrap();
        adapter
            .encode_event(SessionEvent::BindResult {
                accepted: true,
                unit: bind_response_unit(),
            })
            .unwrap();
        adapter.configure_fixed_pacing(7, 1).unwrap();
        let wrong = encode_whole_biu(
            (PLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Normal,
            &data_unit(),
        )
        .unwrap();
        assert!(matches!(
            adapter.ingest_verified(observation(s.subsequent_plu_tcid), &wrong),
            Err(HprAdapterError::InvalidAssociation(
                AssociationError::WrongDataAddress
            ))
        ));
        assert_eq!(adapter.phase(), HprSessionPhase::Open);
    }

    #[test]
    fn pacing_indicator_and_ipr_stay_on_hpr_carrier() {
        let s = scope();
        let mut adapter =
            HprSessionAdapter::new(HprSessionRole::PeerPlu, s, SLU_SA, None, None).unwrap();
        let bind = encode_whole_biu(PLU_SA.to_be_bytes(), Flow::Expedited, &bind_unit()).unwrap();
        adapter
            .ingest_verified(observation(s.initial_plu_tcid), &bind)
            .unwrap();
        adapter
            .encode_event(SessionEvent::BindResult {
                accepted: true,
                unit: bind_response_unit(),
            })
            .unwrap();
        adapter.configure_fixed_pacing(1, 1).unwrap();
        let first = adapter
            .encode_event(SessionEvent::Information {
                flow: Flow::Normal,
                unit: data_unit(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            Fid5WholeBiu::parse_complete(&first.message).unwrap().rh[1] & PACING_INDICATOR,
            1
        );
        assert_eq!(
            adapter.encode_event(SessionEvent::Information {
                flow: Flow::Normal,
                unit: data_unit(),
            }),
            Err(HprAdapterError::Pacing(PacingError::SendWindowExhausted))
        );
        let ipr_unit = SessionUnit::from_reduced(&[0, 2, 0x83, 0x01, 0]).unwrap();
        let ipr = encode_whole_biu(
            (SLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Expedited,
            &ipr_unit,
        )
        .unwrap();
        let credit = adapter
            .ingest_verified(observation(s.subsequent_plu_tcid), &ipr)
            .unwrap();
        assert_eq!(
            credit.event,
            SessionEvent::Credit {
                normal: 1,
                expedited: 0
            }
        );
        assert_eq!(credit.extra_credit, None);
        assert!(matches!(
            adapter.ingest_verified(observation(s.subsequent_plu_tcid), &ipr),
            Err(HprAdapterError::Pacing(
                PacingError::DuplicatePacingResponse
            ))
        ));
        assert!(adapter
            .encode_event(SessionEvent::Information {
                flow: Flow::Normal,
                unit: data_unit(),
            })
            .is_ok());
    }

    #[test]
    fn negative_bind_closes_without_assigning_a_second_address() {
        let s = scope();
        let denied =
            SessionUnit::from_reduced(&[0x80, 1, 0xeb, 0x90, 0, 0x10, 0x16, 0, 0x27]).unwrap();
        let mut peer_plu =
            HprSessionAdapter::new(HprSessionRole::PeerPlu, s, SLU_SA, None, None).unwrap();
        let bind = encode_whole_biu(PLU_SA.to_be_bytes(), Flow::Expedited, &bind_unit()).unwrap();
        peer_plu
            .ingest_verified(observation(s.initial_plu_tcid), &bind)
            .unwrap();
        let refusal = peer_plu
            .encode_event(SessionEvent::BindResult {
                accepted: false,
                unit: denied.clone(),
            })
            .unwrap()
            .unwrap();
        let fid5 = Fid5WholeBiu::parse_complete(&refusal.message).unwrap();
        assert_eq!(fid5.session_address, (PLU_SA & !ASSIGNOR).to_be_bytes());
        assert_eq!(fid5.ru, denied.ru());
        assert_eq!(peer_plu.phase(), HprSessionPhase::Closed);

        let mut router_plu =
            HprSessionAdapter::new(HprSessionRole::RouterPlu, s, PLU_SA, None, None).unwrap();
        router_plu
            .encode_event(SessionEvent::BindRequest(bind_unit()))
            .unwrap();
        let incoming =
            encode_whole_biu((PLU_SA & !ASSIGNOR).to_be_bytes(), Flow::Expedited, &denied).unwrap();
        assert_eq!(
            router_plu
                .ingest_verified(observation(s.slu_tcid), &incoming)
                .unwrap()
                .event,
            SessionEvent::BindResult {
                accepted: false,
                unit: denied
            }
        );
        assert_eq!(router_plu.phase(), HprSessionPhase::Closed);
    }

    #[test]
    fn unbind_waits_for_correlated_response_in_both_directions() {
        let s = scope();
        let mut peer_plu =
            HprSessionAdapter::new(HprSessionRole::PeerPlu, s, SLU_SA, None, None).unwrap();
        let bind = encode_whole_biu(PLU_SA.to_be_bytes(), Flow::Expedited, &bind_unit()).unwrap();
        peer_plu
            .ingest_verified(observation(s.initial_plu_tcid), &bind)
            .unwrap();
        peer_plu
            .encode_event(SessionEvent::BindResult {
                accepted: true,
                unit: bind_response_unit(),
            })
            .unwrap();
        let request = SessionUnit::from_reduced(&[0x12, 0x34, 0x6b, 0x80, 0, 0x32]).unwrap();
        let request_message = encode_whole_biu(
            (SLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Expedited,
            &request,
        )
        .unwrap();
        assert_eq!(
            peer_plu
                .ingest_verified(observation(s.subsequent_plu_tcid), &request_message)
                .unwrap()
                .event,
            SessionEvent::Unbind(request.clone())
        );
        assert_eq!(peer_plu.phase(), HprSessionPhase::AwaitUnbindResult);
        let wrong = SessionUnit::from_reduced(&[0x12, 0x35, 0xeb, 0x80, 0, 0x32]).unwrap();
        assert_eq!(
            peer_plu.encode_event(SessionEvent::Unbind(wrong)),
            Err(HprAdapterError::InvalidPhase)
        );
        let response = SessionUnit::from_reduced(&[0x12, 0x34, 0xeb, 0x80, 0, 0x32]).unwrap();
        let egress = peer_plu
            .encode_event(SessionEvent::Unbind(response.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            Fid5WholeBiu::parse_complete(&egress.message)
                .unwrap()
                .session_address,
            (PLU_SA & !ASSIGNOR).to_be_bytes()
        );
        assert_eq!(peer_plu.phase(), HprSessionPhase::Closed);

        let mut router_plu =
            HprSessionAdapter::new(HprSessionRole::RouterPlu, s, PLU_SA, None, None).unwrap();
        router_plu
            .encode_event(SessionEvent::BindRequest(bind_unit()))
            .unwrap();
        let hpr_response = add_cv62(&bind_response_unit(), SLU_SA).unwrap();
        let hpr_message = encode_whole_biu(
            (PLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Expedited,
            &hpr_response,
        )
        .unwrap();
        router_plu
            .ingest_verified(observation(s.slu_tcid), &hpr_message)
            .unwrap();
        router_plu
            .encode_event(SessionEvent::Unbind(request))
            .unwrap();
        assert_eq!(router_plu.phase(), HprSessionPhase::AwaitUnbindResult);
        let response_message = encode_whole_biu(
            (PLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Expedited,
            &response,
        )
        .unwrap();
        assert_eq!(
            router_plu
                .ingest_verified(observation(s.slu_tcid), &response_message)
                .unwrap()
                .event,
            SessionEvent::Unbind(response)
        );
        assert_eq!(router_plu.phase(), HprSessionPhase::Closed);
    }

    #[test]
    fn extracts_directional_fixed_windows_and_rejects_adaptive_claim() {
        let request = bind_unit();
        let response = fixed_bind_response_unit();
        assert_eq!(
            negotiated_fixed_windows(HprSessionRole::PeerPlu, &request, &response),
            Ok((3, 1))
        );
        assert_eq!(
            negotiated_fixed_windows(HprSessionRole::RouterPlu, &request, &response),
            Ok((1, 3))
        );
        let mut invalid = response.as_reduced().to_vec();
        invalid[5 + 12] = 1;
        assert_eq!(
            negotiated_fixed_windows(
                HprSessionRole::PeerPlu,
                &request,
                &SessionUnit::from_reduced(&invalid).unwrap(),
            ),
            Err(HprAdapterError::UnsupportedPacing)
        );

        // Bob V5R4 answered the Alice adaptive offer with these four BIND
        // pacing bytes: adaptive selected, both fixed windows zero. The EE
        // adapter must keep rejecting this until IPM handling exists.
        let mut captured_adaptive = response.as_reduced().to_vec();
        captured_adaptive[5 + 8] = 0x00;
        captured_adaptive[5 + 9] = 0x80;
        captured_adaptive[5 + 12] = 0x80;
        captured_adaptive[5 + 13] = 0x00;
        assert_eq!(
            negotiated_fixed_windows(
                HprSessionRole::RouterPlu,
                &request,
                &SessionUnit::from_reduced(&captured_adaptive).unwrap(),
            ),
            Err(HprAdapterError::UnsupportedPacing)
        );
    }

    #[test]
    fn preview_discards_state_until_delivery_is_committed() {
        let s = scope();
        let adapter =
            HprSessionAdapter::new(HprSessionRole::PeerPlu, s, SLU_SA, None, None).unwrap();
        let bind = encode_whole_biu(PLU_SA.to_be_bytes(), Flow::Expedited, &bind_unit()).unwrap();
        let (mut candidate, ingress) = adapter
            .preview_ingress(observation(s.initial_plu_tcid), &bind)
            .unwrap();
        assert_eq!(adapter.phase(), HprSessionPhase::AwaitBind);
        assert_eq!(candidate.phase(), HprSessionPhase::AwaitBindResult);
        assert!(matches!(ingress.event, SessionEvent::BindRequest(_)));
        candidate
            .encode_event(SessionEvent::BindResult {
                accepted: true,
                unit: fixed_bind_response_unit(),
            })
            .unwrap();
        candidate.configure_fixed_pacing(1, 1).unwrap();
        let event = SessionEvent::Information {
            flow: Flow::Normal,
            unit: data_unit(),
        };
        let (sent, first) = candidate.preview_egress(event.clone()).unwrap();
        assert_eq!(
            first.as_ref().unwrap().message,
            candidate
                .preview_egress(event.clone())
                .unwrap()
                .1
                .unwrap()
                .message
        );
        assert!(candidate.preview_egress(event.clone()).is_ok());
        assert!(matches!(
            sent.preview_egress(event),
            Err(HprAdapterError::Pacing(PacingError::SendWindowExhausted))
        ));
        let ipr_unit = SessionUnit::from_reduced(&[0, 2, 0x83, 0x01, 0]).unwrap();
        let ipr = encode_whole_biu(
            (SLU_SA & !ASSIGNOR).to_be_bytes(),
            Flow::Expedited,
            &ipr_unit,
        )
        .unwrap();
        let (received, credit) = sent
            .preview_ingress(observation(s.subsequent_plu_tcid), &ipr)
            .unwrap();
        assert_eq!(
            credit.event,
            SessionEvent::Credit {
                normal: 1,
                expedited: 0
            }
        );
        assert!(sent
            .preview_ingress(observation(s.subsequent_plu_tcid), &ipr)
            .is_ok());
        assert!(matches!(
            received.preview_ingress(observation(s.subsequent_plu_tcid), &ipr),
            Err(HprAdapterError::Pacing(
                PacingError::DuplicatePacingResponse
            ))
        ));
    }

    #[test]
    fn captured_v5r4_aping_snasvcmg_bind_requires_service_cp() {
        // Complete FID5 BIU observed in the V5R4 EE APING attempt.
        let hex = concat!(
            "5d00000080020600f0f100016b800031001307b0b051330787868687070602",
            "00000000000000944340000be2d6d3d5c5e34be2d5c1c22d000902e2d5",
            "c1e2e5c3d4c709030124e67713cf80000c04e2d6d3d5c5e34be2d5c1",
            "c20a1300b024e67713cf8000000be2d5e4e2d5e44bd7c9d5c76014ce",
            "c370e7b283a29c0be2d6d3d5c5e34be2d5c1c22c0a04087bc3d6d5",
            "d5c5c3e3",
        );
        let message: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(message.len(), 147);
        let fid5 = Fid5WholeBiu::parse_complete(&message).unwrap();
        let bind = fid5.classify_bind().unwrap().unwrap();
        assert_eq!(bind.plu, "SOLNET.SNAB");
        assert_eq!(bind.slu, "SNUSNU.PING");
        assert_eq!(
            bind.class,
            BindClass::Management {
                mode: "SNASVCMG".into()
            }
        );
        let s = scope();
        let mut permitted = HprSessionAdapter::new(
            HprSessionRole::PeerPlu,
            s,
            SLU_SA,
            Some(cp("SNUSNU.SVC")),
            Some(cp("SOLNET.SNAB")),
        )
        .unwrap();
        let admitted = permitted
            .ingest_verified(observation(s.initial_plu_tcid), &message)
            .unwrap();
        assert_eq!(admitted.identity.unwrap().target_lu, cp("SNUSNU.PING"));
        assert!(matches!(admitted.event, SessionEvent::BindRequest(_)));

        let mut no_service_cp = HprSessionAdapter::new(
            HprSessionRole::PeerPlu,
            s,
            SLU_SA,
            None,
            Some(cp("SOLNET.SNAB")),
        )
        .unwrap();
        assert_eq!(
            no_service_cp.ingest_verified(observation(s.initial_plu_tcid), &message),
            Err(HprAdapterError::ManagementBind)
        );

        let mut cp_management = message.clone();
        let mode = [0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
        let at = cp_management
            .windows(mode.len())
            .position(|part| part == mode)
            .unwrap();
        cp_management.splice(
            at..at + mode.len(),
            [0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7],
        );
        cp_management[at - 2] = 8;
        cp_management[at - 4] -= 1;
        let mut reject_cp = HprSessionAdapter::new(
            HprSessionRole::PeerPlu,
            s,
            SLU_SA,
            Some(cp("SNUSNU.SVC")),
            Some(cp("SOLNET.SNAB")),
        )
        .unwrap();
        assert_eq!(
            reject_cp.ingest_verified(observation(s.initial_plu_tcid), &cp_management),
            Err(HprAdapterError::ManagementBind)
        );
    }

    #[test]
    fn concentrator_service_bind_scope_includes_printer_without_admitting_cp() {
        assert!(is_concentrator_service_lu("SNUSNU.PING"));
        assert!(is_concentrator_service_lu("SNUSNU.PRINTER"));
        assert!(!is_concentrator_service_lu("SNUSNU.SVC"));
        assert!(!is_concentrator_service_lu("OTHER.PRINTER"));
        assert!(!is_concentrator_service_lu("PRINTER"));
    }

    #[test]
    fn captured_v5r4_second_bind_starts_independent_session_on_established_rtp() {
        // The guest sent this BIND on the same validated user RTP TCID after
        // its SNASVCMG/CNOS exchange. Its newly assigned SA differs from the
        // management session's SA; RTP setup was not repeated.
        let hex = concat!(
            "5d00000080020800f0f100026b800031001307b0b0513303838c8c8303060200",
            "000000000000944340000be2d6d3d5c5e34be2d5c1c22d000902404040404040",
            "404009030124ebc708ef80000c04e2d6d3d5c5e34be2d5c1c20a1300b024ebc7",
            "08ef8000000be2d5e4e2d5e44bd7c9d5c76014cec370e7b283a2c40be2d6d3d5",
            "c5e34be2d5c1c22c0a01087bc3d6d5d5c5c3e3",
        );
        let message: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(message.len(), 147);
        let s = RtpAssociationScope {
            subsequent_plu_tcid: 0x0000_0002_0000_0008,
            ..scope()
        };
        let mut second = HprSessionAdapter::new_subsequent(
            HprSessionRole::PeerPlu,
            s,
            SLU_SA,
            Some(cp("SNUSNU.SVC")),
            Some(cp("SOLNET.SNAB")),
        )
        .unwrap();
        assert_eq!(
            second.ingest_verified(observation(s.initial_plu_tcid), &message),
            Err(HprAdapterError::InvalidAssociation(
                AssociationError::WrongRtpConnection
            ))
        );
        let ingress = second
            .ingest_verified(observation(s.subsequent_plu_tcid), &message)
            .unwrap();
        let identity = ingress.identity.unwrap();
        assert_eq!(identity.source_lu, cp("SOLNET.SNAB"));
        assert_eq!(identity.target_lu, cp("SNUSNU.PING"));
        assert!(matches!(ingress.event, SessionEvent::BindRequest(_)));
        assert_eq!(second.phase(), HprSessionPhase::AwaitBindResult);

        let mut initial = HprSessionAdapter::new(
            HprSessionRole::PeerPlu,
            s,
            SLU_SA,
            Some(cp("SNUSNU.SVC")),
            Some(cp("SOLNET.SNAB")),
        )
        .unwrap();
        assert_eq!(
            initial.ingest_verified(observation(s.subsequent_plu_tcid), &message),
            Err(HprAdapterError::InvalidAssociation(
                AssociationError::WrongRtpConnection
            ))
        );
    }
}
