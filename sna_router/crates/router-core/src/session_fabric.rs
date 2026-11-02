//! Carrier-neutral session switching. Carrier adapters submit complete session
//! events and drain their own ordered queues; framing never enters this module.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::session::{
    QualifiedName, SessionContract, SessionError, SessionEvent, SessionIdentity, SessionPhase,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AdapterId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FabricSessionId(pub u64);

/// A reachable LU, CP, or LU hosted by a CP. CP-only routes cover LUs
/// dynamically discovered by a carrier adapter at that CP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reachability {
    pub lu: Option<QualifiedName>,
    pub cp: Option<QualifiedName>,
}

impl Reachability {
    pub fn validate(&self) -> Result<(), FabricError> {
        if self.lu.is_none() && self.cp.is_none() {
            return Err(FabricError::InvalidRoute);
        }
        if matches!((&self.lu, &self.cp), (Some(lu), Some(cp)) if lu.netid != cp.netid) {
            return Err(FabricError::InvalidRoute);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FabricError {
    UnknownAdapter,
    UnknownSession,
    InvalidRoute,
    NoRoute,
    AmbiguousRoute,
    LoopRoute,
    WrongEndpoint,
    WrongDirection,
    Capacity,
    Session(SessionError),
}

impl From<SessionError> for FabricError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FabricLimits {
    pub max_sessions: usize,
    pub max_queued_events_per_side: usize,
    pub max_queued_bytes_per_side: usize,
}

impl Default for FabricLimits {
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            max_queued_events_per_side: 64,
            max_queued_bytes_per_side: 128 * 1024,
        }
    }
}

#[derive(Debug)]
struct Pending {
    events: VecDeque<SessionEvent>,
    bytes: usize,
}

impl Pending {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, event: SessionEvent) {
        self.bytes += event_bytes(&event);
        self.events.push_back(event);
    }

    fn pop(&mut self) -> Option<SessionEvent> {
        let event = self.events.pop_front()?;
        self.bytes -= event_bytes(&event);
        Some(event)
    }

    fn clear(&mut self) {
        self.events.clear();
        self.bytes = 0;
    }
}

fn event_bytes(event: &SessionEvent) -> usize {
    match event {
        SessionEvent::BindRequest(unit)
        | SessionEvent::BindResult { unit, .. }
        | SessionEvent::Information { unit, .. }
        | SessionEvent::Unbind(unit) => unit.as_reduced().len(),
        SessionEvent::Credit { .. } => 8,
        SessionEvent::Reset => 1,
    }
}

#[derive(Debug)]
struct Session {
    contract: SessionContract,
    ingress: AdapterId,
    egress: AdapterId,
    to_ingress: Pending,
    to_egress: Pending,
}

/// The adapters remain responsible for decoding, transport pacing, and I/O.
/// Each session pins its selected egress until closure, so route refreshes do
/// not redirect an active conversation.
#[derive(Debug)]
pub struct SessionFabric {
    limits: FabricLimits,
    adapters: HashSet<AdapterId>,
    routes: HashMap<AdapterId, Vec<Reachability>>,
    sessions: HashMap<FabricSessionId, Session>,
    next_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionDetails {
    pub identity: SessionIdentity,
    pub ingress: AdapterId,
    pub egress: AdapterId,
    pub phase: SessionPhase,
}

impl SessionFabric {
    pub fn new(limits: FabricLimits) -> Self {
        Self {
            limits,
            adapters: HashSet::new(),
            routes: HashMap::new(),
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn register_adapter(&mut self, adapter: AdapterId) {
        self.adapters.insert(adapter);
    }

    /// Atomically replace an adapter's current directory view.
    pub fn replace_routes(
        &mut self,
        adapter: AdapterId,
        routes: Vec<Reachability>,
    ) -> Result<(), FabricError> {
        if !self.adapters.contains(&adapter) {
            return Err(FabricError::UnknownAdapter);
        }
        for route in &routes {
            route.validate()?;
        }
        self.routes.insert(adapter, routes);
        Ok(())
    }

    pub fn open(
        &mut self,
        ingress: AdapterId,
        identity: SessionIdentity,
    ) -> Result<(FabricSessionId, AdapterId), FabricError> {
        if identity
            .source_cp
            .as_ref()
            .is_some_and(|cp| cp.netid != identity.source_lu.netid)
            || identity
                .target_cp
                .as_ref()
                .is_some_and(|cp| cp.netid != identity.target_lu.netid)
        {
            return Err(FabricError::Session(SessionError::InvalidIdentity));
        }
        if !self.adapters.contains(&ingress) {
            return Err(FabricError::UnknownAdapter);
        }
        if self.sessions.len() >= self.limits.max_sessions || self.next_id == u64::MAX {
            return Err(FabricError::Capacity);
        }
        let egress = self.resolve(&identity)?;
        if egress == ingress {
            return Err(FabricError::LoopRoute);
        }
        let id = FabricSessionId(self.next_id);
        self.next_id += 1;
        self.sessions.insert(
            id,
            Session {
                contract: SessionContract::new(identity),
                ingress,
                egress,
                to_ingress: Pending::new(),
                to_egress: Pending::new(),
            },
        );
        Ok((id, egress))
    }

    fn resolve(&self, identity: &SessionIdentity) -> Result<AdapterId, FabricError> {
        // An exact LU advertisement wins. A CP route is only usable when the
        // target CP is known; the fabric cannot infer a hosting CP from an LU.
        for by_lu in [true, false] {
            if !by_lu && identity.target_cp.is_none() {
                break;
            }
            let mut selected = None;
            for (&adapter, routes) in &self.routes {
                let matches = routes.iter().any(|route| {
                    if by_lu {
                        route.lu.as_ref() == Some(&identity.target_lu)
                            && (identity.target_cp.is_none()
                                || route.cp.is_none()
                                || route.cp == identity.target_cp)
                    } else {
                        route.lu.is_none() && route.cp == identity.target_cp
                    }
                });
                if matches {
                    if selected.is_some() {
                        return Err(FabricError::AmbiguousRoute);
                    }
                    selected = Some(adapter);
                }
            }
            if let Some(adapter) = selected {
                return Ok(adapter);
            }
        }
        Err(FabricError::NoRoute)
    }

    pub fn submit(
        &mut self,
        id: FabricSessionId,
        from: AdapterId,
        event: SessionEvent,
    ) -> Result<(), FabricError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(FabricError::UnknownSession)?;
        let to_egress = if from == session.ingress {
            true
        } else if from == session.egress {
            false
        } else {
            return Err(FabricError::WrongEndpoint);
        };
        if matches!(event, SessionEvent::BindRequest(_)) && !to_egress
            || matches!(event, SessionEvent::BindResult { .. }) && to_egress
        {
            return Err(FabricError::WrongDirection);
        }
        // A reset must reach the surviving side even when the queue is full.
        if matches!(event, SessionEvent::Reset) {
            session.contract.accept(&event)?;
            session.to_ingress.clear();
            session.to_egress.clear();
            if to_egress {
                &mut session.to_egress
            } else {
                &mut session.to_ingress
            }
            .push(event);
            return Ok(());
        }
        let pending = if to_egress {
            &mut session.to_egress
        } else {
            &mut session.to_ingress
        };
        if pending.events.len() >= self.limits.max_queued_events_per_side
            || event_bytes(&event)
                > self
                    .limits
                    .max_queued_bytes_per_side
                    .saturating_sub(pending.bytes)
        {
            return Err(FabricError::Capacity);
        }
        session.contract.accept(&event)?;
        pending.push(event);
        Ok(())
    }

    /// Drain the next event addressed to this adapter, preserving submission order.
    pub fn poll(
        &mut self,
        id: FabricSessionId,
        for_adapter: AdapterId,
    ) -> Result<Option<SessionEvent>, FabricError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(FabricError::UnknownSession)?;
        let pending = if for_adapter == session.ingress {
            &mut session.to_ingress
        } else if for_adapter == session.egress {
            &mut session.to_egress
        } else {
            return Err(FabricError::WrongEndpoint);
        };
        let event = pending.pop();
        if session.contract.phase() == SessionPhase::Closed
            && session.to_ingress.events.is_empty()
            && session.to_egress.events.is_empty()
        {
            self.sessions.remove(&id);
        }
        Ok(event)
    }

    pub fn phase(&self, id: FabricSessionId) -> Option<SessionPhase> {
        self.sessions
            .get(&id)
            .map(|session| session.contract.phase())
    }

    pub fn details(&self, id: FabricSessionId) -> Option<SessionDetails> {
        self.sessions.get(&id).map(|session| SessionDetails {
            identity: session.contract.identity.clone(),
            ingress: session.ingress,
            egress: session.egress,
            phase: session.contract.phase(),
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Withdraw routes and reset only sessions on the removed attachment.
    /// The surviving adapter can still drain its terminal reset.
    pub fn unregister_adapter(&mut self, adapter: AdapterId) {
        self.adapters.remove(&adapter);
        self.routes.remove(&adapter);
        let mut drained = Vec::new();
        for (&id, session) in &mut self.sessions {
            if session.contract.phase() == SessionPhase::Closed {
                if session.ingress == adapter {
                    session.to_ingress.clear();
                    if session.to_egress.events.is_empty() {
                        drained.push(id);
                    }
                } else if session.egress == adapter {
                    session.to_egress.clear();
                    if session.to_ingress.events.is_empty() {
                        drained.push(id);
                    }
                }
                continue;
            }
            if session.ingress == adapter {
                let _ = session.contract.accept(&SessionEvent::Reset);
                session.to_ingress.clear();
                session.to_egress.clear();
                session.to_egress.push(SessionEvent::Reset);
            } else if session.egress == adapter {
                let _ = session.contract.accept(&SessionEvent::Reset);
                session.to_egress.clear();
                session.to_ingress.clear();
                session.to_ingress.push(SessionEvent::Reset);
            }
        }
        for id in drained {
            self.sessions.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Flow, SessionUnit};

    fn q(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }
    fn unit() -> SessionUnit {
        SessionUnit::from_reduced(&[0x31, 0, 0, 0x31]).unwrap()
    }
    fn identity() -> SessionIdentity {
        SessionIdentity::new(q("SRC.LUA"), q("DST.LUB"))
            .with_control_points(Some(q("SRC.CPA")), Some(q("DST.CPB")))
            .unwrap()
    }
    fn fabric(limits: FabricLimits) -> SessionFabric {
        let mut fabric = SessionFabric::new(limits);
        for id in [AdapterId(1), AdapterId(2), AdapterId(3)] {
            fabric.register_adapter(id);
        }
        fabric
            .replace_routes(
                AdapterId(2),
                vec![Reachability {
                    lu: Some(q("DST.LUB")),
                    cp: Some(q("DST.CPB")),
                }],
            )
            .unwrap();
        fabric
    }

    #[test]
    fn exact_lu_precedes_cp_and_ambiguity_is_rejected() {
        let mut fabric = fabric(FabricLimits::default());
        fabric
            .replace_routes(
                AdapterId(3),
                vec![Reachability {
                    lu: None,
                    cp: Some(q("DST.CPB")),
                }],
            )
            .unwrap();
        assert_eq!(
            fabric.open(AdapterId(1), identity()).unwrap().1,
            AdapterId(2)
        );
        fabric.replace_routes(AdapterId(2), vec![]).unwrap();
        assert_eq!(
            fabric.open(AdapterId(1), identity()).unwrap().1,
            AdapterId(3)
        );
        fabric
            .replace_routes(
                AdapterId(2),
                vec![Reachability {
                    lu: None,
                    cp: Some(q("DST.CPB")),
                }],
            )
            .unwrap();
        assert_eq!(
            fabric.open(AdapterId(1), identity()),
            Err(FabricError::AmbiguousRoute)
        );
    }

    #[test]
    fn invalid_route_replacement_is_atomic_and_loop_is_rejected() {
        let mut fabric = fabric(FabricLimits::default());
        assert_eq!(
            fabric.replace_routes(
                AdapterId(2),
                vec![Reachability {
                    lu: Some(q("DST.LUB")),
                    cp: Some(q("WRONG.CPB"))
                }]
            ),
            Err(FabricError::InvalidRoute)
        );
        assert_eq!(
            fabric.open(AdapterId(1), identity()).unwrap().1,
            AdapterId(2)
        );
        assert_eq!(
            fabric.open(AdapterId(2), identity()),
            Err(FabricError::LoopRoute)
        );
    }

    #[test]
    fn ordered_events_and_direction_are_isolated_per_session() {
        let mut fabric = fabric(FabricLimits::default());
        let (one, _) = fabric.open(AdapterId(1), identity()).unwrap();
        let (two, _) = fabric.open(AdapterId(3), identity()).unwrap();
        assert_eq!(
            fabric.submit(one, AdapterId(2), SessionEvent::BindRequest(unit())),
            Err(FabricError::WrongDirection)
        );
        assert_eq!(
            fabric.submit(one, AdapterId(3), SessionEvent::Reset),
            Err(FabricError::WrongEndpoint)
        );
        fabric
            .submit(one, AdapterId(1), SessionEvent::BindRequest(unit()))
            .unwrap();
        fabric
            .submit(
                one,
                AdapterId(2),
                SessionEvent::BindResult {
                    accepted: true,
                    unit: unit(),
                },
            )
            .unwrap();
        fabric
            .submit(
                one,
                AdapterId(1),
                SessionEvent::Information {
                    flow: Flow::Normal,
                    unit: unit(),
                },
            )
            .unwrap();
        fabric
            .submit(
                one,
                AdapterId(2),
                SessionEvent::Credit {
                    normal: 2,
                    expedited: 0,
                },
            )
            .unwrap();
        assert!(matches!(
            fabric.poll(one, AdapterId(2)).unwrap(),
            Some(SessionEvent::BindRequest(_))
        ));
        assert!(matches!(
            fabric.poll(one, AdapterId(2)).unwrap(),
            Some(SessionEvent::Information { .. })
        ));
        assert!(matches!(
            fabric.poll(one, AdapterId(1)).unwrap(),
            Some(SessionEvent::BindResult { .. })
        ));
        assert_eq!(
            fabric.poll(one, AdapterId(1)).unwrap(),
            Some(SessionEvent::Credit {
                normal: 2,
                expedited: 0
            })
        );
        assert_eq!(fabric.phase(two), Some(SessionPhase::AwaitBind));
        fabric
            .submit(one, AdapterId(1), SessionEvent::Unbind(unit()))
            .unwrap();
        assert!(matches!(
            fabric.poll(one, AdapterId(2)).unwrap(),
            Some(SessionEvent::Unbind(_))
        ));
        assert_eq!(fabric.phase(one), None);
        assert_eq!(fabric.phase(two), Some(SessionPhase::AwaitBind));
    }

    #[test]
    fn backpressure_does_not_advance_contract_and_reset_bypasses_full_queue() {
        let mut fabric = fabric(FabricLimits {
            max_sessions: 2,
            max_queued_events_per_side: 1,
            max_queued_bytes_per_side: 8,
        });
        let (id, _) = fabric.open(AdapterId(1), identity()).unwrap();
        fabric
            .submit(id, AdapterId(1), SessionEvent::BindRequest(unit()))
            .unwrap();
        assert_eq!(
            fabric.submit(
                id,
                AdapterId(2),
                SessionEvent::BindResult {
                    accepted: true,
                    unit: unit()
                }
            ),
            Ok(())
        );
        assert_eq!(
            fabric.submit(
                id,
                AdapterId(1),
                SessionEvent::Information {
                    flow: Flow::Normal,
                    unit: unit()
                }
            ),
            Err(FabricError::Capacity)
        );
        assert_eq!(fabric.phase(id), Some(SessionPhase::Open));
        fabric
            .submit(id, AdapterId(1), SessionEvent::Reset)
            .unwrap();
        assert_eq!(
            fabric.poll(id, AdapterId(2)).unwrap(),
            Some(SessionEvent::Reset)
        );
        assert_eq!(fabric.phase(id), None);
    }

    #[test]
    fn withdrawal_resets_only_affected_sessions() {
        let mut fabric = fabric(FabricLimits::default());
        let (one, _) = fabric.open(AdapterId(1), identity()).unwrap();
        let (two, _) = fabric.open(AdapterId(3), identity()).unwrap();
        fabric.unregister_adapter(AdapterId(1));
        assert_eq!(
            fabric.poll(one, AdapterId(2)).unwrap(),
            Some(SessionEvent::Reset)
        );
        assert_eq!(fabric.phase(two), Some(SessionPhase::AwaitBind));
        assert_eq!(
            fabric.open(AdapterId(1), identity()),
            Err(FabricError::UnknownAdapter)
        );
    }

    #[test]
    fn terminal_event_survives_source_disconnect() {
        let mut fabric = fabric(FabricLimits::default());
        let (id, _) = fabric.open(AdapterId(1), identity()).unwrap();
        fabric
            .submit(id, AdapterId(1), SessionEvent::BindRequest(unit()))
            .unwrap();
        fabric.poll(id, AdapterId(2)).unwrap();
        fabric
            .submit(
                id,
                AdapterId(2),
                SessionEvent::BindResult {
                    accepted: true,
                    unit: unit(),
                },
            )
            .unwrap();
        fabric.poll(id, AdapterId(1)).unwrap();
        fabric
            .submit(id, AdapterId(1), SessionEvent::Unbind(unit()))
            .unwrap();
        fabric.unregister_adapter(AdapterId(1));
        assert!(matches!(
            fabric.poll(id, AdapterId(2)).unwrap(),
            Some(SessionEvent::Unbind(_))
        ));
        assert_eq!(fabric.phase(id), None);
    }
}
