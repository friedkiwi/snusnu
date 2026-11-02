//! Session-level switching for an HPR attachment and any other carrier.
//!
//! This module is deliberately below the attachment runtime: it accepts only
//! verified LU identities and complete reduced SNA units. The EE/APPN/RTP
//! adapters own their wire protocols, while `SessionFabric` selects a route.
//! Each outbound event has an explicit delivery lease so a carrier that
//! temporarily cannot send cannot lose an event popped from the fabric.

use std::collections::HashMap;

use router_core::{
    session::{Flow, SessionEvent, SessionIdentity, SessionUnit},
    session_fabric::{
        AdapterId, FabricError, FabricLimits, FabricSessionId, Reachability, SessionFabric,
    },
};
use std::io;
use transport_ws::wire;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SwitchError {
    Fabric(FabricError),
    DuplicateHandle,
    UnknownHandle,
    WrongEgress,
    InvalidBind,
    DeliveryNotLeased,
}

impl From<FabricError> for SwitchError {
    fn from(error: FabricError) -> Self {
        Self::Fabric(error)
    }
}

/// A `handle` belongs to one carrier attachment, not to the shared fabric.
/// HPR may use a directional SA and generation, while WebSocket uses a circuit
/// ID. The adapter maps its own opaque value to this integer before calling.
type CarrierHandle = u64;

#[derive(Debug)]
pub(crate) struct SessionSwitch {
    fabric: SessionFabric,
    handles: HashMap<(AdapterId, CarrierHandle), FabricSessionId>,
    leased: HashMap<(FabricSessionId, AdapterId), SessionEvent>,
}

impl SessionSwitch {
    pub(crate) fn new() -> Self {
        Self {
            fabric: SessionFabric::new(FabricLimits::default()),
            handles: HashMap::new(),
            leased: HashMap::new(),
        }
    }

    pub(crate) fn register(&mut self, adapter: AdapterId) {
        self.fabric.register_adapter(adapter);
    }

    pub(crate) fn replace_routes(
        &mut self,
        adapter: AdapterId,
        routes: Vec<Reachability>,
    ) -> Result<(), SwitchError> {
        self.fabric.replace_routes(adapter, routes)?;
        Ok(())
    }

    /// Admit an HPR or other carrier BIND after its adapter has verified the
    /// peer, RTP generation, directional session address and LU names. The
    /// route is pinned for this session; later directory refreshes affect only
    /// new BINDs. The egress handle is attached after its carrier opens.
    pub(crate) fn open(
        &mut self,
        ingress: AdapterId,
        handle: CarrierHandle,
        identity: SessionIdentity,
        bind: SessionUnit,
    ) -> Result<(FabricSessionId, AdapterId), SwitchError> {
        if self.handles.contains_key(&(ingress, handle)) {
            return Err(SwitchError::DuplicateHandle);
        }
        if bind.ru().is_empty() {
            return Err(SwitchError::InvalidBind);
        }
        let (id, egress) = self.fabric.open(ingress, identity)?;
        // Default fabric limits always admit one validated SessionUnit. The
        // BIND is the first event on a new session, so no queue can be full.
        self.fabric
            .submit(id, ingress, SessionEvent::BindRequest(bind))?;
        self.handles.insert((ingress, handle), id);
        Ok((id, egress))
    }

    /// Associate the selected egress's new private carrier circuit. This
    /// prevents a WebSocket circuit or HPR SA from being reused by two sessions.
    pub(crate) fn bind_egress(
        &mut self,
        id: FabricSessionId,
        egress: AdapterId,
        handle: CarrierHandle,
    ) -> Result<(), SwitchError> {
        if self.handles.contains_key(&(egress, handle)) {
            return Err(SwitchError::DuplicateHandle);
        }
        let details = self.fabric.details(id).ok_or(SwitchError::UnknownHandle)?;
        if details.egress != egress {
            return Err(SwitchError::WrongEgress);
        }
        self.handles.insert((egress, handle), id);
        Ok(())
    }

    /// If the selected carrier cannot open its private circuit, notify the
    /// ingress through the same session contract. No egress handle exists yet.
    pub(crate) fn fail_egress(&mut self, id: FabricSessionId) -> Result<(), SwitchError> {
        let details = self.fabric.details(id).ok_or(SwitchError::UnknownHandle)?;
        self.fabric
            .submit(id, details.egress, SessionEvent::Reset)?;
        Ok(())
    }

    /// Submit one complete session event. On `Capacity`, the carrier must
    /// retain its input and withhold its own transport acknowledgement.
    pub(crate) fn submit(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
        event: SessionEvent,
    ) -> Result<(), SwitchError> {
        let id = self.lookup(adapter, handle)?;
        self.fabric.submit(id, adapter, event)?;
        Ok(())
    }

    /// Return the same event until `mark_sent` confirms the destination
    /// carrier accepted it. A failed socket send therefore retains the lease.
    pub(crate) fn next_delivery(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<Option<SessionEvent>, SwitchError> {
        let id = self.lookup(adapter, handle)?;
        if let Some(event) = self.leased.get(&(id, adapter)) {
            return Ok(Some(event.clone()));
        }
        let Some(event) = self.fabric.poll(id, adapter)? else {
            return Ok(None);
        };
        self.leased.insert((id, adapter), event.clone());
        Ok(Some(event))
    }

    pub(crate) fn mark_sent(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<(), SwitchError> {
        let id = self.lookup(adapter, handle)?;
        if self.leased.remove(&(id, adapter)).is_none() {
            return Err(SwitchError::DeliveryNotLeased);
        }
        self.reap(id);
        Ok(())
    }

    /// Withdraw one failed attachment and reset only its affected sessions.
    /// Surviving adapters may still drain their terminal Reset events.
    pub(crate) fn withdraw(&mut self, adapter: AdapterId) {
        let unopened = self
            .handles
            .iter()
            .filter_map(|(&(owner, _), &id)| {
                (owner == adapter
                    && !self
                        .handles
                        .iter()
                        .any(|(&(other, _), &other_id)| other != adapter && other_id == id))
                .then_some(id)
            })
            .collect::<Vec<_>>();
        for id in unopened {
            let _ = self.fabric.discard_unopened(id);
        }
        self.handles.retain(|(owner, _), _| *owner != adapter);
        self.leased.retain(|(_, owner), _| *owner != adapter);
        self.fabric.unregister_adapter(adapter);
        let ids = self.handles.values().copied().collect::<Vec<_>>();
        for id in ids {
            self.reap(id);
        }
    }

    pub(crate) fn session_count(&self) -> usize {
        self.fabric.session_count()
    }

    fn lookup(
        &self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<FabricSessionId, SwitchError> {
        self.handles
            .get(&(adapter, handle))
            .copied()
            .ok_or(SwitchError::UnknownHandle)
    }

    fn reap(&mut self, id: FabricSessionId) {
        if self.fabric.phase(id).is_none() && !self.leased.keys().any(|(key, _)| *key == id) {
            self.handles.retain(|_, key| *key != id);
        }
    }
}

/// The `session_v1` WebSocket profile carries the same complete reduced SNA
/// unit as the fabric. Transport byte credit is handled by SessionWsPort;
/// this conversion does not grant or consume application pacing credit.
pub(crate) fn to_session_wire(event: &SessionEvent) -> Option<wire::SessionEvent> {
    use wire::session_event::Event;
    let event = match event {
        SessionEvent::BindRequest(unit) => Event::BindRequest(unit.as_reduced().to_vec()),
        SessionEvent::BindResult { accepted, unit } => Event::BindResult(wire::SessionBindResult {
            accepted: *accepted,
            reduced_unit: unit.as_reduced().to_vec(),
        }),
        SessionEvent::Information { flow, unit } => Event::Information(wire::SessionInformation {
            expedited: *flow == Flow::Expedited,
            reduced_unit: unit.as_reduced().to_vec(),
        }),
        SessionEvent::Credit { normal, expedited } => {
            Event::PacingCredit(wire::SessionPacingCredit {
                normal: *normal,
                expedited: *expedited,
            })
        }
        SessionEvent::Unbind(unit) => Event::Unbind(unit.as_reduced().to_vec()),
        SessionEvent::Reset => return None,
    };
    Some(wire::SessionEvent { event: Some(event) })
}

pub(crate) fn from_session_wire(value: wire::SessionEvent) -> io::Result<SessionEvent> {
    use wire::session_event::Event;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid session_v1 event");
    let unit = |bytes: Vec<u8>| SessionUnit::from_reduced(&bytes).map_err(|_| invalid());
    match value.event.ok_or_else(invalid)? {
        Event::BindRequest(bytes) => Ok(SessionEvent::BindRequest(unit(bytes)?)),
        Event::BindResult(result) => Ok(SessionEvent::BindResult {
            accepted: result.accepted,
            unit: unit(result.reduced_unit)?,
        }),
        Event::Information(info) => Ok(SessionEvent::Information {
            flow: if info.expedited {
                Flow::Expedited
            } else {
                Flow::Normal
            },
            unit: unit(info.reduced_unit)?,
        }),
        Event::PacingCredit(credit) => Ok(SessionEvent::Credit {
            normal: credit.normal,
            expedited: credit.expedited,
        }),
        Event::Unbind(bytes) => Ok(SessionEvent::Unbind(unit(bytes)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::session::{Flow, QualifiedName};

    fn q(value: &str) -> QualifiedName {
        value.parse().unwrap()
    }

    fn identity() -> SessionIdentity {
        SessionIdentity::new(q("PEERNET.PINGER"), q("SNUSNU.PING"))
            .with_control_points(Some(q("PEERNET.HOST")), Some(q("SNUSNU.SVC")))
            .unwrap()
    }

    fn unit(opcode: u8) -> SessionUnit {
        SessionUnit::from_reduced(&[0x80, 1, 0x6b, 0x80, 0, opcode]).unwrap()
    }

    fn switch() -> SessionSwitch {
        let mut switch = SessionSwitch::new();
        switch.register(AdapterId(1));
        switch.register(AdapterId(2));
        switch
            .replace_routes(
                AdapterId(2),
                vec![Reachability {
                    lu: Some(q("SNUSNU.PING")),
                    cp: Some(q("SNUSNU.SVC")),
                }],
            )
            .unwrap();
        switch
    }

    #[test]
    fn bind_is_routed_to_aping_and_delivery_is_retried_until_confirmed() {
        let mut switch = switch();
        let (id, egress) = switch
            .open(AdapterId(1), 0x1234, identity(), unit(0x31))
            .unwrap();
        assert_eq!(egress, AdapterId(2));
        switch.bind_egress(id, egress, 0x55).unwrap();
        assert_eq!(
            switch.next_delivery(egress, 0x55).unwrap(),
            Some(SessionEvent::BindRequest(unit(0x31)))
        );
        assert_eq!(
            switch.next_delivery(egress, 0x55).unwrap(),
            Some(SessionEvent::BindRequest(unit(0x31)))
        );
        switch.mark_sent(egress, 0x55).unwrap();
        assert_eq!(switch.next_delivery(egress, 0x55).unwrap(), None);
        switch
            .submit(
                egress,
                0x55,
                SessionEvent::BindResult {
                    accepted: true,
                    unit: unit(0x31),
                },
            )
            .unwrap();
        assert!(matches!(
            switch.next_delivery(AdapterId(1), 0x1234).unwrap(),
            Some(SessionEvent::BindResult { accepted: true, .. })
        ));
        switch.mark_sent(AdapterId(1), 0x1234).unwrap();
        switch
            .submit(
                AdapterId(1),
                0x1234,
                SessionEvent::Information {
                    flow: Flow::Normal,
                    unit: unit(0x01),
                },
            )
            .unwrap();
        assert!(matches!(
            switch.next_delivery(egress, 0x55).unwrap(),
            Some(SessionEvent::Information { .. })
        ));
    }

    #[test]
    fn withdrawal_resets_only_affected_session() {
        let mut switch = switch();
        let (id, egress) = switch
            .open(AdapterId(1), 1, identity(), unit(0x31))
            .unwrap();
        switch.bind_egress(id, egress, 2).unwrap();
        switch.withdraw(AdapterId(1));
        assert_eq!(
            switch.next_delivery(egress, 2).unwrap(),
            Some(SessionEvent::Reset)
        );
        switch.mark_sent(egress, 2).unwrap();
        assert_eq!(switch.session_count(), 0);
        assert_eq!(
            switch.submit(AdapterId(1), 1, SessionEvent::Reset),
            Err(SwitchError::UnknownHandle)
        );
    }

    #[test]
    fn failed_egress_open_resets_ingress_without_a_phantom_handle() {
        let mut switch = switch();
        let (id, _) = switch
            .open(AdapterId(1), 1, identity(), unit(0x31))
            .unwrap();
        switch.fail_egress(id).unwrap();
        assert_eq!(
            switch.next_delivery(AdapterId(1), 1).unwrap(),
            Some(SessionEvent::Reset)
        );
        switch.mark_sent(AdapterId(1), 1).unwrap();
        assert_eq!(switch.session_count(), 0);
    }

    #[test]
    fn withdrawn_ingress_without_egress_circuit_releases_admission() {
        let mut switch = switch();
        switch
            .open(AdapterId(1), 1, identity(), unit(0x31))
            .unwrap();
        switch.withdraw(AdapterId(1));
        assert_eq!(switch.session_count(), 0);
    }

    #[test]
    fn session_wire_roundtrips_reduced_snf_rh_ru_and_credit() {
        for event in [
            SessionEvent::BindRequest(unit(0x31)),
            SessionEvent::BindResult {
                accepted: true,
                unit: unit(0x31),
            },
            SessionEvent::Information {
                flow: Flow::Expedited,
                unit: unit(0x01),
            },
            SessionEvent::Credit {
                normal: 8,
                expedited: 1,
            },
            SessionEvent::Unbind(unit(0x32)),
        ] {
            let wire = to_session_wire(&event).unwrap();
            assert_eq!(from_session_wire(wire).unwrap(), event);
        }
        assert!(to_session_wire(&SessionEvent::Reset).is_none());
        assert!(from_session_wire(wire::SessionEvent { event: None }).is_err());
    }
}
