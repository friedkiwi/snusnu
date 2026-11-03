//! Carrier handle and delivery leases over the shared SNA session fabric.

use std::collections::HashMap;

use router_core::{
    session::{SessionEvent, SessionIdentity, SessionUnit},
    session_fabric::{
        AdapterId, FabricError, FabricLimits, FabricSessionId, Reachability, SessionFabric,
    },
};

pub(crate) const HPR_ADAPTER: AdapterId = AdapterId(1);
pub(crate) const WS_ADAPTER: AdapterId = AdapterId(2);
pub(crate) const LOCAL_ADAPTER: AdapterId = AdapterId(3);

/// Stable adapter IDs for physical attachments in a process lifetime. The
/// first three IDs remain reserved for the existing single-link runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CarrierKind {
    Llc,
    Mptn,
    HprIp,
    Concentrator,
}

pub(crate) struct AdapterIds {
    next: u64,
    assigned: HashMap<(CarrierKind, String), AdapterId>,
}

impl Default for AdapterIds {
    fn default() -> Self {
        Self {
            next: 4,
            assigned: HashMap::new(),
        }
    }
}

impl AdapterIds {
    pub(crate) fn for_attachment(
        &mut self,
        carrier: CarrierKind,
        attachment_id: &str,
    ) -> Result<AdapterId, SwitchError> {
        if attachment_id.is_empty() {
            return Err(SwitchError::InvalidAdapter);
        }
        let key = (carrier, attachment_id.to_owned());
        if let Some(id) = self.assigned.get(&key) {
            return Ok(*id);
        }
        let following = self
            .next
            .checked_add(1)
            .ok_or(SwitchError::AdapterIdsExhausted)?;
        let id = AdapterId(self.next);
        self.assigned.insert(key, id);
        self.next = following;
        Ok(id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SwitchError {
    Fabric(FabricError),
    DuplicateHandle,
    UnknownHandle,
    WrongEgress,
    InvalidBind,
    DeliveryNotLeased,
    InvalidAdapter,
    AdapterIdsExhausted,
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
        if let Err(error) = self
            .fabric
            .submit(id, ingress, SessionEvent::BindRequest(bind))
        {
            let _ = self.fabric.discard_unopened(id);
            return Err(error.into());
        }
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

    /// Cancel a BIND whose destination has not produced a result yet. No
    /// carrier has been told that the LU session is open, so there is no
    /// peer-side reset to deliver. Both opaque handles are retired together.
    pub(crate) fn discard_unopened(
        &mut self,
        adapter: AdapterId,
        handle: CarrierHandle,
    ) -> Result<(), SwitchError> {
        let id = self.lookup(adapter, handle)?;
        self.fabric.discard_unopened(id)?;
        self.handles.retain(|_, known| *known != id);
        self.leased.retain(|(known, _), _| *known != id);
        Ok(())
    }

    pub(crate) fn has_handle(&self, adapter: AdapterId, handle: CarrierHandle) -> bool {
        self.handles.contains_key(&(adapter, handle))
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

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::session::{Flow, QualifiedName};

    #[test]
    fn adapter_ids_are_stable_per_carrier_and_attachment() {
        let mut ids = AdapterIds::default();
        let llc = ids.for_attachment(CarrierKind::Llc, "guest-a").unwrap();
        assert_eq!(llc, AdapterId(4));
        assert_eq!(ids.for_attachment(CarrierKind::Llc, "guest-a"), Ok(llc));
        assert_ne!(
            ids.for_attachment(CarrierKind::Llc, "guest-b").unwrap(),
            llc
        );
        assert_ne!(
            ids.for_attachment(CarrierKind::Mptn, "guest-a").unwrap(),
            llc
        );
        assert_eq!(
            ids.for_attachment(CarrierKind::HprIp, ""),
            Err(SwitchError::InvalidAdapter)
        );
        assert!(ids.for_attachment(CarrierKind::HprIp, "ee-a").is_ok());
        assert!(ids
            .for_attachment(CarrierKind::Concentrator, "upstream-a")
            .is_ok());
    }

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
    fn abandoned_reverse_bind_releases_both_carrier_handles() {
        let mut switch = switch();
        switch
            .replace_routes(
                HPR_ADAPTER,
                vec![Reachability {
                    lu: Some(q("PEERNET.PINGER")),
                    cp: Some(q("PEERNET.HOST")),
                }],
            )
            .unwrap();
        let reverse = SessionIdentity::new(q("SNUSNU.PING"), q("PEERNET.PINGER"))
            .with_control_points(Some(q("SNUSNU.SVC")), Some(q("PEERNET.HOST")))
            .unwrap();
        let (id, egress) = switch
            .open(WS_ADAPTER, 42, reverse.clone(), unit(0x31))
            .unwrap();
        assert_eq!(egress, HPR_ADAPTER);
        switch.bind_egress(id, HPR_ADAPTER, 42).unwrap();
        switch.discard_unopened(WS_ADAPTER, 42).unwrap();
        assert_eq!(switch.fabric.session_count(), 0);
        assert!(matches!(
            switch.lookup(WS_ADAPTER, 42),
            Err(SwitchError::UnknownHandle)
        ));
        assert!(matches!(
            switch.lookup(HPR_ADAPTER, 42),
            Err(SwitchError::UnknownHandle)
        ));
        assert!(switch.open(WS_ADAPTER, 42, reverse, unit(0x31)).is_ok());
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
    fn overlapping_management_and_application_circuits_retire_independently() {
        let mut switch = switch();
        for handle in [1, 2] {
            let (id, egress) = switch
                .open(AdapterId(1), handle, identity(), unit(0x31))
                .unwrap();
            assert_eq!(egress, AdapterId(2));
            switch.bind_egress(id, egress, handle).unwrap();
            assert!(matches!(
                switch.next_delivery(egress, handle).unwrap(),
                Some(SessionEvent::BindRequest(_))
            ));
            switch.mark_sent(egress, handle).unwrap();
            switch
                .submit(
                    egress,
                    handle,
                    SessionEvent::BindResult {
                        accepted: true,
                        unit: unit(0x31),
                    },
                )
                .unwrap();
            switch.next_delivery(AdapterId(1), handle).unwrap();
            switch.mark_sent(AdapterId(1), handle).unwrap();
        }
        assert_eq!(switch.session_count(), 2);
        switch.submit(AdapterId(2), 1, SessionEvent::Reset).unwrap();
        assert_eq!(
            switch.next_delivery(AdapterId(1), 1).unwrap(),
            Some(SessionEvent::Reset)
        );
        switch.mark_sent(AdapterId(1), 1).unwrap();
        assert_eq!(switch.session_count(), 1);
        assert!(switch.lookup(AdapterId(1), 1).is_err());
        assert!(switch.lookup(AdapterId(1), 2).is_ok());
        switch
            .submit(
                AdapterId(1),
                2,
                SessionEvent::Information {
                    flow: Flow::Normal,
                    unit: unit(0x01),
                },
            )
            .unwrap();
        assert!(matches!(
            switch.next_delivery(AdapterId(2), 2).unwrap(),
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
}
