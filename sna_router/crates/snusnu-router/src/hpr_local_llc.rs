//! Session-level HPR to local native LLC conversion.
//!
//! A V5R4 HPR BIND can be represented as a TCP62 Connect only after the
//! FID5 address is removed. The temporary Connect is an internal request to
//! the existing native PLU initiator; it is never sent on a TCP socket.

use std::{
    fs::File,
    io::{self, Read},
};

use crate::{
    auto_gateway_runtime::virtual_xid,
    mptn_bidirectional_gateway::{fresh_management, pump_virtual},
    routing::RoutePort,
    runtime::{LlcPeer, LlcPort},
    virtual_ws_port::VirtualWsPort,
};
use router_core::{
    native_management::Phase as ResponderPhase,
    native_management_initiator::Phase as ManagementPhase,
    session::{Flow, QualifiedName, SessionEvent, SessionUnit},
};
use transport_ip_sna::{
    anynet::{TcpKind, TcpRecord},
    mptn_compensations::{CompensationSet, TCP62_REQUIRED},
    mptn_connect::{Connect, Direction, OptionalField},
    mptn_ingress::{IngressOffer, IngressPolicy, IngressSession},
    mptn_session::connect_template_for_route,
    mptn_session_unit::{normal_record_to_unit, unit_to_normal_record},
};
use transport_ws::wire;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn validate_lu_cp_pair(
    _source_cp: &QualifiedName,
    target_cp: &QualifiedName,
    _source_lu: &QualifiedName,
    target_lu: &QualifiedName,
) -> io::Result<()> {
    // The adjacent CP belongs to the local network, while the routed source
    // LU may belong to a different network. Only the destination CP and LU
    // must share the local NETID.
    if target_cp.netid != target_lu.netid {
        return Err(invalid("local LLC target CP and LU NETIDs disagree"));
    }
    Ok(())
}

/// TCP62 already carries a full X'83' UNBIND envelope. HPR/IP carries a
/// shorter FID5 form; bind it to this exact user's FQPCID before translating
/// to the native teardown gate's canonical local envelope.
fn local_abort_body(
    unit: &SessionUnit,
    user_fqpcid: &[u8],
    canonical: &[u8],
) -> io::Result<Vec<u8>> {
    if unit.rh() != [0x6b, 0x80, 0] || unit.ru().first() != Some(&0x32) {
        return Err(invalid("local LLC UNBIND has unsupported SNA header"));
    }
    let mut reduced = unit.as_reduced().to_vec();
    reduced[..2].fill(0);
    if unit.ru().get(1..3) == Some(&[0x0f, 0x08][..]) {
        // ReverseUserTeardown still validates the complete extended body.
        return Ok(reduced);
    }
    if unit.ru().get(..6) != Some(&[0x32, 1, 0, 0, 0, 0][..])
        || unit.ru().get(6..) != Some(user_fqpcid)
    {
        return Err(invalid(
            "local LLC HPR UNBIND FQPCID or profile differs from BIND",
        ));
    }
    Ok(canonical.to_vec())
}

/// Convert a complete, validated HPR user BIND to an internal native egress
/// offer. The native V5 profile starts its own FID2 sequence at zero. The
/// caller must retain the original HPR SNF and restore it on BIND response.
pub(crate) fn offer_from_bind(
    bind: &SessionUnit,
    source_lu: &str,
    target_lu: &str,
    correlator: [u8; 8],
) -> io::Result<IngressOffer> {
    if bind.rh() != [0x6b, 0x80, 0] || bind.ru().first() != Some(&0x31) {
        return Err(invalid("local LLC route requires a complete user BIND"));
    }
    let mut reduced = bind.as_reduced().to_vec();
    reduced[..2].fill(0);
    reduced[3] &= !1; // HPR PI belongs to its own adjacent session.
    let mut connect = connect_template_for_route(source_lu, target_lu, correlator)?;
    let bind_option = connect
        .options
        .iter_mut()
        .find(|option| option.kind == 0x0a)
        .ok_or_else(|| invalid("internal Connect lacks BIND option"))?;
    bind_option.value = reduced;
    connect.options.push(OptionalField {
        kind: 0x1a,
        processing: 0,
        value: vec![0x84],
    });
    let bytes = connect.encode()?;
    let available_compensations =
        CompensationSet::from_codes(&TCP62_REQUIRED).map_err(io::Error::other)?;
    let mut ingress = IngressSession::new(IngressPolicy {
        source_lu: source_lu.into(),
        destination_lu: target_lu.into(),
        user_mode: None,
        allow_blank_user_mode: true,
        available_compensations,
        forbidden_fqpcid: None,
    })?;
    Ok(ingress.receive(&bytes)?.clone())
}

#[derive(Clone)]
enum PendingKind {
    Bind(Vec<u8>),
    Record(TcpRecord),
    NativeUnbind(TcpRecord),
    LocalAbort,
}

#[derive(Clone)]
struct PendingEvent {
    event: SessionEvent,
    kind: PendingKind,
}

/// One selected EE-originated LU session to a verified local LLC CP. Native
/// XID/CNOS, user BIND, pacing and close stay with `VirtualWsPort`; the
/// temporary TCP62 records remain entirely inside this process.
pub(crate) struct HprToLlcSession {
    port: VirtualWsPort<LlcPort>,
    bind: SessionUnit,
    offer: Option<IngressOffer>,
    user_fqpcid: Vec<u8>,
    started: bool,
    bound: bool,
    pending: Option<PendingEvent>,
    abort_snf: Option<[u8; 2]>,
    native_abort_snf: Option<[u8; 2]>,
    abort_sequence: u16,
    expedited_ack_pending: bool,
}

/// A private LLC association kept open while HPR RouteSetup waits for live
/// XID and management proof. It becomes the user session's native port after
/// the selected BIND arrives; no second packet socket is opened.
pub(crate) struct HprToLlcProbe {
    port: VirtualWsPort<LlcPort>,
    source_cp: QualifiedName,
    target_cp: QualifiedName,
    last_progress: Option<(bool, Option<ManagementPhase>, Option<ResponderPhase>)>,
}

impl HprToLlcProbe {
    pub(crate) fn new(
        peer: LlcPeer<'_>,
        source_cp: &QualifiedName,
        target_cp: &QualifiedName,
        seed: &[u8],
    ) -> io::Result<Self> {
        Self::new_with_management(peer, source_cp, target_cp, source_cp, seed)
    }

    /// XID names the router's adjacent CP; management negotiates the routed
    /// source CP's session limits with the destination CP. They differ when
    /// the source LU belongs to another NETID.
    pub(crate) fn new_with_management(
        peer: LlcPeer<'_>,
        adjacent_cp: &QualifiedName,
        target_cp: &QualifiedName,
        management_source_cp: &QualifiedName,
        seed: &[u8],
    ) -> io::Result<Self> {
        let cp = wire::SnaName {
            netid: adjacent_cp.netid.clone(),
            name: adjacent_cp.name.clone(),
        };
        let xid = virtual_xid(&cp, seed, None, None, 1)?;
        let mut port = VirtualWsPort::new(
            LlcPort::open(peer)?,
            xid,
            &adjacent_cp.to_string(),
            &target_cp.to_string(),
        )?;
        port.attach_management(fresh_management(
            &management_source_cp.to_string(),
            &target_cp.to_string(),
        )?)?;
        Ok(Self {
            port,
            source_cp: management_source_cp.clone(),
            target_cp: target_cp.clone(),
            last_progress: None,
        })
    }

    pub(crate) fn pump(&mut self) -> io::Result<bool> {
        pump_virtual(&mut self.port)?;
        let ready = self.port.ready();
        let phases = self.port.management_phases();
        let progress = (ready, phases.0, phases.1);
        if self.last_progress != Some(progress) {
            tracing::debug!(source_cp = %self.source_cp, target_cp = %self.target_cp,
                link_ready = ready, management = ?phases.0, reciprocal = ?phases.1,
                "LLC probe state changed");
            self.last_progress = Some(progress);
        }
        Ok(ready && self.port.management_complete())
    }

    pub(crate) fn verified_target_cp(&self) -> Option<&QualifiedName> {
        (self.port.ready() && self.port.management_complete()).then_some(&self.target_cp)
    }

    pub(crate) fn into_session(
        self,
        source_lu: &QualifiedName,
        target_lu: &QualifiedName,
        bind: &SessionUnit,
    ) -> io::Result<HprToLlcSession> {
        if self.verified_target_cp().is_none() {
            return Err(invalid("local LLC route is not verified for this LU pair"));
        }
        validate_lu_cp_pair(&self.source_cp, &self.target_cp, source_lu, target_lu)?;
        HprToLlcSession::with_port(self.port, source_lu, target_lu, bind)
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.port.disconnect()
    }
}

impl HprToLlcSession {
    fn with_port(
        port: VirtualWsPort<LlcPort>,
        source_lu: &QualifiedName,
        target_lu: &QualifiedName,
        bind: &SessionUnit,
    ) -> io::Result<Self> {
        let mut correlator = [0u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut correlator)?;
        correlator[0] |= 1;
        let offer = offer_from_bind(
            bind,
            &source_lu.to_string(),
            &target_lu.to_string(),
            correlator,
        )?;
        Ok(Self {
            port,
            bind: bind.clone(),
            user_fqpcid: offer.fqpcid().to_vec(),
            offer: Some(offer),
            started: false,
            bound: false,
            pending: None,
            abort_snf: None,
            native_abort_snf: None,
            abort_sequence: 1,
            expedited_ack_pending: false,
        })
    }

    /// Accept one leased fabric event. A false result retains the lease at
    /// the caller; no native input is consumed until this returns true.
    pub(crate) fn send(&mut self, event: &SessionEvent) -> io::Result<bool> {
        match event {
            SessionEvent::BindRequest(unit) => {
                if self.started || unit != &self.bind {
                    return Err(invalid("local LLC BIND differs from selected HPR route"));
                }
                if !self.port.management_complete() {
                    return Ok(false);
                }
                let offer = self
                    .offer
                    .take()
                    .ok_or_else(|| invalid("local LLC BIND offer missing"))?;
                let address = self.port.first_user_address()?;
                self.port.begin_user_bind(&offer, address)?;
                self.started = true;
                Ok(true)
            }
            SessionEvent::Information { flow, unit } => {
                if !self.bound {
                    return Ok(false);
                }
                let mut record = unit_to_normal_record(unit)?;
                if *flow == Flow::Expedited {
                    record.bytes[4] = 1;
                    record = TcpRecord::decode(record.bytes)?;
                }
                self.port.submit_tcp_user_record(&record)
            }
            SessionEvent::Credit { .. } => {
                // The native leg grants and consumes its own fixed IPRs. The
                // HPR credit only releases the fabric's adjacent window.
                Ok(self.bound)
            }
            SessionEvent::Unbind(unit) if unit.rh()[0] & 0x80 == 0 => {
                if !self.bound || self.abort_snf.is_some() {
                    return Ok(false);
                }
                let canonical = self.port.canonical_user_abort()?;
                let reduced = local_abort_body(unit, &self.user_fqpcid, &canonical)?;
                if !self.port.submit_udp_abort(self.abort_sequence, &reduced)? {
                    return Ok(false);
                }
                self.abort_snf = Some(unit.snf().try_into().unwrap());
                Ok(true)
            }
            SessionEvent::Unbind(unit) if unit.rh()[0] & 0x80 != 0 => {
                if self.native_abort_snf.as_ref().map(|snf| snf.as_slice()) != Some(unit.snf()) {
                    return Err(invalid("local LLC UNBIND reply has wrong SNF"));
                }
                self.port.complete_udp_abort_response()?;
                self.native_abort_snf = None;
                Ok(true)
            }
            SessionEvent::Reset => {
                self.port.disconnect()?;
                Ok(true)
            }
            _ => Err(invalid("unsupported local LLC session event")),
        }
    }

    /// Peek one native result. The caller submits it to the fabric and then
    /// calls `confirm_polled`; on backpressure the same event is returned.
    pub(crate) fn poll(&mut self) -> io::Result<Option<SessionEvent>> {
        if let Some(pending) = &self.pending {
            return Ok(Some(pending.event.clone()));
        }
        pump_virtual(&mut self.port)?;
        if self.expedited_ack_pending {
            let ack = TcpRecord::decode(vec![0, 0, 0, 5, 3])?;
            if self.port.submit_tcp_user_record(&ack)? {
                self.expedited_ack_pending = false;
            }
        }
        if let Some(bytes) = self.port.tcp_bind_response().map(|bytes| bytes.to_vec()) {
            let response = Connect::decode(&bytes)?;
            let accepted = match response.direction {
                Direction::PositiveResponse => true,
                Direction::NegativeResponse => false,
                Direction::Request => return Err(invalid("local LLC BIND returned a request")),
            };
            let mut reduced = response.connection_data().to_vec();
            if reduced.len() < 5 {
                return Err(invalid("local LLC BIND response is truncated"));
            }
            reduced[..2].copy_from_slice(self.bind.snf());
            let unit = SessionUnit::from_reduced(&reduced).map_err(io::Error::other)?;
            let event = SessionEvent::BindResult { accepted, unit };
            self.pending = Some(PendingEvent {
                event: event.clone(),
                kind: PendingKind::Bind(bytes),
            });
            return Ok(Some(event));
        }
        if let Some(record) = self.port.tcp_user_record().cloned() {
            match record.kind {
                TcpKind::Normal | TcpKind::Expedited => {
                    let mut normalized = record.clone();
                    normalized.bytes[4] = 0;
                    normalized.kind = TcpKind::Normal;
                    let unit = normal_record_to_unit(&normalized)?;
                    let event = SessionEvent::Information {
                        flow: if record.kind == TcpKind::Expedited {
                            Flow::Expedited
                        } else {
                            Flow::Normal
                        },
                        unit,
                    };
                    self.pending = Some(PendingEvent {
                        event: event.clone(),
                        kind: PendingKind::Record(record),
                    });
                    return Ok(Some(event));
                }
                TcpKind::ExpeditedAck => {
                    self.port.mark_tcp_user_record_enqueued(&record)?;
                    self.port.complete_tcp_user_records(1)?;
                }
                _ => return Err(invalid("unsupported native LLC user record")),
            }
        }
        if let Some(record) = self.port.udp_abort_record().cloned() {
            let reduced = record
                .bytes
                .get(5..)
                .ok_or_else(|| invalid("native LLC UNBIND truncated"))?;
            let unit = SessionUnit::from_reduced(reduced).map_err(io::Error::other)?;
            let event = SessionEvent::Unbind(unit.clone());
            self.pending = Some(PendingEvent {
                event: event.clone(),
                kind: PendingKind::NativeUnbind(record),
            });
            return Ok(Some(event));
        }
        if self.port.take_completed_udp_abort() == Some(self.abort_sequence) {
            let snf = self
                .abort_snf
                .take()
                .ok_or_else(|| invalid("unexpected native LLC UNBIND completion"))?;
            let mut reduced = snf.to_vec();
            reduced.extend_from_slice(&[0xeb, 0x80, 0, 0x32]);
            let event = SessionEvent::Unbind(
                SessionUnit::from_reduced(&reduced).map_err(io::Error::other)?,
            );
            self.pending = Some(PendingEvent {
                event: event.clone(),
                kind: PendingKind::LocalAbort,
            });
            return Ok(Some(event));
        }
        Ok(None)
    }

    pub(crate) fn confirm_polled(&mut self) -> io::Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| invalid("no local LLC event to confirm"))?;
        match pending.kind {
            PendingKind::Bind(bytes) => {
                self.port.mark_tcp_bind_response_enqueued(&bytes)?;
                self.bound = matches!(
                    pending.event,
                    SessionEvent::BindResult { accepted: true, .. }
                );
            }
            PendingKind::Record(record) => {
                self.port.mark_tcp_user_record_enqueued(&record)?;
                self.port.complete_tcp_user_records(1)?;
                if record.kind == TcpKind::Expedited {
                    self.expedited_ack_pending = true;
                }
            }
            PendingKind::NativeUnbind(record) => {
                self.port.mark_udp_abort_enqueued(&record)?;
                if let SessionEvent::Unbind(unit) = pending.event {
                    self.native_abort_snf = Some(unit.snf().try_into().unwrap());
                }
            }
            PendingKind::LocalAbort => {
                self.bound = false;
            }
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.port.disconnect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::hpr_fid5::Fid5WholeBiu;
    use transport_ip_sna::{
        mptn_reverse_user_bind::NativeAddress, mptn_reverse_user_teardown::ReverseUserTeardown,
    };

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn captured_v5r4_second_bind_admits_internal_llc_offer() {
        // One complete HPR user BIND, with dynamic fields preserved from a
        // captured V5R4 exchange. The internal Connect resets only the SNF.
        let hex = concat!(
            "5d00000080020800f0f100026b800031001307b0b0513303838c8c8303060200",
            "000000000000944340000be2d6d3d5c5e34be2d5c1c22d000902404040404040",
            "404009030124ebc708ef80000c04e2d6d3d5c5e34be2d5c1c20a1300b024ebc7",
            "08ef8000000be2d5e4e2d5e44bd7c9d5c76014cec370e7b283a2c40be2d6d3d5",
            "c5e34be2d5c1c22c0a01087bc3d6d5d5c5c3e3"
        );
        let message: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect();
        let unit = Fid5WholeBiu::parse_complete(&message)
            .unwrap()
            .session_unit()
            .unwrap();
        assert_eq!(unit.snf(), [0, 0]);
        let offer = offer_from_bind(&unit, "SOLNET.SNAB", "SNUSNU.PING", [1; 8]).unwrap();
        assert_eq!(
            &offer.connect().connection_data()[..5],
            &[0, 0, 0x6b, 0x80, 0]
        );
        let mut invalid = unit.as_reduced().to_vec();
        invalid[5 + 25] = 0x41;
        let invalid = SessionUnit::from_reduced(&invalid).unwrap();
        assert!(offer_from_bind(&invalid, "SOLNET.SNAB", "SNUSNU.PING", [2; 8]).is_err());
        assert!(validate_lu_cp_pair(
            &"OTHER.CP".parse().unwrap(),
            &"SNUSNU.SVC".parse().unwrap(),
            &"SOLNET.SNAB".parse().unwrap(),
            &"SNUSNU.PING".parse().unwrap(),
        )
        .is_ok());
        assert_eq!(
            validate_lu_cp_pair(
                &"OTHER.CP".parse().unwrap(),
                &"SNUSNU.SVC".parse().unwrap(),
                &"SOLNET.SNAB".parse().unwrap(),
                &"OTHER.PING".parse().unwrap(),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn captured_ee_unbind_uses_same_fqpcid_and_prepares_native_teardown() {
        // V5R4 QABOB.SNAB -> SOLNET.SNAA user BIND and subsequent short
        // FID5 UNBIND, captured on sol9 during the EE -> QA -> LLC trial.
        let bind = hex(concat!(
            "5d00000080020300f0f100026b800031001307b0b0513303838c8c83030602000000000000009443",
            "40000ad8c1c2d6c24be2d5c1c22c000902404040404040404009030125f4ebb6af80000b04d8c1c2",
            "d6c24be2d5c1c20a1300b025f4ebb6af8000000be2d6d3d5c5e34be2d5c1c16013e8e772dd240702",
            "7e0ad8c1c2d6c24be2d5c1c22c0a01087bc3d6d5d5c5c3e3",
        ));
        let unbind = hex(concat!(
            "5d00000000000000000000026b80003201000000006013e8e772dd2407027e0ad8c1c2d6c24be2d5",
            "c1c2",
        ));
        let bind = Fid5WholeBiu::parse_complete(&bind)
            .unwrap()
            .session_unit()
            .unwrap();
        let unbind = Fid5WholeBiu::parse_complete(&unbind)
            .unwrap()
            .session_unit()
            .unwrap();
        let offer = offer_from_bind(&bind, "QABOB.SNAB", "SOLNET.SNAA", [1; 8]).unwrap();
        assert_eq!(&unbind.ru()[6..], offer.fqpcid());
        let mut teardown = ReverseUserTeardown::from_user_offer(
            &offer,
            NativeAddress {
                daf: 2,
                oaf: 2,
                odai: true,
            },
        )
        .unwrap();
        let canonical = teardown.canonical_udp_abort().unwrap();
        let reduced = local_abort_body(&unbind, offer.fqpcid(), &canonical).unwrap();
        assert_eq!(reduced, canonical);
        let native = teardown.prepare_udp_abort(&reduced).unwrap();
        assert_eq!(&native[..4], &[0x2f, 0, 2, 2]);
        assert_eq!(&native[4..], reduced);
        let mut wrong = unbind.as_reduced().to_vec();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        let wrong = SessionUnit::from_reduced(&wrong).unwrap();
        assert!(local_abort_body(&wrong, offer.fqpcid(), &canonical).is_err());
        let tcp62 = SessionUnit::from_reduced(&canonical).unwrap();
        assert_eq!(
            local_abort_body(&tcp62, offer.fqpcid(), &canonical).unwrap(),
            canonical
        );
    }
}
