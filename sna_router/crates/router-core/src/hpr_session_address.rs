//! Receive-only FID5 session-address association for one observed BIND.
//!
//! IBM *SNA Formats* GA27-3136-20 pp. 4-15, 6-163–6-165 and 9-5 defines
//! the directional SA assignor bit and the KL-encoded X'62' CV in a positive
//! RSP(BIND). This does not establish RTP, validate a peer, accept a session,
//! or transmit any control. The caller supplies an independently validated
//! RTP connection generation and directional TCIDs for every observation.

use crate::{
    fid2_bind::{BindError, BindIdentity},
    hpr_fid5::Fid5WholeBiu,
    ConnectionGeneration,
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const ADDRESS_BITS: u64 = !(ASSIGNOR | RESERVED);
const MAX_BIND_RESPONSE: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpAssociationScope {
    pub generation: ConnectionGeneration,
    /// TCID of the qualified PLU-originated setup packet carrying BIND.
    pub initial_plu_tcid: u64,
    /// TCID used by subsequent PLU-to-SLU data after CIE exchange.
    pub subsequent_plu_tcid: u64,
    /// TCID used by SLU-to-PLU data.
    pub slu_tcid: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpObservation {
    pub generation: ConnectionGeneration,
    pub tcid: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    PluToSlu,
    SluToPlu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationError {
    StaleGeneration,
    WrongRtpConnection,
    UnexpectedPhase,
    InvalidBind(BindError),
    InvalidRequestAddress,
    InvalidBindResponse,
    WrongBindSequence,
    WrongResponseAddress,
    MissingSessionAddressVector,
    DuplicateSessionAddressVector,
    InvalidSessionAddressVector,
    WrongDataAddress,
    Disconnected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Phase {
    AwaitBind,
    AwaitResponse {
        snf: u16,
        plu_sa: u64,
        identity: BindIdentity,
    },
    Associated {
        plu_sa: u64,
        slu_sa: u64,
        identity: BindIdentity,
    },
    Disconnected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fid5AddressAssociation {
    scope: RtpAssociationScope,
    bind_tcid: u64,
    phase: Phase,
}

impl Fid5AddressAssociation {
    pub fn new(scope: RtpAssociationScope) -> Self {
        Self {
            scope,
            bind_tcid: scope.initial_plu_tcid,
            phase: Phase::AwaitBind,
        }
    }

    /// A fresh LU session can start after RTP setup on the established
    /// PLU-to-SLU TCID. The caller must have validated that this TCID belongs
    /// to the live RTP generation. Each BIND still creates an independent
    /// address association and must carry a new PLU-assigned session address.
    pub fn new_subsequent(scope: RtpAssociationScope) -> Self {
        Self {
            scope,
            bind_tcid: scope.subsequent_plu_tcid,
            phase: Phase::AwaitBind,
        }
    }

    pub fn bind_tcid(&self) -> u64 {
        self.bind_tcid
    }

    fn check(&self, observation: RtpObservation, tcid: u64) -> Result<(), AssociationError> {
        if matches!(self.phase, Phase::Disconnected) {
            return Err(AssociationError::Disconnected);
        }
        if observation.generation != self.scope.generation {
            return Err(AssociationError::StaleGeneration);
        }
        if observation.tcid != tcid {
            return Err(AssociationError::WrongRtpConnection);
        }
        Ok(())
    }

    /// Record a complete LU 6.2 BIND request. The LU pair is retained as
    /// observed; `qualified_identity` stays empty for unqualified names.
    pub fn observe_bind_request(
        &mut self,
        observation: RtpObservation,
        fid5: Fid5WholeBiu<'_>,
    ) -> Result<(), AssociationError> {
        self.check(observation, self.bind_tcid)?;
        if !matches!(self.phase, Phase::AwaitBind) {
            return Err(AssociationError::UnexpectedPhase);
        }
        let identity = fid5
            .classify_bind()
            .map_err(AssociationError::InvalidBind)?
            .ok_or(AssociationError::InvalidBindResponse)?;
        let plu_sa = u64::from_be_bytes(fid5.session_address);
        if plu_sa & (ASSIGNOR | RESERVED) != ASSIGNOR {
            return Err(AssociationError::InvalidRequestAddress);
        }
        self.phase = Phase::AwaitResponse {
            snf: fid5.sequence_number,
            plu_sa: plu_sa & ADDRESS_BITS,
            identity,
        };
        Ok(())
    }

    /// Correlate the positive BIND response and its SLU-assigned CV X'62'.
    /// The variable user-data and URC fields are skipped before parsing KL
    /// vectors; an X'62' byte inside user data is never treated as a vector.
    pub fn observe_bind_response(
        &mut self,
        observation: RtpObservation,
        fid5: Fid5WholeBiu<'_>,
    ) -> Result<(), AssociationError> {
        self.check(observation, self.scope.slu_tcid)?;
        let Phase::AwaitResponse {
            snf,
            plu_sa,
            identity,
        } = &self.phase
        else {
            return Err(AssociationError::UnexpectedPhase);
        };
        if fid5.sequence_number != *snf {
            return Err(AssociationError::WrongBindSequence);
        }
        // RRI=response, category=SC, FI=1, BC/EC=1; RTI=0 is positive.
        if fid5.rh[0] & 0xeb != 0xeb
            || fid5.rh[1] & 0x10 != 0
            || fid5.rh[2] != 0
            || fid5.ru.first() != Some(&0x31)
        {
            return Err(AssociationError::InvalidBindResponse);
        }
        let response_sa = u64::from_be_bytes(fid5.session_address);
        if response_sa & (ASSIGNOR | RESERVED) != 0 || response_sa & ADDRESS_BITS != *plu_sa {
            return Err(AssociationError::WrongResponseAddress);
        }
        let slu_sa = parse_response_cv62(fid5.ru)? & ADDRESS_BITS;
        self.phase = Phase::Associated {
            plu_sa: *plu_sa,
            slu_sa,
            identity: identity.clone(),
        };
        Ok(())
    }

    /// Match a later whole BIU to the established directional SA pair.
    /// This proves only that the observed bytes match this BIND association.
    pub fn observe_data(
        &self,
        direction: Direction,
        observation: RtpObservation,
        fid5: Fid5WholeBiu<'_>,
    ) -> Result<(), AssociationError> {
        let expected_tcid = match direction {
            Direction::PluToSlu => self.scope.subsequent_plu_tcid,
            Direction::SluToPlu => self.scope.slu_tcid,
        };
        self.check(observation, expected_tcid)?;
        let Phase::Associated { plu_sa, slu_sa, .. } = &self.phase else {
            return Err(AssociationError::UnexpectedPhase);
        };
        let expected_sa = match direction {
            Direction::PluToSlu => *slu_sa,
            Direction::SluToPlu => *plu_sa,
        };
        let observed_sa = u64::from_be_bytes(fid5.session_address);
        if observed_sa & (ASSIGNOR | RESERVED) != 0 || observed_sa & ADDRESS_BITS != expected_sa {
            return Err(AssociationError::WrongDataAddress);
        }
        Ok(())
    }

    /// Only fully network-qualified LU pairs can be considered for route
    /// policy. The caller must still reject management modes and apply LU
    /// policy; this does not establish an RTP endpoint or LU session.
    pub fn qualified_identity(&self) -> Option<&BindIdentity> {
        let Phase::Associated { identity, .. } = &self.phase else {
            return None;
        };
        (qualified(&identity.plu) && qualified(&identity.slu)).then_some(identity)
    }

    /// The receiver-assigned SA to use in a positive response to the
    /// outstanding BIND. Its assignor bit must be clear on the wire.
    pub fn bind_response_address(&self) -> Option<[u8; 8]> {
        let Phase::AwaitResponse { plu_sa, .. } = &self.phase else {
            return None;
        };
        Some(plu_sa.to_be_bytes())
    }

    pub fn pending_bind_sequence(&self) -> Option<u16> {
        let Phase::AwaitResponse { snf, .. } = &self.phase else {
            return None;
        };
        Some(*snf)
    }

    /// The receiver-assigned SA for one established directional data flow.
    /// The caller still needs an active RTP connection and matching TCID.
    pub fn data_address(&self, direction: Direction) -> Option<[u8; 8]> {
        let Phase::Associated { plu_sa, slu_sa, .. } = &self.phase else {
            return None;
        };
        Some(match direction {
            Direction::PluToSlu => slu_sa.to_be_bytes(),
            Direction::SluToPlu => plu_sa.to_be_bytes(),
        })
    }

    pub fn disconnect(&mut self) {
        self.phase = Phase::Disconnected;
    }

    /// A strictly newer RTP generation clears all old SAs and identity.
    /// The caller must assign monotonically increasing generations.
    pub fn reset(&mut self, scope: RtpAssociationScope) -> Result<(), AssociationError> {
        if scope.generation.get() <= self.scope.generation.get() {
            return Err(AssociationError::StaleGeneration);
        }
        self.scope = scope;
        self.bind_tcid = scope.initial_plu_tcid;
        self.phase = Phase::AwaitBind;
        Ok(())
    }
}

fn qualified(name: &str) -> bool {
    let mut parts = name.split('.');
    matches!((parts.next(), parts.next(), parts.next()), (Some(net), Some(lu), None) if !net.is_empty() && !lu.is_empty())
}

fn parse_response_cv62(ru: &[u8]) -> Result<u64, AssociationError> {
    // Narrowly support the extended/negotiable no-cryptography form in the
    // successful V5R4 capture. Other legal RSP(BIND) forms are rejected.
    if ru.len() < 31 || ru.len() > MAX_BIND_RESPONSE || ru[0] != 0x31 || ru[26] != 0 || ru[27] != 0
    {
        return Err(AssociationError::InvalidBindResponse);
    }
    let user_end = 29usize
        .checked_add(usize::from(ru[28]))
        .filter(|end| *end < ru.len())
        .ok_or(AssociationError::InvalidBindResponse)?;
    let retired = user_end
        .checked_add(1 + usize::from(ru[user_end]))
        .filter(|end| *end < ru.len())
        .ok_or(AssociationError::InvalidBindResponse)?;
    if ru[retired] != 0 {
        return Err(AssociationError::InvalidBindResponse);
    }
    let mut cursor = retired + 1;
    let mut assigned = None;
    while cursor < ru.len() {
        let header = ru
            .get(cursor..cursor + 2)
            .ok_or(AssociationError::InvalidBindResponse)?;
        let end = cursor
            .checked_add(2 + usize::from(header[1]))
            .filter(|end| *end <= ru.len())
            .ok_or(AssociationError::InvalidBindResponse)?;
        if header[0] == 0x62 {
            if assigned.is_some() {
                return Err(AssociationError::DuplicateSessionAddressVector);
            }
            if header[1] != 8 {
                return Err(AssociationError::InvalidSessionAddressVector);
            }
            let sa = u64::from_be_bytes(ru[cursor + 2..end].try_into().unwrap());
            if sa & (ASSIGNOR | RESERVED) != ASSIGNOR {
                return Err(AssociationError::InvalidSessionAddressVector);
            }
            assigned = Some(sa);
        }
        cursor = end;
    }
    assigned.ok_or(AssociationError::MissingSessionAddressVector)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SA_A: u64 = 0x8000_0000_0000_1111;
    const SA_B: u64 = 0x8000_0000_0000_2222;

    fn scope(generation: u64) -> RtpAssociationScope {
        RtpAssociationScope {
            generation: ConnectionGeneration::new(generation).unwrap(),
            initial_plu_tcid: 0x8015_0000_0000_0040,
            subsequent_plu_tcid: 0x0016_0000_0000_0040,
            slu_tcid: 0x0015_0000_0000_0040,
        }
    }

    fn stamp(scope: RtpAssociationScope, tcid: u64) -> RtpObservation {
        RtpObservation {
            generation: scope.generation,
            tcid,
        }
    }

    fn fid5(sa: u64, snf: u16, rh: [u8; 3], ru: &[u8]) -> Vec<u8> {
        let mut message = vec![0x5d, 0];
        message.extend_from_slice(&snf.to_be_bytes());
        message.extend_from_slice(&sa.to_be_bytes());
        message.extend_from_slice(&rh);
        message.extend_from_slice(ru);
        message
    }

    fn request(qualified_names: bool) -> Vec<u8> {
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        let plu = if qualified_names {
            &[0xd5, 0xc5, 0xe3, 0xc1, 0x4b, 0xd3, 0xe4, 0xc1][..]
        } else {
            &[0xd3, 0xe4, 0xc1][..]
        };
        let slu = if qualified_names {
            &[0xd5, 0xc5, 0xe3, 0xc2, 0x4b, 0xd3, 0xe4, 0xc2][..]
        } else {
            &[0xd3, 0xe4, 0xc2][..]
        };
        ru.push(plu.len() as u8);
        ru.extend_from_slice(plu);
        ru.push(1); // One byte of structured user data, with no mode.
        ru.push(0);
        ru.push(0); // URC length.
        ru.push(slu.len() as u8);
        ru.extend_from_slice(slu);
        fid5(SA_A, 0x8001, [0x6b, 0x80, 0], &ru)
    }

    fn response(cv_area: &[u8]) -> Vec<u8> {
        let mut ru = vec![0; 29];
        ru[0] = 0x31;
        ru[2..4].copy_from_slice(&[0x13, 7]);
        ru[14..16].copy_from_slice(&[6, 2]);
        ru.push(0); // URC length.
        ru.push(0); // Retired byte.
        ru.extend_from_slice(cv_area);
        fid5(SA_A & !ASSIGNOR, 0x8001, [0xeb, 0x80, 0], &ru)
    }

    fn cv62() -> [u8; 10] {
        let mut cv = [0; 10];
        cv[..2].copy_from_slice(&[0x62, 8]);
        cv[2..].copy_from_slice(&SA_B.to_be_bytes());
        cv
    }

    fn parsed(message: &[u8]) -> Fid5WholeBiu<'_> {
        Fid5WholeBiu::parse_complete(message).unwrap()
    }

    #[test]
    fn associates_sanitized_v5r4_bind_and_both_directional_sas() {
        let scope = scope(1);
        let mut tracker = Fid5AddressAssociation::new(scope);
        let bind = request(true);
        tracker
            .observe_bind_request(stamp(scope, scope.initial_plu_tcid), parsed(&bind))
            .unwrap();
        assert!(tracker.qualified_identity().is_none());
        let mut cvs = vec![0x60, 2, 0, 0];
        cvs.extend_from_slice(&cv62());
        let rsp = response(&cvs);
        tracker
            .observe_bind_response(stamp(scope, scope.slu_tcid), parsed(&rsp))
            .unwrap();
        let identity = tracker.qualified_identity().unwrap();
        assert_eq!(identity.plu, "NETA.LUA");
        assert_eq!(identity.slu, "NETB.LUB");
        let a_data = fid5(SA_B & !ASSIGNOR, 2, [0x03, 0x80, 0], &[0]);
        let b_data = fid5(SA_A & !ASSIGNOR, 2, [0x83, 0x80, 0], &[0]);
        tracker
            .observe_data(
                Direction::PluToSlu,
                stamp(scope, scope.subsequent_plu_tcid),
                parsed(&a_data),
            )
            .unwrap();
        tracker
            .observe_data(
                Direction::SluToPlu,
                stamp(scope, scope.slu_tcid),
                parsed(&b_data),
            )
            .unwrap();
        assert_eq!(
            tracker.observe_data(
                Direction::PluToSlu,
                stamp(scope, scope.subsequent_plu_tcid),
                parsed(&b_data)
            ),
            Err(AssociationError::WrongDataAddress)
        );
    }

    #[test]
    fn rejects_malformed_duplicate_or_embedded_fake_cv62() {
        let mut tracker = Fid5AddressAssociation::new(scope(1));
        let s = scope(1);
        tracker
            .observe_bind_request(stamp(s, s.initial_plu_tcid), parsed(&request(true)))
            .unwrap();
        let mut short = cv62();
        short[1] = 7;
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&response(&short))),
            Err(AssociationError::InvalidSessionAddressVector)
        );
        let mut wrong_bit = cv62();
        wrong_bit[2] |= 0x40;
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&response(&wrong_bit))),
            Err(AssociationError::InvalidSessionAddressVector)
        );
        let mut duplicate = cv62().to_vec();
        duplicate.extend_from_slice(&cv62());
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&response(&duplicate))),
            Err(AssociationError::DuplicateSessionAddressVector)
        );
        let mut ru = vec![0; 29];
        ru[0] = 0x31;
        ru[28] = 10;
        ru.extend_from_slice(&cv62()); // Inside user data, not CV area.
        ru.extend_from_slice(&[0, 0]);
        let fake = fid5(SA_A & !ASSIGNOR, 0x8001, [0xeb, 0x80, 0], &ru);
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&fake)),
            Err(AssociationError::MissingSessionAddressVector)
        );
    }

    #[test]
    fn rejects_replay_wrong_scope_and_disconnects_cleanly() {
        let s = scope(1);
        let mut tracker = Fid5AddressAssociation::new(s);
        let bind = request(false);
        assert_eq!(
            tracker.observe_bind_request(stamp(scope(2), s.initial_plu_tcid), parsed(&bind)),
            Err(AssociationError::StaleGeneration)
        );
        assert_eq!(
            tracker.observe_bind_request(stamp(s, s.slu_tcid), parsed(&bind)),
            Err(AssociationError::WrongRtpConnection)
        );
        tracker
            .observe_bind_request(stamp(s, s.initial_plu_tcid), parsed(&bind))
            .unwrap();
        let rsp = response(&cv62());
        let mut wrong_snf = rsp.clone();
        wrong_snf[3] ^= 1;
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&wrong_snf)),
            Err(AssociationError::WrongBindSequence)
        );
        let mut negative = rsp.clone();
        negative[13] |= 0x10;
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&negative)),
            Err(AssociationError::InvalidBindResponse)
        );
        tracker
            .observe_bind_response(stamp(s, s.slu_tcid), parsed(&rsp))
            .unwrap();
        assert!(tracker.qualified_identity().is_none()); // Unqualified LU pair.
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&rsp)),
            Err(AssociationError::UnexpectedPhase)
        );
        tracker.disconnect();
        assert_eq!(
            tracker.observe_bind_response(stamp(s, s.slu_tcid), parsed(&rsp)),
            Err(AssociationError::Disconnected)
        );
        assert_eq!(tracker.reset(s), Err(AssociationError::StaleGeneration));
        let next = scope(2);
        tracker.reset(next).unwrap();
        assert_eq!(tracker.reset(s), Err(AssociationError::StaleGeneration));
        assert_eq!(
            tracker.observe_bind_request(stamp(s, s.initial_plu_tcid), parsed(&bind)),
            Err(AssociationError::StaleGeneration)
        );
        assert!(tracker.qualified_identity().is_none());
    }
}
