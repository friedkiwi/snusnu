//! Bounded, session-local part of an LLC2 LU6.2 to TCP62 gateway.
//!
//! The native APPN/CP link, MPTN transport, expedited traffic, UDP, and
//! teardown still need independent handlers. This state machine never treats
//! a management BIND as an application session and never guesses a blank
//! mode without an explicit policy decision.

use std::io;

use router_core::fid2_bind::{classify_bind, BindClass};

use crate::{
    anynet::{TcpKind, TcpRecord, MAX_RECORD},
    mptn_connect::{Address, Connect, Direction},
    mptn_gateway::{mptn_normal_to_native, native_normal_to_mptn, NativeSessionAddress},
};

const MAX_PENDING: usize = MAX_RECORD * 4;

#[derive(Clone, Debug)]
pub struct BindPolicy {
    pub plu: String,
    pub slu: String,
    /// An explicitly configured application mode. IBM management modes are
    /// rejected even if mistakenly configured here.
    pub mode: Option<String>,
    /// The observed OS/400 user BIND can have a blank mode. Enabling this
    /// requires the operator to bind this LU pair to one known application.
    pub allow_blank_mode: bool,
    pub max_pending_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle,
    Opening,
    Established,
    Closed,
}

enum State {
    Idle,
    Opening {
        request: Connect,
        native: NativeSessionAddress,
    },
    Established {
        native: NativeSessionAddress,
    },
    Closed,
}

pub struct GatewaySession {
    policy: BindPolicy,
    state: State,
    pending_tcp: usize,
    pending_native: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn state_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn encode_lu_name(name: &str) -> io::Result<Address> {
    if name.len() < 3 || name.len() > 17 || name.matches('.').count() != 1 {
        return Err(state_error("invalid network-qualified LU name"));
    }
    let mut parts = name.split('.');
    let netid = parts.next().unwrap_or("");
    let lu = parts.next().unwrap_or("");
    if netid.is_empty() || netid.len() > 8 || lu.is_empty() || lu.len() > 8 {
        return Err(state_error("invalid network-qualified LU name"));
    }
    let mut node = Vec::with_capacity(name.len());
    for byte in name.bytes() {
        node.push(match byte {
            b'A'..=b'I' => 0xc1 + (byte - b'A'),
            b'J'..=b'R' => 0xd1 + (byte - b'J'),
            b'S'..=b'Z' => 0xe2 + (byte - b'S'),
            b'0'..=b'9' => 0xf0 + (byte - b'0'),
            b'.' => 0x4b,
            b'@' => 0x7c,
            b'#' => 0x7b,
            b'$' => 0x5b,
            _ => return Err(state_error("invalid network-qualified LU name")),
        });
    }
    Ok(Address { node })
}

fn reserve(pending: &mut usize, limit: usize, bytes: usize) -> io::Result<()> {
    let next = pending
        .checked_add(bytes)
        .ok_or_else(|| invalid("gateway pending bytes overflow"))?;
    if next > limit {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "gateway delivery credit exhausted",
        ));
    }
    *pending = next;
    Ok(())
}

impl GatewaySession {
    pub fn new(policy: BindPolicy) -> io::Result<Self> {
        encode_lu_name(&policy.plu)?;
        encode_lu_name(&policy.slu)?;
        if let Some(mode) = &policy.mode {
            if mode.is_empty()
                || mode.len() > 8
                || !mode
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                || matches!(mode.as_str(), "SNASVCMG" | "CPSVCMG" | "CPSVCMGR")
            {
                return Err(state_error("invalid or management LU6.2 mode policy"));
            }
        }
        if policy.mode.is_none() && !policy.allow_blank_mode {
            return Err(state_error(
                "LU6.2 gateway requires an explicit mode policy",
            ));
        }
        if !(MAX_RECORD..=MAX_PENDING).contains(&policy.max_pending_bytes) {
            return Err(state_error("invalid gateway pending-byte limit"));
        }
        Ok(Self {
            policy,
            state: State::Idle,
            pending_tcp: 0,
            pending_native: 0,
        })
    }

    pub fn phase(&self) -> Phase {
        match self.state {
            State::Idle => Phase::Idle,
            State::Opening { .. } => Phase::Opening,
            State::Established { .. } => Phase::Established,
            State::Closed => Phase::Closed,
        }
    }

    pub fn pending_bytes(&self) -> (usize, usize) {
        (self.pending_tcp, self.pending_native)
    }

    /// Map one complete native user BIND to a TCP62 Connect request. `template`
    /// supplies negotiated MPTN options and a unique transport correlator;
    /// this method replaces only its Connection Data with reduced TH/RH/RU.
    pub fn begin_native_bind(
        &mut self,
        piu: &[u8],
        mut template: Connect,
    ) -> io::Result<TcpRecord> {
        if !matches!(self.state, State::Idle) {
            return Err(state_error("gateway session already used"));
        }
        let info = classify_bind(piu)
            .map_err(|_| invalid("unsupported native LU6.2 BIND"))?
            .ok_or_else(|| invalid("native PIU is not a BIND"))?;
        if info.plu != self.policy.plu || info.slu != self.policy.slu {
            return Err(invalid("BIND LU pair is not configured"));
        }
        let allowed = match info.class {
            BindClass::Management { .. } => false,
            BindClass::NamedLu62 { mode } => self.policy.mode.as_deref() == Some(mode.as_str()),
            BindClass::Undetermined => self.policy.allow_blank_mode,
        };
        if !allowed {
            return Err(invalid("BIND mode is not authorized for AnyNet"));
        }
        if template.direction != Direction::Request
            || template.source != encode_lu_name(&self.policy.plu)?
            || template.destination != encode_lu_name(&self.policy.slu)?
        {
            return Err(invalid(
                "MPTN Connect addresses or direction do not match BIND",
            ));
        }
        let data = piu
            .get(4..)
            .ok_or_else(|| invalid("truncated native BIND header"))?;
        if data.len() < 6 || data.len() > MAX_RECORD - 32 {
            return Err(invalid("native BIND image outside TCP62 bound"));
        }
        let option = template
            .options
            .iter_mut()
            .find(|option| option.kind == 0x0a)
            .ok_or_else(|| invalid("MPTN Connect has no BIND option"))?;
        option.value = data.to_vec();
        // The native pacing indication is hop-local to the LLC2 side.
        option.value[3] &= !0x01;
        let bytes = template.encode()?;
        let record = TcpRecord::decode(bytes)?;
        let native = NativeSessionAddress {
            daf: info.daf,
            oaf: info.oaf,
            odai: piu[0] & 0x02 != 0,
        };
        self.state = State::Opening {
            request: template,
            native,
        };
        Ok(record)
    }

    /// Translate positive RSP(BIND) inside TCP62 Connect into a native FID2
    /// session-control response. A negative response retires this session.
    pub fn receive_connect_response(&mut self, record: &TcpRecord) -> io::Result<Vec<u8>> {
        let State::Opening { request, native } = &self.state else {
            return Err(state_error("gateway is not awaiting MPTN Connect"));
        };
        if record.kind != TcpKind::Connect {
            return Err(invalid("expected MPTN Connect response"));
        }
        let response = Connect::decode(&record.bytes)?;
        if !request.matches_response(&response) {
            return Err(invalid(
                "MPTN Connect response correlator or LU pair mismatch",
            ));
        }
        if response.direction == Direction::NegativeResponse {
            self.state = State::Closed;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "MPTN peer rejected BIND",
            ));
        }
        let data = response.connection_data();
        if data.len() < 6
            || data[2] & 0xe0 != 0xe0
            || data[5] != 0x31
            || data.len() + 4 > MAX_RECORD
        {
            return Err(invalid("MPTN Connect lacks supported RSP(BIND)"));
        }
        let mut piu = Vec::with_capacity(data.len() + 4);
        piu.extend_from_slice(&[
            0x2d | (u8::from(native.odai) << 1),
            0,
            native.oaf,
            native.daf,
        ]);
        piu.extend_from_slice(data);
        let native = *native;
        self.state = State::Established { native };
        Ok(piu)
    }

    /// Reserve TCP output capacity and translate complete post-BIND data.
    /// Call `complete_tcp_delivery` only after the transport has written bytes.
    pub fn native_normal(&mut self, piu: &[u8]) -> io::Result<TcpRecord> {
        let State::Established { native } = self.state else {
            return Err(state_error("gateway session not established"));
        };
        if piu.get(2..4) != Some(&[native.daf, native.oaf][..])
            || piu
                .first()
                .is_none_or(|first| first & 0x02 != u8::from(native.odai) << 1)
        {
            return Err(invalid("native PIU session address mismatch"));
        }
        let translated = native_normal_to_mptn(piu)?;
        if translated.native_pacing_requested {
            return Err(invalid("native pacing response handler is not installed"));
        }
        let record = TcpRecord::decode(translated.bytes)?;
        reserve(
            &mut self.pending_tcp,
            self.policy.max_pending_bytes,
            record.bytes.len(),
        )?;
        Ok(record)
    }

    /// Reserve native output capacity and restore the local FID2 address.
    /// The LLC endpoint must report delivery before credit is released.
    pub fn mptn_normal(&mut self, record: &TcpRecord) -> io::Result<Vec<u8>> {
        let State::Established { native } = self.state else {
            return Err(state_error("gateway session not established"));
        };
        let reversed = NativeSessionAddress {
            daf: native.oaf,
            oaf: native.daf,
            odai: native.odai,
        };
        let checked = TcpRecord::decode(record.bytes.clone())?;
        let piu = mptn_normal_to_native(&checked, reversed)?;
        reserve(
            &mut self.pending_native,
            self.policy.max_pending_bytes,
            piu.len(),
        )?;
        Ok(piu)
    }

    pub fn complete_tcp_delivery(&mut self, bytes: usize) -> io::Result<()> {
        if bytes > self.pending_tcp {
            return Err(state_error("TCP delivery exceeds reserved credit"));
        }
        self.pending_tcp -= bytes;
        Ok(())
    }

    pub fn complete_native_delivery(&mut self, bytes: usize) -> io::Result<()> {
        if bytes > self.pending_native {
            return Err(state_error("native delivery exceeds reserved credit"));
        }
        self.pending_native -= bytes;
        Ok(())
    }

    pub fn close(&mut self) {
        self.state = State::Closed;
        self.pending_tcp = 0;
        self.pending_native = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{OptionalField, TransportRequirements};

    fn test_policy() -> BindPolicy {
        BindPolicy {
            plu: "SOLNET.SNAA".into(),
            slu: "SOLNET.SNAB".into(),
            mode: None,
            allow_blank_mode: true,
            max_pending_bytes: MAX_RECORD,
        }
    }

    fn native_bind(mode: &[u8]) -> Vec<u8> {
        let mut piu = vec![0x2d, 0, 1, 2, 0, 0, 0x6b, 0x85, 0];
        let mut ru = vec![0; 27];
        ru[..4].copy_from_slice(&[0x31, 0, 0x13, 7]);
        ru[14] = 6;
        ru[15] = 2;
        let plu = encode_lu_name("SOLNET.SNAA").unwrap().node;
        ru.push(plu.len() as u8);
        ru.extend(plu);
        ru.push((1 + mode.len()) as u8);
        ru.push(0);
        ru.extend_from_slice(mode);
        let slu = encode_lu_name("SOLNET.SNAB").unwrap().node;
        ru.push(0); // No URC.
        ru.push(slu.len() as u8);
        ru.extend(slu);
        piu.extend(ru);
        piu
    }

    fn request_template() -> Connect {
        Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 8,
            source: encode_lu_name("SOLNET.SNAA").unwrap(),
            destination: encode_lu_name("SOLNET.SNAB").unwrap(),
            correlator: vec![0x12, 0x34],
            requirements: TransportRequirements {
                max_record: 4096,
                max_expedited: 256,
                max_termination: 256,
            },
            options: vec![OptionalField {
                kind: 0x0a,
                processing: 0x02,
                value: vec![0x31],
            }],
        }
    }

    fn response_for(request: &Connect) -> TcpRecord {
        let mut response = request.clone();
        response.direction = Direction::PositiveResponse;
        response.processing = 0x8a;
        response
            .options
            .iter_mut()
            .find(|option| option.kind == 0x0a)
            .unwrap()
            .value = vec![0, 0, 0xeb, 0x80, 0, 0x31, 0];
        TcpRecord::decode(response.encode().unwrap()).unwrap()
    }

    #[test]
    fn bind_opens_then_normal_records_use_native_session_addresses() {
        let mut session = GatewaySession::new(test_policy()).unwrap();
        let bind = native_bind(&[1, 2]); // Blank mode as observed on user BIND.
        let request = session
            .begin_native_bind(&bind, request_template())
            .unwrap();
        assert_eq!(session.phase(), Phase::Opening);
        let decoded = Connect::decode(&request.bytes).unwrap();
        assert_eq!(&decoded.connection_data()[..5], &[0, 0, 0x6b, 0x84, 0]);
        let response = response_for(&decoded);
        let native_response = session.receive_connect_response(&response).unwrap();
        assert_eq!(
            &native_response[..10],
            &[0x2d, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x31]
        );
        assert_eq!(session.phase(), Phase::Established);

        let native = [0x2c, 0, 1, 2, 0, 1, 0x03, 0, 0, 0xaa];
        let record = session.native_normal(&native).unwrap();
        assert_eq!(record.kind, TcpKind::Normal);
        assert_eq!(session.pending_bytes(), (record.bytes.len(), 0));
        session.complete_tcp_delivery(record.bytes.len()).unwrap();
        assert_eq!(session.pending_bytes(), (0, 0));
        let reverse = TcpRecord::decode(vec![0, 0, 0, 10, 0, 0, 1, 3, 0, 0]).unwrap();
        let native_reverse = session.mptn_normal(&reverse).unwrap();
        assert_eq!(&native_reverse[..6], &[0x2c, 0, 2, 1, 0, 1]);
        assert_eq!(session.pending_bytes(), (0, native_reverse.len()));
        session
            .complete_native_delivery(native_reverse.len())
            .unwrap();
        assert_eq!(session.pending_bytes(), (0, 0));
    }

    #[test]
    fn management_and_unconfigured_modes_cannot_open_gateway() {
        let mut session = GatewaySession::new(test_policy()).unwrap();
        let management = native_bind(&[9, 2, 0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]);
        assert!(session
            .begin_native_bind(&management, request_template())
            .is_err());
        assert_eq!(session.phase(), Phase::Idle);
        let named = native_bind(&[8, 2, 0xc1, 0xd7, 0xd7, 0xe3, 0xc5, 0xe2, 0xe3]);
        assert!(session
            .begin_native_bind(&named, request_template())
            .is_err());
        let mut strict = test_policy();
        strict.allow_blank_mode = false;
        strict.mode = Some("APPTEST".into());
        let mut session = GatewaySession::new(strict).unwrap();
        assert!(session
            .begin_native_bind(&named, request_template())
            .is_ok());
    }

    #[test]
    fn stale_or_negative_connect_response_does_not_establish_session() {
        let mut session = GatewaySession::new(test_policy()).unwrap();
        let request = session
            .begin_native_bind(&native_bind(&[1, 2]), request_template())
            .unwrap();
        let decoded = Connect::decode(&request.bytes).unwrap();
        let mut stale = decoded.clone();
        stale.direction = Direction::PositiveResponse;
        stale.processing = 0x8a;
        stale.correlator[0] ^= 1;
        stale.options[0].value = vec![0, 0, 0xeb, 0x80, 0, 0x31, 0];
        let stale = TcpRecord::decode(stale.encode().unwrap()).unwrap();
        assert!(session.receive_connect_response(&stale).is_err());
        assert_eq!(session.phase(), Phase::Opening);
        let mut negative = decoded.clone();
        negative.direction = Direction::NegativeResponse;
        negative.processing = 0xca;
        negative.options[0].value = vec![0, 0, 0xeb, 0x80, 0, 0x31, 0];
        let record = TcpRecord::decode(negative.encode().unwrap()).unwrap();
        assert!(session.receive_connect_response(&record).is_err());
        assert_eq!(session.phase(), Phase::Closed);
    }

    #[test]
    fn credit_and_unsupported_record_types_are_enforced() {
        let mut session = GatewaySession::new(test_policy()).unwrap();
        let request = session
            .begin_native_bind(&native_bind(&[1, 2]), request_template())
            .unwrap();
        let decoded = Connect::decode(&request.bytes).unwrap();
        session
            .receive_connect_response(&response_for(&decoded))
            .unwrap();
        let native = [0x2c, 0, 1, 2, 0, 1, 0x03, 0, 0, 0xaa];
        // No delivery notifications: bounded reservations eventually stop ingress.
        let count = MAX_RECORD / 11;
        for _ in 0..count {
            session.native_normal(&native).unwrap();
        }
        assert_eq!(
            session.native_normal(&native).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(session.complete_tcp_delivery(MAX_RECORD + 1).is_err());
        let expedited = TcpRecord::decode(vec![0, 0, 0, 6, 1, 0xaa]).unwrap();
        assert!(session.mptn_normal(&expedited).is_err());
    }
}
