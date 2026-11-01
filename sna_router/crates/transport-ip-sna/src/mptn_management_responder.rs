//! Pure responder for the observed V5R4 TCP62 SNASVCMG/CNOS exchange.
//!
//! No socket or router calls live here. A positive management BIND is only
//! constructed after a strict inbound classifier and an explicit declaration
//! that all six TCP62 compensations have working handlers. The caller must
//! mark each output as sent before the next input can advance the exchange.

use std::io;

use router_core::cnos::{CnosGds, Service};

use crate::{
    anynet::{TcpKind, TcpRecord},
    mptn_bind_negotiation::validate_positive_response,
    mptn_compensations::{required_from_connect, CompensationSet},
    mptn_connect::{Connect, Direction},
    mptn_reverse_management::ReverseManagementConnect,
};

const MODE: [u8; 8] = [0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];
const RESPONSE_FIXED: [u8; 27] = [
    0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 7, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0, 0, 0, 0, 0,
    0x94, 0x43, 0, 0,
];
const CNOS_ENVELOPE: [u8; 17] = [
    0, 1, 0x0b, 0x90, 0x20, 12, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1,
];
const CNOS_REPLY: [u8; 5] = [0, 1, 3, 0x90, 1];
const BIS_REQUEST: [u8; 11] = [0, 0, 0, 11, 0, 0, 2, 0x4b, 0x90, 0, 0x70];
const BIS_REPLY: [u8; 11] = [0, 0, 0, 11, 0, 0, 2, 0x4b, 0xb0, 0, 0x70];
const UNBIND_BODY: [u8; 11] = [0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    AwaitConnectSent,
    AwaitCnos,
    AwaitCnosReplySent,
    AwaitBis,
    AwaitBisReplySent,
    AwaitUnbind,
    AwaitCloseSent,
    Ready,
}

pub struct ManagementResponder {
    fqpcid: Vec<u8>,
    connect_response: Vec<u8>,
    cnos_policy: CnosGds,
    pending: Option<Vec<u8>>,
    phase: Phase,
}

/// Handler declarations for optional V5R4 Connect values. Unsupported
/// options are cleared in the positive response per TCP62 §5.3.1.1.3/5.
/// A caller must supply real socket-side handlers before setting either field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V5Options {
    pub son_handler: bool,
    pub keepalive_handler: bool,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn wrong_phase() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TCP62 management responder phase mismatch",
    )
}

fn record(kind: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(5 + body.len());
    bytes.extend_from_slice(&((5 + body.len()) as u32).to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(body);
    TcpRecord::decode(bytes.clone())?;
    Ok(bytes)
}

impl ManagementResponder {
    /// `response_token` is a fresh local X'13' BIND instance, separate from
    /// the peer's X'03' token and FQPCID. Only direct V5R4 no-security,
    /// fixed-pacing and CONFIRM profile is supported.
    pub fn new(
        admitted: &ReverseManagementConnect,
        available: CompensationSet,
        options: V5Options,
        response_token: [u8; 7],
        cnos_mode: &str,
        session_limit: u16,
    ) -> io::Result<Self> {
        let request = admitted.request();
        let required = required_from_connect(request)
            .map_err(|_| invalid("management Connect compensation field invalid"))?;
        if !required.is_complete_tcp62()
            || !required.missing_from(available).is_empty()
            || request.options.len() != 5
            || request
                .options
                .iter()
                .map(|field| field.kind)
                .collect::<Vec<_>>()
                != [5, 10, 0x18, 0x19, 0x1a]
            || request.options[0].value != [1, 1]
            || request.options[2].value != [1]
            || request.options[4].value != [0x84]
            || response_token[0] != 0x23
            || response_token[1..5].iter().all(|byte| *byte == 0)
            || !matches!(response_token[5], 0 | 0x80)
            || response_token[6] != 0
            || !(2..=8).contains(&session_limit)
            || session_limit % 2 != 0
        {
            return Err(invalid(
                "management response capability or token unsupported",
            ));
        }
        let cnos_policy = CnosGds {
            service: Service::Request,
            modifier: 0,
            session_limit,
            source_winners: session_limit / 2,
            target_winners: session_limit / 2,
            mode: cnos_mode.to_owned(),
            mode_field_length: 8,
        };
        cnos_policy
            .encode()
            .map_err(|_| invalid("CNOS policy invalid"))?;

        let destination = &request.destination.node;
        let mut user = vec![0, 9, 2];
        user.extend_from_slice(&MODE);
        user.extend_from_slice(&[2, 3, 2, (destination.len() + 1) as u8, 5]);
        user.extend_from_slice(destination);
        user.extend_from_slice(&[10, 0x13, 0, 0xb0]);
        user.extend_from_slice(&response_token);

        let mut data = vec![0, 0, 0xeb, 0x80, 0];
        data.extend_from_slice(&RESPONSE_FIXED);
        data.extend_from_slice(&[0, user.len() as u8]);
        data.extend_from_slice(&user);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(admitted.fqpcid());
        let mut response = request.clone();
        response.direction = Direction::PositiveResponse;
        response.processing = 0x8a;
        response.options[1].value = data;
        response.options[2].value = vec![u8::from(options.son_handler)];
        response.options[4].value = vec![if options.keepalive_handler { 0x84 } else { 0 }];
        let connect_response = response.encode()?;
        let checked = Connect::decode(&connect_response)?;
        if !request.matches_response(&checked)
            || validate_positive_response(request.connection_data(), checked.connection_data())
                .is_err()
        {
            return Err(invalid("management BIND response correlation failed"));
        }
        Ok(Self {
            fqpcid: admitted.fqpcid().to_vec(),
            connect_response,
            cnos_policy,
            pending: None,
            phase: Phase::AwaitConnectSent,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    pub fn connect_response(&self) -> &[u8] {
        &self.connect_response
    }

    pub fn mark_connect_response_sent(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.phase != Phase::AwaitConnectSent || bytes != self.connect_response {
            return Err(wrong_phase());
        }
        self.phase = Phase::AwaitCnos;
        Ok(())
    }

    pub fn accept_cnos(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AwaitCnos {
            return Err(wrong_phase());
        }
        let checked = TcpRecord::decode(bytes.to_vec())?;
        if checked.kind != TcpKind::Normal || bytes.len() != 47 || bytes[5..22] != CNOS_ENVELOPE {
            return Err(invalid("unsupported management CNOS envelope"));
        }
        let cnos = CnosGds::decode(&bytes[22..]).map_err(|_| invalid("invalid management CNOS"))?;
        if cnos != self.cnos_policy {
            return Err(invalid("management CNOS policy mismatch"));
        }
        let mut accepted = self.cnos_policy.clone();
        accepted.service = Service::AcceptedPending;
        let mut body = CNOS_REPLY.to_vec();
        body.extend_from_slice(
            &accepted
                .encode()
                .map_err(|_| invalid("CNOS reply invalid"))?,
        );
        let reply = record(0, &body)?;
        self.pending = Some(reply.clone());
        self.phase = Phase::AwaitCnosReplySent;
        Ok(reply)
    }

    pub fn mark_cnos_reply_sent(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.mark_pending_sent(bytes, Phase::AwaitCnosReplySent, Phase::AwaitBis)
    }

    pub fn accept_bis(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.phase != Phase::AwaitBis {
            return Err(wrong_phase());
        }
        let checked = TcpRecord::decode(bytes.to_vec())?;
        if checked.kind != TcpKind::Normal || bytes != BIS_REQUEST {
            return Err(invalid("unsupported management BIS"));
        }
        self.pending = Some(BIS_REPLY.to_vec());
        self.phase = Phase::AwaitBisReplySent;
        Ok(BIS_REPLY.to_vec())
    }

    pub fn mark_bis_reply_sent(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.mark_pending_sent(bytes, Phase::AwaitBisReplySent, Phase::AwaitUnbind)
    }

    pub fn accept_unbind(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.phase != Phase::AwaitUnbind {
            return Err(wrong_phase());
        }
        let checked = TcpRecord::decode(bytes.to_vec())?;
        if checked.kind != TcpKind::Abort
            || bytes.len() != 16 + self.fqpcid.len()
            || bytes[5..16] != UNBIND_BODY
            || bytes[16..] != self.fqpcid
        {
            return Err(invalid("management UNBIND is unsupported or stale"));
        }
        self.phase = Phase::AwaitCloseSent;
        Ok(())
    }

    /// The responder may report readiness only after its TCP close has been
    /// handed to the socket owner following the correlated UNBIND.
    pub fn mark_close_sent(&mut self) -> io::Result<()> {
        if self.phase != Phase::AwaitCloseSent {
            return Err(wrong_phase());
        }
        self.phase = Phase::Ready;
        Ok(())
    }

    fn mark_pending_sent(&mut self, bytes: &[u8], expected: Phase, next: Phase) -> io::Result<()> {
        if self.phase != expected || self.pending.as_deref() != Some(bytes) {
            return Err(wrong_phase());
        }
        self.pending = None;
        self.phase = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mptn_management_initiator::ManagementInitiator,
        mptn_reverse_management::classify_reverse_management_connect,
    };

    fn pair() -> (ManagementInitiator, ManagementResponder) {
        let source = vec![
            0xd8, 0xc1, 0xc1, 0xd3, 0xc9, 0xc3, 0xc5, 0x4b, 0xe2, 0xd5, 0xc1, 0xc1,
        ]; // QAALICE.SNAA
        let mut fqpcid = vec![0x60, (9 + source.len()) as u8];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(source.len() as u8);
        fqpcid.extend_from_slice(&source);
        let initiator = ManagementInitiator::new(
            "QAALICE.SNAA",
            "QABOB.SNAB",
            fqpcid,
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let admitted = classify_reverse_management_connect(
            Connect::decode(initiator.connect_request()).unwrap(),
            "QAALICE.SNAA",
            "QABOB.SNAB",
            None,
        )
        .unwrap();
        let responder = ManagementResponder::new(
            &admitted,
            CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).unwrap(),
            V5Options {
                son_handler: true,
                keepalive_handler: true,
            },
            [0x23, 0x33, 0x33, 0x33, 0x33, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        (initiator, responder)
    }

    #[test]
    fn qa_cross_netid_cnos_round_trip_requires_each_handoff() {
        let (mut initiator, mut responder) = pair();
        assert_eq!(responder.phase(), Phase::AwaitConnectSent);
        assert_eq!(responder.connect_response().len(), 189);
        assert!(responder.accept_cnos(&[0, 0, 0, 5, 0]).is_err());
        let positive = responder.connect_response().to_vec();
        responder.mark_connect_response_sent(&positive).unwrap();
        let cnos = initiator.accept_connect_response(&positive).unwrap();
        assert_eq!(cnos.len(), 47);
        let reply = responder.accept_cnos(&cnos).unwrap();
        assert_eq!(reply.len(), 35);
        assert!(responder.accept_bis(&BIS_REQUEST).is_err());
        responder.mark_cnos_reply_sent(&reply).unwrap();
        let bis = initiator.accept_cnos_reply(&reply).unwrap();
        let bis_reply = responder.accept_bis(&bis).unwrap();
        assert_eq!(bis_reply, BIS_REPLY);
        responder.mark_bis_reply_sent(&bis_reply).unwrap();
        let unbind = initiator.accept_bis(&bis_reply).unwrap();
        assert_eq!(unbind.len(), 39);
        assert!(!responder.ready());
        responder.accept_unbind(&unbind).unwrap();
        assert!(!responder.ready());
        responder.mark_close_sent().unwrap();
        assert!(responder.ready());
    }

    #[test]
    fn malformed_cnos_and_stale_unbind_do_not_advance() {
        let (mut initiator, mut responder) = pair();
        let positive = responder.connect_response().to_vec();
        responder.mark_connect_response_sent(&positive).unwrap();
        let cnos = initiator.accept_connect_response(&positive).unwrap();
        let mut wrong_cnos = cnos.clone();
        wrong_cnos[14] ^= 1;
        assert!(responder.accept_cnos(&wrong_cnos).is_err());
        assert_eq!(responder.phase(), Phase::AwaitCnos);
        let reply = responder.accept_cnos(&cnos).unwrap();
        let mut wrong_reply = reply.clone();
        wrong_reply[10] ^= 1;
        assert!(responder.mark_cnos_reply_sent(&wrong_reply).is_err());
        responder.mark_cnos_reply_sent(&reply).unwrap();
        let bis = initiator.accept_cnos_reply(&reply).unwrap();
        let bis_reply = responder.accept_bis(&bis).unwrap();
        responder.mark_bis_reply_sent(&bis_reply).unwrap();
        let mut unbind = initiator.accept_bis(&bis_reply).unwrap();
        *unbind.last_mut().unwrap() ^= 1;
        assert!(responder.accept_unbind(&unbind).is_err());
        assert_eq!(responder.phase(), Phase::AwaitUnbind);
        assert!(responder.mark_close_sent().is_err());
    }

    #[test]
    fn response_requires_actual_compensation_handlers() {
        let (initiator, _) = pair();
        let admitted = classify_reverse_management_connect(
            Connect::decode(initiator.connect_request()).unwrap(),
            "QAALICE.SNAA",
            "QABOB.SNAB",
            None,
        )
        .unwrap();
        let missing_oob = CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20]).unwrap();
        assert!(ManagementResponder::new(
            &admitted,
            missing_oob,
            V5Options {
                son_handler: true,
                keepalive_handler: true
            },
            [0x23, 0x33, 0x33, 0x33, 0x33, 0x80, 0],
            "",
            8,
        )
        .is_err());
        let all = CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).unwrap();
        let cleared = ManagementResponder::new(
            &admitted,
            all,
            V5Options {
                son_handler: false,
                keepalive_handler: false,
            },
            [0x23, 0x33, 0x33, 0x33, 0x33, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let response = Connect::decode(cleared.connect_response()).unwrap();
        assert_eq!(response.options[2].value, [0]);
        assert_eq!(response.options[4].value, [0]);
    }
}
