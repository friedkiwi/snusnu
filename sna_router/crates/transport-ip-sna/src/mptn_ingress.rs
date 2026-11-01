//! Pure admission of an inbound V5R4 TCP62 Connect before any gateway reply.
//!
//! The configured LU pair, not the source IP or a shared NETID, selects the
//! intended SNA route. This state only recognizes captured complete BINDs;
//! it never sends a positive response or forwards application records.

use std::io;

use router_core::fid2_bind::{classify_bind, BindClass};

use crate::{
    anynet::{TcpKind, TcpRecord},
    mptn_compensations::{required_from_connect, CompensationSet},
    mptn_connect::{Connect, Direction},
    mptn_reverse_management::classify_reverse_management_connect,
};

const USER_FIXED: [u8; 27] = [
    0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 3, 0x83, 0x8c, 0x8c, 0x83, 3, 6, 2, 0, 0, 0, 0, 0, 0,
    0, 0x94, 0x43, 0, 0,
];
const CONNECT_TAIL: [u8; 8] = [0x7b, 0xc3, 0xd6, 0xd5, 0xd5, 0xc5, 0xc3, 0xe3];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngressKind {
    Management,
    User { mode: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressOffer {
    connect: Connect,
    kind: IngressKind,
    fqpcid: [u8; 22],
}

impl IngressOffer {
    pub fn connect(&self) -> &Connect {
        &self.connect
    }
    pub fn kind(&self) -> &IngressKind {
        &self.kind
    }
    pub fn fqpcid(&self) -> &[u8; 22] {
        &self.fqpcid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    AwaitConnect,
    PendingConverter,
    Closed,
}

pub struct IngressPolicy {
    /// The remote V5 PLU; may belong to a different NETID than this router.
    pub source_lu: String,
    /// The local or routed destination SLU.
    pub destination_lu: String,
    /// A configured application mode, or an explicitly allowed blank mode.
    pub user_mode: Option<String>,
    pub allow_blank_user_mode: bool,
    /// Actual handlers, never merely the peer's advertised code list.
    pub available_compensations: CompensationSet,
    /// A management FQPCID already active on another leg must not be reused.
    pub forbidden_fqpcid: Option<[u8; 22]>,
}

pub struct IngressSession {
    policy: IngressPolicy,
    source: Vec<u8>,
    destination: Vec<u8>,
    phase: Phase,
    offer: Option<IngressOffer>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn name(value: &str) -> io::Result<Vec<u8>> {
    let (netid, lu) = value
        .split_once('.')
        .ok_or_else(|| invalid("LU must be NETID.LU"))?;
    if netid.is_empty() || lu.is_empty() || netid.len() > 8 || lu.len() > 8 || lu.contains('.') {
        return Err(invalid("invalid network-qualified LU"));
    }
    value
        .bytes()
        .map(|byte| {
            Ok(match byte {
                b'A'..=b'I' => 0xc1 + (byte - b'A'),
                b'J'..=b'R' => 0xd1 + (byte - b'J'),
                b'S'..=b'Z' => 0xe2 + (byte - b'S'),
                b'0'..=b'9' => 0xf0 + (byte - b'0'),
                b'.' => 0x4b,
                _ => return Err(invalid("invalid LU character")),
            })
        })
        .collect()
}

fn user_fqpcid(data: &[u8], source: &[u8], destination: &[u8]) -> io::Result<[u8; 22]> {
    // The direct V5R4 user BIND has 11-byte PLU/SLU, a fixed 45-byte user
    // field, a 22-byte FQPCID, and X'2C' '#CONNECT' trailer. Other shapes
    // need their own verified profile before an ingress session can open.
    if source.len() != 11
        || destination.len() != 11
        || data.len() != 137
        || data[..5] != [0, 0, 0x6b, 0x80, 0]
        || data[5..32] != USER_FIXED
        || data[32] != 11
        || data[33..44] != *source
        || data[44..48] != [45, 0, 9, 2]
        || data[56..59] != [9, 3, 1]
        || data[59] != 0x23
        || data[64..66] != [0, 0]
        || data[66..68] != [12, 4]
        || data[68..79] != *source
        || data[79..83] != [10, 0x13, 0, 0xb0]
        || data[83..90] != data[59..66]
        || data[90..92] != [0, 11]
        || data[92..103] != *destination
        || data[125..129] != [0x2c, 10, 1, 8]
        || data[129..137] != CONNECT_TAIL
    {
        return Err(invalid("unsupported V5R4 user BIND profile"));
    }
    let fqpcid: [u8; 22] = data[103..125].try_into().unwrap();
    if fqpcid[..2] != [0x60, 0x14]
        || fqpcid[2..10].iter().all(|byte| *byte == 0)
        || fqpcid[10] != 11
        || fqpcid[11..] != *source
    {
        return Err(invalid("user BIND FQPCID does not name its source LU"));
    }
    Ok(fqpcid)
}

impl IngressSession {
    pub fn new(policy: IngressPolicy) -> io::Result<Self> {
        let source = name(&policy.source_lu)?;
        let destination = name(&policy.destination_lu)?;
        if source == destination {
            return Err(invalid("ingress source and destination LU must differ"));
        }
        Ok(Self {
            policy,
            source,
            destination,
            phase: Phase::AwaitConnect,
            offer: None,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn offer(&self) -> Option<&IngressOffer> {
        self.offer.as_ref()
    }

    /// Admit exactly one inbound Connect request on this TCP association.
    /// No normal or expedited record is permitted until a separate, fully
    /// implemented converter has negotiated and sent a BIND response.
    pub fn receive(&mut self, bytes: &[u8]) -> io::Result<&IngressOffer> {
        if self.phase != Phase::AwaitConnect {
            self.close();
            return Err(invalid("duplicate or retired inbound TCP62 Connect"));
        }
        let offer = match self.classify(bytes) {
            Ok(offer) => offer,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        self.offer = Some(offer);
        self.phase = Phase::PendingConverter;
        Ok(self.offer.as_ref().unwrap())
    }

    fn classify(&self, bytes: &[u8]) -> io::Result<IngressOffer> {
        let record = TcpRecord::decode(bytes.to_vec())?;
        if record.kind != TcpKind::Connect {
            return Err(invalid("inbound TCP62 session must begin with Connect"));
        }
        let connect = Connect::decode(bytes)?;
        if connect.direction != Direction::Request
            || connect.source.node != self.source
            || connect.destination.node != self.destination
            || connect.correlator.len() != 8
            || connect
                .options
                .iter()
                .map(|option| option.kind)
                .collect::<Vec<_>>()
                != [5, 10, 0x18, 0x19, 0x1a]
            || connect.options[0].value != [1, 1]
            || connect.options[2].value != [1]
            || connect.options[4].value != [0x84]
        {
            return Err(invalid(
                "inbound TCP62 identity or option profile unsupported",
            ));
        }
        let required = required_from_connect(&connect)
            .map_err(|_| invalid("inbound TCP62 required compensation is malformed"))?;
        if !required.is_complete_tcp62()
            || !required
                .missing_from(self.policy.available_compensations)
                .is_empty()
        {
            return Err(invalid("inbound TCP62 compensation handler unavailable"));
        }
        let data = connect.connection_data();
        let mut piu = vec![0x2d, 0, 1, 2]; // synthetic FID2 addresses only
        piu.extend_from_slice(data);
        let bind = classify_bind(&piu)
            .map_err(|_| invalid("inbound TCP62 BIND is invalid"))?
            .ok_or_else(|| invalid("inbound Connect lacks a BIND request"))?;
        if bind.plu != self.policy.source_lu || bind.slu != self.policy.destination_lu {
            return Err(invalid("inbound BIND LU names disagree with Connect"));
        }
        let (kind, fqpcid) = match bind.class {
            BindClass::Management { mode } if mode == "SNASVCMG" => {
                let admitted = classify_reverse_management_connect(
                    connect.clone(),
                    &self.policy.source_lu,
                    &self.policy.destination_lu,
                    self.policy.forbidden_fqpcid.as_ref(),
                )?;
                (IngressKind::Management, *admitted.fqpcid())
            }
            BindClass::Management { .. } => return Err(invalid("unsupported management mode")),
            BindClass::NamedLu62 { mode }
                if self.policy.user_mode.as_deref() == Some(mode.as_str()) =>
            {
                let fqpcid = user_fqpcid(data, &self.source, &self.destination)?;
                (IngressKind::User { mode }, fqpcid)
            }
            BindClass::Undetermined if self.policy.allow_blank_user_mode => {
                let fqpcid = user_fqpcid(data, &self.source, &self.destination)?;
                (
                    IngressKind::User {
                        mode: String::new(),
                    },
                    fqpcid,
                )
            }
            _ => {
                return Err(invalid(
                    "inbound user BIND mode has no explicit route policy",
                ))
            }
        };
        if self.policy.forbidden_fqpcid.as_ref() == Some(&fqpcid) {
            return Err(invalid("inbound BIND reuses active FQPCID"));
        }
        Ok(IngressOffer {
            connect,
            kind,
            fqpcid,
        })
    }

    pub fn close(&mut self) {
        self.offer = None;
        self.phase = Phase::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mptn_connect::{Address, OptionalField, TransportRequirements};

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn request_data() -> Vec<u8> {
        // Sanitized direct V5R4 user BIND. Only the SLU NETID differs from
        // the observed same-NETID pair; no source/transport IP is embedded.
        let mut data = hex(concat!(
            "00006b800031001307b0b0513303838c8c830306020000000000000094430000",
            "0be2d6d3d5c5e34be2d5c1c12d0009024040404040404040",
            "090301231111111100000c04e2d6d3d5c5e34be2d5c1c1",
            "0a1300b023111111110000000be2d6d3d5c5e34be2d5c1c2",
            "601422222222222222220be2d6d3d5c5e34be2d5c1c1",
            "2c0a01087bc3d6d5d5c5c3e3"
        ));
        assert_eq!(data.len(), 137);
        data[92..103].copy_from_slice(&name("OTHNET.SNAB").unwrap());
        data
    }

    fn connect(data: Vec<u8>) -> Connect {
        Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            source: Address {
                node: name("SOLNET.SNAA").unwrap(),
            },
            destination: Address {
                node: name("OTHNET.SNAB").unwrap(),
            },
            correlator: vec![0x11; 8],
            requirements: TransportRequirements {
                max_record: 0x8005,
                max_expedited: 0x76,
                max_termination: 0x76,
            },
            options: vec![
                OptionalField {
                    kind: 5,
                    processing: 8,
                    value: vec![1, 1],
                },
                OptionalField {
                    kind: 10,
                    processing: 2,
                    value: data,
                },
                OptionalField {
                    kind: 0x18,
                    processing: 0,
                    value: vec![1],
                },
                OptionalField {
                    kind: 0x19,
                    processing: 10,
                    value: vec![0, 0x20, 1, 3, 0x10, 0x83],
                },
                OptionalField {
                    kind: 0x1a,
                    processing: 0,
                    value: vec![0x84],
                },
            ],
        }
    }

    fn policy() -> IngressPolicy {
        IngressPolicy {
            source_lu: "SOLNET.SNAA".into(),
            destination_lu: "OTHNET.SNAB".into(),
            user_mode: None,
            allow_blank_user_mode: true,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        }
    }

    #[test]
    fn admits_cross_netid_user_bind_without_opening_application_flow() {
        let mut ingress = IngressSession::new(policy()).unwrap();
        let request = connect(request_data());
        let offer = ingress.receive(&request.encode().unwrap()).unwrap();
        assert_eq!(
            offer.kind(),
            &IngressKind::User {
                mode: String::new()
            }
        );
        assert_eq!(offer.connect().source.node, name("SOLNET.SNAA").unwrap());
        assert_eq!(
            offer.connect().destination.node,
            name("OTHNET.SNAB").unwrap()
        );
        assert_eq!(offer.fqpcid(), &request.connection_data()[103..125]);
        assert_eq!(ingress.phase(), Phase::PendingConverter);
        assert!(ingress.receive(&request.encode().unwrap()).is_err());
        assert_eq!(ingress.phase(), Phase::Closed);
        assert!(ingress.offer().is_none());
        assert!(ingress.receive(&[0, 0, 0, 10, 0, 0, 1, 3, 0, 0]).is_err());
        ingress.close();
        assert!(ingress.offer().is_none());
        assert_eq!(ingress.phase(), Phase::Closed);
    }

    #[test]
    fn rejects_wrong_lu_fqpcid_mode_and_missing_handler() {
        let request = connect(request_data());
        let mut wrong_name = request.clone();
        wrong_name.destination.node = name("SOLNET.SNAB").unwrap();
        let mut ingress = IngressSession::new(policy()).unwrap();
        assert!(ingress.receive(&wrong_name.encode().unwrap()).is_err());
        assert_eq!(ingress.phase(), Phase::Closed);
        assert!(ingress.receive(&request.encode().unwrap()).is_err());

        let mut wrong_bind = request.clone();
        wrong_bind.options[1].value[92] ^= 1;
        assert!(IngressSession::new(policy())
            .unwrap()
            .receive(&wrong_bind.encode().unwrap())
            .is_err());

        let mut wrong_fqpcid = request.clone();
        wrong_fqpcid.options[1].value[114] ^= 1;
        assert!(IngressSession::new(policy())
            .unwrap()
            .receive(&wrong_fqpcid.encode().unwrap())
            .is_err());

        let mut no_blank = policy();
        no_blank.allow_blank_user_mode = false;
        no_blank.user_mode = Some("INTER".into());
        assert!(IngressSession::new(no_blank)
            .unwrap()
            .receive(&request.encode().unwrap())
            .is_err());

        let mut unavailable = policy();
        unavailable.available_compensations =
            CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20]).unwrap();
        assert!(IngressSession::new(unavailable)
            .unwrap()
            .receive(&request.encode().unwrap())
            .is_err());
    }

    #[test]
    fn management_bind_is_typed_and_fqpcid_cannot_alias_user() {
        let mut data = request_data();
        data[5..32].copy_from_slice(&[
            0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 7, 0x87, 0x86, 0x86, 0x87, 7, 6, 2, 0, 0, 0,
            0, 0, 0, 0, 0x94, 0x43, 0, 0,
        ]);
        data[48..56].copy_from_slice(&[0xe2, 0xd5, 0xc1, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7]);
        data[64] = 0x80;
        data[88] = 0x80;
        data[127] = 4;
        let request = connect(data);
        let mut management_only = policy();
        management_only.allow_blank_user_mode = false;
        let mut ingress = IngressSession::new(management_only).unwrap();
        let offer = ingress.receive(&request.encode().unwrap()).unwrap();
        assert_eq!(offer.kind(), &IngressKind::Management);
        let mut duplicate = policy();
        duplicate.forbidden_fqpcid = Some(*offer.fqpcid());
        assert!(IngressSession::new(duplicate)
            .unwrap()
            .receive(&request.encode().unwrap())
            .is_err());
    }
}
