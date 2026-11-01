//! Local LLC Type 1 handling for a native, fixed-secondary APPN peer.
//!
//! This adapter works on the LLC PDU returned by `Endpoint::Event::Type1`.
//! The peer's XID3 is parsed into activation state; outgoing identity always
//! comes from the locally configured profile. LLC2 connection and SNA session
//! control are separate stages.

use router_core::{
    llc::SNA_SAP,
    xid3::Xid3,
    xid3_activation::{ActivationError, Phase, SecondaryActivation},
};
use std::io;

const XID: u8 = 0xaf;
const TEST: u8 = 0xe3;
const POLL_FINAL: u8 = 0x10;

pub(crate) struct OutboundType1 {
    pub(crate) pdu: Vec<u8>,
    xid: Option<Xid3>,
}

pub(crate) struct NativeType1 {
    activation: SecondaryActivation,
}

impl NativeType1 {
    pub(crate) fn new(local_xid: Xid3) -> io::Result<Self> {
        Ok(Self {
            activation: SecondaryActivation::new(local_xid).map_err(protocol_error)?,
        })
    }

    pub(crate) fn phase(&self) -> Phase {
        self.activation.phase()
    }

    pub(crate) fn peer_name(&self) -> Option<&str> {
        self.activation.peer_name()
    }

    pub(crate) fn on_pdu(&mut self, pdu: &[u8]) -> io::Result<Option<OutboundType1>> {
        if pdu.len() < 3 || pdu[0] != SNA_SAP || pdu[1] & !1 != SNA_SAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid APPN Type 1 PDU",
            ));
        }
        let control = pdu[2] & !POLL_FINAL;
        let is_response = pdu[1] & 1 != 0;
        let info = &pdu[3..];
        match control {
            TEST if !is_response => Ok(Some(OutboundType1 {
                pdu: [vec![SNA_SAP, SNA_SAP | 1, pdu[2]], info.to_vec()].concat(),
                xid: None,
            })),
            TEST => Ok(None),
            XID if is_response && info.is_empty() => Ok(None),
            XID => {
                let xid = if info.is_empty() {
                    self.activation.on_null_xid()
                } else {
                    self.activation.on_peer_xid(info)
                }
                .map_err(protocol_error)?;
                let mut outgoing = Vec::with_capacity(3 + 255);
                outgoing.extend_from_slice(&[
                    SNA_SAP,
                    SNA_SAP | u8::from(!is_response),
                    XID | (pdu[2] & POLL_FINAL),
                ]);
                outgoing.extend_from_slice(
                    &xid.encode()
                        .map_err(|error| protocol_error(ActivationError::InvalidPeer(error)))?,
                );
                Ok(Some(OutboundType1 {
                    pdu: outgoing,
                    xid: Some(xid),
                }))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported APPN Type 1 control",
            )),
        }
    }

    /// Call only after `Endpoint::send_type1` accepted this PDU. Send failure
    /// leaves XID activation incomplete and prevents an early SABME.
    pub(crate) fn confirm_sent(&mut self, outbound: &OutboundType1) -> io::Result<Phase> {
        if let Some(xid) = &outbound.xid {
            self.activation.confirm_sent(xid).map_err(protocol_error)
        } else {
            Ok(self.phase())
        }
    }
}

fn protocol_error(error: ActivationError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::xid3::{ControlVector, ExchangeState, Role};

    fn xid(name: &str, role: Role, state: ExchangeState) -> Xid3 {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(&[0xff, 0xf1, 0x23, 0x45]);
        fixed[9] = 0x08;
        fixed[19] = 0x40;
        fixed[21..23].copy_from_slice(&1496u16.to_be_bytes());
        fixed[27] = 7;
        let mut xid = Xid3::from_parts(
            fixed,
            vec![ControlVector {
                key: 0x0e,
                data: vec![
                    0xf4, 0xe2, 0xd6, 0xd3, 0xd5, 0xc5, 0xe3, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2,
                ],
            }],
        )
        .unwrap();
        xid.set_cp_name(name).unwrap();
        xid.set_role(role);
        xid.set_exchange_state(state);
        xid
    }

    #[test]
    fn null_and_peer_xid_use_local_identity_then_complete_after_send() {
        let local = xid(
            "SOLNET.ROUTER",
            Role::Secondary,
            ExchangeState::Prenegotiation,
        );
        let mut handler = NativeType1::new(local.clone()).unwrap();
        let pre = handler.on_pdu(&[4, 4, 0xbf]).unwrap().unwrap();
        assert_eq!(&pre.pdu[..3], &[4, 5, 0xbf]);
        assert_eq!(
            Xid3::decode(&pre.pdu[3..]).unwrap().cp_name().unwrap(),
            "SOLNET.ROUTER"
        );
        assert_eq!(handler.confirm_sent(&pre).unwrap(), Phase::Exchanging);

        let mut peer = xid(
            "SOLNET.SNAB",
            Role::Negotiable,
            ExchangeState::Prenegotiation,
        );
        let mut command = vec![4, 4, 0xbf];
        command.extend_from_slice(&peer.encode().unwrap());
        let response = handler.on_pdu(&command).unwrap().unwrap();
        assert_eq!(&response.pdu[..3], &[4, 5, 0xbf]);
        assert_eq!(handler.confirm_sent(&response).unwrap(), Phase::Exchanging);
        peer.set_role(Role::Primary);
        peer.set_exchange_state(ExchangeState::NegotiationProceeding);
        command.truncate(3);
        command.extend_from_slice(&peer.encode().unwrap());
        let response = handler.on_pdu(&command).unwrap().unwrap();
        assert_eq!(handler.phase(), Phase::ReadyForSabme);
        assert_eq!(
            handler.confirm_sent(&response).unwrap(),
            Phase::ReadyForSabme
        );
    }

    #[test]
    fn test_echoes_only_commands_and_does_not_advance_xid() {
        let local = xid(
            "SOLNET.ROUTER",
            Role::Secondary,
            ExchangeState::Prenegotiation,
        );
        let mut handler = NativeType1::new(local).unwrap();
        let response = handler.on_pdu(&[4, 4, 0xf3, 0xaa, 0xbb]).unwrap().unwrap();
        assert_eq!(response.pdu, [4, 5, 0xf3, 0xaa, 0xbb]);
        assert_eq!(handler.confirm_sent(&response).unwrap(), Phase::Exchanging);
        assert!(handler.on_pdu(&[4, 5, 0xf3]).unwrap().is_none());
    }
}
