//! Reverse TCP62 user BIND gate for a native FID2 leg.
//!
//! The TCP62 initiator owns the BIND. Its reduced SNF/RH/RU image becomes a
//! native FID2 request only after management and the native link are ready.
//! The TCP62 positive response is withheld until the exact native session
//! returns a correlated positive RSP(BIND). Later FM and teardown traffic
//! belongs to a separate session bridge.

use std::io;

use crate::{
    mptn_bind_negotiation::validate_positive_response,
    mptn_connect::{Connect, Direction},
    mptn_ingress::{IngressKind, IngressOffer},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    NativeBindPrepared,
    AwaitNativeBind,
    TcpResponsePrepared,
    Active,
    Closed,
}

/// FID2 addresses are allocated by the native link owner, not derived from
/// the TCP socket or an untrusted Connect field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAddress {
    pub daf: u8,
    pub oaf: u8,
    pub odai: bool,
}

pub struct ReverseUserBind {
    request: Connect,
    native_request: Vec<u8>,
    native_address: NativeAddress,
    response: Option<Connect>,
    phase: Phase,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn wrong_phase() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "reverse user BIND is in the wrong phase",
    )
}

impl ReverseUserBind {
    /// `offer` must come from IngressSession's complete Connect admission.
    /// The caller must establish native management before calling this method.
    pub fn after_management(offer: &IngressOffer, address: NativeAddress) -> io::Result<Self> {
        if !matches!(offer.kind(), IngressKind::User { .. }) || address.daf == 0 || address.oaf == 0
        {
            return Err(invalid(
                "reverse user BIND needs a user offer and native addresses",
            ));
        }
        let request = offer.connect().clone();
        let reduced = request.connection_data();
        if reduced.len() < 9 || reduced[..5] != [0, 0, 0x6b, 0x80, 0] {
            return Err(invalid("reverse user BIND request image is unsupported"));
        }
        let mut native_request = Vec::with_capacity(reduced.len() + 4);
        native_request.extend_from_slice(&[
            0x2d | (u8::from(address.odai) << 1),
            0,
            address.daf,
            address.oaf,
        ]);
        native_request.extend_from_slice(reduced);
        // V4R4 native p70 and V5R4 TCP62 p8 share their variable LU/FQPCID
        // fields but negotiate different local BIND capabilities and pacing.
        native_request[4 + 3] = 0x85;
        native_request[4 + 5 + 10..4 + 5 + 12].copy_from_slice(&[0xc7, 0xc7]);
        native_request[4 + 5 + 25] = 0x40;
        Ok(Self {
            request,
            native_request,
            native_address: address,
            response: None,
            phase: Phase::NativeBindPrepared,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn native_bind(&self) -> &[u8] {
        &self.native_request
    }

    /// For the exact V4R4 positive BIND profile accepted by this gate, the
    /// initiator's captured send window is three. Keep the local receive
    /// budget at one until a wider V4 response/traffic profile is validated.
    /// These are native hop pacing limits, not TCP62 BIND capability bytes.
    pub fn native_flow_windows(&self) -> Option<(u8, u8)> {
        matches!(self.phase, Phase::TcpResponsePrepared | Phase::Active).then_some((3, 1))
    }

    pub fn mark_native_bind_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::NativeBindPrepared || piu != self.native_request {
            return Err(wrong_phase());
        }
        self.phase = Phase::AwaitNativeBind;
        Ok(())
    }

    /// Accept only the response for this FID2 address pair and FQPCID. A
    /// rejected or malformed native response retires the TCP62 attempt.
    pub fn accept_native_response(&mut self, piu: &[u8]) -> io::Result<&Connect> {
        if self.phase != Phase::AwaitNativeBind {
            return Err(wrong_phase());
        }
        let result = self.check_native_response(piu);
        match result {
            Ok(response) => {
                self.response = Some(response);
                self.phase = Phase::TcpResponsePrepared;
                Ok(self.response.as_ref().unwrap())
            }
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }

    fn check_native_response(&self, piu: &[u8]) -> io::Result<Connect> {
        if piu.len() < 9
            || piu[0] != self.native_request[0]
            || piu[1] != 0
            || piu[2..4] != [self.native_address.oaf, self.native_address.daf]
            || piu[4..9] != [0, 0, 0xeb, 0x80, 0]
        {
            return Err(invalid(
                "native user BIND did not return positive response for this session",
            ));
        }
        let mut native_request = self.native_request[4..].to_vec();
        // The shared validator accepts the canonical native RH 0x84. Live
        // V4R4 uses 0x85; normalize only this copy for correlation.
        native_request[3] &= !1;
        validate_positive_response(&native_request, &piu[4..]).map_err(|_| {
            invalid("native user BIND response failed LU, mode or FQPCID correlation")
        })?;
        let mut tcp_bind_response = piu[4..].to_vec();
        let fixed = &mut tcp_bind_response[5..32];
        if fixed[8..14] != [0, 0x80, 0xc7, 0xc7, 0x80, 0] || fixed[25] != 0x40 {
            return Err(invalid(
                "native user BIND response is not captured V4R4 profile",
            ));
        }
        fixed[8..14].copy_from_slice(&[3, 3, 0x8c, 0x8c, 0x83, 3]);
        fixed[25] = 0;
        validate_positive_response(self.request.connection_data(), &tcp_bind_response)
            .map_err(|_| invalid("converted TCP62 BIND response failed correlation"))?;
        let mut response = self.request.clone();
        response.direction = Direction::PositiveResponse;
        response.processing = 0x8a;
        response
            .options
            .iter_mut()
            .find(|field| field.kind == 0x0a)
            .ok_or_else(|| invalid("TCP62 user Connect lacks BIND option"))?
            .value = tcp_bind_response;
        if let Some(son) = response.options.iter_mut().find(|field| field.kind == 0x18) {
            son.value = vec![0];
        }
        if let Some(keepalive) = response.options.iter_mut().find(|field| field.kind == 0x1a) {
            keepalive.value = vec![0];
        }
        let response = Connect::decode(&response.encode()?)?;
        if !self.request.matches_response(&response) {
            return Err(invalid("TCP62 user Connect response identity changed"));
        }
        Ok(response)
    }

    pub fn mark_tcp_response_enqueued(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.phase != Phase::TcpResponsePrepared
            || self
                .response
                .as_ref()
                .is_none_or(|response| response.encode().ok().as_deref() != Some(bytes))
        {
            return Err(wrong_phase());
        }
        self.phase = Phase::Active;
        Ok(())
    }

    pub fn close(&mut self) {
        self.response = None;
        self.phase = Phase::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mptn_compensations::CompensationSet,
        mptn_connect::{Address, OptionalField, TransportRequirements},
        mptn_ingress::{IngressPolicy, IngressSession},
    };

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    const REQUEST: &str = "00006b800031001307b0b0513303838c8c8303060200000000000000944300000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301238ff2ee2700000c04e2d6d3d5c5e34be2d5c1c10a1300b0238ff2ee270000000be2d6d3d5c5e34be2d5c1c26014cec37477b5dc299a0be2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e3";
    const RESPONSE: &str = "0000eb800031001307b0b0513303038c8c830306020000000000000094430000002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20a1300b0238ff4f5c3000000006014cec37477b5dc299a0be2d6d3d5c5e34be2d5c1c1";
    const V4_RESPONSE: &str = "0000eb800031001307b0b051330080c7c7800006020000000000000094434000002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20a1300b023506a33da800000006014cec37477b5dbed8d0be2d6d3d5c5e34be2d5c1c1";

    fn connect() -> Connect {
        let source = hex("e2d6d3d5c5e34be2d5c1c1");
        let destination = hex("e2d6d3d5c5e34be2d5c1c2");
        Connect {
            direction: Direction::Request,
            processing: 0x0a,
            ttl: 42,
            source: Address { node: source },
            destination: Address { node: destination },
            correlator: vec![0x35; 8],
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
                    value: hex(REQUEST),
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

    fn offer() -> IngressOffer {
        let mut ingress = IngressSession::new(IngressPolicy {
            source_lu: "SOLNET.SNAA".into(),
            destination_lu: "SOLNET.SNAB".into(),
            user_mode: None,
            allow_blank_user_mode: true,
            available_compensations: CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83])
                .unwrap(),
            forbidden_fqpcid: None,
        })
        .unwrap();
        ingress
            .receive(&connect().encode().unwrap())
            .unwrap()
            .clone()
    }

    fn address() -> NativeAddress {
        NativeAddress {
            daf: 2,
            oaf: 1,
            odai: false,
        }
    }

    fn native_response() -> Vec<u8> {
        let mut reduced = hex(RESPONSE);
        reduced[5 + 8..5 + 14].copy_from_slice(&[0, 0x80, 0xc7, 0xc7, 0x80, 0]);
        reduced[5 + 25] = 0x40;
        [vec![0x2d, 0, 1, 2], reduced].concat()
    }

    #[test]
    fn waits_for_correlated_native_bind_before_positive_tcp_connect() {
        let mut bridge = ReverseUserBind::after_management(&offer(), address()).unwrap();
        assert_eq!(bridge.phase(), Phase::NativeBindPrepared);
        assert_eq!(
            &bridge.native_bind()[..9],
            &[0x2d, 0, 2, 1, 0, 0, 0x6b, 0x85, 0]
        );
        assert_eq!(
            &bridge.native_bind()[4 + 5 + 8..4 + 5 + 14],
            &[3, 0x83, 0xc7, 0xc7, 0x83, 3]
        );
        assert_eq!(bridge.native_bind()[4 + 5 + 25], 0x40);
        assert!(bridge.accept_native_response(&native_response()).is_err());
        let request = bridge.native_bind().to_vec();
        bridge.mark_native_bind_enqueued(&request).unwrap();
        let response = bridge
            .accept_native_response(&native_response())
            .unwrap()
            .clone();
        assert_eq!(bridge.native_flow_windows(), Some((3, 1)));
        assert_eq!(bridge.phase(), Phase::TcpResponsePrepared);
        assert_eq!(response.direction, Direction::PositiveResponse);
        assert_eq!(response.connection_data(), hex(RESPONSE));
        assert_eq!(response.options[2].value, [0]);
        assert_eq!(response.options[4].value, [0]);
        bridge
            .mark_tcp_response_enqueued(&response.encode().unwrap())
            .unwrap();
        assert_eq!(bridge.phase(), Phase::Active);
        assert_eq!(bridge.native_flow_windows(), Some((3, 1)));
    }

    #[test]
    fn wrong_native_address_or_fqpcid_retires_attempt() {
        for mutation in [2, 3, 4 + 5 + 27 + 1] {
            let mut bridge = ReverseUserBind::after_management(&offer(), address()).unwrap();
            bridge
                .mark_native_bind_enqueued(&bridge.native_bind().to_vec())
                .unwrap();
            let mut response = native_response();
            response[mutation] ^= 1;
            assert!(bridge.accept_native_response(&response).is_err());
            assert_eq!(bridge.phase(), Phase::Closed);
        }
    }

    #[test]
    fn captured_v4_response_profile_correlates_after_fqpcid_rebinding() {
        let offer = offer();
        let address = NativeAddress {
            daf: 2,
            oaf: 2,
            odai: true,
        };
        let mut bridge = ReverseUserBind::after_management(&offer, address).unwrap();
        assert_eq!(
            &bridge.native_bind()[..9],
            &[0x2f, 0, 2, 2, 0, 0, 0x6b, 0x85, 0]
        );
        let bind = bridge.native_bind().to_vec();
        bridge.mark_native_bind_enqueued(&bind).unwrap();
        let mut response = hex(V4_RESPONSE);
        let pos = response
            .windows(2)
            .position(|part| part == [0x60, 0x14])
            .unwrap();
        response[pos..pos + offer.fqpcid().len()].copy_from_slice(offer.fqpcid());
        let piu = [vec![0x2f, 0, 2, 2], response].concat();
        let tcp = bridge.accept_native_response(&piu).unwrap();
        assert_eq!(tcp.direction, Direction::PositiveResponse);
        assert_eq!(
            tcp.connection_data()[5 + 8..5 + 14],
            [3, 3, 0x8c, 0x8c, 0x83, 3]
        );
    }
}
