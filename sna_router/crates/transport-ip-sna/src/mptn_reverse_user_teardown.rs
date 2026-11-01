//! Strict captured V5R4 TCP62 Abort/UNBIND to native FID2 candidate.
//!
//! A data-bearing Abort is recognized only when its FQPCID and destination
//! name match the admitted user Connect. The native UNBIND request still
//! requires live V4R4 interoperability before a runtime may enable graceful
//! teardown. An empty Abort forces local hard close.

use std::io;

use crate::{
    anynet::{TcpKind, TcpRecord},
    mptn_ingress::{IngressKind, IngressOffer},
    mptn_reverse_user_bind::NativeAddress,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Active,
    NativeUnbindPrepared,
    AwaitNativeResponse,
    Closed,
}

pub enum AbortAction<'a> {
    HardClose,
    NativeUnbind(&'a [u8]),
}

pub struct ReverseUserTeardown {
    fqpcid: Vec<u8>,
    destination: Vec<u8>,
    address: NativeAddress,
    pending: Option<Vec<u8>>,
    phase: Phase,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

impl ReverseUserTeardown {
    pub fn from_user_offer(offer: &IngressOffer, address: NativeAddress) -> io::Result<Self> {
        if !matches!(offer.kind(), IngressKind::User { .. }) || address.daf == 0 || address.oaf == 0
        {
            return Err(invalid("TCP62 teardown requires an admitted user session"));
        }
        Ok(Self {
            fqpcid: offer.fqpcid().to_vec(),
            destination: offer.connect().destination.node.clone(),
            address,
            pending: None,
            phase: Phase::Active,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn accept_abort(&mut self, record: &TcpRecord) -> io::Result<AbortAction<'_>> {
        if self.phase != Phase::Active {
            return Err(invalid("duplicate or retired TCP62 user Abort"));
        }
        let checked = TcpRecord::decode(record.bytes.clone())?;
        if checked.kind != TcpKind::Abort {
            return Err(invalid("expected TCP62 user Abort"));
        }
        if checked.bytes.len() == 5 {
            self.phase = Phase::Closed;
            return Ok(AbortAction::HardClose);
        }
        if let Err(error) = self.check_abort(&checked.bytes[5..]) {
            self.phase = Phase::Closed;
            return Err(error);
        }
        let mut native = Vec::with_capacity(checked.bytes.len() - 1);
        native.extend_from_slice(&[
            0x2d | (u8::from(self.address.odai) << 1),
            0,
            self.address.daf,
            self.address.oaf,
        ]);
        native.extend_from_slice(&checked.bytes[5..]);
        self.pending = Some(native);
        self.phase = Phase::NativeUnbindPrepared;
        Ok(AbortAction::NativeUnbind(self.pending.as_ref().unwrap()))
    }

    fn check_abort(&self, body: &[u8]) -> io::Result<()> {
        const PREFIX: [u8; 11] = [0, 0, 0x6b, 0x80, 0, 0x32, 0x0f, 0x08, 1, 0, 0];
        let tail_start = PREFIX.len() + self.fqpcid.len();
        let tail = body
            .get(tail_start..)
            .ok_or_else(|| invalid("TCP62 user UNBIND is truncated"))?;
        if body.get(..PREFIX.len()) != Some(PREFIX.as_slice())
            || body.get(PREFIX.len()..tail_start) != Some(self.fqpcid.as_slice())
            || self.destination.len() > 17
            || tail.len() != 10 + self.destination.len()
            || tail[..9]
                != [
                    0x35,
                    0x13,
                    0x08,
                    1,
                    0,
                    0,
                    (self.destination.len() + 1) as u8,
                    0,
                    self.destination.len() as u8,
                ]
            || tail[9..9 + self.destination.len()] != self.destination
            || tail[9 + self.destination.len()] != 0
        {
            return Err(invalid(
                "TCP62 user UNBIND profile or FQPCID is unsupported",
            ));
        }
        Ok(())
    }

    pub fn mark_native_unbind_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::NativeUnbindPrepared || self.pending.as_deref() != Some(piu) {
            return Err(invalid("native user UNBIND differs from prepared PIU"));
        }
        self.phase = Phase::AwaitNativeResponse;
        Ok(())
    }

    /// A native peer's minimal positive RSP(UNBIND) retires this session.
    /// The caller still owns LLC completion and TCP close ordering.
    pub fn accept_native_response(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::AwaitNativeResponse
            || piu
                != [
                    0x2d | (u8::from(self.address.odai) << 1),
                    0,
                    self.address.oaf,
                    self.address.daf,
                    0,
                    0,
                    0xeb,
                    0x80,
                    0,
                    0x32,
                ]
        {
            self.phase = Phase::Closed;
            return Err(invalid("native user UNBIND response is unsupported"));
        }
        self.pending = None;
        self.phase = Phase::Closed;
        Ok(())
    }

    pub fn close(&mut self) {
        self.pending = None;
        self.phase = Phase::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mptn_compensations::CompensationSet,
        mptn_ingress::{IngressPolicy, IngressSession},
    };

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // Direct V5R4 A→B captured user Connect and B→A forced-failure Abort.
    const CONNECT: &str = "000000e6800a00e22a0b010ce2d6d3d5c5e34be2d5c1c2010b010ce2d6d3d5c5e34be2d5c1c10109b0239f7a1a3280000f00008005000000760000007620000508000601010a02008d00006b800031001307b0b0513303838c8c8303060200000000000000944300000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301239f773c9a00000c04e2d6d3d5c5e34be2d5c1c10a1300b0239f773c9a0000000be2d6d3d5c5e34be2d5c1c26014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e31800000501190a000a0020010310831a00000584";
    const ABORT: &str = "0000003b1000006b8000320f080100006014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c13513080100000c000be2d6d3d5c5e34be2d5c1c200";

    fn fixture() -> ReverseUserTeardown {
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
        let offer = ingress.receive(&hex(CONNECT)).unwrap();
        ReverseUserTeardown::from_user_offer(
            offer,
            NativeAddress {
                daf: 2,
                oaf: 1,
                odai: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn captured_abort_yields_correlated_native_unbind_candidate() {
        let mut teardown = fixture();
        let record = TcpRecord::decode(hex(ABORT)).unwrap();
        let AbortAction::NativeUnbind(native) = teardown.accept_abort(&record).unwrap() else {
            panic!("expected UNBIND")
        };
        let native = native.to_vec();
        assert_eq!(
            &native[..15],
            &[0x2d, 0, 2, 1, 0, 0, 0x6b, 0x80, 0, 0x32, 0x0f, 0x08, 1, 0, 0]
        );
        assert_eq!(native.len(), 58);
        teardown.mark_native_unbind_enqueued(&native).unwrap();
        teardown
            .accept_native_response(&[0x2d, 0, 1, 2, 0, 0, 0xeb, 0x80, 0, 0x32])
            .unwrap();
        assert_eq!(teardown.phase(), Phase::Closed);
    }

    #[test]
    fn wrong_fqpcid_and_destination_fail_closed() {
        for mutation in [16, 5 + 11 + 22 + 9] {
            let mut teardown = fixture();
            let mut data = hex(ABORT);
            data[mutation] ^= 1;
            assert!(teardown
                .accept_abort(&TcpRecord::decode(data).unwrap())
                .is_err());
            assert_eq!(teardown.phase(), Phase::Closed);
        }
    }

    #[test]
    fn empty_abort_is_hard_close() {
        let mut teardown = fixture();
        let record = TcpRecord::decode(vec![0, 0, 0, 5, 0x10]).unwrap();
        assert!(matches!(
            teardown.accept_abort(&record).unwrap(),
            AbortAction::HardClose
        ));
        assert_eq!(teardown.phase(), Phase::Closed);
    }
}
