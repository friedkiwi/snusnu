//! Capture-profile native UNBIND to TCP62 Abort candidate.
//!
//! The native peer may initiate teardown. This gate accepts only the
//! FQPCID-bound FID2 UNBIND shape observed in the V4R4 management trace,
//! then builds the corresponding captured V5R4 data-bearing TCP62 Abort.
//! It does not claim every V4R4 user-session UNBIND profile is identical;
//! unrecognized forms require hard close.

use std::io;

use crate::{
    anynet::TcpRecord,
    mptn_ingress::{IngressKind, IngressOffer},
    mptn_reverse_user_bind::NativeAddress,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Active,
    TcpAbortPrepared,
    UdpAbortQueued,
    NativeResponsePrepared,
    Closed,
}

pub struct NativeUserClose {
    fqpcid: Vec<u8>,
    destination: Vec<u8>,
    address: NativeAddress,
    abort: Option<TcpRecord>,
    native_response: Option<Vec<u8>>,
    phase: Phase,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn matches_native_unbind(
    piu: &[u8],
    address: NativeAddress,
    fqpcid: &[u8],
    destination: &[u8],
) -> bool {
    let prefix = [
        0x2d | (u8::from(address.odai) << 1),
        0,
        address.oaf,
        address.daf,
        0,
        0,
        0x6b,
        0x80,
        0,
        0x32,
    ];
    if !piu.starts_with(&prefix) {
        return false;
    }
    let body = &piu[prefix.len()..];
    let short_prefix = [1, 0, 0, 0, 0];
    if body.starts_with(&short_prefix) && body[short_prefix.len()..] == *fqpcid {
        return true;
    }
    // V4R4 can also send the extended X'0f08' image when its local
    // controller is varied off. Its destination length fields count the
    // name itself, unlike the TCP62 Abort image prepared below.
    let extended_prefix = [0x0f, 0x08, 1, 0, 0];
    if destination.len() > 17
        || !body.starts_with(&extended_prefix)
        || body.len() != extended_prefix.len() + fqpcid.len() + 10 + destination.len()
        || body[extended_prefix.len()..extended_prefix.len() + fqpcid.len()] != *fqpcid
    {
        return false;
    }
    let tail = &body[extended_prefix.len() + fqpcid.len()..];
    tail[..9]
        == [
            0x35,
            (destination.len() + 8) as u8,
            0x08,
            1,
            0,
            0,
            destination.len() as u8,
            0,
            destination.len() as u8,
        ]
        && tail[9..9 + destination.len()] == *destination
        && tail[9 + destination.len()] == 0
}

impl NativeUserClose {
    pub fn from_user_offer(offer: &IngressOffer, address: NativeAddress) -> io::Result<Self> {
        if !matches!(offer.kind(), IngressKind::User { .. }) || address.daf == 0 || address.oaf == 0
        {
            return Err(invalid(
                "native user close requires an admitted user session",
            ));
        }
        Ok(Self {
            fqpcid: offer.fqpcid().to_vec(),
            destination: offer.connect().destination.node.clone(),
            address,
            abort: None,
            native_response: None,
            phase: Phase::Active,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn accept_native_unbind(&mut self, piu: &[u8]) -> io::Result<&TcpRecord> {
        if self.phase != Phase::Active
            || !matches_native_unbind(piu, self.address, &self.fqpcid, &self.destination)
        {
            self.close();
            return Err(invalid(
                "native user UNBIND profile or FQPCID is unsupported",
            ));
        }
        let mut body = Vec::with_capacity(21 + self.fqpcid.len() + self.destination.len());
        body.extend_from_slice(&[0, 0, 0x6b, 0x80, 0, 0x32, 0x0f, 0x08, 1, 0, 0]);
        body.extend_from_slice(&self.fqpcid);
        body.extend_from_slice(&[
            0x35,
            0x13,
            0x08,
            1,
            0,
            0,
            (self.destination.len() + 1) as u8,
            0,
            self.destination.len() as u8,
        ]);
        body.extend_from_slice(&self.destination);
        body.push(0);
        let len = 5 + body.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.push(0x10);
        bytes.extend_from_slice(&body);
        self.abort = Some(TcpRecord::decode(bytes)?);
        self.phase = Phase::TcpAbortPrepared;
        Ok(self.abort.as_ref().unwrap())
    }

    /// The TCP62 Abort must be fully written before telling the native peer
    /// its UNBIND succeeded. Merely entering a local socket queue is not enough.
    pub fn mark_tcp_abort_written(&mut self, record: &TcpRecord) -> io::Result<&[u8]> {
        if self.phase != Phase::TcpAbortPrepared || self.abort.as_ref() != Some(record) {
            return Err(invalid(
                "TCP62 Abort differs from prepared native UNBIND conversion",
            ));
        }
        Ok(self.prepare_native_response())
    }

    /// The gateway has accepted the exact reduced Abort image into its
    /// bounded UDP queue. A positive native response still waits for the
    /// correlated X'83' UDP acknowledgement.
    pub fn mark_udp_abort_enqueued(&mut self, record: &TcpRecord) -> io::Result<()> {
        if self.phase != Phase::TcpAbortPrepared || self.abort.as_ref() != Some(record) {
            return Err(invalid(
                "UDP Abort differs from prepared native UNBIND conversion",
            ));
        }
        self.phase = Phase::UdpAbortQueued;
        Ok(())
    }

    pub fn accept_udp_abort_response(&mut self) -> io::Result<&[u8]> {
        if self.phase != Phase::UdpAbortQueued {
            return Err(invalid(
                "native user UNBIND lacks a correlated UDP Abort response",
            ));
        }
        Ok(self.prepare_native_response())
    }

    fn prepare_native_response(&mut self) -> &[u8] {
        self.native_response = Some(vec![
            0x2d | (u8::from(self.address.odai) << 1),
            0,
            self.address.daf,
            self.address.oaf,
            0,
            0,
            0xeb,
            0x80,
            0,
            0x32,
        ]);
        self.phase = Phase::NativeResponsePrepared;
        self.native_response.as_deref().unwrap()
    }

    pub fn mark_native_response_enqueued(&mut self, piu: &[u8]) -> io::Result<()> {
        if self.phase != Phase::NativeResponsePrepared
            || self.native_response.as_deref() != Some(piu)
        {
            return Err(invalid(
                "native user UNBIND response differs from prepared PIU",
            ));
        }
        self.close();
        Ok(())
    }

    pub fn close(&mut self) {
        self.abort = None;
        self.native_response = None;
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

    const CONNECT: &str = "000000e6800a00e22a0b010ce2d6d3d5c5e34be2d5c1c2010b010ce2d6d3d5c5e34be2d5c1c10109b0239f7a1a3280000f00008005000000760000007620000508000601010a02008d00006b800031001307b0b0513303838c8c8303060200000000000000944300000be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301239f773c9a00000c04e2d6d3d5c5e34be2d5c1c10a1300b0239f773c9a0000000be2d6d3d5c5e34be2d5c1c26014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e31800000501190a000a0020010310831a00000584";
    const ABORT: &str = "0000003b1000006b8000320f080100006014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c13513080100000c000be2d6d3d5c5e34be2d5c1c200";

    fn fixture() -> NativeUserClose {
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
        NativeUserClose::from_user_offer(
            offer,
            NativeAddress {
                daf: 2,
                oaf: 1,
                odai: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn native_unbind_emits_captured_v5_abort_only_after_fqpcid_check() {
        let mut close = fixture();
        let fqpcid = hex("6014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c1");
        let native = [
            vec![0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0],
            fqpcid,
        ]
        .concat();
        let record = close.accept_native_unbind(&native).unwrap().clone();
        assert_eq!(record.bytes, hex(ABORT));
        assert!(close.mark_native_response_enqueued(&[0]).is_err());
        let response = close.mark_tcp_abort_written(&record).unwrap().to_vec();
        assert_eq!(response, [0x2f, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x32]);
        close.mark_native_response_enqueued(&response).unwrap();
        assert_eq!(close.phase(), Phase::Closed);
    }

    #[test]
    fn stale_native_unbind_fails_closed() {
        let mut close = fixture();
        let mut native = [
            vec![0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0],
            hex("6014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c1"),
        ]
        .concat();
        native[16] ^= 1;
        assert!(close.accept_native_unbind(&native).is_err());
        assert_eq!(close.phase(), Phase::Closed);
    }

    #[test]
    fn captured_v4_extended_unbind_requires_exact_fqpcid_and_destination() {
        let fqpcid = hex("6013e8e772dd2409213b0ad8c1c2d6c24be2d5c1c2");
        let destination = hex("d8c1c1d3c9c3c54be2d5c1c1");
        let captured = hex("2f00020200006b8000320f080100006013e8e772dd2409213b0ad8c1c2d6c24be2d5c1c23514080100000c000cd8c1c1d3c9c3c54be2d5c1c100");
        let address = NativeAddress {
            daf: 2,
            oaf: 2,
            odai: true,
        };
        assert!(matches_native_unbind(
            &captured,
            address,
            &fqpcid,
            &destination
        ));
        let mut wrong_fqpcid = captured.clone();
        wrong_fqpcid[16] ^= 1;
        assert!(!matches_native_unbind(
            &wrong_fqpcid,
            address,
            &fqpcid,
            &destination
        ));
        let mut wrong_destination = captured.clone();
        wrong_destination[captured.len() - 2] ^= 1;
        assert!(!matches_native_unbind(
            &wrong_destination,
            address,
            &fqpcid,
            &destination
        ));
        let mut wrong_length = captured.clone();
        wrong_length[42] += 1;
        assert!(!matches_native_unbind(
            &wrong_length,
            address,
            &fqpcid,
            &destination
        ));
    }

    #[test]
    fn extended_native_unbind_reaches_correlated_tcp_abort() {
        let mut close = fixture();
        let mut native = hex("2f00010200006b8000320f08010000");
        native.extend_from_slice(&hex("6014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c1"));
        native.extend_from_slice(&hex("3513080100000b000be2d6d3d5c5e34be2d5c1c200"));
        assert!(matches_native_unbind(
            &native,
            close.address,
            &close.fqpcid,
            &close.destination
        ));
        let abort = close.accept_native_unbind(&native).unwrap().clone();
        assert_eq!(abort.bytes, hex(ABORT));
        let response = close.mark_tcp_abort_written(&abort).unwrap().to_vec();
        assert_eq!(response, hex("2f0002010000eb800032"));
        close.mark_native_response_enqueued(&response).unwrap();
        assert_eq!(close.phase(), Phase::Closed);
    }

    #[test]
    fn native_unbind_waits_for_correlated_udp_abort_ack() {
        let mut close = fixture();
        let native = [
            vec![0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0],
            hex("6014cec37477b5dc29a10be2d6d3d5c5e34be2d5c1c1"),
        ]
        .concat();
        let abort = close.accept_native_unbind(&native).unwrap().clone();
        assert!(close.accept_udp_abort_response().is_err());
        close.mark_udp_abort_enqueued(&abort).unwrap();
        assert!(close.mark_tcp_abort_written(&abort).is_err());
        assert!(close.mark_udp_abort_enqueued(&abort).is_err());
        let response = close.accept_udp_abort_response().unwrap().to_vec();
        assert_eq!(response, [0x2f, 0, 2, 1, 0, 0, 0xeb, 0x80, 0, 0x32]);
        assert!(close.accept_udp_abort_response().is_err());
        close.mark_native_response_enqueued(&response).unwrap();
        assert_eq!(close.phase(), Phase::Closed);
    }
}
