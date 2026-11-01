//! Lossless part of a native FID2 LU6.2 PIU / TCP62 normal-record conversion.
//!
//! A gateway must first establish and identify an LU6.2 session, carry BIND
//! in MPTN_Connect, synthesize native pacing, filter APPN CP protocols, and
//! handle expedited and segmented traffic. These pure functions only convert
//! a complete, normal-flow, post-BIND PIU within such a session. They reject
//! traffic that needs those other gateway operations.
//!
//! TCP62 draft sections 2.1.1, 3.2, 4.2 and 5.3.2 define the reduced TH and
//! record envelope. IBM SNA Formats GA27-3136 defines the six-byte FID2 TH
//! and RH pacing indicator (byte 1, mask 0x01).

use crate::anynet::{TcpKind, TcpRecord, MAX_RECORD};
use std::io;

const FID2_TH: usize = 6;
const RH: usize = 3;
const MPTN_NORMAL_PREFIX: usize = 4 + 1 + 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSessionAddress {
    pub daf: u8,
    pub oaf: u8,
    pub odai: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct NormalRecord {
    pub bytes: Vec<u8>,
    /// The native peer requested a pacing window. The session gateway must
    /// answer locally after the TCP send queue accepts this record; this bit
    /// must not be forwarded to the TCP62 peer.
    pub native_pacing_requested: bool,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn check_rh(rh: &[u8]) -> io::Result<()> {
    // BIND/UNBIND and other session-control RUs need MPTN Connect/Abort.
    // Network-control and APPN CP flows must not cross the IP boundary.
    if rh[0] & 0x60 == 0x60 || rh[0] & 0x60 == 0x20 {
        return Err(invalid(
            "SNA session/network control requires a gateway handler",
        ));
    }
    // An isolated pacing response/message is consumed on the native leg.
    if rh[0] & 0x80 != 0 && rh[1] & 0x01 != 0 {
        return Err(invalid("native pacing response must be handled locally"));
    }
    Ok(())
}

/// Strip the FID2 transport fields that TCP62 replaces with its TCP session.
/// The caller must already have selected one established LU6.2 session and
/// filtered its APPN control flows.
pub fn native_normal_to_mptn(piu: &[u8]) -> io::Result<NormalRecord> {
    if piu.len() < FID2_TH + RH || piu.len() + 1 > MAX_RECORD {
        return Err(invalid("FID2 normal PIU length outside supported bound"));
    }
    let th0 = piu[0];
    if th0 >> 4 != 2 || th0 & 0x0c != 0x0c || th0 & 1 != 0 || piu[1] != 0 {
        return Err(invalid("only complete normal-flow FID2 PIUs are supported"));
    }
    let rh = &piu[FID2_TH..FID2_TH + RH];
    check_rh(rh)?;
    let pacing_requested = rh[0] & 0x80 == 0 && rh[1] & 0x01 != 0;
    let total = piu.len() - 4 + 5;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&(total as u32).to_be_bytes());
    bytes.push(0x00);
    bytes.extend_from_slice(&piu[4..6]); // SNF is the only TH field on TCP.
    bytes.extend_from_slice(&piu[6..]);
    bytes[8] &= !0x01; // RH pacing indication is hop-local.
    Ok(NormalRecord {
        bytes,
        native_pacing_requested: pacing_requested,
    })
}

/// Rebuild a full FID2 TH for one TCP62 normal record. DAF/OAF/ODAI are
/// session-local values negotiated on the native leg, not fields on TCP62.
/// Native pacing policy is applied later by the session gateway.
pub fn mptn_normal_to_native(
    record: &TcpRecord,
    addr: NativeSessionAddress,
) -> io::Result<Vec<u8>> {
    if record.kind != TcpKind::Normal || record.bytes.len() < MPTN_NORMAL_PREFIX + RH {
        return Err(invalid("TCP62 record is not complete normal data"));
    }
    let rh = &record.bytes[MPTN_NORMAL_PREFIX..MPTN_NORMAL_PREFIX + RH];
    check_rh(rh)?;
    if rh[1] & 0x01 != 0 {
        return Err(invalid("TCP62 peer sent forbidden pacing indication"));
    }
    let mut piu = Vec::with_capacity(record.bytes.len() - 1);
    piu.extend_from_slice(&[0x2c | (u8::from(addr.odai) << 1), 0, addr.daf, addr.oaf]);
    piu.extend_from_slice(&record.bytes[5..]);
    Ok(piu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_normal_piu_to_tcp62_clears_hop_pacing() {
        let piu = [
            0x2c, 0, 0x11, 0x22, 0x12, 0x34, 0x03, 0x01, 0x20, 0xaa, 0xbb,
        ];
        let converted = native_normal_to_mptn(&piu).unwrap();
        assert!(converted.native_pacing_requested);
        assert_eq!(
            converted.bytes,
            [0, 0, 0, 12, 0, 0x12, 0x34, 0x03, 0, 0x20, 0xaa, 0xbb]
        );
    }

    #[test]
    fn tcp62_normal_to_native_uses_native_session_address() {
        let record =
            TcpRecord::decode(vec![0, 0, 0, 12, 0, 0x12, 0x34, 0x03, 0, 0x20, 0xaa, 0xbb]).unwrap();
        assert_eq!(
            mptn_normal_to_native(
                &record,
                NativeSessionAddress {
                    daf: 0x44,
                    oaf: 0x55,
                    odai: true,
                }
            )
            .unwrap(),
            [0x2e, 0, 0x44, 0x55, 0x12, 0x34, 0x03, 0, 0x20, 0xaa, 0xbb]
        );
    }

    #[test]
    fn rejects_flows_requiring_session_or_pacing_handlers() {
        let mut piu = [0x2c, 0, 1, 2, 0, 1, 0x03, 0, 0, 0xaa];
        for first in [0x28, 0x2d, 0x1c] {
            piu[0] = first;
            assert!(native_normal_to_mptn(&piu).is_err());
        }
        piu[0] = 0x2c;
        piu[6] = 0x63; // Session-control BIND-family RU.
        piu[9] = 0x31;
        assert!(native_normal_to_mptn(&piu).is_err());
        piu[6] = 0x83;
        piu[7] = 1; // Native isolated pacing response.
        assert!(native_normal_to_mptn(&piu).is_err());

        let paced = TcpRecord::decode(vec![0, 0, 0, 10, 0, 0, 1, 3, 1, 0]).unwrap();
        assert!(mptn_normal_to_native(
            &paced,
            NativeSessionAddress {
                daf: 1,
                oaf: 2,
                odai: false
            }
        )
        .is_err());
    }
}
