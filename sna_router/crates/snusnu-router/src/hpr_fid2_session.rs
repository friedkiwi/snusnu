//! One validated native LLC user session at the carrier-neutral boundary.
//!
//! `NativePeerPort` owns XID, management and the exact V4R4 positive BIND
//! response. This codec owns only the selected FID2 address pair, complete
//! user PIUs and hop-local fixed pacing. Callers commit a preview only after
//! the destination queue accepts its event or PIU.

use std::io;

use router_core::{
    fid2_bind::{classify_bind, BindClass},
    fixed_pacing::{is_canonical_ipr, FixedPacing, PacingError, IPR_RH},
    session::{Flow, QualifiedName, SessionEvent, SessionIdentity, SessionUnit},
};
use transport_ip_sna::mptn_bind_negotiation::{request_fqpcid, validate_positive_response};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    AwaitBindResult,
    Open,
    AwaitUnbindResult,
    Closed,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeFid2Session {
    daf: u8,
    oaf: u8,
    odai: bool,
    bind_snf: [u8; 2],
    bind_request: SessionUnit,
    phase: Phase,
    pacing: Option<FixedPacing>,
    pending_native_grant: Option<[u8; 2]>,
    pending_unbind_snf: Option<[u8; 2]>,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn pacing_error(error: PacingError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("native pacing: {error:?}"),
    )
}

fn unit(bytes: &[u8]) -> io::Result<SessionUnit> {
    SessionUnit::from_reduced(bytes).map_err(io::Error::other)
}

// A V4R4 user session sends BIS while ending an LU 6.2 session. It is a
// normal-flow DFC request, so it uses the same local pacing as user data.
// The PI bit is hop-local; only this captured DFC form crosses the SNA bus.
fn is_user_bis(rh: &[u8], ru: &[u8]) -> bool {
    matches!(rh, [0x4b, 0x90 | 0x91 | 0xb0 | 0xb1, 0]) && ru == [0x70]
}

fn qualified_lu(name: &str, cp: Option<&QualifiedName>) -> io::Result<QualifiedName> {
    if name.contains('.') {
        return name.parse().map_err(io::Error::other);
    }
    let cp = cp.ok_or_else(|| invalid("unqualified LU has no verified CP NETID"))?;
    QualifiedName::new(&cp.netid, name).map_err(io::Error::other)
}

impl NativeFid2Session {
    pub(crate) fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }
    /// Prepare a normal user UNBIND after the fabric circuit disappears.
    /// The FQPCID comes from the already validated BIND; commit the returned
    /// candidate only after the native LLC queue accepts its PIU.
    pub(crate) fn preview_local_unbind(&self) -> io::Result<(Self, Vec<u8>)> {
        if self.phase != Phase::Open {
            return Err(invalid("native user session is not open for local UNBIND"));
        }
        let fqpcid = request_fqpcid(self.bind_request.as_reduced()).map_err(io::Error::other)?;
        let mut reduced = vec![0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0];
        reduced.extend_from_slice(fqpcid);
        let unit = unit(&reduced)?;
        let (candidate, piu) = self.preview_event(&SessionEvent::Unbind(unit), None)?;
        Ok((
            candidate,
            piu.ok_or_else(|| invalid("local user UNBIND has no PIU"))?,
        ))
    }

    /// Consume the native converter's already validated user BIND. The CP
    /// must have been observed on this same LLC association's XID3 exchange.
    pub(crate) fn from_user_bind(
        piu: &[u8],
        verified_peer_cp: &QualifiedName,
        target_cp: Option<QualifiedName>,
    ) -> io::Result<(Self, SessionIdentity, SessionEvent)> {
        let info = classify_bind(piu)
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("native user PIU is not a BIND"))?;
        if matches!(info.class, BindClass::Management { .. })
            || info.daf == 0
            || info.oaf == 0
            || piu.len() < 4 + 5 + 27
            || piu[0] & 0xfc != 0x2c
            || piu[1] != 0
            || !matches!(&piu[6..9], [0x6b, 0x85, 0] | [0x6b, 0x80, 0])
        {
            return Err(invalid("unsupported native user BIND profile"));
        }
        let source_lu = qualified_lu(&info.plu, Some(verified_peer_cp))?;
        let target_lu = qualified_lu(&info.slu, target_cp.as_ref())?;
        let identity = SessionIdentity::new(source_lu, target_lu)
            .with_control_points(Some(verified_peer_cp.clone()), target_cp)
            .map_err(io::Error::other)?;
        let mut reduced = piu[4..].to_vec();
        let fixed = &mut reduced[5..32];
        if fixed[8..14] != [3, 0x83, 0xc7, 0xc7, 0x83, 3] || fixed[25] != 0x40 {
            return Err(invalid("native BIND fixed profile is unsupported"));
        }
        // The V4R4 LLC hop's pacing/profile markers are replaced with the
        // V5R4 HPR profile; all LU names, mode and FQPCID stay unchanged.
        fixed[10..12].copy_from_slice(&[0x8c, 0x8c]);
        fixed[25] = 0;
        reduced[3] = 0x80;
        let bind_request = unit(&reduced)?;
        let event = SessionEvent::BindRequest(bind_request.clone());
        Ok((
            Self {
                daf: info.daf,
                oaf: info.oaf,
                odai: piu[0] & 2 != 0,
                bind_snf: [piu[4], piu[5]],
                bind_request,
                phase: Phase::AwaitBindResult,
                pacing: None,
                pending_native_grant: None,
                pending_unbind_snf: None,
            },
            identity,
            event,
        ))
    }

    /// Translate a native PIU without changing committed state. An isolated
    /// IPR is consumed by this hop and returns no fabric event.
    pub(crate) fn preview_native(&self, piu: &[u8]) -> io::Result<(Self, Option<SessionEvent>)> {
        if self.phase != Phase::Open && self.phase != Phase::AwaitUnbindResult {
            return Err(invalid("native session is not open"));
        }
        self.check_inbound(piu)?;
        let mut next = self.clone();
        let rh = &piu[6..9];
        let ru = &piu[9..];
        if rh == IPR_RH {
            // Live V4R4 grants a local window with the three-byte RU 000003
            // or 000006. The IPR SNF is zero, independent of the request's
            // SNF. Reject every other count and trailing byte.
            if piu[4..6] != [0, 0]
                || !(is_canonical_ipr(rh, ru) || matches!(ru, [0, 0, 3] | [0, 0, 6]))
            {
                return Err(invalid("native IPR sequence or grant RU is unsupported"));
            }
            next.pacing_mut()?
                .receive_pacing_response()
                .map_err(pacing_error)?;
            return Ok((next, None));
        }
        if rh[0] & 0xe0 == 0x60 && ru.first() == Some(&0x32) {
            if self.phase != Phase::Open || piu[0] & 1 == 0 {
                return Err(invalid("native UNBIND request has wrong phase or flow"));
            }
            next.phase = Phase::AwaitUnbindResult;
            next.pending_unbind_snf = Some([piu[4], piu[5]]);
            return Ok((next, Some(SessionEvent::Unbind(unit(&piu[4..])?))));
        }
        if rh[0] & 0x80 != 0 && ru.first() == Some(&0x32) {
            if self.phase != Phase::AwaitUnbindResult
                || rh != [0xeb, 0x80, 0]
                || self.pending_unbind_snf != Some([piu[4], piu[5]])
            {
                return Err(invalid("native UNBIND response is uncorrelated"));
            }
            next.phase = Phase::Closed;
            next.pending_unbind_snf = None;
            return Ok((next, Some(SessionEvent::Unbind(unit(&piu[4..])?))));
        }
        if self.phase != Phase::Open
            || (rh[0] & 0x60 != 0 && !is_user_bis(rh, ru))
            || (is_user_bis(rh, ru) && piu[0] & 1 != 0)
        {
            return Err(invalid("unsupported native session-control PIU"));
        }
        if piu[0] & 1 == 0 && rh[0] & 0x80 == 0 {
            let pi = rh[1] & 1 != 0;
            next.pacing_mut()?
                .receive_request(pi)
                .map_err(pacing_error)?;
            if pi {
                if next.pending_native_grant.is_some() {
                    return Err(invalid("native pacing grant already pending"));
                }
                next.pending_native_grant = Some([piu[4], piu[5]]);
            }
        }
        let mut reduced = piu[4..].to_vec();
        reduced[3] &= !1;
        let event = SessionEvent::Information {
            flow: if piu[0] & 1 == 0 {
                Flow::Normal
            } else {
                Flow::Expedited
            },
            unit: unit(&reduced)?,
        };
        Ok((next, Some(event)))
    }

    /// Prepare the native IPR only after the HPR egress has accepted the
    /// PI-bearing information event. Commit after native enqueue succeeds.
    pub(crate) fn preview_native_grant(&self) -> io::Result<Option<(Self, Vec<u8>)>> {
        let Some(_) = self.pending_native_grant else {
            return Ok(None);
        };
        let mut next = self.clone();
        next.pacing_mut()?
            .grant_receive_window()
            .map_err(pacing_error)?;
        next.pending_native_grant = None;
        let mut piu = vec![0x2d | (u8::from(self.odai) << 1), 0, self.oaf, self.daf];
        piu.extend_from_slice(&[0, 0]);
        piu.extend_from_slice(&IPR_RH);
        Ok(Some((next, piu)))
    }

    /// Prepare one native egress PIU. `fixed_bind_response` is the exact
    /// profile constructed from NativePeerPort's validated UserBindOffer.
    pub(crate) fn preview_event(
        &self,
        event: &SessionEvent,
        fixed_bind_response: Option<&[u8]>,
    ) -> io::Result<(Self, Option<Vec<u8>>)> {
        let mut next = self.clone();
        match (self.phase, event) {
            (
                Phase::AwaitBindResult,
                SessionEvent::BindResult {
                    accepted: true,
                    unit,
                },
            ) => {
                if unit.rh()[0] & 0x80 == 0
                    || unit.ru().first() != Some(&0x31)
                    || unit.snf() != self.bind_snf.as_slice()
                {
                    return Err(invalid("HPR BIND result is not positive"));
                }
                if let Err(error) =
                    validate_positive_response(self.bind_request.as_reduced(), unit.as_reduced())
                {
                    tracing::debug!(
                        error = %error,
                        request = format_args!("{:02x?}", self.bind_request.as_reduced()),
                        response = format_args!("{:02x?}", unit.as_reduced()),
                        "local FID2 positive BIND negotiation rejected"
                    );
                    return Err(io::Error::other(error));
                }
                let piu =
                    fixed_bind_response.ok_or_else(|| invalid("native BIND reply missing"))?;
                if piu.len() < 10
                    || piu[0] & 0xfc != 0x2c
                    || piu[1] != 0
                    || piu[2..4] != [self.oaf, self.daf]
                    || piu[0] & 2 != u8::from(self.odai) << 1
                    || piu[4..6] != self.bind_snf
                    || piu[6..9] != [0xeb, 0x80, 0]
                    || piu[9] != 0x31
                {
                    return Err(invalid("native BIND reply is uncorrelated"));
                }
                // The converter's fixed V4R4 positive response advertises a
                // three-request send window and one inbound request slot.
                next.pacing = Some(FixedPacing::new(3, 1).map_err(pacing_error)?);
                next.phase = Phase::Open;
                Ok((next, Some(piu.to_vec())))
            }
            (
                Phase::AwaitBindResult,
                SessionEvent::BindResult {
                    accepted: false, ..
                },
            ) => {
                next.phase = Phase::Closed;
                Ok((next, None))
            }
            (Phase::Open, SessionEvent::Information { flow, unit }) => {
                if unit.rh()[0] & 0x60 != 0
                    && !(*flow == Flow::Normal && is_user_bis(unit.rh(), unit.ru()))
                {
                    return Err(invalid("session or network control cannot be Information"));
                }
                let mut piu = self.outbound_piu(*flow, unit)?;
                if *flow == Flow::Normal && unit.rh()[0] & 0x80 == 0 {
                    let pi = next.pacing_mut()?.send_request().map_err(pacing_error)?;
                    piu[7] = (piu[7] & !1) | u8::from(pi);
                } else {
                    piu[7] &= !1;
                }
                Ok((next, Some(piu)))
            }
            (Phase::Open, SessionEvent::Unbind(unit)) if unit.rh()[0] & 0x80 == 0 => {
                if unit.ru().first() != Some(&0x32) {
                    return Err(invalid("HPR UNBIND has invalid RU"));
                }
                next.phase = Phase::AwaitUnbindResult;
                next.pending_unbind_snf = Some(unit.snf().try_into().unwrap());
                Ok((next, Some(self.outbound_piu(Flow::Expedited, unit)?)))
            }
            (Phase::AwaitUnbindResult, SessionEvent::Unbind(unit)) if unit.rh()[0] & 0x80 != 0 => {
                if unit.rh() != [0xeb, 0x80, 0]
                    || self.pending_unbind_snf.as_ref().map(|snf| snf.as_slice())
                        != Some(unit.snf())
                {
                    return Err(invalid("HPR UNBIND response is uncorrelated"));
                }
                next.phase = Phase::Closed;
                next.pending_unbind_snf = None;
                Ok((next, Some(self.outbound_piu(Flow::Expedited, unit)?)))
            }
            (Phase::Open, SessionEvent::Credit { .. }) => Ok((next, None)),
            (_, SessionEvent::Reset) => {
                next.phase = Phase::Closed;
                Ok((next, None))
            }
            _ => Err(invalid("unsupported native session event")),
        }
    }

    fn check_inbound(&self, piu: &[u8]) -> io::Result<()> {
        if piu.len() < 9
            || piu[0] & 0xfc != 0x2c
            || piu[1] != 0
            || piu[2..4] != [self.daf, self.oaf]
            || piu[0] & 2 != u8::from(self.odai) << 1
        {
            return Err(invalid("native user PIU has wrong FID2 address or framing"));
        }
        Ok(())
    }

    fn outbound_piu(&self, flow: Flow, unit: &SessionUnit) -> io::Result<Vec<u8>> {
        if unit.rh()[0] & 0x60 == 0x20 {
            return Err(invalid("APPN network-control PIU on user session"));
        }
        let mut piu = vec![
            0x2c | u8::from(flow == Flow::Expedited) | (u8::from(self.odai) << 1),
            0,
            self.oaf,
            self.daf,
        ];
        piu.extend_from_slice(unit.as_reduced());
        Ok(piu)
    }

    fn pacing_mut(&mut self) -> io::Result<&mut FixedPacing> {
        self.pacing
            .as_mut()
            .ok_or_else(|| invalid("native pacing not configured"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn bind() -> Vec<u8> {
        // Sanitized V4R4 p71 user BIND from the native gateway fixture.
        unhex(concat!(
            "2d00010200006b850031001307b0b051330383c7c7830306020000000000000094434000",
            "0be2d6d3d5c5e34be2d5c1c12d0009024040404040404040090301235069de6780000c04",
            "e2d6d3d5c5e34be2d5c1c10a1300b0235069de678000000b",
            "e2d6d3d5c5e34be2d5c1c26014cec37477b5dbed8d0b",
            "e2d6d3d5c5e34be2d5c1c12c0a01087bc3d6d5d5c5c3e3"
        ))
    }

    fn native_response() -> Vec<u8> {
        unhex(concat!(
            "2d0002010000eb800031001307b0b051330080c7c7800006020000000000000094434000",
            "002600090240404040404040400203020c05e2d6d3d5c5e34be2d5c1c20",
            "a1300b023506a33da800000006014cec37477b5dbed8d0b",
            "e2d6d3d5c5e34be2d5c1c1"
        ))
    }

    fn hpr_response(native: &[u8]) -> SessionUnit {
        let mut reduced = native[4..].to_vec();
        reduced[5 + 8..5 + 14].copy_from_slice(&[3, 3, 0x8c, 0x8c, 0x83, 3]);
        reduced[5 + 25] = 0;
        unit(&reduced).unwrap()
    }

    #[test]
    fn captured_v4_to_ee_positive_bind_opens_local_fid2_session() {
        let native = unhex("2d00020200006b800031001307b0b051330383c7c78303060200000000000000944340000cd8c1c1d3c9c3c54be2d5c1c12e0009024040404040404040090301262d1483ba00000d04d8c1c1d3c9c3c54be2d5c1c10a1300b0262d1483ba0000000ad8c1c2d6c24be2d5c1c26015d8e7221f0a553c960cd8c1c1d3c9c3c54be2d5c1c12c0a01087bc3d6d5d5c5c3e3");
        let (codec, _, _) = NativeFid2Session::from_user_bind(
            &native,
            &"QAALICE.SNAA".parse().unwrap(),
            Some("QABOB.SNAB".parse().unwrap()),
        )
        .unwrap();
        let response = unit(&unhex("0000eb800031001307b0b0513303038c8c830306020000000000000094434000002500090240404040404040400203020b05d8c1c2d6c24be2d5c1c20a1300b0262d1598d5800000006015d8e7221f0a553c960cd8c1c1d3c9c3c54be2d5c1c1")).unwrap();
        let native_reply = unhex("2d0002020000eb800031");
        assert!(codec
            .preview_event(
                &SessionEvent::BindResult {
                    accepted: true,
                    unit: response,
                },
                Some(&native_reply),
            )
            .is_ok());
    }

    #[test]
    fn unqualified_lu_uses_only_verified_cp_netid() {
        let cp: QualifiedName = "SOLNET.SNAA".parse().unwrap();
        assert_eq!(
            qualified_lu("APP", Some(&cp)).unwrap().to_string(),
            "SOLNET.APP"
        );
        assert_eq!(
            qualified_lu("SOLNET.APP", None).unwrap().to_string(),
            "SOLNET.APP"
        );
        assert!(qualified_lu("APP", None).is_err());
        assert!(qualified_lu("lower", Some(&cp)).is_err());
    }

    fn opened() -> NativeFid2Session {
        let native_bind = bind();
        let (codec, identity, event) = NativeFid2Session::from_user_bind(
            &native_bind,
            &"SOLNET.SNAA".parse().unwrap(),
            Some("SOLNET.SNAB".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(identity.source_lu.to_string(), "SOLNET.SNAA");
        assert_eq!(identity.target_lu.to_string(), "SOLNET.SNAB");
        let SessionEvent::BindRequest(bind_unit) = event else {
            panic!("BIND event expected")
        };
        assert_eq!(bind_unit.rh(), [0x6b, 0x80, 0]);
        assert_eq!(&bind_unit.ru()[10..12], &[0x8c, 0x8c]);
        assert_eq!(bind_unit.ru()[25], 0);
        let native_response = native_response();
        let (opened, piu) = codec
            .preview_event(
                &SessionEvent::BindResult {
                    accepted: true,
                    unit: hpr_response(&native_response),
                },
                Some(&native_response),
            )
            .unwrap();
        assert_eq!(piu.unwrap(), native_response);
        opened
    }

    #[test]
    fn local_unbind_uses_bound_fqpcid_and_waits_for_correlated_response() {
        let codec = opened();
        let fqpcid = request_fqpcid(codec.bind_request.as_reduced()).unwrap();
        let (awaiting, piu) = codec.preview_local_unbind().unwrap();
        assert_eq!(
            &piu[..15],
            &[0x2d, 0, 2, 1, 0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0]
        );
        assert_eq!(&piu[15..], fqpcid);
        assert!(!awaiting.is_closed());
        let wrong = [0x2d, 0, 1, 2, 0, 1, 0xeb, 0x80, 0, 0x32];
        assert!(awaiting.preview_native(&wrong).is_err());
        let response = [0x2d, 0, 1, 2, 0, 0, 0xeb, 0x80, 0, 0x32];
        let (closed, event) = awaiting.preview_native(&response).unwrap();
        assert!(closed.is_closed());
        assert!(matches!(event, Some(SessionEvent::Unbind(_))));
    }

    #[test]
    fn v4r4_user_bind_without_rh_pacing_bit_is_converted() {
        // The V4R4 LLC capture uses RH 6b8000 on its 143-byte user BIND;
        // another validated capture uses 6b8500. Both carry the same fixed
        // LU 6.2 BIND profile and normalize to the SessionV1 request.
        let mut native_bind = bind();
        native_bind[7] = 0x80;
        let (_, identity, event) = NativeFid2Session::from_user_bind(
            &native_bind,
            &"SOLNET.SNAA".parse().unwrap(),
            Some("SOLNET.SNAB".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(identity.source_lu.to_string(), "SOLNET.SNAA");
        assert_eq!(identity.target_lu.to_string(), "SOLNET.SNAB");
        let SessionEvent::BindRequest(bind) = event else {
            panic!("BIND expected")
        };
        assert_eq!(bind.rh(), [0x6b, 0x80, 0]);
        native_bind[7] = 0x84;
        assert!(NativeFid2Session::from_user_bind(
            &native_bind,
            &"SOLNET.SNAA".parse().unwrap(),
            Some("SOLNET.SNAB".parse().unwrap()),
        )
        .is_err());
    }

    #[test]
    fn unrelated_positive_hpr_bind_result_cannot_open_native_session() {
        let (codec, _, _) = NativeFid2Session::from_user_bind(
            &bind(),
            &"SOLNET.SNAA".parse().unwrap(),
            Some("SOLNET.SNAB".parse().unwrap()),
        )
        .unwrap();
        let native = native_response();
        let mut response = hpr_response(&native).as_reduced().to_vec();
        *response.last_mut().unwrap() ^= 1;
        assert!(codec
            .preview_event(
                &SessionEvent::BindResult {
                    accepted: true,
                    unit: unit(&response).unwrap(),
                },
                Some(&native),
            )
            .is_err());
    }

    #[test]
    fn native_pi_is_local_and_granted_only_after_egress_acceptance() {
        let codec = opened();
        let native = unhex("2c0001020001030120aa");
        let (candidate, event) = codec.preview_native(&native).unwrap();
        let Some(SessionEvent::Information { flow, unit }) = event else {
            panic!("information expected")
        };
        assert_eq!(flow, Flow::Normal);
        assert_eq!(unit.rh(), [3, 0, 0x20]);
        assert!(codec.preview_native_grant().unwrap().is_none());
        let (after_grant, ipr) = candidate.preview_native_grant().unwrap().unwrap();
        assert_eq!(ipr, unhex("2d0002010000830100"));
        assert!(after_grant.preview_native_grant().unwrap().is_none());
        let next_window = unhex("2c0001020002030120bb");
        assert!(candidate.preview_native(&next_window).is_err());
        assert!(after_grant.preview_native(&next_window).is_ok());
        let mut wrong = native.clone();
        wrong[2] = 3;
        assert!(codec.preview_native(&wrong).is_err());
    }

    #[test]
    fn captured_user_bis_crosses_bus_with_local_pacing() {
        let codec = opened();
        // The live V4R4 frame used DAF=OAF=2. This fixture's admitted
        // address is 1/2; the RH/RU and SNF are the captured shutdown form.
        let bis = unhex("2c00010200034b910070");
        let (candidate, event) = codec.preview_native(&bis).unwrap();
        let Some(SessionEvent::Information {
            flow,
            unit: bis_unit,
        }) = event
        else {
            panic!("BIS information expected")
        };
        assert_eq!(flow, Flow::Normal);
        assert_eq!(bis_unit.as_reduced(), unhex("00034b900070"));
        assert!(codec.preview_native_grant().unwrap().is_none());
        let (_, grant) = candidate.preview_native_grant().unwrap().unwrap();
        assert_eq!(grant, unhex("2d0002010000830100"));

        let outbound = SessionEvent::Information {
            flow: Flow::Normal,
            unit: bis_unit,
        };
        let (_, piu) = codec.preview_event(&outbound, None).unwrap();
        assert_eq!(piu.unwrap(), unhex("2c00020100034b910070"));
        let reciprocal_bis = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(&unhex("00034bb00070")).unwrap(),
        };
        let (_, piu) = codec.preview_event(&reciprocal_bis, None).unwrap();
        assert_eq!(piu.unwrap(), unhex("2c00020100034bb10070"));

        for invalid in [
            unhex("2d00010200034b910070"),
            unhex("2c00010200034b910071"),
            unhex("2c00010200034b920070"),
        ] {
            assert!(codec.preview_native(&invalid).is_err());
        }
        let other_dfc = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(&unhex("00034b900071")).unwrap(),
        };
        assert!(codec.preview_event(&other_dfc, None).is_err());
        let expedited_bis = SessionEvent::Information {
            flow: Flow::Expedited,
            unit: unit(&unhex("00034b900070")).unwrap(),
        };
        assert!(codec.preview_event(&expedited_bis, None).is_err());
    }

    #[test]
    fn native_send_window_waits_for_correlated_ipr() {
        let codec = opened();
        let info = SessionEvent::Information {
            flow: Flow::Normal,
            unit: unit(&unhex("0002030020bb")).unwrap(),
        };
        let (sent, piu) = codec.preview_event(&info, None).unwrap();
        assert_eq!(piu.unwrap(), unhex("2c0002010002030120bb"));
        let (granted, event) = sent.preview_native(&unhex("2c0001020000830100")).unwrap();
        assert!(event.is_none());
        assert!(granted
            .preview_native(&unhex("2c0001020000830100"))
            .is_err());
        let (_, adaptive) = sent
            .preview_native(&unhex("2c0001020000830100000003"))
            .unwrap();
        assert!(adaptive.is_none());
        assert!(sent
            .preview_native(&unhex("2c0001020000830100000004"))
            .is_err());
        assert!(sent
            .preview_native(&unhex("2c0001020001830100000003"))
            .is_err());
    }

    #[test]
    fn expedited_information_and_unbind_keep_native_address_and_snf() {
        let codec = opened();
        let (codec, event) = codec
            .preview_native(&unhex("2d00010200030b0000aa"))
            .unwrap();
        assert!(matches!(
            event,
            Some(SessionEvent::Information {
                flow: Flow::Expedited,
                ..
            })
        ));
        assert!(codec.preview_native_grant().unwrap().is_none());
        let (codec, event) = codec
            .preview_native(&unhex("2d00010200046b800032"))
            .unwrap();
        assert!(matches!(event, Some(SessionEvent::Unbind(_))));
        assert!(codec
            .preview_event(
                &SessionEvent::Unbind(unit(&unhex("0005eb800032")).unwrap()),
                None,
            )
            .is_err());
        let (closed, response) = codec
            .preview_event(
                &SessionEvent::Unbind(unit(&unhex("0004eb800032")).unwrap()),
                None,
            )
            .unwrap();
        assert_eq!(response.unwrap(), unhex("2d0002010004eb800032"));
        assert_eq!(closed.phase, Phase::Closed);
        assert!(closed.is_closed());
    }
}
