//! Virtual APPN Type 1 endpoint for a WebSocket native circuit.
//!
//! The remote LLC port owns Ethernet, LLC2, SABME and retransmission. This
//! endpoint owns its configured CP identity and initiates the XID3 exchange
//! as a fixed secondary with an answering V4 primary. It cannot mark a
//! circuit ready until the remote port reports LinkReady.

use crate::native_type1::{NativeType1, OutboundType1};
use router_core::{
    xid3::{Role, Xid3},
    xid3_activation::Phase,
};
use std::io;

pub(crate) struct VirtualNativeCp {
    type1: NativeType1,
    #[allow(dead_code)] // Inspectable identity in the virtual-CP tests.
    local_cp: String,
    expected_peer_cp: String,
    pending: Option<OutboundType1>,
    link_ready: bool,
}

impl VirtualNativeCp {
    /// `local_xid` is a locally constructed capability profile. In particular,
    /// its node ID and control vectors must describe this router, not a copy
    /// of a captured OS/400 peer. The passive V4 LLC station becomes primary.
    pub(crate) fn new(local_xid: Xid3, local_cp: &str, expected_peer_cp: &str) -> io::Result<Self> {
        if local_cp == expected_peer_cp
            || local_xid.cp_name().ok().as_deref() != Some(local_cp)
            || local_xid.role() != Ok(Role::Secondary)
        {
            return Err(invalid(
                "virtual CP requires its own fixed-secondary XID3 identity",
            ));
        }
        Ok(Self {
            type1: NativeType1::new(local_xid)?,
            local_cp: local_cp.to_owned(),
            expected_peer_cp: expected_peer_cp.to_owned(),
            pending: None,
            link_ready: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn local_cp(&self) -> &str {
        &self.local_cp
    }

    #[cfg(test)]
    pub(crate) fn peer_cp(&self) -> Option<&str> {
        self.type1.peer_name()
    }

    #[cfg(test)]
    pub(crate) fn xid_ready(&self) -> bool {
        self.pending.is_none() && self.type1.phase() == Phase::ReadyForSabme
    }

    /// Queue the first null XID command. This also gives a WebSocket route
    /// port an outbound Type1 event with which to open its circuit. Commit it
    /// only after the route port has accepted the event.
    pub(crate) fn prepare_active_null_xid(&mut self) -> io::Result<Vec<u8>> {
        if self.pending.is_some() {
            return Err(invalid("virtual CP has an unconfirmed Type1 command"));
        }
        let outbound = self.type1.prepare_active_null_xid()?;
        let pdu = outbound.pdu.clone();
        self.pending = Some(outbound);
        Ok(pdu)
    }

    /// Feed one decoded WebSocket Type1 LLC PDU. The caller must send the
    /// returned bytes before calling `confirm_sent`; a failed send leaves the
    /// circuit blocked and must cause a reset rather than premature readiness.
    pub(crate) fn receive_type1(&mut self, pdu: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if self.pending.is_some() {
            return Err(invalid("virtual CP has an unconfirmed Type1 response"));
        }
        if self.link_ready {
            return Err(invalid("Type1 received after virtual link readiness"));
        }
        let outbound = self.type1.on_pdu(pdu)?;
        if self
            .type1
            .peer_name()
            .is_some_and(|name| name != self.expected_peer_cp)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "virtual CP expected peer {}, got {}",
                    self.expected_peer_cp,
                    self.type1.peer_name().unwrap_or_default()
                ),
            ));
        }
        if let Some(outbound) = outbound {
            let pdu = outbound.pdu.clone();
            self.pending = Some(outbound);
            Ok(Some(pdu))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn confirm_sent(&mut self, pdu: &[u8]) -> io::Result<()> {
        let outbound = self
            .pending
            .as_ref()
            .ok_or_else(|| invalid("virtual CP has no prepared Type1 response"))?;
        if outbound.pdu != pdu {
            return Err(invalid(
                "virtual CP Type1 send differs from prepared response",
            ));
        }
        self.type1.confirm_sent(outbound)?;
        self.pending = None;
        Ok(())
    }

    /// LinkReady is the remote LLC port's report that SABME/UA completed.
    pub(crate) fn receive_link_ready(&mut self) -> io::Result<()> {
        if self.pending.is_some()
            || self.type1.phase() != Phase::ReadyForSabme
            || self.type1.peer_name() != Some(self.expected_peer_cp.as_str())
        {
            return Err(invalid("LinkReady before verified XID3 activation"));
        }
        self.link_ready = true;
        Ok(())
    }

    pub(crate) fn ready(&self) -> bool {
        self.link_ready
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::xid3::{ControlVector, ExchangeState};

    fn xid(name: &str, role: Role, node_id: [u8; 4]) -> Xid3 {
        let mut fixed = [0u8; 29];
        fixed[2..6].copy_from_slice(&node_id);
        fixed[9] = 0x08;
        fixed[19] = 0x40;
        fixed[21..23].copy_from_slice(&1496u16.to_be_bytes());
        fixed[27] = 7;
        let mut xid = Xid3::from_parts(
            fixed,
            vec![ControlVector {
                key: 0x0e,
                data: vec![
                    0xf4, 0xd8, 0xc1, 0xc1, 0xd3, 0xc9, 0xc3, 0xc5, 0x4b, 0xe2, 0xd5, 0xc1, 0xc1,
                ],
            }],
        )
        .unwrap();
        xid.set_cp_name(name).unwrap();
        xid.set_role(role);
        xid.set_exchange_state(ExchangeState::Prenegotiation);
        xid
    }

    #[test]
    fn active_virtual_secondary_activates_with_passive_v4_primary_and_link_ready() {
        let mut virtual_cp = VirtualNativeCp::new(
            xid("QABOB.SNAB", Role::Secondary, [0xff, 0xf1, 0x12, 0x34]),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        let mut llc =
            NativeType1::new(xid("QAALICE.SNAA", Role::Primary, [0x05, 0x63, 0x39, 0x50])).unwrap();
        let mut next = virtual_cp.prepare_active_null_xid().unwrap();
        assert_eq!(next, [4, 4, 0xbf]);
        assert!(virtual_cp.prepare_active_null_xid().is_err());
        virtual_cp.confirm_sent(&next).unwrap();
        for _ in 0..8 {
            let reply = llc.on_pdu(&next).unwrap().unwrap();
            llc.confirm_sent(&reply).unwrap();
            let response = virtual_cp.receive_type1(&reply.pdu).unwrap().unwrap();
            assert!(!virtual_cp.ready());
            assert!(virtual_cp.receive_type1(&reply.pdu).is_err());
            virtual_cp.confirm_sent(&response).unwrap();
            next = response;
            if llc.phase() == Phase::ReadyForSabme
                && virtual_cp.type1.phase() == Phase::ReadyForSabme
            {
                break;
            }
        }
        assert_eq!(llc.phase(), Phase::ReadyForSabme);
        assert_eq!(virtual_cp.peer_cp(), Some("QAALICE.SNAA"));
        assert_eq!(virtual_cp.local_cp(), "QABOB.SNAB");
        assert!(!virtual_cp.ready());
        virtual_cp.receive_link_ready().unwrap();
        assert!(virtual_cp.ready());
    }

    #[test]
    fn rejects_wrong_peer_and_early_link_ready() {
        let mut virtual_cp = VirtualNativeCp::new(
            xid("QABOB.SNAB", Role::Secondary, [0xff, 0xf1, 0x12, 0x34]),
            "QABOB.SNAB",
            "QAALICE.SNAA",
        )
        .unwrap();
        assert!(virtual_cp.receive_link_ready().is_err());
        let mut wrong = vec![4, 5, 0xbf];
        wrong.extend(
            xid("QAALICE.OTHER", Role::Negotiable, [0x05, 0x63, 0x39, 0x50])
                .encode()
                .unwrap(),
        );
        assert_eq!(
            virtual_cp.receive_type1(&wrong).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
