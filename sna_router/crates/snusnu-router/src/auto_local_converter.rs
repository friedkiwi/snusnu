//! One automatic LLC-originated LU6.2 circuit to a selected MPTN attachment.
//!
//! The listener and destination resolver choose this circuit before calling
//! here. The converter consumes their owned LLC offer and an exclusive
//! UDP/397 lease, keeping native pacing and TCP62 credit within this session.

use crate::{
    auto_llc::LlcIngressOffer, llc_target_identity::LlcTargetIdentity, mptn_llc_reverse,
    mptn_outbound_port::OutboundEndpoint, native_llc_port::NativeLlcPort,
};
use router_core::xid3::Xid3;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::atomic::AtomicBool,
    time::Duration,
};
use transport_ws::wire;

/// Build the router's native XID from the selected MPTN target's trusted CP.
/// The LLC guest CP is never used as the router's CP: the two can have
/// different NETIDs. When no target CP is known, routing must wait for an
/// advertised hosting CP or an explicit attachment hint.
pub(crate) fn virtual_xid_for_target(target_cp: &wire::SnaName, seed: &[u8]) -> io::Result<Xid3> {
    let attachment_id = std::str::from_utf8(seed).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "LLC identity seed is not UTF-8",
        )
    })?;
    LlcTargetIdentity::from_wire(Some(target_cp), attachment_id)?.xid()
}

/// The virtual XID CP and target MPTN attachment must already be selected by
/// the caller. The guest CP is learned from XID3, and the LU pair and TP are
/// learned from validated BIND and FMH-5 units during the session.
pub(crate) fn run_llc_to_mptn(
    offer: LlcIngressOffer,
    virtual_xid: Xid3,
    udp: UdpSocket,
    target: OutboundEndpoint,
    timeout: Duration,
    cancel: &AtomicBool,
) -> io::Result<()> {
    validate_target(&udp, target)?;
    let interface = offer.interface.clone();
    let native = NativeLlcPort::open_dynamic_from_offer(offer, virtual_xid)?;
    mptn_llc_reverse::run_with_native(native, udp, target, &interface, timeout, cancel)
}

fn validate_target(udp: &UdpSocket, target: OutboundEndpoint) -> io::Result<()> {
    if target.local_ip.is_unspecified()
        || target.peer_ip.is_unspecified()
        || target.local_ip == target.peer_ip
        || target.local_ip.is_ipv4() != target.peer_ip.is_ipv4()
        || udp.local_addr()? != SocketAddr::new(target.local_ip, 397)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "automatic LLC to MPTN target or UDP lease is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_mptn_target_must_own_exclusive_udp_endpoint() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = OutboundEndpoint {
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.2".parse().unwrap(),
        };
        assert_eq!(
            validate_target(&udp, target).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn virtual_identity_uses_selected_target_cp_even_across_netids() {
        let cp = wire::SnaName {
            netid: "QABOB".into(),
            name: "SNAB".into(),
        };
        let xid = virtual_xid_for_target(&cp, b"router").unwrap();
        assert_eq!(xid.cp_name().unwrap(), "QABOB.SNAB");
    }
}
