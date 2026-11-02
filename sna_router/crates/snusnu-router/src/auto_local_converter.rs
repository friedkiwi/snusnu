//! One automatic LLC-originated LU6.2 circuit to a selected MPTN attachment.
//!
//! The listener and destination resolver choose this circuit before calling
//! here. The converter consumes their owned LLC offer and an exclusive
//! UDP/397 lease, keeping native pacing and TCP62 credit within this session.

use crate::{
    auto_llc::LlcIngressOffer,
    auto_gateway_runtime::{virtual_cp_for_source, virtual_xid},
    config,
    mptn_llc_reverse,
    mptn_outbound_port::OutboundEndpoint,
    native_llc_port::NativeLlcPort,
};
use router_core::xid3::Xid3;
use std::{io, net::{SocketAddr, UdpSocket}, time::Duration};
use transport_ws::wire;

/// Generate the router's virtual APPN identity only after the LLC guest has
/// supplied XID3. A null XID contains no NETID, so callers must use the
/// native listener's completed bootstrap offer or a previously verified CP.
pub(crate) fn virtual_xid_for_offer(
    offer: &LlcIngressOffer,
    seed: &[u8],
) -> io::Result<Xid3> {
    virtual_xid_for_observed_cp(offer.peer_cp.as_deref(), seed)
}

fn virtual_xid_for_observed_cp(guest_cp: Option<&str>, seed: &[u8]) -> io::Result<Xid3> {
    let guest_cp = guest_cp.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "LLC peer CP is not known before XID3")
    })?;
    let guest = config::parse_cp(guest_cp)?;
    let wire_guest = wire::SnaName { netid: guest.netid, name: guest.name };
    let local_cp = virtual_cp_for_source(&wire_guest, seed, None)?;
    virtual_xid(&local_cp, seed, None, None, 1)
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
) -> io::Result<()> {
    validate_target(&udp, target)?;
    let interface = offer.interface.clone();
    let native = NativeLlcPort::open_dynamic_from_offer(offer, virtual_xid)?;
    mptn_llc_reverse::run_with_native(native, udp, target, &interface, timeout)
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
        assert_eq!(validate_target(&udp, target).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn virtual_identity_requires_observed_xid3_cp() {
        assert_eq!(virtual_xid_for_observed_cp(None, b"router").unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let xid = virtual_xid_for_observed_cp(Some("SOLNET.SNAA"), b"router").unwrap();
        assert!(xid.cp_name().unwrap().starts_with("SOLNET.R"));
    }
}
