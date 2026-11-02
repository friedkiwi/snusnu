//! Admits datagrams from one local HPR/IP neighbor and observes its XID3 CP.
//!
//! This is a listener building block, not an HPR gateway: it does not
//! negotiate an LDLC link, terminate RTP, or expose LU sessions. Automatic
//! configuration remains gated until those functions can consume its events.

use router_core::xid3::Xid3;
use std::{io, net::IpAddr};
use transport_ip_sna::ee::{Datagram, EeSockets, LdlcKind};

pub(crate) struct HprIpIngress {
    pub(crate) datagram: Datagram,
    /// A newly verified CP, or None if this datagram supplied no identity.
    pub(crate) observed_cp: Option<String>,
}

pub(crate) struct AutoHprIpListener {
    sockets: EeSockets,
    local_ip: IpAddr,
    peer_ip: IpAddr,
    peer_cp: Option<String>,
}

impl AutoHprIpListener {
    pub(crate) fn bind(local_ip: IpAddr, peer_ip: IpAddr) -> io::Result<Self> {
        if local_ip == peer_ip
            || local_ip.is_unspecified()
            || peer_ip.is_unspecified()
            || local_ip.is_ipv4() != peer_ip.is_ipv4()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid HPR/IP neighbor address pair",
            ));
        }
        Ok(Self {
            sockets: EeSockets::bind(local_ip)?,
            local_ip,
            peer_ip,
            peer_cp: None,
        })
    }

    pub(crate) fn poll(&mut self) -> io::Result<Option<HprIpIngress>> {
        let (source, datagram) = match self.sockets.receive() {
            Ok(Some(received)) => received,
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip,
                    error = %error, "malformed HPR/IP datagram discarded");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if source.ip() != self.peer_ip {
            tracing::warn!(local_ip = %self.local_ip, source_ip = %source.ip(),
                configured_peer_ip = %self.peer_ip, "HPR/IP datagram from unconfigured peer discarded");
            return Ok(None);
        }
        match observe_xid3_cp(&datagram, self.peer_cp.as_deref()) {
            Ok(observed_cp) => {
                if let Some(cp) = &observed_cp {
                    tracing::info!(local_ip = %self.local_ip, peer_ip = %self.peer_ip,
                        peer_cp = %cp, "HPR/IP neighbor CP observed in XID3");
                    self.peer_cp = Some(cp.clone());
                }
                Ok(Some(HprIpIngress {
                    datagram,
                    observed_cp,
                }))
            }
            Err(error) => {
                tracing::warn!(local_ip = %self.local_ip, peer_ip = %self.peer_ip,
                    error = %error, "HPR/IP XID3 identity rejected");
                Ok(None)
            }
        }
    }

    pub(crate) fn peer_cp(&self) -> Option<&str> {
        self.peer_cp.as_deref()
    }
}

fn observe_xid3_cp(datagram: &Datagram, existing: Option<&str>) -> io::Result<Option<String>> {
    if datagram.kind != LdlcKind::Xid || datagram.payload.get(3) != Some(&0x32) {
        return Ok(None);
    }
    let cp = Xid3::decode(&datagram.payload[3..])
        .and_then(|xid| xid.cp_name())
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HPR/IP XID3 CP: {error}"),
            )
        })?;
    if existing.is_some_and(|known| known != cp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HPR/IP neighbor CP changed on the same address",
        ));
    }
    Ok((existing != Some(cp.as_str())).then_some(cp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::{xid3::Role, xid3_local::LocalLlcProfile};
    use std::{net::UdpSocket, thread, time::Duration};
    use transport_ip_sna::ee::CONTROL_PORT;

    fn xid3(cp: &str) -> Datagram {
        let xid = LocalLlcProfile {
            cp_name: cp.into(),
            station_name: "STATION".into(),
            node_id: [0xff, 0xf0, 0, 1],
            tg_number: 1,
            max_receive_btu: 1496,
            max_iframes_before_ack: 1,
            role: Role::Secondary,
        }
        .build()
        .unwrap()
        .encode()
        .unwrap();
        Datagram::decode(CONTROL_PORT, [vec![4, 4, 0xaf], xid].concat()).unwrap()
    }

    #[test]
    fn xid3_observation_is_stable_and_rejects_identity_switch() {
        let xid = xid3("NETA.PEERA");
        assert_eq!(
            observe_xid3_cp(&xid, None).unwrap().as_deref(),
            Some("NETA.PEERA")
        );
        assert!(observe_xid3_cp(&xid, Some("NETA.PEERA")).unwrap().is_none());
        assert!(observe_xid3_cp(&xid, Some("NETA.PEERB")).is_err());
        let null_xid = Datagram::decode(CONTROL_PORT, vec![4, 4, 0xaf]).unwrap();
        assert!(observe_xid3_cp(&null_xid, None).unwrap().is_none());
        let mut damaged = xid;
        damaged.payload[4] = 0;
        assert!(observe_xid3_cp(&damaged, None).is_err());
    }

    #[test]
    fn listener_admits_only_configured_peer_ip() {
        let pid = std::process::id();
        let local_ip = IpAddr::from([127, 73, (pid >> 8) as u8, pid as u8]);
        let peer_ip = IpAddr::from([127, 74, (pid >> 8) as u8, pid as u8]);
        let rogue_ip = IpAddr::from([127, 75, (pid >> 8) as u8, pid as u8]);
        let mut listener = AutoHprIpListener::bind(local_ip, peer_ip).unwrap();
        let rogue = UdpSocket::bind((rogue_ip, 0)).unwrap();
        let allowed = UdpSocket::bind((peer_ip, 0)).unwrap();
        let packet = xid3("NETA.PEERA").payload;
        rogue.send_to(&packet, (local_ip, CONTROL_PORT)).unwrap();
        for _ in 0..100 {
            if listener.poll().unwrap().is_none() {
                thread::sleep(Duration::from_millis(1));
            }
        }
        assert!(listener.peer_cp().is_none());
        allowed.send_to(&packet, (local_ip, CONTROL_PORT)).unwrap();
        let ingress = (0..100)
            .find_map(|_| {
                let result = listener.poll().unwrap();
                if result.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                result
            })
            .expect("configured peer XID3 received");
        assert_eq!(ingress.observed_cp.as_deref(), Some("NETA.PEERA"));
        assert_eq!(ingress.datagram.port, CONTROL_PORT);
        assert_eq!(listener.peer_cp(), Some("NETA.PEERA"));
    }
}
