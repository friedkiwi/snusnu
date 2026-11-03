//! Linux AF_PACKET access to complete Ethernet frames.
//!
//! Opening this socket requires CAP_NET_RAW. Frame decoding and protocol
//! validation belong in `router-core`; this module bounds each raw read/write.

use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

/// Largest untagged Ethernet frame excluding its FCS.
pub const MAX_FRAME_LEN: usize = 1514;
const MIN_HEADER_LEN: usize = 14;
const MIN_WIRE_LEN: usize = 60;
const ETH_P_ALL: u16 = 0x0003;

pub struct PacketPort {
    fd: OwnedFd,
}

impl PacketPort {
    /// Bind a nonblocking raw packet socket to one Linux Ethernet interface.
    pub fn open(interface: &str) -> io::Result<Self> {
        let name = CString::new(interface).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface contains a NUL byte")
        })?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let protocol = i32::from(ETH_P_ALL.to_be());
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        // Receive LLC traffic addressed to remote DLC MACs as well as the
        // interface's own address. Membership is released with the socket.
        let membership = libc::packet_mreq {
            mr_ifindex: index as i32,
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&raw const membership).cast(),
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Receive one frame, omitting locally transmitted and oversized frames.
    /// `WouldBlock` means no frame is ready. Promiscuous sockets also receive
    /// unrelated jumbo traffic, which must not fail an LLC route.
    pub fn receive_frame(&self, frame: &mut [u8; MAX_FRAME_LEN]) -> io::Result<usize> {
        receive_frame_with(frame, |frame| {
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut address_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let length = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    frame.as_mut_ptr().cast(),
                    frame.len(),
                    libc::MSG_TRUNC,
                    (&raw mut address).cast::<libc::sockaddr>(),
                    &raw mut address_len,
                )
            };
            if length < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((length as usize, address.sll_pkttype))
        })
    }

    /// Transmit a complete untagged Ethernet frame excluding its FCS.
    pub fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        if !(MIN_HEADER_LEN..=MAX_FRAME_LEN).contains(&frame.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Ethernet frame length outside untagged bounds",
            ));
        }
        // TAP does not necessarily insert the padding a physical NIC would.
        let mut padding = [0u8; MIN_WIRE_LEN];
        let wire_frame = if frame.len() < MIN_WIRE_LEN {
            padding[..frame.len()].copy_from_slice(frame);
            &padding[..]
        } else {
            frame
        };
        let length = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                wire_frame.as_ptr().cast(),
                wire_frame.len(),
                0,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != wire_frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short packet send",
            ));
        }
        Ok(())
    }
}

fn receive_frame_with(
    frame: &mut [u8; MAX_FRAME_LEN],
    mut receive: impl FnMut(&mut [u8; MAX_FRAME_LEN]) -> io::Result<(usize, u8)>,
) -> io::Result<usize> {
    loop {
        let (length, packet_type) = receive(frame)?;
        if packet_type == libc::PACKET_OUTGOING || length > frame.len() {
            continue;
        }
        return Ok(length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_unrelated_jumbo_and_then_delivers_llc() {
        let mut frame = [0u8; MAX_FRAME_LEN];
        let mut calls = 0;
        let length = receive_frame_with(&mut frame, |buffer| {
            calls += 1;
            if calls == 1 {
                buffer[..14].copy_from_slice(&[0xff; 14]);
                Ok((MAX_FRAME_LEN + 1, libc::PACKET_OTHERHOST))
            } else {
                buffer[..17]
                    .copy_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0, 3, 4, 4, 0x6f]);
                Ok((17, libc::PACKET_OTHERHOST))
            }
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(length, 17);
        assert_eq!(&frame[14..17], &[4, 4, 0x6f]);
    }
}
