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

    /// Receive one frame, omitting locally transmitted frames. `WouldBlock`
    /// means no frame is ready. `MSG_TRUNC` detects oversized packets.
    pub fn receive_frame(&self, frame: &mut [u8; MAX_FRAME_LEN]) -> io::Result<usize> {
        loop {
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
            if address.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            if length as usize > frame.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Ethernet frame exceeds untagged maximum",
                ));
            }
            return Ok(length as usize);
        }
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
