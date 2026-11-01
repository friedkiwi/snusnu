//! Unregistered native APPN LLC leg for a future session converter.
//!
//! This adapter reuses the live-tested XID3/LLC2 and SNASVCMG state in
//! NativePeerPort. It emits user-session PIUs only after the management
//! sequence reaches its protocol boundary. The converter owns user pacing,
//! MPTN Connect admission, and route readiness; this adapter never marks a
//! route ready by itself.

use crate::{
    native_peer_port::{NativeLlcEvent, NativePeerPort},
    routing::RoutePort,
    runtime::LlcPeer,
};
use router_core::fid2_session_control::ManagementBind;
use router_core::xid3::Xid3;
use std::io;
use transport_ip_sna::mptn_gateway_edge::{NativeEvent, NativeLeg};

pub(crate) struct NativeLlcPort {
    inner: NativePeerPort,
}

impl NativeLlcPort {
    pub(crate) fn open(
        peer: LlcPeer<'_>,
        local_xid: Xid3,
        remote_cp: String,
        local_cp: String,
        user_plu: String,
        user_slu: String,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: NativePeerPort::open_converter(
                peer, local_xid, remote_cp, local_cp, user_plu, user_slu,
            )?,
        })
    }

    pub(crate) fn receive_once(&mut self) -> io::Result<Option<NativeLlcEvent>> {
        if let Some(event) = self.inner.take_converter_event() {
            return Ok(Some(event));
        }
        self.inner.poll(true)?;
        self.inner.tick()?;
        Ok(self.inner.take_converter_event())
    }

    pub(crate) fn enqueue(&mut self, piu: &[u8]) -> io::Result<bool> {
        self.inner.enqueue_converter_piu(piu)
    }

    pub(crate) fn available_slots(&self) -> usize {
        self.inner.converter_available_slots()
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.inner.disconnect()
    }

    pub(crate) fn management_bind(&self) -> Option<&ManagementBind> {
        self.inner.converter_management_bind()
    }
}

impl NativeLeg for NativeLlcPort {
    fn receive_once(&mut self) -> io::Result<Option<NativeEvent>> {
        let event = NativeLlcPort::receive_once(self)?;
        Ok(match event {
            Some(NativeLlcEvent::UserBind(piu)) => Some(NativeEvent::UserBind(piu)),
            Some(NativeLlcEvent::BindResponseAck) => Some(NativeEvent::BindResponseAck(1)),
            Some(NativeLlcEvent::FirstAttach(piu)) => Some(NativeEvent::FirstAttach(piu)),
            Some(NativeLlcEvent::EgressAck(count)) => Some(NativeEvent::EgressAck(count)),
            Some(NativeLlcEvent::Closed) => Some(NativeEvent::Closed),
            Some(NativeLlcEvent::UserInformation(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "later native APPC PIU needs gateway handler",
                ));
            }
            None => None,
        })
    }

    fn enqueue(&mut self, piu: &[u8]) -> io::Result<bool> {
        NativeLlcPort::enqueue(self, piu)
    }

    fn available_slots(&self) -> usize {
        NativeLlcPort::available_slots(self)
    }

    fn close(&mut self) -> io::Result<()> {
        NativeLlcPort::close(self)
    }
}
