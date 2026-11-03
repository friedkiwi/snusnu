//! Local HPR-side attachment lifetime, independent of EE and upstream links.
//!
//! An active EE session runtime temporarily leases the MPTN gateways. The
//! listener and management evidence return here when that generation ends.

use std::io;

use crate::{config::RouterConfig, hpr_mptn_attachments::HprMptnAttachments};

pub(crate) struct HprLocalSessionRunner<'a> {
    mptn: Option<HprMptnAttachments<'a>>,
}

impl<'a> HprLocalSessionRunner<'a> {
    pub(crate) fn new(config: &'a RouterConfig) -> io::Result<Self> {
        let mptn = (!config.mptn_gateway.is_empty())
            .then(|| HprMptnAttachments::new(config))
            .transpose()?;
        Ok(Self { mptn })
    }

    pub(crate) fn poll_idle(&mut self) -> io::Result<()> {
        if let Some(mptn) = self.mptn.as_mut() {
            mptn.poll_without_ee()?;
        }
        Ok(())
    }

    pub(crate) fn lease_for_ee(&mut self) -> Option<HprMptnAttachments<'a>> {
        self.mptn.take()
    }

    pub(crate) fn return_from_ee(&mut self, mptn: Option<HprMptnAttachments<'a>>) {
        debug_assert!(self.mptn.is_none());
        self.mptn = mptn;
    }
}
