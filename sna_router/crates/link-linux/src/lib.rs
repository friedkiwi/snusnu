//! Linux packet I/O boundary.

use router_core::CircuitId;

#[cfg(target_os = "linux")]
pub mod packet;

pub trait LinkPort {
    type Error;

    fn send(&mut self, circuit: CircuitId, frame: &[u8]) -> Result<(), Self::Error>;
}
