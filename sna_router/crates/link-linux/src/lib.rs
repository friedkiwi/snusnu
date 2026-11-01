//! Boundary for future Linux packet I/O. No live adapter exists yet.

use router_core::CircuitId;

pub trait LinkPort {
    type Error;

    fn send(&mut self, circuit: CircuitId, frame: &[u8]) -> Result<(), Self::Error>;
}
