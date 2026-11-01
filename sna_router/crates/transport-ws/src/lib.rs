//! Boundary for future outbound concentrator transport. No WSS client exists yet.

use router_core::{CircuitId, ConnectionGeneration};

pub trait CircuitTransport {
    type Error;

    fn send(
        &mut self,
        generation: ConnectionGeneration,
        circuit: CircuitId,
        payload: &[u8],
    ) -> Result<(), Self::Error>;
}
