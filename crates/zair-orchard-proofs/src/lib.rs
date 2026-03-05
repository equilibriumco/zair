//! Orchard airdrop proof generation and verification.

mod error;
mod instance;
mod keys;
mod types;

use zair_orchard_circuit::circuit::airdrop::ValueCommitmentScheme as CircuitValueCommitmentScheme;

pub use crate::error::ClaimProofError;
pub use crate::types::{ClaimProofInputs, ClaimProofOutput, ValueCommitmentScheme};

/// Return the Halo2 `k` parameter for the given scheme.
#[must_use]
pub fn k_for_scheme(scheme: ValueCommitmentScheme) -> u32 {
    let circuit_scheme: CircuitValueCommitmentScheme = scheme.into();
    circuit_scheme.k()
}

#[cfg(feature = "prove")]
pub mod prover;

#[cfg(feature = "prove")]
pub use prover::generate_claim_proof;

#[cfg(feature = "verify")]
pub mod verifier;

#[cfg(feature = "verify")]
pub use verifier::*;

#[cfg(test)]
mod tests;
